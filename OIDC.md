# Native OpenID Connect login

DDNS-GO supports optional OpenID Connect (OIDC) sign-in. It uses
[go-oidc](https://github.com/coreos/go-oidc) for discovery, JWKS and ID token
verification, [oauth2](https://pkg.go.dev/golang.org/x/oauth2) for Authorization
Code + PKCE S256, and [SCS](https://github.com/alexedwards/scs) for server-side
sessions. Token signatures, issuer, audience, expiry, browser-bound state and
nonce are checked. Tokens and client secrets are never returned to the UI.

## Setup

1. Sign in with the existing local administrator account. Select the **OIDC**
   tab in the **Others / 其他** account/password card on the dashboard.
2. Create a confidential OAuth2/OIDC client at your identity provider, enabling
   Authorization Code, and register the exact callback
   `https://ddns.example.com/oidc/callback`. Use HTTPS for the issuer and public
   application; no subpath hosting or insecure TLS mode is supported for OIDC.
3. Enter only **Issuer URL**, **Client ID**, and **Client Secret**. The callback
   is displayed for copying and generated from the current origin on first setup.
   First setup uses the standard `openid` scope and automatic login. Existing
   callback, scopes and automatic-login preferences are preserved. No local
   username match, group claim, profile claim or provider-specific mapping is required.
4. Enable and save. Saving validates discovery without changing DNS records.
   Click **测试登录**, then verify the existing DDNS configuration is visible.
   Automatic login also completes SSO after an outer proxy authentication gate.
   `/login?local=1` always shows the local recovery form; logout uses this URL
   so an existing identity-provider session does not immediately sign you in again.
5. If migrating from a reverse-proxy login gate, remove its outer forward-auth
   only after the application login works. Keep standard HTTPS, Host forwarding
   and network restrictions. Do not place an interactive gate before callbacks.

DDNS-GO is a generic OIDC relying party. Configure who may authorize **this
client/application at the identity provider**. A valid authorization grants
administrator access to the **same DDNS configuration and DNS credentials**.
There is no tenant or per-user isolation. A general login account at the
identity provider is not by itself an application-access policy: configure the
provider's client access controls before enabling OIDC.

DDNS-GO validates the ID token signature, issuer, audience, expiry, subject and
nonce plus browser-bound state and PKCE. The identity is the standard issuer
and subject pair (`iss`, `sub`). It does not interpret `groups` or require the
optional `preferred_username`, `profile` or `email` claims.

Expand **Advanced options / 高级选项** below the callback to edit scopes,
callback URL and automatic login. It is collapsed by
default; simply opening or closing it does not change settings. Only edited
advanced fields are submitted, including edits made before collapsing it again.
These values also remain configurable in YAML; restart after editing the file.
The page-wide Save buttons always save DNS/global settings; Save OIDC (or Enter
in an OIDC text input) saves OIDC only. OIDC inputs are locked while saving.
Saving OIDC does not save pending DNS/password changes. Old `/oidc-settings` bookmarks
redirect to the dashboard's OIDC tab.

Configuration is stored under `oidc` in the existing YAML file, mode 0600. Blank
client secret in the settings form preserves the stored value. Changing OIDC
settings or disabling OIDC invalidates existing OIDC sessions. Sessions are
in-memory, last at most 12 hours, and are invalidated on process restart.
Cookies are host-only, Secure, HttpOnly, SameSite=Lax. Logout ends the local
application session, not the identity-provider session. Revoking access at the
identity provider does not instantly revoke an already-issued local session;
disable OIDC or restart the application for immediate session revocation.

All state-changing web routes require POST and Go's CrossOriginProtection.
OIDC callback GETs use state/nonce/PKCE; a minimal callback document completes
the navigation before entering the application, avoiding cross-origin redirect
chain errors. Local login is the recovery path if the IdP is unavailable.
Concurrent discovery requests share a bounded lookup and can cancel independently.
OIDC saves merge only OIDC into the latest configuration; a concurrent OIDC edit
returns a conflict instead of overwriting it.

Run the UI regression tests with Node.js 20 or newer:

```sh
node --test web/oidc_ui_test.mjs
```
Local password cookies use Secure on direct TLS connections; direct LAN HTTP
remains usable for recovery. Forwarded scheme headers are not implicitly trusted.
When terminating TLS at a reverse proxy, configure that proxy to set Secure on
the local `token` cookie (for nginx: `proxy_cookie_flags token secure`).
OIDC cookies are always Secure regardless of the local-login transport.
