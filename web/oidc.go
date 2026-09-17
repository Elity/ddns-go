package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jeessy2/ddns-go/v6/config"
	"golang.org/x/oauth2"
)

var oidcSessions = newOIDCSessions()

func newOIDCSessions() *scs.SessionManager {
	s := scs.New()
	s.Lifetime = 12 * time.Hour
	s.Cookie.Name = "__Host-ddns_oidc"
	s.Cookie.Secure = true
	s.Cookie.Persist = false
	s.HashTokenInStore = true
	return s
}

// SessionMiddleware preserves safe OIDC GET redirects while protecting writes.
func SessionMiddleware(next http.Handler) http.Handler {
	return http.NewCrossOriginProtection().Handler(oidcSessions.LoadAndSave(next))
}

func oidcFingerprint(o config.OIDC) string {
	data, _ := json.Marshal(o)
	sum := sha256.Sum256(append(data, []byte(o.ClientSecret)...))
	return hex.EncodeToString(sum[:])
}

func oidcAuthenticated(r *http.Request, o config.OIDC) bool {
	return o.Enabled && oidcSessions.GetString(r.Context(), "subject") != "" && oidcSessions.GetString(r.Context(), "config") == oidcFingerprint(o)
}

var oidcProviderCache struct {
	sync.Mutex
	fingerprint string
	provider    *oidc.Provider
}

var oidcHTTPClient = &http.Client{Timeout: 15 * time.Second}

func getOIDCProvider(ctx context.Context, o config.OIDC) (*oidc.Provider, *oauth2.Config, error) {
	if err := o.Validate(); err != nil || !o.Enabled {
		return nil, nil, errors.New("OIDC is disabled or invalid")
	}
	key := oidcFingerprint(o)
	oidcProviderCache.Lock()
	defer oidcProviderCache.Unlock()
	if oidcProviderCache.provider == nil || oidcProviderCache.fingerprint != key {
		provider, err := oidc.NewProvider(oidc.ClientContext(ctx, oidcHTTPClient), o.Issuer)
		if err != nil {
			return nil, nil, err
		}
		endpoint := provider.Endpoint()
		for _, raw := range []string{endpoint.AuthURL, endpoint.TokenURL} {
			u, err := url.Parse(raw)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
				return nil, nil, errors.New("OIDC endpoints must use HTTPS")
			}
		}
		oidcProviderCache.provider = provider
		oidcProviderCache.fingerprint = key
	}
	return oidcProviderCache.provider, &oauth2.Config{ClientID: o.ClientID, ClientSecret: o.ClientSecret, RedirectURL: o.RedirectURL, Scopes: strings.Fields(o.Scopes), Endpoint: oidcProviderCache.provider.Endpoint()}, nil
}

func OIDCStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	conf, _ := config.GetConfigCached()
	_, client, err := getOIDCProvider(r.Context(), conf.OIDC)
	if err != nil {
		http.Error(w, "OIDC unavailable. Open /login?local=1 for local recovery login.", http.StatusServiceUnavailable)
		return
	}
	if err = oidcSessions.RenewToken(r.Context()); err != nil {
		http.Error(w, "Session unavailable", 500)
		return
	}
	state, nonce, verifier := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
	oidcSessions.Put(r.Context(), "state", state)
	oidcSessions.Put(r.Context(), "nonce", nonce)
	oidcSessions.Put(r.Context(), "verifier", verifier)
	oidcSessions.Put(r.Context(), "started", time.Now().Unix())
	oidcSessions.Put(r.Context(), "pending_config", oidcFingerprint(conf.OIDC))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, client.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func OIDCCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	fail := func() {
		http.Error(w, "OIDC login failed. Start a new login or open /login?local=1 for local recovery login.", http.StatusUnauthorized)
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	conf, _ := config.GetConfigCached()
	state := oidcSessions.PopString(r.Context(), "state")
	nonce := oidcSessions.PopString(r.Context(), "nonce")
	verifier := oidcSessions.PopString(r.Context(), "verifier")
	started := time.Unix(oidcSessions.GetInt64(r.Context(), "started"), 0)
	oidcSessions.Remove(r.Context(), "started")
	pending := oidcSessions.PopString(r.Context(), "pending_config")
	q := r.URL.Query()
	if state == "" || len(q["state"]) != 1 || subtle.ConstantTimeCompare([]byte(state), []byte(q.Get("state"))) != 1 || nonce == "" || verifier == "" || time.Since(started) > 5*time.Minute || pending != oidcFingerprint(conf.OIDC) || q.Get("error") != "" || len(q["code"]) != 1 || q.Get("code") == "" {
		fail()
		return
	}
	provider, client, err := getOIDCProvider(r.Context(), conf.OIDC)
	if err != nil {
		fail()
		return
	}
	ctx, cancel := context.WithTimeout(oidc.ClientContext(r.Context(), oidcHTTPClient), 20*time.Second)
	defer cancel()
	token, err := client.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		fail()
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		fail()
		return
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: conf.OIDC.ClientID}).Verify(ctx, raw)
	if err != nil || idToken.Subject == "" || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) != 1 {
		fail()
		return
	}
	// The provider decides which identities may authorize this client. Only
	// standard OIDC claims are required; usernames and groups are not assumed.
	// Recheck configuration after network I/O, before issuing a session.
	current, _ := config.GetConfigCached()
	if oidcFingerprint(current.OIDC) != pending || !current.OIDC.Enabled {
		fail()
		return
	}
	if err = oidcSessions.RenewToken(r.Context()); err != nil {
		fail()
		return
	}
	oidcSessions.Put(r.Context(), "subject", idToken.Subject)
	oidcSessions.Put(r.Context(), "issuer", idToken.Issuer)
	oidcSessions.Put(r.Context(), "config", pending)
	// A document ends the cross-origin redirect chain before opening the UI.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	w.Write([]byte(`<!doctype html><html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=/"><title>DDNS-GO</title><a href="/">Continue to DDNS-GO</a></html>`))
}

func OIDCSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/#oidc", http.StatusSeeOther)
}

func SaveOIDCSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		Enabled      *bool
		AutoLogin    *bool
		Issuer       *string
		ClientID     *string
		ClientSecret string
		RedirectURL  *string
		Scopes       *string
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&input); err != nil {
		http.Error(w, "Invalid settings", 400)
		return
	}
	conf, _ := config.GetConfigCached()
	next := conf.OIDC
	// Preserve omitted protocol settings; initialize defaults on first setup.
	if next.Issuer == "" && next.ClientID == "" {
		next.AutoLogin = true
	}
	if next.Scopes == "" {
		next.Scopes = "openid"
	}
	if input.Enabled != nil {
		next.Enabled = *input.Enabled
	}
	if input.AutoLogin != nil {
		next.AutoLogin = *input.AutoLogin
	}
	if input.Issuer != nil {
		next.Issuer = strings.TrimSpace(*input.Issuer)
	}
	if input.ClientID != nil {
		next.ClientID = strings.TrimSpace(*input.ClientID)
	}
	if input.ClientSecret != "" {
		next.ClientSecret = input.ClientSecret
	}
	if input.RedirectURL != nil {
		next.RedirectURL = strings.TrimSpace(*input.RedirectURL)
	}
	if input.Scopes != nil {
		next.Scopes = strings.Join(strings.Fields(*input.Scopes), " ")
	}
	if err := next.Validate(); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if next.Enabled {
		if _, _, err := getOIDCProvider(r.Context(), next); err != nil {
			http.Error(w, "Could not discover OIDC provider. Verify the issuer and HTTPS connectivity.", 400)
			return
		}
	}
	conf.OIDC = next
	if err := conf.SaveConfig(); err != nil {
		http.Error(w, "Could not save settings", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{"message": "Saved. Sign in again if OIDC settings changed. Local login remains available."})
}
