package config

import (
	"errors"
	"net/url"
	"strings"
)

// OIDC grants access to the existing single-tenant administrator workspace.
// ClientSecret is deliberately excluded from JSON responses.
type OIDC struct {
	Enabled      bool
	AutoLogin    bool
	Issuer       string
	ClientID     string
	ClientSecret string `json:"-"`
	RedirectURL  string
	Scopes       string
}

func (o OIDC) Validate() error {
	if !o.Enabled {
		return nil
	}
	if strings.TrimSpace(o.ClientID) == "" || o.ClientSecret == "" {
		return errors.New("Client ID and client secret are required")
	}
	for _, raw := range []string{o.Issuer, o.RedirectURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("Issuer and callback must be absolute HTTPS URLs without credentials, query or fragment")
		}
	}
	u, _ := url.Parse(o.RedirectURL)
	if u.Path != "/oidc/callback" {
		return errors.New("Callback path must be /oidc/callback")
	}
	if !strings.Contains(" "+strings.Join(strings.Fields(o.Scopes), " ")+" ", " openid ") {
		return errors.New("Scopes must include openid")
	}
	return nil
}
