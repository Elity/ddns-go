package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOIDCValidate(t *testing.T) {
	valid := OIDC{Enabled: true, Issuer: "https://id.example/", ClientID: "ddns", ClientSecret: "secret-value", RedirectURL: "https://ddns.example/oidc/callback", Scopes: "openid"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*OIDC){func(o *OIDC) { o.Issuer = "http://id.example" }, func(o *OIDC) { o.RedirectURL = "https://ddns.example/wrong" }, func(o *OIDC) { o.Scopes = "profile" }, func(o *OIDC) { o.ClientSecret = "" }} {
		o := valid
		change(&o)
		if o.Validate() == nil {
			t.Fatal("invalid settings accepted")
		}
	}
	b, _ := json.Marshal(valid)
	if strings.Contains(string(b), valid.ClientSecret) {
		t.Fatal("secret leaked in JSON")
	}
}
