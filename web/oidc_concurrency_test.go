package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
)

func delayedProvider(t *testing.T) (config.OIDC, <-chan struct{}, chan struct{}, *atomic.Int32) {
	t.Helper()
	started, release := make(chan struct{}, 1), make(chan struct{})
	calls := &atomic.Int32{}
	var issuer string
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	}))
	issuer = s.URL
	previous := oidcHTTPClient
	oidcHTTPClient = s.Client()
	t.Cleanup(func() { s.Close(); oidcHTTPClient = previous })
	return config.OIDC{Enabled: true, Issuer: issuer, ClientID: "test", ClientSecret: "test-secret", RedirectURL: "https://app.example/oidc/callback", Scopes: "openid"}, started, release, calls
}

func TestDiscoveryWaiterCancellation(t *testing.T) {
	o, started, release, calls := delayedProvider(t)
	done := make(chan error, 1)
	go func() { _, _, err := getOIDCProvider(context.Background(), o); done <- err }()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	waiter := make(chan error, 1)
	go func() { _, _, err := getOIDCProvider(ctx, o); waiter <- err }()
	cancel()
	select {
	case err := <-waiter:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Error("discovery waiter ignored cancellation")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("duplicate discovery requests: %d", calls.Load())
	}
}

func TestOIDCSavePreservesConcurrentConfig(t *testing.T) {
	t.Setenv(util.ConfigFilePathENV, filepath.Join(t.TempDir(), "config.yaml"))
	initial := config.Config{Lang: "en"}
	initial.Username = "local"
	initial.Password = "old-password"
	if err := initial.SaveConfig(); err != nil {
		t.Fatal(err)
	}
	o, started, release, _ := delayedProvider(t)
	data, _ := json.Marshal(map[string]any{"Enabled": true, "Issuer": o.Issuer, "ClientID": o.ClientID, "ClientSecret": o.ClientSecret, "RedirectURL": o.RedirectURL})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		SaveOIDCSettings(w, httptest.NewRequest(http.MethodPost, "/oidc-settings/save", strings.NewReader(string(data))))
		done <- w
	}()
	<-started
	latest, _ := config.GetConfigCached()
	latest.Lang = "zh"
	latest.Password = "new-password"
	latest.WebhookURL = "https://hooks.example/new"
	latest.DnsConf = []config.DnsConfig{{Name: "new-dns-config"}}
	if err := latest.SaveConfig(); err != nil {
		close(release)
		<-done
		t.Fatal(err)
	}
	close(release)
	w := <-done
	if w.Code != http.StatusOK {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	saved, _ := config.GetConfigCached()
	if saved.Lang != latest.Lang || saved.Password != latest.Password || saved.WebhookURL != latest.WebhookURL || len(saved.DnsConf) != 1 {
		t.Fatal("OIDC discovery overwrote concurrent settings")
	}
	if !saved.OIDC.Enabled || saved.OIDC.Issuer != o.Issuer {
		t.Fatal("OIDC not saved")
	}
}

func TestOIDCSaveDetectsConcurrentOIDCChange(t *testing.T) {
	t.Setenv(util.ConfigFilePathENV, filepath.Join(t.TempDir(), "config.yaml"))
	conf := config.Config{}
	conf.Username = "local"
	conf.Password = "hash"
	if err := conf.SaveConfig(); err != nil {
		t.Fatal(err)
	}
	o, started, release, _ := delayedProvider(t)
	body, _ := json.Marshal(map[string]any{"Enabled": true, "Issuer": o.Issuer, "ClientID": o.ClientID, "ClientSecret": o.ClientSecret, "RedirectURL": o.RedirectURL})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		SaveOIDCSettings(w, httptest.NewRequest(http.MethodPost, "/oidc-settings/save", strings.NewReader(string(body))))
		done <- w
	}()
	<-started
	conf.OIDC.ClientID = "changed-by-another-admin"
	if err := conf.SaveConfig(); err != nil {
		close(release)
		<-done
		t.Fatal(err)
	}
	close(release)
	if w := <-done; w.Code != http.StatusConflict {
		t.Fatalf("got %d, want conflict", w.Code)
	}
	saved, _ := config.GetConfigCached()
	if saved.OIDC.ClientID != conf.OIDC.ClientID {
		t.Fatal("lost concurrent OIDC edit")
	}
}
