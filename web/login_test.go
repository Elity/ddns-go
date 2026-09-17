package web

import (
	"encoding/json"
	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalRecoveryHTTPWithOIDC(t *testing.T) {
	t.Setenv(util.ConfigFilePathENV, filepath.Join(t.TempDir(), "config.yaml"))
	conf := config.Config{OIDC: config.OIDC{Enabled: true}}
	conf.Username = "local"
	conf.Password, _ = util.HashPassword("test-password")
	if err := conf.SaveConfig(); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"Username": "local", "Password": "test-password"})
	r := httptest.NewRequest(http.MethodPost, "http://192.168.1.10:9876/loginFunc", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	LoginFunc(w, r)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Secure {
		t.Fatal("local HTTP login must not issue an unusable Secure cookie")
	}
	for _, secure := range []bool{false, true} {
		scheme := "http"
		if secure {
			scheme = "https"
		}
		r := httptest.NewRequest(http.MethodPost, scheme+"://app.example/loginFunc", strings.NewReader(string(body)))
		r.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()
		LoginFunc(w, r)
		if w.Result().Cookies()[0].Secure != secure {
			t.Fatal("must use actual TLS, not untrusted forwarded headers")
		}
	}
	if !newOIDCSessions().Cookie.Secure {
		t.Fatal("OIDC cookies must remain Secure")
	}
}

func TestLoginAutoOIDC(t *testing.T) {
	t.Setenv(util.ConfigFilePathENV, filepath.Join(t.TempDir(), "config.yaml"))
	for _, tt := range []struct {
		name          string
		enabled, auto bool
		path          string
		status        int
	}{
		{"automatic", true, true, "/login", http.StatusSeeOther},
		{"local recovery", true, true, "/login?local=1", http.StatusOK},
		{"manual OIDC", true, false, "/login", http.StatusOK},
		{"disabled OIDC", false, true, "/login", http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conf := config.Config{OIDC: config.OIDC{Enabled: tt.enabled, AutoLogin: tt.auto}}
			if err := conf.SaveConfig(); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			Login(w, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if w.Code != tt.status {
				t.Fatalf("status %d, want %d", w.Code, tt.status)
			}
			if tt.status == http.StatusSeeOther && w.Header().Get("Location") != "/oidc/start" {
				t.Fatal("missing automatic OIDC redirect")
			}
			if tt.status == http.StatusOK && !strings.Contains(w.Body.String(), `id="Password"`) {
				t.Fatal("local login missing")
			}
		})
	}
}
