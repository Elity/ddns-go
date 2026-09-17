package web

import (
	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

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
