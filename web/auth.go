package web

import (
	"net/http"
	"time"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
)

// ViewFunc func
type ViewFunc func(http.ResponseWriter, *http.Request)

// Auth 验证Token是否已经通过
func Auth(f ViewFunc) ViewFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		conf, _ := config.GetConfigCached()
		if conf.NotAllowWanAccess && !util.IsPrivateNetwork(r.RemoteAddr) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if oidcAuthenticated(r, conf.OIDC) {
			f(w, r)
			return
		}
		cookieInWeb, err := r.Cookie(cookieName)
		if err != nil {
			requireLogin(w, r)
			return
		}

		// 验证token
		if cookieInSystem.Value != "" &&
			cookieInSystem.Value == cookieInWeb.Value &&
			cookieInSystem.Expires.After(time.Now()) {
			f(w, r) // 执行被装饰的函数
			return
		}

		requireLogin(w, r)
	}
}

func requireLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// PostOnly prevents safe-method navigations from changing application state.
func PostOnly(next ViewFunc) ViewFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

// AuthAssert 保护静态等文件不被公网访问
func AuthAssert(f ViewFunc) ViewFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		conf, err := config.GetConfigCached()

		// 配置文件为空, 启动时间超过3小时禁止从公网访问
		if err != nil &&
			time.Since(startTime) > time.Duration(3*time.Hour) && !util.IsPrivateNetwork(r.RemoteAddr) {
			w.WriteHeader(http.StatusForbidden)
			util.Log("%q 配置文件为空, 超过3小时禁止从公网访问", util.GetRequestIPStr(r))
			return
		}

		// 禁止公网访问
		if conf.NotAllowWanAccess {
			if !util.IsPrivateNetwork(r.RemoteAddr) {
				w.WriteHeader(http.StatusForbidden)
				util.Log("%q 被禁止从公网访问", util.GetRequestIPStr(r))
				return
			}
		}

		f(w, r) // 执行被装饰的函数

	}
}
