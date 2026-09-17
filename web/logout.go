package web

import (
	"net/http"
	"time"
)

func Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := oidcSessions.Destroy(r.Context()); err != nil {
		http.Error(w, "Could not end session", http.StatusInternalServerError)
		return
	}
	// 覆盖cookieInSystem
	cookieInSystem = &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0), // 设置为过期时间
		MaxAge:   -1,              // 立即删除该 Cookie
		HttpOnly: true,
	}
	// 设置过期的 Cookie
	http.SetCookie(w, cookieInSystem)

	// 重定向用户到登录页面
	http.Redirect(w, r, "/login?local=1", http.StatusFound)
}
