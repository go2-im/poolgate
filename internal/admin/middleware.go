// middleware.go holds the admin API's cross-cutting HTTP behavior (DESIGN.md §22
// / §3): strict security headers + CSP on every response, same-origin CORS, a
// session-auth guard, and a CSRF check on state-changing methods.
package admin

import (
	"context"
	"net"
	"net/http"
	"net/url"

	"github.com/go2-im/poolgate/internal/model"
)

// ctxKey is the private type for request-context values.
type ctxKey int

const sessionCtxKey ctxKey = iota

// securityHeaders sets a strict header set on every response (DESIGN.md §22):
// a locked-down CSP suitable for the JSON API + a same-origin React app, plus
// framing / sniffing / referrer protections. It wraps the whole router so even
// 404s and errors carry the headers.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// cors enforces same-origin access (DESIGN.md §22.3). Requests without an Origin
// header (curl, native clients) pass through unrestricted. When an Origin is
// present it must equal the resolved admin origin: a match echoes the CORS
// allow-headers (with credentials); a mismatch is rejected with 403 before the
// route runs. Preflight OPTIONS for a same-origin request short-circuits with 204.
func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if !s.originAllowed(origin) {
				writeErr(w, http.StatusForbidden, errForbidden, "cross-origin request rejected")
				return
			}
			h := w.Header()
			// Echo the (validated) request origin — required for credentialed CORS,
			// and lets a loopback alias (localhost vs 127.0.0.1) work.
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Content-Type, "+CSRFHeaderName)
			h.Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// originAllowed reports whether a request Origin may access the admin API. It is
// the resolved admin origin exactly, OR — when that origin is loopback — a
// loopback alias with the same scheme+port (so an operator who opens
// http://localhost:7070 works even though the origin resolved to
// http://127.0.0.1:7070, and vice versa). A genuine cross-site origin (any
// non-loopback host) is still rejected.
func (s *Server) originAllowed(origin string) bool {
	if origin == s.origin {
		return true
	}
	req, err1 := url.Parse(origin)
	self, err2 := url.Parse(s.origin)
	if err1 != nil || err2 != nil {
		return false
	}
	if req.Scheme != self.Scheme || req.Port() != self.Port() {
		return false
	}
	return isLoopbackHost(req.Hostname()) && isLoopbackHost(self.Hostname())
}

// isLoopbackHost reports whether h is a loopback host name or IP.
func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// guard wraps a handler so it runs only for a valid admin session, and — for
// state-changing methods — only with a valid CSRF token. The validated session
// is stashed in the request context for the handler (see sessionFromCtx).
func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.authenticate(w, r)
		if !ok {
			return
		}
		if isStateChanging(r.Method) {
			if !s.sessions.VerifyCSRF(sess.ID, r.Header.Get(CSRFHeaderName)) {
				writeErr(w, http.StatusForbidden, errForbidden, "missing or invalid CSRF token")
				return
			}
		}
		ctx := context.WithValue(r.Context(), sessionCtxKey, sess)
		next(w, r.WithContext(ctx))
	}
}

// authenticate reads the session cookie and validates it. On failure it writes a
// 401 and returns ok=false; the stale cookie is cleared so the browser stops
// resending it.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (model.Session, bool) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		writeErr(w, http.StatusUnauthorized, errUnauthorized, "authentication required")
		return model.Session{}, false
	}
	sess, err := s.sessions.ValidateSession(r.Context(), c.Value)
	if err != nil {
		s.clearSessionCookie(w)
		writeErr(w, http.StatusUnauthorized, errUnauthorized, "session invalid or expired")
		return model.Session{}, false
	}
	return sess, true
}

// sessionFromCtx returns the validated session stashed by guard.
func sessionFromCtx(ctx context.Context) (model.Session, bool) {
	sess, ok := ctx.Value(sessionCtxKey).(model.Session)
	return sess, ok
}

// isStateChanging reports whether the HTTP method mutates state and therefore
// requires a CSRF token.
func isStateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// setSessionCookie writes the admin session cookie for sess.
func (s *Server) setSessionCookie(w http.ResponseWriter, sess model.Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sess.ID,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearSessionCookie expires the admin session cookie.
func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// clientIP extracts the peer IP from RemoteAddr for rate-limit keying. The admin
// listener is loopback / behind the operator's own proxy, so forwarded headers
// are intentionally NOT trusted here (DESIGN.md §14).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
