package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// ---- small unit helpers ---------------------------------------------------

func TestMaskKey(t *testing.T) {
	if got := maskKey("sk-abcdef1234"); got != "sk-…1234" {
		t.Errorf("maskKey long = %q", got)
	}
	if got := maskKey("sk-"); got != "sk-…" {
		t.Errorf("maskKey short = %q", got)
	}
}

func TestClientIP(t *testing.T) {
	s := &Server{} // no trusted proxies -> peer address only, X-Forwarded-For ignored
	r := httptest.NewRequest(http.MethodGet, "/admin/me", nil)
	r.RemoteAddr = "10.0.0.5:1234"
	if got := s.clientIP(r); got != "10.0.0.5" {
		t.Errorf("clientIP with port = %q, want 10.0.0.5", got)
	}
	r.RemoteAddr = "no-port"
	if got := s.clientIP(r); got != "no-port" {
		t.Errorf("clientIP no port = %q, want no-port", got)
	}
	// A spoofed X-Forwarded-For from an untrusted peer must be ignored.
	r.RemoteAddr = "10.0.0.5:1234"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := s.clientIP(r); got != "10.0.0.5" {
		t.Errorf("clientIP with untrusted XFF = %q, want 10.0.0.5 (peer)", got)
	}
}

func TestNewLimiterDefaults(t *testing.T) {
	l := newLimiter(0, 0, 0, nil)
	if l.maxFailures != defaultMaxFailures || l.window != defaultBruteWindow || l.lockout != defaultLockout {
		t.Fatalf("newLimiter defaults not applied: maxFailures=%d window=%s lockout=%s",
			l.maxFailures, l.window, l.lockout)
	}
	if !l.Allow("k") {
		t.Error("fresh key should be allowed")
	}
}

func TestResolveOriginHTTPSSecure(t *testing.T) {
	origin, secure, err := resolveOrigin(model.ListenConfig{ExternalOrigin: "https://poolgate.example.com"})
	if err != nil {
		t.Fatalf("resolveOrigin: %v", err)
	}
	if origin != "https://poolgate.example.com" || !secure {
		t.Fatalf("resolveOrigin = (%q,%v), want https + secure", origin, secure)
	}
}

func TestWithRecoveryCodeCount(t *testing.T) {
	h := newHarness(t, WithRecoveryCodeCount(2))
	if h.srv.recovery != 2 {
		t.Fatalf("recovery count = %d, want 2", h.srv.recovery)
	}
}

// ---- internal-error (500) branches ----------------------------------------

func TestSessionCreateFailuresReturn500(t *testing.T) {
	// login finish, recovery, and register finish all mint a session; a failing
	// session backend must surface as 500.
	t.Run("login-finish", func(t *testing.T) {
		h := newHarness(t)
		h.sessions.failCreate = true
		rec := h.do(http.MethodPost, "/admin/login/finish",
			map[string]any{"challenge_id": "c", "credential": nil}, nil)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("= %d, want 500", rec.Code)
		}
	})
	t.Run("recovery", func(t *testing.T) {
		h := newHarness(t)
		h.sessions.recoveryOK["ok"] = true
		h.sessions.failCreate = true
		rec := h.do(http.MethodPost, "/admin/login/recovery", map[string]any{"code": "ok"}, nil)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("= %d, want 500", rec.Code)
		}
	})
	t.Run("register-finish-rotate", func(t *testing.T) {
		h := newHarness(t)
		h.sessions.failCreate = true
		rec := h.do(http.MethodPost, "/admin/register/finish",
			map[string]any{"bootstrap_token": "pgbt", "challenge_id": "chal-reg", "credential": nil}, nil)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("= %d, want 500", rec.Code)
		}
	})
}

func TestRegisterFinishGenCodesFailure(t *testing.T) {
	h := newHarness(t)
	h.sessions.failGenCodes = true
	rec := h.do(http.MethodPost, "/admin/register/finish",
		map[string]any{"bootstrap_token": "pgbt", "challenge_id": "chal-reg", "credential": nil}, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("gen codes fail = %d, want 500", rec.Code)
	}
}

func TestCSRFIssueFailure(t *testing.T) {
	h := newHarness(t)
	h.sessions.failCSRF = true
	cookie, _ := h.authed()
	rec := h.do(http.MethodGet, "/admin/csrf", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("csrf issue fail = %d, want 500", rec.Code)
	}
}

func TestRecoveryBackendErrorReturn500(t *testing.T) {
	h := newHarness(t)
	h.sessions.failRecovery = true
	rec := h.do(http.MethodPost, "/admin/login/recovery", map[string]any{"code": "x"}, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("recovery backend err = %d, want 500", rec.Code)
	}
}

func TestRegisterFinishNotAuthorized(t *testing.T) {
	h := newHarness(t)
	h.cer.finishRegErr = errNotAuthorizedForTest()
	rec := h.do(http.MethodPost, "/admin/register/finish",
		map[string]any{"bootstrap_token": "pgbt", "challenge_id": "chal-reg", "credential": nil}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("finish not-authorized = %d, want 401", rec.Code)
	}
}

func TestLogoutRevokeFailure(t *testing.T) {
	// Logout with a valid session but a revoke that errors -> 500. Use a stub
	// SessionManager wrapping the fake to force RevokeSession to fail.
	h := newHarness(t)
	cookie, csrf := h.authed()
	h.srv.sessions = failingRevoke{h.sessions}
	rec := h.do(http.MethodPost, "/admin/logout", nil, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("logout revoke fail = %d, want 500", rec.Code)
	}
}

func TestRevokeAllFailure(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.authed()
	h.srv.sessions = failingRevokeAll{h.sessions}
	rec := h.do(http.MethodPost, "/admin/sessions/revoke-all", nil, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("revoke-all fail = %d, want 500", rec.Code)
	}
}

func TestApiKeyCreateStoreFailure(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.authed()
	h.srv.store = failingInsertKey{h.store}
	rec := h.do(http.MethodPost, "/admin/api/api_keys", map[string]any{"label": "k"}, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("api key store fail = %d, want 500", rec.Code)
	}
}

func TestImportStoreFailure(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.authed()
	h.srv.store = failingInsertAccount{h.store}
	rec := h.do(http.MethodPost, "/admin/api/accounts/import",
		map[string]any{"content": fakeAuthJSON}, func(r *http.Request) {
			r.AddCookie(cookie)
			r.Header.Set(CSRFHeaderName, csrf)
		})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("import store fail = %d, want 500", rec.Code)
	}
}

func TestUsageAndHealthStoreErrors(t *testing.T) {
	// A per-account read error (not the top-level list) must surface as 500.
	h := newHarness(t)
	cookie, _ := h.authed()
	h.store.InsertAccount(context.Background(), model.Account{Label: "l"})
	h.srv.store = failingUsageRead{h.store}
	rec := h.do(http.MethodGet, "/admin/api/usage", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("usage read fail = %d, want 500", rec.Code)
	}
	h.srv.store = failingHealthRead{h.store}
	rec = h.do(http.MethodGet, "/admin/api/health", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("health read fail = %d, want 500", rec.Code)
	}
}

func TestPatchUpdateFailure(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.authed()
	g, _ := h.store.InsertPolicyGroup(context.Background(), model.PolicyGroup{Name: "g", Strategy: model.StrategyFallback})
	h.srv.store = failingUpdateGroup{h.store}
	rec := h.do(http.MethodPatch, "/admin/api/policy_groups/"+g.ID,
		map[string]any{"strategy": "best-quota"}, func(r *http.Request) {
			r.AddCookie(cookie)
			r.Header.Set(CSRFHeaderName, csrf)
		})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("patch update fail = %d, want 500", rec.Code)
	}
}

func TestClockDefaultAndUnusedFields(t *testing.T) {
	// WithClock(nil) keeps the default clock; exercise the guard.
	h := newHarness(t, WithClock(nil))
	if h.srv.now == nil {
		t.Fatal("clock should not be nil")
	}
	// Touch the limiter Reset path on an unknown key (no-op).
	h.srv.limiter.Reset("unknown|1.2.3.4")
	_ = time.Now
}
