package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/webauthnsvc"
)

// harness bundles a Server with its fakes and a mutable clock.
type harness struct {
	srv      *Server
	store    *fakeStore
	sessions *fakeSessions
	cer      *fakeCeremonies
	now      time.Time
	h        http.Handler
}

func newHarness(t *testing.T, opts ...Option) *harness {
	t.Helper()
	h := &harness{
		store:    newFakeStore(),
		sessions: newFakeSessions(),
		cer:      &fakeCeremonies{},
		now:      time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC),
	}
	cfg := model.Config{Server: model.ServerConfig{Admin: model.ListenConfig{Host: "127.0.0.1", Port: 7070}}}
	base := []Option{WithClock(func() time.Time { return h.now })}
	srv, err := New(cfg, h.store, h.sessions, h.cer, append(base, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.srv = srv
	h.h = srv.Handler()
	return h
}

// authed returns a request cookie for a freshly created valid session, along
// with a matching CSRF token.
func (h *harness) authed() (*http.Cookie, string) {
	sess := h.sessions.put()
	return &http.Cookie{Name: SessionCookieName, Value: sess.ID}, "csrf-" + sess.ID
}

// do executes a request against the handler and returns the recorder.
func (h *harness) do(method, path string, body any, mutate func(*http.Request)) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.RemoteAddr = "127.0.0.1:5555"
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return m
}

// ---- middleware: headers, auth guard, CSRF, CORS --------------------------

func TestSecurityHeadersPresent(t *testing.T) {
	h := newHarness(t)
	rec := h.do(http.MethodGet, "/admin/me", nil, nil)
	hdr := rec.Header()
	if !strings.Contains(hdr.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Errorf("CSP = %q, want default-src 'self'", hdr.Get("Content-Security-Policy"))
	}
	if hdr.Get("X-Frame-Options") != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", hdr.Get("X-Frame-Options"))
	}
	if hdr.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", hdr.Get("X-Content-Type-Options"))
	}
	if hdr.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", hdr.Get("Referrer-Policy"))
	}
}

func TestGuardRejectsUnauthenticated(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/admin/me", "/admin/api/accounts", "/admin/csrf"} {
		rec := h.do(http.MethodGet, p, nil, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s unauth = %d, want 401", p, rec.Code)
		}
	}
}

func TestGuardRejectsInvalidSession(t *testing.T) {
	h := newHarness(t)
	rec := h.do(http.MethodGet, "/admin/me", nil, func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "does-not-exist"})
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid session = %d, want 401", rec.Code)
	}
	// The stale cookie should be cleared.
	if !strings.Contains(rec.Header().Get("Set-Cookie"), SessionCookieName+"=;") &&
		!strings.Contains(rec.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Errorf("expected cleared cookie, got %q", rec.Header().Get("Set-Cookie"))
	}
}

func TestCSRFRequiredOnStateChanging(t *testing.T) {
	h := newHarness(t)
	cookie, _ := h.authed()
	// No CSRF header -> 403.
	rec := h.do(http.MethodPost, "/admin/logout", nil, func(r *http.Request) {
		r.AddCookie(cookie)
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF = %d, want 403", rec.Code)
	}
	// Wrong CSRF -> 403.
	rec = h.do(http.MethodPost, "/admin/logout", nil, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, "bogus")
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad CSRF = %d, want 403", rec.Code)
	}
}

func TestCORSLoopbackAlias(t *testing.T) {
	h := newHarness(t) // origin resolves to http://127.0.0.1:7070
	cookie, _ := h.authed()

	// A loopback alias (localhost) on the same scheme+port is accepted, and the
	// ACAO echoes the request origin so credentialed CORS works.
	rec := h.do(http.MethodGet, "/admin/me", nil, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set("Origin", "http://localhost:7070")
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback alias = %d, want 200", rec.Code)
	}
	if acao := rec.Header().Get("Access-Control-Allow-Origin"); acao != "http://localhost:7070" {
		t.Errorf("ACAO = %q, want the request origin echoed", acao)
	}

	// A loopback host on a DIFFERENT port is still cross-origin -> 403.
	rec = h.do(http.MethodGet, "/admin/me", nil, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set("Origin", "http://localhost:9999")
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("different-port loopback = %d, want 403", rec.Code)
	}

	// A non-loopback host is rejected even on the same port.
	rec = h.do(http.MethodGet, "/admin/me", nil, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set("Origin", "http://10.0.0.5:7070")
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-loopback host = %d, want 403", rec.Code)
	}
}

func TestCORSSameOrigin(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.authed()

	// Cross-origin -> 403 before the handler runs.
	rec := h.do(http.MethodGet, "/admin/me", nil, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set("Origin", "https://evil.example")
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin = %d, want 403", rec.Code)
	}

	// Same-origin -> allowed + ACAO echoed.
	rec = h.do(http.MethodGet, "/admin/me", nil, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set("Origin", h.srv.Origin())
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("same-origin = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != h.srv.Origin() {
		t.Errorf("ACAO = %q, want %q", rec.Header().Get("Access-Control-Allow-Origin"), h.srv.Origin())
	}

	// Same-origin preflight -> 204.
	rec = h.do(http.MethodOptions, "/admin/api/accounts", nil, func(r *http.Request) {
		r.Header.Set("Origin", h.srv.Origin())
	})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight = %d, want 204", rec.Code)
	}
	_ = csrf
}

// ---- login / recovery / logout / sessions ---------------------------------

func TestLoginFinishSuccessSetsCookie(t *testing.T) {
	h := newHarness(t)
	rec := h.do(http.MethodPost, "/admin/login/finish",
		map[string]any{"challenge_id": "c", "credential": json.RawMessage(`{}`)}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login finish = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), SessionCookieName+"=") {
		t.Errorf("expected session cookie, got %q", rec.Header().Get("Set-Cookie"))
	}
}

func TestLoginBeginNoCredentials(t *testing.T) {
	h := newHarness(t)
	h.cer.beginLoginErr = webauthnsvc.ErrNoCredentials
	rec := h.do(http.MethodPost, "/admin/login/begin", nil, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("login begin (no creds) = %d, want 400", rec.Code)
	}
}

func TestLoginBeginOK(t *testing.T) {
	h := newHarness(t)
	rec := h.do(http.MethodPost, "/admin/login/begin", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login begin = %d, want 200", rec.Code)
	}
	m := decodeBody(t, rec)
	if m["challenge_id"] != "chal-login" {
		t.Errorf("challenge_id = %v, want chal-login", m["challenge_id"])
	}
}

func TestRecoveryLoginSuccessAndFailure(t *testing.T) {
	h := newHarness(t)
	h.sessions.recoveryOK["good-code"] = true

	rec := h.do(http.MethodPost, "/admin/login/recovery", map[string]any{"code": "good-code"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("recovery ok = %d, want 200", rec.Code)
	}
	rec = h.do(http.MethodPost, "/admin/login/recovery", map[string]any{"code": "nope"}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("recovery bad = %d, want 401", rec.Code)
	}
}

func TestLogoutAndRevokeAll(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.authed()
	rec := h.do(http.MethodPost, "/admin/logout", nil, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("logout = %d, want 200", rec.Code)
	}

	cookie2, csrf2 := h.authed()
	h.sessions.put() // another session to revoke
	rec = h.do(http.MethodPost, "/admin/sessions/revoke-all", nil, func(r *http.Request) {
		r.AddCookie(cookie2)
		r.Header.Set(CSRFHeaderName, csrf2)
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke-all = %d, want 200", rec.Code)
	}
	if len(h.sessions.sessions) != 0 {
		t.Errorf("sessions after revoke-all = %d, want 0", len(h.sessions.sessions))
	}
}

func TestCSRFAndMe(t *testing.T) {
	h := newHarness(t)
	cookie, _ := h.authed()
	rec := h.do(http.MethodGet, "/admin/csrf", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusOK {
		t.Fatalf("csrf = %d, want 200", rec.Code)
	}
	m := decodeBody(t, rec)
	if !strings.HasPrefix(m["csrf_token"].(string), "csrf-") {
		t.Errorf("csrf_token = %v", m["csrf_token"])
	}

	rec = h.do(http.MethodGet, "/admin/me", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusOK {
		t.Fatalf("me = %d, want 200", rec.Code)
	}
	if decodeBody(t, rec)["operator"] != "operator" {
		t.Errorf("me operator missing")
	}
}

// ---- registration ---------------------------------------------------------

func TestRegisterFirstPasskeyBootstrap(t *testing.T) {
	h := newHarness(t)
	// Begin with a bootstrap token (no session cookie).
	rec := h.do(http.MethodPost, "/admin/register/begin",
		map[string]any{"bootstrap_token": "pgbt_x"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("register begin = %d body=%s", rec.Code, rec.Body.String())
	}
	if h.cer.lastGate.BootstrapToken != "pgbt_x" {
		t.Errorf("gate bootstrap = %q, want pgbt_x", h.cer.lastGate.BootstrapToken)
	}

	// Finish -> session cookie + recovery codes (shown once).
	rec = h.do(http.MethodPost, "/admin/register/finish",
		map[string]any{"bootstrap_token": "pgbt_x", "challenge_id": "chal-reg", "credential": json.RawMessage(`{}`)}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("register finish = %d body=%s", rec.Code, rec.Body.String())
	}
	m := decodeBody(t, rec)
	codes, ok := m["recovery_codes"].([]any)
	if !ok || len(codes) != 2 {
		t.Fatalf("recovery_codes = %v, want 2", m["recovery_codes"])
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), SessionCookieName+"=") {
		t.Errorf("expected session cookie after register")
	}
}

func TestRegisterAdditionalRequiresCSRF(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.authed()

	// With a session cookie but no CSRF -> 403.
	rec := h.do(http.MethodPost, "/admin/register/begin", map[string]any{}, func(r *http.Request) {
		r.AddCookie(cookie)
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("register begin (no csrf) = %d, want 403", rec.Code)
	}

	// With CSRF -> the gate carries the session id, no recovery codes on finish.
	rec = h.do(http.MethodPost, "/admin/register/finish",
		map[string]any{"challenge_id": "chal-reg", "credential": json.RawMessage(`{}`)}, func(r *http.Request) {
			r.AddCookie(cookie)
			r.Header.Set(CSRFHeaderName, csrf)
		})
	if rec.Code != http.StatusOK {
		t.Fatalf("register finish (session) = %d body=%s", rec.Code, rec.Body.String())
	}
	if _, has := decodeBody(t, rec)["recovery_codes"]; has {
		t.Errorf("additional passkey should not mint recovery codes")
	}
	if h.cer.lastGate.SessionID == "" {
		t.Errorf("gate should carry session id for additional passkey")
	}
}

func TestRegisterNotAuthorized(t *testing.T) {
	h := newHarness(t)
	h.cer.beginRegErr = webauthnsvc.ErrNotAuthorized
	rec := h.do(http.MethodPost, "/admin/register/begin", map[string]any{}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("register begin unauthorized = %d, want 401", rec.Code)
	}
}

// ---- resources ------------------------------------------------------------

const fakeAuthJSON = `{"tokens":{"access_token":"at-secret","refresh_token":"rt-secret","account_id":"acc-123","id_token":"idtok"}}`

func TestAccountImportCreatesAccountNoSecrets(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.authed()
	rec := h.do(http.MethodPost, "/admin/api/accounts/import",
		map[string]any{"content": fakeAuthJSON, "label": "acct-1"}, func(r *http.Request) {
			r.AddCookie(cookie)
			r.Header.Set(CSRFHeaderName, csrf)
		})
	if rec.Code != http.StatusCreated {
		t.Fatalf("import = %d body=%s", rec.Code, rec.Body.String())
	}
	// The account was created.
	if len(h.store.accounts) != 1 {
		t.Fatalf("accounts stored = %d, want 1", len(h.store.accounts))
	}
	// No secret material in the response body.
	assertNoSecrets(t, rec.Body.String())
	m := decodeBody(t, rec)
	if m["label"] != "acct-1" || m["account_id"] != "acc-123" {
		t.Errorf("import view = %v", m)
	}
}

func TestAccountImportValidation(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.authed()
	add := func(r *http.Request) { r.AddCookie(cookie); r.Header.Set(CSRFHeaderName, csrf) }

	// Neither content nor path.
	rec := h.do(http.MethodPost, "/admin/api/accounts/import", map[string]any{}, add)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("import empty = %d, want 400", rec.Code)
	}
	// Both content and path.
	rec = h.do(http.MethodPost, "/admin/api/accounts/import",
		map[string]any{"content": fakeAuthJSON, "path": "/x"}, add)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("import both = %d, want 400", rec.Code)
	}
	// Bad content.
	rec = h.do(http.MethodPost, "/admin/api/accounts/import",
		map[string]any{"content": "{}"}, add)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("import bad = %d, want 400", rec.Code)
	}
}

func TestAccountListGetDeleteNoSecrets(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.authed()
	a, _ := h.store.InsertAccount(context.Background(), model.Account{
		Label: "l", AccessToken: "at-secret", RefreshToken: "rt-secret",
		AccountID: "acc-1", State: model.StateOK,
		CreatedAt: h.now, UpdatedAt: h.now,
	})

	rec := h.do(http.MethodGet, "/admin/api/accounts", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusOK {
		t.Fatalf("accounts list = %d", rec.Code)
	}
	assertNoSecrets(t, rec.Body.String())

	rec = h.do(http.MethodGet, "/admin/api/accounts/"+a.ID, nil, func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusOK {
		t.Fatalf("account get = %d", rec.Code)
	}
	assertNoSecrets(t, rec.Body.String())

	// Missing account.
	rec = h.do(http.MethodGet, "/admin/api/accounts/missing", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusNotFound {
		t.Fatalf("account get missing = %d, want 404", rec.Code)
	}

	// Delete happy + missing.
	rec = h.do(http.MethodDelete, "/admin/api/accounts/"+a.ID, nil, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("account delete = %d", rec.Code)
	}
	rec = h.do(http.MethodDelete, "/admin/api/accounts/"+a.ID, nil, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("account delete missing = %d, want 404", rec.Code)
	}
}

func TestApiKeyCreateShowsSecretOnceThenMasks(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.authed()
	add := func(r *http.Request) { r.AddCookie(cookie); r.Header.Set(CSRFHeaderName, csrf) }

	rec := h.do(http.MethodPost, "/admin/api/api_keys", map[string]any{"label": "k1"}, add)
	if rec.Code != http.StatusCreated {
		t.Fatalf("api key create = %d body=%s", rec.Code, rec.Body.String())
	}
	m := decodeBody(t, rec)
	secret, _ := m["key"].(string)
	if !strings.HasPrefix(secret, "sk-") {
		t.Fatalf("create should return full sk- once, got %v", m["key"])
	}

	// List masks the secret.
	rec = h.do(http.MethodGet, "/admin/api/api_keys", nil, func(r *http.Request) { r.AddCookie(cookie) })
	body := rec.Body.String()
	if strings.Contains(body, secret) {
		t.Fatalf("list leaked full key: %s", body)
	}
	if !strings.Contains(body, "sk-…") {
		t.Fatalf("list should mask key, got %s", body)
	}

	// Delete happy + missing.
	var id string
	for kid := range h.store.keys {
		id = kid
	}
	rec = h.do(http.MethodDelete, "/admin/api/api_keys/"+id, nil, add)
	if rec.Code != http.StatusOK {
		t.Fatalf("api key delete = %d", rec.Code)
	}
	rec = h.do(http.MethodDelete, "/admin/api/api_keys/"+id, nil, add)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("api key delete missing = %d, want 404", rec.Code)
	}
}

func TestEndpointAndPolicyGroupCRUD(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.authed()
	add := func(r *http.Request) { r.AddCookie(cookie); r.Header.Set(CSRFHeaderName, csrf) }

	// Create group (valid strategy).
	rec := h.do(http.MethodPost, "/admin/api/policy_groups",
		map[string]any{"name": "g1", "strategy": "fallback"}, add)
	if rec.Code != http.StatusCreated {
		t.Fatalf("group create = %d body=%s", rec.Code, rec.Body.String())
	}
	gid := decodeBody(t, rec)["id"].(string)

	// Invalid strategy -> 400.
	rec = h.do(http.MethodPost, "/admin/api/policy_groups",
		map[string]any{"name": "bad", "strategy": "round-robin"}, add)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("group create bad strategy = %d, want 400", rec.Code)
	}
	// Missing name -> 400.
	rec = h.do(http.MethodPost, "/admin/api/policy_groups", map[string]any{"strategy": "fallback"}, add)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("group create no name = %d, want 400", rec.Code)
	}

	// Patch group: strategy + members.
	rec = h.do(http.MethodPatch, "/admin/api/policy_groups/"+gid,
		map[string]any{"strategy": "best-quota", "member_account_ids": []string{"a1"}}, add)
	if rec.Code != http.StatusOK {
		t.Fatalf("group patch = %d body=%s", rec.Code, rec.Body.String())
	}
	if h.store.groups[gid].Strategy != model.StrategyBestQuota {
		t.Errorf("patched strategy = %q", h.store.groups[gid].Strategy)
	}
	// Patch invalid strategy -> 400.
	rec = h.do(http.MethodPatch, "/admin/api/policy_groups/"+gid, map[string]any{"strategy": "x"}, add)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("group patch bad = %d, want 400", rec.Code)
	}
	// Patch missing group -> 404.
	rec = h.do(http.MethodPatch, "/admin/api/policy_groups/missing", map[string]any{}, add)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("group patch missing = %d, want 404", rec.Code)
	}

	// Create endpoint bound to the group.
	rec = h.do(http.MethodPost, "/admin/api/endpoints",
		map[string]any{"name": "prod", "group_id": gid}, add)
	if rec.Code != http.StatusCreated {
		t.Fatalf("endpoint create = %d body=%s", rec.Code, rec.Body.String())
	}
	// Endpoint missing fields -> 400.
	rec = h.do(http.MethodPost, "/admin/api/endpoints", map[string]any{"name": "x"}, add)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("endpoint create no group = %d, want 400", rec.Code)
	}
	// Endpoint unknown group -> 409.
	rec = h.do(http.MethodPost, "/admin/api/endpoints",
		map[string]any{"name": "y", "group_id": "nope"}, add)
	if rec.Code != http.StatusConflict {
		t.Fatalf("endpoint create bad group = %d, want 409", rec.Code)
	}

	// Deleting the group while an endpoint references it -> 409.
	rec = h.do(http.MethodDelete, "/admin/api/policy_groups/"+gid, nil, add)
	if rec.Code != http.StatusConflict {
		t.Fatalf("group delete referenced = %d, want 409", rec.Code)
	}
	// Delete endpoint, then the group.
	rec = h.do(http.MethodDelete, "/admin/api/endpoints/prod", nil, add)
	if rec.Code != http.StatusOK {
		t.Fatalf("endpoint delete = %d", rec.Code)
	}
	rec = h.do(http.MethodDelete, "/admin/api/policy_groups/"+gid, nil, add)
	if rec.Code != http.StatusOK {
		t.Fatalf("group delete = %d", rec.Code)
	}
	rec = h.do(http.MethodDelete, "/admin/api/policy_groups/"+gid, nil, add)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("group delete missing = %d, want 404", rec.Code)
	}
	// Delete missing endpoint -> 404.
	rec = h.do(http.MethodDelete, "/admin/api/endpoints/ghost", nil, add)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("endpoint delete missing = %d, want 404", rec.Code)
	}

	// List endpoints + groups (empty-safe JSON arrays).
	rec = h.do(http.MethodGet, "/admin/api/endpoints", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "endpoints") {
		t.Fatalf("endpoints list = %d %s", rec.Code, rec.Body.String())
	}
	rec = h.do(http.MethodGet, "/admin/api/policy_groups", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "policy_groups") {
		t.Fatalf("groups list = %d %s", rec.Code, rec.Body.String())
	}
}

func TestUsageHealthStatus(t *testing.T) {
	h := newHarness(t)
	cookie, _ := h.authed()
	get := func(r *http.Request) { r.AddCookie(cookie) }

	a, _ := h.store.InsertAccount(context.Background(), model.Account{Label: "l", State: model.StateOK})
	h.store.usage[a.ID] = model.UsageSnapshot{
		AccountID: a.ID, PlanType: "plus",
		Windows: []model.UsageWindow{{Name: "primary", UsedPercent: 40}},
	}
	h.store.checks[a.ID] = []model.HealthCheck{{AccountID: a.ID, Kind: model.HealthKindUsagePoll, OK: true}}

	// Add a second account with no usage snapshot to exercise the not-found branch.
	h.store.InsertAccount(context.Background(), model.Account{Label: "l2", State: model.StateUnknown})

	for _, p := range []string{"/admin/api/usage", "/admin/api/health", "/admin/api/status"} {
		rec := h.do(http.MethodGet, p, nil, get)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d body=%s", p, rec.Code, rec.Body.String())
		}
	}
	rec := h.do(http.MethodGet, "/admin/api/status", nil, get)
	m := decodeBody(t, rec)
	if m["schema_version"].(float64) != 3 {
		t.Errorf("status schema_version = %v, want 3", m["schema_version"])
	}
}

func TestSettings(t *testing.T) {
	h := newHarness(t)
	h.cer.rpID = "poolgate.example"
	cookie, _ := h.authed()

	// Guarded: no cookie → 401.
	if rec := h.do(http.MethodGet, "/admin/api/settings", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated settings = %d, want 401", rec.Code)
	}

	rec := h.do(http.MethodGet, "/admin/api/settings", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusOK {
		t.Fatalf("GET settings = %d body=%s", rec.Code, rec.Body.String())
	}
	m := decodeBody(t, rec)
	if m["rp_id"] != "poolgate.example" {
		t.Errorf("rp_id = %v, want poolgate.example", m["rp_id"])
	}
	if origin, _ := m["origin"].(string); origin == "" {
		t.Errorf("origin is empty, want the resolved admin origin")
	}
	// The response must never carry a secret or token field.
	for _, k := range []string{"secret", "token", "bootstrap_token", "csrf_token"} {
		if _, ok := m[k]; ok {
			t.Errorf("settings response leaked %q", k)
		}
	}
}

// ---- rate-limit / lockout -------------------------------------------------

func TestRecoveryLockout(t *testing.T) {
	h := newHarness(t, WithRateLimit(3, time.Minute, 10*time.Minute))
	// 3 failures arm the lockout.
	for i := 0; i < 3; i++ {
		rec := h.do(http.MethodPost, "/admin/login/recovery", map[string]any{"code": "bad"}, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i, rec.Code)
		}
	}
	// 4th attempt is locked out.
	rec := h.do(http.MethodPost, "/admin/login/recovery", map[string]any{"code": "bad"}, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("locked = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on lockout")
	}
	// After the lockout elapses, attempts resume.
	h.now = h.now.Add(11 * time.Minute)
	rec = h.do(http.MethodPost, "/admin/login/recovery", map[string]any{"code": "bad"}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("post-lockout = %d, want 401", rec.Code)
	}
}

func TestSuccessfulLoginResetsFailures(t *testing.T) {
	h := newHarness(t, WithRateLimit(3, time.Minute, 10*time.Minute))
	h.sessions.recoveryOK["good"] = true
	// Two failures, then a success resets the counter.
	for i := 0; i < 2; i++ {
		h.do(http.MethodPost, "/admin/login/recovery", map[string]any{"code": "bad"}, nil)
	}
	rec := h.do(http.MethodPost, "/admin/login/recovery", map[string]any{"code": "good"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("success = %d, want 200", rec.Code)
	}
	// Three more failures should be needed to lock out again (counter reset).
	for i := 0; i < 2; i++ {
		rec = h.do(http.MethodPost, "/admin/login/recovery", map[string]any{"code": "bad"}, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("post-reset attempt %d = %d, want 401", i, rec.Code)
		}
	}
}

// ---- error branches -------------------------------------------------------

func TestBadJSONBodies(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.authed()
	add := func(r *http.Request) { r.AddCookie(cookie); r.Header.Set(CSRFHeaderName, csrf) }
	for _, p := range []string{
		"/admin/api/accounts/import", "/admin/api/api_keys",
		"/admin/api/endpoints", "/admin/api/policy_groups",
	} {
		req := httptest.NewRequest(http.MethodPost, p, strings.NewReader("{bad json"))
		req.RemoteAddr = "127.0.0.1:1"
		req.AddCookie(cookie)
		req.Header.Set(CSRFHeaderName, csrf)
		rec := httptest.NewRecorder()
		h.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST %s bad json = %d, want 400", p, rec.Code)
		}
	}
	_ = add
}

func TestListErrorsReturn500(t *testing.T) {
	h := newHarness(t)
	h.store.failList = true
	cookie, _ := h.authed()
	get := func(r *http.Request) { r.AddCookie(cookie) }
	for _, p := range []string{
		"/admin/api/accounts", "/admin/api/api_keys", "/admin/api/endpoints",
		"/admin/api/policy_groups", "/admin/api/usage", "/admin/api/health", "/admin/api/status",
	} {
		rec := h.do(http.MethodGet, p, nil, get)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("GET %s (store fail) = %d, want 500", p, rec.Code)
		}
	}
}

func TestNewRejectsNilAndBadOrigin(t *testing.T) {
	cfg := model.Config{}
	if _, err := New(cfg, nil, newFakeSessions(), &fakeCeremonies{}); err == nil {
		t.Error("New(nil store) = nil err")
	}
	badCfg := model.Config{Server: model.ServerConfig{Admin: model.ListenConfig{ExternalOrigin: "://bad"}}}
	if _, err := New(badCfg, newFakeStore(), newFakeSessions(), &fakeCeremonies{}); err == nil {
		t.Error("New(bad origin) = nil err")
	}
}

// assertNoSecrets fails if any known secret marker appears in the body.
func assertNoSecrets(t *testing.T, body string) {
	t.Helper()
	for _, secret := range []string{"at-secret", "rt-secret", "idtok", "access_token", "refresh_token"} {
		if strings.Contains(body, secret) {
			t.Fatalf("response leaked secret %q: %s", secret, body)
		}
	}
}
