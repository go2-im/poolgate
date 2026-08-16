package admin

import (
	"net/http"
	"strings"
	"testing"
)

// TestApiKeyLifecycleFields covers create with expiry + IP allowlist (valid +
// invalid), that the view exposes them secret-free, and the rotate action.
func TestApiKeyLifecycleFields(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.authed()
	add := func(r *http.Request) { r.AddCookie(cookie); r.Header.Set(CSRFHeaderName, csrf) }

	// Valid create with expiry + allowlist.
	rec := h.do(http.MethodPost, "/admin/api/api_keys", map[string]any{
		"label":        "scoped",
		"expires_at":   "2099-01-02T15:04:05Z",
		"ip_allowlist": []string{"203.0.113.4", "10.0.0.0/8"},
	}, add)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d body=%s", rec.Code, rec.Body.String())
	}
	m := decodeBody(t, rec)
	if m["expires_at"] != "2099-01-02T15:04:05Z" {
		t.Errorf("expires_at = %v, want the RFC3339 value back", m["expires_at"])
	}
	allow, _ := m["ip_allowlist"].([]any)
	if len(allow) != 2 {
		t.Errorf("ip_allowlist = %v, want 2 entries", m["ip_allowlist"])
	}
	secret, _ := m["key"].(string)
	if !strings.HasPrefix(secret, "sk-") {
		t.Fatalf("create should return the sk- secret once")
	}
	id, _ := m["id"].(string)

	// Invalid expiry → 400.
	rec = h.do(http.MethodPost, "/admin/api/api_keys",
		map[string]any{"label": "bad", "expires_at": "not-a-time"}, add)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad expires_at = %d, want 400", rec.Code)
	}
	// Invalid IP allowlist entry → 400.
	rec = h.do(http.MethodPost, "/admin/api/api_keys",
		map[string]any{"label": "bad", "ip_allowlist": []string{"not-an-ip"}}, add)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad ip_allowlist = %d, want 400", rec.Code)
	}

	// Rotate: new secret returned once; it differs from the original.
	rec = h.do(http.MethodPost, "/admin/api/api_keys/"+id+"/rotate", map[string]any{}, add)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate = %d body=%s", rec.Code, rec.Body.String())
	}
	rm := decodeBody(t, rec)
	rotated, _ := rm["key"].(string)
	if !strings.HasPrefix(rotated, "sk-") || rotated == secret {
		t.Errorf("rotate should return a NEW sk- secret, got %q (orig %q)", rotated, secret)
	}
	// The rotated key preserves the expiry/allowlist.
	if rm["expires_at"] != "2099-01-02T15:04:05Z" {
		t.Errorf("rotate lost expiry: %v", rm["expires_at"])
	}

	// Rotate a missing id → 404.
	rec = h.do(http.MethodPost, "/admin/api/api_keys/nope/rotate", map[string]any{}, add)
	if rec.Code != http.StatusNotFound {
		t.Errorf("rotate missing = %d, want 404", rec.Code)
	}
}
