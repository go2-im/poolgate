package admin

import (
	"net/http"
	"strings"
	"testing"
)

// TestAuditLogRecordsActions performs a few mutating admin actions and asserts
// each is recorded in the append-only audit log and surfaced by GET
// /admin/api/audit (newest-first), secret-free.
func TestAuditLogRecordsActions(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.authed()
	mut := func(r *http.Request) { r.AddCookie(cookie); r.Header.Set(CSRFHeaderName, csrf) }

	// Create an api key (audited as apikey.create) and capture its secret.
	rec := h.do(http.MethodPost, "/admin/api/api_keys", map[string]any{"label": "audited"}, mut)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create key = %d", rec.Code)
	}
	secret, _ := decodeBody(t, rec)["key"].(string)

	// Revoke all sessions (audited as auth.revoke_all_sessions).
	if rec := h.do(http.MethodPost, "/admin/sessions/revoke-all", map[string]any{}, mut); rec.Code != http.StatusOK {
		t.Fatalf("revoke-all = %d", rec.Code)
	}

	// Read the audit log (re-auth: revoke-all killed the session).
	cookie2, _ := h.authed()
	rec = h.do(http.MethodGet, "/admin/api/audit", nil, func(r *http.Request) { r.AddCookie(cookie2) })
	if rec.Code != http.StatusOK {
		t.Fatalf("audit list = %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"apikey.create", "auth.revoke_all_sessions"} {
		if !strings.Contains(body, want) {
			t.Errorf("audit log missing %q; body=%s", want, body)
		}
	}
	// The audit log must never contain the actual key secret.
	if secret != "" && strings.Contains(body, secret) {
		t.Errorf("audit log leaked the api key secret")
	}

	// Entries are newest-first: parse and confirm the first entry is the most
	// recent action (revoke-all happened after create).
	m := decodeBody(t, rec)
	entries, _ := m["audit"].([]any)
	if len(entries) < 2 {
		t.Fatalf("want >=2 audit entries, got %d", len(entries))
	}
	first, _ := entries[0].(map[string]any)
	if first["action"] != "auth.revoke_all_sessions" {
		t.Errorf("newest entry action = %v, want auth.revoke_all_sessions", first["action"])
	}
}
