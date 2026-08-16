package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// testServer starts a gateway over the fixture's store on an httptest server.
func testServer(t *testing.T, f *fixture) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(New(f.st, f.cfg).Routes())
	t.Cleanup(srv.Close)
	return srv
}

// postWithKey sends a proxy request bearing the given inbound key and returns the
// status code + decoded error type (if any).
func postWithKey(t *testing.T, url, key string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url+"/e/default/v1/responses",
		strings.NewReader(`{"model":"gpt-5"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	var eb errorBody
	_ = json.NewDecoder(resp.Body).Decode(&eb)
	return resp.StatusCode, eb.Error.Type
}

// TestKeyExpiryRejected: an expired key is refused at auth with key_expired.
func TestKeyExpiryRejected(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	const key = "sk-expired-key-0"
	if _, err := f.st.InsertApiKey(ctx, model.ApiKey{
		Key: key, Label: "e", Endpoints: []string{"default"},
		ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("InsertApiKey: %v", err)
	}
	srv := testServer(t, f)

	status, typ := postWithKey(t, srv.URL, key)
	if status != http.StatusUnauthorized || typ != "poolgate_key_expired" {
		t.Fatalf("expired key: status=%d type=%q, want 401 poolgate_key_expired", status, typ)
	}
}

// TestKeyIPAllowlistDenied: a key whose allowlist excludes the loopback peer is
// refused with key_ip_denied.
func TestKeyIPAllowlistDenied(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	const key = "sk-ipdenied-key0"
	if _, err := f.st.InsertApiKey(ctx, model.ApiKey{
		Key: key, Label: "d", Endpoints: []string{"default"},
		IPAllowlist: []string{"10.0.0.0/8"}, // loopback (127.0.0.1) is NOT in this
	}); err != nil {
		t.Fatalf("InsertApiKey: %v", err)
	}
	srv := testServer(t, f)

	status, typ := postWithKey(t, srv.URL, key)
	if status != http.StatusForbidden || typ != "poolgate_key_ip_denied" {
		t.Fatalf("ip-denied key: status=%d type=%q, want 403 poolgate_key_ip_denied", status, typ)
	}
}

// TestKeyIPAllowlistAllowed: a key whose allowlist includes the loopback peer
// passes the IP gate (it then fails later against the absent upstream, but the
// point is it is NOT rejected as key_ip_denied).
func TestKeyIPAllowlistAllowed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	const key = "sk-ipok-key-000"
	if _, err := f.st.InsertApiKey(ctx, model.ApiKey{
		Key: key, Label: "ok", Endpoints: []string{"default"},
		IPAllowlist: []string{"127.0.0.1", "::1"},
	}); err != nil {
		t.Fatalf("InsertApiKey: %v", err)
	}
	srv := testServer(t, f)

	status, typ := postWithKey(t, srv.URL, key)
	if status == http.StatusForbidden && typ == "poolgate_key_ip_denied" {
		t.Fatalf("loopback allowlist should pass the IP gate, got 403 key_ip_denied")
	}
}
