package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go2-im/poolgate/internal/config"
	"github.com/go2-im/poolgate/internal/gateway"
	"github.com/go2-im/poolgate/internal/model"
)

// TestIntegrationInitImportServeProxy is the Phase 2a end-to-end walking-skeleton
// test: it drives the real `poolgate init` and `poolgate import` CLI functions
// against a temp data dir, then wires the gateway exactly the way `serve` does
// (through openStore) but points it at an in-process fake upstream. It asserts
// the translation-gateway contract (Authorization + ChatGPT-Account-ID rewritten
// together, forced stream:true + Accept: text/event-stream, SSE relayed with
// per-chunk flush) and the health endpoints.
func TestIntegrationInitImportServeProxy(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(envDataDir, dataDir)
	// Default master_key_source is keyfile; make sure env source is not selected.
	t.Setenv(envMasterKey, "")

	// (1) init: provisions data dir + keyfile + migrated DB. Idempotent.
	if err := cmdInit(nil, io.Discard); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}
	// Re-running init must be a no-op (idempotency, DESIGN.md §17).
	if err := cmdInit(nil, io.Discard); err != nil {
		t.Fatalf("cmdInit (second run): %v", err)
	}

	// (2) import: write a tiny fake Codex auth.json and import it. This is the
	// only account and it is imported explicitly (never automatically).
	authPath := filepath.Join(t.TempDir(), "auth.json")
	const (
		wantAccess    = "acct-access-token-xyz"
		wantRefresh   = "acct-refresh-token-xyz"
		wantAccountID = "chatgpt-account-id-123"
	)
	authJSON := `{"tokens":{"access_token":"` + wantAccess +
		`","refresh_token":"` + wantRefresh +
		`","account_id":"` + wantAccountID +
		`","id_token":"header.payload.sig"}}`
	if err := os.WriteFile(authPath, []byte(authJSON), 0o600); err != nil {
		t.Fatalf("write fake auth.json: %v", err)
	}
	if err := cmdImport([]string{authPath}, io.Discard); err != nil {
		t.Fatalf("cmdImport: %v", err)
	}

	// (3) reopen the store the way `serve` does and recover the generated sk- key.
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	st, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer st.Close()

	ctx := context.Background()
	keys, err := st.ListApiKeys(ctx)
	if err != nil {
		t.Fatalf("ListApiKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("api keys = %d, want 1 (import creates one default key)", len(keys))
	}
	apiKey := keys[0].Key
	if !strings.HasPrefix(apiKey, "sk-") {
		t.Fatalf("generated key %q lacks sk- prefix", apiKey)
	}

	// (4) fake upstream: captures the rewritten headers + forced stream flag,
	// then streams 3 SSE chunks with per-chunk flush.
	type capture struct {
		path       string
		auth       string
		accountID  string
		originator string
		userAgent  string
		accept     string
		streamVal  any
	}
	got := make(chan capture, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		got <- capture{
			path:       r.URL.Path,
			auth:       r.Header.Get("Authorization"),
			accountID:  r.Header.Get("ChatGPT-Account-ID"),
			originator: r.Header.Get("originator"),
			userAgent:  r.Header.Get("User-Agent"),
			accept:     r.Header.Get("Accept"),
			streamVal:  body["stream"],
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		for i := 0; i < 3; i++ {
			_, _ = io.WriteString(w, "data: chunk\n\n")
			if fl != nil {
				fl.Flush()
			}
		}
	}))
	defer upstream.Close()

	// (5) wire the gateway like `serve` (openStore + cfg) but override the pinned
	// upstream to the fake and allowlist its host so egress is permitted.
	cfg.UpstreamAllowlist = []string{mustHost(t, upstream.URL)}
	gw := gateway.New(st, cfg,
		gateway.WithUpstreamBase(upstream.URL),
		gateway.WithHTTPClient(upstream.Client()))
	proxy := httptest.NewServer(gw.Routes())
	defer proxy.Close()

	// (6) health endpoints: /healthz alive, /readyz ready (migrations applied +
	// the imported account is eligible).
	assertStatus(t, proxy.URL+"/healthz", http.MethodGet, "", http.StatusOK)
	assertStatus(t, proxy.URL+"/readyz", http.MethodGet, "", http.StatusOK)

	// Unauthenticated proxy POST must be 401.
	unauth := doPost(t, proxy.URL+"/e/default/v1/responses", "", `{"model":"gpt-5"}`)
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth POST status = %d, want 401", unauth.StatusCode)
	}
	unauth.Body.Close()

	// (7) authenticated proxy POST: goes through the translation gateway to the
	// fake upstream. Client sends stream:false; the gateway must force it true.
	resp := doPost(t, proxy.URL+"/e/default/v1/responses", apiKey, `{"model":"gpt-5","stream":false}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy POST status = %d, want 200", resp.StatusCode)
	}

	c := <-got
	if c.path != "/responses" {
		t.Errorf("upstream path = %q, want /responses", c.path)
	}
	if c.auth != "Bearer "+wantAccess {
		t.Errorf("upstream Authorization = %q, want rewritten account access token", c.auth)
	}
	if c.accountID != wantAccountID {
		t.Errorf("upstream ChatGPT-Account-ID = %q, want %q", c.accountID, wantAccountID)
	}
	if c.originator != gateway.DefaultOriginator {
		t.Errorf("upstream originator = %q, want %q", c.originator, gateway.DefaultOriginator)
	}
	if c.userAgent == "" {
		t.Errorf("upstream User-Agent is empty; want a synthesized Codex UA")
	}
	if c.accept != "text/event-stream" {
		t.Errorf("upstream Accept = %q, want text/event-stream", c.accept)
	}
	if c.streamVal != true {
		t.Errorf("upstream stream = %v, want true (forced)", c.streamVal)
	}

	// SSE chunks must be relayed to the client.
	var lines int
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "data:") {
			lines++
		}
	}
	if lines != 3 {
		t.Errorf("received %d SSE data lines, want 3", lines)
	}
}

func doPost(t *testing.T, url, bearer, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build POST %s: %v", url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

func assertStatus(t *testing.T, url, method, bearer string, want int) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, url, err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("%s %s status = %d, want %d", method, url, resp.StatusCode, want)
	}
}

func mustHost(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	return u.Hostname()
}

// fakeBindSink records emitted events for the bind-warning test.
type fakeBindSink struct{ events []model.NotifyEvent }

func (f *fakeBindSink) Emit(ev model.NotifyEvent) { f.events = append(f.events, ev) }

func TestEmitBindWarnings(t *testing.T) {
	cfg := config.Default()

	// Both loopback → no warnings.
	cfg.Server.Proxy.Host = "127.0.0.1"
	cfg.Server.Admin.Host = "127.0.0.1"
	s := &fakeBindSink{}
	emitBindWarnings(cfg, s)
	if len(s.events) != 0 {
		t.Fatalf("loopback binds emitted %d warnings, want 0", len(s.events))
	}

	// Proxy non-loopback → exactly one warning naming the proxy.
	cfg.Server.Proxy.Host = "0.0.0.0"
	s = &fakeBindSink{}
	emitBindWarnings(cfg, s)
	if len(s.events) != 1 || s.events[0].Kind != model.EventStartupBindWarning {
		t.Fatalf("events = %+v, want 1 startup_bind_warning", s.events)
	}
	if !strings.Contains(s.events[0].Message, "proxy") {
		t.Errorf("message = %q, want it to name the proxy listener", s.events[0].Message)
	}

	// Both non-loopback → two warnings.
	cfg.Server.Admin.Host = "0.0.0.0"
	s = &fakeBindSink{}
	emitBindWarnings(cfg, s)
	if len(s.events) != 2 {
		t.Errorf("both non-loopback emitted %d warnings, want 2", len(s.events))
	}

	// Nil sink is a no-op (no panic).
	emitBindWarnings(cfg, nil)
}

func TestCmdRotateKeyKeyfile(t *testing.T) {
	t.Setenv(envDataDir, t.TempDir())
	t.Setenv(envMasterKey, "")
	if err := cmdInit(nil, io.Discard); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	ctx := context.Background()

	// Insert an account under the original key.
	st, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	acct, err := st.InsertAccount(ctx, model.Account{
		AccessToken: "tok-access", RefreshToken: "tok-refresh", AccountID: "acc-1", State: model.StateOK,
	})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	_ = st.Close()

	var out bytes.Buffer
	if err := cmdRotateKey(nil, &out); err != nil {
		t.Fatalf("cmdRotateKey: %v", err)
	}
	if !strings.Contains(out.String(), "rotated") {
		t.Errorf("output missing success line: %s", out.String())
	}

	// A pre-rotation snapshot must exist.
	snaps, _ := filepath.Glob(filepath.Join(cfg.DataDir, "poolgate-pre-rotate-*.db"))
	if len(snaps) != 1 {
		t.Errorf("pre-rotation snapshots = %d, want 1", len(snaps))
	}

	// Reopen: the new keyfile must decrypt the account tokens.
	st2, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore after rotate: %v", err)
	}
	defer st2.Close()
	got, err := st2.GetAccount(ctx, acct.ID)
	if err != nil {
		t.Fatalf("GetAccount after rotate: %v", err)
	}
	if got.AccessToken != "tok-access" || got.RefreshToken != "tok-refresh" {
		t.Errorf("tokens after rotate = %q/%q, want originals", got.AccessToken, got.RefreshToken)
	}
}
