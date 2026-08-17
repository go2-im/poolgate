package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go2-im/poolgate/internal/config"
	"github.com/go2-im/poolgate/internal/crypto"
	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/store"
)

// newStore builds an isolated encrypted store in a temp dir.
func newStore(t *testing.T) (*store.Store, model.Config) {
	t.Helper()
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(11*i + 3)
	}
	cipher, err := crypto.New(key)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	st, err := store.Open(cfg, cipher)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, cfg
}

// ---- handleResponses error paths (HTTP-level) -----------------------------

func TestHandleResponsesErrorPaths(t *testing.T) {
	t.Run("invalid key -> 401", func(t *testing.T) {
		f := newFixture(t)
		gw := New(f.st, f.cfg)
		srv := httptest.NewServer(gw.Routes())
		defer srv.Close()

		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/default/v1/responses",
			strings.NewReader(`{"model":"gpt-5"}`))
		req.Header.Set("Authorization", "Bearer sk-not-a-real-key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
		var eb errorBody
		_ = json.NewDecoder(resp.Body).Decode(&eb)
		if eb.Error.Type != "poolgate_invalid_key" {
			t.Errorf("type = %q, want poolgate_invalid_key", eb.Error.Type)
		}
	})

	t.Run("key not scoped to endpoint -> 403", func(t *testing.T) {
		f := newFixture(t) // apiKey scoped to "default" only
		gw := New(f.st, f.cfg)
		srv := httptest.NewServer(gw.Routes())
		defer srv.Close()

		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/other/v1/responses",
			strings.NewReader(`{"model":"gpt-5"}`))
		req.Header.Set("Authorization", "Bearer "+f.apiKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
		var eb errorBody
		_ = json.NewDecoder(resp.Body).Decode(&eb)
		if eb.Error.Type != "poolgate_key_unscoped" {
			t.Errorf("type = %q, want poolgate_key_unscoped", eb.Error.Type)
		}
	})

	t.Run("unknown endpoint -> 404", func(t *testing.T) {
		f := newFixture(t)
		// Add an UNSCOPED key so scoping passes and we reach endpoint resolution.
		const openKey = "sk-open-000"
		if _, err := f.st.InsertApiKey(context.Background(),
			model.ApiKey{Key: openKey, Label: "open"}); err != nil {
			t.Fatalf("InsertApiKey: %v", err)
		}
		gw := New(f.st, f.cfg)
		srv := httptest.NewServer(gw.Routes())
		defer srv.Close()

		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/ghost/v1/responses",
			strings.NewReader(`{"model":"gpt-5"}`))
		req.Header.Set("Authorization", "Bearer "+openKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
		var eb errorBody
		_ = json.NewDecoder(resp.Body).Decode(&eb)
		if eb.Error.Type != "poolgate_unknown_endpoint" {
			t.Errorf("type = %q, want poolgate_unknown_endpoint", eb.Error.Type)
		}
	})

	t.Run("no healthy account -> 503", func(t *testing.T) {
		f := newFixture(t)
		// Drive the only account to a non-eligible (terminal) state.
		if err := f.st.UpdateState(context.Background(), f.acct.ID, model.StateExpired); err != nil {
			t.Fatalf("UpdateState: %v", err)
		}
		gw := New(f.st, f.cfg)
		srv := httptest.NewServer(gw.Routes())
		defer srv.Close()

		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/default/v1/responses",
			strings.NewReader(`{"model":"gpt-5"}`))
		req.Header.Set("Authorization", "Bearer "+f.apiKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", resp.StatusCode)
		}
		var eb errorBody
		_ = json.NewDecoder(resp.Body).Decode(&eb)
		if eb.Error.Type != "poolgate_no_healthy_account" {
			t.Errorf("type = %q, want poolgate_no_healthy_account", eb.Error.Type)
		}
	})

	t.Run("POST with spurious Upgrade headers is treated as HTTP, not WS", func(t *testing.T) {
		// WS is GET-only; a POST carrying Upgrade headers must NOT be routed to the
		// WS path. Here the body is invalid JSON so the HTTP path returns 400 before
		// any upstream dial — proving it went down the HTTP branch.
		f := newFixture(t)
		gw := New(f.st, f.cfg)
		srv := httptest.NewServer(gw.Routes())
		defer srv.Close()

		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/default/v1/responses",
			strings.NewReader(`{not json`))
		req.Header.Set("Authorization", "Bearer "+f.apiKey)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (HTTP path, not WS)", resp.StatusCode)
		}
		var eb errorBody
		_ = json.NewDecoder(resp.Body).Decode(&eb)
		if eb.Error.Type != "poolgate_bad_request" {
			t.Errorf("type = %q, want poolgate_bad_request", eb.Error.Type)
		}
	})

	t.Run("malformed JSON body -> 400", func(t *testing.T) {
		f := newFixture(t)
		f.cfg.UpstreamAllowlist = []string{"chatgpt.com"}
		gw := New(f.st, f.cfg)
		srv := httptest.NewServer(gw.Routes())
		defer srv.Close()

		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/default/v1/responses",
			strings.NewReader(`{not-json`))
		req.Header.Set("Authorization", "Bearer "+f.apiKey)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
		var eb errorBody
		_ = json.NewDecoder(resp.Body).Decode(&eb)
		if eb.Error.Type != "poolgate_bad_request" {
			t.Errorf("type = %q, want poolgate_bad_request", eb.Error.Type)
		}
	})
}

// authenticate returns false when the store fails (closed DB) -> invalid key.
func TestAuthenticateStoreError(t *testing.T) {
	st, cfg := newStore(t)
	// Seed nothing needed; close the DB so ListApiKeys errors during auth.
	_ = st.Close()
	gw := New(st, cfg)
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/default/v1/responses",
		strings.NewReader(`{"model":"gpt-5"}`))
	req.Header.Set("Authorization", "Bearer sk-anything")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// ---- forward / fallback ---------------------------------------------------

// twoAccountFixture seeds two accounts in one fallback group + an unscoped key.
type twoAccountFixture struct {
	st        *store.Store
	cfg       model.Config
	apiKey    string
	badToken  string
	goodToken string
}

func newTwoAccountFixture(t *testing.T) *twoAccountFixture {
	t.Helper()
	st, cfg := newStore(t)
	ctx := context.Background()
	a1, err := st.InsertAccount(ctx, model.Account{
		Label: "bad", AccessToken: "token-bad", AccountID: "id-bad", State: model.StateOK,
	})
	if err != nil {
		t.Fatalf("InsertAccount bad: %v", err)
	}
	a2, err := st.InsertAccount(ctx, model.Account{
		Label: "good", AccessToken: "token-good", AccountID: "id-good", State: model.StateOK,
	})
	if err != nil {
		t.Fatalf("InsertAccount good: %v", err)
	}
	grp, err := st.InsertPolicyGroup(ctx, model.PolicyGroup{
		Name: "default", Strategy: model.StrategyFallback,
		MemberAccountIDs: []string{a1.ID, a2.ID},
	})
	if err != nil {
		t.Fatalf("InsertPolicyGroup: %v", err)
	}
	if _, err := st.InsertEndpoint(ctx, model.Endpoint{Name: "default", GroupID: grp.ID}); err != nil {
		t.Fatalf("InsertEndpoint: %v", err)
	}
	const apiKey = "sk-two-000"
	if _, err := st.InsertApiKey(ctx, model.ApiKey{Key: apiKey, Label: "k"}); err != nil {
		t.Fatalf("InsertApiKey: %v", err)
	}
	return &twoAccountFixture{st: st, cfg: cfg, apiKey: apiKey, badToken: "token-bad", goodToken: "token-good"}
}

// First account returns 5xx pre-stream; with an Idempotency-Key (which authorizes
// safe cross-account retry of an uncertain outcome, §19.2) the gateway falls over
// to the second account.
func TestForwardFallbackToSecondAccount(t *testing.T) {
	f := newTwoAccountFixture(t)

	var sawBad, sawGood bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer token-bad":
			sawBad = true
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "upstream boom")
		case "Bearer token-good":
			sawGood = true
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			fl, _ := w.(http.Flusher)
			_, _ = io.WriteString(w, "data: ok\n\n")
			if fl != nil {
				fl.Flush()
			}
		default:
			t.Errorf("unexpected auth %q", r.Header.Get("Authorization"))
		}
	}))
	defer upstream.Close()

	f.cfg.UpstreamAllowlist = []string{mustHost(t, upstream.URL)}
	gw := New(f.st, f.cfg, WithUpstreamBase(upstream.URL), WithHTTPClient(upstream.Client()),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/default/v1/responses",
		strings.NewReader(`{"model":"gpt-5"}`))
	req.Header.Set("Authorization", "Bearer "+f.apiKey)
	req.Header.Set("Idempotency-Key", "k-fallback")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fell over to good account)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "data: ok") {
		t.Errorf("body = %q, want streamed data from good account", string(body))
	}
	if !sawBad || !sawGood {
		t.Errorf("expected both accounts attempted: sawBad=%v sawGood=%v", sawBad, sawGood)
	}
}

// All accounts fail pre-stream -> all_exhausted 502 with last upstream status.
// (5xx is an uncertain outcome, so an Idempotency-Key is required to fail over at
// all; without it the first 5xx is relayed — see TestForward5xxNoKeyRelayed.)
func TestForwardAllExhausted(t *testing.T) {
	f := newTwoAccountFixture(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer upstream.Close()

	f.cfg.UpstreamAllowlist = []string{mustHost(t, upstream.URL)}
	gw := New(f.st, f.cfg, WithUpstreamBase(upstream.URL), WithHTTPClient(upstream.Client()),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/default/v1/responses",
		strings.NewReader(`{"model":"gpt-5"}`))
	req.Header.Set("Authorization", "Bearer "+f.apiKey)
	req.Header.Set("Idempotency-Key", "k-exhaust")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	var eb errorBody
	_ = json.NewDecoder(resp.Body).Decode(&eb)
	if eb.Error.Type != "poolgate_all_exhausted" {
		t.Errorf("type = %q, want poolgate_all_exhausted", eb.Error.Type)
	}
}

// Upstream transport error (connection refused) with NO Idempotency-Key: the
// outcome is uncertain (the request may have executed), so the gateway must NOT
// replay it across accounts — it returns poolgate_upstream_error (502) instead.
func TestForwardTransportError(t *testing.T) {
	f := newFixture(t)
	// Stand up then immediately close a server so its address refuses connections.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	deadClient := dead.Client()
	dead.Close()

	f.cfg.UpstreamAllowlist = []string{mustHost(t, deadURL)}
	gw := New(f.st, f.cfg, WithUpstreamBase(deadURL), WithHTTPClient(deadClient),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/default/v1/responses",
		strings.NewReader(`{"model":"gpt-5"}`))
	req.Header.Set("Authorization", "Bearer "+f.apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	var eb errorBody
	_ = json.NewDecoder(resp.Body).Decode(&eb)
	if eb.Error.Type != "poolgate_upstream_error" {
		t.Errorf("type = %q, want poolgate_upstream_error", eb.Error.Type)
	}
}

// ---- health / readiness ---------------------------------------------------

func TestHandleHealthz(t *testing.T) {
	f := newFixture(t)
	gw := New(f.st, f.cfg)
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("status field = %q, want ok", body["status"])
	}
}

func TestReadyzNotReadyNoHealthyAccount(t *testing.T) {
	f := newFixture(t)
	if err := f.st.UpdateState(context.Background(), f.acct.ID, model.StateDead); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}
	gw := New(f.st, f.cfg)
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	var eb errorBody
	_ = json.NewDecoder(resp.Body).Decode(&eb)
	if eb.Error.Type != "poolgate_not_ready" {
		t.Errorf("type = %q, want poolgate_not_ready", eb.Error.Type)
	}
}

func TestReadyzNotReadySchemaError(t *testing.T) {
	st, cfg := newStore(t)
	_ = st.Close() // SchemaVersion now errors -> not ready.
	gw := New(st, cfg)
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestAnyEndpointReadyListError(t *testing.T) {
	st, cfg := newStore(t)
	_ = st.Close()
	gw := New(st, cfg)
	if gw.anyEndpointReady(context.Background()) {
		t.Errorf("anyEndpointReady = true on closed store, want false")
	}
}

// ---- helper unit tests ----------------------------------------------------

func TestBearerToken(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
		ok     bool
	}{
		{"valid", "Bearer sk-abc", "sk-abc", true},
		{"case-insensitive prefix", "bearer sk-xyz", "sk-xyz", true},
		{"missing header", "", "", false},
		{"no bearer prefix", "Token sk-abc", "", false},
		{"only prefix", "Bearer ", "", false},
		{"whitespace token", "Bearer    ", "", false},
		{"too short", "Bear", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodPost, "/", nil)
			if tt.header != "" {
				r.Header.Set("Authorization", tt.header)
			}
			got, ok := bearerToken(r)
			if ok != tt.ok || got != tt.want {
				t.Errorf("bearerToken(%q) = (%q,%v), want (%q,%v)", tt.header, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestKeyScopedTo(t *testing.T) {
	tests := []struct {
		name     string
		key      model.ApiKey
		endpoint string
		want     bool
	}{
		{"unscoped allows any", model.ApiKey{}, "anything", true},
		{"scoped match", model.ApiKey{Endpoints: []string{"a", "b"}}, "b", true},
		{"scoped no match", model.ApiKey{Endpoints: []string{"a", "b"}}, "c", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := keyScopedTo(tt.key, tt.endpoint); got != tt.want {
				t.Errorf("keyScopedTo = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckEgress(t *testing.T) {
	g := &Gateway{allowlist: []string{"chatgpt.com"}}
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"allowlisted https", "https://chatgpt.com/backend-api/codex/responses", false},
		{"allowlisted http", "http://chatgpt.com/x", false},
		{"host not allowed", "https://evil.example.com/x", true},
		{"bad scheme", "ftp://chatgpt.com/x", true},
		{"unparseable url", "https://exa mple.com/ %zz", true},
		{"no scheme", "://chatgpt.com/x", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := g.checkEgress(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkEgress(%q) err = %v, wantErr = %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestForceStream(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"empty body", "", false},
		{"whitespace body", "   \n\t ", false},
		{"valid object stream false", `{"model":"gpt-5","stream":false}`, false},
		{"valid object no stream", `{"model":"gpt-5"}`, false},
		{"invalid json", `{not json`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := forceStream([]byte(tt.in))
			if (err != nil) != tt.wantErr {
				t.Fatalf("forceStream err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			var m map[string]any
			if uerr := json.Unmarshal(out, &m); uerr != nil {
				t.Fatalf("output not valid json: %v", uerr)
			}
			if m["stream"] != true {
				t.Errorf("stream = %v, want true", m["stream"])
			}
		})
	}
}

func TestHeaderOrDefault(t *testing.T) {
	r, _ := http.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set("originator", "custom")
	if got := headerOrDefault(r, "originator", "def"); got != "custom" {
		t.Errorf("present header = %q, want custom", got)
	}
	if got := headerOrDefault(r, "User-Agent", "def-ua"); got != "def-ua" {
		t.Errorf("absent header = %q, want def-ua", got)
	}
}

func TestEligibleAccounts(t *testing.T) {
	accounts := []model.Account{
		{ID: "1", State: model.StateOK},
		{ID: "2", State: model.StateCooldown},
		{ID: "3", State: model.StateUnknown},
		{ID: "4", State: model.StateExpired},
		{ID: "5", State: model.StateDead},
		{ID: "6", State: model.StateQuotaExhausted},
	}
	got := eligibleAccounts(model.PolicyGroup{Strategy: model.StrategyFallback}, accounts)
	var ids []string
	for _, a := range got {
		ids = append(ids, a.ID)
	}
	want := []string{"1", "3"} // ok + unknown only, preserving order
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("eligible ids = %v, want %v", ids, want)
	}
}

func TestRelayHeaders(t *testing.T) {
	t.Run("with content-type and rate-limit headers", func(t *testing.T) {
		rec := httptest.NewRecorder()
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Set("Content-Type", "application/json")
		resp.Header.Set("Retry-After", "42")
		resp.Header.Set("X-RateLimit-Remaining", "7")
		relayHeaders(rec, resp)
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		if got := rec.Header().Get("Retry-After"); got != "42" {
			t.Errorf("Retry-After = %q, want 42", got)
		}
		if got := rec.Header().Get("X-RateLimit-Remaining"); got != "7" {
			t.Errorf("X-RateLimit-Remaining = %q, want 7", got)
		}
		if got := rec.Header().Get("X-Accel-Buffering"); got != "no" {
			t.Errorf("X-Accel-Buffering = %q, want no", got)
		}
	})

	t.Run("without content-type defaults to event-stream", func(t *testing.T) {
		rec := httptest.NewRecorder()
		resp := &http.Response{Header: http.Header{}}
		relayHeaders(rec, resp)
		if got := rec.Header().Get("Content-Type"); got != "text/event-stream" {
			t.Errorf("Content-Type = %q, want text/event-stream", got)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-transform" {
			t.Errorf("Cache-Control = %q, want no-transform", got)
		}
	})
}

// errWriter fails on Write to exercise relayStream's write-error early return.
type errWriter struct{ header http.Header }

func (e *errWriter) Header() http.Header {
	if e.header == nil {
		e.header = http.Header{}
	}
	return e.header
}
func (e *errWriter) Write([]byte) (int, error) { return 0, errors.New("client gone") }
func (e *errWriter) WriteHeader(int)           {}

// errReader returns a non-EOF error after some data.
type errReader struct {
	data []byte
	done bool
}

func (r *errReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		n := copy(p, r.data)
		return n, nil
	}
	return 0, errors.New("read failure")
}

func TestRelayStream(t *testing.T) {
	t.Run("normal copy with flush", func(t *testing.T) {
		rec := httptest.NewRecorder()
		relayStream(rec, strings.NewReader("data: a\n\ndata: b\n\n"))
		if !strings.Contains(rec.Body.String(), "data: a") {
			t.Errorf("body = %q, want relayed data", rec.Body.String())
		}
	})

	t.Run("write error returns early", func(t *testing.T) {
		w := &errWriter{}
		// Should not panic; returns after the first failed Write.
		relayStream(w, strings.NewReader("data: x\n\n"))
	})

	t.Run("non-EOF read error returns", func(t *testing.T) {
		rec := httptest.NewRecorder()
		relayStream(rec, &errReader{data: []byte("data: partial\n\n")})
		if !strings.Contains(rec.Body.String(), "partial") {
			t.Errorf("body = %q, want the partial chunk before error", rec.Body.String())
		}
	})
}

// resolveEndpoint internal-error path (non-ErrNotFound) -> 500. Force it by
// closing the DB after auth succeeds is impossible mid-request; instead verify
// the error mapping is not ErrNotFound via a sanity guard on ResolveEndpoint.
func TestResolveEndpointNotFoundIsMapped(t *testing.T) {
	st, _ := newStore(t)
	_, _, _, err := st.ResolveEndpoint(context.Background(), "does-not-exist")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ResolveEndpoint unknown err = %v, want ErrNotFound", err)
	}
}

// Ensure New applies options (WithHTTPClient/WithUpstreamBase/WithLogger).
func TestNewAppliesOptions(t *testing.T) {
	f := newFixture(t)
	c := &http.Client{}
	l := slog.New(slog.NewTextHandler(io.Discard, nil))
	gw := New(f.st, f.cfg,
		WithHTTPClient(c),
		WithUpstreamBase("https://example.com/base/"),
		WithLogger(l))
	if gw.httpc != c {
		t.Errorf("WithHTTPClient not applied")
	}
	if gw.upstreamBase != "https://example.com/base" {
		t.Errorf("upstreamBase = %q, want trailing slash trimmed", gw.upstreamBase)
	}
	if gw.logger != l {
		t.Errorf("WithLogger not applied")
	}
}
