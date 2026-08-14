package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go2-im/poolgate/internal/config"
	"github.com/go2-im/poolgate/internal/crypto"
	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/store"
)

// fixture builds a store seeded with one account, a fallback group, an endpoint
// named "default", and an sk- key scoped to it.
type fixture struct {
	st     *store.Store
	cfg    model.Config
	apiKey string
	acct   model.Account
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(7 * i)
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
	ctx := context.Background()

	acct, err := st.InsertAccount(ctx, model.Account{
		Label:        "a1",
		AccessToken:  "acct-access-token",
		RefreshToken: "acct-refresh-token",
		AccountID:    "acct-chatgpt-id",
		State:        model.StateOK,
	})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	grp, err := st.InsertPolicyGroup(ctx, model.PolicyGroup{
		Name:             "default",
		Strategy:         model.StrategyFallback,
		MemberAccountIDs: []string{acct.ID},
	})
	if err != nil {
		t.Fatalf("InsertPolicyGroup: %v", err)
	}
	if _, err := st.InsertEndpoint(ctx, model.Endpoint{Name: "default", GroupID: grp.ID}); err != nil {
		t.Fatalf("InsertEndpoint: %v", err)
	}
	const apiKey = "sk-testkey-000"
	if _, err := st.InsertApiKey(ctx, model.ApiKey{Key: apiKey, Label: "k", Endpoints: []string{"default"}}); err != nil {
		t.Fatalf("InsertApiKey: %v", err)
	}
	return &fixture{st: st, cfg: cfg, apiKey: apiKey, acct: acct}
}

func TestMissingKeyReturns401(t *testing.T) {
	f := newFixture(t)
	gw := New(f.st, f.cfg)
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/e/default/v1/responses", "application/json",
		strings.NewReader(`{"model":"gpt-5"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	var eb errorBody
	if err := json.NewDecoder(resp.Body).Decode(&eb); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if !strings.HasPrefix(eb.Error.Type, "poolgate_") {
		t.Errorf("error type = %q, want poolgate_ prefix", eb.Error.Type)
	}
}

func TestRewriteAndSSEFlush(t *testing.T) {
	f := newFixture(t)

	type capture struct {
		auth       string
		accountID  string
		originator string
		accept     string
		streamVal  any
	}
	got := make(chan capture, 1)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Errorf("upstream path = %q, want /responses", r.URL.Path)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		got <- capture{
			auth:       r.Header.Get("Authorization"),
			accountID:  r.Header.Get("ChatGPT-Account-ID"),
			originator: r.Header.Get("originator"),
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

	// Allowlist the upstream host so egress is permitted.
	f.cfg.UpstreamAllowlist = []string{mustHost(t, upstream.URL)}
	gw := New(f.st, f.cfg, WithUpstreamBase(upstream.URL), WithHTTPClient(upstream.Client()))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/default/v1/responses",
		strings.NewReader(`{"model":"gpt-5","stream":false}`))
	req.Header.Set("Authorization", "Bearer "+f.apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	c := <-got
	if c.auth != "Bearer acct-access-token" {
		t.Errorf("upstream Authorization = %q, want rewritten account token", c.auth)
	}
	if c.accountID != "acct-chatgpt-id" {
		t.Errorf("upstream ChatGPT-Account-ID = %q, want acct-chatgpt-id", c.accountID)
	}
	if c.originator != DefaultOriginator {
		t.Errorf("upstream originator = %q, want %q", c.originator, DefaultOriginator)
	}
	if c.accept != "text/event-stream" {
		t.Errorf("upstream Accept = %q, want text/event-stream", c.accept)
	}
	if c.streamVal != true {
		t.Errorf("upstream stream = %v, want true (forced)", c.streamVal)
	}

	// SSE chunks must arrive (flushed through).
	sc := bufio.NewScanner(resp.Body)
	var lines int
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "data:") {
			lines++
		}
	}
	if lines != 3 {
		t.Errorf("received %d SSE data lines, want 3", lines)
	}
}

func TestEgressRefusedForNonAllowlistedHost(t *testing.T) {
	f := newFixture(t)
	// Point upstream at a host that is NOT on the allowlist.
	f.cfg.UpstreamAllowlist = []string{"chatgpt.com"}
	gw := New(f.st, f.cfg, WithUpstreamBase("https://evil.example.com/backend"))
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
		t.Fatalf("status = %d, want 502 (egress refused)", resp.StatusCode)
	}
	var eb errorBody
	_ = json.NewDecoder(resp.Body).Decode(&eb)
	if eb.Error.Type != "poolgate_egress_refused" {
		t.Errorf("error type = %q, want poolgate_egress_refused", eb.Error.Type)
	}
}

func TestReadyzReflectsHealthyAccount(t *testing.T) {
	f := newFixture(t)
	gw := New(f.st, f.cfg)
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/readyz status = %d, want 200", resp.StatusCode)
	}
}

// mustHost extracts the host (no port) from a URL for allowlisting.
func mustHost(t *testing.T, rawURL string) string {
	t.Helper()
	// httptest URLs are http://127.0.0.1:PORT
	u := strings.TrimPrefix(rawURL, "http://")
	u = strings.TrimPrefix(u, "https://")
	if i := strings.IndexByte(u, ':'); i >= 0 {
		u = u[:i]
	}
	return u
}
