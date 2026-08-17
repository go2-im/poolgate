package gateway

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/store"
)

// ---- test helpers ---------------------------------------------------------

// seedAccount inserts an OK account with an explicit token + ChatGPT-Account-ID.
func seedAccount(t *testing.T, st *store.Store, label, token, chatgptID string) model.Account {
	t.Helper()
	a, err := st.InsertAccount(context.Background(), model.Account{
		Label: label, AccessToken: token, AccountID: chatgptID, State: model.StateOK,
	})
	if err != nil {
		t.Fatalf("InsertAccount(%s): %v", label, err)
	}
	return a
}

// seedGroupEndpointKey wires a group with the given strategy over members, a
// "default" endpoint, and one unscoped sk- key. Returns the key.
func seedGroupEndpointKey(t *testing.T, st *store.Store, strategy model.Strategy, memberIDs ...string) string {
	t.Helper()
	ctx := context.Background()
	grp, err := st.InsertPolicyGroup(ctx, model.PolicyGroup{
		Name: "default", Strategy: strategy, MemberAccountIDs: memberIDs,
	})
	if err != nil {
		t.Fatalf("InsertPolicyGroup: %v", err)
	}
	if _, err := st.InsertEndpoint(ctx, model.Endpoint{Name: "default", GroupID: grp.ID}); err != nil {
		t.Fatalf("InsertEndpoint: %v", err)
	}
	const key = "sk-stage4-000"
	if _, err := st.InsertApiKey(ctx, model.ApiKey{Key: key, Label: "k"}); err != nil {
		t.Fatalf("InsertApiKey: %v", err)
	}
	return key
}

// authRecorder is a fake upstream that records the Authorization header per
// request and dispatches a scripted response by token.
type authRecorder struct {
	mu   sync.Mutex
	seen []string
}

func (a *authRecorder) record(auth string) {
	a.mu.Lock()
	a.seen = append(a.seen, auth)
	a.mu.Unlock()
}

func (a *authRecorder) tokens() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, len(a.seen))
	copy(out, a.seen)
	return out
}

// fakeHealth records passive-hook calls and (for 401) returns a rotated token.
type fakeHealth struct {
	mu           sync.Mutex
	unauthorized int
	rateLimited  []time.Duration
	quota        int
	refreshTo    string // access token to swap in on OnUnauthorized; "" => error
}

type errWrapper struct{ msg string }

func (e errWrapper) Error() string { return e.msg }

func (f *fakeHealth) OnUnauthorized(_ context.Context, acct model.Account) (model.Account, error) {
	f.mu.Lock()
	f.unauthorized++
	f.mu.Unlock()
	if f.refreshTo == "" {
		return acct, errWrapper{msg: "refresh failed"}
	}
	acct.AccessToken = f.refreshTo
	return acct, nil
}

func (f *fakeHealth) OnRateLimited(_ context.Context, _ model.Account, ra time.Duration) error {
	f.mu.Lock()
	f.rateLimited = append(f.rateLimited, ra)
	f.mu.Unlock()
	return nil
}

func (f *fakeHealth) OnQuotaExhausted(_ context.Context, _ model.Account, _ time.Time) error {
	f.mu.Lock()
	f.quota++
	f.mu.Unlock()
	return nil
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func streamOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	_, _ = io.WriteString(w, "data: ok\n\n")
}

func doProxyPost(t *testing.T, url, key string, idem ...string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url+"/e/default/v1/responses",
		strings.NewReader(`{"model":"gpt-5"}`))
	req.Header.Set("Authorization", "Bearer "+key)
	if len(idem) > 0 && idem[0] != "" {
		req.Header.Set("Idempotency-Key", idem[0])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	return resp
}

// ---- best-quota strategy ---------------------------------------------------

// best-quota must ignore member order and route to the account with the most
// remaining headroom (min over windows of 100-used_percent).
func TestSelectBestQuotaRoutesToMostHeadroom(t *testing.T) {
	st, cfg := newStore(t)
	ctx := context.Background()
	low := seedAccount(t, st, "low", "tok-low", "id-low")     // 90% used -> headroom 10
	high := seedAccount(t, st, "high", "tok-high", "id-high") // 10% used -> headroom 90
	if _, err := st.SaveUsageSnapshot(ctx, model.UsageSnapshot{
		AccountID: low.ID, Windows: []model.UsageWindow{{Name: "primary", UsedPercent: 90}},
	}); err != nil {
		t.Fatalf("SaveUsageSnapshot low: %v", err)
	}
	if _, err := st.SaveUsageSnapshot(ctx, model.UsageSnapshot{
		AccountID: high.ID, Windows: []model.UsageWindow{{Name: "primary", UsedPercent: 10}},
	}); err != nil {
		t.Fatalf("SaveUsageSnapshot high: %v", err)
	}
	// low is inserted first, so fallback would pick it; best-quota must pick high.
	key := seedGroupEndpointKey(t, st, model.StrategyBestQuota, low.ID, high.ID)

	rec := &authRecorder{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r.Header.Get("Authorization"))
		streamOK(w)
	}))
	defer upstream.Close()

	cfg.UpstreamAllowlist = []string{mustHost(t, upstream.URL)}
	gw := New(st, cfg, WithUpstreamBase(upstream.URL), WithHTTPClient(upstream.Client()), WithLogger(quietLogger()))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	resp := doProxyPost(t, srv.URL, key)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	tokens := rec.tokens()
	if len(tokens) != 1 || tokens[0] != "Bearer tok-high" {
		t.Errorf("upstream tokens = %v, want [Bearer tok-high] (best-quota)", tokens)
	}
}

// best-quota with NO usage snapshots treats every account as fully unconstrained
// (headroom 100) and tie-breaks to the lowest account id deterministically.
func TestSelectBestQuotaNoSnapshotTieBreak(t *testing.T) {
	st, cfg := newStore(t)
	a := seedAccount(t, st, "a", "tok-a", "id-a")
	b := seedAccount(t, st, "b", "tok-b", "id-b")
	// best-quota tie-break is the lowest account id (independent of member order).
	lowTok := "tok-a"
	if b.ID < a.ID {
		lowTok = "tok-b"
	}
	key := seedGroupEndpointKey(t, st, model.StrategyBestQuota, a.ID, b.ID)

	rec := &authRecorder{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r.Header.Get("Authorization"))
		streamOK(w)
	}))
	defer upstream.Close()

	cfg.UpstreamAllowlist = []string{mustHost(t, upstream.URL)}
	gw := New(st, cfg, WithUpstreamBase(upstream.URL), WithHTTPClient(upstream.Client()), WithLogger(quietLogger()))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	resp := doProxyPost(t, srv.URL, key)
	defer resp.Body.Close()
	tokens := rec.tokens()
	if len(tokens) != 1 || tokens[0] != "Bearer "+lowTok {
		t.Errorf("upstream tokens = %v, want [Bearer %s] (lowest-id tie-break)", tokens, lowTok)
	}
}

// ---- load-balance strategy -------------------------------------------------

// load-balance round-robins across healthy members on successive requests.
func TestSelectLoadBalanceRoundRobin(t *testing.T) {
	st, cfg := newStore(t)
	a := seedAccount(t, st, "a", "tok-a", "id-a")
	b := seedAccount(t, st, "b", "tok-b", "id-b")
	key := seedGroupEndpointKey(t, st, model.StrategyLoadBalance, a.ID, b.ID)

	rec := &authRecorder{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r.Header.Get("Authorization"))
		streamOK(w)
	}))
	defer upstream.Close()

	cfg.UpstreamAllowlist = []string{mustHost(t, upstream.URL)}
	gw := New(st, cfg, WithUpstreamBase(upstream.URL), WithHTTPClient(upstream.Client()), WithLogger(quietLogger()))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	for i := 0; i < 4; i++ {
		resp := doProxyPost(t, srv.URL, key)
		resp.Body.Close()
	}
	tokens := rec.tokens()
	if len(tokens) != 4 {
		t.Fatalf("got %d upstream calls, want 4", len(tokens))
	}
	// Round-robin: a, b, a, b (cursor advances once per successful selection).
	want := []string{"Bearer tok-a", "Bearer tok-b", "Bearer tok-a", "Bearer tok-b"}
	for i := range want {
		if tokens[i] != want[i] {
			t.Errorf("request %d token = %q, want %q (round-robin)", i, tokens[i], want[i])
		}
	}
}

// ---- passive hooks on failure ----------------------------------------------

// A 401 drives the shared refresh (health.OnUnauthorized); the rotated token is
// retried against the same account and succeeds.
func TestForward401RefreshThenRetry(t *testing.T) {
	st, cfg := newStore(t)
	a := seedAccount(t, st, "a", "stale", "id-a")
	key := seedGroupEndpointKey(t, st, model.StrategyFallback, a.ID)

	rec := &authRecorder{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		rec.record(auth)
		if auth == "Bearer fresh" {
			streamOK(w)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	fh := &fakeHealth{refreshTo: "fresh"}
	cfg.UpstreamAllowlist = []string{mustHost(t, upstream.URL)}
	gw := New(st, cfg, WithUpstreamBase(upstream.URL), WithHTTPClient(upstream.Client()),
		WithLogger(quietLogger()), WithHealth(fh))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	resp := doProxyPost(t, srv.URL, key)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (retry after refresh)", resp.StatusCode)
	}
	if fh.unauthorized != 1 {
		t.Errorf("OnUnauthorized calls = %d, want 1", fh.unauthorized)
	}
	tokens := rec.tokens()
	if len(tokens) != 2 || tokens[0] != "Bearer stale" || tokens[1] != "Bearer fresh" {
		t.Errorf("upstream tokens = %v, want [Bearer stale, Bearer fresh]", tokens)
	}
}

// A 401 whose refresh FAILS expires the account; with no other member the
// request ends in all_exhausted.
func TestForward401RefreshFailsExhausts(t *testing.T) {
	st, cfg := newStore(t)
	a := seedAccount(t, st, "a", "stale", "id-a")
	key := seedGroupEndpointKey(t, st, model.StrategyFallback, a.ID)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	fh := &fakeHealth{refreshTo: ""} // refresh fails
	cfg.UpstreamAllowlist = []string{mustHost(t, upstream.URL)}
	gw := New(st, cfg, WithUpstreamBase(upstream.URL), WithHTTPClient(upstream.Client()),
		WithLogger(quietLogger()), WithHealth(fh))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	resp := doProxyPost(t, srv.URL, key)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (all_exhausted)", resp.StatusCode)
	}
	if fh.unauthorized != 1 {
		t.Errorf("OnUnauthorized calls = %d, want 1", fh.unauthorized)
	}
	var eb errorBody
	_ = json.NewDecoder(resp.Body).Decode(&eb)
	if eb.Error.Type != "poolgate_all_exhausted" {
		t.Errorf("type = %q, want poolgate_all_exhausted", eb.Error.Type)
	}
}

// A 429 with Retry-After drives OnRateLimited with the parsed delay, then the
// account is skipped (exhausted with a single member).
func TestForward429DrivesCooldown(t *testing.T) {
	st, cfg := newStore(t)
	a := seedAccount(t, st, "a", "tok-a", "id-a")
	key := seedGroupEndpointKey(t, st, model.StrategyFallback, a.ID)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer upstream.Close()

	fh := &fakeHealth{}
	cfg.UpstreamAllowlist = []string{mustHost(t, upstream.URL)}
	gw := New(st, cfg, WithUpstreamBase(upstream.URL), WithHTTPClient(upstream.Client()),
		WithLogger(quietLogger()), WithHealth(fh))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	resp := doProxyPost(t, srv.URL, key)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if len(fh.rateLimited) != 1 || fh.rateLimited[0] != 7*time.Second {
		t.Errorf("OnRateLimited = %v, want [7s]", fh.rateLimited)
	}
}

// A 5xx on the first member, WITH an Idempotency-Key (which authorizes safe
// cross-account retry, §19.2), drives OnRateLimited(0) (cooldown) and fails over to
// the healthy second member.
func TestForward5xxCooldownThenFailover(t *testing.T) {
	st, cfg := newStore(t)
	a := seedAccount(t, st, "bad", "tok-bad", "id-bad")
	b := seedAccount(t, st, "good", "tok-good", "id-good")
	key := seedGroupEndpointKey(t, st, model.StrategyFallback, a.ID, b.ID)

	rec := &authRecorder{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		rec.record(auth)
		if auth == "Bearer tok-good" {
			streamOK(w)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream.Close()

	fh := &fakeHealth{}
	cfg.UpstreamAllowlist = []string{mustHost(t, upstream.URL)}
	cfg.Server.AllowUncertainCrossAccountRetry = true
	gw := New(st, cfg, WithUpstreamBase(upstream.URL), WithHTTPClient(upstream.Client()),
		WithLogger(quietLogger()), WithHealth(fh))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	resp := doProxyPost(t, srv.URL, key, "k-5xx")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (failover to good)", resp.StatusCode)
	}
	if len(fh.rateLimited) != 1 || fh.rateLimited[0] != 0 {
		t.Errorf("OnRateLimited = %v, want [0s] (5xx cooldown default)", fh.rateLimited)
	}
	tokens := rec.tokens()
	if len(tokens) != 2 || tokens[0] != "Bearer tok-bad" || tokens[1] != "Bearer tok-good" {
		t.Errorf("upstream tokens = %v, want [Bearer tok-bad, Bearer tok-good]", tokens)
	}
}

// Without an Idempotency-Key a 5xx is an UNCERTAIN outcome: the gateway must NOT
// fail over (double-execution risk) — it relays the 5xx to the client and does not
// cool the account down or touch the second member.
func TestForward5xxNoKeyRelayedNoFailover(t *testing.T) {
	st, cfg := newStore(t)
	a := seedAccount(t, st, "bad", "tok-bad", "id-bad")
	b := seedAccount(t, st, "good", "tok-good", "id-good")
	key := seedGroupEndpointKey(t, st, model.StrategyFallback, a.ID, b.ID)

	rec := &authRecorder{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r.Header.Get("Authorization"))
		if r.Header.Get("Authorization") == "Bearer tok-good" {
			streamOK(w)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "upstream boom")
	}))
	defer upstream.Close()

	fh := &fakeHealth{}
	cfg.UpstreamAllowlist = []string{mustHost(t, upstream.URL)}
	gw := New(st, cfg, WithUpstreamBase(upstream.URL), WithHTTPClient(upstream.Client()),
		WithLogger(quietLogger()), WithHealth(fh))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	resp := doProxyPost(t, srv.URL, key)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 relayed (no failover without Idempotency-Key)", resp.StatusCode)
	}
	if len(fh.rateLimited) != 0 {
		t.Errorf("OnRateLimited = %v, want none (an upstream 5xx must not cool the account down)", fh.rateLimited)
	}
	if tokens := rec.tokens(); len(tokens) != 1 {
		t.Errorf("upstream attempts = %v, want exactly 1 (no cross-account replay)", tokens)
	}
}

// A non-401/429/5xx error (e.g. 403) with health wired hits the default branch:
// no hook is called, the account is marked tried, and failover advances.
func TestForward403DefaultBranchFailover(t *testing.T) {
	st, cfg := newStore(t)
	a := seedAccount(t, st, "bad", "tok-bad", "id-bad")
	b := seedAccount(t, st, "good", "tok-good", "id-good")
	key := seedGroupEndpointKey(t, st, model.StrategyFallback, a.ID, b.ID)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer tok-good" {
			streamOK(w)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer upstream.Close()

	fh := &fakeHealth{}
	cfg.UpstreamAllowlist = []string{mustHost(t, upstream.URL)}
	gw := New(st, cfg, WithUpstreamBase(upstream.URL), WithHTTPClient(upstream.Client()),
		WithLogger(quietLogger()), WithHealth(fh))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	resp := doProxyPost(t, srv.URL, key)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (failover past 403)", resp.StatusCode)
	}
	if fh.unauthorized != 0 || len(fh.rateLimited) != 0 || fh.quota != 0 {
		t.Errorf("no hook should fire for 403: unauthorized=%d rateLimited=%v quota=%d",
			fh.unauthorized, fh.rateLimited, fh.quota)
	}
}

// ---- unit tests: buildView / cursorFor / parseRetryAfter -------------------

func TestBuildViewHeadroomDefaults(t *testing.T) {
	st, cfg := newStore(t)
	ctx := context.Background()
	a := seedAccount(t, st, "a", "tok-a", "id-a")
	b := seedAccount(t, st, "b", "tok-b", "id-b")
	// Snapshot only for a; b has none -> unknown headroom (ranked below any known).
	if _, err := st.SaveUsageSnapshot(ctx, model.UsageSnapshot{
		AccountID: a.ID, Windows: []model.UsageWindow{{Name: "primary", UsedPercent: 75}},
	}); err != nil {
		t.Fatalf("SaveUsageSnapshot: %v", err)
	}
	gw := New(st, cfg)
	group := model.PolicyGroup{ID: "grp1", Strategy: model.StrategyBestQuota}
	v := gw.buildView(ctx, group, []model.Account{a, b})
	if got := v.Headroom(a.ID); got != 25 {
		t.Errorf("Headroom(a) = %v, want 25", got)
	}
	if got := v.Headroom(b.ID); got != unknownHeadroom {
		t.Errorf("Headroom(b) = %v, want %v (no snapshot => unknown)", got, unknownHeadroom)
	}
	// Unknown headroom must rank below any known value so an unprobed account
	// never outranks trusted data.
	if !(v.Headroom(b.ID) < v.Headroom(a.ID)) {
		t.Errorf("unknown headroom %v should rank below known %v", v.Headroom(b.ID), v.Headroom(a.ID))
	}
	if !v.IsHealthy(a.ID) {
		t.Errorf("a should be healthy")
	}
	v.tried[a.ID] = true
	if v.IsHealthy(a.ID) {
		t.Errorf("a should be unhealthy once tried")
	}
}

// Non-best-quota views leave headroom nil; Headroom returns the unconstrained
// default so the accessor is safe regardless of strategy.
func TestBuildViewNonBestQuotaHeadroomNil(t *testing.T) {
	st, cfg := newStore(t)
	a := seedAccount(t, st, "a", "tok-a", "id-a")
	gw := New(st, cfg)
	v := gw.buildView(context.Background(), model.PolicyGroup{ID: "g", Strategy: model.StrategyFallback}, []model.Account{a})
	if v.headroom != nil {
		t.Errorf("headroom map should be nil for non-best-quota")
	}
	if got := v.Headroom(a.ID); got != 100 {
		t.Errorf("Headroom = %v, want 100 default", got)
	}
}

func TestCursorForReuse(t *testing.T) {
	st, cfg := newStore(t)
	gw := New(st, cfg)
	c1 := gw.cursorFor("g1")
	c2 := gw.cursorFor("g1")
	if c1 != c2 {
		t.Errorf("cursorFor(g1) returned different pointers; want the same persistent cursor")
	}
	if other := gw.cursorFor("g2"); other == c1 {
		t.Errorf("cursorFor(g2) aliases g1; want a distinct cursor")
	}
}

func TestParseRetryAfter(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"  ", 0},
		{"7", 7 * time.Second},
		{"0", 0},
		{"-3", 0},
		{"abc", 0},
		{"Wed, 21 Oct 2025 07:28:00 GMT", 0}, // HTTP-date form treated as unknown
	}
	for _, tt := range tests {
		if got := parseRetryAfter(tt.in); got != tt.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// With server.allow_uncertain_cross_account_retry OFF (the default), an
// Idempotency-Key alone does NOT enable cross-account replay of a 5xx — the key
// can't be trusted to dedup across accounts on the private upstream, so the 5xx is
// relayed and the second member is never tried.
func TestForward5xxKeyButConfigOffNoFailover(t *testing.T) {
	st, cfg := newStore(t)
	a := seedAccount(t, st, "bad", "tok-bad", "id-bad")
	b := seedAccount(t, st, "good", "tok-good", "id-good")
	key := seedGroupEndpointKey(t, st, model.StrategyFallback, a.ID, b.ID)

	rec := &authRecorder{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r.Header.Get("Authorization"))
		if r.Header.Get("Authorization") == "Bearer tok-good" {
			streamOK(w)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream.Close()

	cfg.UpstreamAllowlist = []string{mustHost(t, upstream.URL)}
	// AllowUncertainCrossAccountRetry left at its zero value (false).
	gw := New(st, cfg, WithUpstreamBase(upstream.URL), WithHTTPClient(upstream.Client()),
		WithLogger(quietLogger()))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	resp := doProxyPost(t, srv.URL, key, "k-should-not-help")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 relayed (config off ⇒ no cross-account replay even with a key)", resp.StatusCode)
	}
	if tokens := rec.tokens(); len(tokens) != 1 {
		t.Errorf("upstream attempts = %v, want exactly 1 (no replay)", tokens)
	}
}
