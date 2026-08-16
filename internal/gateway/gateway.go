// Package gateway is poolgate's translation-gateway proxy (DESIGN.md §0 D1 /
// §4 / §6). It is NOT a transparent reverse proxy: the OpenAI-compatible surface
// is inbound only, and on the upstream leg poolgate rewrites Authorization AND
// ChatGPT-Account-ID TOGETHER for the chosen pooled account, preserves/synthesizes
// Codex identity headers (originator, User-Agent, OpenAI-Beta), forces
// stream:true + Accept: text/event-stream, and targets {upstream_base}/responses.
//
// Request flow: inbound sk- key auth (constant-time) -> resolve endpoint ->
// policy group -> internal/policy.Select drives account selection per the group's
// Strategy (fallback / best-quota / load-balance) over a health/usage View backed
// by internal/store (+ the optional health engine) -> translation rewrite ->
// egress allowlist check -> relay SSE with per-chunk flush. WebSocket upgrades
// are NOT accepted in v1 (Codex falls back to HTTP POST+SSE, §0 D2).
//
// Failover stays strictly pre-first-byte (DESIGN.md §19.2): on an upstream
// 401/429/5xx BEFORE any byte reaches the client, the gateway records the failure
// through the health passive hooks (401 -> single-flight refresh-then-retry or
// expire; 429/5xx -> cooldown) and re-selects the next account per the strategy.
// Once streaming starts, the upstream response is committed and never switched.
package gateway

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/policy"
	"github.com/go2-im/poolgate/internal/store"
)

// Defaults for the pinned upstream and synthesized Codex identity headers.
const (
	// DefaultUpstreamBase is the pinned Codex backend base; /responses is
	// appended by the gateway (DESIGN.md §6).
	DefaultUpstreamBase = "https://chatgpt.com/backend-api/codex"
	// DefaultOriginator is Codex's default originator header value.
	DefaultOriginator = "codex_cli_rs"
	// DefaultUserAgent is synthesized when the inbound request omits User-Agent.
	DefaultUserAgent = "codex_cli_rs"
	// DefaultOpenAIBeta is synthesized when the inbound request omits OpenAI-Beta.
	DefaultOpenAIBeta = "responses=experimental"
)

// HealthHooks is the passive-transition surface the gateway calls on real
// upstream failures (DESIGN.md §12 passive hooks). *health.Engine satisfies it.
// It is optional: when nil, the gateway still fails over pre-first-byte but does
// not mutate account state.
type HealthHooks interface {
	// OnUnauthorized handles a 401: refresh via the shared single-flight and
	// return the refreshed account (state ok) on success, or the original account
	// plus an error (state expired) on failure.
	OnUnauthorized(ctx context.Context, acct model.Account) (model.Account, error)
	// OnRateLimited handles a 429/5xx: move the account to cooldown, gated on
	// retryAfter (a conservative default is used when retryAfter <= 0).
	OnRateLimited(ctx context.Context, acct model.Account, retryAfter time.Duration) error
	// OnQuotaExhausted handles a quota=0 signal: move to quota_exhausted, gated on
	// the window reset time.
	OnQuotaExhausted(ctx context.Context, acct model.Account, resetAt time.Time) error
}

// EventSink receives the secret-free notification events the gateway emits when an
// endpoint's policy group has no healthy member (DESIGN.md §11). *notify.Engine
// satisfies it. Optional; when nil, no events are emitted. Emit MUST be
// non-blocking so request handling is never stalled by notification I/O.
type EventSink interface {
	Emit(ev model.NotifyEvent)
}

// Recorder receives a secret-free per-request record for the real-time monitor
// (DESIGN.md §15). *monitor.Engine satisfies it. Optional; when nil, no request
// logs are recorded. Record MUST be non-blocking.
type Recorder interface {
	Record(l model.RequestLog)
}

// Gateway is the proxy HTTP handler set.
type Gateway struct {
	store        *store.Store
	cfg          model.Config
	httpc        *http.Client
	upstreamBase string
	allowlist    []string
	logger       *slog.Logger
	health       HealthHooks
	events       EventSink
	recorder     Recorder

	// Concurrency control (DESIGN.md §23.1). inflight tracks per-account in-flight
	// requests; defaultCap applies when an account's own ConcurrencyCap is 0 (0 =
	// unlimited); queueWait is the bounded-queue window to wait for a free slot
	// when every healthy member is capped before returning 429; retryAfterSecs is
	// the Retry-After sent on that 429.
	inflight       *inflight
	defaultCap     int
	queueWait      time.Duration
	retryAfterSecs int

	// cursors holds one round-robin Cursor per policy group id (load-balance
	// strategy). It persists across requests so rotation is fair over time.
	cursorsMu sync.Mutex
	cursors   map[string]*policy.Cursor

	// wsAff pins a WebSocket turn to one backend across reconnects, keyed on the
	// x-codex-turn-state upgrade header when present (DESIGN.md §0 D3 / §19.1).
	// Within a single connection the backend is always pinned regardless.
	wsAff *wsAffinity
}

// Option customizes a Gateway.
type Option func(*Gateway)

// WithHTTPClient overrides the upstream HTTP client (tests point it at a fake).
func WithHTTPClient(c *http.Client) Option { return func(g *Gateway) { g.httpc = c } }

// WithUpstreamBase overrides the pinned upstream base URL. It must still pass
// the egress allowlist at request time.
func WithUpstreamBase(base string) Option {
	return func(g *Gateway) { g.upstreamBase = strings.TrimRight(base, "/") }
}

// WithLogger sets the structured logger.
func WithLogger(l *slog.Logger) Option { return func(g *Gateway) { g.logger = l } }

// WithHealth wires the health passive-hook surface (DESIGN.md §12). When set, the
// gateway drives account-state transitions on real upstream 401/429/5xx failures
// and retries a refreshed account after a 401.
func WithHealth(h HealthHooks) Option { return func(g *Gateway) { g.health = h } }

// WithEventSink wires the notification sink (DESIGN.md §11). When set, the gateway
// emits a secret-free policy_no_healthy_member event when an endpoint's group has
// no routable account.
func WithEventSink(s EventSink) Option { return func(g *Gateway) { g.events = s } }

// WithRecorder wires the real-time monitor recorder (DESIGN.md §15). When set, the
// gateway records a secret-free per-request log (routing/failover trace, chosen
// account, status, latency, best-effort token counts) for each proxied request.
func WithRecorder(r Recorder) Option { return func(g *Gateway) { g.recorder = r } }

// WithDefaultConcurrencyCap sets a per-account in-flight cap applied to accounts
// whose own ConcurrencyCap is 0 (DESIGN.md §23.1). 0 (default) means unlimited.
func WithDefaultConcurrencyCap(n int) Option {
	return func(g *Gateway) {
		if n >= 0 {
			g.defaultCap = n
		}
	}
}

// WithBackpressure configures the bounded-queue behavior when every healthy
// member is at its concurrency cap: the gateway waits up to queueWait for a slot
// to free before returning 429 with the given Retry-After (seconds). queueWait 0
// means fail fast (immediate 429). retryAfterSecs <= 0 keeps the default (1s).
func WithBackpressure(queueWait time.Duration, retryAfterSecs int) Option {
	return func(g *Gateway) {
		if queueWait >= 0 {
			g.queueWait = queueWait
		}
		if retryAfterSecs > 0 {
			g.retryAfterSecs = retryAfterSecs
		}
	}
}

// New builds a Gateway over st using cfg (for the upstream allowlist).
func New(st *store.Store, cfg model.Config, opts ...Option) *Gateway {
	g := &Gateway{
		store:        st,
		cfg:          cfg,
		upstreamBase: DefaultUpstreamBase,
		allowlist:    cfg.UpstreamAllowlist,
		logger:       slog.Default(),
		cursors:      make(map[string]*policy.Cursor),
		inflight:     newInflight(),
		wsAff:        newWSAffinity(),
		retryAfterSecs: 1,
		// No client Timeout: SSE streams are long-lived; cancellation rides the
		// request context instead.
		httpc: &http.Client{},
	}
	for _, o := range opts {
		o(g)
	}
	return g
}

// Routes returns an http.ServeMux wiring the proxy surface plus health probes.
func (g *Gateway) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	// Primary inbound Responses API route (DESIGN.md §23.5).
	mux.HandleFunc("POST /e/{endpoint}/v1/responses", g.handleResponses)
	// WebSocket transport (DESIGN.md §0 D2/D3): the WS upgrade is a GET.
	mux.HandleFunc("GET /e/{endpoint}/v1/responses", g.handleResponsesWS)
	mux.HandleFunc("/healthz", g.handleHealthz)
	mux.HandleFunc("/readyz", g.handleReadyz)
	return mux
}

// errorBody is poolgate's OpenAI-compatible error envelope (DESIGN.md §19.4).
type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}

func writeError(w http.ResponseWriter, status int, typ, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: errorDetail{Message: msg, Type: typ, Code: code}})
}

// authorizeInbound runs the shared inbound checks for a /responses request
// (HTTP or WebSocket): sk- key auth (constant-time), key lifecycle (expiry + IP
// allowlist), endpoint scoping, and endpoint→group→member-accounts resolution.
// On any failure it writes the error response and returns ok=false, so both
// transports enforce identical authorization with no divergence.
func (g *Gateway) authorizeInbound(w http.ResponseWriter, r *http.Request) (apiKey model.ApiKey, endpoint string, group model.PolicyGroup, accounts []model.Account, ok bool) {
	// (1) inbound sk- key auth, constant-time.
	key, has := bearerToken(r)
	if !has {
		writeError(w, http.StatusUnauthorized, "poolgate_missing_key",
			"missing_api_key", "missing or malformed Authorization: Bearer sk-... header")
		return model.ApiKey{}, "", model.PolicyGroup{}, nil, false
	}
	apiKey, matched := g.authenticate(r.Context(), key)
	if !matched {
		writeError(w, http.StatusUnauthorized, "poolgate_invalid_key",
			"invalid_api_key", "invalid API key")
		return model.ApiKey{}, "", model.PolicyGroup{}, nil, false
	}

	// (1a) key lifecycle: reject an expired key and enforce its IP allowlist
	// (DESIGN.md §22). The allowlist matches the direct peer (RemoteAddr).
	if apiKey.Expired(time.Now().UTC()) {
		writeError(w, http.StatusUnauthorized, "poolgate_key_expired",
			"key_expired", "API key has expired")
		return model.ApiKey{}, "", model.PolicyGroup{}, nil, false
	}
	if !keyIPAllowed(apiKey, r) {
		writeError(w, http.StatusForbidden, "poolgate_key_ip_denied",
			"key_ip_denied", "client IP is not allowed for this API key")
		return model.ApiKey{}, "", model.PolicyGroup{}, nil, false
	}

	endpoint = r.PathValue("endpoint")

	// (1b) endpoint scoping: empty scope = all endpoints.
	if !keyScopedTo(apiKey, endpoint) {
		writeError(w, http.StatusForbidden, "poolgate_key_unscoped",
			"key_unscoped", "API key is not scoped to endpoint "+endpoint)
		return model.ApiKey{}, "", model.PolicyGroup{}, nil, false
	}

	// (2) resolve endpoint -> group -> ordered member accounts.
	_, group, accounts, err := g.store.ResolveEndpoint(r.Context(), endpoint)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "poolgate_unknown_endpoint",
				"unknown_endpoint", "no such endpoint: "+endpoint)
			return model.ApiKey{}, "", model.PolicyGroup{}, nil, false
		}
		writeError(w, http.StatusInternalServerError, "poolgate_internal",
			"internal_error", "failed to resolve endpoint")
		return model.ApiKey{}, "", model.PolicyGroup{}, nil, false
	}
	return apiKey, endpoint, group, accounts, true
}

func (g *Gateway) handleResponses(w http.ResponseWriter, r *http.Request) {
	// WebSocket upgrades are a GET and are served by handleResponsesWS via the
	// GET route (DESIGN.md §0 D2/D3); this POST path is HTTP+SSE only.
	apiKey, endpoint, group, accounts, ok := g.authorizeInbound(w, r)
	if !ok {
		return
	}

	// Per-request monitor record (DESIGN.md §15): secret-free, populated as the
	// request progresses and emitted at every terminal path via rec.finish.
	rec := &requestRecord{
		g:     g,
		start: time.Now(),
		log: model.RequestLog{
			Endpoint:    endpoint,
			Policy:      group.Name,
			APIKeyID:    apiKey.ID,
			APIKeyLabel: apiKey.Label,
			SessionID:   sessionID(r, apiKey),
		},
	}

	eligible := eligibleAccounts(group, accounts)
	if len(eligible) == 0 {
		g.emitNoHealthyMember(endpoint, group)
		rec.finish(http.StatusServiceUnavailable, model.Account{}, "no_healthy_account", 0, 0)
		writeError(w, http.StatusServiceUnavailable, "poolgate_no_healthy_account",
			"no_healthy_account", "no healthy account available for endpoint "+endpoint)
		return
	}

	// Read and normalize the inbound body once (force stream:true).
	inBody, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		rec.finish(http.StatusBadRequest, model.Account{}, "bad_request", 0, 0)
		writeError(w, http.StatusBadRequest, "poolgate_bad_request",
			"bad_request", "failed to read request body")
		return
	}
	rec.log.Model = model.SanitizeField(extractModel(inBody))
	upBody, err := forceStream(inBody)
	if err != nil {
		rec.finish(http.StatusBadRequest, model.Account{}, "bad_request", 0, 0)
		writeError(w, http.StatusBadRequest, "poolgate_bad_request",
			"bad_request", "request body is not valid JSON")
		return
	}

	// (4) egress allowlist check (we carry Authorization upstream).
	target := g.upstreamBase + "/responses"
	if err := g.checkEgress(target); err != nil {
		rec.finish(http.StatusBadGateway, model.Account{}, "egress_refused", 0, 0)
		writeError(w, http.StatusBadGateway, "poolgate_egress_refused",
			"egress_refused", err.Error())
		return
	}

	// (3) + (5) strategy-driven selection with pre-first-byte failover
	// (DESIGN.md §4 / §19.2). policy.Select picks per the group's Strategy over a
	// health/usage View; on a pre-stream failure we record it (health passive
	// hooks) and re-select the next candidate until one streams or none remain.
	view := g.buildView(r.Context(), group, eligible)
	byID := make(map[string]int, len(eligible))
	for i, a := range eligible {
		byID[a.ID] = i
	}

	var lastStatus int
	triedAny := false
	bpDeadline := time.Now().Add(g.queueWait)
	for {
		acct, serr := policy.Select(group.Strategy, eligible, view)
		if serr != nil {
			// Nothing selectable. If we haven't tried anyone yet and the members
			// are state-healthy, the only reason is that every member is at its
			// concurrency cap → bounded-queue backpressure (DESIGN.md §23.1): wait
			// briefly for a slot, else 429 + Retry-After.
			if errors.Is(serr, policy.ErrNoHealthyMember) && !triedAny && g.anyCapped(eligible, view) {
				if g.waitForSlot(r.Context(), eligible, view, bpDeadline) {
					continue // a slot freed within the bounded-queue window
				}
				rec.finish(http.StatusTooManyRequests, model.Account{}, "backpressure", 0, 0)
				w.Header().Set("Retry-After", strconv.Itoa(g.retryAfterSecs))
				writeError(w, http.StatusTooManyRequests, "poolgate_backpressure",
					"backpressure", "all accounts are at their concurrency limit; retry after a moment")
				return
			}
			break // no remaining healthy candidate for this strategy
		}
		// Atomically reserve a slot honoring the account's cap. Losing this race
		// (another request took the last slot between Select and reserve) means the
		// account is now at cap: skip it — the next Select's atCap gate (live) will
		// exclude it, so we either pick another member or fall into backpressure.
		if !g.inflight.tryAdd(acct.ID, view.caps[acct.ID]) {
			continue
		}
		triedAny = true
		streamed, status, retryAfter, tokensIn, tokensOut := g.forward(w, r, target, upBody, acct)
		g.inflight.done(acct.ID)
		if streamed {
			rec.trace = append(rec.trace, acct.ID+":streamed")
			rec.finish(status, acct, "", tokensIn, tokensOut)
			return // response already written to client; do not re-select.
		}
		rec.trace = append(rec.trace, fmt.Sprintf("%s:%d", acct.ID, status))
		lastStatus = status
		g.logger.Warn("account attempt failed pre-stream",
			slog.String("endpoint", endpoint), slog.String("account", acct.ID),
			slog.String("strategy", string(group.Strategy)), slog.Int("status", status))
		g.recordFailure(r.Context(), eligible, byID, view, acct, status, retryAfter)
	}

	rec.finish(http.StatusBadGateway, model.Account{}, "all_exhausted", 0, 0)
	writeError(w, http.StatusBadGateway, "poolgate_all_exhausted",
		"all_exhausted", fmt.Sprintf("all accounts failed (last upstream status %d)", lastStatus))
}

// requestRecord accumulates a monitor RequestLog across a request's lifecycle and
// emits it once, secret-free, via finish (a no-op when no recorder is wired).
type requestRecord struct {
	g     *Gateway
	start time.Time
	log   model.RequestLog
	trace []string
}

// finish stamps the terminal fields and hands the record to the recorder.
func (rc *requestRecord) finish(status int, acct model.Account, errType string, tokensIn, tokensOut int) {
	if rc.g.recorder == nil {
		return
	}
	rc.log.At = rc.start
	rc.log.Status = status
	rc.log.AccountID = acct.ID
	rc.log.AccountLabel = acct.Label
	rc.log.ErrorType = errType
	rc.log.TokensIn = tokensIn
	rc.log.TokensOut = tokensOut
	rc.log.LatencyMS = int(time.Since(rc.start) / time.Millisecond)
	rc.log.Trace = model.SanitizeField(strings.Join(rc.trace, "; "))
	rc.g.recorder.Record(rc.log)
}

// recordFailure applies the health passive hook for a pre-stream upstream failure
// and updates the routeView so the next policy.Select advances correctly:
//
//   - 401: refresh once via the shared single-flight. On success the account's
//     token is swapped in place and it stays selectable (retried with fresh
//     creds); on failure (or a repeat 401) it is marked tried.
//   - 429: cooldown gated on Retry-After, then marked tried.
//   - 5xx / transport error / other: cooldown (429/5xx) or just marked tried.
//
// When no health surface is wired, the account is simply marked tried so
// failover still advances without mutating account state.
func (g *Gateway) recordFailure(ctx context.Context, accounts []model.Account, byID map[string]int, view *routeView, acct model.Account, status int, retryAfter time.Duration) {
	if g.health == nil {
		view.tried[acct.ID] = true
		return
	}
	switch {
	case status == http.StatusUnauthorized:
		if view.refreshed[acct.ID] {
			view.tried[acct.ID] = true // already retried once; give up on it.
			return
		}
		view.refreshed[acct.ID] = true
		refreshed, err := g.health.OnUnauthorized(ctx, acct)
		if err != nil {
			view.tried[acct.ID] = true // refresh failed -> account now expired.
			return
		}
		if i, ok := byID[refreshed.ID]; ok {
			accounts[i] = refreshed // retry with rotated token; still selectable.
		}
	case status == http.StatusTooManyRequests:
		_ = g.health.OnRateLimited(ctx, acct, retryAfter)
		view.tried[acct.ID] = true
	case status >= 500:
		_ = g.health.OnRateLimited(ctx, acct, 0)
		view.tried[acct.ID] = true
	default:
		view.tried[acct.ID] = true
	}
}

// forward issues one upstream attempt for acct. It returns streamed=true once
// any byte (headers + status) has been written to the client; in that case the
// caller MUST NOT re-select. If the upstream errors before streaming, it returns
// streamed=false, the upstream status (0 on transport error), and any parsed
// Retry-After so the caller may cooldown-gate and try the next account. On a
// streamed response it also returns best-effort token counts sniffed from the
// SSE usage event (DESIGN.md §15 / §23.4).
func (g *Gateway) forward(w http.ResponseWriter, r *http.Request, target string, body []byte, acct model.Account) (streamed bool, status int, retryAfter time.Duration, tokensIn, tokensOut int) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return false, 0, 0, 0, 0
	}

	// Translation-gateway rewrite: Authorization + ChatGPT-Account-ID TOGETHER.
	req.Header.Set("Authorization", "Bearer "+acct.AccessToken)
	req.Header.Set("ChatGPT-Account-ID", acct.AccountID)

	// Preserve/synthesize Codex identity headers.
	req.Header.Set("originator", headerOrDefault(r, "originator", DefaultOriginator))
	req.Header.Set("User-Agent", headerOrDefault(r, "User-Agent", DefaultUserAgent))
	req.Header.Set("OpenAI-Beta", headerOrDefault(r, "OpenAI-Beta", DefaultOpenAIBeta))

	// Force streaming.
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.httpc.Do(req)
	if err != nil {
		return false, 0, 0, 0, 0
	}

	// Pre-stream upstream error -> allow re-selection (nothing written yet).
	if resp.StatusCode >= 400 {
		ra := parseRetryAfter(resp.Header.Get("Retry-After"))
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		return false, resp.StatusCode, ra, 0, 0
	}

	// Commit to this account: relay with per-chunk flush.
	defer resp.Body.Close()
	relayHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)
	tin, tout := relayStream(w, resp.Body)
	return true, resp.StatusCode, 0, tin, tout
}

// authenticate constant-time-compares the presented key against every stored
// key (crypto/subtle), returning the matched ApiKey. Comparing against all keys
// avoids leaking which key (if any) matched via timing.
func (g *Gateway) authenticate(ctx context.Context, presented string) (model.ApiKey, bool) {
	keys, err := g.store.ListApiKeys(ctx)
	if err != nil {
		return model.ApiKey{}, false
	}
	var matched model.ApiKey
	found := false
	pb := []byte(presented)
	for _, k := range keys {
		if subtle.ConstantTimeCompare(pb, []byte(k.Key)) == 1 {
			matched = k
			found = true
		}
	}
	return matched, found
}

func (g *Gateway) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// handleReadyz reports ready when migrations are applied AND at least one
// endpoint has an eligible account. It is secret-free and leaks no account ids
// (DESIGN.md §21.1).
func (g *Gateway) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ver, err := g.store.SchemaVersion(r.Context())
	if err != nil || ver == 0 {
		writeError(w, http.StatusServiceUnavailable, "poolgate_not_ready",
			"not_ready", "migrations not applied")
		return
	}
	if !g.anyEndpointReady(r.Context()) {
		writeError(w, http.StatusServiceUnavailable, "poolgate_not_ready",
			"not_ready", "no endpoint has a healthy account")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ready"}`))
}

func (g *Gateway) anyEndpointReady(ctx context.Context) bool {
	names, err := g.store.ListEndpointNames(ctx)
	if err != nil {
		return false
	}
	for _, name := range names {
		_, group, accounts, err := g.store.ResolveEndpoint(ctx, name)
		if err != nil {
			continue
		}
		if len(eligibleAccounts(group, accounts)) > 0 {
			return true
		}
	}
	return false
}

// emitNoHealthyMember emits a secret-free policy_no_healthy_member event
// (DESIGN.md §11) referencing the endpoint and group by name only. Best-effort:
// a nil sink is a no-op and Emit never blocks.
func (g *Gateway) emitNoHealthyMember(endpoint string, group model.PolicyGroup) {
	if g.events == nil {
		return
	}
	g.events.Emit(model.NotifyEvent{
		Kind:        model.EventPolicyNoHealthyMember,
		Endpoint:    endpoint,
		PolicyGroup: group.Name,
		Message:     "poolgate: endpoint " + endpoint + " has no healthy account (policy group " + group.Name + ")",
		At:          time.Now().UTC(),
	})
}

// checkEgress refuses Authorization-bearing egress to any host not on the
// allowlist (DESIGN.md §6).
func (g *Gateway) checkEgress(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid upstream url")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("upstream scheme %q not allowed", u.Scheme)
	}
	host := u.Hostname()
	for _, allowed := range g.allowlist {
		if host == allowed {
			return nil
		}
	}
	return fmt.Errorf("egress to host %q is not on the allowlist", host)
}

// ---- helpers --------------------------------------------------------------

// eligibleAccounts returns the members that are routable regardless of strategy.
// Healthy = ok or unknown (a freshly imported account is unknown but usable);
// terminal/cooldown/expired/exhausted are skipped. This is the strategy-agnostic
// health filter used both to gate the 503 (no healthy account) response and to
// seed the routeView.
func eligibleAccounts(group model.PolicyGroup, accounts []model.Account) []model.Account {
	out := make([]model.Account, 0, len(accounts))
	for _, a := range accounts {
		if routable(a.State) {
			out = append(out, a)
		}
	}
	_ = group // health filter is strategy-agnostic; ordering is stored order.
	return out
}

// routable reports whether an account state is eligible for routing.
func routable(s model.AccountState) bool {
	return s == model.StateOK || s == model.StateUnknown
}

// routeView is the gateway's per-request policy.View. It filters selection to the
// still-routable, not-yet-tried, not-at-cap members and supplies best-quota
// headroom from the latest usage snapshot, live in-flight counts for
// least-in-flight load-balance, and the group's persistent round-robin cursor.
type routeView struct {
	healthy   map[string]bool    // base routability (ok/unknown) at request start
	headroom  map[string]float64 // best-quota min headroom (only populated for that strategy)
	tried     map[string]bool    // accounts already attempted this request
	refreshed map[string]bool    // accounts whose token was refreshed once after a 401
	caps      map[string]int     // effective per-account concurrency cap (0 = unlimited)
	inflight  *inflight          // live per-account in-flight counts (shared with the gateway)
	cursor    *policy.Cursor
}

// IsHealthy reports whether the account is still a selectable candidate: routable
// at request start, not yet tried in this request, and not at its concurrency cap.
func (v *routeView) IsHealthy(id string) bool {
	return v.healthy[id] && !v.tried[id] && !v.atCap(id)
}

// atCap reports whether the account is at (or over) its effective concurrency cap.
func (v *routeView) atCap(id string) bool {
	cap := v.caps[id]
	if cap <= 0 || v.inflight == nil {
		return false // unlimited (or no tracker)
	}
	return v.inflight.count(id) >= cap
}

// InFlight returns the account's live in-flight count (0 when untracked).
func (v *routeView) InFlight(id string) int {
	if v.inflight == nil {
		return 0
	}
	return v.inflight.count(id)
}

// Headroom returns the account's best-quota headroom (default 100 = unconstrained
// when no usage snapshot exists).
func (v *routeView) Headroom(id string) float64 {
	if v.headroom == nil {
		return 100
	}
	return v.headroom[id]
}

// Cursor returns the group's round-robin cursor (load-balance).
func (v *routeView) Cursor() *policy.Cursor { return v.cursor }

// buildView builds the routeView for one request. Base routability comes from the
// eligible members; best-quota additionally loads each member's latest usage
// snapshot to compute min headroom (missing snapshot => 100, unconstrained).
func (g *Gateway) buildView(ctx context.Context, group model.PolicyGroup, eligible []model.Account) *routeView {
	v := &routeView{
		healthy:   make(map[string]bool, len(eligible)),
		tried:     make(map[string]bool),
		refreshed: make(map[string]bool),
		caps:      make(map[string]int, len(eligible)),
		inflight:  g.inflight,
		cursor:    g.cursorFor(group.ID),
	}
	for _, a := range eligible {
		v.healthy[a.ID] = routable(a.State)
		v.caps[a.ID] = g.effectiveCap(a)
	}
	if group.Strategy == model.StrategyBestQuota {
		v.headroom = make(map[string]float64, len(eligible))
		for _, a := range eligible {
			h := 100.0
			if snap, err := g.store.GetLatestUsage(ctx, a.ID); err == nil {
				h = policy.MinHeadroom(model.Usage{PlanType: snap.PlanType, Windows: snap.Windows})
			}
			v.headroom[a.ID] = h
		}
	}
	return v
}

// effectiveCap is the account's own ConcurrencyCap, or the gateway default when
// that is 0. 0 means unlimited (DESIGN.md §23.1).
func (g *Gateway) effectiveCap(a model.Account) int {
	if a.ConcurrencyCap > 0 {
		return a.ConcurrencyCap
	}
	return g.defaultCap
}

// anyCapped reports whether at least one eligible member is currently at its
// concurrency cap (i.e. concurrency limiting is actually in play).
func (g *Gateway) anyCapped(eligible []model.Account, view *routeView) bool {
	for _, a := range eligible {
		if view.atCap(a.ID) {
			return true
		}
	}
	return false
}

// waitForSlot blocks until an eligible member drops below its concurrency cap, the
// deadline passes, or the request is cancelled. It returns true if a slot freed
// (the caller should re-select). This is the bounded queue of DESIGN.md §23.1.
func (g *Gateway) waitForSlot(ctx context.Context, eligible []model.Account, view *routeView, deadline time.Time) bool {
	const poll = 20 * time.Millisecond
	for {
		for _, a := range eligible {
			if !view.atCap(a.ID) {
				return true
			}
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		wait := poll
		if remaining < wait {
			wait = remaining
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(wait):
		}
	}
}

// cursorFor returns the persistent round-robin cursor for a group id, creating it
// on first use. Cursors are shared across requests so load-balance rotates fairly.
func (g *Gateway) cursorFor(groupID string) *policy.Cursor {
	g.cursorsMu.Lock()
	defer g.cursorsMu.Unlock()
	c, ok := g.cursors[groupID]
	if !ok {
		c = &policy.Cursor{}
		g.cursors[groupID] = c
	}
	return c
}

// parseRetryAfter parses a Retry-After header (delta-seconds only; the HTTP-date
// form is treated as unknown => 0). Non-numeric or non-positive values => 0.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// bearerToken extracts the sk- token from Authorization: Bearer <token>.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	if tok == "" {
		return "", false
	}
	return tok, true
}

func keyScopedTo(k model.ApiKey, endpoint string) bool {
	if len(k.Endpoints) == 0 {
		return true // unscoped = all endpoints
	}
	for _, e := range k.Endpoints {
		if e == endpoint {
			return true
		}
	}
	return false
}

// keyIPAllowed reports whether the request's client IP is permitted by the key's
// IP allowlist. An empty allowlist permits any IP. Each entry is an IP or CIDR.
func keyIPAllowed(k model.ApiKey, r *http.Request) bool {
	if len(k.IPAllowlist) == 0 {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(clientIP(r)))
	if ip == nil {
		return false
	}
	for _, entry := range k.IPAllowlist {
		if ipMatches(ip, entry) {
			return true
		}
	}
	return false
}

// ipMatches reports whether ip is covered by a single allowlist entry (an exact
// IP or a CIDR). A malformed entry never matches.
func ipMatches(ip net.IP, entry string) bool {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return false
	}
	if strings.Contains(entry, "/") {
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			return false
		}
		return cidr.Contains(ip)
	}
	e := net.ParseIP(entry)
	return e != nil && e.Equal(ip)
}

func headerOrDefault(r *http.Request, name, def string) string {
	if v := r.Header.Get(name); v != "" {
		return v
	}
	return def
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// forceStream sets "stream": true on a JSON request body (DESIGN.md §0 D1).
func forceStream(body []byte) ([]byte, error) {
	var m map[string]any
	if len(bytes.TrimSpace(body)) == 0 {
		m = map[string]any{}
	} else if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	m["stream"] = true
	return json.Marshal(m)
}

// relayHeaders copies safe upstream headers to the client and tunes streaming.
func relayHeaders(w http.ResponseWriter, resp *http.Response) {
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	} else {
		w.Header().Set("Content-Type", "text/event-stream")
	}
	// Relay upstream rate-limit headers (DESIGN.md §23.3).
	for _, h := range []string{"Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	// Keep tunnels/proxies from buffering or transforming the stream.
	w.Header().Set("Cache-Control", "no-transform")
	w.Header().Set("X-Accel-Buffering", "no")
}

// relayStream copies the upstream body to the client, flushing each chunk so
// SSE events reach the caller immediately (DESIGN.md §14 streaming pass-through).
// It also keeps a bounded tail of the stream and, at EOF, sniffs the final SSE
// usage event for token counts (best-effort; 0 when absent — DESIGN.md §15/§23.4).
func relayStream(w http.ResponseWriter, body io.Reader) (tokensIn, tokensOut int) {
	flusher, _ := w.(http.Flusher)
	tail := &tailBuffer{max: 64 << 10}
	buf := make([]byte, 16<<10)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				break
			}
			if flusher != nil {
				flusher.Flush()
			}
			_, _ = tail.Write(buf[:n])
		}
		if err != nil {
			// EOF or transport error: stop. Mid-stream we propagate nothing
			// extra (§19.2).
			break
		}
	}
	return parseUsage(tail.bytes())
}

// tailBuffer retains only the last max bytes written to it — enough to hold the
// final SSE usage event without buffering the whole (possibly huge) stream.
type tailBuffer struct {
	buf []byte
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) bytes() []byte { return t.buf }

var (
	reInputTokens  = regexp.MustCompile(`"input_tokens"\s*:\s*(\d+)`)
	reOutputTokens = regexp.MustCompile(`"output_tokens"\s*:\s*(\d+)`)
)

// parseUsage best-effort extracts token counts from an SSE usage payload. The
// Responses API emits usage in the terminal event, so the LAST match in the tail
// is the authoritative total.
func parseUsage(b []byte) (tokensIn, tokensOut int) {
	if m := reInputTokens.FindAllSubmatch(b, -1); len(m) > 0 {
		tokensIn = atoiSafe(m[len(m)-1][1])
	}
	if m := reOutputTokens.FindAllSubmatch(b, -1); len(m) > 0 {
		tokensOut = atoiSafe(m[len(m)-1][1])
	}
	return tokensIn, tokensOut
}

func atoiSafe(b []byte) int {
	n, err := strconv.Atoi(string(b))
	if err != nil {
		return 0
	}
	return n
}

// sessionID resolves the monitor's session grouping (DESIGN.md §15): a
// client-supplied X-Session-Id header when present, else a value derived per
// (api-key + client ip). It is sanitized (control chars stripped, length capped)
// and is used for logging/monitoring ONLY — never for routing or affinity.
func sessionID(r *http.Request, k model.ApiKey) string {
	if s := r.Header.Get("X-Session-Id"); s != "" {
		return model.SanitizeField(s)
	}
	return model.SanitizeField("k:" + k.ID + ":" + clientIP(r))
}

// clientIP returns the peer IP (host portion of RemoteAddr). Forwarded-header
// resolution for trusted proxies is a separate concern (§14) and not used here.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// extractModel best-effort reads the "model" field from the inbound JSON body so
// the monitor can group by model. Failure yields "".
func extractModel(body []byte) string {
	var m struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &m)
	return m.Model
}
