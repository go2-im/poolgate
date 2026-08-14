// Package gateway is poolgate's translation-gateway proxy (DESIGN.md §0 D1 /
// §4 / §6). It is NOT a transparent reverse proxy: the OpenAI-compatible surface
// is inbound only, and on the upstream leg poolgate rewrites Authorization AND
// ChatGPT-Account-ID TOGETHER for the chosen pooled account, preserves/synthesizes
// Codex identity headers (originator, User-Agent, OpenAI-Beta), forces
// stream:true + Accept: text/event-stream, and targets {upstream_base}/responses.
//
// Request flow: inbound sk- key auth (constant-time) -> resolve endpoint ->
// policy group -> first healthy account (fallback strategy) -> translation
// rewrite -> egress allowlist check -> relay SSE with per-chunk flush. WebSocket
// upgrades are NOT accepted in v1 (Codex falls back to HTTP POST+SSE, §0 D2).
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
	"net/http"
	"net/url"
	"strings"

	"github.com/go2-im/poolgate/internal/model"
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

// Gateway is the proxy HTTP handler set.
type Gateway struct {
	store        *store.Store
	cfg          model.Config
	httpc        *http.Client
	upstreamBase string
	allowlist    []string
	logger       *slog.Logger
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

// New builds a Gateway over st using cfg (for the upstream allowlist).
func New(st *store.Store, cfg model.Config, opts ...Option) *Gateway {
	g := &Gateway{
		store:        st,
		cfg:          cfg,
		upstreamBase: DefaultUpstreamBase,
		allowlist:    cfg.UpstreamAllowlist,
		logger:       slog.Default(),
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

func (g *Gateway) handleResponses(w http.ResponseWriter, r *http.Request) {
	// v1 does not accept WebSocket upgrades — Codex falls back to HTTP+SSE.
	if isWebSocketUpgrade(r) {
		writeError(w, http.StatusNotImplemented, "poolgate_websocket_unsupported",
			"websocket_unsupported", "websocket upgrade is not supported; use HTTP POST + SSE")
		return
	}

	// (1) inbound sk- key auth, constant-time.
	key, ok := bearerToken(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "poolgate_missing_key",
			"missing_api_key", "missing or malformed Authorization: Bearer sk-... header")
		return
	}
	apiKey, ok := g.authenticate(r.Context(), key)
	if !ok {
		writeError(w, http.StatusUnauthorized, "poolgate_invalid_key",
			"invalid_api_key", "invalid API key")
		return
	}

	endpoint := r.PathValue("endpoint")

	// (1b) endpoint scoping: empty scope = all endpoints.
	if !keyScopedTo(apiKey, endpoint) {
		writeError(w, http.StatusForbidden, "poolgate_key_unscoped",
			"key_unscoped", "API key is not scoped to endpoint "+endpoint)
		return
	}

	// (2) resolve endpoint -> group -> ordered member accounts.
	_, group, accounts, err := g.store.ResolveEndpoint(r.Context(), endpoint)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "poolgate_unknown_endpoint",
				"unknown_endpoint", "no such endpoint: "+endpoint)
			return
		}
		writeError(w, http.StatusInternalServerError, "poolgate_internal",
			"internal_error", "failed to resolve endpoint")
		return
	}

	eligible := eligibleAccounts(group, accounts)
	if len(eligible) == 0 {
		writeError(w, http.StatusServiceUnavailable, "poolgate_no_healthy_account",
			"no_healthy_account", "no healthy account available for endpoint "+endpoint)
		return
	}

	// Read and normalize the inbound body once (force stream:true).
	inBody, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "poolgate_bad_request",
			"bad_request", "failed to read request body")
		return
	}
	upBody, err := forceStream(inBody)
	if err != nil {
		writeError(w, http.StatusBadRequest, "poolgate_bad_request",
			"bad_request", "request body is not valid JSON")
		return
	}

	// (4) egress allowlist check (we carry Authorization upstream).
	target := g.upstreamBase + "/responses"
	if err := g.checkEgress(target); err != nil {
		writeError(w, http.StatusBadGateway, "poolgate_egress_refused",
			"egress_refused", err.Error())
		return
	}

	// (3) + (5) fallback over eligible accounts; re-select only before the first
	// byte is written to the client (DESIGN.md §19.2 failover boundary).
	var lastStatus int
	for _, acct := range eligible {
		streamed, status := g.forward(w, r, target, upBody, acct)
		if streamed {
			return // response already written to client; do not re-select.
		}
		lastStatus = status
		g.logger.Warn("account attempt failed pre-stream",
			slog.String("endpoint", endpoint), slog.String("account", acct.ID),
			slog.Int("status", status))
	}

	writeError(w, http.StatusBadGateway, "poolgate_all_exhausted",
		"all_exhausted", fmt.Sprintf("all accounts failed (last upstream status %d)", lastStatus))
}

// forward issues one upstream attempt for acct. It returns streamed=true once
// any byte (headers + status) has been written to the client; in that case the
// caller MUST NOT re-select. If the upstream errors before streaming, it returns
// streamed=false and the upstream status (0 on transport error) so the caller
// may try the next account.
func (g *Gateway) forward(w http.ResponseWriter, r *http.Request, target string, body []byte, acct model.Account) (streamed bool, status int) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return false, 0
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
		return false, 0
	}

	// Pre-stream upstream error -> allow re-selection (nothing written yet).
	if resp.StatusCode >= 400 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		return false, resp.StatusCode
	}

	// Commit to this account: relay with per-chunk flush.
	defer resp.Body.Close()
	relayHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)
	relayStream(w, resp.Body)
	return true, resp.StatusCode
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

// eligibleAccounts returns the fallback-ordered members that are routable.
// v1 fallback: first healthy in order. Healthy = ok or unknown (a freshly
// imported account is unknown but usable); terminal/cooldown/expired/exhausted
// are skipped.
func eligibleAccounts(group model.PolicyGroup, accounts []model.Account) []model.Account {
	out := make([]model.Account, 0, len(accounts))
	for _, a := range accounts {
		if a.State == model.StateOK || a.State == model.StateUnknown {
			out = append(out, a)
		}
	}
	_ = group // strategy is fallback in v1; ordering is the stored member order.
	return out
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
func relayStream(w http.ResponseWriter, body io.Reader) {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 16<<10)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if err != io.EOF {
				// Best-effort: propagate nothing extra mid-stream (§19.2).
				_ = err
			}
			return
		}
	}
}
