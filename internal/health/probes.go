// This file holds the default HTTP implementations of the two non-usage probe
// kinds (DESIGN.md §12): the zero-spend auth-check (GET {base}/models, §0 D5)
// and the opt-in small-live-request. Both reuse the gateway's rewrite
// conventions — Authorization Bearer + ChatGPT-Account-ID together, plus the
// preserved Codex identity headers. The usage-poll kind is served by
// internal/usage.Client directly.
package health

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// Codex identity header defaults (mirror internal/gateway / internal/usage).
const (
	defaultOriginator = "codex_cli_rs"
	defaultUserAgent  = "codex_cli_rs"

	// DefaultModelsBase is the pinned base for the auth-check probe; /models is
	// appended (verified vs codex backend-client PathStyle::ChatGptApi).
	DefaultModelsBase = "https://chatgpt.com/backend-api/codex"
	// DefaultResponsesBase is the pinned base for the live-request probe;
	// /responses is appended (mirrors gateway.DefaultUpstreamBase).
	DefaultResponsesBase = "https://chatgpt.com/backend-api/codex"
	// DefaultClientVersion is sent as ?client_version= on the auth check.
	DefaultClientVersion = "0.147.0"
	// DefaultLiveModel is the model used for the minimal live request.
	DefaultLiveModel = "gpt-5-codex"
)

// ModelsAuthChecker implements AuthProbe via an authenticated GET
// {base}/models?client_version=<v>: 200 → valid, 401/403 → invalid, anything
// else → error. Zero token spend (DESIGN.md §0 D5).
type ModelsAuthChecker struct {
	httpc         *http.Client
	base          string
	clientVersion string
	originator    string
	userAgent     string
}

// AuthOption customizes a ModelsAuthChecker.
type AuthOption func(*ModelsAuthChecker)

// WithAuthHTTPClient overrides the HTTP client (tests inject httptest).
func WithAuthHTTPClient(c *http.Client) AuthOption {
	return func(a *ModelsAuthChecker) { a.httpc = c }
}

// WithAuthBase overrides the models base URL. /models is appended.
func WithAuthBase(base string) AuthOption {
	return func(a *ModelsAuthChecker) { a.base = strings.TrimRight(base, "/") }
}

// WithClientVersion overrides the client_version query value.
func WithClientVersion(v string) AuthOption {
	return func(a *ModelsAuthChecker) { a.clientVersion = v }
}

// NewModelsAuthChecker builds an auth-check prober with sane defaults.
func NewModelsAuthChecker(opts ...AuthOption) *ModelsAuthChecker {
	a := &ModelsAuthChecker{
		httpc:         &http.Client{Timeout: 30 * time.Second},
		base:          DefaultModelsBase,
		clientVersion: DefaultClientVersion,
		originator:    defaultOriginator,
		userAgent:     defaultUserAgent,
	}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Check performs the auth check. ok=true for 200; ok=false for 401/403; a
// non-nil error for transport failures and other statuses.
func (a *ModelsAuthChecker) Check(ctx context.Context, acct model.Account) (bool, string, error) {
	url := a.base + "/models?client_version=" + a.clientVersion
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, "", fmt.Errorf("auth check: build request: %w", err)
	}
	setCodexHeaders(req, acct, a.originator, a.userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpc.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("auth check: request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	switch {
	case resp.StatusCode == http.StatusOK:
		return true, "models 200", nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return false, fmt.Sprintf("models %d", resp.StatusCode), nil
	default:
		return false, "", fmt.Errorf("auth check: unexpected status %d", resp.StatusCode)
	}
}

// LiveRequester implements LiveProbe via a minimal POST {base}/responses with a
// tiny output cap. A 2xx confirms the account serves traffic; a 429 returns the
// parsed Retry-After so the engine can cooldown-gate.
type LiveRequester struct {
	httpc      *http.Client
	base       string
	model      string
	originator string
	userAgent  string
}

// LiveOption customizes a LiveRequester.
type LiveOption func(*LiveRequester)

// WithLiveHTTPClient overrides the HTTP client (tests inject httptest).
func WithLiveHTTPClient(c *http.Client) LiveOption {
	return func(l *LiveRequester) { l.httpc = c }
}

// WithLiveBase overrides the responses base URL. /responses is appended.
func WithLiveBase(base string) LiveOption {
	return func(l *LiveRequester) { l.base = strings.TrimRight(base, "/") }
}

// WithLiveModel overrides the model used for the minimal request.
func WithLiveModel(m string) LiveOption { return func(l *LiveRequester) { l.model = m } }

// NewLiveRequester builds a live-request prober with sane defaults.
func NewLiveRequester(opts ...LiveOption) *LiveRequester {
	l := &LiveRequester{
		httpc:      &http.Client{Timeout: 30 * time.Second},
		base:       DefaultResponsesBase,
		model:      DefaultLiveModel,
		originator: defaultOriginator,
		userAgent:  defaultUserAgent,
	}
	for _, o := range opts {
		o(l)
	}
	return l
}

// Live sends a minimal completion. ok=true on 2xx; on 429 ok=false with the
// parsed Retry-After; other non-2xx statuses return ok=false (soft fail) and a
// transport failure returns an error.
func (l *LiveRequester) Live(ctx context.Context, acct model.Account) (bool, time.Duration, string, error) {
	body, _ := json.Marshal(map[string]any{
		"model":             l.model,
		"input":             "ping",
		"max_output_tokens": 1,
		"stream":            false,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.base+"/responses", bytes.NewReader(body))
	if err != nil {
		return false, 0, "", fmt.Errorf("live probe: build request: %w", err)
	}
	setCodexHeaders(req, acct, l.originator, l.userAgent)
	req.Header.Set("Content-Type", "application/json")

	resp, err := l.httpc.Do(req)
	if err != nil {
		return false, 0, "", fmt.Errorf("live probe: request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return true, 0, fmt.Sprintf("responses %d", resp.StatusCode), nil
	case resp.StatusCode == http.StatusTooManyRequests:
		return false, parseRetryAfter(resp.Header.Get("Retry-After")), "responses 429", nil
	default:
		return false, 0, fmt.Sprintf("responses %d", resp.StatusCode), nil
	}
}

// setCodexHeaders applies the shared translation-gateway rewrite: Authorization
// + ChatGPT-Account-ID together, plus the Codex identity headers.
func setCodexHeaders(req *http.Request, acct model.Account, originator, userAgent string) {
	req.Header.Set("Authorization", "Bearer "+acct.AccessToken)
	req.Header.Set("ChatGPT-Account-ID", acct.AccountID)
	req.Header.Set("originator", originator)
	req.Header.Set("User-Agent", userAgent)
}

// parseRetryAfter parses a Retry-After header value (delta-seconds only; an
// HTTP-date form is treated as unknown → 0). Negative/zero → 0.
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
