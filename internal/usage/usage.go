// Package usage reads an account's generic percent-usage windows from the
// upstream usage endpoint (DESIGN.md §0 D4 / §12 probe kind 1). It is a
// zero-token-spend probe: it GETs {base}/wham/usage with the account's auth
// headers (reusing the gateway's rewrite conventions — Authorization Bearer +
// ChatGPT-Account-ID + originator) and parses the response into the GENERIC
// model.Usage (plan_type + N windows), with NO hardcoded 5h/1week semantics.
//
// The exact JSON shape is verified against openai/codex@rust-v0.147.0
// (backend-client crate: RateLimitStatusPayload / RateLimitStatusDetails /
// RateLimitWindowSnapshot, flattened at {base}/wham/usage):
//
//	{
//	  "plan_type": "plus",
//	  "rate_limit": {
//	    "allowed": true, "limit_reached": false,
//	    "primary_window":   {"used_percent":12,"limit_window_seconds":18000,"reset_after_seconds":3600,"reset_at":1699999999},
//	    "secondary_window": {"used_percent":40,"limit_window_seconds":604800,"reset_after_seconds":86400,"reset_at":1700500000}
//	  },
//	  "additional_rate_limits": [
//	    {"limit_name":"gpt-5-codex","metered_feature":"codex","rate_limit":{"primary_window":{...}}}
//	  ],
//	  "rate_limit_reached_type": {"type":"rate_limit_reached"},
//	  "rate_limit_reset_credits": {"available_count":3}
//	}
package usage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// DefaultBase is the pinned usage base. NOTE: /wham/usage lives under
// backend-api directly, NOT under the gateway's /backend-api/codex responses
// base (verified vs codex backend-client PathStyle::ChatGptApi).
const DefaultBase = "https://chatgpt.com/backend-api"

// Codex identity header defaults (mirror internal/gateway conventions).
const (
	defaultOriginator = "codex_cli_rs"
	defaultUserAgent  = "codex_cli_rs"
)

// ErrTokenInvalid is returned (wrapped) when the usage endpoint answers 401,
// meaning the account's access token is no longer valid. Callers use it to
// distinguish "needs refresh/expired" from a transient upstream error via
// errors.Is.
var ErrTokenInvalid = errors.New("usage: token invalid (401)")

// Client fetches generic usage windows for an account.
type Client struct {
	httpc      *http.Client
	base       string
	originator string
	userAgent  string
	now        func() time.Time
}

// Option customizes a Client.
type Option func(*Client)

// WithHTTPClient overrides the HTTP client (tests inject an httptest client).
func WithHTTPClient(c *http.Client) Option { return func(cl *Client) { cl.httpc = c } }

// WithBase overrides the usage base URL. /wham/usage is appended.
func WithBase(base string) Option {
	return func(cl *Client) { cl.base = strings.TrimRight(base, "/") }
}

// WithClock injects a clock (default time.Now). It is used only to resolve a
// window's ResetsAt from reset_after_seconds when the absolute reset_at is
// absent, keeping tests deterministic.
func WithClock(now func() time.Time) Option { return func(cl *Client) { cl.now = now } }

// WithOriginator overrides the originator header value.
func WithOriginator(o string) Option { return func(cl *Client) { cl.originator = o } }

// WithUserAgent overrides the User-Agent header value.
func WithUserAgent(ua string) Option { return func(cl *Client) { cl.userAgent = ua } }

// New builds a usage Client with sane defaults.
func New(opts ...Option) *Client {
	c := &Client{
		httpc:      &http.Client{Timeout: 30 * time.Second},
		base:       DefaultBase,
		originator: defaultOriginator,
		userAgent:  defaultUserAgent,
		now:        time.Now,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// ---- raw wire shape (verified vs codex backend-client) --------------------

type rawPayload struct {
	PlanType             string              `json:"plan_type"`
	RateLimit            *rawStatusDetails   `json:"rate_limit"`
	AdditionalRateLimits []rawAdditionalRate `json:"additional_rate_limits"`
}

type rawAdditionalRate struct {
	LimitName      string            `json:"limit_name"`
	MeteredFeature string            `json:"metered_feature"`
	RateLimit      *rawStatusDetails `json:"rate_limit"`
}

type rawStatusDetails struct {
	Allowed         bool       `json:"allowed"`
	LimitReached    bool       `json:"limit_reached"`
	PrimaryWindow   *rawWindow `json:"primary_window"`
	SecondaryWindow *rawWindow `json:"secondary_window"`
}

type rawWindow struct {
	UsedPercent        float64 `json:"used_percent"`
	LimitWindowSeconds int     `json:"limit_window_seconds"`
	ResetAfterSeconds  int     `json:"reset_after_seconds"`
	ResetAt            int64   `json:"reset_at"`
}

// Fetch GETs {base}/wham/usage with acct's auth headers and returns the parsed
// generic Usage. A 401 yields ErrTokenInvalid (wrapped); other non-2xx statuses
// and transport/decroding failures return a descriptive error.
func (c *Client) Fetch(ctx context.Context, acct model.Account) (model.Usage, error) {
	url := c.base + "/wham/usage"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return model.Usage{}, fmt.Errorf("usage: build request: %w", err)
	}
	// Reuse gateway rewrite conventions: Authorization + ChatGPT-Account-ID
	// together, plus preserved Codex identity headers.
	req.Header.Set("Authorization", "Bearer "+acct.AccessToken)
	req.Header.Set("ChatGPT-Account-ID", acct.AccountID)
	req.Header.Set("originator", c.originator)
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpc.Do(req)
	if err != nil {
		return model.Usage{}, fmt.Errorf("usage: request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusUnauthorized {
		return model.Usage{}, fmt.Errorf("%w", ErrTokenInvalid)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return model.Usage{}, fmt.Errorf("usage: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var raw rawPayload
	if err := json.Unmarshal(body, &raw); err != nil {
		return model.Usage{}, fmt.Errorf("usage: decode response: %w", err)
	}
	return c.toUsage(raw), nil
}

// toUsage flattens the raw payload into the generic model. The primary
// rate_limit contributes "primary"/"secondary" windows; each additional limit
// contributes windows named after its limit_name (or metered_feature).
func (c *Client) toUsage(raw rawPayload) model.Usage {
	u := model.Usage{PlanType: raw.PlanType}
	c.appendWindows(&u, "primary", "secondary", raw.RateLimit)
	for _, add := range raw.AdditionalRateLimits {
		name := add.LimitName
		if name == "" {
			name = add.MeteredFeature
		}
		if name == "" {
			name = "additional"
		}
		c.appendWindows(&u, name, name+"_secondary", add.RateLimit)
	}
	if skew, ok := c.measureSkew(raw); ok {
		u.ClockSkew, u.ClockSkewValid = skew, true
	}
	return u
}

// measureSkew derives the host↔upstream clock skew (DESIGN.md §21.4) from any
// window that reports BOTH an absolute reset_at and a relative
// reset_after_seconds: the upstream's own "now" is reset_at − reset_after_seconds,
// so skew = host_now − upstream_now. A positive value means the host clock runs
// ahead of upstream. Windows carrying only one of the two signals cannot anchor a
// skew estimate; when none do, ok is false.
func (c *Client) measureSkew(raw rawPayload) (time.Duration, bool) {
	windows := []*rawWindow{}
	collect := func(d *rawStatusDetails) {
		if d != nil {
			windows = append(windows, d.PrimaryWindow, d.SecondaryWindow)
		}
	}
	collect(raw.RateLimit)
	for _, add := range raw.AdditionalRateLimits {
		collect(add.RateLimit)
	}
	for _, rw := range windows {
		if rw == nil || rw.ResetAt <= 0 || rw.ResetAfterSeconds <= 0 {
			continue
		}
		upstreamNow := time.Unix(rw.ResetAt, 0).UTC().Add(-time.Duration(rw.ResetAfterSeconds) * time.Second)
		return c.now().UTC().Sub(upstreamNow), true
	}
	return 0, false
}

func (c *Client) appendWindows(u *model.Usage, primaryName, secondaryName string, d *rawStatusDetails) {
	if d == nil {
		return
	}
	if w := c.toWindow(primaryName, d.PrimaryWindow); w != nil {
		u.Windows = append(u.Windows, *w)
	}
	if w := c.toWindow(secondaryName, d.SecondaryWindow); w != nil {
		u.Windows = append(u.Windows, *w)
	}
}

func (c *Client) toWindow(name string, rw *rawWindow) *model.UsageWindow {
	if rw == nil {
		return nil
	}
	w := model.UsageWindow{
		Name:          name,
		UsedPercent:   rw.UsedPercent,
		WindowSeconds: rw.LimitWindowSeconds,
		ResetsAt:      c.resolveReset(rw),
	}
	return &w
}

// resolveReset prefers the absolute reset_at (unix seconds); when it is absent
// (0) it derives the reset time from reset_after_seconds relative to the
// injected clock. When neither is present, ResetsAt is the zero time.
func (c *Client) resolveReset(rw *rawWindow) time.Time {
	if rw.ResetAt > 0 {
		return time.Unix(rw.ResetAt, 0).UTC()
	}
	if rw.ResetAfterSeconds > 0 {
		return c.now().UTC().Add(time.Duration(rw.ResetAfterSeconds) * time.Second)
	}
	return time.Time{}
}
