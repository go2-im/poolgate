// Package model holds the shared domain structs used across poolgate:
// pooled accounts, inbound API keys, endpoints, policy groups, and config.
package model

import "time"

// AccountState is the lifecycle state of a pooled Codex/ChatGPT account.
//
// The transient states (ok/cooldown/quota_exhausted/expired/unknown) are driven
// by real proxy traffic and the health probe engine; the terminal states
// (revoked/dead) are never auto-recovered and require re-import / re-auth.
// See DESIGN.md §4 / §12 / §23.6.
type AccountState string

const (
	// StateOK — account is healthy and eligible for routing.
	StateOK AccountState = "ok"
	// StateCooldown — transient failures (429/5xx); re-probed with backoff.
	StateCooldown AccountState = "cooldown"
	// StateQuotaExhausted — a usage window hit 0 headroom.
	StateQuotaExhausted AccountState = "quota_exhausted"
	// StateExpired — token invalid (401) and refresh failed.
	StateExpired AccountState = "expired"
	// StateUnknown — freshly seen, not yet probed.
	StateUnknown AccountState = "unknown"
	// StateRevoked — terminal; credential revoked upstream, no auto-recovery.
	StateRevoked AccountState = "revoked"
	// StateDead — terminal; account permanently unusable, no auto-recovery.
	StateDead AccountState = "dead"
)

// Valid reports whether s is a recognized account state.
func (s AccountState) Valid() bool {
	switch s {
	case StateOK, StateCooldown, StateQuotaExhausted, StateExpired,
		StateUnknown, StateRevoked, StateDead:
		return true
	default:
		return false
	}
}

// Terminal reports whether s is a terminal state excluded from auto-recovery.
func (s AccountState) Terminal() bool {
	return s == StateRevoked || s == StateDead
}

// Account is a pooled Codex/ChatGPT credential (the leaf "proxy").
//
// AccessToken and RefreshToken are secrets: they are field-encrypted before
// they hit the store, and decrypted only in memory on the hot path.
type Account struct {
	ID           string       `json:"id"`
	Label        string       `json:"label"`
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	AccountID    string       `json:"account_id"` // ChatGPT-Account-ID rewritten on the proxy path
	IDToken      string       `json:"id_token"`
	State        AccountState `json:"state"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

// ApiKey is an inbound `sk-` proxy credential. Key is compared constant-time.
// Endpoints scopes the key to a set of endpoint names (empty = all endpoints).
type ApiKey struct {
	ID        string   `json:"id"`
	Key       string   `json:"key"`
	Label     string   `json:"label"`
	Endpoints []string `json:"endpoints"`
}

// Endpoint is a named inbound route bound to one PolicyGroup, surfaced at
// /e/<Name>/v1/... The caller picks a strategy by choosing the URL.
type Endpoint struct {
	Name    string `json:"name"`
	GroupID string `json:"group_id"`
}

// Strategy names the routing strategy of a PolicyGroup (DESIGN.md §0 D7).
type Strategy string

const (
	// StrategyFallback — first healthy member in order; advance + cooldown on failure.
	StrategyFallback Strategy = "fallback"
	// StrategyBestQuota — route to the account with the most remaining headroom.
	StrategyBestQuota Strategy = "best-quota"
	// StrategyLoadBalance — distribute across healthy members (round-robin default).
	StrategyLoadBalance Strategy = "load-balance"
)

// PolicyGroup is a named strategy over an ordered member account list.
// v1 is flat: MemberAccountIDs references Accounts directly (DESIGN.md §0 D8).
type PolicyGroup struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Strategy         Strategy `json:"strategy"`
	MemberAccountIDs []string `json:"member_account_ids"`
}

// UsageWindow is one generic rate-limit window read from the upstream usage
// endpoint (DESIGN.md §0 D4). It intentionally carries NO fixed 5h/1week
// semantics: Name is a display label (e.g. "primary"/"secondary" or an
// additional limit's name), and the window is described purely by its used
// percentage, its length in seconds, and when it resets.
type UsageWindow struct {
	Name          string    `json:"name"`
	UsedPercent   float64   `json:"used_percent"`
	WindowSeconds int       `json:"window_seconds"`
	ResetsAt      time.Time `json:"resets_at"`
}

// Headroom returns the remaining percentage headroom (100 - used_percent),
// clamped to [0,100]. best-quota routing uses the min headroom across windows
// (DESIGN.md §4 / §24.2).
func (w UsageWindow) Headroom() float64 {
	h := 100 - w.UsedPercent
	if h < 0 {
		return 0
	}
	if h > 100 {
		return 100
	}
	return h
}

// Usage is the generic usage model: a plan type plus N percent-usage windows.
// It is what internal/usage.Client returns after parsing GET /wham/usage.
type Usage struct {
	PlanType string        `json:"plan_type"`
	Windows  []UsageWindow `json:"windows"`
}

// UsageSnapshot is a persisted point-in-time Usage for one account.
type UsageSnapshot struct {
	ID         string        `json:"id"`
	AccountID  string        `json:"account_id"`
	PlanType   string        `json:"plan_type"`
	Windows    []UsageWindow `json:"windows"`
	CapturedAt time.Time     `json:"captured_at"`
}

// HealthCheckKind labels the probe that produced a HealthCheck record
// (DESIGN.md §12 probe kinds).
type HealthCheckKind string

const (
	// HealthKindUsagePoll — GET /wham/usage (zero token spend).
	HealthKindUsagePoll HealthCheckKind = "usage_poll"
	// HealthKindAuthCheck — authenticated GET /models (zero token spend).
	HealthKindAuthCheck HealthCheckKind = "auth_check"
	// HealthKindLiveRequest — tiny real completion (minimal spend).
	HealthKindLiveRequest HealthCheckKind = "live_request"
)

// HealthCheck is one recorded probe result for an account (DESIGN.md §12).
type HealthCheck struct {
	ID        string          `json:"id"`
	AccountID string          `json:"account_id"`
	Kind      HealthCheckKind `json:"kind"`
	OK        bool            `json:"ok"`
	Detail    string          `json:"detail"`
	LatencyMS int             `json:"latency_ms"`
	At        time.Time       `json:"at"`
}

// AccountTiming holds the per-account scheduling/backoff state driven by the
// health engine (DESIGN.md §12 scheduling & §23.1 concurrency). Zero-valued
// timestamps mean "unset" (stored as SQL NULL).
type AccountTiming struct {
	CooldownUntil       time.Time `json:"cooldown_until"`
	NextProbeAt         time.Time `json:"next_probe_at"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	BackoffLevel        int       `json:"backoff_level"`
	ConcurrencyCap      int       `json:"concurrency_cap"`
}

// Config is the runtime configuration (see internal/config for loading/defaults).
type Config struct {
	Server            ServerConfig `yaml:"server" json:"server"`
	DataDir           string       `yaml:"data_dir" json:"data_dir"`
	MasterKeySource   string       `yaml:"master_key_source" json:"master_key_source"`
	UpstreamAllowlist []string     `yaml:"upstream_allowlist" json:"upstream_allowlist"`
	Issuer            string       `yaml:"issuer" json:"issuer"`
	// HealthProbeMode selects the global probe cost policy for the health
	// engine (DESIGN.md §12 scheduling & cost control):
	//   - "usage-poll-only" (default) — zero token spend; only usage-poll and
	//     the zero-spend auth-check are used.
	//   - "allow-live"      — additionally permit the opt-in small-live-request
	//     for degraded/recovery checks, bounded by the per-account daily budget.
	HealthProbeMode string `yaml:"health_probe_mode" json:"health_probe_mode"`
}

// ServerConfig holds the two listener bindings (admin + proxy).
type ServerConfig struct {
	Admin ListenConfig `yaml:"admin" json:"admin"`
	Proxy ListenConfig `yaml:"proxy" json:"proxy"`
}

// ListenConfig is a host:port bind pair.
type ListenConfig struct {
	Host string `yaml:"host" json:"host"`
	Port int    `yaml:"port" json:"port"`
}
