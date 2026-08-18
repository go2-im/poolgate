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
	// CredentialVersion is a per-account monotonic counter bumped by EVERY credential
	// mutation (online refresh, interactive login, file import). It is the AUTHORITATIVE
	// ordering of credential generations (DESIGN.md §19.3a): the online-refresh commit
	// does a version compare-and-swap (write only when the DB version still equals the
	// base it rotated from), and the rotation-recovery journal records base/target
	// versions so a crash-interrupted rotation is applied only when the DB is still at
	// its base — never re-applying a generation the DB has already moved past. A stale
	// refresh_token string could collide across generations (the issuer may not rotate
	// it), so the version — not the token string — is what disambiguates who won.
	CredentialVersion int64 `json:"credential_version"`
	// LastRefreshedAt is when the account's credentials were last written by a token
	// operation (online refresh, interactive login, file import, or initial insert) —
	// NOT bumped by state/timing updates. The health engine uses it to PROACTIVELY
	// refresh an idle account before its refresh_token lapses from disuse, even with
	// no client traffic (DESIGN.md §12). Zero = never recorded.
	LastRefreshedAt time.Time `json:"last_refreshed_at"`
	// ConcurrencyCap is the max simultaneous in-flight upstream requests routed to
	// this account (0 = unlimited). It backs least-in-flight selection + bounded
	// backpressure (DESIGN.md §23.1). Persisted in the accounts.concurrency_cap
	// column; also surfaced on AccountTiming for the health engine.
	ConcurrencyCap int       `json:"concurrency_cap"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// ApiKey is an inbound `sk-` proxy credential. Key is compared constant-time.
// Endpoints scopes the key to a set of endpoint names (empty = all endpoints).
type ApiKey struct {
	ID string `json:"id"`
	// Key is the plaintext sk- secret. It is populated ONLY at create/rotate time
	// (returned once for display); reads from the store leave it empty because the
	// secret is not stored in the clear — only KeyHash (for lookup) and KeyHint
	// (a short suffix for display) are persisted.
	Key string `json:"key"`
	// KeyHash is the SHA-256 hex of the secret, used for constant-time auth lookup.
	// Never serialized.
	KeyHash string `json:"-"`
	// KeyHint is a short display suffix of the secret (e.g. the last 4 chars) so the
	// admin UI can show "sk-…abcd" without storing the usable key. Never serialized.
	KeyHint   string   `json:"-"`
	Label     string   `json:"label"`
	Endpoints []string `json:"endpoints"`
	// ExpiresAt is when the key stops being accepted; zero = never expires.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	// IPAllowlist restricts which client IPs may use the key. Each entry is an IP
	// or CIDR (e.g. "203.0.113.4" or "10.0.0.0/8"); empty = any IP. Matched
	// against the direct peer (RemoteAddr), so behind a reverse proxy the proxy's
	// IP is what is checked.
	IPAllowlist []string `json:"ip_allowlist,omitempty"`
}

// Expired reports whether the key has an expiry that is at or before now.
func (k ApiKey) Expired(now time.Time) bool {
	return !k.ExpiresAt.IsZero() && !now.Before(k.ExpiresAt)
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
	// StrategyWeighted — distribute across healthy members proportionally to each
	// member's weight (smooth weighted round-robin; DESIGN.md §0 D7).
	StrategyWeighted Strategy = "weighted"
)

// PolicyGroup is a named strategy over an ordered member account list.
// v1 is flat: MemberAccountIDs references Accounts directly (DESIGN.md §0 D8).
type PolicyGroup struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Strategy         Strategy `json:"strategy"`
	MemberAccountIDs []string `json:"member_account_ids"`
	// MemberWeights maps an account id to its weighted-load-balance weight (>=1;
	// a missing entry means the default weight 1). Only meaningful for the
	// "weighted" strategy; carried for all groups.
	MemberWeights map[string]int `json:"member_weights,omitempty"`
}

// Weight returns the weighted-LB weight for account id (>=1; default 1).
func (g PolicyGroup) Weight(accountID string) int {
	if w, ok := g.MemberWeights[accountID]; ok && w >= 1 {
		return w
	}
	return 1
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

	// ClockSkew is the measured difference between the host wall clock and the
	// upstream usage endpoint's clock (host_now − upstream_now), derived when a
	// window reports both an absolute reset_at and a relative reset_after_seconds
	// (DESIGN.md §21.4). It is transient telemetry — never persisted — so it is
	// excluded from JSON. ClockSkewValid reports whether it could be computed.
	ClockSkew      time.Duration `json:"-"`
	ClockSkewValid bool          `json:"-"`
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

// Session is a persisted admin login session (DESIGN.md §16 / §22.3). It carries
// only timestamps: the opaque session id is the bearer credential (stored in a
// cookie by the admin HTTP layer in a later stage). Lifetime is bounded by
// ExpiresAt (absolute) and by an idle timeout measured from LastSeenAt.
type Session struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// RecoveryCode is a one-time admin recovery code (DESIGN.md §16). Only the
// SHA-256 hash of the code is persisted; the plaintext is shown once at
// generation. UsedAt is the zero time until the code is consumed.
type RecoveryCode struct {
	ID     string    `json:"id"`
	Hash   string    `json:"hash"`
	UsedAt time.Time `json:"used_at"`
}

// Used reports whether the recovery code has already been consumed.
func (c RecoveryCode) Used() bool { return !c.UsedAt.IsZero() }

// BootstrapToken is a short-TTL, single-use admin bootstrap registration token
// (DESIGN.md §16 / §17 / §0 fixes). Only the SHA-256 hash is persisted; the
// plaintext is printed once to the local console and never to durable logs.
// UsedAt is the zero time until the token is consumed.
type BootstrapToken struct {
	ID        string    `json:"id"`
	TokenHash string    `json:"token_hash"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedAt    time.Time `json:"used_at"`
}

// Used reports whether the bootstrap token has already been consumed.
func (t BootstrapToken) Used() bool { return !t.UsedAt.IsZero() }

// WebAuthnCredential is a registered passkey (DESIGN.md §8 / §16). CredID and
// PublicKey are opaque WebAuthn byte blobs; SignCount guards against cloned
// authenticators; Transports is the authenticator's advertised transport list.
// Flags is the raw authenticator-data flags byte recorded at registration (UP /
// UV / BE / BS); it MUST be persisted so login can enforce go-webauthn's
// Backup-Eligible consistency check — a synced passkey (iCloud Keychain, password
// managers) asserts BE=1, and a stored BE=0 (the pre-flags default) makes every
// login fail with a BE-flag inconsistency.
type WebAuthnCredential struct {
	ID         string    `json:"id"`
	CredID     []byte    `json:"cred_id"`
	PublicKey  []byte    `json:"public_key"`
	SignCount  uint32    `json:"sign_count"`
	AAGUID     []byte    `json:"aaguid"`
	Transports []string  `json:"transports"`
	Flags      byte      `json:"flags"`
	Label      string    `json:"label"`
	CreatedAt  time.Time `json:"created_at"`
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
	// ProactiveTokenRefresh is how stale an account's credentials may get before the
	// health engine proactively refreshes them (a Go duration string, e.g. "12h"), so
	// an idle account's refresh_token cannot lapse from disuse even with no client
	// traffic (DESIGN.md §12). Empty = the built-in default (12h); "0" disables it.
	ProactiveTokenRefresh string `yaml:"proactive_token_refresh,omitempty" json:"proactive_token_refresh,omitempty"`
}

// ServerConfig holds the two listener bindings (admin + proxy).
type ServerConfig struct {
	Admin ListenConfig `yaml:"admin" json:"admin"`
	Proxy ListenConfig `yaml:"proxy" json:"proxy"`
	// Transport selects which proxy transport(s) the /responses surface offers
	// (DESIGN.md §0 D2): "http-only" (default — refuse the WS upgrade so Codex falls
	// back to stateless HTTP+SSE, which needs no turn affinity and is always correct),
	// "both" (also accept the WS upgrade), or "ws-only" (require the WS upgrade; refuse
	// plain HTTP POST). Empty = http-only. Accepting the WS upgrade is opt-in because
	// its reconnect affinity relies on an x-codex-turn-state header current clients
	// don't send (audit P2#10).
	Transport string `yaml:"transport" json:"transport"`
	// TrustedProxies lists reverse-proxy addresses/networks (IPs or CIDRs) whose
	// X-Forwarded-For header poolgate will trust when resolving the real client IP
	// for the API-key IP allowlist and the admin brute-force limiter. Empty (the
	// default) means poolgate is directly exposed: X-Forwarded-For is ignored and
	// only the direct peer address is used.
	TrustedProxies []string `yaml:"trusted_proxies,omitempty" json:"trusted_proxies,omitempty"`
	// BackpressureWait is how long the proxy waits for a per-account concurrency
	// slot to free before returning 429 when every healthy member is at its cap
	// (DESIGN.md §23.1). A duration string ("200ms"). Empty/"0" = fail fast
	// (immediate 429 + Retry-After), which is the default.
	BackpressureWait string `yaml:"backpressure_wait,omitempty" json:"backpressure_wait,omitempty"`
	// AllowUncertainCrossAccountRetry opts into replaying a POST on ANOTHER account
	// for an UNCERTAIN upstream outcome (408/425/5xx/transport error) when the client
	// sent an Idempotency-Key. It defaults to FALSE and should stay off unless the
	// upstream is KNOWN to honor the key AND to dedup it across different accounts
	// (Authorization + ChatGPT-Account-ID change on failover) — otherwise a retry can
	// double-execute / double-bill. Provably non-executing statuses (401/403/429) are
	// always failover-eligible regardless of this flag (DESIGN.md §19.2).
	AllowUncertainCrossAccountRetry bool `yaml:"allow_uncertain_cross_account_retry,omitempty" json:"allow_uncertain_cross_account_retry,omitempty"`
	// ReadyzRequireHealthy makes /readyz require at least one endpoint with a
	// PROVEN-healthy (state ok) account, instead of the default which — during a
	// bounded cold-start grace after startup — also accepts freshly-imported
	// (unknown, not-yet-probed) accounts so a fresh process reports ready promptly
	// (DESIGN.md §21.1). Default false (cold-start-friendly). Set true for a strict
	// readiness signal (e.g. a load balancer that must only route to a poolgate
	// whose pool has a probe-confirmed account).
	ReadyzRequireHealthy bool `yaml:"readyz_require_healthy,omitempty" json:"readyz_require_healthy,omitempty"`
}

// ListenConfig is a host:port bind pair. For the admin listener it also carries
// the static WebAuthn RP inputs (DESIGN.md §16 / §0 fixes): the RP origin and RP
// ID are resolved ONCE at startup from these fields and never from per-request
// forwarded headers. Both are optional and meaningful only on the admin
// listener; when empty the WebAuthn service derives them from Host:Port.
type ListenConfig struct {
	Host string `yaml:"host" json:"host"`
	Port int    `yaml:"port" json:"port"`
	// ExternalOrigin is the browser-facing origin (scheme://host[:port]) used as
	// the WebAuthn RP origin for the admin listener. Optional.
	ExternalOrigin string `yaml:"external_origin,omitempty" json:"external_origin,omitempty"`
	// RPID is the WebAuthn Relying Party ID (an effective domain) for the admin
	// listener. Optional; when empty it is derived from the origin's host.
	RPID string `yaml:"rp_id,omitempty" json:"rp_id,omitempty"`
}
