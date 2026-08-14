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

// Config is the runtime configuration (see internal/config for loading/defaults).
type Config struct {
	Server            ServerConfig `yaml:"server" json:"server"`
	DataDir           string       `yaml:"data_dir" json:"data_dir"`
	MasterKeySource   string       `yaml:"master_key_source" json:"master_key_source"`
	UpstreamAllowlist []string     `yaml:"upstream_allowlist" json:"upstream_allowlist"`
	Issuer            string       `yaml:"issuer" json:"issuer"`
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
