// notify.go holds the shared domain types for poolgate's notification subsystem
// (DESIGN.md §11): the alertable events emitted by the health/policy engines and
// the configured delivery channels (DingTalk / WeCom / custom webhook).
//
// SECURITY (DESIGN.md §11 / SECURITY.md): a NotifyEvent is SECRET-FREE by
// construction — it references an account by id/label only and carries no tokens,
// sk- keys, or PII. A NotifyChannel's Config DOES hold secrets (webhook URL,
// signing secret) and is therefore field-encrypted at rest by the store and never
// serialized back across the admin API.
package model

import (
	"slices"
	"time"
)

// NotifyEventKind enumerates the alertable events poolgate emits. The values are
// stable identifiers persisted in channel subscriptions, so they are append-only.
type NotifyEventKind string

const (
	// EventAccountExpired — a pooled account's token is invalid and refresh failed.
	EventAccountExpired NotifyEventKind = "account_expired"
	// EventAccountCooldown — an account entered cooldown after repeated 429/5xx.
	EventAccountCooldown NotifyEventKind = "account_cooldown"
	// EventAccountQuotaExhausted — a usage window hit 0 headroom.
	EventAccountQuotaExhausted NotifyEventKind = "account_quota_exhausted"
	// EventAccountRecovered — a degraded/expired account passed a probe and is ok.
	EventAccountRecovered NotifyEventKind = "account_recovered"
	// EventQuotaLow — an account's remaining headroom dropped below a threshold
	// (but is not yet exhausted). Carries the observed Headroom percentage.
	EventQuotaLow NotifyEventKind = "quota_low"
	// EventPolicyNoHealthyMember — an endpoint's policy group has no healthy
	// member, so that endpoint is failing.
	EventPolicyNoHealthyMember NotifyEventKind = "policy_no_healthy_member"
	// EventAuthAnomaly — repeated invalid proxy-key / bootstrap attempts (possible
	// probing). Reserved: wired by the real-time monitor phase (ROADMAP item 2).
	EventAuthAnomaly NotifyEventKind = "auth_anomaly"
	// EventStartupBindWarning — a listener bound to a non-loopback address.
	// Reserved: wired by the real-time monitor phase (ROADMAP item 2).
	EventStartupBindWarning NotifyEventKind = "startup_bind_warning"
)

// Valid reports whether k is a recognized event kind.
func (k NotifyEventKind) Valid() bool {
	switch k {
	case EventAccountExpired, EventAccountCooldown, EventAccountQuotaExhausted,
		EventAccountRecovered, EventQuotaLow, EventPolicyNoHealthyMember,
		EventAuthAnomaly, EventStartupBindWarning:
		return true
	default:
		return false
	}
}

// NotifyEvent is a secret-free alert payload. It intentionally carries only
// non-sensitive identifiers (account id/label, endpoint, policy group) so it can
// never leak credentials into a notification (DESIGN.md §11 / SECURITY.md).
type NotifyEvent struct {
	Kind         NotifyEventKind `json:"kind"`
	AccountID    string          `json:"account_id,omitempty"`
	AccountLabel string          `json:"account_label,omitempty"`
	Endpoint     string          `json:"endpoint,omitempty"`
	PolicyGroup  string          `json:"policy_group,omitempty"`
	// Headroom is the remaining headroom percentage for EventQuotaLow; unused for
	// other kinds.
	Headroom float64 `json:"headroom,omitempty"`
	// Message is a short human-readable, secret-free summary of the event.
	Message string    `json:"message,omitempty"`
	At      time.Time `json:"at"`
}

// DedupKey is the per-account, per-kind identity used to suppress duplicate
// alerts within a channel's dedup window. It contains no secrets.
func (e NotifyEvent) DedupKey() string {
	return string(e.Kind) + "|" + e.AccountID + "|" + e.Endpoint
}

// NotifyChannelType names a delivery channel implementation (DESIGN.md §11).
type NotifyChannelType string

const (
	// ChannelDingTalk — DingTalk custom robot (supports secret/加签 signing).
	ChannelDingTalk NotifyChannelType = "dingtalk"
	// ChannelWeCom — WeCom / 企业微信 group robot (webhook key in the URL).
	ChannelWeCom NotifyChannelType = "wecom"
	// ChannelWebhook — arbitrary HTTPS endpoint with configurable method/headers/body.
	ChannelWebhook NotifyChannelType = "webhook"
)

// Valid reports whether t is a recognized channel type.
func (t NotifyChannelType) Valid() bool {
	switch t {
	case ChannelDingTalk, ChannelWeCom, ChannelWebhook:
		return true
	default:
		return false
	}
}

// NotifyConfig holds the channel-specific delivery settings, INCLUDING SECRETS.
// The whole struct is serialized to JSON and field-encrypted before it hits the
// store; it is never returned across the admin API. The DingTalk/WeCom webhook
// URL itself is a secret (it embeds an access token / key), so URL is treated as
// sensitive too.
type NotifyConfig struct {
	// URL is the delivery endpoint. For DingTalk/WeCom it embeds the robot token.
	URL string `json:"url"`
	// Secret is the DingTalk 加签 signing secret (empty for keyword-only robots).
	Secret string `json:"secret,omitempty"`
	// Method is the HTTP method for a custom webhook (default POST). Unused by
	// dingtalk/wecom (always POST).
	Method string `json:"method,omitempty"`
	// Headers are extra HTTP headers for a custom webhook.
	Headers map[string]string `json:"headers,omitempty"`
	// Template is a Go text/template body for a custom webhook. When empty, the
	// NotifyEvent is delivered as a compact JSON object. Fields available:
	// .Kind .AccountID .AccountLabel .Endpoint .PolicyGroup .Headroom .Message .At
	// text/template does not escape for JSON; a `json` function is provided to
	// safely emit a quoted/escaped JSON value, e.g. {"text": {{.Message | json}}}.
	Template string `json:"template,omitempty"`
}

// NotifyChannel is a configured alert destination (DESIGN.md §11). Config carries
// secrets and is field-encrypted at rest (never JSON-serialized to the API — note
// the `json:"-"` tag). Events is the set of subscribed event kinds; an empty set
// means "all events". DedupSeconds is the per-(kind, account) suppression window.
//
// MinHeadroom gates quota_low delivery for this channel: the event is forwarded
// only when the observed headroom is <= MinHeadroom. The health engine emits
// quota_low while an account is still routable and its headroom is at/below its
// own emit threshold (default 15%); a channel MinHeadroom therefore only NARROWS
// that band (0 = accept every quota_low the engine emits). Values above the
// engine's emit threshold have no additional effect, since no such event is
// produced.
type NotifyChannel struct {
	ID           string            `json:"id"`
	Type         NotifyChannelType `json:"type"`
	Name         string            `json:"name"`
	Enabled      bool              `json:"enabled"`
	Config       NotifyConfig      `json:"-"`
	Events       []NotifyEventKind `json:"events"`
	MinHeadroom  float64           `json:"min_headroom"`
	DedupSeconds int               `json:"dedup_seconds"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// Subscribes reports whether the channel is interested in an event kind. An empty
// Events list subscribes to every kind.
func (c NotifyChannel) Subscribes(kind NotifyEventKind) bool {
	if len(c.Events) == 0 {
		return true
	}
	return slices.Contains(c.Events, kind)
}
