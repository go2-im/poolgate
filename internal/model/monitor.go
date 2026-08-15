// monitor.go holds the shared types for poolgate's real-time request monitor
// (DESIGN.md §15 / §24.1): the per-request record streamed to the admin UI and
// persisted to request_logs. Records are SECRET-FREE — they reference the api
// key and account by id/label only and carry no token, sk- key, or request body.
//
// Client-supplied fields (session id, model) are UNTRUSTED and must be passed
// through SanitizeField before they are persisted or streamed (DESIGN.md §0
// fixes / §15): the value is length-capped and control characters — crucially
// newlines — are stripped, so a malicious header can neither bloat the DB nor
// break SSE event framing.
package model

import (
	"strings"
	"time"
)

// MaxMonitorFieldLen caps the length of a client-supplied monitor field.
const MaxMonitorFieldLen = 200

// RequestLog is one per-request record for the real-time monitor (DESIGN.md §15).
// Every field is secret-free.
type RequestLog struct {
	ID           string    `json:"id"`
	At           time.Time `json:"at"`
	Endpoint     string    `json:"endpoint"`
	Policy       string    `json:"policy"` // policy group name (the caller's chosen strategy)
	AccountID    string    `json:"account_id"`
	AccountLabel string    `json:"account_label"`
	Model        string    `json:"model"`
	APIKeyID     string    `json:"api_key_id"`
	APIKeyLabel  string    `json:"api_key_label"`
	SessionID    string    `json:"session_id"`
	Status       int       `json:"status"`
	LatencyMS    int       `json:"latency_ms"`
	TokensIn     int       `json:"tokens_in"`
	TokensOut    int       `json:"tokens_out"`
	// Trace is a compact, secret-free routing/failover decision trace, e.g.
	// "acct_a:401→refresh; acct_b:streamed" (DESIGN.md §24.1).
	Trace string `json:"trace"`
	// ErrorType is the poolgate error type when the request failed pre-stream
	// (e.g. "no_healthy_account"), else empty.
	ErrorType string `json:"error_type"`
}

// RequestLogFilter narrows a request-log query. Zero-valued fields are ignored.
// The session/api-key/model facets are the primary composable filters (DESIGN.md
// §15); endpoint/account/status/time-range refine further. It filters in SQL.
type RequestLogFilter struct {
	SessionID string
	APIKeyID  string
	Model     string
	Endpoint  string
	AccountID string
	Status    int       // 0 = any
	Since     time.Time // zero = open lower bound
	Until     time.Time // zero = open upper bound
}

// Matches reports whether a log satisfies the filter. It is the single predicate
// shared by the SQL history query and the live-stream filter so both behave
// identically (DESIGN.md §15: "also applied to the live stream").
func (f RequestLogFilter) Matches(l RequestLog) bool {
	if f.SessionID != "" && l.SessionID != f.SessionID {
		return false
	}
	if f.APIKeyID != "" && l.APIKeyID != f.APIKeyID {
		return false
	}
	if f.Model != "" && l.Model != f.Model {
		return false
	}
	if f.Endpoint != "" && l.Endpoint != f.Endpoint {
		return false
	}
	if f.AccountID != "" && l.AccountID != f.AccountID {
		return false
	}
	if f.Status != 0 && l.Status != f.Status {
		return false
	}
	if !f.Since.IsZero() && l.At.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && !l.At.Before(f.Until) {
		return false
	}
	return true
}

// SanitizeField makes an untrusted client-supplied value safe to persist and to
// stream over SSE: it strips ASCII control characters (including CR/LF, which
// would break SSE framing) and caps the length to MaxMonitorFieldLen runes.
func SanitizeField(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	n := 0
	for _, r := range s {
		if n >= MaxMonitorFieldLen {
			break
		}
		// Drop C0 controls (incl. \n \r \t), DEL, and C1 controls.
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			continue
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
