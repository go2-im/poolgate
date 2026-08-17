// audit.go holds the append-only audit-log entry (DESIGN.md §22). An entry
// records one security-relevant admin/system action. It is SECRET-FREE by
// construction — it references accounts/keys/endpoints by id or label only and
// never carries tokens, sk- secrets, passphrases, or request bodies.
package model

import "time"

// AuditEntry is one immutable audit record. The store only ever inserts and
// reads these (never updates/deletes), so the log is append-only.
type AuditEntry struct {
	ID     string    `json:"id"`
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`  // "operator" (an authenticated admin) or "system"
	Action string    `json:"action"` // dotted verb, e.g. "apikey.create", "auth.login"
	Target string    `json:"target"` // secret-free subject id/name (may be empty)
	Detail string    `json:"detail"` // short secret-free note (may be empty)
}

// Audit actor constants.
const (
	AuditActorOperator = "operator"
	AuditActorSystem   = "system"
)
