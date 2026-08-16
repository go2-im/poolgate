// audit.go implements the append-only audit log store (DESIGN.md §22). Only
// Insert and List are exposed — there is intentionally no update or delete, so
// the log cannot be tampered with through the store API.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// InsertAuditEntry appends one audit record. If e.ID is empty a fresh id is
// generated; if e.At is zero the current time is used. The `at` column is
// fixed-width so TEXT ordering is chronological.
func (s *Store) InsertAuditEntry(ctx context.Context, e model.AuditEntry) error {
	if e.ID == "" {
		e.ID = newID("audit")
	}
	at := e.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (id, at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		e.ID, formatTimeFixed(at), e.Actor, e.Action, e.Target, e.Detail); err != nil {
		return fmt.Errorf("store: insert audit entry: %w", err)
	}
	return nil
}

// maxAuditListLimit caps a single ListAuditEntries page so an authenticated
// caller cannot pull the entire log in one unpaginated request.
const maxAuditListLimit = 1000

// ListAuditEntries returns audit records newest-first, paginated. A non-positive
// limit falls back to 100; a limit above maxAuditListLimit is clamped down.
func (s *Store) ListAuditEntries(ctx context.Context, limit, offset int) ([]model.AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > maxAuditListLimit {
		limit = maxAuditListLimit
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, at, actor, action, target, detail FROM audit_log ORDER BY at DESC, id DESC LIMIT ? OFFSET ?`,
		limit, offset)
	if err != nil {
		return nil, fmt.Errorf("store: list audit entries: %w", err)
	}
	defer rows.Close()

	var out []model.AuditEntry
	for rows.Next() {
		var (
			e  model.AuditEntry
			at string
		)
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, fmt.Errorf("store: scan audit entry: %w", err)
		}
		e.At = parseTime(at)
		out = append(out, e)
	}
	return out, rows.Err()
}