// audit.go implements the append-only, tamper-evident audit log store (DESIGN.md
// §22). Only Insert and List are exposed — there is intentionally no update or
// delete. Each row additionally stores a hash that chains the previous row's
// hash over the row's canonical fields, so any tampering, deletion, or
// reordering of the persisted log is detectable via VerifyAuditChain.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// auditHash computes hash_i = SHA256(prevHash ‖ length-prefixed(fields...)) as
// hex. Length-prefixing makes the encoding injective, so no field content can
// forge a boundary. prev is the previous row's hash ("" for the first row).
func auditHash(prev, id, at, actor, action, target, detail string) string {
	h := sha256.New()
	for _, f := range []string{prev, id, at, actor, action, target, detail} {
		fmt.Fprintf(h, "%d:", len(f))
		_, _ = h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// InsertAuditEntry appends one audit record, chaining its hash to the current
// tip. If e.ID is empty a fresh id is generated; if e.At is zero the current
// time is used. The read-tip + insert run in one transaction so concurrent
// appends produce a well-defined chain. The `at` column is fixed-width so TEXT
// ordering is chronological.
func (s *Store) InsertAuditEntry(ctx context.Context, e model.AuditEntry) error {
	if e.ID == "" {
		e.ID = newID("audit")
	}
	at := e.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	atStr := formatTimeFixed(at)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin audit insert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var prev string
	if err := tx.QueryRowContext(ctx,
		`SELECT hash FROM audit_log ORDER BY rowid DESC LIMIT 1`).Scan(&prev); err != nil &&
		!errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("store: read audit tip: %w", err)
	}
	hash := auditHash(prev, e.ID, atStr, e.Actor, e.Action, e.Target, e.Detail)

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_log (id, at, actor, action, target, detail, hash) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.ID, atStr, e.Actor, e.Action, e.Target, e.Detail, hash); err != nil {
		return fmt.Errorf("store: insert audit entry: %w", err)
	}
	return tx.Commit()
}

// VerifyAuditChain recomputes the hash chain over every row in insertion order
// (rowid) and reports whether the persisted log is intact. On a mismatch it
// returns valid=false and the id of the first row whose stored hash does not
// match the recomputed one (tampered, or a row was deleted/reordered before it).
func (s *Store) VerifyAuditChain(ctx context.Context) (valid bool, count int, brokenID string, err error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, at, actor, action, target, detail, hash FROM audit_log ORDER BY rowid ASC`)
	if err != nil {
		return false, 0, "", fmt.Errorf("store: verify audit chain: %w", err)
	}
	defer rows.Close()

	prev := ""
	for rows.Next() {
		var id, at, actor, action, target, detail, hash string
		if err := rows.Scan(&id, &at, &actor, &action, &target, &detail, &hash); err != nil {
			return false, count, "", fmt.Errorf("store: scan audit row: %w", err)
		}
		count++
		if auditHash(prev, id, at, actor, action, target, detail) != hash {
			return false, count, id, nil
		}
		prev = hash
	}
	if err := rows.Err(); err != nil {
		return false, count, "", err
	}
	return true, count, "", nil
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
