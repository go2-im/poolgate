package store

// authstore.go holds the v3 admin-auth persistence: WebAuthn credentials, admin
// login sessions, one-time recovery codes, and short-TTL single-use bootstrap
// tokens (DESIGN.md §16 / §22). Recovery codes and bootstrap tokens persist only
// a SHA-256 hash of the secret; the plaintext lives only in the caller
// (internal/adminauth). The single-use consume methods flip used_at inside a
// guarded UPDATE so a double-consume can never succeed even under a race.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// ---- webauthn credentials -------------------------------------------------

// InsertWebAuthnCredential stores a registered passkey. If c.ID is empty a
// random id is generated; if CreatedAt is zero it defaults to now. Transports is
// stored as a JSON array. The stored credential (with its final ID) is returned.
func (s *Store) InsertWebAuthnCredential(ctx context.Context, c model.WebAuthnCredential) (model.WebAuthnCredential, error) {
	if len(c.CredID) == 0 {
		return model.WebAuthnCredential{}, errors.New("store: webauthn credential missing cred_id")
	}
	if len(c.PublicKey) == 0 {
		return model.WebAuthnCredential{}, errors.New("store: webauthn credential missing public_key")
	}
	if c.ID == "" {
		c.ID = newID("wac")
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	if c.Transports == nil {
		c.Transports = []string{}
	}
	transports, err := json.Marshal(c.Transports)
	if err != nil {
		return model.WebAuthnCredential{}, fmt.Errorf("store: marshal transports: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO webauthn_credentials
	(id, cred_id, public_key, sign_count, aaguid, transports, label, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.CredID, c.PublicKey, c.SignCount, c.AAGUID, string(transports), c.Label, formatTime(c.CreatedAt),
	); err != nil {
		return model.WebAuthnCredential{}, fmt.Errorf("store: insert webauthn credential: %w", err)
	}
	return c, nil
}

// ListWebAuthnCredentials returns all registered passkeys ordered by creation
// time then id.
func (s *Store) ListWebAuthnCredentials(ctx context.Context) ([]model.WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, cred_id, public_key, sign_count, aaguid, transports, label, created_at
FROM webauthn_credentials ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list webauthn credentials: %w", err)
	}
	defer rows.Close()

	var out []model.WebAuthnCredential
	for rows.Next() {
		c, err := scanWebAuthnCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetWebAuthnCredentialByCredID looks up a passkey by its opaque WebAuthn
// credential id (the value the authenticator returns during assertion).
func (s *Store) GetWebAuthnCredentialByCredID(ctx context.Context, credID []byte) (model.WebAuthnCredential, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, cred_id, public_key, sign_count, aaguid, transports, label, created_at
FROM webauthn_credentials WHERE cred_id = ?`, credID)
	return scanWebAuthnCredential(row)
}

// UpdateWebAuthnSignCount persists a bumped signature counter after a successful
// assertion (clone-detection guard). ErrNotFound if the credential is missing.
func (s *Store) UpdateWebAuthnSignCount(ctx context.Context, id string, signCount uint32) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE webauthn_credentials SET sign_count = ? WHERE id = ?`, signCount, id)
	if err != nil {
		return fmt.Errorf("store: update sign count: %w", err)
	}
	return oneRow(res, "update sign count")
}

// CountWebAuthnCredentials returns the number of registered passkeys. Used by
// the first-run wizard / readiness checks (DESIGN.md §17).
func (s *Store) CountWebAuthnCredentials(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM webauthn_credentials`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count webauthn credentials: %w", err)
	}
	return n, nil
}

// DeleteAllWebAuthnCredentials removes every registered passkey and returns the
// number deleted. Used by `poolgate admin reset-auth` (DESIGN.md §16).
func (s *Store) DeleteAllWebAuthnCredentials(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_credentials`)
	if err != nil {
		return 0, fmt.Errorf("store: delete webauthn credentials: %w", err)
	}
	return rowsAffected(res, "delete webauthn credentials")
}

func scanWebAuthnCredential(sc rowScanner) (model.WebAuthnCredential, error) {
	var (
		c          model.WebAuthnCredential
		transports string
		createdAt  string
	)
	if err := sc.Scan(&c.ID, &c.CredID, &c.PublicKey, &c.SignCount, &c.AAGUID,
		&transports, &c.Label, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.WebAuthnCredential{}, ErrNotFound
		}
		return model.WebAuthnCredential{}, fmt.Errorf("store: scan webauthn credential: %w", err)
	}
	if err := json.Unmarshal([]byte(transports), &c.Transports); err != nil {
		return model.WebAuthnCredential{}, fmt.Errorf("store: unmarshal transports: %w", err)
	}
	c.CreatedAt = parseTime(createdAt)
	return c, nil
}

// ---- sessions -------------------------------------------------------------

// InsertSession persists a new admin session. If sess.ID is empty a random id is
// generated; zero timestamps default to now (created/last_seen). The stored
// session (with its final ID/timestamps) is returned.
func (s *Store) InsertSession(ctx context.Context, sess model.Session) (model.Session, error) {
	if sess.ID == "" {
		sess.ID = newSessionID()
	}
	now := time.Now().UTC()
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = now
	}
	if sess.LastSeenAt.IsZero() {
		sess.LastSeenAt = sess.CreatedAt
	}
	if sess.ExpiresAt.IsZero() {
		return model.Session{}, errors.New("store: session missing expires_at")
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO sessions (id, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?)`,
		sess.ID, formatTime(sess.CreatedAt), formatTime(sess.LastSeenAt), formatTime(sess.ExpiresAt),
	); err != nil {
		return model.Session{}, fmt.Errorf("store: insert session: %w", err)
	}
	return sess, nil
}

// GetSession loads one session by id. ErrNotFound if it does not exist.
func (s *Store) GetSession(ctx context.Context, id string) (model.Session, error) {
	var (
		sess                             model.Session
		createdAt, lastSeenAt, expiresAt string
	)
	err := s.db.QueryRowContext(ctx, `
SELECT id, created_at, last_seen_at, expires_at FROM sessions WHERE id = ?`, id,
	).Scan(&sess.ID, &createdAt, &lastSeenAt, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Session{}, ErrNotFound
		}
		return model.Session{}, fmt.Errorf("store: get session: %w", err)
	}
	sess.CreatedAt = parseTime(createdAt)
	sess.LastSeenAt = parseTime(lastSeenAt)
	sess.ExpiresAt = parseTime(expiresAt)
	return sess, nil
}

// TouchSession updates a session's last_seen_at (idle-timeout sliding window).
// ErrNotFound if the session is missing.
func (s *Store) TouchSession(ctx context.Context, id string, lastSeen time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at = ? WHERE id = ?`, formatTime(lastSeen.UTC()), id)
	if err != nil {
		return fmt.Errorf("store: touch session: %w", err)
	}
	return oneRow(res, "touch session")
}

// DeleteSession revokes one session. ErrNotFound if it does not exist.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete session: %w", err)
	}
	return oneRow(res, "delete session")
}

// DeleteAllSessions revokes every session ("revoke all sessions", DESIGN.md
// §22.3) and returns the number deleted.
func (s *Store) DeleteAllSessions(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions`)
	if err != nil {
		return 0, fmt.Errorf("store: delete sessions: %w", err)
	}
	return rowsAffected(res, "delete sessions")
}

// ---- recovery codes -------------------------------------------------------

// InsertRecoveryCode stores the SHA-256 hash of one recovery code. If rc.ID is
// empty a random id is generated. The stored record (with its final ID) is
// returned. UsedAt is written as NULL unless already set.
func (s *Store) InsertRecoveryCode(ctx context.Context, rc model.RecoveryCode) (model.RecoveryCode, error) {
	if rc.Hash == "" {
		return model.RecoveryCode{}, errors.New("store: recovery code missing hash")
	}
	if rc.ID == "" {
		rc.ID = newID("rec")
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO recovery_codes (id, hash, used_at) VALUES (?, ?, ?)`,
		rc.ID, rc.Hash, nullableTime(rc.UsedAt),
	); err != nil {
		return model.RecoveryCode{}, fmt.Errorf("store: insert recovery code: %w", err)
	}
	return rc, nil
}

// ListRecoveryCodes returns all recovery codes (used and unused) ordered by id.
func (s *Store) ListRecoveryCodes(ctx context.Context) ([]model.RecoveryCode, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, hash, used_at FROM recovery_codes ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: list recovery codes: %w", err)
	}
	defer rows.Close()

	var out []model.RecoveryCode
	for rows.Next() {
		var (
			rc     model.RecoveryCode
			usedAt sql.NullString
		)
		if err := rows.Scan(&rc.ID, &rc.Hash, &usedAt); err != nil {
			return nil, fmt.Errorf("store: scan recovery code: %w", err)
		}
		if usedAt.Valid {
			rc.UsedAt = parseTime(usedAt.String)
		}
		out = append(out, rc)
	}
	return out, rows.Err()
}

// ConsumeRecoveryCode marks one recovery code used, but only if it is still
// unused. Returns ErrAlreadyUsed if it was already consumed and ErrNotFound if
// the id does not exist — so a double-consume can never succeed.
func (s *Store) ConsumeRecoveryCode(ctx context.Context, id string, usedAt time.Time) error {
	return s.consumeSingleUse(ctx, "recovery_codes", id, usedAt)
}

// DeleteAllRecoveryCodes removes every recovery code and returns the number
// deleted. Used by `poolgate admin reset-auth`.
func (s *Store) DeleteAllRecoveryCodes(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM recovery_codes`)
	if err != nil {
		return 0, fmt.Errorf("store: delete recovery codes: %w", err)
	}
	return rowsAffected(res, "delete recovery codes")
}

// ---- bootstrap tokens -----------------------------------------------------

// InsertBootstrapToken stores the SHA-256 hash of one bootstrap token plus its
// expiry. If bt.ID is empty a random id is generated. The stored record (with
// its final ID) is returned.
func (s *Store) InsertBootstrapToken(ctx context.Context, bt model.BootstrapToken) (model.BootstrapToken, error) {
	if bt.TokenHash == "" {
		return model.BootstrapToken{}, errors.New("store: bootstrap token missing hash")
	}
	if bt.ExpiresAt.IsZero() {
		return model.BootstrapToken{}, errors.New("store: bootstrap token missing expires_at")
	}
	if bt.ID == "" {
		bt.ID = newID("bst")
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO bootstrap_tokens (id, token_hash, expires_at, used_at) VALUES (?, ?, ?, ?)`,
		bt.ID, bt.TokenHash, formatTime(bt.ExpiresAt), nullableTime(bt.UsedAt),
	); err != nil {
		return model.BootstrapToken{}, fmt.Errorf("store: insert bootstrap token: %w", err)
	}
	return bt, nil
}

// ListBootstrapTokens returns all bootstrap tokens (used and unused) ordered by
// expiry then id.
func (s *Store) ListBootstrapTokens(ctx context.Context) ([]model.BootstrapToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, token_hash, expires_at, used_at FROM bootstrap_tokens ORDER BY expires_at, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list bootstrap tokens: %w", err)
	}
	defer rows.Close()

	var out []model.BootstrapToken
	for rows.Next() {
		var (
			bt        model.BootstrapToken
			expiresAt string
			usedAt    sql.NullString
		)
		if err := rows.Scan(&bt.ID, &bt.TokenHash, &expiresAt, &usedAt); err != nil {
			return nil, fmt.Errorf("store: scan bootstrap token: %w", err)
		}
		bt.ExpiresAt = parseTime(expiresAt)
		if usedAt.Valid {
			bt.UsedAt = parseTime(usedAt.String)
		}
		out = append(out, bt)
	}
	return out, rows.Err()
}

// ConsumeBootstrapToken marks one bootstrap token used, but only if it is still
// unused. Returns ErrAlreadyUsed if it was already consumed and ErrNotFound if
// the id does not exist. Expiry is enforced by the caller (adminauth), which
// holds the clock — the store guards single-use.
func (s *Store) ConsumeBootstrapToken(ctx context.Context, id string, usedAt time.Time) error {
	return s.consumeSingleUse(ctx, "bootstrap_tokens", id, usedAt)
}

// DeleteAllBootstrapTokens removes every bootstrap token and returns the number
// deleted. Used by `poolgate admin reset-auth` to invalidate stale tokens.
func (s *Store) DeleteAllBootstrapTokens(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM bootstrap_tokens`)
	if err != nil {
		return 0, fmt.Errorf("store: delete bootstrap tokens: %w", err)
	}
	return rowsAffected(res, "delete bootstrap tokens")
}

// ---- helpers --------------------------------------------------------------

// consumeSingleUse flips used_at on a row only when it is still NULL, inside a
// transaction. It distinguishes "already used" from "missing" so callers can
// treat a replayed single-use secret differently from a bad id. table is a
// trusted internal constant (never user input).
func (s *Store) consumeSingleUse(ctx context.Context, table, id string, usedAt time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin consume %s: %w", table, err)
	}
	res, err := tx.ExecContext(ctx,
		"UPDATE "+table+" SET used_at = ? WHERE id = ? AND used_at IS NULL",
		formatTime(usedAt.UTC()), id)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("store: consume %s: %w", table, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("store: consume %s rows: %w", table, err)
	}
	if n == 0 {
		// Either the row is missing or it was already consumed; disambiguate.
		var exists int
		qerr := tx.QueryRowContext(ctx,
			"SELECT 1 FROM "+table+" WHERE id = ?", id).Scan(&exists)
		_ = tx.Rollback()
		if errors.Is(qerr, sql.ErrNoRows) {
			return ErrNotFound
		}
		if qerr != nil {
			return fmt.Errorf("store: consume %s check: %w", table, qerr)
		}
		return ErrAlreadyUsed
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit consume %s: %w", table, err)
	}
	return nil
}

// oneRow maps a mutating result to ErrNotFound when it affected no rows.
func oneRow(res interface{ RowsAffected() (int64, error) }, op string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: %s rows: %w", op, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// rowsAffected returns the affected-row count for a bulk delete.
func rowsAffected(res interface{ RowsAffected() (int64, error) }, op string) (int64, error) {
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: %s rows: %w", op, err)
	}
	return n, nil
}
