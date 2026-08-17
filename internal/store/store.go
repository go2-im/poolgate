// Package store is poolgate's persistence layer: a pure-Go SQLite database
// (modernc.org/sqlite, no CGO) in WAL mode with an idempotent migration runner.
//
// Secret columns (accounts.access_token, accounts.refresh_token) are
// field-encrypted with the crypto package before insert and decrypted on read,
// so tokens are never stored as plaintext at rest (DESIGN.md §5). Token
// rotation is written inside a transaction so a rotated refresh_token is
// persisted atomically (DESIGN.md §0 D6 / §19.3).
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go2-im/poolgate/internal/crypto"
	"github.com/go2-im/poolgate/internal/model"

	_ "modernc.org/sqlite"
)

// DBFileName is the SQLite database filename created under Config.DataDir.
const DBFileName = "poolgate.db"

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrAlreadyUsed is returned by the single-use consume methods
// (ConsumeRecoveryCode / ConsumeBootstrapToken) when the row exists but has
// already been consumed (used_at is set).
var ErrAlreadyUsed = errors.New("store: already used")

// memberTypeAccount / memberTypeGroup are the polymorphic member kinds in
// group_members. v1 is flat and only uses account members, but the column is
// kept so nesting can land later without a schema break (DESIGN.md §0 D8).
const (
	memberTypeAccount = "account"
	memberTypeGroup   = "group"
)

// Store wraps a SQLite handle plus the field-encryption cipher.
type Store struct {
	db      *sql.DB
	cipher  *crypto.Cipher
	dataDir string // where the DB lives; used for the pre-migration snapshot
}

// migration is one ordered schema step. Versions are contiguous and append-only.
type migration struct {
	version int
	sql     string
}

// ErrSchemaTooNew is returned by Migrate when the database's recorded schema
// version is higher than the newest migration this binary knows — i.e. an older
// binary is being run against a database migrated by a newer one. Opening would
// risk misreading/corrupting data, so it is refused (DESIGN.md §20/§21).
var ErrSchemaTooNew = errors.New("store: database schema is newer than this binary supports")

// Open opens (creating if needed) the SQLite database under cfg.DataDir, enables
// WAL + a busy timeout + foreign keys, and runs pending migrations. The cipher
// is used to seal/open secret columns; it must be non-nil.
func Open(cfg model.Config, cipher *crypto.Cipher) (*Store, error) {
	if cipher == nil {
		return nil, errors.New("store: nil cipher")
	}
	if cfg.DataDir == "" {
		return nil, errors.New("store: empty data dir")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("store: mkdir data dir: %w", err)
	}
	dbPath := filepath.Join(cfg.DataDir, DBFileName)
	dsn := "file:" + dbPath +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(on)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open db: %w", err)
	}
	// modernc/sqlite applies connection pragmas per-connection; a single
	// writer connection keeps WAL semantics simple and avoids write contention.
	db.SetMaxOpenConns(1)

	s := &Store{db: db, cipher: cipher, dataDir: cfg.DataDir}
	if err := s.Migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the raw handle for tests and advanced callers.
func (s *Store) DB() *sql.DB { return s.db }

// migrations is the ordered list of schema versions. Each entry is applied once
// (tracked in schema_migrations) inside a transaction. Append-only: never edit
// or reorder a shipped migration.
var migrations = []migration{
	{
		version: 1,
		sql: `
CREATE TABLE accounts (
	id            TEXT PRIMARY KEY,
	label         TEXT NOT NULL DEFAULT '',
	access_token  TEXT NOT NULL,
	refresh_token TEXT NOT NULL,
	account_id    TEXT NOT NULL DEFAULT '',
	id_token      TEXT NOT NULL DEFAULT '',
	state         TEXT NOT NULL DEFAULT 'unknown',
	created_at    TEXT NOT NULL,
	updated_at    TEXT NOT NULL
);

CREATE TABLE api_keys (
	id        TEXT PRIMARY KEY,
	key       TEXT NOT NULL UNIQUE,
	label     TEXT NOT NULL DEFAULT '',
	endpoints TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE policy_groups (
	id       TEXT PRIMARY KEY,
	name     TEXT NOT NULL UNIQUE,
	strategy TEXT NOT NULL
);

CREATE TABLE group_members (
	group_id    TEXT NOT NULL REFERENCES policy_groups(id) ON DELETE CASCADE,
	member_type TEXT NOT NULL,
	member_id   TEXT NOT NULL,
	position    INTEGER NOT NULL,
	PRIMARY KEY (group_id, member_type, member_id)
);

CREATE TABLE endpoints (
	name     TEXT PRIMARY KEY,
	group_id TEXT NOT NULL REFERENCES policy_groups(id) ON DELETE RESTRICT
);
`,
	},
	{
		// v2 — generic usage snapshots + health-check history + per-account
		// timing/backoff columns for the health engine (DESIGN.md §0 D4 / §5 /
		// §12 / §23.1). Append-only: v1 above is never edited.
		version: 2,
		sql: `
CREATE TABLE usage_snapshots (
	id          TEXT PRIMARY KEY,
	account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
	plan_type   TEXT NOT NULL DEFAULT '',
	windows     TEXT NOT NULL DEFAULT '[]',
	captured_at TEXT NOT NULL
);
CREATE INDEX idx_usage_snapshots_account ON usage_snapshots(account_id, captured_at);

CREATE TABLE health_checks (
	id          TEXT PRIMARY KEY,
	account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
	kind        TEXT NOT NULL,
	ok          INTEGER NOT NULL DEFAULT 0,
	detail      TEXT NOT NULL DEFAULT '',
	latency_ms  INTEGER NOT NULL DEFAULT 0,
	at          TEXT NOT NULL
);
CREATE INDEX idx_health_checks_account ON health_checks(account_id, at);

ALTER TABLE accounts ADD COLUMN cooldown_until        TEXT;
ALTER TABLE accounts ADD COLUMN next_probe_at         TEXT;
ALTER TABLE accounts ADD COLUMN consecutive_failures  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN backoff_level         INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN concurrency_cap       INTEGER NOT NULL DEFAULT 0;
`,
	},
	{
		// v3 — admin-auth persistence (DESIGN.md §16 / §22): registered passkeys,
		// login sessions, one-time recovery codes, and short-TTL single-use
		// bootstrap registration tokens. Recovery codes and bootstrap tokens store
		// only a SHA-256 hash of the secret, never the plaintext. Append-only:
		// v1/v2 above are never edited.
		version: 3,
		sql: `
CREATE TABLE webauthn_credentials (
	id          TEXT PRIMARY KEY,
	cred_id     BLOB NOT NULL UNIQUE,
	public_key  BLOB NOT NULL,
	sign_count  INTEGER NOT NULL DEFAULT 0,
	aaguid      BLOB,
	transports  TEXT NOT NULL DEFAULT '[]',
	label       TEXT NOT NULL DEFAULT '',
	created_at  TEXT NOT NULL
);

CREATE TABLE sessions (
	id           TEXT PRIMARY KEY,
	created_at   TEXT NOT NULL,
	last_seen_at TEXT NOT NULL,
	expires_at   TEXT NOT NULL
);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

CREATE TABLE recovery_codes (
	id      TEXT PRIMARY KEY,
	hash    TEXT NOT NULL,
	used_at TEXT
);

CREATE TABLE bootstrap_tokens (
	id         TEXT PRIMARY KEY,
	token_hash TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	used_at    TEXT
);
`,
	},
	{
		// v4 — notification channels (DESIGN.md §11). One row per configured
		// DingTalk / WeCom / custom-webhook destination. The `config` column holds
		// the channel's delivery settings INCLUDING SECRETS (webhook URL, signing
		// secret) and is FIELD-ENCRYPTED with the crypto cipher before insert,
		// exactly like accounts.access_token — it is never stored or served in
		// plaintext (DESIGN.md §5 / SECURITY.md). `events` is a JSON array of
		// subscribed event kinds (empty = all). Append-only: v1–v3 above are never
		// edited.
		version: 4,
		sql: `
CREATE TABLE notify_channels (
	id            TEXT PRIMARY KEY,
	type          TEXT NOT NULL,
	name          TEXT NOT NULL DEFAULT '',
	enabled       INTEGER NOT NULL DEFAULT 1,
	config        TEXT NOT NULL,
	events        TEXT NOT NULL DEFAULT '[]',
	min_headroom  REAL NOT NULL DEFAULT 0,
	dedup_seconds INTEGER NOT NULL DEFAULT 0,
	created_at    TEXT NOT NULL,
	updated_at    TEXT NOT NULL
);
`,
	},
	{
		// v5 — request logs for the real-time monitor (DESIGN.md §15 / §24.1). One
		// secret-free row per proxied request; indexed on the columns the monitor
		// filters/streams by (time, api key, model, session, account, status).
		// Append-only: v1–v4 above are never edited.
		version: 5,
		sql: `
CREATE TABLE request_logs (
	id            TEXT PRIMARY KEY,
	at            TEXT NOT NULL,
	endpoint      TEXT NOT NULL DEFAULT '',
	policy        TEXT NOT NULL DEFAULT '',
	account_id    TEXT NOT NULL DEFAULT '',
	account_label TEXT NOT NULL DEFAULT '',
	model         TEXT NOT NULL DEFAULT '',
	api_key_id    TEXT NOT NULL DEFAULT '',
	api_key_label TEXT NOT NULL DEFAULT '',
	session_id    TEXT NOT NULL DEFAULT '',
	status        INTEGER NOT NULL DEFAULT 0,
	latency_ms    INTEGER NOT NULL DEFAULT 0,
	tokens_in     INTEGER NOT NULL DEFAULT 0,
	tokens_out    INTEGER NOT NULL DEFAULT 0,
	trace         TEXT NOT NULL DEFAULT '',
	error_type    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_request_logs_at      ON request_logs(at);
CREATE INDEX idx_request_logs_apikey  ON request_logs(api_key_id, at);
CREATE INDEX idx_request_logs_model   ON request_logs(model, at);
CREATE INDEX idx_request_logs_session ON request_logs(session_id, at);
CREATE INDEX idx_request_logs_account ON request_logs(account_id, at);
CREATE INDEX idx_request_logs_status  ON request_logs(status, at);
`,
	},
	{
		// v6 — proxy-key lifecycle (DESIGN.md §22): inbound api keys gain an
		// optional expiry and an optional IP allowlist. Additive columns with safe
		// defaults ('' = never expires, '[]' = any IP), so existing keys keep
		// working unchanged. Append-only: v1–v5 above are never edited.
		version: 6,
		sql: `
ALTER TABLE api_keys ADD COLUMN expires_at   TEXT NOT NULL DEFAULT '';
ALTER TABLE api_keys ADD COLUMN ip_allowlist TEXT NOT NULL DEFAULT '[]';
`,
	},
	{
		// v7 — append-only audit log (DESIGN.md §22): one secret-free row per
		// security-relevant admin/system action. Fixed-width `at` for chronological
		// TEXT ordering. Append-only: v1–v6 above are never edited.
		version: 7,
		sql: `
CREATE TABLE audit_log (
	id     TEXT PRIMARY KEY,
	at     TEXT NOT NULL,
	actor  TEXT NOT NULL DEFAULT '',
	action TEXT NOT NULL DEFAULT '',
	target TEXT NOT NULL DEFAULT '',
	detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_audit_log_at ON audit_log(at);
`,
	},
	{
		version: 8,
		sql: `
ALTER TABLE group_members ADD COLUMN weight INTEGER NOT NULL DEFAULT 1;
`,
	},
	{
		version: 9,
		sql: `
ALTER TABLE audit_log ADD COLUMN hash TEXT NOT NULL DEFAULT '';
`,
	},
	{
		version: 10,
		sql: `
-- Remove historical dangling account members left by older builds that deleted
-- accounts without cleaning group_members. Prevents a deleted account from
-- breaking endpoint routing for the whole group.
DELETE FROM group_members
WHERE member_type = 'account'
  AND member_id NOT IN (SELECT id FROM accounts);
`,
	},
}

// Migrate applies any migrations whose version is not yet recorded. It is
// idempotent: calling it repeatedly is a no-op once all versions are applied.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version    INTEGER PRIMARY KEY,
	applied_at TEXT NOT NULL
);`); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}

	// Load the set of already-applied versions in one scan; used for both the
	// downgrade guard and the per-version apply check below.
	applied, err := s.appliedVersions(ctx)
	if err != nil {
		return err
	}
	current := 0
	for v := range applied {
		if v > current {
			current = v
		}
	}
	newest := newestMigrationVersion()

	// Downgrade guard: refuse to run when the DB was migrated by a newer binary
	// (its recorded version exceeds what we know). Applying our older migrations
	// or reading newer schema could corrupt/misread data (DESIGN.md §20/§21).
	if current > newest {
		return fmt.Errorf("%w: database is at v%d but this poolgate supports up to v%d — upgrade the binary",
			ErrSchemaTooNew, current, newest)
	}

	// Determine whether any known migration is unrecorded — the SAME condition
	// the apply loop uses, so the snapshot is taken whenever the loop is about to
	// mutate the DB (including an out-of-order gap at/below MAX, not just MAX<newest).
	hasPending := false
	for _, m := range migrations {
		if !applied[m.version] {
			hasPending = true
			break
		}
	}

	// Pre-migration snapshot: before applying pending migrations to a non-empty
	// database, capture a consistent copy so a botched migration can be rolled
	// back. A fresh DB (current == 0) has nothing to preserve.
	if current > 0 && hasPending {
		if err := s.preMigrationSnapshot(ctx, current); err != nil {
			return fmt.Errorf("store: pre-migration snapshot: %w", err)
		}
	}

	for _, m := range migrations {
		if applied[m.version] {
			continue // already applied
		}

		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("store: begin migration %d: %w", m.version, err)
		}
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: apply migration %d: %w", m.version, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			m.version, nowRFC3339(),
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: record migration %d: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: commit migration %d: %w", m.version, err)
		}
	}
	return nil
}

// appliedVersions returns the set of migration versions recorded in
// schema_migrations (which must already exist).
func (s *Store) appliedVersions(ctx context.Context) (map[int]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("store: read applied migrations: %w", err)
	}
	defer rows.Close()
	set := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("store: scan migration version: %w", err)
		}
		set[v] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate migrations: %w", err)
	}
	return set, nil
}

// SchemaVersion returns the highest applied migration version (0 if none).
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT MAX(version) FROM schema_migrations`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("store: schema version: %w", err)
	}
	if !v.Valid {
		return 0, nil
	}
	return int(v.Int64), nil
}

// newestMigrationVersion is the highest version this binary can migrate to.
func newestMigrationVersion() int {
	max := 0
	for _, m := range migrations {
		if m.version > max {
			max = m.version
		}
	}
	return max
}

// preMigrationSnapshot writes a consistent copy of the current database to
// poolgate.pre-migration-v<fromVersion>.db in the data dir (0600) so a failed
// migration can be recovered. It publishes atomically — VACUUM INTO a temp file,
// chmod 0600, then rename into place — so an interrupted/failed snapshot never
// leaves a partial file under the real name (which the next run could mistake
// for a valid backup) and the published file is 0600 the instant it exists. It
// always writes a FRESH image reflecting the current data (overwriting any prior
// snapshot for this from-version), since migrations are atomic so the DB is
// always at fromVersion when this runs.
func (s *Store) preMigrationSnapshot(ctx context.Context, fromVersion int) error {
	if s.dataDir == "" {
		return nil
	}
	final := filepath.Join(s.dataDir, fmt.Sprintf("poolgate.pre-migration-v%d.db", fromVersion))
	tmp := final + ".tmp"
	// Clear any leftover temp from a prior interrupted run (VACUUM INTO requires
	// the target not to pre-exist).
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// VACUUM INTO produces a single consistent file with no -wal/-shm sidecars,
	// safe on the live WAL connection.
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", tmp); err != nil {
		_ = os.Remove(tmp) // never leave a partial file behind
		return err
	}
	// The snapshot is an unencrypted SQLite image (field-encrypted secrets, but
	// plaintext metadata) — restrict it before publishing under the real name.
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("chmod snapshot: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// ---- accounts -------------------------------------------------------------

// InsertAccount seals the token columns and inserts the account. If a.ID is
// empty a random id is generated. The stored account (with its final ID) is
// returned.
func (s *Store) InsertAccount(ctx context.Context, a model.Account) (model.Account, error) {
	if a.ID == "" {
		a.ID = newID("acct")
	}
	if a.State == "" {
		a.State = model.StateUnknown
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	if a.UpdatedAt.IsZero() {
		a.UpdatedAt = a.CreatedAt
	}

	sealedAccess, err := s.cipher.Seal(a.AccessToken)
	if err != nil {
		return model.Account{}, fmt.Errorf("store: seal access token: %w", err)
	}
	sealedRefresh, err := s.cipher.Seal(a.RefreshToken)
	if err != nil {
		return model.Account{}, fmt.Errorf("store: seal refresh token: %w", err)
	}

	if _, err := s.db.ExecContext(ctx, `
INSERT INTO accounts
	(id, label, access_token, refresh_token, account_id, id_token, state, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Label, sealedAccess, sealedRefresh, a.AccountID, a.IDToken,
		string(a.State), formatTime(a.CreatedAt), formatTime(a.UpdatedAt),
	); err != nil {
		return model.Account{}, fmt.Errorf("store: insert account: %w", err)
	}
	return a, nil
}

// GetAccount loads and decrypts a single account by id.
func (s *Store) GetAccount(ctx context.Context, id string) (model.Account, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, label, access_token, refresh_token, account_id, id_token, state, concurrency_cap, created_at, updated_at
FROM accounts WHERE id = ?`, id)
	return s.scanAccount(row)
}

// ListAccounts returns all accounts ordered by creation time then id.
func (s *Store) ListAccounts(ctx context.Context) ([]model.Account, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, label, access_token, refresh_token, account_id, id_token, state, concurrency_cap, created_at, updated_at
FROM accounts ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list accounts: %w", err)
	}
	defer rows.Close()

	var out []model.Account
	for rows.Next() {
		a, err := s.scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpdateTokens atomically rewrites the (rotated) token columns for one account
// inside a transaction, bumping updated_at. This is the persistence half of the
// single-flight refresh (DESIGN.md §0 D6 / §19.3): waiters must not proceed
// until the rotated refresh_token is durably committed.
func (s *Store) UpdateTokens(ctx context.Context, id, accessToken, refreshToken string) error {
	sealedAccess, err := s.cipher.Seal(accessToken)
	if err != nil {
		return fmt.Errorf("store: seal access token: %w", err)
	}
	sealedRefresh, err := s.cipher.Seal(refreshToken)
	if err != nil {
		return fmt.Errorf("store: seal refresh token: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin update tokens: %w", err)
	}
	res, err := tx.ExecContext(ctx, `
UPDATE accounts SET access_token = ?, refresh_token = ?, updated_at = ? WHERE id = ?`,
		sealedAccess, sealedRefresh, formatTime(time.Now().UTC()), id)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("store: update tokens: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("store: update tokens rows: %w", err)
	}
	if n == 0 {
		_ = tx.Rollback()
		return ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit update tokens: %w", err)
	}
	return nil
}

// UpdateState sets the lifecycle state for one account, bumping updated_at.
func (s *Store) UpdateState(ctx context.Context, id string, state model.AccountState) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE accounts SET state = ?, updated_at = ? WHERE id = ?`,
		string(state), formatTime(time.Now().UTC()), id)
	if err != nil {
		return fmt.Errorf("store: update state: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: update state rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateAccountMeta updates an account's editable, non-secret metadata (label and
// concurrency cap). Tokens/state are untouched. Returns ErrNotFound if no row
// matches.
func (s *Store) UpdateAccountMeta(ctx context.Context, id, label string, concurrencyCap int) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE accounts SET label = ?, concurrency_cap = ?, updated_at = ? WHERE id = ?`,
		label, concurrencyCap, formatTime(time.Now().UTC()), id)
	if err != nil {
		return fmt.Errorf("store: update account meta: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: update account meta rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func (s *Store) scanAccount(sc rowScanner) (model.Account, error) {
	var (
		a                     model.Account
		sealedAccess, refresh string
		state                 string
		createdAt, updatedAt  string
	)
	if err := sc.Scan(&a.ID, &a.Label, &sealedAccess, &refresh, &a.AccountID,
		&a.IDToken, &state, &a.ConcurrencyCap, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Account{}, ErrNotFound
		}
		return model.Account{}, fmt.Errorf("store: scan account: %w", err)
	}
	access, err := s.cipher.Open(sealedAccess)
	if err != nil {
		return model.Account{}, fmt.Errorf("store: open access token: %w", err)
	}
	rt, err := s.cipher.Open(refresh)
	if err != nil {
		return model.Account{}, fmt.Errorf("store: open refresh token: %w", err)
	}
	a.AccessToken = access
	a.RefreshToken = rt
	a.State = model.AccountState(state)
	a.CreatedAt = parseTime(createdAt)
	a.UpdatedAt = parseTime(updatedAt)
	return a, nil
}

// ---- usage snapshots ------------------------------------------------------

// SaveUsageSnapshot inserts a generic usage snapshot for an account. The
// windows are stored as a JSON column (DESIGN.md §0 D4 / §5). If snap.ID is
// empty a random id is generated; if CapturedAt is zero it defaults to now. The
// stored snapshot (with its final ID/CapturedAt) is returned.
func (s *Store) SaveUsageSnapshot(ctx context.Context, snap model.UsageSnapshot) (model.UsageSnapshot, error) {
	if snap.AccountID == "" {
		return model.UsageSnapshot{}, errors.New("store: usage snapshot missing account_id")
	}
	if snap.ID == "" {
		snap.ID = newID("usg")
	}
	if snap.CapturedAt.IsZero() {
		snap.CapturedAt = time.Now().UTC()
	}
	if snap.Windows == nil {
		snap.Windows = []model.UsageWindow{}
	}
	windows, err := json.Marshal(snap.Windows)
	if err != nil {
		return model.UsageSnapshot{}, fmt.Errorf("store: marshal usage windows: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO usage_snapshots (id, account_id, plan_type, windows, captured_at)
VALUES (?, ?, ?, ?, ?)`,
		snap.ID, snap.AccountID, snap.PlanType, string(windows), formatTime(snap.CapturedAt),
	); err != nil {
		return model.UsageSnapshot{}, fmt.Errorf("store: insert usage snapshot: %w", err)
	}
	return snap, nil
}

// GetLatestUsage returns the most recent usage snapshot for an account.
// ErrNotFound is returned when the account has no snapshots.
func (s *Store) GetLatestUsage(ctx context.Context, accountID string) (model.UsageSnapshot, error) {
	var (
		snap       model.UsageSnapshot
		windows    string
		capturedAt string
	)
	err := s.db.QueryRowContext(ctx, `
SELECT id, account_id, plan_type, windows, captured_at
FROM usage_snapshots WHERE account_id = ?
ORDER BY captured_at DESC, id DESC LIMIT 1`, accountID,
	).Scan(&snap.ID, &snap.AccountID, &snap.PlanType, &windows, &capturedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.UsageSnapshot{}, ErrNotFound
		}
		return model.UsageSnapshot{}, fmt.Errorf("store: get latest usage: %w", err)
	}
	if err := json.Unmarshal([]byte(windows), &snap.Windows); err != nil {
		return model.UsageSnapshot{}, fmt.Errorf("store: unmarshal usage windows: %w", err)
	}
	snap.CapturedAt = parseTime(capturedAt)
	return snap, nil
}

// ---- health checks --------------------------------------------------------

// RecordHealthCheck appends one probe result to health_checks. If hc.ID is
// empty a random id is generated; if At is zero it defaults to now. The stored
// record (with its final ID/At) is returned.
func (s *Store) RecordHealthCheck(ctx context.Context, hc model.HealthCheck) (model.HealthCheck, error) {
	if hc.AccountID == "" {
		return model.HealthCheck{}, errors.New("store: health check missing account_id")
	}
	if hc.ID == "" {
		hc.ID = newID("hc")
	}
	if hc.At.IsZero() {
		hc.At = time.Now().UTC()
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO health_checks (id, account_id, kind, ok, detail, latency_ms, at)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		hc.ID, hc.AccountID, string(hc.Kind), boolToInt(hc.OK), hc.Detail, hc.LatencyMS, formatTime(hc.At),
	); err != nil {
		return model.HealthCheck{}, fmt.Errorf("store: insert health check: %w", err)
	}
	return hc, nil
}

// ListHealthChecks returns an account's probe history newest-first, up to limit
// rows (limit <= 0 means all).
func (s *Store) ListHealthChecks(ctx context.Context, accountID string, limit int) ([]model.HealthCheck, error) {
	q := `SELECT id, account_id, kind, ok, detail, latency_ms, at
FROM health_checks WHERE account_id = ? ORDER BY at DESC, id DESC`
	args := []any{accountID}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list health checks: %w", err)
	}
	defer rows.Close()

	var out []model.HealthCheck
	for rows.Next() {
		var (
			hc   model.HealthCheck
			kind string
			okI  int
			at   string
		)
		if err := rows.Scan(&hc.ID, &hc.AccountID, &kind, &okI, &hc.Detail, &hc.LatencyMS, &at); err != nil {
			return nil, fmt.Errorf("store: scan health check: %w", err)
		}
		hc.Kind = model.HealthCheckKind(kind)
		hc.OK = okI != 0
		hc.At = parseTime(at)
		out = append(out, hc)
	}
	return out, rows.Err()
}

// ---- account timing -------------------------------------------------------

// GetAccountTiming loads the per-account scheduling/backoff state. Zero-valued
// timestamps mean the column was NULL. ErrNotFound if the account is missing.
func (s *Store) GetAccountTiming(ctx context.Context, id string) (model.AccountTiming, error) {
	var (
		t                        model.AccountTiming
		cooldownUntil, nextProbe sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `
SELECT cooldown_until, next_probe_at, consecutive_failures, backoff_level, concurrency_cap
FROM accounts WHERE id = ?`, id,
	).Scan(&cooldownUntil, &nextProbe, &t.ConsecutiveFailures, &t.BackoffLevel, &t.ConcurrencyCap)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.AccountTiming{}, ErrNotFound
		}
		return model.AccountTiming{}, fmt.Errorf("store: get account timing: %w", err)
	}
	if cooldownUntil.Valid {
		t.CooldownUntil = parseTime(cooldownUntil.String)
	}
	if nextProbe.Valid {
		t.NextProbeAt = parseTime(nextProbe.String)
	}
	return t, nil
}

// SetAccountTiming persists the per-account scheduling/backoff state, bumping
// updated_at. Zero-valued timestamps are written as SQL NULL.
func (s *Store) SetAccountTiming(ctx context.Context, id string, t model.AccountTiming) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE accounts SET
	cooldown_until = ?, next_probe_at = ?,
	consecutive_failures = ?, backoff_level = ?, concurrency_cap = ?,
	updated_at = ?
WHERE id = ?`,
		nullableTime(t.CooldownUntil), nullableTime(t.NextProbeAt),
		t.ConsecutiveFailures, t.BackoffLevel, t.ConcurrencyCap,
		formatTime(time.Now().UTC()), id)
	if err != nil {
		return fmt.Errorf("store: set account timing: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: set account timing rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetAccountState reads an account's current health state. The health engine uses
// it to re-read the authoritative state under its per-account lock before
// applying a transition, so a slow probe cannot compute against a stale snapshot.
func (s *Store) GetAccountState(ctx context.Context, id string) (model.AccountState, error) {
	var state string
	err := s.db.QueryRowContext(ctx, `SELECT state FROM accounts WHERE id = ?`, id).Scan(&state)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("store: get account state: %w", err)
	}
	return model.AccountState(state), nil
}

// UpdateStateAndTiming writes an account's health state AND scheduling/backoff
// timing in ONE UPDATE statement, so the two can never be observed or persisted
// out of sync (previously they were two separate statements — a crash or error
// between them left state and cooldown inconsistent). Zero-valued timestamps are
// written as SQL NULL.
func (s *Store) UpdateStateAndTiming(ctx context.Context, id string, state model.AccountState, t model.AccountTiming) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE accounts SET
	state = ?,
	cooldown_until = ?, next_probe_at = ?,
	consecutive_failures = ?, backoff_level = ?, concurrency_cap = ?,
	updated_at = ?
WHERE id = ?`,
		string(state),
		nullableTime(t.CooldownUntil), nullableTime(t.NextProbeAt),
		t.ConsecutiveFailures, t.BackoffLevel, t.ConcurrencyCap,
		formatTime(time.Now().UTC()), id)
	if err != nil {
		return fmt.Errorf("store: update state and timing: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: update state and timing rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- api keys -------------------------------------------------------------

// InsertApiKey inserts an inbound key. Endpoints scoping is stored as a JSON
// array; an empty slice means "all endpoints". If k.ID is empty a random id is
// generated. The stored key (with its final ID) is returned.
func (s *Store) InsertApiKey(ctx context.Context, k model.ApiKey) (model.ApiKey, error) {
	if k.ID == "" {
		k.ID = newID("key")
	}
	if k.Endpoints == nil {
		k.Endpoints = []string{}
	}
	if k.IPAllowlist == nil {
		k.IPAllowlist = []string{}
	}
	scopes, err := json.Marshal(k.Endpoints)
	if err != nil {
		return model.ApiKey{}, fmt.Errorf("store: marshal key scopes: %w", err)
	}
	allow, err := json.Marshal(k.IPAllowlist)
	if err != nil {
		return model.ApiKey{}, fmt.Errorf("store: marshal key ip allowlist: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO api_keys (id, key, label, endpoints, expires_at, ip_allowlist) VALUES (?, ?, ?, ?, ?, ?)`,
		k.ID, k.Key, k.Label, string(scopes), formatExpiry(k.ExpiresAt), string(allow)); err != nil {
		return model.ApiKey{}, fmt.Errorf("store: insert api key: %w", err)
	}
	return k, nil
}

// RotateApiKey replaces the secret of an existing key (same id, label, scope,
// expiry, allowlist), returning the updated key. Used by the admin rotate action.
func (s *Store) RotateApiKey(ctx context.Context, id, newKey string) (model.ApiKey, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE api_keys SET key = ? WHERE id = ?`, newKey, id)
	if err != nil {
		return model.ApiKey{}, fmt.Errorf("store: rotate api key: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return model.ApiKey{}, ErrNotFound
	}
	return s.GetApiKeyByID(ctx, id)
}

// ListApiKeys returns all inbound keys ordered by id.
func (s *Store) ListApiKeys(ctx context.Context) ([]model.ApiKey, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, key, label, endpoints, expires_at, ip_allowlist FROM api_keys ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: list api keys: %w", err)
	}
	defer rows.Close()

	var out []model.ApiKey
	for rows.Next() {
		k, err := scanApiKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// GetApiKeyByKey looks up an inbound key by its secret value. Callers doing
// inbound auth should still constant-time compare the returned key (the SQL
// lookup itself is not constant-time); this method exists so that lookup has a
// single home.
func (s *Store) GetApiKeyByKey(ctx context.Context, key string) (model.ApiKey, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, key, label, endpoints, expires_at, ip_allowlist FROM api_keys WHERE key = ?`, key)
	return scanApiKey(row)
}

func scanApiKey(sc rowScanner) (model.ApiKey, error) {
	var (
		k      model.ApiKey
		scopes string
		expiry string
		allow  string
	)
	if err := sc.Scan(&k.ID, &k.Key, &k.Label, &scopes, &expiry, &allow); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ApiKey{}, ErrNotFound
		}
		return model.ApiKey{}, fmt.Errorf("store: scan api key: %w", err)
	}
	if err := json.Unmarshal([]byte(scopes), &k.Endpoints); err != nil {
		return model.ApiKey{}, fmt.Errorf("store: unmarshal key scopes: %w", err)
	}
	if err := json.Unmarshal([]byte(allow), &k.IPAllowlist); err != nil {
		return model.ApiKey{}, fmt.Errorf("store: unmarshal key ip allowlist: %w", err)
	}
	if expiry != "" {
		t, err := time.Parse(time.RFC3339, expiry)
		if err != nil {
			return model.ApiKey{}, fmt.Errorf("store: parse key expiry: %w", err)
		}
		k.ExpiresAt = t.UTC()
	}
	return k, nil
}

// formatExpiry renders an expiry timestamp for storage (” when zero = never).
func formatExpiry(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// ---- policy groups & endpoints -------------------------------------------

// InsertPolicyGroup inserts a group and its ordered account members in a
// transaction. Member ordering follows g.MemberAccountIDs. If g.ID is empty a
// random id is generated. The stored group (with its final ID) is returned.
func (s *Store) InsertPolicyGroup(ctx context.Context, g model.PolicyGroup) (model.PolicyGroup, error) {
	if g.ID == "" {
		g.ID = newID("grp")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.PolicyGroup{}, fmt.Errorf("store: begin insert group: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO policy_groups (id, name, strategy) VALUES (?, ?, ?)`,
		g.ID, g.Name, string(g.Strategy)); err != nil {
		_ = tx.Rollback()
		return model.PolicyGroup{}, fmt.Errorf("store: insert group: %w", err)
	}
	for i, accID := range g.MemberAccountIDs {
		if err := assertAccountExistsTx(ctx, tx, accID); err != nil {
			_ = tx.Rollback()
			return model.PolicyGroup{}, err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO group_members (group_id, member_type, member_id, position, weight) VALUES (?, ?, ?, ?, ?)`,
			g.ID, memberTypeAccount, accID, i, g.Weight(accID)); err != nil {
			_ = tx.Rollback()
			return model.PolicyGroup{}, fmt.Errorf("store: insert group member: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return model.PolicyGroup{}, fmt.Errorf("store: commit insert group: %w", err)
	}
	return g, nil
}

// assertAccountExistsTx returns ErrNotFound (wrapped) when member id does not
// reference a real account, so policy-group writes can't create a dangling
// member that would degrade routing.
func assertAccountExistsTx(ctx context.Context, tx *sql.Tx, id string) error {
	var one int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM accounts WHERE id = ?`, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("store: policy group member %q does not exist: %w", id, ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("store: check member %q: %w", id, err)
	}
	return nil
}

// GetPolicyGroup loads a group and its ordered account member ids. Group-typed
// members are ignored in v1 (flat model, DESIGN.md §0 D8).
func (s *Store) GetPolicyGroup(ctx context.Context, id string) (model.PolicyGroup, error) {
	var (
		g        model.PolicyGroup
		strategy string
	)
	if err := s.db.QueryRowContext(ctx,
		`SELECT id, name, strategy FROM policy_groups WHERE id = ?`, id,
	).Scan(&g.ID, &g.Name, &strategy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.PolicyGroup{}, ErrNotFound
		}
		return model.PolicyGroup{}, fmt.Errorf("store: get group: %w", err)
	}
	g.Strategy = model.Strategy(strategy)

	rows, err := s.db.QueryContext(ctx, `
SELECT member_id, weight FROM group_members
WHERE group_id = ? AND member_type = ?
ORDER BY position`, id, memberTypeAccount)
	if err != nil {
		return model.PolicyGroup{}, fmt.Errorf("store: get group members: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			mid    string
			weight int
		)
		if err := rows.Scan(&mid, &weight); err != nil {
			return model.PolicyGroup{}, fmt.Errorf("store: scan group member: %w", err)
		}
		g.MemberAccountIDs = append(g.MemberAccountIDs, mid)
		if weight != 1 {
			if g.MemberWeights == nil {
				g.MemberWeights = make(map[string]int)
			}
			g.MemberWeights[mid] = weight
		}
	}
	if err := rows.Err(); err != nil {
		return model.PolicyGroup{}, err
	}
	return g, nil
}

// InsertEndpoint binds a named inbound route to a policy group.
func (s *Store) InsertEndpoint(ctx context.Context, e model.Endpoint) (model.Endpoint, error) {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO endpoints (name, group_id) VALUES (?, ?)`,
		e.Name, e.GroupID); err != nil {
		return model.Endpoint{}, fmt.Errorf("store: insert endpoint: %w", err)
	}
	return e, nil
}

// ListEndpointNames returns all endpoint names ordered by name.
func (s *Store) ListEndpointNames(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM endpoints ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list endpoint names: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("store: scan endpoint name: %w", err)
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// GetEndpoint loads an endpoint by name.
func (s *Store) GetEndpoint(ctx context.Context, name string) (model.Endpoint, error) {
	var e model.Endpoint
	if err := s.db.QueryRowContext(ctx,
		`SELECT name, group_id FROM endpoints WHERE name = ?`, name,
	).Scan(&e.Name, &e.GroupID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Endpoint{}, ErrNotFound
		}
		return model.Endpoint{}, fmt.Errorf("store: get endpoint: %w", err)
	}
	return e, nil
}

// ResolveEndpoint resolves endpoint name -> policy group -> ordered member
// accounts (decrypted). This is the routing lookup the proxy uses to pick an
// account for an inbound request.
func (s *Store) ResolveEndpoint(ctx context.Context, name string) (model.Endpoint, model.PolicyGroup, []model.Account, error) {
	ep, err := s.GetEndpoint(ctx, name)
	if err != nil {
		return model.Endpoint{}, model.PolicyGroup{}, nil, err
	}
	group, err := s.GetPolicyGroup(ctx, ep.GroupID)
	if err != nil {
		return model.Endpoint{}, model.PolicyGroup{}, nil, err
	}
	accounts := make([]model.Account, 0, len(group.MemberAccountIDs))
	for _, id := range group.MemberAccountIDs {
		a, err := s.GetAccount(ctx, id)
		if err != nil {
			// A dangling member (e.g. an account deleted by an older build that did
			// not clean group_members) is SKIPPED rather than failing the whole
			// endpoint — other healthy members must still route. A genuine store
			// error still propagates.
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return model.Endpoint{}, model.PolicyGroup{}, nil, fmt.Errorf("store: resolve member %q: %w", id, err)
		}
		accounts = append(accounts, a)
	}
	return ep, group, accounts, nil
}

// ---- helpers --------------------------------------------------------------

// timeLayout is the timestamp storage format (RFC3339 with nanoseconds, UTC).
const timeLayout = "2006-01-02T15:04:05.999999999Z07:00"

// timeLayoutFixed is a FIXED-WIDTH variant (always 9 fractional digits) used for
// columns that are range-filtered or ORDER BY'd as TEXT under SQLite's byte-wise
// BINARY collation (e.g. request_logs.at). The variable-width timeLayout drops
// trailing-zero fractions, so lexical order there is NOT chronological; the
// zero-padded form makes lexical order equal chronological order. parseTime reads
// both (its ".999999999" accepts any fraction width).
const timeLayoutFixed = "2006-01-02T15:04:05.000000000Z07:00"

func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

// formatTimeFixed formats t with fixed-width nanoseconds for lexically-orderable
// storage/comparison (see timeLayoutFixed).
func formatTimeFixed(t time.Time) string { return t.UTC().Format(timeLayoutFixed) }

func parseTime(s string) time.Time {
	t, err := time.Parse(timeLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func nowRFC3339() string { return formatTime(time.Now().UTC()) }

// nullableTime formats t for storage, or returns a NULL for the zero time.
func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return formatTime(t)
}

// boolToInt maps a bool to SQLite's 0/1 integer boolean.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// newID returns a short random id with the given prefix, e.g. "acct_9f3a...".
func newID(prefix string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read never returns an error on supported platforms; fall back to
		// a timestamp so we still return a usable (if less random) id.
		return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

// newSessionID mints an admin session id. Unlike newID (64-bit, fine for opaque
// row ids), the session id is ALSO the admin bearer cookie value and the only
// secret gating authenticated endpoints, so it uses 256 bits of entropy — far
// beyond any online guessing budget even without a per-request throttle.
func newSessionID() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("sess_%d", time.Now().UnixNano())
	}
	return "sess_" + hex.EncodeToString(b[:])
}
