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

// memberTypeAccount / memberTypeGroup are the polymorphic member kinds in
// group_members. v1 is flat and only uses account members, but the column is
// kept so nesting can land later without a schema break (DESIGN.md §0 D8).
const (
	memberTypeAccount = "account"
	memberTypeGroup   = "group"
)

// Store wraps a SQLite handle plus the field-encryption cipher.
type Store struct {
	db     *sql.DB
	cipher *crypto.Cipher
}

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

	s := &Store{db: db, cipher: cipher}
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
var migrations = []struct {
	version int
	sql     string
}{
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

	for _, m := range migrations {
		var exists int
		if err := s.db.QueryRowContext(ctx,
			`SELECT 1 FROM schema_migrations WHERE version = ?`, m.version,
		).Scan(&exists); err == nil {
			continue // already applied
		} else if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store: check migration %d: %w", m.version, err)
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
SELECT id, label, access_token, refresh_token, account_id, id_token, state, created_at, updated_at
FROM accounts WHERE id = ?`, id)
	return s.scanAccount(row)
}

// ListAccounts returns all accounts ordered by creation time then id.
func (s *Store) ListAccounts(ctx context.Context) ([]model.Account, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, label, access_token, refresh_token, account_id, id_token, state, created_at, updated_at
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
		&a.IDToken, &state, &createdAt, &updatedAt); err != nil {
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
	scopes, err := json.Marshal(k.Endpoints)
	if err != nil {
		return model.ApiKey{}, fmt.Errorf("store: marshal key scopes: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO api_keys (id, key, label, endpoints) VALUES (?, ?, ?, ?)`,
		k.ID, k.Key, k.Label, string(scopes)); err != nil {
		return model.ApiKey{}, fmt.Errorf("store: insert api key: %w", err)
	}
	return k, nil
}

// ListApiKeys returns all inbound keys ordered by id.
func (s *Store) ListApiKeys(ctx context.Context) ([]model.ApiKey, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, key, label, endpoints FROM api_keys ORDER BY id`)
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
		`SELECT id, key, label, endpoints FROM api_keys WHERE key = ?`, key)
	return scanApiKey(row)
}

func scanApiKey(sc rowScanner) (model.ApiKey, error) {
	var (
		k      model.ApiKey
		scopes string
	)
	if err := sc.Scan(&k.ID, &k.Key, &k.Label, &scopes); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ApiKey{}, ErrNotFound
		}
		return model.ApiKey{}, fmt.Errorf("store: scan api key: %w", err)
	}
	if err := json.Unmarshal([]byte(scopes), &k.Endpoints); err != nil {
		return model.ApiKey{}, fmt.Errorf("store: unmarshal key scopes: %w", err)
	}
	return k, nil
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
		if _, err := tx.ExecContext(ctx, `
INSERT INTO group_members (group_id, member_type, member_id, position) VALUES (?, ?, ?, ?)`,
			g.ID, memberTypeAccount, accID, i); err != nil {
			_ = tx.Rollback()
			return model.PolicyGroup{}, fmt.Errorf("store: insert group member: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return model.PolicyGroup{}, fmt.Errorf("store: commit insert group: %w", err)
	}
	return g, nil
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
SELECT member_id FROM group_members
WHERE group_id = ? AND member_type = ?
ORDER BY position`, id, memberTypeAccount)
	if err != nil {
		return model.PolicyGroup{}, fmt.Errorf("store: get group members: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var mid string
		if err := rows.Scan(&mid); err != nil {
			return model.PolicyGroup{}, fmt.Errorf("store: scan group member: %w", err)
		}
		g.MemberAccountIDs = append(g.MemberAccountIDs, mid)
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
			return model.Endpoint{}, model.PolicyGroup{}, nil, fmt.Errorf("store: resolve member %q: %w", id, err)
		}
		accounts = append(accounts, a)
	}
	return ep, group, accounts, nil
}

// ---- helpers --------------------------------------------------------------

// timeLayout is the timestamp storage format (RFC3339 with nanoseconds, UTC).
const timeLayout = "2006-01-02T15:04:05.999999999Z07:00"

func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func parseTime(s string) time.Time {
	t, err := time.Parse(timeLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func nowRFC3339() string { return formatTime(time.Now().UTC()) }

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
