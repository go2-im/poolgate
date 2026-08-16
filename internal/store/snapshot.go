// snapshot.go implements a consistent, on-line snapshot of the SQLite database
// for `poolgate backup` (DESIGN.md §20). It uses SQLite's `VACUUM INTO`, which
// takes a read transaction and writes a single defragmented database file with
// no -wal/-shm sidecars — safe to run while the server holds the DB open in WAL
// mode. It deliberately opens a raw connection and does NOT migrate, so a backup
// never mutates the source database.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go2-im/poolgate/internal/crypto"
	"github.com/go2-im/poolgate/internal/model"
)

// CurrentSchemaVersion is the highest migration version this binary knows how to
// run. A restore bundle newer than this cannot be safely opened by this binary.
func CurrentSchemaVersion() int { return len(migrations) }

// VerifyRestoreBundle sanity-checks a decrypted backup database image BEFORE it
// is committed over a live install (DESIGN.md §20). It runs SQLite's
// integrity_check, refuses a bundle whose schema is newer than this binary
// supports, and — when the database has any accounts — sample-decrypts one
// sealed secret with the supplied master key to confirm the key actually matches
// the database (catching a bundle whose key and ciphertext diverged, e.g. one
// produced after a lost keyfile was silently regenerated).
func VerifyRestoreBundle(dbBytes, key []byte) error {
	cipher, err := crypto.New(key)
	if err != nil {
		return fmt.Errorf("store: verify bundle: %w", err)
	}
	tmpDir, err := os.MkdirTemp("", "poolgate-verify-")
	if err != nil {
		return fmt.Errorf("store: verify tempdir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	p := filepath.Join(tmpDir, "bundle.db")
	if err := os.WriteFile(p, dbBytes, 0o600); err != nil {
		return fmt.Errorf("store: write bundle for verify: %w", err)
	}

	db, err := sql.Open("sqlite", "file:"+p+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return fmt.Errorf("store: open bundle for verify: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := context.Background()

	var integ string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integ); err != nil {
		return fmt.Errorf("store: bundle integrity_check failed to run: %w", err)
	}
	if integ != "ok" {
		return fmt.Errorf("store: bundle database is corrupt (integrity_check: %s)", integ)
	}

	var ver sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&ver); err != nil {
		return fmt.Errorf("store: read bundle schema version: %w", err)
	}
	if ver.Valid && int(ver.Int64) > CurrentSchemaVersion() {
		return fmt.Errorf("store: bundle schema version %d is newer than this binary supports (%d) — upgrade poolgate before restoring",
			ver.Int64, CurrentSchemaVersion())
	}

	// Sample-decrypt one sealed secret to confirm the key matches the ciphertext.
	var sealed string
	switch err := db.QueryRowContext(ctx, `SELECT access_token FROM accounts LIMIT 1`).Scan(&sealed); {
	case errors.Is(err, sql.ErrNoRows):
		// No accounts to sample — integrity + schema checks are all we can do.
		return nil
	case err != nil:
		return fmt.Errorf("store: read bundle sample secret: %w", err)
	}
	if _, err := cipher.Open(sealed); err != nil {
		return errors.New("store: master key does not match this backup's database (bundle key/ciphertext mismatch)")
	}
	return nil
}

// Snapshot returns a consistent copy of the database under cfg.DataDir as a byte
// slice (a standalone SQLite file) plus its schema version. It errors if the
// database does not exist. The snapshot is written to a temporary directory,
// read, and removed; the caller receives only the bytes.
func Snapshot(cfg model.Config) (data []byte, schemaVersion int, err error) {
	if cfg.DataDir == "" {
		return nil, 0, errors.New("store: empty data dir")
	}
	dbPath := filepath.Join(cfg.DataDir, DBFileName)
	if _, err := os.Stat(dbPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, fmt.Errorf("store: no database at %s (nothing to back up)", dbPath)
		}
		return nil, 0, fmt.Errorf("store: stat db: %w", err)
	}

	// Open the source READ-ONLY so the snapshot can never mutate it — mode=ro
	// forbids writes, and dropping the journal_mode pragma prevents a
	// checkpoint-on-close from folding the WAL into the main file (both would
	// otherwise change the source bytes, breaking the non-mutation contract).
	// VACUUM INTO reads the source and writes only the target, so it works fine
	// on a read-only connection.
	dsn := "file:" + dbPath + "?mode=ro&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, 0, fmt.Errorf("store: open db for snapshot: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	// Snapshot under the data dir (already 0700) rather than the shared system
	// temp, and restrict the file to 0600 — the snapshot is an unencrypted SQLite
	// image (field-encrypted secret columns, but plaintext labels/endpoints/logs).
	tmpDir, err := os.MkdirTemp(cfg.DataDir, ".backup-snap-")
	if err != nil {
		return nil, 0, fmt.Errorf("store: snapshot tempdir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	snapPath := filepath.Join(tmpDir, "snapshot.db")

	// VACUUM INTO takes the target filename as an expression, so a bound parameter
	// is both correct and injection-safe.
	if _, err := db.ExecContext(context.Background(), "VACUUM INTO ?", snapPath); err != nil {
		return nil, 0, fmt.Errorf("store: vacuum into: %w", err)
	}
	if err := os.Chmod(snapPath, 0o600); err != nil {
		return nil, 0, fmt.Errorf("store: chmod snapshot: %w", err)
	}

	// Read the schema version FROM the produced snapshot (a single consistent
	// image), so the reported version always matches the bytes in the bundle —
	// not a separate read of the live DB that a concurrent migration could skew.
	schemaVersion, err = snapshotSchemaVersion(snapPath)
	if err != nil {
		return nil, 0, err
	}

	data, err = os.ReadFile(snapPath)
	if err != nil {
		return nil, 0, fmt.Errorf("store: read snapshot: %w", err)
	}
	return data, schemaVersion, nil
}

// snapshotSchemaVersion opens a produced snapshot file read-only and returns its
// schema version (MAX(version) FROM schema_migrations, 0 if none).
func snapshotSchemaVersion(snapPath string) (int, error) {
	db, err := sql.Open("sqlite", "file:"+snapPath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return 0, fmt.Errorf("store: open snapshot for version: %w", err)
	}
	defer db.Close()
	var v sql.NullInt64
	if err := db.QueryRowContext(context.Background(),
		`SELECT MAX(version) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, fmt.Errorf("store: read schema version: %w", err)
	}
	if v.Valid {
		return int(v.Int64), nil
	}
	return 0, nil
}
