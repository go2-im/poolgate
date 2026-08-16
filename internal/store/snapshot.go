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

	"github.com/go2-im/poolgate/internal/model"
)

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
