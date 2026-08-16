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

	dsn := "file:" + dbPath +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, 0, fmt.Errorf("store: open db for snapshot: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	// Read the schema version without migrating (backups never mutate the source).
	var v sql.NullInt64
	if err := db.QueryRowContext(context.Background(),
		`SELECT MAX(version) FROM schema_migrations`).Scan(&v); err != nil {
		return nil, 0, fmt.Errorf("store: read schema version: %w", err)
	}
	if v.Valid {
		schemaVersion = int(v.Int64)
	}

	tmpDir, err := os.MkdirTemp("", "poolgate-snap-")
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

	data, err = os.ReadFile(snapPath)
	if err != nil {
		return nil, 0, fmt.Errorf("store: read snapshot: %w", err)
	}
	return data, schemaVersion, nil
}
