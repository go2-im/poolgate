package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/go2-im/poolgate/internal/config"
	"github.com/go2-im/poolgate/internal/crypto"
	"github.com/go2-im/poolgate/internal/model"
)

// openStoreDir opens a store rooted at dir (so tests can inspect files under it).
func openStoreDir(t *testing.T, dir string) *Store {
	t.Helper()
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	c, err := crypto.New(key)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	cfg := config.Default()
	cfg.DataDir = dir
	s, err := Open(cfg, c)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestMigrateDowngradeGuard asserts an older binary refuses a DB migrated by a
// newer one (recorded version > newest known migration) with ErrSchemaTooNew.
func TestMigrateDowngradeGuard(t *testing.T) {
	ctx := context.Background()
	s := openStoreDir(t, t.TempDir())

	future := newestMigrationVersion() + 1
	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
		future, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("insert future version: %v", err)
	}

	if err := s.Migrate(ctx); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("Migrate err = %v, want ErrSchemaTooNew", err)
	}
}

// TestPreMigrationSnapshotDirect covers the snapshot mechanism: it writes a
// 0600, self-contained, consistent DB copy and is a no-op if one already exists.
func TestPreMigrationSnapshotDirect(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := openStoreDir(t, dir)

	if _, err := s.InsertAccount(ctx, model.Account{Label: "pre-snap", State: model.StateOK}); err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	if err := s.preMigrationSnapshot(ctx, 3); err != nil {
		t.Fatalf("preMigrationSnapshot: %v", err)
	}

	snap := filepath.Join(dir, "poolgate.pre-migration-v3.db")
	fi, err := os.Stat(snap)
	if err != nil {
		t.Fatalf("snapshot missing: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("snapshot perm = %v, want 0600", fi.Mode().Perm())
	}

	// It is a self-contained DB carrying the data.
	db, err := sql.Open("sqlite", "file:"+snap+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE label='pre-snap'`).Scan(&n); err != nil {
		t.Fatalf("query snapshot: %v", err)
	}
	if n != 1 {
		t.Errorf("snapshot account count = %d, want 1", n)
	}

	// Publishing is atomic and always-fresh: a second call re-publishes a valid
	// 0600 snapshot (no leftover .tmp, no partial file under the real name).
	if err := s.preMigrationSnapshot(ctx, 3); err != nil {
		t.Fatalf("second preMigrationSnapshot: %v", err)
	}
	fi2, err := os.Stat(snap)
	if err != nil {
		t.Fatalf("snapshot missing after second call: %v", err)
	}
	if fi2.Mode().Perm() != 0o600 {
		t.Errorf("refreshed snapshot perm = %v, want 0600", fi2.Mode().Perm())
	}
	if _, err := os.Stat(snap + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("leftover temp file after publish: %v", err)
	}
}

// TestMigratePreSnapshotOnPending is a white-box test: it appends a pending
// migration beyond the current newest and asserts Migrate takes a pre-migration
// snapshot of the existing (non-empty) DB and then applies the pending migration.
func TestMigratePreSnapshotOnPending(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := openStoreDir(t, dir) // fresh dir → migrates 1..newest with no snapshot

	if _, err := s.InsertAccount(ctx, model.Account{Label: "x", State: model.StateOK}); err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}

	from := newestMigrationVersion()
	orig := migrations
	defer func() { migrations = orig }()
	migrations = append(append([]migration{}, orig...),
		migration{version: from + 1, sql: "CREATE TABLE tmg_pending (x INTEGER)"})

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate with pending: %v", err)
	}

	// After a SUCCESSFUL migration the pre-migration snapshot is removed: it is a
	// raw unencrypted image of the old schema and keeping it would leak pre-hash
	// plaintext. Its only job (failed-migration recovery) is moot on success.
	snap := filepath.Join(dir, fmt.Sprintf("poolgate.pre-migration-v%d.db", from))
	if _, err := os.Stat(snap); !os.IsNotExist(err) {
		t.Fatalf("pre-migration snapshot should be cleaned up after success, still present: %v", err)
	}
	// The pending migration was applied.
	var n int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM tmg_pending`).Scan(&n); err != nil {
		t.Fatalf("pending migration not applied: %v", err)
	}
}

// TestMigrateSnapshotKeptOnFailure proves the snapshot IS created before applying
// migrations and is PRESERVED when a migration fails (so a botched upgrade can be
// recovered), i.e. it is only removed on full success.
func TestMigrateSnapshotKeptOnFailure(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	if _, err := s.InsertAccount(ctx, model.Account{Label: "x", State: model.StateOK}); err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	from := newestMigrationVersion()
	orig := migrations
	defer func() { migrations = orig }()
	migrations = append(append([]migration{}, orig...),
		migration{version: from + 1, sql: "THIS IS NOT VALID SQL"})

	if err := s.Migrate(ctx); err == nil {
		t.Fatal("Migrate with a broken pending migration should fail")
	}
	snap := filepath.Join(dir, fmt.Sprintf("poolgate.pre-migration-v%d.db", from))
	if _, err := os.Stat(snap); err != nil {
		t.Fatalf("pre-migration snapshot must be preserved on failure: %v", err)
	}
}

// TestMigrateFreshNoSnapshot asserts a fresh DB (version 0) takes no snapshot.
func TestMigrateFreshNoSnapshot(t *testing.T) {
	dir := t.TempDir()
	_ = openStoreDir(t, dir) // Open runs Migrate on a fresh DB

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if len(e.Name()) >= len("poolgate.pre-migration") && e.Name()[:len("poolgate.pre-migration")] == "poolgate.pre-migration" {
			t.Errorf("fresh DB unexpectedly produced a pre-migration snapshot: %s", e.Name())
		}
	}
}
