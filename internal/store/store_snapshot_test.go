package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/go2-im/poolgate/internal/config"
	"github.com/go2-im/poolgate/internal/crypto"
	"github.com/go2-im/poolgate/internal/model"
)

// TestSnapshot writes some data, snapshots the DB, and verifies the snapshot is
// a standalone SQLite file containing that data — with no -wal/-shm sidecars.
func TestSnapshot(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i + 7)
	}
	c, err := crypto.New(key)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	cfg := config.Default()
	cfg.DataDir = t.TempDir()

	s, err := Open(cfg, c)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.InsertAccount(context.Background(), model.Account{Label: "snap-acct", State: model.StateOK}); err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}

	// Snapshot while the store is still open (exercises the WAL / concurrent path).
	data, ver, err := Snapshot(cfg)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("snapshot is empty")
	}
	if ver <= 0 {
		t.Errorf("snapshot schema version = %d, want > 0", ver)
	}
	_ = s.Close()

	// The snapshot must be a self-contained DB: write it out and open it fresh.
	snapPath := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(snapPath, data, 0o600); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	db, err := sql.Open("sqlite", "file:"+snapPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE label = 'snap-acct'`).Scan(&n); err != nil {
		t.Fatalf("query snapshot: %v", err)
	}
	if n != 1 {
		t.Errorf("snapshot account count = %d, want 1", n)
	}
}

// TestSnapshotNoDB errors cleanly when the data dir has no database.
func TestSnapshotNoDB(t *testing.T) {
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	if _, _, err := Snapshot(cfg); err == nil {
		t.Fatal("expected an error snapshotting a data dir with no db")
	}
}

// TestSnapshotEmptyDataDir errors on an empty data dir path.
func TestSnapshotEmptyDataDir(t *testing.T) {
	if _, _, err := Snapshot(model.Config{}); err == nil {
		t.Fatal("expected an error for empty data dir")
	}
}
