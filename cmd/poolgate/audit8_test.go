package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go2-im/poolgate/internal/lock"
	"github.com/go2-im/poolgate/internal/store"
)

// TestBackupRefusesWhileServing asserts backup is now an offline operation: it takes
// the single-instance lock so no concurrent serve refresh can race the snapshot.
func TestBackupRefusesWhileServing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)
	t.Setenv(envMasterKey, "")
	t.Setenv(envBackupPassphrase, "pw-serving")
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	held, err := lock.Acquire(filepath.Join(dir, lockFile))
	if err != nil {
		t.Fatalf("hold instance lock: %v", err)
	}
	defer held.Release()

	err = run(ctx, []string{"backup", "--out", filepath.Join(t.TempDir(), "b.pgbak")}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "stop it before backing up") {
		t.Fatalf("backup-while-serving err = %v, want a 'stop it before backing up' message", err)
	}
}

// TestRestoreClearsStaleRotations asserts restore moves the target's existing
// rotations/ journal directory aside (into the .prev generation) so a restored
// install has no stale/foreign-key journals blocking backup/rotate.
func TestRestoreClearsStaleRotations(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)
	t.Setenv(envMasterKey, "")
	t.Setenv(envBackupPassphrase, "pw-rot")
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	// Take a clean bundle (no journals yet).
	bundle := filepath.Join(t.TempDir(), "b.pgbak")
	if err := run(ctx, []string{"backup", "--out", bundle}, io.Discard, io.Discard); err != nil {
		t.Fatalf("backup: %v", err)
	}
	// Now plant a STALE rotation journal in the live install.
	if err := os.MkdirAll(store.RotationsDir(dir), 0o700); err != nil {
		t.Fatalf("mkdir rotations: %v", err)
	}
	if err := os.WriteFile(filepath.Join(store.RotationsDir(dir), "acct_stale.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write stale journal: %v", err)
	}
	// Restore over it: the stale rotations/ must be moved aside and cleaned.
	if err := run(ctx, []string{"restore", bundle, "--force"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("restore --force: %v", err)
	}
	ids, err := store.PendingRotationIDsAt(dir)
	if err != nil {
		t.Fatalf("PendingRotationIDsAt: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("stale rotations survived restore: %v", ids)
	}
	// No leftover residue (.prev / rotations dir).
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".prev") {
			t.Errorf("restore left residue: %s", e.Name())
		}
	}
}
