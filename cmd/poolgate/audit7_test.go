package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedPendingRotationJournal drops a dummy rotation-journal file under the data dir
// so the "pending rotation" guards trigger (they only glob rotations/*.json).
func seedPendingRotationJournal(t *testing.T, dir string) {
	t.Helper()
	rdir := filepath.Join(dir, "rotations")
	if err := os.MkdirAll(rdir, 0o700); err != nil {
		t.Fatalf("mkdir rotations: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rdir, "acct_pending.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write journal: %v", err)
	}
}

func TestRotateKeyRefusesWithPendingRotation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)
	t.Setenv(envMasterKey, "")
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	seedPendingRotationJournal(t, dir)
	err := run(ctx, []string{"rotate-key"}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "token-rotation journal") {
		t.Fatalf("rotate-key err = %v, want a pending-rotation refusal", err)
	}
	// No snapshot should have been written (it aborts before that).
	if snaps, _ := filepath.Glob(filepath.Join(dir, "poolgate-pre-rotate-*.db")); len(snaps) != 0 {
		t.Fatalf("rotate aborted must not write a snapshot, got %d", len(snaps))
	}
}

func TestBackupRefusesWithPendingRotation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)
	t.Setenv(envMasterKey, "")
	t.Setenv(envBackupPassphrase, "pw-pending")
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	seedPendingRotationJournal(t, dir)
	bundle := filepath.Join(t.TempDir(), "b.pgbak")
	err := run(ctx, []string{"backup", "--out", bundle}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "token-rotation journal") {
		t.Fatalf("backup err = %v, want a pending-rotation refusal", err)
	}
	if _, statErr := os.Stat(bundle); !os.IsNotExist(statErr) {
		t.Fatalf("no bundle should be written when a rotation is pending: %v", statErr)
	}
}

func TestRestoreRefusesWithStaleMarker(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)
	t.Setenv(envMasterKey, "")
	t.Setenv(envBackupPassphrase, "pw-marker")
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	bundle := filepath.Join(t.TempDir(), "b.pgbak")
	if err := run(ctx, []string{"backup", "--out", bundle}, io.Discard, io.Discard); err != nil {
		t.Fatalf("backup: %v", err)
	}
	// A leftover marker from an interrupted prior restore must block a new restore.
	if err := os.WriteFile(filepath.Join(dir, restoreMarkerFile), []byte("restore in progress\n"), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	err := run(ctx, []string{"restore", bundle, "--force"}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("restore err = %v, want a stale-marker refusal", err)
	}
}
