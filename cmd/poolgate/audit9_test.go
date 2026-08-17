package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRestoreMarker plants a restore-in-progress marker in the data dir.
func writeRestoreMarker(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, restoreMarkerFile), []byte("restore in progress\n"), 0o600); err != nil {
		t.Fatalf("write restore marker: %v", err)
	}
}

// TestImportRefusedWithRestoreMarker asserts import (which opens/creates the store)
// refuses to run over a half-committed restore.
func TestImportRefusedWithRestoreMarker(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)
	t.Setenv(envMasterKey, "")
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	writeRestoreMarker(t, dir)
	authPath := writeAuthJSON(t)
	err := run(ctx, []string{"import", authPath}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "interrupted restore") {
		t.Fatalf("import err = %v, want an interrupted-restore refusal", err)
	}
}

// TestBackupRefusedWithRestoreMarker asserts backup (which uses store.Snapshot, not
// openStore) also refuses over a half-committed restore.
func TestBackupRefusedWithRestoreMarker(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)
	t.Setenv(envMasterKey, "")
	t.Setenv(envBackupPassphrase, "pw-marker2")
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	writeRestoreMarker(t, dir)
	err := run(ctx, []string{"backup", "--out", filepath.Join(t.TempDir(), "b.pgbak")}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "interrupted restore") {
		t.Fatalf("backup err = %v, want an interrupted-restore refusal", err)
	}
}

// TestInitRefusedWithRestoreMarker asserts init won't mint a fresh key/DB over a
// half-committed restore (openStore guards it).
func TestInitRefusedWithRestoreMarker(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)
	t.Setenv(envMasterKey, "")
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("first init: %v", err)
	}
	writeRestoreMarker(t, dir)
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "interrupted restore") {
		t.Fatalf("init-over-marker err = %v, want an interrupted-restore refusal", err)
	}
}
