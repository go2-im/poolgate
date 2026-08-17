package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The P1#5 fix adds a restore-marker check (under the command locks) to rotate-key,
// init, and admin reset-auth — commands that previously either never checked the
// marker (rotate-key) or checked it with no lock held (init / admin). A stale marker
// (a prior restore interrupted mid-commit) must make each of them refuse rather than
// operate on a half-committed generation.

func writeStaleMarker(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, restoreMarkerFile), []byte("restore in progress\n"), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
}

func TestRotateKeyRefusesUnderStaleMarker(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)
	t.Setenv(envMasterKey, "")
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	writeStaleMarker(t, dir)
	err := run(ctx, []string{"rotate-key"}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "recover it manually") {
		t.Fatalf("rotate-key under stale marker err = %v, want a marker refusal", err)
	}
	// It must abort at the guard, before writing any pre-rotation snapshot.
	if snaps, _ := filepath.Glob(filepath.Join(dir, "poolgate-pre-rotate-*.db")); len(snaps) != 0 {
		t.Fatalf("rotate-key aborted at the marker must not write a snapshot, got %d", len(snaps))
	}
}

func TestInitRefusesUnderStaleMarker(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)
	t.Setenv(envMasterKey, "")
	writeStaleMarker(t, dir)
	err := run(ctx, []string{"init"}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "recover it manually") {
		t.Fatalf("init under stale marker err = %v, want a marker refusal", err)
	}
}

func TestAdminResetAuthRefusesUnderStaleMarker(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)
	t.Setenv(envMasterKey, "")
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	writeStaleMarker(t, dir)
	err := run(ctx, []string{"admin", "reset-auth"}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "recover it manually") {
		t.Fatalf("admin reset-auth under stale marker err = %v, want a marker refusal", err)
	}
}
