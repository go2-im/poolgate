package main

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go2-im/poolgate/internal/lock"
)

// TestServeSingleInstance asserts that `serve` refuses to start when another
// holder already owns the data dir's lockfile, returning a clear error before
// binding any listener.
func TestServeSingleInstance(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)

	// Provision the data dir (creates the store so openStore succeeds in serve).
	if err := run(context.Background(), []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Hold the lock as if a first server were running.
	held, err := lock.Acquire(filepath.Join(dir, lockFile))
	if err != nil {
		t.Fatalf("hold lock: %v", err)
	}
	defer held.Release()

	// A second serve must fail fast with the single-instance message.
	err = run(context.Background(), []string{"serve"}, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected serve to fail while the lock is held")
	}
	if !strings.Contains(err.Error(), "already running") {
		t.Fatalf("serve error = %v, want an 'already running' message", err)
	}
}

// TestRestoreRefusesWhileServing asserts restore won't run against a data dir a
// live server is using (it would delete the server's WAL sidecars).
func TestRestoreRefusesWhileServing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Setenv(envBackupPassphrase, "pw-abcdef")
	bundle := filepath.Join(t.TempDir(), "b.pgbak")
	if err := run(ctx, []string{"backup", "--out", bundle}, io.Discard, io.Discard); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// Simulate a live server by holding the lock.
	held, err := lock.Acquire(filepath.Join(dir, lockFile))
	if err != nil {
		t.Fatalf("hold lock: %v", err)
	}
	defer held.Release()

	err = run(ctx, []string{"restore", bundle, "--force"}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "stop it before restoring") {
		t.Fatalf("restore-while-serving error = %v, want a 'stop it before restoring' message", err)
	}
}
