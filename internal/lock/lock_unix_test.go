//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly || illumos

package lock

import (
	"path/filepath"
	"testing"
)

// TestAcquireReleaseReacquire covers the core flock lifecycle: acquire succeeds,
// a second concurrent acquire on the same path fails with ErrLocked, and after
// Release the lock can be re-acquired.
func TestAcquireReleaseReacquire(t *testing.T) {
	path := filepath.Join(t.TempDir(), "poolgate.lock")

	l1, err := Acquire(path)
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}

	// A second, independent open of the same file must be refused (flock is per
	// open file description, so this models a second process).
	if _, err := Acquire(path); err != ErrLocked {
		t.Fatalf("second Acquire err = %v, want ErrLocked", err)
	}

	if err := l1.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	// Release is idempotent / nil-safe.
	if err := l1.Release(); err != nil {
		t.Fatalf("second Release: %v", err)
	}

	l2, err := Acquire(path)
	if err != nil {
		t.Fatalf("re-Acquire after release: %v", err)
	}
	_ = l2.Release()
}

// TestAcquireOpenError returns an error (not ErrLocked) when the lockfile path is
// not creatable (its parent dir does not exist).
func TestAcquireOpenError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", "poolgate.lock")
	if _, err := Acquire(path); err == nil {
		t.Fatal("expected an error for an uncreatable lockfile path")
	}
}

// TestReleaseNil confirms Release is safe on a nil receiver.
func TestReleaseNil(t *testing.T) {
	var l *Lock
	if err := l.Release(); err != nil {
		t.Fatalf("nil Release: %v", err)
	}
}
