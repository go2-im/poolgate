//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly || illumos

package lock

import (
	"path/filepath"
	"testing"
	"time"
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

// TestAcquireBlockingWaitsThenAcquires proves AcquireBlocking waits for a held lock
// to release rather than failing, then takes it.
func TestAcquireBlockingWaitsThenAcquires(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cred.lock")
	held, err := AcquireBlocking(path)
	if err != nil {
		t.Fatalf("first AcquireBlocking: %v", err)
	}

	got := make(chan *Lock, 1)
	go func() {
		l, aerr := AcquireBlocking(path) // must block until `held` is released
		if aerr != nil {
			t.Errorf("blocking AcquireBlocking: %v", aerr)
			got <- nil
			return
		}
		got <- l
	}()

	// The waiter must still be blocked while we hold the lock.
	select {
	case <-got:
		t.Fatal("AcquireBlocking returned while the lock was still held")
	case <-time.After(100 * time.Millisecond):
	}
	if err := held.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	select {
	case l := <-got:
		if l == nil {
			t.Fatal("waiter failed to acquire after release")
		}
		_ = l.Release()
	case <-time.After(2 * time.Second):
		t.Fatal("AcquireBlocking did not acquire after the holder released")
	}
}

// TestAcquireBlockingOpenError surfaces an error for an uncreatable path.
func TestAcquireBlockingOpenError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", "cred.lock")
	if _, err := AcquireBlocking(path); err == nil {
		t.Fatal("expected an error for an uncreatable lockfile path")
	}
}
