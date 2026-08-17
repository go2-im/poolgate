//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly || illumos

package lock

import (
	"fmt"
	"os"
	"syscall"
)

// Lock is a held advisory file lock. Release (or process exit) frees it.
type Lock struct {
	f *os.File
}

// Acquire opens (creating if needed) the lockfile at path and takes a
// non-blocking exclusive flock. It returns ErrLocked if another process already
// holds it, or another error if the lockfile can't be opened.
func Acquire(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lock: open %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if err == syscall.EWOULDBLOCK {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("lock: flock %s: %w", path, err)
	}
	return &Lock{f: f}, nil
}

// AcquireBlocking opens (creating if needed) the lockfile at path and takes a
// BLOCKING exclusive flock: it waits until any other holder releases, rather than
// returning ErrLocked. Used for short-lived mutual-exclusion critical sections
// (e.g. the per-data-dir credential lock) that must serialize across processes —
// a live serve refresh vs a CLI login — without failing the caller. The lock is
// released by Release() or process exit, so a crashed holder never wedges it.
func AcquireBlocking(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lock: open %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock: flock %s: %w", path, err)
	}
	return &Lock{f: f}, nil
}

// Release unlocks and closes the lockfile. It is safe to call on a nil Lock and
// idempotent after the first call.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	f := l.f
	l.f = nil
	// LOCK_UN is implied by closing the fd, but unlock explicitly first so the
	// lock is dropped even if Close is deferred behind other work.
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return f.Close()
}
