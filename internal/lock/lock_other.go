//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || illumos)

package lock

// Lock is a no-op placeholder on platforms without advisory file locking.
type Lock struct{}

// Acquire always returns ErrUnsupported off unix. poolgate's release targets are
// linux/darwin, so this path is never exercised in practice.
func Acquire(path string) (*Lock, error) {
	return nil, ErrUnsupported
}

// AcquireBlocking always returns ErrUnsupported off unix (see Acquire).
func AcquireBlocking(path string) (*Lock, error) {
	return nil, ErrUnsupported
}

// Release is a no-op.
func (l *Lock) Release() error { return nil }
