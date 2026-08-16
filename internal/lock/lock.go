// Package lock provides a single-instance advisory file lock so only one
// `poolgate serve` runs against a given data dir at a time (DESIGN.md §21). Two
// servers on the same data dir would double-bind the listeners and race on the
// SQLite WAL; an exclusive flock on a lockfile in the data dir prevents that.
//
// The lock is advisory and held for the lifetime of the returned *Lock (i.e. the
// process): it is associated with the open file description and is released by
// Release() or automatically when the process exits and the fd is closed by the
// kernel — so a crashed server does not leave a stale lock.
package lock

import "errors"

// ErrLocked is returned by Acquire when another process already holds the lock.
var ErrLocked = errors.New("lock: already held by another process")

// ErrUnsupported is returned on platforms without advisory file locking (none of
// poolgate's release targets, which are linux/darwin).
var ErrUnsupported = errors.New("lock: file locking not supported on this platform")
