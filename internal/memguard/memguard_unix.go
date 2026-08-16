//go:build linux || darwin

package memguard

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// harden disables core dumps and locks the process's memory. Each step is
// independent and best-effort: a failure is recorded as a warning rather than
// aborting, and one failing does not skip the other.
func harden() Report {
	var r Report
	// Disable core dumps: a core file would contain the decrypted master key and
	// any in-flight plaintext. Setting both the soft and hard limit to 0 prevents
	// the kernel from writing one (and stops the process re-raising the limit).
	r.CoreDumpsDisabled = try(&r, "disable core dumps", func() error {
		return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
	})
	// Lock all current and future pages so secret material is never paged to
	// swap. This needs a sufficient RLIMIT_MEMLOCK; under the default container
	// limit (~64 KiB) without CAP_IPC_LOCK it fails with ENOMEM/EPERM, which we
	// surface as a warning and continue.
	r.MemoryLocked = try(&r, "lock memory (raise RLIMIT_MEMLOCK or add CAP_IPC_LOCK)", func() error {
		return unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE)
	})
	return r
}

// try runs one best-effort mitigation. On error it appends a "<what>: <err>"
// warning to r and reports false; on success it reports true.
func try(r *Report, what string, fn func() error) bool {
	if err := fn(); err != nil {
		r.Warnings = append(r.Warnings, fmt.Sprintf("%s: %v", what, err))
		return false
	}
	return true
}
