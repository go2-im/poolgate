// Package memguard applies best-effort process memory hygiene to the long-lived
// `serve` process (DESIGN.md §22). It exists to keep the decrypted master key and
// account tokens off durable media:
//
//   - Core dumps are disabled (RLIMIT_CORE = 0) so a crash cannot write a core
//     file containing the master key or in-flight plaintext secrets.
//   - The process's memory is locked (mlockall MCL_CURRENT|MCL_FUTURE) so secret
//     pages are never paged out to swap.
//
// Applied at the top of serve, before the store (and thus the master key) is
// opened, these precede the key entering memory for the keyfile and
// POOLGATE_MASTER_KEY_FILE sources. A plain POOLGATE_MASTER_KEY env var is an
// exception: it is resident in the process environment block before any Go code
// runs, so use the _FILE convention to avoid that pre-Harden exposure.
//
// Both are hardening measures, not correctness requirements. Where they cannot be
// applied — an unsupported platform, or (for memory locking) an insufficient
// RLIMIT_MEMLOCK such as the ~64 KiB container default without the IPC_LOCK
// capability — Harden degrades to a warning in the returned Report and serve
// continues. Disabling core dumps succeeds unconditionally on the supported
// platforms; memory locking is the part expected to fail under tight limits.
package memguard

// Report is the outcome of Harden, for the caller to log. A false flag with a
// corresponding Warning means that mitigation could not be applied.
type Report struct {
	// CoreDumpsDisabled is true when RLIMIT_CORE was set to 0.
	CoreDumpsDisabled bool
	// MemoryLocked is true when the process memory was locked against swap.
	MemoryLocked bool
	// Warnings holds a human-readable reason for each mitigation that failed or
	// was skipped. Empty when everything applied cleanly.
	Warnings []string
}

// Harden applies the memory-hygiene mitigations for the current process and
// reports what was (and was not) applied. It never returns an error: hardening
// is best-effort and must not block startup.
func Harden() Report { return harden() }
