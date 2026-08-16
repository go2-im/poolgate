//go:build !(linux || darwin)

package memguard

// harden is a no-op on platforms without the required syscalls. poolgate's
// release targets are linux (container) and darwin (dev), so this path is not
// exercised in practice; it records a warning so the caller can log that no
// memory hygiene was applied.
func harden() Report {
	return Report{Warnings: []string{"memory hygiene unsupported on this platform"}}
}
