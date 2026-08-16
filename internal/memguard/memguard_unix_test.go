//go:build linux || darwin

package memguard

import (
	"errors"
	"testing"
)

// TestHardenDisablesCoreDumps confirms that on a supported platform Harden
// always disables core dumps (lowering RLIMIT_CORE to 0 is permitted even
// unprivileged). Memory locking is environment-dependent (RLIMIT_MEMLOCK), so it
// is only checked for internal consistency: not-locked implies a warning.
func TestHardenDisablesCoreDumps(t *testing.T) {
	r := Harden()
	if !r.CoreDumpsDisabled {
		t.Errorf("core dumps not disabled; warnings=%v", r.Warnings)
	}
	if !r.MemoryLocked && len(r.Warnings) == 0 {
		t.Error("memory not locked but no warning recorded")
	}
}

// TestTry covers both branches of the best-effort helper deterministically,
// independent of any syscall outcome.
func TestTry(t *testing.T) {
	var r Report
	if ok := try(&r, "always ok", func() error { return nil }); !ok {
		t.Error("try(nil-error) should report true")
	}
	if len(r.Warnings) != 0 {
		t.Errorf("success path must not warn; got %v", r.Warnings)
	}

	if ok := try(&r, "always fails", func() error { return errors.New("boom") }); ok {
		t.Error("try(error) should report false")
	}
	if len(r.Warnings) != 1 || r.Warnings[0] != "always fails: boom" {
		t.Errorf("failure path warning = %v, want [\"always fails: boom\"]", r.Warnings)
	}
}
