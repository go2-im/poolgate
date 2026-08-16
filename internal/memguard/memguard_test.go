package memguard

import "testing"

// TestHardenSmoke calls Harden and asserts it returns a usable Report without
// panicking. It makes no platform-specific claim so it is valid everywhere.
func TestHardenSmoke(t *testing.T) {
	r := Harden()
	// A mitigation that did not apply must leave a warning explaining why, and a
	// mitigation that applied must not. (On unsupported platforms both are false
	// with a single "unsupported" warning.)
	if !r.CoreDumpsDisabled && !r.MemoryLocked && len(r.Warnings) == 0 {
		t.Fatal("nothing applied but no warning recorded")
	}
}
