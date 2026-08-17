package admin

import (
	"fmt"
	"testing"
	"time"
)

// TestLimiterBucketMapBounded proves the anti-brute-force bucket map cannot grow
// without bound: a flood of DISTINCT keys is capped at maxBuckets (eviction runs
// before each new-key insert).
func TestLimiterBucketMapBounded(t *testing.T) {
	now := time.Now().UTC()
	clock := func() time.Time { return now }
	l := &limiter{buckets: map[string]*bucket{}, maxFailures: 5, maxBuckets: 3, window: time.Minute, lockout: time.Minute, now: clock}

	for i := 0; i < 200; i++ {
		l.Fail(fmt.Sprintf("route|ip-%d", i))
		if len(l.buckets) > l.maxBuckets {
			t.Fatalf("bucket map grew to %d, exceeds cap %d", len(l.buckets), l.maxBuckets)
		}
	}
	if len(l.buckets) != l.maxBuckets {
		t.Fatalf("final map size = %d, want %d (kept at the cap)", len(l.buckets), l.maxBuckets)
	}
}

// TestLimiterEvictsExpiredBeforeActive proves eviction drops EXPIRED buckets first
// (they hold no useful state) rather than a still-locked one, so a genuine active
// lockout survives a flood of stale keys.
func TestLimiterEvictsExpiredBeforeActive(t *testing.T) {
	now := time.Now().UTC()
	cur := now
	l := &limiter{buckets: map[string]*bucket{}, maxFailures: 2, maxBuckets: 3, window: time.Minute, lockout: 10 * time.Minute, now: func() time.Time { return cur }}

	// "victim" gets locked out (2 failures -> lockout 10m).
	l.Fail("victim")
	l.Fail("victim")
	if l.Allow("victim") {
		t.Fatal("victim should be locked out")
	}
	// Fill the rest of the cap with keys that will EXPIRE (single failure, window 1m).
	l.Fail("stale-a")
	l.Fail("stale-b")
	if len(l.buckets) != 3 {
		t.Fatalf("map size = %d, want 3 (victim + 2 stale)", len(l.buckets))
	}
	// Advance past the stale keys' window (but well within victim's 10m lockout).
	cur = now.Add(2 * time.Minute)
	// A new distinct key at the cap must prune the two expired stale keys, not the
	// still-locked victim.
	l.Fail("newcomer")
	if !contains(l.buckets, "victim") {
		t.Fatal("active lockout (victim) must survive eviction")
	}
	if !contains(l.buckets, "newcomer") {
		t.Fatal("newcomer must be inserted")
	}
	// victim is still locked out from the caller's perspective.
	if l.Allow("victim") {
		t.Fatal("victim must remain locked out after eviction")
	}
}

func contains(m map[string]*bucket, k string) bool {
	_, ok := m[k]
	return ok
}
