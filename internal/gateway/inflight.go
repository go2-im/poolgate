// inflight.go tracks the number of in-flight upstream requests routed to each
// pooled account, backing per-account concurrency caps + least-in-flight
// selection + bounded-queue backpressure (DESIGN.md §23.1). It is a tiny
// mutex-guarded counter map, safe for concurrent use on the proxy hot path.
package gateway

import "sync"

type inflight struct {
	mu sync.Mutex
	n  map[string]int
}

func newInflight() *inflight { return &inflight{n: make(map[string]int)} }

// add increments the in-flight count for an account (call before forwarding).
func (i *inflight) add(id string) {
	i.mu.Lock()
	i.n[id]++
	i.mu.Unlock()
}

// tryAdd atomically reserves a slot for an account honoring its concurrency cap:
// under a single lock it admits (and increments) only when cap <= 0 (unlimited)
// or the current count is below cap, returning whether the slot was reserved.
// This closes the check-then-add TOCTOU so the live count can never exceed the
// cap under concurrent arrivals (DESIGN.md §23.1).
func (i *inflight) tryAdd(id string, cap int) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if cap > 0 && i.n[id] >= cap {
		return false
	}
	i.n[id]++
	return true
}

// done decrements the in-flight count for an account (call after the attempt
// completes — streamed or failed). It never goes below zero.
func (i *inflight) done(id string) {
	i.mu.Lock()
	if i.n[id] > 0 {
		i.n[id]--
	}
	i.mu.Unlock()
}

// count returns the current in-flight count for an account.
func (i *inflight) count(id string) int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.n[id]
}
