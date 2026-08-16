// authanomaly.go tracks repeated invalid inbound-key attempts and emits a
// secret-free EventAuthAnomaly (DESIGN.md §11) when they cross a threshold within
// a rolling window — a signal of possible credential probing against the proxy.
package gateway

import (
	"fmt"
	"sync"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

const (
	// authAnomalyThreshold invalid-key attempts within authAnomalyWindow emit one
	// EventAuthAnomaly (the notify engine dedups repeats across the window).
	authAnomalyThreshold = 10
	authAnomalyWindow    = 5 * time.Minute
)

// failWindow counts failures in a true SLIDING window and fires at most once per
// window when the count reaches the threshold. It is safe for concurrent use.
// (A previous fixed/tumbling window reset the counter on window boundaries, so an
// attacker straddling a boundary could evade the threshold.) The timestamp ring
// is capped at the threshold, so memory stays bounded under a flood.
type failWindow struct {
	mu        sync.Mutex
	events    []time.Time
	firedAt   time.Time
	threshold int
	window    time.Duration
	now       func() time.Time
}

func newFailWindow(threshold int, window time.Duration) *failWindow {
	return &failWindow{threshold: threshold, window: window, now: time.Now}
}

// record registers one failure and returns true exactly when this failure makes
// the number of failures within the trailing window reach the threshold, firing
// at most once per window so the caller emits once rather than on every
// subsequent failure.
func (f *failWindow) record() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	cutoff := now.Add(-f.window)

	// Drop events that have aged out of the trailing window.
	keep := f.events[:0]
	for _, t := range f.events {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	f.events = keep
	f.events = append(f.events, now)
	// Bound the ring: only the most recent threshold timestamps matter for the
	// crossing decision.
	if len(f.events) > f.threshold {
		f.events = f.events[len(f.events)-f.threshold:]
	}

	if len(f.events) >= f.threshold && (f.firedAt.IsZero() || !f.firedAt.After(cutoff)) {
		f.firedAt = now
		return true
	}
	return false
}

// noteAuthFailure records one invalid-key attempt and emits EventAuthAnomaly when
// the rolling threshold is crossed. Best-effort: a nil sink is a no-op.
func (g *Gateway) noteAuthFailure() {
	if g.events == nil || g.authFail == nil {
		return
	}
	if g.authFail.record() {
		g.events.Emit(model.NotifyEvent{
			Kind: model.EventAuthAnomaly,
			Message: fmt.Sprintf("poolgate: %d invalid API-key attempts within %s (possible credential probing)",
				g.authFail.threshold, g.authFail.window),
			At: time.Now().UTC(),
		})
	}
}
