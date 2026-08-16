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

// failWindow counts failures in a fixed rolling window and fires exactly once per
// window, when the count reaches the threshold. It is safe for concurrent use.
type failWindow struct {
	mu        sync.Mutex
	count     int
	start     time.Time
	threshold int
	window    time.Duration
	now       func() time.Time
}

func newFailWindow(threshold int, window time.Duration) *failWindow {
	return &failWindow{threshold: threshold, window: window, now: time.Now}
}

// record registers one failure and returns true exactly when this failure makes
// the count reach the threshold within the current window (so the caller emits
// once, not on every subsequent failure).
func (f *failWindow) record() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	if f.start.IsZero() || now.Sub(f.start) > f.window {
		f.start = now
		f.count = 0
	}
	f.count++
	return f.count == f.threshold
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
