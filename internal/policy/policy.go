// Package policy is the pure, deterministic account-selection engine for a
// PolicyGroup (DESIGN.md §0 D7 / §4). Given an ordered member list and a
// health/usage View, it picks the account to route to for one of the three v1
// strategies:
//
//   - fallback     — first healthy member in stored order.
//   - best-quota   — healthy member with the MOST headroom, where an account's
//     headroom = min over its usage windows of (100 - used_percent);
//     deterministic tie-break = lowest account id.
//   - load-balance — round-robin across healthy members (round-robin is its
//     only mode in v1). A `select` (manually pinned member) is expressed as a
//     single-member group and falls out of `fallback` over one member.
//
// The engine performs NO I/O: health, headroom, and the round-robin cursor are
// all supplied by the caller through View, so scheduling is fully deterministic
// and testable. The round-robin Cursor is an explicit, caller-held value (one
// per group) — never a package global.
package policy

import (
	"errors"
	"fmt"
	"sync"

	"github.com/go2-im/poolgate/internal/model"
)

// ErrEmptyGroup is returned when Select is called with no members at all.
var ErrEmptyGroup = errors.New("policy: group has no members")

// ErrNoHealthyMember is the typed error returned when a group has members but
// none of them are currently healthy. Callers distinguish it via errors.Is to
// answer with a 503/backpressure rather than a hard configuration error.
var ErrNoHealthyMember = errors.New("policy: no healthy member in group")

// View is the health/usage snapshot the caller provides to the selection
// engine. Implementations read from the health engine (§12) and the last usage
// snapshot (§0 D4); the engine itself never touches storage or the network.
type View interface {
	// IsHealthy reports whether the account is currently eligible for routing
	// (state ok/unknown and not in cooldown — the caller decides the exact
	// predicate; the engine only skips members for which this is false).
	IsHealthy(accountID string) bool
	// Headroom returns the account's remaining headroom in [0,100] — the min
	// over its usage windows of (100 - used_percent). Only consulted by
	// best-quota. See MinHeadroom for the canonical computation from a Usage.
	Headroom(accountID string) float64
	// InFlight returns the number of in-flight upstream requests currently routed
	// to the account. Consulted by load-balance for least-in-flight selection
	// (DESIGN.md §23.1). Implementations that don't track concurrency return 0,
	// which reduces load-balance to plain round-robin.
	InFlight(accountID string) int
	// Cursor returns the group's round-robin cursor (stateful, advanced by
	// load-balance). Callers keep one Cursor per group; it is only consulted by
	// the load-balance strategy.
	Cursor() *Cursor
}

// Select picks an account from members for the given strategy using view.
// members MUST be in the group's stored order (fallback and round-robin both
// depend on it). It returns ErrEmptyGroup for an empty member list and
// ErrNoHealthyMember when members exist but none are healthy.
func Select(strategy model.Strategy, members []model.Account, view View) (model.Account, error) {
	if len(members) == 0 {
		return model.Account{}, ErrEmptyGroup
	}
	switch strategy {
	case model.StrategyFallback:
		return selectFallback(members, view)
	case model.StrategyBestQuota:
		return selectBestQuota(members, view)
	case model.StrategyLoadBalance:
		return selectLoadBalance(members, view)
	default:
		return model.Account{}, fmt.Errorf("policy: unknown strategy %q", strategy)
	}
}

// selectFallback returns the first healthy member in order.
func selectFallback(members []model.Account, view View) (model.Account, error) {
	for _, a := range members {
		if view.IsHealthy(a.ID) {
			return a, nil
		}
	}
	return model.Account{}, ErrNoHealthyMember
}

// selectBestQuota returns the healthy member with the maximum headroom, breaking
// ties deterministically toward the lowest account id (independent of member
// order).
func selectBestQuota(members []model.Account, view View) (model.Account, error) {
	var (
		best  model.Account
		bestH float64
		found bool
	)
	for _, a := range members {
		if !view.IsHealthy(a.ID) {
			continue
		}
		h := view.Headroom(a.ID)
		switch {
		case !found:
			best, bestH, found = a, h, true
		case h > bestH:
			best, bestH = a, h
		case h == bestH && a.ID < best.ID:
			// Equal headroom: deterministic tie-break to the lowest id.
			best = a
		}
	}
	if !found {
		return model.Account{}, ErrNoHealthyMember
	}
	return best, nil
}

// selectLoadBalance distributes across the healthy members using least-in-flight
// selection (DESIGN.md §23.1): it picks the healthy member with the fewest
// in-flight requests, breaking ties with the group's round-robin cursor over the
// tied set. When every healthy member has equal in-flight counts (the common case,
// e.g. all zero when concurrency is untracked), this reduces to plain round-robin
// (DESIGN.md §0 D7).
func selectLoadBalance(members []model.Account, view View) (model.Account, error) {
	healthy := make([]model.Account, 0, len(members))
	for _, a := range members {
		if view.IsHealthy(a.ID) {
			healthy = append(healthy, a)
		}
	}
	if len(healthy) == 0 {
		return model.Account{}, ErrNoHealthyMember
	}
	// Snapshot each healthy member's in-flight count ONCE: a View backed by live
	// counters (the gateway's) can change between reads, so computing the minimum
	// and the tied set from separate reads could otherwise yield an empty tied set
	// (and a divide-by-zero in the cursor). One snapshot keeps them consistent.
	counts := make([]int, len(healthy))
	minInFlight := 0
	for i, a := range healthy {
		counts[i] = view.InFlight(a.ID)
		if i == 0 || counts[i] < minInFlight {
			minInFlight = counts[i]
		}
	}
	// Round-robin over the members tied at that minimum (stored order). The min
	// came from this snapshot, so at least one member qualifies — tied is never
	// empty.
	tied := make([]model.Account, 0, len(healthy))
	for i, a := range healthy {
		if counts[i] == minInFlight {
			tied = append(tied, a)
		}
	}
	idx := view.Cursor().next(len(tied))
	return tied[idx], nil
}

// Cursor is the per-group round-robin state. The zero value is ready to use.
// It is an explicit, caller-held value (one per group) rather than a global, so
// rotation is deterministic and independently testable. It is safe for
// concurrent use on the proxy hot path.
type Cursor struct {
	mu sync.Mutex
	n  uint64
}

// next returns the index into a slice of the given length for the current
// rotation position, then advances the cursor by one. mod <= 0 returns 0 (a
// defensive guard so a momentarily-empty candidate set can never divide by zero).
func (c *Cursor) next(mod int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if mod <= 0 {
		return 0
	}
	i := int(c.n % uint64(mod))
	c.n++
	return i
}

// MinHeadroom is the canonical best-quota headroom for an account: the minimum
// over its usage windows of (100 - used_percent), each clamped to [0,100]. A
// Usage with no windows returns 100 (nothing constrains it). View
// implementations should use this so the metric matches DESIGN.md §4 / §0 D4.
func MinHeadroom(u model.Usage) float64 {
	if len(u.Windows) == 0 {
		return 100
	}
	m := 100.0
	for _, w := range u.Windows {
		if h := w.Headroom(); h < m {
			m = h
		}
	}
	return m
}

// StaticView is a simple in-memory View backed by maps plus one Cursor. It is a
// general-purpose implementation used by callers with a precomputed snapshot
// and by tests; missing ids read as unhealthy with zero headroom.
type StaticView struct {
	Healthy      map[string]bool
	HeadroomByID map[string]float64
	InFlightByID map[string]int
	cursor       Cursor
}

// IsHealthy reports the recorded health of the account (missing = unhealthy).
func (v *StaticView) IsHealthy(accountID string) bool { return v.Healthy[accountID] }

// Headroom reports the recorded headroom of the account (missing = 0).
func (v *StaticView) Headroom(accountID string) float64 { return v.HeadroomByID[accountID] }

// InFlight reports the recorded in-flight count of the account (missing = 0).
func (v *StaticView) InFlight(accountID string) int { return v.InFlightByID[accountID] }

// Cursor returns the view's round-robin cursor.
func (v *StaticView) Cursor() *Cursor { return &v.cursor }
