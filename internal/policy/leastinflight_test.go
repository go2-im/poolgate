package policy

import (
	"testing"

	"github.com/go2-im/poolgate/internal/model"
)

func TestLoadBalanceLeastInFlight(t *testing.T) {
	members := []model.Account{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	v := &StaticView{
		Healthy:      map[string]bool{"a": true, "b": true, "c": true},
		InFlightByID: map[string]int{"a": 5, "b": 1, "c": 3},
	}
	got, err := Select(model.StrategyLoadBalance, members, v)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got.ID != "b" {
		t.Errorf("least-in-flight picked %q, want b (fewest in-flight)", got.ID)
	}
}

func TestLoadBalanceTieBreaksRoundRobin(t *testing.T) {
	members := []model.Account{{ID: "a"}, {ID: "b"}}
	v := &StaticView{
		Healthy:      map[string]bool{"a": true, "b": true},
		InFlightByID: map[string]int{"a": 2, "b": 2}, // tied
	}
	first, _ := Select(model.StrategyLoadBalance, members, v)
	second, _ := Select(model.StrategyLoadBalance, members, v)
	third, _ := Select(model.StrategyLoadBalance, members, v)
	if first.ID == second.ID {
		t.Errorf("tie should round-robin, got %q twice in a row", first.ID)
	}
	if first.ID != third.ID {
		t.Errorf("round-robin should cycle back: first=%q third=%q", first.ID, third.ID)
	}
}

func TestLoadBalanceSkipsUnhealthyThenLeastInFlight(t *testing.T) {
	members := []model.Account{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	v := &StaticView{
		Healthy:      map[string]bool{"a": false, "b": true, "c": true},
		InFlightByID: map[string]int{"b": 4, "c": 2},
	}
	got, err := Select(model.StrategyLoadBalance, members, v)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got.ID != "c" {
		t.Errorf("picked %q, want c (healthy + least in-flight)", got.ID)
	}
}

func TestLoadBalanceZeroInFlightIsRoundRobin(t *testing.T) {
	// With no in-flight tracking (all zero), least-in-flight reduces to round-robin.
	members := []model.Account{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	v := &StaticView{Healthy: map[string]bool{"a": true, "b": true, "c": true}}
	seen := map[string]int{}
	for i := 0; i < 3; i++ {
		got, _ := Select(model.StrategyLoadBalance, members, v)
		seen[got.ID]++
	}
	for _, id := range []string{"a", "b", "c"} {
		if seen[id] != 1 {
			t.Errorf("round-robin over 3 should hit each once, %q=%d", id, seen[id])
		}
	}
}

// mutatingView returns a DIFFERENT (increasing) in-flight count on each InFlight
// call — modelling the gateway's live counter changing between the min-scan and
// the tied-scan. It must not panic (the fix snapshots each count once).
type mutatingView struct {
	healthy map[string]bool
	calls   map[string]int
	cursor  Cursor
}

func (v *mutatingView) IsHealthy(id string) bool { return v.healthy[id] }
func (v *mutatingView) Headroom(string) float64  { return 100 }
func (v *mutatingView) Weight(string) int        { return 1 }
func (v *mutatingView) Cursor() *Cursor          { return &v.cursor }
func (v *mutatingView) InFlight(id string) int {
	v.calls[id]++
	return v.calls[id] // strictly increases every read
}

func TestLoadBalanceLiveCounterNoPanic(t *testing.T) {
	members := []model.Account{{ID: "a"}, {ID: "b"}}
	v := &mutatingView{healthy: map[string]bool{"a": true, "b": true}, calls: map[string]int{}}
	// Before the fix, the second (tied) scan saw larger counts than the min-scan,
	// producing an empty tied set and a divide-by-zero in Cursor.next(0).
	for i := 0; i < 10; i++ {
		got, err := Select(model.StrategyLoadBalance, members, v)
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if got.ID != "a" && got.ID != "b" {
			t.Fatalf("selected %q, want a or b", got.ID)
		}
	}
}

func TestCursorNextZeroSafe(t *testing.T) {
	var c Cursor
	if got := c.next(0); got != 0 {
		t.Errorf("next(0) = %d, want 0 (guarded, no divide-by-zero)", got)
	}
	if got := c.next(-3); got != 0 {
		t.Errorf("next(-3) = %d, want 0", got)
	}
}
