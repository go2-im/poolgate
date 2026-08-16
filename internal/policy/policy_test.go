package policy

import (
	"errors"
	"testing"

	"github.com/go2-im/poolgate/internal/model"
)

// acct is a tiny helper to build a member with just an id.
func acct(id string) model.Account { return model.Account{ID: id} }

// members builds an ordered member slice from ids.
func members(ids ...string) []model.Account {
	out := make([]model.Account, 0, len(ids))
	for _, id := range ids {
		out = append(out, acct(id))
	}
	return out
}

// newView builds a StaticView from a healthy-id set and an id->headroom map.
func newView(healthy []string, headroom map[string]float64) *StaticView {
	h := make(map[string]bool, len(healthy))
	for _, id := range healthy {
		h[id] = true
	}
	return &StaticView{Healthy: h, HeadroomByID: headroom}
}

func TestSelect_EmptyGroup(t *testing.T) {
	for _, s := range []model.Strategy{
		model.StrategyFallback, model.StrategyBestQuota, model.StrategyLoadBalance,
	} {
		_, err := Select(s, nil, newView(nil, nil))
		if !errors.Is(err, ErrEmptyGroup) {
			t.Fatalf("strategy %q: want ErrEmptyGroup, got %v", s, err)
		}
	}
}

func TestSelect_UnknownStrategy(t *testing.T) {
	_, err := Select(model.Strategy("bogus"), members("a"), newView([]string{"a"}, nil))
	if err == nil {
		t.Fatal("want error for unknown strategy, got nil")
	}
	if errors.Is(err, ErrEmptyGroup) || errors.Is(err, ErrNoHealthyMember) {
		t.Fatalf("unexpected typed error: %v", err)
	}
}

func TestSelect_Fallback(t *testing.T) {
	tests := []struct {
		name    string
		members []string
		healthy []string
		want    string
		wantErr error
	}{
		{"first healthy in order", []string{"a", "b", "c"}, []string{"a", "b", "c"}, "a", nil},
		{"skip leading unhealthy", []string{"a", "b", "c"}, []string{"b", "c"}, "b", nil},
		{"skip to last healthy", []string{"a", "b", "c"}, []string{"c"}, "c", nil},
		{"order not id-sorted", []string{"z", "a"}, []string{"z", "a"}, "z", nil},
		{"single member", []string{"solo"}, []string{"solo"}, "solo", nil},
		{"all unhealthy", []string{"a", "b"}, nil, "", ErrNoHealthyMember},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Select(model.StrategyFallback, members(tt.members...), newView(tt.healthy, nil))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("want err %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got.ID != tt.want {
				t.Fatalf("want %q, got %q", tt.want, got.ID)
			}
		})
	}
}

func TestSelect_BestQuota(t *testing.T) {
	tests := []struct {
		name     string
		members  []string
		healthy  []string
		headroom map[string]float64
		want     string
		wantErr  error
	}{
		{
			name:     "max headroom wins",
			members:  []string{"a", "b", "c"},
			healthy:  []string{"a", "b", "c"},
			headroom: map[string]float64{"a": 10, "b": 90, "c": 50},
			want:     "b",
		},
		{
			name:     "unhealthy max is skipped",
			members:  []string{"a", "b", "c"},
			healthy:  []string{"a", "c"},
			headroom: map[string]float64{"a": 10, "b": 99, "c": 50},
			want:     "c",
		},
		{
			name:     "tie-break lowest id despite member order",
			members:  []string{"z", "m", "a"},
			healthy:  []string{"z", "m", "a"},
			headroom: map[string]float64{"z": 80, "m": 80, "a": 80},
			want:     "a",
		},
		{
			name:     "tie-break lowest id among the max only",
			members:  []string{"b", "a", "c"},
			healthy:  []string{"b", "a", "c"},
			headroom: map[string]float64{"b": 70, "a": 70, "c": 40},
			want:     "a",
		},
		{
			name:     "all unhealthy",
			members:  []string{"a", "b"},
			healthy:  nil,
			headroom: map[string]float64{"a": 100, "b": 100},
			want:     "",
			wantErr:  ErrNoHealthyMember,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Select(model.StrategyBestQuota, members(tt.members...), newView(tt.healthy, tt.headroom))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("want err %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got.ID != tt.want {
				t.Fatalf("want %q, got %q", tt.want, got.ID)
			}
		})
	}
}

func TestSelect_LoadBalance_Rotation(t *testing.T) {
	view := newView([]string{"a", "b", "c"}, nil)
	mem := members("a", "b", "c")
	// Two full rotations must cycle in stored order and repeat deterministically.
	want := []string{"a", "b", "c", "a", "b", "c"}
	for i, w := range want {
		got, err := Select(model.StrategyLoadBalance, mem, view)
		if err != nil {
			t.Fatalf("call %d: unexpected err: %v", i, err)
		}
		if got.ID != w {
			t.Fatalf("call %d: want %q, got %q", i, w, got.ID)
		}
	}
}

func TestSelect_LoadBalance_Fairness(t *testing.T) {
	view := newView([]string{"a", "b", "c"}, nil)
	mem := members("a", "b", "c")
	counts := map[string]int{}
	const rounds = 300
	for i := 0; i < rounds; i++ {
		got, err := Select(model.StrategyLoadBalance, mem, view)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		counts[got.ID]++
	}
	for _, id := range []string{"a", "b", "c"} {
		if counts[id] != rounds/3 {
			t.Fatalf("unfair distribution for %q: got %d want %d (%v)", id, counts[id], rounds/3, counts)
		}
	}
}

func TestSelect_LoadBalance_SkipUnhealthy(t *testing.T) {
	// b is unhealthy: rotation must fairly alternate a, c only.
	view := newView([]string{"a", "c"}, nil)
	mem := members("a", "b", "c")
	want := []string{"a", "c", "a", "c"}
	for i, w := range want {
		got, err := Select(model.StrategyLoadBalance, mem, view)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if got.ID != w {
			t.Fatalf("call %d: want %q, got %q", i, w, got.ID)
		}
	}
}

func TestSelect_LoadBalance_SingleAndNone(t *testing.T) {
	// Single healthy member always returns it (select == fallback of one).
	single := newView([]string{"solo"}, nil)
	for i := 0; i < 3; i++ {
		got, err := Select(model.StrategyLoadBalance, members("solo"), single)
		if err != nil || got.ID != "solo" {
			t.Fatalf("single member call %d: got %q err %v", i, got.ID, err)
		}
	}
	// No healthy member -> typed error.
	none := newView(nil, nil)
	if _, err := Select(model.StrategyLoadBalance, members("a", "b"), none); !errors.Is(err, ErrNoHealthyMember) {
		t.Fatalf("want ErrNoHealthyMember, got %v", err)
	}
}

func TestCursor_NextDeterministic(t *testing.T) {
	var c Cursor
	// mod 3 rotation.
	want := []int{0, 1, 2, 0, 1, 2}
	for i, w := range want {
		if got := c.next(3); got != w {
			t.Fatalf("next %d: want %d got %d", i, w, got)
		}
	}
	// Changing modulus rotates within the new length using the running counter.
	var c2 Cursor
	if got := c2.next(2); got != 0 {
		t.Fatalf("c2 first: want 0 got %d", got)
	}
	if got := c2.next(2); got != 1 {
		t.Fatalf("c2 second: want 1 got %d", got)
	}
}

func TestMinHeadroom(t *testing.T) {
	tests := []struct {
		name string
		u    model.Usage
		want float64
	}{
		{"no windows -> 100", model.Usage{}, 100},
		{
			name: "min across windows",
			u: model.Usage{Windows: []model.UsageWindow{
				{UsedPercent: 10}, // headroom 90
				{UsedPercent: 75}, // headroom 25 (min)
				{UsedPercent: 40}, // headroom 60
			}},
			want: 25,
		},
		{
			name: "clamps over-100 usage to 0 headroom",
			u: model.Usage{Windows: []model.UsageWindow{
				{UsedPercent: 120}, // clamps to 0
				{UsedPercent: 30},  // headroom 70
			}},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MinHeadroom(tt.u); got != tt.want {
				t.Fatalf("want %v got %v", tt.want, got)
			}
		})
	}
}

func TestStaticView_Accessors(t *testing.T) {
	v := &StaticView{
		Healthy:      map[string]bool{"a": true},
		HeadroomByID: map[string]float64{"a": 42},
	}
	if !v.IsHealthy("a") {
		t.Fatal("a should be healthy")
	}
	if v.IsHealthy("missing") {
		t.Fatal("missing id should be unhealthy")
	}
	if v.Headroom("a") != 42 {
		t.Fatalf("headroom a: want 42 got %v", v.Headroom("a"))
	}
	if v.Headroom("missing") != 0 {
		t.Fatalf("missing headroom: want 0 got %v", v.Headroom("missing"))
	}
	if v.Cursor() == nil {
		t.Fatal("cursor must not be nil")
	}
	// Cursor identity is stable across calls (same group state).
	c1, c2 := v.Cursor(), v.Cursor()
	if c1 != c2 {
		t.Fatal("cursor pointer must be stable")
	}
}

// TestSelect_LoadBalance_Concurrent exercises the cursor under -race; it only
// asserts every selection is a healthy member (rotation order is unspecified
// under concurrency, but no data race or out-of-range index may occur).
func TestSelect_LoadBalance_Concurrent(t *testing.T) {
	view := newView([]string{"a", "b", "c"}, nil)
	mem := members("a", "b", "c")
	const workers = 8
	done := make(chan error, workers)
	for w := 0; w < workers; w++ {
		go func() {
			for i := 0; i < 200; i++ {
				got, err := Select(model.StrategyLoadBalance, mem, view)
				if err != nil {
					done <- err
					return
				}
				if !view.IsHealthy(got.ID) {
					done <- errors.New("selected unhealthy member")
					return
				}
			}
			done <- nil
		}()
	}
	for w := 0; w < workers; w++ {
		if err := <-done; err != nil {
			t.Fatalf("worker error: %v", err)
		}
	}
}

func TestSelectWeightedDistributesByWeight(t *testing.T) {
	members := []model.Account{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	view := &StaticView{
		Healthy:    map[string]bool{"a": true, "b": true, "c": true},
		WeightByID: map[string]int{"a": 1, "b": 2, "c": 3}, // total 6
	}
	counts := map[string]int{}
	for i := 0; i < 12; i++ { // two full cycles
		got, err := Select(model.StrategyWeighted, members, view)
		if err != nil {
			t.Fatalf("select %d: %v", i, err)
		}
		counts[got.ID]++
	}
	if counts["a"] != 2 || counts["b"] != 4 || counts["c"] != 6 {
		t.Errorf("counts = %v, want a=2 b=4 c=6 (proportional to weights)", counts)
	}
}

func TestSelectWeightedDefaultsToEqualRoundRobin(t *testing.T) {
	members := []model.Account{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	// No WeightByID → every weight defaults to 1 → even distribution.
	view := &StaticView{Healthy: map[string]bool{"a": true, "b": true, "c": true}}
	counts := map[string]int{}
	for i := 0; i < 9; i++ {
		got, _ := Select(model.StrategyWeighted, members, view)
		counts[got.ID]++
	}
	if counts["a"] != 3 || counts["b"] != 3 || counts["c"] != 3 {
		t.Errorf("counts = %v, want 3/3/3", counts)
	}
}

func TestSelectWeightedSkipsUnhealthyAndErrsWhenNone(t *testing.T) {
	members := []model.Account{{ID: "a"}, {ID: "b"}}
	view := &StaticView{
		Healthy:    map[string]bool{"a": false, "b": true},
		WeightByID: map[string]int{"a": 5, "b": 1},
	}
	for i := 0; i < 3; i++ {
		got, err := Select(model.StrategyWeighted, members, view)
		if err != nil || got.ID != "b" {
			t.Fatalf("select = %v (err %v), want b (a is unhealthy)", got.ID, err)
		}
	}
	none := &StaticView{Healthy: map[string]bool{"a": false, "b": false}}
	if _, err := Select(model.StrategyWeighted, members, none); !errors.Is(err, ErrNoHealthyMember) {
		t.Errorf("no healthy → err %v, want ErrNoHealthyMember", err)
	}
}
