package health

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/usage"
)

// ---- fakes ----------------------------------------------------------------

// fakeStore is an in-memory Store for deterministic tests.
type fakeStore struct {
	mu       sync.Mutex
	accounts []model.Account
	timing   map[string]model.AccountTiming
	states   map[string]model.AccountState
	snaps    map[string][]model.UsageSnapshot
	checks   map[string][]model.HealthCheck

	failTiming   bool // GetAccountTiming errors
	failList     bool // ListAccounts errors
	failState    bool // UpdateState errors
	failSetTime  bool // SetAccountTiming errors
	failChecks   bool // ListHealthChecks errors
	failRecordHC bool // RecordHealthCheck errors
}

func newFakeStore(accts ...model.Account) *fakeStore {
	fs := &fakeStore{
		timing: map[string]model.AccountTiming{},
		states: map[string]model.AccountState{},
		snaps:  map[string][]model.UsageSnapshot{},
		checks: map[string][]model.HealthCheck{},
	}
	for _, a := range accts {
		fs.accounts = append(fs.accounts, a)
		fs.states[a.ID] = a.State
		fs.timing[a.ID] = model.AccountTiming{}
	}
	return fs
}

func (f *fakeStore) ListAccounts(context.Context) ([]model.Account, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList {
		return nil, errors.New("list boom")
	}
	// Reflect current states onto returned accounts.
	out := make([]model.Account, len(f.accounts))
	copy(out, f.accounts)
	for i := range out {
		if s, ok := f.states[out[i].ID]; ok {
			out[i].State = s
		}
	}
	return out, nil
}

func (f *fakeStore) GetAccountTiming(_ context.Context, id string) (model.AccountTiming, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failTiming {
		return model.AccountTiming{}, errors.New("timing boom")
	}
	return f.timing[id], nil
}

func (f *fakeStore) SetAccountTiming(_ context.Context, id string, t model.AccountTiming) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSetTime {
		return errors.New("set timing boom")
	}
	f.timing[id] = t
	return nil
}

func (f *fakeStore) UpdateState(_ context.Context, id string, s model.AccountState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failState {
		return errors.New("state boom")
	}
	f.states[id] = s
	return nil
}

func (f *fakeStore) SaveUsageSnapshot(_ context.Context, snap model.UsageSnapshot) (model.UsageSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	snap.ID = "snap"
	f.snaps[snap.AccountID] = append(f.snaps[snap.AccountID], snap)
	return snap, nil
}

func (f *fakeStore) RecordHealthCheck(_ context.Context, hc model.HealthCheck) (model.HealthCheck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failRecordHC {
		return model.HealthCheck{}, errors.New("record boom")
	}
	hc.ID = "hc"
	f.checks[hc.AccountID] = append(f.checks[hc.AccountID], hc)
	return hc, nil
}

func (f *fakeStore) ListHealthChecks(_ context.Context, id string, _ int) ([]model.HealthCheck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failChecks {
		return nil, errors.New("checks boom")
	}
	return append([]model.HealthCheck(nil), f.checks[id]...), nil
}

func (f *fakeStore) stateOf(id string) model.AccountState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.states[id]
}

func (f *fakeStore) timingOf(id string) model.AccountTiming {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.timing[id]
}

func (f *fakeStore) snapCount(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.snaps[id])
}

func (f *fakeStore) checkCount(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.checks[id])
}

// seedLiveChecks inserts n live-request checks at the given time.
func (f *fakeStore) seedLiveChecks(id string, n int, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := 0; i < n; i++ {
		f.checks[id] = append(f.checks[id], model.HealthCheck{
			AccountID: id, Kind: model.HealthKindLiveRequest, At: at,
		})
	}
}

// fakeUsage returns a scripted Usage or error.
type fakeUsage struct {
	u    model.Usage
	err  error
	seen int
}

func (f *fakeUsage) Fetch(context.Context, model.Account) (model.Usage, error) {
	f.seen++
	return f.u, f.err
}

// fakeRefresher records calls and returns a scripted result.
type fakeRefresher struct {
	err  error
	seen int
}

func (f *fakeRefresher) RefreshAccount(_ context.Context, a model.Account) (model.Account, error) {
	f.seen++
	if f.err != nil {
		return a, f.err
	}
	a.AccessToken = "refreshed"
	return a, nil
}

type fakeAuth struct {
	ok     bool
	detail string
	err    error
}

func (f *fakeAuth) Check(context.Context, model.Account) (bool, string, error) {
	return f.ok, f.detail, f.err
}

type fakeLive struct {
	ok         bool
	retryAfter time.Duration
	detail     string
	err        error
}

func (f *fakeLive) Live(context.Context, model.Account) (bool, time.Duration, string, error) {
	return f.ok, f.retryAfter, f.detail, f.err
}

// fixedClock returns a controllable clock.
type fixedClock struct{ t time.Time }

func (c *fixedClock) now() time.Time      { return c.t }
func (c *fixedClock) add(d time.Duration) { c.t = c.t.Add(d) }

var baseTime = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

// testSchedule is deterministic: no jitter unless a test overrides rnd.
func testSchedule() Schedule {
	s := DefaultSchedule()
	s.JitterFrac = 0 // deterministic by default
	return s
}

func newTestEngine(t *testing.T, st Store, up UsageProbe, rf Refresher, opts ...Option) (*Engine, *fixedClock) {
	t.Helper()
	clk := &fixedClock{t: baseTime}
	base := []Option{
		WithClock(clk.now),
		WithSchedule(testSchedule()),
		WithRand(func() float64 { return 0 }),
	}
	base = append(base, opts...)
	return New(st, up, rf, base...), clk
}

func healthyUsage() model.Usage {
	return model.Usage{PlanType: "plus", Windows: []model.UsageWindow{
		{Name: "primary", UsedPercent: 20, WindowSeconds: 18000},
		{Name: "secondary", UsedPercent: 40, WindowSeconds: 604800},
	}}
}

// ---- pure state machine ---------------------------------------------------

func TestApplyEventTransitions(t *testing.T) {
	e, _ := newTestEngine(t, newFakeStore(), &fakeUsage{}, &fakeRefresher{})
	now := baseTime

	tests := []struct {
		name      string
		state     model.AccountState
		in        model.AccountTiming
		ev        eventKind
		p         eventParams
		wantState model.AccountState
		check     func(t *testing.T, tr Transition)
	}{
		{
			name:      "healthy recovers to ok and resets backoff",
			state:     model.StateCooldown,
			in:        model.AccountTiming{BackoffLevel: 3, ConsecutiveFailures: 2, CooldownUntil: now.Add(time.Hour), ConcurrencyCap: 7},
			ev:        evProbeHealthy,
			p:         eventParams{now: now},
			wantState: model.StateOK,
			check: func(t *testing.T, tr Transition) {
				if tr.Timing.BackoffLevel != 0 || tr.Timing.ConsecutiveFailures != 0 {
					t.Fatalf("backoff/failures not reset: %+v", tr.Timing)
				}
				if !tr.Timing.CooldownUntil.IsZero() {
					t.Fatalf("cooldown not cleared: %v", tr.Timing.CooldownUntil)
				}
				if tr.Timing.ConcurrencyCap != 7 {
					t.Fatalf("ConcurrencyCap not preserved: %d", tr.Timing.ConcurrencyCap)
				}
				wantNext := now.Add(e.sched.OK)
				if !tr.Timing.NextProbeAt.Equal(wantNext) {
					t.Fatalf("next=%v want %v", tr.Timing.NextProbeAt, wantNext)
				}
			},
		},
		{
			name:      "refreshed recovers to ok",
			state:     model.StateExpired,
			ev:        evRefreshed,
			p:         eventParams{now: now},
			wantState: model.StateOK,
		},
		{
			name:      "rate-limited cooldown gated on retry-after",
			state:     model.StateOK,
			ev:        evRateLimited,
			p:         eventParams{now: now, retryAfter: 10 * time.Minute},
			wantState: model.StateCooldown,
			check: func(t *testing.T, tr Transition) {
				wantUntil := now.Add(10 * time.Minute)
				if !tr.Timing.CooldownUntil.Equal(wantUntil) {
					t.Fatalf("cooldownUntil=%v want %v", tr.Timing.CooldownUntil, wantUntil)
				}
				// Degraded base (1m) < retry-after (10m) → gated to CooldownUntil.
				if !tr.Timing.NextProbeAt.Equal(wantUntil) {
					t.Fatalf("next=%v want gated %v", tr.Timing.NextProbeAt, wantUntil)
				}
				if tr.Timing.BackoffLevel != 1 {
					t.Fatalf("backoff=%d want 1", tr.Timing.BackoffLevel)
				}
			},
		},
		{
			name:      "rate-limited without retry-after uses default cooldown",
			state:     model.StateOK,
			ev:        evRateLimited,
			p:         eventParams{now: now},
			wantState: model.StateCooldown,
			check: func(t *testing.T, tr Transition) {
				wantUntil := now.Add(e.sched.DefaultCooldown)
				if !tr.Timing.CooldownUntil.Equal(wantUntil) {
					t.Fatalf("cooldownUntil=%v want %v", tr.Timing.CooldownUntil, wantUntil)
				}
			},
		},
		{
			name:      "quota-zero gated on window reset",
			state:     model.StateOK,
			ev:        evQuotaZero,
			p:         eventParams{now: now, resetAt: now.Add(2 * time.Hour)},
			wantState: model.StateQuotaExhausted,
			check: func(t *testing.T, tr Transition) {
				wantUntil := now.Add(2 * time.Hour)
				if !tr.Timing.CooldownUntil.Equal(wantUntil) || !tr.Timing.NextProbeAt.Equal(wantUntil) {
					t.Fatalf("quota gating wrong: %+v", tr.Timing)
				}
			},
		},
		{
			name:      "quota-zero with past reset falls back to default cooldown",
			state:     model.StateOK,
			ev:        evQuotaZero,
			p:         eventParams{now: now, resetAt: now.Add(-time.Hour)},
			wantState: model.StateQuotaExhausted,
			check: func(t *testing.T, tr Transition) {
				wantUntil := now.Add(e.sched.DefaultCooldown)
				if !tr.Timing.CooldownUntil.Equal(wantUntil) {
					t.Fatalf("cooldownUntil=%v want %v", tr.Timing.CooldownUntil, wantUntil)
				}
			},
		},
		{
			name:      "expired sets expired and clears cooldown",
			state:     model.StateCooldown,
			in:        model.AccountTiming{CooldownUntil: now.Add(time.Hour)},
			ev:        evExpired,
			p:         eventParams{now: now},
			wantState: model.StateExpired,
			check: func(t *testing.T, tr Transition) {
				if !tr.Timing.CooldownUntil.IsZero() {
					t.Fatalf("cooldown not cleared")
				}
				wantNext := now.Add(e.sched.Expired)
				if !tr.Timing.NextProbeAt.Equal(wantNext) {
					t.Fatalf("next=%v want %v", tr.Timing.NextProbeAt, wantNext)
				}
			},
		},
		{
			name:      "soft fail keeps state and grows backoff",
			state:     model.StateOK,
			in:        model.AccountTiming{BackoffLevel: 1},
			ev:        evProbeSoftFail,
			p:         eventParams{now: now},
			wantState: model.StateOK,
			check: func(t *testing.T, tr Transition) {
				if tr.Timing.BackoffLevel != 2 {
					t.Fatalf("backoff=%d want 2", tr.Timing.BackoffLevel)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := e.applyEvent(tc.state, tc.in, tc.ev, tc.p)
			if tr.State != tc.wantState {
				t.Fatalf("state=%q want %q", tr.State, tc.wantState)
			}
			if tc.check != nil {
				tc.check(t, tr)
			}
		})
	}
}

func TestApplyEventTerminalNeverChanges(t *testing.T) {
	e, _ := newTestEngine(t, newFakeStore(), &fakeUsage{}, &fakeRefresher{})
	for _, s := range []model.AccountState{model.StateRevoked, model.StateDead} {
		in := model.AccountTiming{BackoffLevel: 2}
		tr := e.applyEvent(s, in, evProbeHealthy, eventParams{now: baseTime})
		if tr.State != s {
			t.Fatalf("terminal %q changed to %q", s, tr.State)
		}
		if tr.Timing.BackoffLevel != 2 {
			t.Fatalf("terminal timing mutated: %+v", tr.Timing)
		}
	}
}

func TestApplyEventUnknownEvent(t *testing.T) {
	e, _ := newTestEngine(t, newFakeStore(), &fakeUsage{}, &fakeRefresher{})
	tr := e.applyEvent(model.StateOK, model.AccountTiming{}, eventKind(999), eventParams{now: baseTime})
	if tr.State != model.StateOK {
		t.Fatalf("unknown event changed state to %q", tr.State)
	}
}

// ---- backoff / jitter -----------------------------------------------------

func TestBackoffIntervalGrowsAndCaps(t *testing.T) {
	base := time.Minute
	cap := 30 * time.Minute
	// Grows by doubling.
	for level, want := range map[int]time.Duration{
		0: 1 * time.Minute,
		1: 2 * time.Minute,
		2: 4 * time.Minute,
		3: 8 * time.Minute,
		4: 16 * time.Minute,
	} {
		if got := backoffInterval(base, level, cap); got != want {
			t.Fatalf("level %d: got %v want %v", level, got, want)
		}
	}
	// Caps for high levels (and never exceeds cap, no overflow).
	for _, level := range []int{5, 6, 100, 1_000_000} {
		if got := backoffInterval(base, level, cap); got != cap {
			t.Fatalf("level %d: got %v want cap %v", level, got, cap)
		}
	}
	if got := backoffInterval(0, 5, cap); got != 0 {
		t.Fatalf("zero base: got %v want 0", got)
	}
}

func TestJitterBounds(t *testing.T) {
	st := newFakeStore()
	s := testSchedule()
	s.JitterFrac = 0.5
	// rnd near 1 → max jitter; result must stay < d*(1+frac).
	e := New(st, &fakeUsage{}, &fakeRefresher{}, WithSchedule(s), WithRand(func() float64 { return 0.999999 }))
	d := 10 * time.Second
	got := e.jittered(d)
	if got < d {
		t.Fatalf("jitter reduced duration: %v < %v", got, d)
	}
	upper := time.Duration(float64(d) * (1 + s.JitterFrac))
	if got >= upper {
		t.Fatalf("jitter exceeded bound: %v >= %v", got, upper)
	}
	// rnd == 0 → exactly d.
	e2 := New(st, &fakeUsage{}, &fakeRefresher{}, WithSchedule(s), WithRand(func() float64 { return 0 }))
	if got := e2.jittered(d); got != d {
		t.Fatalf("zero jitter: got %v want %v", got, d)
	}
	// Out-of-range rnd is clamped (no panic, stays bounded).
	e3 := New(st, &fakeUsage{}, &fakeRefresher{}, WithSchedule(s), WithRand(func() float64 { return 5 }))
	if got := e3.jittered(d); got < d || got >= upper {
		t.Fatalf("clamp failed: %v", got)
	}
	// Disabled jitter or non-positive d returns d.
	if got := e2.jittered(0); got != 0 {
		t.Fatalf("zero d: %v", got)
	}
	e4 := New(st, &fakeUsage{}, &fakeRefresher{}, WithSchedule(testSchedule()))
	if got := e4.jittered(d); got != d {
		t.Fatalf("disabled jitter: %v", got)
	}
}

func TestClampLevel(t *testing.T) {
	if clampLevel(5, 3) != 3 {
		t.Fatal("clamp above max failed")
	}
	if clampLevel(2, 3) != 2 {
		t.Fatal("clamp below max mutated")
	}
	if clampLevel(9, 0) != 9 {
		t.Fatal("zero max should disable clamp")
	}
}

// ---- Due (scheduling gate) ------------------------------------------------

func TestDue(t *testing.T) {
	now := baseTime
	tests := []struct {
		name  string
		state model.AccountState
		t     model.AccountTiming
		want  bool
	}{
		{"terminal never due", model.StateRevoked, model.AccountTiming{}, false},
		{"dead never due", model.StateDead, model.AccountTiming{}, false},
		{"never scheduled is due", model.StateUnknown, model.AccountTiming{}, true},
		{"future probe not due", model.StateOK, model.AccountTiming{NextProbeAt: now.Add(time.Minute)}, false},
		{"past probe is due", model.StateOK, model.AccountTiming{NextProbeAt: now.Add(-time.Minute)}, true},
		{"exactly now is due", model.StateOK, model.AccountTiming{NextProbeAt: now}, true},
		{
			"cooldown gate blocks early re-probe",
			model.StateCooldown,
			model.AccountTiming{CooldownUntil: now.Add(time.Minute), NextProbeAt: now.Add(-time.Hour)},
			false,
		},
		{
			"after cooldown elapses becomes due",
			model.StateCooldown,
			model.AccountTiming{CooldownUntil: now.Add(-time.Second), NextProbeAt: now.Add(-time.Second)},
			true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Due(now, tc.state, tc.t); got != tc.want {
				t.Fatalf("Due=%v want %v", got, tc.want)
			}
		})
	}
}

// ---- passive hooks --------------------------------------------------------

func TestOnUnauthorizedRefreshOK(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateOK}
	st := newFakeStore(acct)
	rf := &fakeRefresher{}
	e, _ := newTestEngine(t, st, &fakeUsage{}, rf)

	got, err := e.OnUnauthorized(context.Background(), acct)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rf.seen != 1 {
		t.Fatalf("refresher called %d times", rf.seen)
	}
	if got.AccessToken != "refreshed" {
		t.Fatalf("expected refreshed token, got %q", got.AccessToken)
	}
	if st.stateOf("a1") != model.StateOK {
		t.Fatalf("state=%q want ok", st.stateOf("a1"))
	}
}

func TestOnUnauthorizedRefreshFailsExpires(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateOK}
	st := newFakeStore(acct)
	rf := &fakeRefresher{err: errors.New("bad refresh token")}
	e, _ := newTestEngine(t, st, &fakeUsage{}, rf)

	_, err := e.OnUnauthorized(context.Background(), acct)
	if err == nil {
		t.Fatal("expected error")
	}
	if st.stateOf("a1") != model.StateExpired {
		t.Fatalf("state=%q want expired", st.stateOf("a1"))
	}
}

func TestOnUnauthorizedTimingLoadError(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateOK}
	st := newFakeStore(acct)
	st.failTiming = true
	e, _ := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{})
	if _, err := e.OnUnauthorized(context.Background(), acct); err == nil {
		t.Fatal("expected timing load error")
	}
}

func TestOnRateLimited(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateOK}
	st := newFakeStore(acct)
	e, clk := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{})

	if err := e.OnRateLimited(context.Background(), acct, 5*time.Minute); err != nil {
		t.Fatalf("err: %v", err)
	}
	if st.stateOf("a1") != model.StateCooldown {
		t.Fatalf("state=%q want cooldown", st.stateOf("a1"))
	}
	tm := st.timingOf("a1")
	if !tm.CooldownUntil.Equal(clk.now().Add(5 * time.Minute)) {
		t.Fatalf("cooldownUntil=%v", tm.CooldownUntil)
	}
	// error propagation
	st.failTiming = true
	if err := e.OnRateLimited(context.Background(), acct, time.Minute); err == nil {
		t.Fatal("expected timing error")
	}
}

func TestOnQuotaExhausted(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateOK}
	st := newFakeStore(acct)
	e, clk := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{})
	reset := clk.now().Add(3 * time.Hour)
	if err := e.OnQuotaExhausted(context.Background(), acct, reset); err != nil {
		t.Fatalf("err: %v", err)
	}
	if st.stateOf("a1") != model.StateQuotaExhausted {
		t.Fatalf("state=%q want quota_exhausted", st.stateOf("a1"))
	}
	if !st.timingOf("a1").CooldownUntil.Equal(reset) {
		t.Fatalf("cooldown gate not set to reset")
	}
	st.failTiming = true
	if err := e.OnQuotaExhausted(context.Background(), acct, reset); err == nil {
		t.Fatal("expected timing error")
	}
}

func TestPersistUpdateStateError(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateOK}
	st := newFakeStore(acct)
	st.failState = true
	e, _ := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{})
	// A transition that changes state (ok→cooldown) must surface the state error.
	if err := e.OnRateLimited(context.Background(), acct, time.Minute); err == nil {
		t.Fatal("expected UpdateState error")
	}
}

// ---- active probing: usage poll -------------------------------------------

func TestProbeUsagePollHealthy(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateCooldown}
	st := newFakeStore(acct)
	up := &fakeUsage{u: healthyUsage()}
	e, _ := newTestEngine(t, st, up, &fakeRefresher{})

	hc, err := e.ProbeAccount(context.Background(), acct)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if hc.Kind != model.HealthKindUsagePoll || !hc.OK {
		t.Fatalf("hc=%+v", hc)
	}
	if st.stateOf("a1") != model.StateOK {
		t.Fatalf("state=%q want ok (recovered)", st.stateOf("a1"))
	}
	if st.snapCount("a1") != 1 {
		t.Fatalf("expected a usage snapshot saved, got %d", st.snapCount("a1"))
	}
}

func TestProbeUsagePollQuotaZero(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateOK}
	st := newFakeStore(acct)
	reset := baseTime.Add(90 * time.Minute)
	up := &fakeUsage{u: model.Usage{PlanType: "plus", Windows: []model.UsageWindow{
		{Name: "primary", UsedPercent: 100, ResetsAt: reset},
	}}}
	e, _ := newTestEngine(t, st, up, &fakeRefresher{})

	hc, err := e.ProbeAccount(context.Background(), acct)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if hc.OK {
		t.Fatal("expected not-ok health check for exhausted quota")
	}
	if st.stateOf("a1") != model.StateQuotaExhausted {
		t.Fatalf("state=%q want quota_exhausted", st.stateOf("a1"))
	}
	if !st.timingOf("a1").CooldownUntil.Equal(reset) {
		t.Fatalf("quota gate not set to window reset: %v", st.timingOf("a1").CooldownUntil)
	}
}

func TestProbeUsagePoll401RefreshOK(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateOK}
	st := newFakeStore(acct)
	up := &fakeUsage{err: usage.ErrTokenInvalid}
	rf := &fakeRefresher{}
	e, _ := newTestEngine(t, st, up, rf)

	if _, err := e.ProbeAccount(context.Background(), acct); err != nil {
		t.Fatalf("err: %v", err)
	}
	if rf.seen != 1 {
		t.Fatalf("refresher not called via single-flight path: %d", rf.seen)
	}
	if st.stateOf("a1") != model.StateOK {
		t.Fatalf("state=%q want ok", st.stateOf("a1"))
	}
}

func TestProbeUsagePoll401RefreshFails(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateOK}
	st := newFakeStore(acct)
	up := &fakeUsage{err: usage.ErrTokenInvalid}
	rf := &fakeRefresher{err: errors.New("refresh boom")}
	e, _ := newTestEngine(t, st, up, rf)

	if _, err := e.ProbeAccount(context.Background(), acct); err != nil {
		t.Fatalf("err: %v", err)
	}
	if st.stateOf("a1") != model.StateExpired {
		t.Fatalf("state=%q want expired", st.stateOf("a1"))
	}
}

func TestProbeUsagePollSoftFail(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateOK}
	st := newFakeStore(acct)
	up := &fakeUsage{err: errors.New("network glitch")}
	e, _ := newTestEngine(t, st, up, &fakeRefresher{})

	if _, err := e.ProbeAccount(context.Background(), acct); err != nil {
		t.Fatalf("err: %v", err)
	}
	// Soft fail keeps state ok but grows backoff.
	if st.stateOf("a1") != model.StateOK {
		t.Fatalf("state=%q want ok (soft fail must not flap)", st.stateOf("a1"))
	}
	if st.timingOf("a1").BackoffLevel != 1 {
		t.Fatalf("backoff=%d want 1", st.timingOf("a1").BackoffLevel)
	}
}

func TestProbeTerminalSkipped(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateRevoked}
	st := newFakeStore(acct)
	up := &fakeUsage{u: healthyUsage()}
	e, _ := newTestEngine(t, st, up, &fakeRefresher{})

	hc, err := e.ProbeAccount(context.Background(), acct)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if hc.ID != "" {
		t.Fatal("terminal account should not be probed/recorded")
	}
	if up.seen != 0 {
		t.Fatal("usage probe should not run for terminal account")
	}
}

func TestProbeTimingLoadError(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateOK}
	st := newFakeStore(acct)
	st.failTiming = true
	e, _ := newTestEngine(t, st, &fakeUsage{u: healthyUsage()}, &fakeRefresher{})
	if _, err := e.ProbeAccount(context.Background(), acct); err == nil {
		t.Fatal("expected timing load error")
	}
}

func TestProbeRecordError(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateOK}
	st := newFakeStore(acct)
	st.failRecordHC = true
	e, _ := newTestEngine(t, st, &fakeUsage{u: healthyUsage()}, &fakeRefresher{})
	if _, err := e.ProbeAccount(context.Background(), acct); err == nil {
		t.Fatal("expected record health check error")
	}
}

func TestProbePersistError(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateOK}
	st := newFakeStore(acct)
	st.failSetTime = true
	e, _ := newTestEngine(t, st, &fakeUsage{u: healthyUsage()}, &fakeRefresher{})
	if _, err := e.ProbeAccount(context.Background(), acct); err == nil {
		t.Fatal("expected persist (set timing) error")
	}
}

// ---- active probing: auth-check -------------------------------------------

func TestProbeAuthCheckValid(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateExpired}
	st := newFakeStore(acct)
	e, _ := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{},
		WithAuthProbe(&fakeAuth{ok: true, detail: "models 200"}))

	hc, err := e.ProbeAccount(context.Background(), acct)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if hc.Kind != model.HealthKindAuthCheck {
		t.Fatalf("kind=%q want auth_check", hc.Kind)
	}
	if st.stateOf("a1") != model.StateOK {
		t.Fatalf("state=%q want ok (token valid again)", st.stateOf("a1"))
	}
}

func TestProbeAuthCheckInvalidRefreshFails(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateExpired}
	st := newFakeStore(acct)
	rf := &fakeRefresher{err: errors.New("nope")}
	e, _ := newTestEngine(t, st, &fakeUsage{}, rf,
		WithAuthProbe(&fakeAuth{ok: false, detail: "models 401"}))

	if _, err := e.ProbeAccount(context.Background(), acct); err != nil {
		t.Fatalf("err: %v", err)
	}
	if rf.seen != 1 {
		t.Fatalf("refresher not called: %d", rf.seen)
	}
	if st.stateOf("a1") != model.StateExpired {
		t.Fatalf("state=%q want expired", st.stateOf("a1"))
	}
}

func TestProbeAuthCheckError(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateExpired}
	st := newFakeStore(acct)
	e, _ := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{},
		WithAuthProbe(&fakeAuth{err: errors.New("timeout")}))

	if _, err := e.ProbeAccount(context.Background(), acct); err != nil {
		t.Fatalf("err: %v", err)
	}
	// soft fail: expired stays expired, backoff grows
	if st.stateOf("a1") != model.StateExpired {
		t.Fatalf("state=%q want expired", st.stateOf("a1"))
	}
	if st.timingOf("a1").BackoffLevel != 1 {
		t.Fatalf("backoff not grown on soft fail")
	}
}

func TestExpiredWithoutAuthProbeUsesUsagePoll(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateExpired}
	st := newFakeStore(acct)
	up := &fakeUsage{u: healthyUsage()}
	e, _ := newTestEngine(t, st, up, &fakeRefresher{}) // no auth probe

	hc, err := e.ProbeAccount(context.Background(), acct)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if hc.Kind != model.HealthKindUsagePoll {
		t.Fatalf("kind=%q want usage_poll fallback", hc.Kind)
	}
}

// ---- active probing: live requests + budget -------------------------------

func TestProbeLiveRecovers(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateCooldown}
	st := newFakeStore(acct)
	e, _ := newTestEngine(t, st, &fakeUsage{u: healthyUsage()}, &fakeRefresher{},
		WithAllowLive(true), WithLiveProbe(&fakeLive{ok: true, detail: "responses 200"}))

	hc, err := e.ProbeAccount(context.Background(), acct)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if hc.Kind != model.HealthKindLiveRequest {
		t.Fatalf("kind=%q want live_request", hc.Kind)
	}
	if st.stateOf("a1") != model.StateOK {
		t.Fatalf("state=%q want ok", st.stateOf("a1"))
	}
}

func TestProbeLive429Cooldown(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateCooldown}
	st := newFakeStore(acct)
	e, clk := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{},
		WithAllowLive(true), WithLiveProbe(&fakeLive{ok: false, retryAfter: 4 * time.Minute, detail: "429"}))

	if _, err := e.ProbeAccount(context.Background(), acct); err != nil {
		t.Fatalf("err: %v", err)
	}
	if st.stateOf("a1") != model.StateCooldown {
		t.Fatalf("state=%q want cooldown", st.stateOf("a1"))
	}
	if !st.timingOf("a1").CooldownUntil.Equal(clk.now().Add(4 * time.Minute)) {
		t.Fatalf("cooldown gate not set from live 429 retry-after")
	}
}

func TestProbeLiveSoftFail(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateQuotaExhausted}
	st := newFakeStore(acct)
	e, _ := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{},
		WithAllowLive(true), WithLiveProbe(&fakeLive{ok: false, detail: "500"}))

	if _, err := e.ProbeAccount(context.Background(), acct); err != nil {
		t.Fatalf("err: %v", err)
	}
	if st.stateOf("a1") != model.StateQuotaExhausted {
		t.Fatalf("state=%q want quota_exhausted (soft fail stays degraded)", st.stateOf("a1"))
	}
}

func TestProbeLiveError(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateCooldown}
	st := newFakeStore(acct)
	e, _ := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{},
		WithAllowLive(true), WithLiveProbe(&fakeLive{err: errors.New("dial fail")}))
	if _, err := e.ProbeAccount(context.Background(), acct); err != nil {
		t.Fatalf("err: %v", err)
	}
	if st.stateOf("a1") != model.StateCooldown {
		t.Fatalf("state=%q want cooldown", st.stateOf("a1"))
	}
}

func TestLiveProbeBudgetEnforced(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateCooldown}
	st := newFakeStore(acct)
	// Budget default is 5; seed 5 recent live checks → budget exhausted.
	st.seedLiveChecks("a1", 5, baseTime.Add(-time.Hour))
	live := &fakeLive{ok: true}
	e, _ := newTestEngine(t, st, &fakeUsage{u: healthyUsage()}, &fakeRefresher{},
		WithAllowLive(true), WithLiveProbe(live))

	hc, err := e.ProbeAccount(context.Background(), acct)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// Budget exhausted → falls back to usage poll, not a live request.
	if hc.Kind != model.HealthKindUsagePoll {
		t.Fatalf("kind=%q want usage_poll (budget exhausted)", hc.Kind)
	}
}

func TestLiveProbeBudgetIgnoresOldChecks(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateCooldown}
	st := newFakeStore(acct)
	// 5 live checks but all older than 24h → do not count → live allowed.
	st.seedLiveChecks("a1", 5, baseTime.Add(-48*time.Hour))
	e, _ := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{},
		WithAllowLive(true), WithLiveProbe(&fakeLive{ok: true}))

	hc, err := e.ProbeAccount(context.Background(), acct)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if hc.Kind != model.HealthKindLiveRequest {
		t.Fatalf("kind=%q want live_request (old checks should not count)", hc.Kind)
	}
}

func TestUsagePollOnlyByDefault(t *testing.T) {
	// AllowLive is false by default → even a degraded account gets usage-poll.
	acct := model.Account{ID: "a1", State: model.StateCooldown}
	st := newFakeStore(acct)
	live := &fakeLive{ok: true}
	e, _ := newTestEngine(t, st, &fakeUsage{u: healthyUsage()}, &fakeRefresher{},
		WithLiveProbe(live)) // provided but AllowLive not set

	hc, err := e.ProbeAccount(context.Background(), acct)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if hc.Kind != model.HealthKindUsagePoll {
		t.Fatalf("kind=%q want usage_poll (live is opt-in)", hc.Kind)
	}
}

func TestCanLiveProbeZeroBudget(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateCooldown}
	st := newFakeStore(acct)
	s := testSchedule()
	s.LiveBudget = 0
	e := New(st, &fakeUsage{u: healthyUsage()}, &fakeRefresher{},
		WithClock((&fixedClock{t: baseTime}).now), WithSchedule(s),
		WithAllowLive(true), WithLiveProbe(&fakeLive{ok: true}))
	hc, err := e.ProbeAccount(context.Background(), acct)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if hc.Kind != model.HealthKindUsagePoll {
		t.Fatalf("kind=%q want usage_poll (zero budget disables live)", hc.Kind)
	}
}

func TestCanLiveProbeCheckListError(t *testing.T) {
	acct := model.Account{ID: "a1", State: model.StateCooldown}
	st := newFakeStore(acct)
	st.failChecks = true
	e, _ := newTestEngine(t, st, &fakeUsage{u: healthyUsage()}, &fakeRefresher{},
		WithAllowLive(true), WithLiveProbe(&fakeLive{ok: true}))
	hc, err := e.ProbeAccount(context.Background(), acct)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// ListHealthChecks error → canLiveProbe false → usage poll fallback.
	if hc.Kind != model.HealthKindUsagePoll {
		t.Fatalf("kind=%q want usage_poll", hc.Kind)
	}
}

// ---- bindingReset ---------------------------------------------------------

func TestBindingReset(t *testing.T) {
	now := baseTime
	u := model.Usage{Windows: []model.UsageWindow{
		{Name: "a", UsedPercent: 50, ResetsAt: now.Add(time.Hour)},         // not exhausted, ignored
		{Name: "b", UsedPercent: 100, ResetsAt: now.Add(2 * time.Hour)},    // exhausted
		{Name: "c", UsedPercent: 100, ResetsAt: now.Add(30 * time.Minute)}, // exhausted, earliest
	}}
	if got := bindingReset(u); !got.Equal(now.Add(30 * time.Minute)) {
		t.Fatalf("bindingReset=%v want earliest exhausted reset", got)
	}
	// No exhausted window with a reset → zero.
	if got := bindingReset(model.Usage{Windows: []model.UsageWindow{{UsedPercent: 10}}}); !got.IsZero() {
		t.Fatalf("bindingReset=%v want zero", got)
	}
}

// ---- Tick / NextDue / Run -------------------------------------------------

func TestTickProbesOnlyDueNonTerminal(t *testing.T) {
	due := model.Account{ID: "due", State: model.StateOK}       // never scheduled → due
	notDue := model.Account{ID: "notdue", State: model.StateOK} // future probe
	terminal := model.Account{ID: "term", State: model.StateDead}
	st := newFakeStore(due, notDue, terminal)
	st.timing["notdue"] = model.AccountTiming{NextProbeAt: baseTime.Add(time.Hour)}
	up := &fakeUsage{u: healthyUsage()}
	e, _ := newTestEngine(t, st, up, &fakeRefresher{})

	if err := e.Tick(context.Background()); err != nil {
		t.Fatalf("err: %v", err)
	}
	if st.checkCount("due") != 1 {
		t.Fatalf("due account not probed: %d", st.checkCount("due"))
	}
	if st.checkCount("notdue") != 0 {
		t.Fatalf("not-due account probed: %d", st.checkCount("notdue"))
	}
	if st.checkCount("term") != 0 {
		t.Fatalf("terminal account probed: %d", st.checkCount("term"))
	}
}

func TestTickListError(t *testing.T) {
	st := newFakeStore()
	st.failList = true
	e, _ := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{})
	if err := e.Tick(context.Background()); err == nil {
		t.Fatal("expected list error")
	}
}

func TestTickContinuesOnTimingError(t *testing.T) {
	a := model.Account{ID: "a1", State: model.StateOK}
	st := newFakeStore(a)
	st.failTiming = true
	e, _ := newTestEngine(t, st, &fakeUsage{u: healthyUsage()}, &fakeRefresher{})
	// Timing load fails per-account; Tick should not error out.
	if err := e.Tick(context.Background()); err != nil {
		t.Fatalf("Tick should swallow per-account errors: %v", err)
	}
}

func TestTickContinuesOnProbeError(t *testing.T) {
	a := model.Account{ID: "a1", State: model.StateOK}
	st := newFakeStore(a)
	st.failRecordHC = true // ProbeAccount will error
	e, _ := newTestEngine(t, st, &fakeUsage{u: healthyUsage()}, &fakeRefresher{})
	if err := e.Tick(context.Background()); err != nil {
		t.Fatalf("Tick should swallow probe errors: %v", err)
	}
}

func TestNextDue(t *testing.T) {
	a := model.Account{ID: "a", State: model.StateOK}
	b := model.Account{ID: "b", State: model.StateOK}
	term := model.Account{ID: "t", State: model.StateRevoked}
	st := newFakeStore(a, b, term)
	st.timing["a"] = model.AccountTiming{NextProbeAt: baseTime.Add(10 * time.Minute)}
	st.timing["b"] = model.AccountTiming{NextProbeAt: baseTime.Add(3 * time.Minute)}
	e, _ := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{})

	next, ok, err := e.NextDue(context.Background())
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if !next.Equal(baseTime.Add(3 * time.Minute)) {
		t.Fatalf("next=%v want earliest (b)", next)
	}
}

func TestNextDueNeverScheduledIsNow(t *testing.T) {
	a := model.Account{ID: "a", State: model.StateUnknown}
	st := newFakeStore(a)
	e, clk := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{})
	next, ok, err := e.NextDue(context.Background())
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if !next.Equal(clk.now()) {
		t.Fatalf("next=%v want now", next)
	}
}

func TestNextDueNoneWhenAllTerminal(t *testing.T) {
	st := newFakeStore(model.Account{ID: "t", State: model.StateDead})
	e, _ := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{})
	_, ok, err := e.NextDue(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Fatal("expected no due account when all terminal")
	}
}

func TestNextDueListError(t *testing.T) {
	st := newFakeStore()
	st.failList = true
	e, _ := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{})
	if _, _, err := e.NextDue(context.Background()); err == nil {
		t.Fatal("expected list error")
	}
}

func TestRunTicksThenStopsOnCancel(t *testing.T) {
	a := model.Account{ID: "a1", State: model.StateOK}
	st := newFakeStore(a)
	up := &fakeUsage{u: healthyUsage()}
	clk := &fixedClock{t: baseTime}

	ctx, cancel := context.WithCancel(context.Background())
	iterations := 0
	// Deterministic sleep: advance the clock and cancel after 3 ticks.
	sleep := func(_ context.Context, d time.Duration) error {
		iterations++
		clk.add(d)
		if iterations >= 3 {
			cancel()
			return context.Canceled
		}
		return nil
	}
	e := New(st, up, &fakeRefresher{},
		WithClock(clk.now), WithSchedule(testSchedule()),
		WithRand(func() float64 { return 0 }), WithSleep(sleep))

	if err := e.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run err=%v want context.Canceled", err)
	}
	if iterations != 3 {
		t.Fatalf("iterations=%d want 3", iterations)
	}
	// First tick probed the account (subsequent ticks were not due yet).
	if up.seen == 0 {
		t.Fatal("Run never probed")
	}
}

func TestRunReturnsImmediatelyIfCancelled(t *testing.T) {
	st := newFakeStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e, _ := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{})
	if err := e.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run err=%v want context.Canceled", err)
	}
}

func TestRunTickErrorIsLoggedNotFatal(t *testing.T) {
	st := newFakeStore()
	st.failList = true // Tick returns an error each iteration
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	sleep := func(_ context.Context, _ time.Duration) error {
		calls++
		cancel()
		return context.Canceled
	}
	e, _ := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{}, WithSleep(sleep))
	if err := e.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run err=%v want context.Canceled", err)
	}
	if calls != 1 {
		t.Fatalf("sleep calls=%d want 1 (tick error must not abort loop)", calls)
	}
}

func TestRealSleepReturnsAfterDuration(t *testing.T) {
	if err := realSleep(context.Background(), time.Millisecond); err != nil {
		t.Fatalf("realSleep err: %v", err)
	}
	// Cancellation path.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := realSleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("realSleep cancel err=%v", err)
	}
	// Non-positive duration is clamped to a tiny sleep (no hang).
	if err := realSleep(context.Background(), 0); err != nil {
		t.Fatalf("realSleep(0) err: %v", err)
	}
}
