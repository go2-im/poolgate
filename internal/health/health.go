// Package health is poolgate's probe engine and per-account state machine
// (DESIGN.md §12). It keeps the pool's view of each account fresh — driving
// auto-recovery once a rate-limit/quota clears — and it holds the transient
// account-state transitions in ONE place so both real proxy traffic (passive
// hooks) and active probes flow through identical logic.
//
// # State machine
//
// States live on model.AccountState: transient ok / cooldown / quota_exhausted
// / expired / unknown, plus terminal revoked / dead which are NEVER probed or
// auto-recovered (§12 / §23.6). Transitions are produced by a single pure
// function (applyEvent) so every path — passive and active — is deterministic
// and unit-testable with an injected clock.
//
//   - Passive hooks (called by the gateway on real traffic):
//     OnUnauthorized (401 → refresh-then-expired), OnRateLimited (429 → cooldown
//     gated on Retry-After), OnQuotaExhausted (a usage window hit 0 → gated on
//     the window reset).
//   - Active probes (run by the scheduler): usage-poll (default, zero spend),
//     auth-check (GET {base}/models, zero spend), and small-live-request
//     (opt-in, minimal spend, budget-capped).
//
// # Single-flight refresh
//
// The engine NEVER implements its own token refresh. It calls the same
// oauth.Refresher the gateway hot path uses, so a probe-triggered refresh and a
// concurrent 401 for the same account coalesce into ONE HTTP refresh and one
// atomic rotation write (DESIGN.md §0 D6 / §19.3).
//
// # Scheduling
//
// Per-state intervals with exponential backoff + jitter to a cap. Auto-recovery
// of a cooled-down (429'd) or quota-exhausted account is GATED: a probe is never
// due before its CooldownUntil (derived from Retry-After / the window reset, or
// a conservative default) elapses. The decision logic (Due, applyEvent,
// backoffInterval, jitter) is pure; the scheduler loop (Run/Tick/NextDue) is
// thin and only orchestrates I/O.
package health

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"strconv"
	"sync"
	"time"

	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/policy"
	"github.com/go2-im/poolgate/internal/usage"
)

// ---- collaborators (interfaces so tests inject fakes) ---------------------

// Store is the persistence surface the engine needs. *store.Store satisfies it.
type Store interface {
	ListAccounts(ctx context.Context) ([]model.Account, error)
	GetAccountState(ctx context.Context, id string) (model.AccountState, error)
	GetAccountTiming(ctx context.Context, id string) (model.AccountTiming, error)
	SetAccountTiming(ctx context.Context, id string, t model.AccountTiming) error
	UpdateState(ctx context.Context, id string, state model.AccountState) error
	UpdateStateAndTiming(ctx context.Context, id string, state model.AccountState, t model.AccountTiming) error
	SaveUsageSnapshot(ctx context.Context, snap model.UsageSnapshot) (model.UsageSnapshot, error)
	RecordHealthCheck(ctx context.Context, hc model.HealthCheck) (model.HealthCheck, error)
	ListHealthChecks(ctx context.Context, accountID string, limit int) ([]model.HealthCheck, error)
}

// UsageProbe fetches generic usage windows (zero token spend). *usage.Client
// satisfies it.
type UsageProbe interface {
	Fetch(ctx context.Context, acct model.Account) (model.Usage, error)
}

// Refresher refreshes an account's tokens with per-account single-flight.
// *oauth.Refresher satisfies it — the engine reuses that ONE primitive so probe
// and hot-path refreshes coalesce (DESIGN.md §19.3).
type Refresher interface {
	RefreshAccount(ctx context.Context, acct model.Account) (model.Account, error)
}

// AuthProbe is the zero-spend auth check (GET {base}/models): ok=true for 200,
// ok=false for 401/403, err for anything else (DESIGN.md §0 D5). Optional; when
// nil, expired accounts are re-checked via a usage poll instead.
type AuthProbe interface {
	Check(ctx context.Context, acct model.Account) (ok bool, detail string, err error)
}

// LiveProbe is the opt-in small-live-request (minimal spend). retryAfter > 0
// signals an upstream 429 so the engine can cooldown-gate. Optional; when nil,
// live probing is disabled regardless of AllowLive.
type LiveProbe interface {
	Live(ctx context.Context, acct model.Account) (ok bool, retryAfter time.Duration, detail string, err error)
}

// EventSink receives the secret-free notification events the engine emits on
// account-state transitions and quota-low observations (DESIGN.md §11 / §12).
// *notify.Engine satisfies it. It is optional: when nil, no events are emitted.
// Emit MUST be non-blocking (the notify engine queues) so state transitions are
// never stalled by notification I/O.
type EventSink interface {
	Emit(ev model.NotifyEvent)
}

// SleepFunc waits for d or until ctx is cancelled; it returns ctx.Err() on
// cancellation. Injected so Run is testable without wall-clock sleeps.
type SleepFunc func(ctx context.Context, d time.Duration) error

// ---- scheduling config ----------------------------------------------------

// Schedule holds the per-state probe cadences and backoff/jitter parameters.
// The zero value is not useful; use DefaultSchedule and override as needed.
type Schedule struct {
	OK              time.Duration // usage-poll cadence for healthy accounts
	Degraded        time.Duration // base re-probe interval for cooldown/quota_exhausted (before backoff)
	Expired         time.Duration // rare re-check cadence for expired accounts
	Unknown         time.Duration // probe-soon cadence for freshly-seen accounts
	BackoffCap      time.Duration // maximum interval after exponential backoff
	DefaultCooldown time.Duration // conservative cooldown when no Retry-After / reset is known
	PollInterval    time.Duration // scheduler loop tick period (Run)
	JitterFrac      float64       // additive jitter as a fraction of the interval, in [0,1)
	MaxBackoffLevel int           // cap on the backoff level counter
	LiveBudget      int           // max small-live-requests per account per rolling 24h
}

// DefaultQuotaLowThreshold is the default headroom percentage at/below which the
// engine emits a quota_low notification event (DESIGN.md §11) while an account is
// still routable.
const DefaultQuotaLowThreshold = 15.0

// DefaultSchedule returns sane, conservative defaults (usage-poll-only cadence;
// live probing stays opt-in via AllowLive + a LiveProbe).
func DefaultSchedule() Schedule {
	return Schedule{
		OK:              15 * time.Minute,
		Degraded:        1 * time.Minute,
		Expired:         30 * time.Minute,
		Unknown:         30 * time.Second,
		BackoffCap:      30 * time.Minute,
		DefaultCooldown: 60 * time.Second,
		PollInterval:    30 * time.Second,
		JitterFrac:      0.2,
		MaxBackoffLevel: 10,
		LiveBudget:      5,
	}
}

// ---- engine ---------------------------------------------------------------

// Engine runs probes and owns account-state transitions. It is safe to share:
// the pure decision logic holds no mutable state and refresh coalescing lives in
// the injected Refresher.
type Engine struct {
	store     Store
	usage     UsageProbe
	refresher Refresher
	auth      AuthProbe
	live      LiveProbe

	sched     Schedule
	allowLive bool // global mode switch; false = usage-poll-only (the default)

	events         EventSink // optional notification sink (DESIGN.md §11)
	quotaLowPct    float64   // headroom% at/below which a quota_low event is emitted

	now    func() time.Time
	rnd    func() float64
	sleep  SleepFunc
	logger *slog.Logger

	// clock-skew telemetry (DESIGN.md §21.4): the most recent host↔upstream skew
	// measured from a usage poll, guarded for concurrent read by the admin status
	// endpoint. skewWarn is the |skew| above which a warning is logged.
	skewMu   sync.Mutex
	skew     time.Duration
	skewAt   time.Time
	haveSkew bool
	skewWarn time.Duration

	// acctLocks serializes the read-modify-write of state+timing per account so a
	// slow active probe cannot overwrite a fresher passive transition (a lost
	// update that could clear a live Retry-After gate). Each transition re-reads
	// the authoritative state+timing under this lock before applying its event.
	acctLocksMu sync.Mutex
	acctLocks   map[string]*sync.Mutex
}

// lockAccount returns the per-account mutex, locked. The caller must call the
// returned unlock function.
func (e *Engine) lockAccount(id string) func() {
	e.acctLocksMu.Lock()
	if e.acctLocks == nil {
		e.acctLocks = make(map[string]*sync.Mutex)
	}
	m, ok := e.acctLocks[id]
	if !ok {
		m = &sync.Mutex{}
		e.acctLocks[id] = m
	}
	e.acctLocksMu.Unlock()
	m.Lock()
	return m.Unlock
}

// Option customizes an Engine.
type Option func(*Engine)

// WithClock injects the clock (default time.Now). Tests pass a fake for
// determinism.
func WithClock(now func() time.Time) Option { return func(e *Engine) { e.now = now } }

// WithRand injects the jitter source returning a value in [0,1) (default
// math/rand/v2). Tests pass a fixed value to bound jitter deterministically.
func WithRand(fn func() float64) Option { return func(e *Engine) { e.rnd = fn } }

// WithSchedule overrides the scheduling parameters.
func WithSchedule(s Schedule) Option { return func(e *Engine) { e.sched = s } }

// WithAuthProbe sets the zero-spend auth-check prober.
func WithAuthProbe(p AuthProbe) Option { return func(e *Engine) { e.auth = p } }

// WithLiveProbe sets the opt-in small-live-request prober.
func WithLiveProbe(p LiveProbe) Option { return func(e *Engine) { e.live = p } }

// WithAllowLive enables live probing of degraded accounts (still bounded by the
// per-account daily budget and requires a LiveProbe). Default false.
func WithAllowLive(v bool) Option { return func(e *Engine) { e.allowLive = v } }

// WithEventSink wires the notification sink (DESIGN.md §11). When set, the engine
// emits secret-free events on account-state transitions (expired / cooldown /
// quota_exhausted / recovered) and on quota-low observations.
func WithEventSink(s EventSink) Option { return func(e *Engine) { e.events = s } }

// WithQuotaLowThreshold sets the headroom percentage at/below which a quota_low
// event is emitted (while the account is still routable). Default 15; a value <=0
// disables quota_low emission.
func WithQuotaLowThreshold(pct float64) Option { return func(e *Engine) { e.quotaLowPct = pct } }

// WithSleep injects the sleep primitive used by Run (default a real timer).
func WithSleep(fn SleepFunc) Option { return func(e *Engine) { e.sleep = fn } }

// WithLogger sets the structured logger.
func WithLogger(l *slog.Logger) Option { return func(e *Engine) { e.logger = l } }

// DefaultClockSkewWarn is the |host↔upstream skew| above which the engine logs a
// warning (DESIGN.md §21.4). Small skews are normal; a large one indicates the
// host clock has drifted from the upstream usage endpoint (fix NTP).
const DefaultClockSkewWarn = 2 * time.Minute

// WithClockSkewWarn overrides the |skew| warning threshold. A value <= 0 disables
// the warning log (the skew is still measured and exposed via ClockSkew).
func WithClockSkewWarn(d time.Duration) Option { return func(e *Engine) { e.skewWarn = d } }

// New builds an Engine over st using the usage prober and the shared refresher.
func New(st Store, up UsageProbe, rf Refresher, opts ...Option) *Engine {
	e := &Engine{
		store:       st,
		usage:       up,
		refresher:   rf,
		sched:       DefaultSchedule(),
		quotaLowPct: DefaultQuotaLowThreshold,
		now:         time.Now,
		rnd:         rand.Float64,
		sleep:       realSleep,
		logger:      slog.Default(),
		skewWarn:    DefaultClockSkewWarn,
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// ---- pure state machine ---------------------------------------------------

// eventKind enumerates the inputs to the state machine. All transitions — both
// passive (real traffic) and active (probe results) — reduce to one of these.
type eventKind int

const (
	evProbeHealthy  eventKind = iota // usage ok with headroom, or auth/live ok → recover to ok
	evRefreshed                      // 401 → refresh succeeded → ok
	evQuotaZero                      // a usage window hit 0 headroom → quota_exhausted
	evRateLimited                    // 429 → cooldown, gated on Retry-After
	evExpired                        // 401 → refresh failed → expired
	evProbeSoftFail                  // transient probe/transport error → keep state, back off
)

// eventParams carries the timing inputs an event needs.
type eventParams struct {
	now        time.Time
	retryAfter time.Duration // evRateLimited: upstream Retry-After
	resetAt    time.Time     // evQuotaZero: when the exhausted window resets
}

// Transition is the pure result of applying an event: the next state and the
// next per-account timing/backoff record.
type Transition struct {
	State  model.AccountState
	Timing model.AccountTiming
}

// applyEvent is the single, pure transition function. Terminal accounts never
// change. It preserves fields it does not own (e.g. ConcurrencyCap).
func (e *Engine) applyEvent(state model.AccountState, t model.AccountTiming, ev eventKind, p eventParams) Transition {
	if state.Terminal() {
		return Transition{State: state, Timing: t}
	}
	switch ev {
	case evProbeHealthy, evRefreshed:
		// A probe reporting healthy must not clear a cooldown/quota gate that a
		// more-authoritative live 429/5xx set and that has not yet elapsed (e.g. a
		// usage poll that began before the 429 landed, then re-read the fresh
		// cooldown under the lock). Keep the gated state; only reschedule. Refresh
		// (401 recovery) is exempt: an expired account carries no cooldown gate.
		if ev == evProbeHealthy && degraded(state) && t.CooldownUntil.After(p.now) {
			t.NextProbeAt = e.gatedNext(state, t, p.now, t.CooldownUntil)
			return Transition{State: state, Timing: t}
		}
		t.ConsecutiveFailures = 0
		t.BackoffLevel = 0
		t.CooldownUntil = time.Time{}
		t.NextProbeAt = e.scheduleFor(model.StateOK, t, p.now)
		return Transition{State: model.StateOK, Timing: t}

	case evRateLimited:
		ra := p.retryAfter
		if ra <= 0 {
			ra = e.sched.DefaultCooldown
		}
		t.ConsecutiveFailures++
		t.BackoffLevel = clampLevel(t.BackoffLevel+1, e.sched.MaxBackoffLevel)
		t.CooldownUntil = p.now.Add(ra)
		t.NextProbeAt = e.gatedNext(model.StateCooldown, t, p.now, t.CooldownUntil)
		return Transition{State: model.StateCooldown, Timing: t}

	case evQuotaZero:
		until := p.resetAt
		if !until.After(p.now) {
			until = p.now.Add(e.sched.DefaultCooldown)
		}
		t.ConsecutiveFailures++
		t.BackoffLevel = clampLevel(t.BackoffLevel+1, e.sched.MaxBackoffLevel)
		t.CooldownUntil = until
		t.NextProbeAt = e.gatedNext(model.StateQuotaExhausted, t, p.now, until)
		return Transition{State: model.StateQuotaExhausted, Timing: t}

	case evExpired:
		t.ConsecutiveFailures++
		t.CooldownUntil = time.Time{}
		t.NextProbeAt = e.scheduleFor(model.StateExpired, t, p.now)
		return Transition{State: model.StateExpired, Timing: t}

	case evProbeSoftFail:
		// Keep the current state (a transient error must not flap an ok account),
		// but grow the backoff and reschedule — still honoring any cooldown gate.
		t.ConsecutiveFailures++
		t.BackoffLevel = clampLevel(t.BackoffLevel+1, e.sched.MaxBackoffLevel)
		t.NextProbeAt = e.gatedNext(state, t, p.now, t.CooldownUntil)
		return Transition{State: state, Timing: t}

	default:
		return Transition{State: state, Timing: t}
	}
}

// scheduleFor computes the next probe time for a state: now + a jittered
// per-state interval (with backoff for degraded states).
func (e *Engine) scheduleFor(state model.AccountState, t model.AccountTiming, now time.Time) time.Time {
	return now.Add(e.jittered(e.baseInterval(state, t.BackoffLevel)))
}

// gatedNext is scheduleFor clamped so the result is never before the gate
// (Retry-After / window reset). This is the auto-recovery gate: a cooled-down or
// quota-exhausted account is never probed before its cooldown elapses. When the
// gate dominates, a jittered spread is added on TOP of the gate so a fleet of
// accounts sharing one Retry-After do not all re-probe (and potentially re-storm
// the upstream) at the exact same instant.
func (e *Engine) gatedNext(state model.AccountState, t model.AccountTiming, now, gate time.Time) time.Time {
	n := e.scheduleFor(state, t, now)
	if gate.After(n) {
		return gate.Add(e.jitterSpread(e.baseInterval(state, t.BackoffLevel)))
	}
	return n
}

// jitterSpread returns just the jitter component (0..JitterFrac*d) of jittered,
// used to spread accounts that would otherwise release from a shared gate in
// lockstep.
func (e *Engine) jitterSpread(d time.Duration) time.Duration {
	return e.jittered(d) - d
}

// baseInterval is the (pre-jitter) interval for a state and backoff level.
func (e *Engine) baseInterval(state model.AccountState, level int) time.Duration {
	switch state {
	case model.StateOK:
		return e.sched.OK
	case model.StateUnknown:
		return e.sched.Unknown
	case model.StateExpired:
		return e.sched.Expired
	case model.StateCooldown, model.StateQuotaExhausted:
		return backoffInterval(e.sched.Degraded, level, e.sched.BackoffCap)
	default:
		return e.sched.OK
	}
}

// jittered adds up to JitterFrac*d of positive jitter, bounded to [d, d*(1+frac)).
func (e *Engine) jittered(d time.Duration) time.Duration {
	if e.sched.JitterFrac <= 0 || d <= 0 {
		return d
	}
	f := e.rnd()
	if f < 0 {
		f = 0
	}
	if f >= 1 {
		f = 0.9999999
	}
	return d + time.Duration(f*e.sched.JitterFrac*float64(d))
}

// backoffInterval doubles base once per level, capped at cap (and guarded
// against overflow). level 0 returns base (capped).
func backoffInterval(base time.Duration, level int, cap time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	d := base
	for i := 0; i < level; i++ {
		d *= 2
		if d <= 0 || d >= cap { // overflow or reached the cap
			return cap
		}
	}
	if d > cap {
		return cap
	}
	return d
}

func clampLevel(level, max int) int {
	if max > 0 && level > max {
		return max
	}
	return level
}

// Due reports whether an account is due for a probe now. It is pure: terminal
// accounts are never due; the cooldown gate blocks early re-probes; a never-yet
// scheduled account (zero NextProbeAt) is due immediately.
func Due(now time.Time, state model.AccountState, t model.AccountTiming) bool {
	if state.Terminal() {
		return false
	}
	if !t.CooldownUntil.IsZero() && now.Before(t.CooldownUntil) {
		return false
	}
	if t.NextProbeAt.IsZero() {
		return true
	}
	return !now.Before(t.NextProbeAt)
}

// ---- passive hooks (called by the gateway on real traffic) ----------------

// OnUnauthorized handles a real-traffic 401: it refreshes via the shared
// single-flight Refresher, moving the account to ok on success (returning the
// refreshed account so the caller can retry) or to expired on failure.
func (e *Engine) OnUnauthorized(ctx context.Context, acct model.Account) (model.Account, error) {
	unlock := e.lockAccount(acct.ID)
	defer unlock()
	curState, t, err := e.readCurrent(ctx, acct)
	if err != nil {
		return acct, err
	}
	refreshed, rerr := e.refresher.RefreshAccount(ctx, acct)
	now := e.now()
	if rerr != nil {
		tr := e.applyEvent(curState, t, evExpired, eventParams{now: now})
		_ = e.persist(ctx, acct, curState, tr)
		return acct, rerr
	}
	tr := e.applyEvent(curState, t, evRefreshed, eventParams{now: now})
	if err := e.persist(ctx, acct, curState, tr); err != nil {
		return refreshed, err
	}
	return refreshed, nil
}

// OnRateLimited handles a real-traffic 429: cooldown gated on retryAfter (a
// conservative default is used when retryAfter <= 0).
func (e *Engine) OnRateLimited(ctx context.Context, acct model.Account, retryAfter time.Duration) error {
	unlock := e.lockAccount(acct.ID)
	defer unlock()
	curState, t, err := e.readCurrent(ctx, acct)
	if err != nil {
		return err
	}
	tr := e.applyEvent(curState, t, evRateLimited, eventParams{now: e.now(), retryAfter: retryAfter})
	return e.persist(ctx, acct, curState, tr)
}

// OnQuotaExhausted handles a real-traffic quota=0 signal: quota_exhausted gated
// on resetAt (a conservative default is used when resetAt is unknown/past).
func (e *Engine) OnQuotaExhausted(ctx context.Context, acct model.Account, resetAt time.Time) error {
	unlock := e.lockAccount(acct.ID)
	defer unlock()
	curState, t, err := e.readCurrent(ctx, acct)
	if err != nil {
		return err
	}
	tr := e.applyEvent(curState, t, evQuotaZero, eventParams{now: e.now(), resetAt: resetAt})
	return e.persist(ctx, acct, curState, tr)
}

// readCurrent re-reads the authoritative state+timing for acct. Callers hold the
// per-account lock so the values cannot change before they persist a transition.
func (e *Engine) readCurrent(ctx context.Context, acct model.Account) (model.AccountState, model.AccountTiming, error) {
	state, err := e.store.GetAccountState(ctx, acct.ID)
	if err != nil {
		return "", model.AccountTiming{}, err
	}
	t, err := e.store.GetAccountTiming(ctx, acct.ID)
	if err != nil {
		return "", model.AccountTiming{}, err
	}
	return state, t, nil
}

func (e *Engine) persist(ctx context.Context, acct model.Account, oldState model.AccountState, tr Transition) error {
	if err := e.store.UpdateStateAndTiming(ctx, acct.ID, tr.State, tr.Timing); err != nil {
		return err
	}
	e.emitTransition(acct, oldState, tr.State)
	return nil
}

// emitTransition emits a secret-free notification event when an account changes
// state (DESIGN.md §11). It references the account by id/label only. A recovery
// is reported only when the previous state was degraded/expired.
func (e *Engine) emitTransition(acct model.Account, oldState, newState model.AccountState) {
	if e.events == nil || oldState == newState {
		return
	}
	var kind model.NotifyEventKind
	switch newState {
	case model.StateExpired:
		kind = model.EventAccountExpired
	case model.StateCooldown:
		kind = model.EventAccountCooldown
	case model.StateQuotaExhausted:
		kind = model.EventAccountQuotaExhausted
	case model.StateOK:
		if oldState != model.StateCooldown && oldState != model.StateQuotaExhausted && oldState != model.StateExpired {
			return // e.g. unknown -> ok on first probe is not a "recovery"
		}
		kind = model.EventAccountRecovered
	default:
		return
	}
	e.events.Emit(model.NotifyEvent{
		Kind:         kind,
		AccountID:    acct.ID,
		AccountLabel: acct.Label,
		Message:      transitionMessage(kind, acct),
		At:           e.now(),
	})
}

// formatPct renders a headroom percentage like "12.3%".
func formatPct(v float64) string {
	return strconv.FormatFloat(v, 'f', 1, 64) + "%"
}

// transitionMessage builds a short, secret-free human summary for a transition.
func transitionMessage(kind model.NotifyEventKind, acct model.Account) string {
	name := acct.Label
	if name == "" {
		name = acct.ID
	}
	switch kind {
	case model.EventAccountExpired:
		return "poolgate: account " + name + " expired (token invalid, refresh failed)"
	case model.EventAccountCooldown:
		return "poolgate: account " + name + " entered cooldown (repeated 429/5xx)"
	case model.EventAccountQuotaExhausted:
		return "poolgate: account " + name + " exhausted its quota"
	case model.EventAccountRecovered:
		return "poolgate: account " + name + " recovered and is back in rotation"
	default:
		return "poolgate: account " + name + " changed state"
	}
}

// ---- active probing --------------------------------------------------------

// ProbeAccount runs one probe for acct (kind chosen by selectProbeKind), applies
// the resulting transition, and records state + timing + history. Terminal
// accounts are skipped (no probe, no error). The recorded HealthCheck is
// returned for observability/tests.
func (e *Engine) ProbeAccount(ctx context.Context, acct model.Account) (model.HealthCheck, error) {
	if acct.State.Terminal() {
		return model.HealthCheck{}, nil
	}

	kind := e.selectProbeKind(ctx, acct)
	start := e.now()

	var (
		ev         eventKind
		retryAfter time.Duration
		resetAt    time.Time
		ok         bool
		detail     string
	)
	switch kind {
	case model.HealthKindAuthCheck:
		ev, retryAfter, resetAt, ok, detail = e.runAuthCheck(ctx, acct)
	case model.HealthKindLiveRequest:
		ev, retryAfter, resetAt, ok, detail = e.runLive(ctx, acct)
	default:
		kind = model.HealthKindUsagePoll
		ev, retryAfter, resetAt, ok, detail = e.runUsagePoll(ctx, acct)
	}

	now := e.now()
	// Serialize the state write against passive hooks and re-read the
	// authoritative state+timing: the probe above may have raced a live 429/quota
	// transition. Applying against the fresh state (and honoring an unexpired
	// cooldown gate in applyEvent) prevents a stale "healthy" probe from clearing
	// a live Retry-After.
	unlock := e.lockAccount(acct.ID)
	curState, t, rerr := e.readCurrent(ctx, acct)
	if rerr != nil {
		unlock()
		return model.HealthCheck{}, rerr
	}
	tr := e.applyEvent(curState, t, ev, eventParams{now: now, retryAfter: retryAfter, resetAt: resetAt})
	perr := e.persist(ctx, acct, curState, tr)
	unlock()
	if perr != nil {
		return model.HealthCheck{}, perr
	}

	return e.store.RecordHealthCheck(ctx, model.HealthCheck{
		AccountID: acct.ID,
		Kind:      kind,
		OK:        ok,
		Detail:    detail,
		LatencyMS: int(now.Sub(start) / time.Millisecond),
		At:        now,
	})
}

// selectProbeKind picks the cheapest probe that answers the current question:
// expired accounts get the zero-spend auth-check (has the token become valid
// again?); degraded accounts get a live request only when live probing is
// enabled and the daily budget allows; everything else gets the default
// zero-spend usage poll.
func (e *Engine) selectProbeKind(ctx context.Context, acct model.Account) model.HealthCheckKind {
	if acct.State == model.StateExpired && e.auth != nil {
		return model.HealthKindAuthCheck
	}
	if e.allowLive && e.live != nil && degraded(acct.State) && e.canLiveProbe(ctx, acct.ID) {
		return model.HealthKindLiveRequest
	}
	return model.HealthKindUsagePoll
}

func degraded(s model.AccountState) bool {
	return s == model.StateCooldown || s == model.StateQuotaExhausted
}

// canLiveProbe enforces the per-account rolling-24h live-probe budget.
func (e *Engine) canLiveProbe(ctx context.Context, id string) bool {
	if e.sched.LiveBudget <= 0 {
		return false
	}
	hist, err := e.store.ListHealthChecks(ctx, id, 500)
	if err != nil {
		return false
	}
	return countLiveSince(hist, e.now().Add(-24*time.Hour)) < e.sched.LiveBudget
}

func countLiveSince(hist []model.HealthCheck, since time.Time) int {
	n := 0
	for _, h := range hist {
		if h.Kind == model.HealthKindLiveRequest && h.At.After(since) {
			n++
		}
	}
	return n
}

// runUsagePoll performs the default zero-spend usage poll and maps it to an
// event. A 401 routes through the shared refresher (refresh-then-expired). A
// success persists a usage snapshot and yields recover/quota-zero based on the
// min headroom across windows.
func (e *Engine) runUsagePoll(ctx context.Context, acct model.Account) (eventKind, time.Duration, time.Time, bool, string) {
	u, err := e.usage.Fetch(ctx, acct)
	if err != nil {
		if errors.Is(err, usage.ErrTokenInvalid) {
			return e.refreshOrExpire(ctx, acct)
		}
		return evProbeSoftFail, 0, time.Time{}, false, "usage poll error: " + err.Error()
	}
	_, _ = e.store.SaveUsageSnapshot(ctx, model.UsageSnapshot{
		AccountID:  acct.ID,
		PlanType:   u.PlanType,
		Windows:    u.Windows,
		CapturedAt: e.now(),
	})
	if u.ClockSkewValid {
		e.recordSkew(u.ClockSkew)
	}
	h := policy.MinHeadroom(u)
	if h <= 0 {
		return evQuotaZero, 0, bindingReset(u), false, "quota exhausted"
	}
	e.emitQuotaLow(acct, h)
	return evProbeHealthy, 0, time.Time{}, true, "usage ok"
}

// emitQuotaLow emits a secret-free quota_low event when a still-routable account's
// remaining headroom is at/below the configured threshold (DESIGN.md §11 / §24.2).
// The notify engine's per-channel dedup suppresses repeats across polls.
func (e *Engine) emitQuotaLow(acct model.Account, headroom float64) {
	if e.events == nil || e.quotaLowPct <= 0 || headroom > e.quotaLowPct {
		return
	}
	name := acct.Label
	if name == "" {
		name = acct.ID
	}
	e.events.Emit(model.NotifyEvent{
		Kind:         model.EventQuotaLow,
		AccountID:    acct.ID,
		AccountLabel: acct.Label,
		Headroom:     headroom,
		Message:      "poolgate: account " + name + " is low on quota (headroom " + formatPct(headroom) + ")",
		At:           e.now(),
	})
}

// runAuthCheck performs the zero-spend GET {base}/models auth check. ok → the
// token is valid again (recover); not-ok (401/403) → refresh-then-expired; error
// → soft fail.
func (e *Engine) runAuthCheck(ctx context.Context, acct model.Account) (eventKind, time.Duration, time.Time, bool, string) {
	ok, detail, err := e.auth.Check(ctx, acct)
	if err != nil {
		return evProbeSoftFail, 0, time.Time{}, false, "auth check error: " + err.Error()
	}
	if ok {
		return evProbeHealthy, 0, time.Time{}, true, detail
	}
	return e.refreshOrExpire(ctx, acct)
}

// runLive performs the opt-in small-live-request. ok → serving (recover); a 429
// (retryAfter > 0) → cooldown; any other failure → soft fail (stay degraded).
func (e *Engine) runLive(ctx context.Context, acct model.Account) (eventKind, time.Duration, time.Time, bool, string) {
	ok, retryAfter, detail, err := e.live.Live(ctx, acct)
	if err != nil {
		return evProbeSoftFail, 0, time.Time{}, false, "live probe error: " + err.Error()
	}
	if ok {
		return evProbeHealthy, 0, time.Time{}, true, detail
	}
	if retryAfter > 0 {
		return evRateLimited, retryAfter, time.Time{}, false, detail
	}
	return evProbeSoftFail, 0, time.Time{}, false, detail
}

// refreshOrExpire routes a 401 through the shared single-flight refresher.
func (e *Engine) refreshOrExpire(ctx context.Context, acct model.Account) (eventKind, time.Duration, time.Time, bool, string) {
	if _, err := e.refresher.RefreshAccount(ctx, acct); err != nil {
		return evExpired, 0, time.Time{}, false, "refresh failed: " + err.Error()
	}
	return evRefreshed, 0, time.Time{}, true, "refreshed after 401"
}

// bindingReset returns the earliest future reset among the exhausted (headroom
// <= 0) windows — the window whose reset gates recovery. Zero if unknown.
func bindingReset(u model.Usage) time.Time {
	var t time.Time
	for _, w := range u.Windows {
		if w.Headroom() <= 0 && !w.ResetsAt.IsZero() {
			if t.IsZero() || w.ResetsAt.Before(t) {
				t = w.ResetsAt
			}
		}
	}
	return t
}

// recordSkew stores the latest measured host↔upstream clock skew (DESIGN.md
// §21.4) and logs a warning when its magnitude exceeds the configured threshold.
// Usage windows are anchored to the upstream absolute reset_at; this skew is the
// monitoring signal that surfaces host-clock drift against that anchor.
func (e *Engine) recordSkew(skew time.Duration) {
	e.skewMu.Lock()
	e.skew, e.skewAt, e.haveSkew = skew, e.now(), true
	e.skewMu.Unlock()

	if e.skewWarn > 0 && (skew > e.skewWarn || skew < -e.skewWarn) {
		e.logger.Warn("clock skew vs upstream usage endpoint exceeds threshold",
			slog.Duration("skew", skew), slog.Duration("threshold", e.skewWarn))
	}
}

// ClockSkew returns the most recently measured host↔upstream clock skew
// (host_now − upstream_now), the time it was measured, and whether any
// measurement has been recorded yet. It is safe for concurrent use.
func (e *Engine) ClockSkew() (skew time.Duration, at time.Time, ok bool) {
	e.skewMu.Lock()
	defer e.skewMu.Unlock()
	return e.skew, e.skewAt, e.haveSkew
}

// ---- scheduler loop (thin) -------------------------------------------------

// Tick probes every non-terminal account that is Due now. Per-account errors are
// logged and do not abort the sweep.
func (e *Engine) Tick(ctx context.Context) error {
	accts, err := e.store.ListAccounts(ctx)
	if err != nil {
		return err
	}
	now := e.now()
	for _, a := range accts {
		if a.State.Terminal() {
			continue
		}
		t, err := e.store.GetAccountTiming(ctx, a.ID)
		if err != nil {
			e.logger.Warn("health: load timing failed", slog.String("account", a.ID), slog.Any("err", err))
			continue
		}
		if !Due(now, a.State, t) {
			continue
		}
		if _, err := e.ProbeAccount(ctx, a); err != nil {
			e.logger.Warn("health: probe failed", slog.String("account", a.ID), slog.Any("err", err))
		}
	}
	return nil
}

// NextDue returns the earliest time any non-terminal account is next due, and
// whether one exists. A never-yet-scheduled account counts as due now. Callers
// may use it to sleep adaptively; Run itself uses a fixed poll.
func (e *Engine) NextDue(ctx context.Context) (time.Time, bool, error) {
	accts, err := e.store.ListAccounts(ctx)
	if err != nil {
		return time.Time{}, false, err
	}
	now := e.now()
	var earliest time.Time
	found := false
	for _, a := range accts {
		if a.State.Terminal() {
			continue
		}
		t, err := e.store.GetAccountTiming(ctx, a.ID)
		if err != nil {
			continue
		}
		due := t.NextProbeAt
		if due.IsZero() {
			due = now
		}
		if !found || due.Before(earliest) {
			earliest = due
			found = true
		}
	}
	return earliest, found, nil
}

// Run is the thin scheduler loop: Tick, then sleep PollInterval, until ctx is
// cancelled (whereupon ctx.Err() is returned). All decision logic lives in the
// pure helpers above; Run only orchestrates.
func (e *Engine) Run(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := e.Tick(ctx); err != nil {
			e.logger.Warn("health: tick failed", slog.Any("err", err))
		}
		if err := e.sleep(ctx, e.sched.PollInterval); err != nil {
			return err
		}
	}
}

// realSleep waits d or until ctx is cancelled.
func realSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		d = time.Millisecond
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
