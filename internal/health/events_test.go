package health

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// errBoom is a generic failure used to drive the refresh-then-expire path.
var errBoom = errors.New("boom")

// recordSink captures emitted notification events for assertions.
type recordSink struct {
	mu     sync.Mutex
	events []model.NotifyEvent
}

func (r *recordSink) Emit(ev model.NotifyEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordSink) kinds() []model.NotifyEventKind {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]model.NotifyEventKind, len(r.events))
	for i, e := range r.events {
		out[i] = e.Kind
	}
	return out
}

func (r *recordSink) only(t *testing.T, want model.NotifyEventKind) model.NotifyEvent {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) != 1 {
		t.Fatalf("emitted %v, want exactly [%s]", kindsOf(r.events), want)
	}
	if r.events[0].Kind != want {
		t.Fatalf("emitted %s, want %s", r.events[0].Kind, want)
	}
	return r.events[0]
}

func kindsOf(evs []model.NotifyEvent) []model.NotifyEventKind {
	out := make([]model.NotifyEventKind, len(evs))
	for i, e := range evs {
		out[i] = e.Kind
	}
	return out
}

func acct(id, label string, state model.AccountState) model.Account {
	return model.Account{ID: id, Label: label, State: state, RefreshToken: "rt"}
}

func TestEmitOnRateLimited(t *testing.T) {
	sink := &recordSink{}
	st := newFakeStore(acct("a1", "prod-1", model.StateOK))
	e, _ := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{}, WithEventSink(sink))

	if err := e.OnRateLimited(context.Background(), acct("a1", "prod-1", model.StateOK), 30*time.Second); err != nil {
		t.Fatalf("OnRateLimited: %v", err)
	}
	ev := sink.only(t, model.EventAccountCooldown)
	if ev.AccountID != "a1" || ev.AccountLabel != "prod-1" || ev.Message == "" {
		t.Errorf("event fields = %+v", ev)
	}
}

func TestEmitOnQuotaExhausted(t *testing.T) {
	sink := &recordSink{}
	st := newFakeStore(acct("a1", "prod-1", model.StateOK))
	e, _ := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{}, WithEventSink(sink))

	if err := e.OnQuotaExhausted(context.Background(), acct("a1", "prod-1", model.StateOK), time.Time{}); err != nil {
		t.Fatalf("OnQuotaExhausted: %v", err)
	}
	sink.only(t, model.EventAccountQuotaExhausted)
}

func TestEmitOnExpired(t *testing.T) {
	sink := &recordSink{}
	st := newFakeStore(acct("a1", "prod-1", model.StateOK))
	// Refresher fails -> account moves to expired.
	rf := &fakeRefresher{err: errBoom}
	e, _ := newTestEngine(t, st, &fakeUsage{}, rf, WithEventSink(sink))

	_, _ = e.OnUnauthorized(context.Background(), acct("a1", "prod-1", model.StateOK))
	sink.only(t, model.EventAccountExpired)
}

func TestEmitRecovered(t *testing.T) {
	sink := &recordSink{}
	st := newFakeStore(acct("a1", "prod-1", model.StateCooldown))
	up := &fakeUsage{u: healthyUsage()}
	e, _ := newTestEngine(t, st, up, &fakeRefresher{}, WithEventSink(sink))

	if _, err := e.ProbeAccount(context.Background(), acct("a1", "prod-1", model.StateCooldown)); err != nil {
		t.Fatalf("ProbeAccount: %v", err)
	}
	sink.only(t, model.EventAccountRecovered)
}

func TestNoRecoveryFromUnknown(t *testing.T) {
	sink := &recordSink{}
	st := newFakeStore(acct("a1", "prod-1", model.StateUnknown))
	up := &fakeUsage{u: healthyUsage()}
	e, _ := newTestEngine(t, st, up, &fakeRefresher{}, WithEventSink(sink))

	if _, err := e.ProbeAccount(context.Background(), acct("a1", "prod-1", model.StateUnknown)); err != nil {
		t.Fatalf("ProbeAccount: %v", err)
	}
	if k := sink.kinds(); len(k) != 0 {
		t.Fatalf("unknown->ok should emit nothing, got %v", k)
	}
}

func TestEmitQuotaLow(t *testing.T) {
	sink := &recordSink{}
	st := newFakeStore(acct("a1", "prod-1", model.StateOK))
	// primary window at 90% used -> headroom 10 <= default threshold 15.
	up := &fakeUsage{u: model.Usage{PlanType: "plus", Windows: []model.UsageWindow{
		{Name: "primary", UsedPercent: 90, WindowSeconds: 18000},
	}}}
	e, _ := newTestEngine(t, st, up, &fakeRefresher{}, WithEventSink(sink))

	if _, err := e.ProbeAccount(context.Background(), acct("a1", "prod-1", model.StateOK)); err != nil {
		t.Fatalf("ProbeAccount: %v", err)
	}
	ev := sink.only(t, model.EventQuotaLow)
	if ev.Headroom != 10 {
		t.Errorf("Headroom = %v, want 10", ev.Headroom)
	}
}

func TestNoQuotaLowAboveThreshold(t *testing.T) {
	sink := &recordSink{}
	st := newFakeStore(acct("a1", "prod-1", model.StateOK))
	up := &fakeUsage{u: healthyUsage()} // 80% headroom -> no quota_low
	e, _ := newTestEngine(t, st, up, &fakeRefresher{}, WithEventSink(sink))

	if _, err := e.ProbeAccount(context.Background(), acct("a1", "prod-1", model.StateOK)); err != nil {
		t.Fatalf("ProbeAccount: %v", err)
	}
	if k := sink.kinds(); len(k) != 0 {
		t.Fatalf("healthy usage should emit nothing, got %v", k)
	}
}

func TestQuotaLowDisabledByThresholdZero(t *testing.T) {
	sink := &recordSink{}
	st := newFakeStore(acct("a1", "prod-1", model.StateOK))
	up := &fakeUsage{u: model.Usage{Windows: []model.UsageWindow{{Name: "primary", UsedPercent: 99, WindowSeconds: 18000}}}}
	e, _ := newTestEngine(t, st, up, &fakeRefresher{}, WithEventSink(sink), WithQuotaLowThreshold(0))

	if _, err := e.ProbeAccount(context.Background(), acct("a1", "prod-1", model.StateOK)); err != nil {
		t.Fatalf("ProbeAccount: %v", err)
	}
	if k := sink.kinds(); len(k) != 0 {
		t.Fatalf("threshold 0 disables quota_low, got %v", k)
	}
}

func TestNoSinkNoPanic(t *testing.T) {
	st := newFakeStore(acct("a1", "prod-1", model.StateOK))
	e, _ := newTestEngine(t, st, &fakeUsage{}, &fakeRefresher{}) // no sink
	if err := e.OnRateLimited(context.Background(), acct("a1", "prod-1", model.StateOK), 0); err != nil {
		t.Fatalf("OnRateLimited without sink: %v", err)
	}
}
