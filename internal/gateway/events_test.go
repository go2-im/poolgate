package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// recordSink captures emitted notification events.
type recordSink struct {
	mu     sync.Mutex
	events []model.NotifyEvent
}

func (r *recordSink) Emit(ev model.NotifyEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordSink) snapshot() []model.NotifyEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]model.NotifyEvent, len(r.events))
	copy(out, r.events)
	return out
}

func TestEmitNoHealthyMemberOn503(t *testing.T) {
	f := newFixture(t)
	// Force the only member out of rotation so the group has no healthy account.
	if err := f.st.UpdateState(context.Background(), f.acct.ID, model.StateExpired); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}
	sink := &recordSink{}
	gw := New(f.st, f.cfg, WithEventSink(sink))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/default/v1/responses",
		strings.NewReader(`{"model":"gpt-5"}`))
	req.Header.Set("Authorization", "Bearer "+f.apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}

	evs := sink.snapshot()
	if len(evs) != 1 {
		t.Fatalf("emitted %d events, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Kind != model.EventPolicyNoHealthyMember {
		t.Errorf("kind = %s, want policy_no_healthy_member", ev.Kind)
	}
	if ev.Endpoint != "default" || ev.PolicyGroup != "default" {
		t.Errorf("event endpoint/group = %q/%q, want default/default", ev.Endpoint, ev.PolicyGroup)
	}
	if ev.AccountID != "" || strings.Contains(ev.Message, f.apiKey) {
		t.Errorf("event must carry no account id / no secret: %+v", ev)
	}
}

func TestNoSinkNoHealthyMember(t *testing.T) {
	f := newFixture(t)
	if err := f.st.UpdateState(context.Background(), f.acct.ID, model.StateExpired); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}
	// No event sink wired: must not panic and still return 503.
	gw := New(f.st, f.cfg)
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/default/v1/responses",
		strings.NewReader(`{"model":"gpt-5"}`))
	req.Header.Set("Authorization", "Bearer "+f.apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestFailWindowSlidingCatchesBoundaryStraddle(t *testing.T) {
	// Threshold 3 within 60s. Two failures late in one notional window and one
	// just after a fixed-window boundary are within 60s of each other, so a true
	// sliding window must fire (a tumbling window would have reset and missed it).
	fw := newFailWindow(3, time.Minute)
	base := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	now := base
	fw.now = func() time.Time { return now }

	now = base.Add(58 * time.Second)
	if fw.record() {
		t.Fatal("1st failure should not fire")
	}
	now = base.Add(59 * time.Second)
	if fw.record() {
		t.Fatal("2nd failure should not fire")
	}
	now = base.Add(61 * time.Second) // past a 60s tumbling boundary, still within 60s of the 1st two
	if !fw.record() {
		t.Fatal("3rd failure within the trailing 60s window should fire (sliding window)")
	}

	// Genuinely spread-out failures do NOT fire: advance well past the window.
	fw2 := newFailWindow(3, time.Minute)
	n2 := base
	fw2.now = func() time.Time { return n2 }
	fw2.record()
	n2 = base.Add(30 * time.Second)
	fw2.record()
	n2 = base.Add(200 * time.Second) // first two aged out
	if fw2.record() {
		t.Fatal("failures spread beyond the window should not fire")
	}
}

func TestFailWindowFiresOnceAtThreshold(t *testing.T) {
	fw := newFailWindow(3, time.Minute)
	base := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	fw.now = func() time.Time { return base }
	got := []bool{fw.record(), fw.record(), fw.record(), fw.record()}
	want := []bool{false, false, true, false} // fires exactly at the 3rd
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("record #%d = %v, want %v (seq %v)", i+1, got[i], want[i], got)
		}
	}
	// A new window resets the counter.
	fw.now = func() time.Time { return base.Add(2 * time.Minute) }
	if fw.record() {
		t.Error("first record in a fresh window should not fire")
	}
}

func TestEmitAuthAnomalyOnRepeatedInvalidKeys(t *testing.T) {
	f := newFixture(t)
	sink := &recordSink{}
	gw := New(f.st, f.cfg, WithEventSink(sink))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	// Fire threshold invalid-key requests; exactly one auth_anomaly must emit.
	for i := 0; i < authAnomalyThreshold; i++ {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/default/v1/responses",
			strings.NewReader(`{"model":"gpt-5"}`))
		req.Header.Set("Authorization", "Bearer sk-wrong")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("req %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("req %d status = %d, want 401", i, resp.StatusCode)
		}
	}
	var anomalies int
	for _, e := range sink.snapshot() {
		if e.Kind == model.EventAuthAnomaly {
			anomalies++
			if strings.Contains(e.Message, "sk-") {
				t.Errorf("auth_anomaly message leaked a key: %q", e.Message)
			}
		}
	}
	if anomalies != 1 {
		t.Errorf("emitted %d auth_anomaly events, want exactly 1", anomalies)
	}
}
