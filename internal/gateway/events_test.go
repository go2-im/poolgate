package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

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
