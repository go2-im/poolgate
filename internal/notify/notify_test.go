package notify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// fakeChannelStore is an in-memory ChannelStore.
type fakeChannelStore struct {
	mu       sync.Mutex
	channels []model.NotifyChannel
	err      error
}

func (f *fakeChannelStore) ListNotifyChannels(context.Context) ([]model.NotifyChannel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.channels, nil
}

func noopSleep(context.Context, time.Duration) error { return nil }

// countingServer is a TLS httptest server that counts requests and replies with a
// scripted status + body.
func countingServer(t *testing.T, status int, body string) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = io.Copy(io.Discard, r.Body)
		if status != 0 {
			w.WriteHeader(status)
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func dingtalkChannel(url string) model.NotifyChannel {
	return model.NotifyChannel{
		ID: "ch1", Type: model.ChannelDingTalk, Name: "ops", Enabled: true,
		Config: model.NotifyConfig{URL: url}, DedupSeconds: 300,
	}
}

func TestShouldSend(t *testing.T) {
	e := New(&fakeChannelStore{}, WithClock(fixedNow))

	base := model.NotifyChannel{ID: "c", Enabled: true}
	// Disabled channel: never.
	off := base
	off.Enabled = false
	if e.shouldSend(off, testEvent()) {
		t.Error("disabled channel should not send")
	}
	// Subscription filter.
	sub := base
	sub.Events = []model.NotifyEventKind{model.EventAccountExpired}
	if e.shouldSend(sub, testEvent()) { // testEvent is cooldown
		t.Error("unsubscribed kind should not send")
	}
	// Subscribed kind sends.
	sub.Events = []model.NotifyEventKind{model.EventAccountCooldown}
	if !e.shouldSend(sub, testEvent()) {
		t.Error("subscribed kind should send")
	}
	// quota_low threshold gating.
	ql := model.NotifyEvent{Kind: model.EventQuotaLow, AccountID: "a", Headroom: 20}
	ch := base
	ch.MinHeadroom = 10
	if e.shouldSend(ch, ql) {
		t.Error("headroom 20 > threshold 10 should not send")
	}
	ql.Headroom = 5
	if !e.shouldSend(ch, ql) {
		t.Error("headroom 5 <= threshold 10 should send")
	}
	// Default threshold (MinHeadroom 0 -> 15).
	def := base
	if !e.shouldSend(def, model.NotifyEvent{Kind: model.EventQuotaLow, Headroom: 12}) {
		t.Error("headroom 12 <= default 15 should send")
	}
	if e.shouldSend(def, model.NotifyEvent{Kind: model.EventQuotaLow, Headroom: 40}) {
		t.Error("headroom 40 > default 15 should not send")
	}
}

func TestDispatchDeliversAndDedups(t *testing.T) {
	srv, hits := countingServer(t, 200, `{"errcode":0}`)
	store := &fakeChannelStore{channels: []model.NotifyChannel{dingtalkChannel(srv.URL)}}
	clk := fixedNow()
	e := New(store, WithHTTPClient(srv.Client()), WithClock(func() time.Time { return clk }), WithSleep(noopSleep))

	e.dispatch(context.Background(), testEvent())
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Fatalf("hits = %d, want 1", got)
	}
	// Immediate repeat within the dedup window is suppressed.
	e.dispatch(context.Background(), testEvent())
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Fatalf("after dedup hits = %d, want 1", got)
	}
	// After the dedup window elapses it delivers again.
	clk = clk.Add(301 * time.Second)
	e.dispatch(context.Background(), testEvent())
	if got := atomic.LoadInt32(hits); got != 2 {
		t.Fatalf("after window hits = %d, want 2", got)
	}
}

func TestDispatchListError(t *testing.T) {
	store := &fakeChannelStore{err: context.DeadlineExceeded}
	e := New(store, WithSleep(noopSleep))
	// Must not panic; simply logs and returns.
	e.dispatch(context.Background(), testEvent())
}

func TestDeliverRetries(t *testing.T) {
	srv, hits := countingServer(t, 500, ``)
	store := &fakeChannelStore{channels: []model.NotifyChannel{dingtalkChannel(srv.URL)}}
	e := New(store, WithHTTPClient(srv.Client()), WithClock(fixedNow), WithSleep(noopSleep), WithRetries(2))

	err := e.deliver(context.Background(), dingtalkChannel(srv.URL), testEvent())
	if err == nil {
		t.Fatal("expected delivery error after retries")
	}
	if got := atomic.LoadInt32(hits); got != 3 { // 1 + 2 retries
		t.Fatalf("attempts = %d, want 3", got)
	}
}

func TestDeliverContextCancelStopsRetry(t *testing.T) {
	srv, _ := countingServer(t, 500, ``)
	store := &fakeChannelStore{channels: []model.NotifyChannel{dingtalkChannel(srv.URL)}}
	// Sleep that reports cancellation aborts the retry loop.
	e := New(store, WithHTTPClient(srv.Client()), WithClock(fixedNow),
		WithSleep(func(context.Context, time.Duration) error { return context.Canceled }), WithRetries(5))
	if err := e.deliver(context.Background(), dingtalkChannel(srv.URL), testEvent()); err != context.Canceled {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestTestMethodBypassesFilters(t *testing.T) {
	srv, hits := countingServer(t, 200, `{"errcode":0}`)
	// Disabled + unsubscribed channel is still delivered by Test().
	ch := dingtalkChannel(srv.URL)
	ch.Enabled = false
	ch.Events = []model.NotifyEventKind{model.EventAccountExpired}
	e := New(&fakeChannelStore{}, WithHTTPClient(srv.Client()), WithClock(fixedNow))
	if err := e.Test(context.Background(), ch); err != nil {
		t.Fatalf("Test: %v", err)
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Fatalf("Test hits = %d, want 1", got)
	}
}

func TestEmitAndRun(t *testing.T) {
	srv, hits := countingServer(t, 200, `{"errcode":0}`)
	store := &fakeChannelStore{channels: []model.NotifyChannel{dingtalkChannel(srv.URL)}}
	e := New(store, WithHTTPClient(srv.Client()), WithClock(fixedNow), WithSleep(noopSleep))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = e.Run(ctx); close(done) }()

	e.Emit(model.NotifyEvent{Kind: model.EventAccountCooldown, AccountID: "a"})
	// Wait for delivery.
	deadline := time.After(2 * time.Second)
	for atomic.LoadInt32(hits) == 0 {
		select {
		case <-deadline:
			t.Fatal("event was not delivered by Run")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

func TestEmitNilEngineNoPanic(t *testing.T) {
	var e *Engine
	e.Emit(model.NotifyEvent{Kind: model.EventAccountCooldown}) // must not panic
}

func TestGCDedup(t *testing.T) {
	clk := fixedNow()
	e := New(&fakeChannelStore{}, WithClock(func() time.Time { return clk }))
	e.lastSent["stale"] = clk.Add(-25 * time.Hour)
	e.lastSent["fresh"] = clk.Add(-1 * time.Hour)
	e.gcDedup()
	if _, ok := e.lastSent["stale"]; ok {
		t.Error("stale dedup entry not pruned")
	}
	if _, ok := e.lastSent["fresh"]; !ok {
		t.Error("fresh dedup entry wrongly pruned")
	}
}

// TestGuardBlocksThroughDefaultClient exercises the SSRF guard through the REAL
// delivery path: an Engine built via New() (default guarded client, no
// WithHTTPClient override) must refuse a channel whose https URL resolves to a
// blocked address, and the returned error must be redacted (no channel URL/path).
func TestGuardBlocksThroughDefaultClient(t *testing.T) {
	secretURL := "https://127.0.0.1:9/robot/send?access_token=SECRET_TOKEN"
	store := &fakeChannelStore{channels: []model.NotifyChannel{{
		ID: "c", Type: model.ChannelDingTalk, Enabled: true,
		Config: model.NotifyConfig{URL: secretURL},
	}}}
	e := New(store, WithClock(fixedNow), WithSleep(noopSleep), WithRetries(0))

	err := e.deliver(context.Background(), store.channels[0], model.NotifyEvent{Kind: model.EventAccountCooldown})
	if err == nil {
		t.Fatal("guarded client delivered to a blocked address")
	}
	if !strings.Contains(err.Error(), "block") {
		t.Errorf("error = %v, want a block error", err)
	}
	// The channel URL / access token must not appear in the (logged) error.
	if strings.Contains(err.Error(), "SECRET_TOKEN") || strings.Contains(err.Error(), "/robot/send") {
		t.Errorf("delivery error leaked channel URL: %v", err)
	}
}

func TestDeliverNoRetryOnPermanent(t *testing.T) {
	// A DingTalk errcode!=0 is a permanent rejection: deliver must attempt once.
	srv, hits := countingServer(t, 200, `{"errcode":310000,"errmsg":"keyword not found"}`)
	store := &fakeChannelStore{}
	e := New(store, WithHTTPClient(srv.Client()), WithClock(fixedNow), WithSleep(noopSleep), WithRetries(5))
	if err := e.deliver(context.Background(), dingtalkChannel(srv.URL), testEvent()); err == nil {
		t.Fatal("expected permanent errcode failure")
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Fatalf("permanent error attempts = %d, want 1 (no retry)", got)
	}
}

func TestDeliverNoRetryOnBadScheme(t *testing.T) {
	// An http URL is rejected by requireHTTPS (ErrInsecureScheme) — permanent.
	ch := model.NotifyChannel{ID: "c", Type: model.ChannelWebhook, Config: model.NotifyConfig{URL: "http://insecure.example.com"}}
	e := New(&fakeChannelStore{}, WithHTTPClient(http.DefaultClient), WithClock(fixedNow),
		WithSleep(func(context.Context, time.Duration) error { t.Fatal("must not sleep/retry on permanent error"); return nil }),
		WithRetries(3))
	if err := e.deliver(context.Background(), ch, testEvent()); err == nil {
		t.Fatal("expected ErrInsecureScheme")
	}
}
