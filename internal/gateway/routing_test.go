package gateway

import (
	"context"
	"encoding/json"
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

func TestInflightTryAddEnforcesCapUnderConcurrency(t *testing.T) {
	i := newInflight()
	const capLimit = 3
	const goroutines = 50
	var admitted int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if i.tryAdd("a", capLimit) {
				atomic.AddInt64(&admitted, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if admitted != capLimit {
		t.Errorf("tryAdd admitted %d, want exactly %d (hard cap under concurrency)", admitted, capLimit)
	}
	if i.count("a") != capLimit {
		t.Errorf("count = %d, want %d", i.count("a"), capLimit)
	}
	// Unlimited cap (0) always admits.
	if !i.tryAdd("b", 0) {
		t.Error("cap 0 should admit (1st)")
	}
	if !i.tryAdd("b", 0) {
		t.Error("cap 0 should admit (2nd)")
	}
}

func TestInflightCounter(t *testing.T) {
	i := newInflight()
	if i.count("a") != 0 {
		t.Fatal("fresh count should be 0")
	}
	i.add("a")
	i.add("a")
	if i.count("a") != 2 {
		t.Errorf("count = %d, want 2", i.count("a"))
	}
	i.done("a")
	if i.count("a") != 1 {
		t.Errorf("count = %d, want 1", i.count("a"))
	}
	// done never goes negative.
	i.done("a")
	i.done("a")
	if i.count("a") != 0 {
		t.Errorf("count = %d, want 0 (no negative)", i.count("a"))
	}
}

func TestRouteViewAtCap(t *testing.T) {
	inf := newInflight()
	v := &routeView{caps: map[string]int{"a": 2, "b": 0}, inflight: inf}
	if v.atCap("a") {
		t.Error("a at 0/2 should not be capped")
	}
	inf.add("a")
	inf.add("a")
	if !v.atCap("a") {
		t.Error("a at 2/2 should be capped")
	}
	// cap 0 = unlimited.
	inf.add("b")
	inf.add("b")
	if v.atCap("b") {
		t.Error("b has cap 0 (unlimited), never capped")
	}
	// IsHealthy reflects the cap.
	v.healthy = map[string]bool{"a": true}
	if v.IsHealthy("a") {
		t.Error("IsHealthy(a) should be false while at cap")
	}
}

func TestWaitForSlotFreesUp(t *testing.T) {
	g := &Gateway{}
	inf := newInflight()
	inf.add("a") // 1/1 -> capped
	v := &routeView{caps: map[string]int{"a": 1}, inflight: inf}
	eligible := []model.Account{{ID: "a"}}

	go func() {
		time.Sleep(30 * time.Millisecond)
		inf.done("a")
	}()
	if !g.waitForSlot(context.Background(), eligible, v, time.Now().Add(2*time.Second)) {
		t.Fatal("expected a slot to free within the window")
	}
}

func TestWaitForSlotDeadline(t *testing.T) {
	g := &Gateway{}
	inf := newInflight()
	inf.add("a")
	v := &routeView{caps: map[string]int{"a": 1}, inflight: inf}
	eligible := []model.Account{{ID: "a"}}
	// Deadline already passed -> immediate false (fail-fast backpressure).
	if g.waitForSlot(context.Background(), eligible, v, time.Now().Add(-time.Second)) {
		t.Fatal("expected false when deadline has passed and all capped")
	}
}

// TestBackpressure429 holds the only account's single slot open and asserts a
// second concurrent request is shed with 429 + Retry-After (queueWait=0).
func TestBackpressure429(t *testing.T) {
	f := newFixture(t)
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: hi\n\n")
		if fl != nil {
			fl.Flush()
		}
		select {
		case started <- struct{}{}:
		default:
		}
		<-release // hold the request in-flight
	}))
	defer upstream.Close()
	// NOTE: release is closed explicitly at the end (not deferred) so the held
	// request-1 finishes BEFORE srv.Close()/upstream.Close() (which block on
	// outstanding requests) run — otherwise cleanup deadlocks.

	f.cfg.UpstreamAllowlist = []string{mustHost(t, upstream.URL)}
	gw := New(f.st, f.cfg, WithUpstreamBase(upstream.URL), WithHTTPClient(upstream.Client()),
		WithDefaultConcurrencyCap(1), WithBackpressure(0, 2))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	// Request 1: occupies the single slot (blocks in-flight on the upstream).
	go func() {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/default/v1/responses", strings.NewReader(`{"model":"gpt-5"}`))
		req.Header.Set("Authorization", "Bearer "+f.apiKey)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	<-started
	// Wait until the in-flight counter reflects the held request.
	deadline := time.Now().Add(2 * time.Second)
	for gw.inflight.count(f.acct.ID) < 1 {
		if time.Now().After(deadline) {
			t.Fatal("request 1 never registered in-flight")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Request 2: the only account is at cap → 429 + Retry-After.
	req2, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/default/v1/responses", strings.NewReader(`{"model":"gpt-5"}`))
	req2.Header.Set("Authorization", "Bearer "+f.apiKey)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("request 2: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("request 2 status = %d, want 429", resp2.StatusCode)
	}
	if ra := resp2.Header.Get("Retry-After"); ra != "2" {
		t.Errorf("Retry-After = %q, want 2", ra)
	}
	var eb errorBody
	_ = json.NewDecoder(resp2.Body).Decode(&eb)
	if eb.Error.Type != "poolgate_backpressure" {
		t.Errorf("error type = %q, want poolgate_backpressure", eb.Error.Type)
	}

	// Release request 1 so the held upstream returns and both servers can close
	// without deadlocking on the outstanding request.
	close(release)
}
