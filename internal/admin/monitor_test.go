package admin

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

func TestMonitorLogsFilterAndPaginate(t *testing.T) {
	h := newHarness(t)
	h.store.reqLogs = []model.RequestLog{
		{ID: "r1", Model: "gpt-5", SessionID: "s1", Status: 200},
		{ID: "r2", Model: "gpt-4", SessionID: "s1", Status: 500},
		{ID: "r3", Model: "gpt-5", SessionID: "s2", Status: 200},
	}
	cookie, _ := h.authed()

	rec := h.do(http.MethodGet, "/admin/api/monitor/logs?model=gpt-5", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusOK {
		t.Fatalf("logs = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		Logs []model.RequestLog `json:"logs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Logs) != 2 {
		t.Fatalf("model filter returned %d, want 2", len(resp.Logs))
	}
	for _, l := range resp.Logs {
		if l.Model != "gpt-5" {
			t.Errorf("unexpected model %q", l.Model)
		}
	}

	// Pagination: limit=1 returns 1.
	rec = h.do(http.MethodGet, "/admin/api/monitor/logs?limit=1", nil, func(r *http.Request) { r.AddCookie(cookie) })
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Logs) != 1 {
		t.Errorf("limit=1 returned %d, want 1", len(resp.Logs))
	}
}

func TestMonitorCounters(t *testing.T) {
	h := newHarness(t)
	h.store.reqLogs = []model.RequestLog{
		{Model: "gpt-5", Status: 200, TokensIn: 10, TokensOut: 20},
		{Model: "gpt-5", Status: 500, TokensIn: 1, TokensOut: 0},
	}
	cookie, _ := h.authed()
	rec := h.do(http.MethodGet, "/admin/api/monitor/counters", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusOK {
		t.Fatalf("counters = %d, want 200", rec.Code)
	}
	m := decodeBody(t, rec)
	if m["total"].(float64) != 2 || m["success"].(float64) != 1 || m["error"].(float64) != 1 {
		t.Errorf("counters = %v", m)
	}
	if m["tokens_in"].(float64) != 11 {
		t.Errorf("tokens_in = %v, want 11", m["tokens_in"])
	}
}

func TestMonitorStreamNoMonitor(t *testing.T) {
	h := newHarness(t) // no WithMonitor
	cookie, _ := h.authed()
	rec := h.do(http.MethodGet, "/admin/api/monitor/stream", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("stream without monitor = %d, want 503", rec.Code)
	}
}

func TestMonitorStreamSSE(t *testing.T) {
	fm := &fakeMonitor{}
	h := newHarness(t, WithMonitor(fm))
	cookie, _ := h.authed()

	// A real server streams properly (ResponseRecorder is not concurrency-safe).
	srv := httptest.NewServer(h.h)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/admin/api/monitor/stream", nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET stream: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("content-type = %q, want text/event-stream", ct)
	}

	// Stream lines to a channel so the test can wait without racing on a buffer.
	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()

	// Handler subscribes, then we push an event.
	waitFor(t, func() bool { return fm.subCount() > 0 })
	fm.push(model.RequestLog{ID: "req1", Model: "gpt-5", Status: 200})

	var sawConnected, sawData bool
	deadline := time.After(3 * time.Second)
	for !(sawData) {
		select {
		case <-deadline:
			t.Fatalf("did not receive SSE data (connected=%v)", sawConnected)
		case ln := <-lines:
			if strings.Contains(ln, ": connected") {
				sawConnected = true
			}
			if strings.HasPrefix(ln, "data: ") && strings.Contains(ln, "req1") && strings.Contains(ln, "gpt-5") {
				sawData = true
			}
		}
	}
	if !sawConnected {
		t.Error("missing initial ': connected' comment")
	}
}

func (m *fakeMonitor) subCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.subs)
}

// waitFor polls cond up to ~2s.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
