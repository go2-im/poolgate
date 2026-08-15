package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go2-im/poolgate/internal/model"
)

// fakeRecorder collects recorded request logs.
type fakeRecorder struct {
	mu   sync.Mutex
	logs []model.RequestLog
}

func (r *fakeRecorder) Record(l model.RequestLog) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs = append(r.logs, l)
}

func (r *fakeRecorder) last() (model.RequestLog, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.logs) == 0 {
		return model.RequestLog{}, false
	}
	return r.logs[len(r.logs)-1], true
}

func TestRecordsStreamedRequestWithUsage(t *testing.T) {
	f := newFixture(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n")
		if fl != nil {
			fl.Flush()
		}
		// Terminal usage event — the monitor should sniff these token counts.
		_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":11,\"output_tokens\":22}}}\n\n")
		if fl != nil {
			fl.Flush()
		}
	}))
	defer upstream.Close()

	f.cfg.UpstreamAllowlist = []string{mustHost(t, upstream.URL)}
	rec := &fakeRecorder{}
	gw := New(f.st, f.cfg, WithUpstreamBase(upstream.URL), WithHTTPClient(upstream.Client()), WithRecorder(rec))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/default/v1/responses",
		strings.NewReader(`{"model":"gpt-5-codex"}`))
	req.Header.Set("Authorization", "Bearer "+f.apiKey)
	req.Header.Set("X-Session-Id", "conv-123")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	log, ok := rec.last()
	if !ok {
		t.Fatal("no request log recorded")
	}
	if log.Status != 200 {
		t.Errorf("status = %d, want 200", log.Status)
	}
	if log.Endpoint != "default" || log.Model != "gpt-5-codex" {
		t.Errorf("endpoint/model = %q/%q", log.Endpoint, log.Model)
	}
	if log.AccountID != f.acct.ID {
		t.Errorf("account = %q, want %q", log.AccountID, f.acct.ID)
	}
	if log.SessionID != "conv-123" {
		t.Errorf("session = %q, want conv-123", log.SessionID)
	}
	if log.TokensIn != 11 || log.TokensOut != 22 {
		t.Errorf("tokens = %d/%d, want 11/22", log.TokensIn, log.TokensOut)
	}
	if !strings.Contains(log.Trace, f.acct.ID+":streamed") {
		t.Errorf("trace = %q, want a streamed entry", log.Trace)
	}
	// The record must carry no secret (no api key value, no account token).
	if strings.Contains(log.Trace, f.apiKey) || strings.Contains(log.SessionID, "acct-access-token") {
		t.Errorf("record leaked a secret: %+v", log)
	}
}

func TestRecordsNoHealthyAccount(t *testing.T) {
	f := newFixture(t)
	// Force the only member out of rotation.
	if err := f.st.UpdateState(t.Context(), f.acct.ID, model.StateExpired); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}
	rec := &fakeRecorder{}
	gw := New(f.st, f.cfg, WithRecorder(rec))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/default/v1/responses",
		strings.NewReader(`{"model":"gpt-5"}`))
	req.Header.Set("Authorization", "Bearer "+f.apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()

	log, ok := rec.last()
	if !ok {
		t.Fatal("no request log recorded for 503")
	}
	if log.Status != http.StatusServiceUnavailable || log.ErrorType != "no_healthy_account" {
		t.Errorf("log = status %d type %q, want 503/no_healthy_account", log.Status, log.ErrorType)
	}
}

func TestParseUsageAndSanitizeHelpers(t *testing.T) {
	in, out := parseUsage([]byte(`... "input_tokens": 3 ... "input_tokens":7, "output_tokens":  9 ...`))
	if in != 7 || out != 9 {
		t.Errorf("parseUsage = %d/%d, want 7/9 (last match wins)", in, out)
	}
	if in, out := parseUsage([]byte(`no usage here`)); in != 0 || out != 0 {
		t.Errorf("parseUsage(none) = %d/%d, want 0/0", in, out)
	}
	if got := extractModel([]byte(`{"model":"gpt-5","x":1}`)); got != "gpt-5" {
		t.Errorf("extractModel = %q", got)
	}
	if got := extractModel([]byte(`not json`)); got != "" {
		t.Errorf("extractModel(bad) = %q, want empty", got)
	}
}

func TestTailBufferKeepsTail(t *testing.T) {
	tb := &tailBuffer{max: 8}
	_, _ = tb.Write([]byte("abcdef"))
	_, _ = tb.Write([]byte("ghijkl")) // total 12 > 8
	if got := string(tb.bytes()); got != "efghijkl" {
		t.Errorf("tail = %q, want last 8 bytes efghijkl", got)
	}
}
