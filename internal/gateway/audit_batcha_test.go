package gateway

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// errAfterReader yields payload once, then returns a non-EOF error to simulate a
// truncated/aborted upstream stream.
type errAfterReader struct {
	payload []byte
	done    bool
}

func (r *errAfterReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		n := copy(p, r.payload)
		return n, nil
	}
	return 0, errors.New("connection reset")
}

func TestParseRetryAfterHTTPDate(t *testing.T) {
	// delta-seconds
	if got := parseRetryAfter("120"); got != 120*time.Second {
		t.Errorf("delta-seconds = %v, want 2m", got)
	}
	// HTTP-date ~30s in the future should yield a positive, roughly-30s delta.
	future := time.Now().UTC().Add(30 * time.Second).Format(http.TimeFormat)
	got := parseRetryAfter(future)
	if got <= 0 || got > 31*time.Second {
		t.Errorf("HTTP-date Retry-After = %v, want ~30s", got)
	}
	// A past HTTP-date and garbage both clamp to 0.
	past := time.Now().UTC().Add(-time.Hour).Format(http.TimeFormat)
	if parseRetryAfter(past) != 0 || parseRetryAfter("nonsense") != 0 || parseRetryAfter("") != 0 {
		t.Errorf("past/garbage/empty Retry-After should be 0")
	}
}

func TestForceStreamPreservesLargeInteger(t *testing.T) {
	// 9007199254740993 = 2^53 + 1, not representable as float64.
	in := []byte(`{"model":"gpt-5","seed":9007199254740993}`)
	out, err := forceStream(in)
	if err != nil {
		t.Fatalf("forceStream: %v", err)
	}
	if !strings.Contains(string(out), "9007199254740993") {
		t.Errorf("large integer lost precision: %s", out)
	}
	if !strings.Contains(string(out), `"stream":true`) {
		t.Errorf("stream:true not set: %s", out)
	}
}

func TestRelayStreamSurfacesUpstreamError(t *testing.T) {
	rec := httptest.NewRecorder()
	_, _, err := relayStream(rec, &errAfterReader{payload: []byte("data: {}\n\n")})
	if err == nil {
		t.Fatal("relayStream should return an error on a truncated upstream stream")
	}
	if !strings.Contains(err.Error(), "upstream read") {
		t.Errorf("err = %v, want upstream read error", err)
	}
	// Bytes read before the error must still have reached the client.
	if !strings.Contains(rec.Body.String(), "data: {}") {
		t.Errorf("partial body not relayed: %q", rec.Body.String())
	}
}

func TestRetryableStatusClassification(t *testing.T) {
	retryable := []int{401, 403, 408, 425, 429, 500, 502, 503, 504}
	for _, s := range retryable {
		if !retryableStatus(s) {
			t.Errorf("status %d should be retryable", s)
		}
	}
	nonRetryable := []int{400, 402, 404, 405, 409, 410, 413, 415, 422, 426, 451}
	for _, s := range nonRetryable {
		if retryableStatus(s) {
			t.Errorf("status %d should NOT be retryable (relay as-is)", s)
		}
	}
}

// TestNonRetryable4xxRelayedVerbatim proves a client 400 is returned to the caller
// as-is with its body, is NOT failed over across accounts, and fires no health hook.
func TestNonRetryable4xxRelayedVerbatim(t *testing.T) {
	st, cfg := newStore(t)
	a := seedAccount(t, st, "a", "tok-a", "id-a")
	b := seedAccount(t, st, "b", "tok-b", "id-b")
	key := seedGroupEndpointKey(t, st, model.StrategyFallback, a.ID, b.ID)

	var calls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"message":"invalid model"}}`)
	}))
	defer upstream.Close()

	fh := &fakeHealth{}
	cfg.UpstreamAllowlist = []string{mustHost(t, upstream.URL)}
	gw := New(st, cfg, WithUpstreamBase(upstream.URL), WithHTTPClient(upstream.Client()),
		WithLogger(quietLogger()), WithHealth(fh))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	resp := doProxyPost(t, srv.URL, key)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 relayed verbatim", resp.StatusCode)
	}
	if !strings.Contains(string(body), "invalid model") {
		t.Errorf("upstream error body not relayed: %s", body)
	}
	if calls != 1 {
		t.Errorf("upstream called %d times, want 1 (no failover on client 4xx)", calls)
	}
	if fh.unauthorized != 0 || len(fh.rateLimited) != 0 || fh.quota != 0 {
		t.Errorf("no health hook should fire for a non-retryable 4xx")
	}
}
