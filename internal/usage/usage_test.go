package usage

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// fixedClock returns a deterministic clock for tests.
func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func testAccount() model.Account {
	return model.Account{ID: "acct_1", AccessToken: "acc-tok", AccountID: "chatgpt-acc-42"}
}

func TestFetch_ParsesCapturedFixture(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "usage_plus.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var gotAuth, gotAccount, gotOriginator, gotUA, gotAccept, gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAccount = r.Header.Get("ChatGPT-Account-ID")
		gotOriginator = r.Header.Get("originator")
		gotUA = r.Header.Get("User-Agent")
		gotAccept = r.Header.Get("Accept")
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	c := New(WithHTTPClient(srv.Client()), WithBase(srv.URL))
	u, err := c.Fetch(context.Background(), testAccount())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	// Header-rewrite conventions reused from the gateway.
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	if gotPath != "/wham/usage" {
		t.Errorf("path = %q, want /wham/usage", gotPath)
	}
	if gotAuth != "Bearer acc-tok" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotAccount != "chatgpt-acc-42" {
		t.Errorf("ChatGPT-Account-ID = %q", gotAccount)
	}
	if gotOriginator != defaultOriginator {
		t.Errorf("originator = %q, want %q", gotOriginator, defaultOriginator)
	}
	if gotUA != defaultUserAgent {
		t.Errorf("User-Agent = %q, want %q", gotUA, defaultUserAgent)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q", gotAccept)
	}

	// Generic model mapping.
	if u.PlanType != "plus" {
		t.Errorf("PlanType = %q, want plus", u.PlanType)
	}
	if len(u.Windows) != 3 {
		t.Fatalf("len(Windows) = %d, want 3 (primary + secondary + 1 additional primary)", len(u.Windows))
	}
	// primary
	w0 := u.Windows[0]
	if w0.Name != "primary" || w0.UsedPercent != 12 || w0.WindowSeconds != 18000 {
		t.Errorf("primary window = %+v", w0)
	}
	if want := time.Unix(1699999999, 0).UTC(); !w0.ResetsAt.Equal(want) {
		t.Errorf("primary ResetsAt = %v, want %v", w0.ResetsAt, want)
	}
	// secondary
	w1 := u.Windows[1]
	if w1.Name != "secondary" || w1.UsedPercent != 40 || w1.WindowSeconds != 604800 {
		t.Errorf("secondary window = %+v", w1)
	}
	// additional (named after limit_name)
	w2 := u.Windows[2]
	if w2.Name != "gpt-5-codex" || w2.UsedPercent != 5 || w2.WindowSeconds != 3600 {
		t.Errorf("additional window = %+v", w2)
	}
}

func TestFetch_401ReturnsTokenInvalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer srv.Close()

	c := New(WithHTTPClient(srv.Client()), WithBase(srv.URL))
	_, err := c.Fetch(context.Background(), testAccount())
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("err = %v, want ErrTokenInvalid", err)
	}
}

func TestFetch_ErrorStatuses(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{"429 rate limited", http.StatusTooManyRequests},
		{"500 server error", http.StatusInternalServerError},
		{"403 forbidden", http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			c := New(WithHTTPClient(srv.Client()), WithBase(srv.URL))
			_, err := c.Fetch(context.Background(), testAccount())
			if err == nil {
				t.Fatalf("expected error for status %d", tc.status)
			}
			if errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("status %d should not be ErrTokenInvalid", tc.status)
			}
		})
	}
}

func TestFetch_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer srv.Close()

	c := New(WithHTTPClient(srv.Client()), WithBase(srv.URL))
	if _, err := c.Fetch(context.Background(), testAccount()); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestFetch_TransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // immediately closed -> connection refused

	c := New(WithHTTPClient(srv.Client()), WithBase(srv.URL))
	if _, err := c.Fetch(context.Background(), testAccount()); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestToUsage_ResetFromResetAfterSeconds(t *testing.T) {
	now := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	c := New(WithClock(fixedClock(now)))
	raw := rawPayload{
		PlanType: "pro",
		RateLimit: &rawStatusDetails{
			PrimaryWindow: &rawWindow{UsedPercent: 20, LimitWindowSeconds: 18000, ResetAfterSeconds: 1800, ResetAt: 0},
		},
	}
	u := c.toUsage(raw)
	if len(u.Windows) != 1 {
		t.Fatalf("len(Windows) = %d, want 1", len(u.Windows))
	}
	want := now.Add(30 * time.Minute)
	if !u.Windows[0].ResetsAt.Equal(want) {
		t.Errorf("ResetsAt = %v, want %v", u.Windows[0].ResetsAt, want)
	}
}

func TestToUsage_NoResetInfoZeroTime(t *testing.T) {
	c := New(WithClock(fixedClock(time.Unix(1000, 0).UTC())))
	raw := rawPayload{
		RateLimit: &rawStatusDetails{
			PrimaryWindow: &rawWindow{UsedPercent: 1, LimitWindowSeconds: 60, ResetAfterSeconds: 0, ResetAt: 0},
		},
	}
	u := c.toUsage(raw)
	if !u.Windows[0].ResetsAt.IsZero() {
		t.Errorf("ResetsAt = %v, want zero", u.Windows[0].ResetsAt)
	}
}

func TestToUsage_NilRateLimitNoWindows(t *testing.T) {
	c := New()
	u := c.toUsage(rawPayload{PlanType: "free"})
	if u.PlanType != "free" {
		t.Errorf("PlanType = %q", u.PlanType)
	}
	if len(u.Windows) != 0 {
		t.Errorf("len(Windows) = %d, want 0", len(u.Windows))
	}
}

func TestToUsage_AdditionalNameFallbacks(t *testing.T) {
	c := New()
	raw := rawPayload{
		AdditionalRateLimits: []rawAdditionalRate{
			{ // limit_name empty -> falls back to metered_feature
				MeteredFeature: "codex",
				RateLimit:      &rawStatusDetails{PrimaryWindow: &rawWindow{UsedPercent: 1}, SecondaryWindow: &rawWindow{UsedPercent: 2}},
			},
			{ // both empty -> "additional"
				RateLimit: &rawStatusDetails{PrimaryWindow: &rawWindow{UsedPercent: 3}},
			},
		},
	}
	u := c.toUsage(raw)
	names := []string{}
	for _, w := range u.Windows {
		names = append(names, w.Name)
	}
	want := []string{"codex", "codex_secondary", "additional"}
	if len(names) != len(want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("names[%d] = %q, want %q", i, names[i], want[i])
		}
	}
}

func TestHeadroom(t *testing.T) {
	tests := []struct {
		used float64
		want float64
	}{
		{0, 100},
		{40, 60},
		{100, 0},
		{120, 0},   // over 100 -> clamp to 0
		{-10, 100}, // negative used -> clamp headroom to 100
	}
	for _, tc := range tests {
		if got := (model.UsageWindow{UsedPercent: tc.used}).Headroom(); got != tc.want {
			t.Errorf("Headroom(used=%v) = %v, want %v", tc.used, got, tc.want)
		}
	}
}
