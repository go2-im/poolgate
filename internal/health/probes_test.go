package health

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

func testAcct() model.Account {
	return model.Account{ID: "a1", AccessToken: "tok", AccountID: "chatgpt-acct-1"}
}

func TestModelsAuthCheckerStatuses(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantOK  bool
		wantErr bool
	}{
		{"200 valid", http.StatusOK, true, false},
		{"401 invalid", http.StatusUnauthorized, false, false},
		{"403 invalid", http.StatusForbidden, false, false},
		{"500 error", http.StatusInternalServerError, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotAuth, gotAcctID, gotOrig, gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				gotAcctID = r.Header.Get("ChatGPT-Account-ID")
				gotOrig = r.Header.Get("originator")
				gotPath = r.URL.Path + "?" + r.URL.RawQuery
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			a := NewModelsAuthChecker(WithAuthHTTPClient(srv.Client()),
				WithAuthBase(srv.URL), WithClientVersion("9.9.9"))
			ok, detail, err := a.Check(context.Background(), testAcct())
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got ok=%v detail=%q", ok, detail)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v", ok, tc.wantOK)
			}
			if gotAuth != "Bearer tok" {
				t.Fatalf("Authorization=%q", gotAuth)
			}
			if gotAcctID != "chatgpt-acct-1" {
				t.Fatalf("ChatGPT-Account-ID=%q", gotAcctID)
			}
			if gotOrig != defaultOriginator {
				t.Fatalf("originator=%q", gotOrig)
			}
			if gotPath != "/models?client_version=9.9.9" {
				t.Fatalf("path=%q want /models?client_version=9.9.9", gotPath)
			}
		})
	}
}

func TestModelsAuthCheckerTransportError(t *testing.T) {
	a := NewModelsAuthChecker(WithAuthBase("http://127.0.0.1:1"),
		WithAuthHTTPClient(&http.Client{Timeout: 200 * time.Millisecond}))
	if _, _, err := a.Check(context.Background(), testAcct()); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestModelsAuthCheckerDefaults(t *testing.T) {
	a := NewModelsAuthChecker()
	if a.base != DefaultModelsBase || a.clientVersion != DefaultClientVersion {
		t.Fatalf("unexpected defaults: %+v", a)
	}
}

func TestLiveRequesterStatuses(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		retryAfter  string
		wantOK      bool
		wantRetryAf time.Duration
		wantErr     bool
	}{
		{"200 ok", http.StatusOK, "", true, 0, false},
		{"202 ok", http.StatusAccepted, "", true, 0, false},
		{"429 with retry-after", http.StatusTooManyRequests, "45", false, 45 * time.Second, false},
		{"429 no retry-after", http.StatusTooManyRequests, "", false, 0, false},
		{"500 soft fail", http.StatusInternalServerError, "", false, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotBody map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(b, &gotBody)
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			l := NewLiveRequester(WithLiveHTTPClient(srv.Client()),
				WithLiveBase(srv.URL), WithLiveModel("m-test"))
			ok, ra, _, err := l.Live(context.Background(), testAcct())
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v", ok, tc.wantOK)
			}
			if ra != tc.wantRetryAf {
				t.Fatalf("retryAfter=%v want %v", ra, tc.wantRetryAf)
			}
			if gotBody["model"] != "m-test" {
				t.Fatalf("model=%v", gotBody["model"])
			}
			if gotBody["stream"] != false {
				t.Fatalf("stream=%v want false", gotBody["stream"])
			}
		})
	}
}

func TestLiveRequesterTransportError(t *testing.T) {
	l := NewLiveRequester(WithLiveBase("http://127.0.0.1:1"),
		WithLiveHTTPClient(&http.Client{Timeout: 200 * time.Millisecond}))
	if _, _, _, err := l.Live(context.Background(), testAcct()); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestLiveRequesterDefaults(t *testing.T) {
	l := NewLiveRequester()
	if l.base != DefaultResponsesBase || l.model != DefaultLiveModel {
		t.Fatalf("unexpected defaults: %+v", l)
	}
}

func TestParseRetryAfter(t *testing.T) {
	tests := map[string]time.Duration{
		"":                              0,
		"  ":                            0,
		"30":                            30 * time.Second,
		" 15 ":                          15 * time.Second,
		"0":                             0,
		"-5":                            0,
		"notasec":                       0,
		"Wed, 21 Oct 2026 07:28:00 GMT": 0, // HTTP-date form treated as unknown
	}
	for in, want := range tests {
		if got := parseRetryAfter(in); got != want {
			t.Fatalf("parseRetryAfter(%q)=%v want %v", in, got, want)
		}
	}
}

// setCodexHeaders is exercised indirectly above; this guards the raw helper.
func TestSetCodexHeaders(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example/", bytes.NewReader(nil))
	setCodexHeaders(req, testAcct(), "orig", "ua")
	if req.Header.Get("Authorization") != "Bearer tok" ||
		req.Header.Get("ChatGPT-Account-ID") != "chatgpt-acct-1" ||
		req.Header.Get("originator") != "orig" ||
		req.Header.Get("User-Agent") != "ua" {
		t.Fatalf("headers not set: %+v", req.Header)
	}
}
