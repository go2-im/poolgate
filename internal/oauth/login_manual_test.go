package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestManualLoginHappyPath drives the headless (no-listener) flow: BeginManual
// builds the authorize URL, then CompleteManual validates a pasted redirect URL
// and exchanges the code.
func TestManualLoginHappyPath(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		gotForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse{
			IDToken:      makeIDToken(t, "acc-manual"),
			AccessToken:  "at",
			RefreshToken: "rt",
		})
	}))
	defer srv.Close()

	l := NewLogin(WithAuthBase(srv.URL), WithCallbackPorts(1455),
		WithLoginClock(func() time.Time { return time.Unix(1700000000, 0).UTC() }))

	m, err := l.BeginManual()
	if err != nil {
		t.Fatalf("BeginManual: %v", err)
	}
	au, err := url.Parse(m.AuthorizeURL())
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	q := au.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("authorize url missing S256 challenge: %s", m.AuthorizeURL())
	}
	if q.Get("redirect_uri") != "http://localhost:1455/auth/callback" {
		t.Fatalf("redirect_uri = %q, want fixed loopback :1455", q.Get("redirect_uri"))
	}

	// The operator pastes the full URL the browser was redirected to.
	pasted := "http://localhost:1455/auth/callback?" +
		url.Values{"code": {"the-code"}, "state": {q.Get("state")}}.Encode()
	acct, err := l.CompleteManual(context.Background(), m, pasted)
	if err != nil {
		t.Fatalf("CompleteManual: %v", err)
	}
	if acct.AccountID != "acc-manual" || acct.AccessToken != "at" || acct.RefreshToken != "rt" {
		t.Fatalf("account = %+v", acct)
	}
	if gotForm.Get("grant_type") != "authorization_code" || gotForm.Get("code") != "the-code" {
		t.Fatalf("token form = %v", gotForm)
	}
	if gotForm.Get("redirect_uri") != "http://localhost:1455/auth/callback" || gotForm.Get("code_verifier") == "" {
		t.Fatalf("token form redirect/verifier wrong: %v", gotForm)
	}
}

// TestManualLoginRejections covers the guards that reject a paste without ever
// exchanging (no token server needed — none of these should reach it).
func TestManualLoginRejections(t *testing.T) {
	l := NewLogin(WithAuthBase("https://auth.example"), WithCallbackPorts(1455))
	m, err := l.BeginManual()
	if err != nil {
		t.Fatalf("BeginManual: %v", err)
	}
	au, _ := url.Parse(m.AuthorizeURL())
	state := au.Query().Get("state")

	cases := []struct{ name, pasted string }{
		{"state mismatch", "http://localhost:1455/auth/callback?code=x&state=wrong"},
		{"oauth error", "http://localhost:1455/auth/callback?error=access_denied&state=" + state},
		{"missing code", "http://localhost:1455/auth/callback?state=" + state},
		{"bare code no state", "the-code"},
		{"empty", "   "},
	}
	for _, c := range cases {
		if _, err := l.CompleteManual(context.Background(), m, c.pasted); err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
	if _, err := l.CompleteManual(context.Background(), nil, "x"); err == nil {
		t.Error("nil handle: expected error")
	}
}

// TestManualLoginAcceptsBareQuery confirms a pasted bare query string (no scheme)
// with the right state is accepted up to the exchange.
func TestManualLoginAcceptsBareQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse{
			IDToken: makeIDToken(t, "acc-q"), AccessToken: "at", RefreshToken: "rt",
		})
	}))
	defer srv.Close()
	l := NewLogin(WithAuthBase(srv.URL), WithCallbackPorts(1455))
	m, _ := l.BeginManual()
	state := mustState(t, m)
	acct, err := l.CompleteManual(context.Background(), m, "?code=c&state="+state)
	if err != nil {
		t.Fatalf("CompleteManual(bare query): %v", err)
	}
	if acct.AccountID != "acc-q" {
		t.Fatalf("AccountID = %q", acct.AccountID)
	}
}

func mustState(t *testing.T, m *ManualLogin) string {
	t.Helper()
	u, err := url.Parse(m.AuthorizeURL())
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	return u.Query().Get("state")
}
