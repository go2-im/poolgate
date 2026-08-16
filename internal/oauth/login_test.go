package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// makeIDToken builds an unsigned JWT whose auth claim carries chatgpt_account_id.
func makeIDToken(t *testing.T, accountID string) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := map[string]any{
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": accountID},
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return hdr + "." + base64.RawURLEncoding.EncodeToString(pb) + ".sig"
}

// TestLoginHappyPath drives the full flow: a fake token endpoint plus a
// simulated browser that follows the authorize URL's redirect_uri to the
// loopback callback with a valid code+state.
func TestLoginHappyPath(t *testing.T) {
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
			IDToken:      makeIDToken(t, "acc-xyz"),
			AccessToken:  "at-123",
			RefreshToken: "rt-456",
		})
	}))
	defer srv.Close()

	l := NewLogin(WithAuthBase(srv.URL), WithCallbackPorts(0),
		WithLoginClock(func() time.Time { return time.Unix(1700000000, 0).UTC() }))

	// prompt simulates the browser: follow the authorize URL's redirect_uri to the
	// loopback callback with a valid code + the flow's own state.
	browser := func(authorizeURL string) {
		u, err := url.Parse(authorizeURL)
		if err != nil {
			t.Errorf("parse authorize url: %v", err)
			return
		}
		q := u.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			t.Errorf("authorize url missing S256 challenge: %s", authorizeURL)
		}
		if q.Get("response_type") != "code" || q.Get("client_id") != DefaultClientID {
			t.Errorf("authorize url params wrong: %s", authorizeURL)
		}
		cb, _ := url.Parse(q.Get("redirect_uri"))
		cbq := url.Values{"code": {"the-code"}, "state": {q.Get("state")}}
		cb.RawQuery = cbq.Encode()
		resp, err := http.Get(cb.String())
		if err != nil {
			t.Errorf("browser callback GET: %v", err)
			return
		}
		resp.Body.Close()
	}

	acct, err := l.Run(context.Background(), browser)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if acct.AccessToken != "at-123" || acct.RefreshToken != "rt-456" {
		t.Errorf("tokens = %q / %q", acct.AccessToken, acct.RefreshToken)
	}
	if acct.AccountID != "acc-xyz" {
		t.Errorf("AccountID = %q, want acc-xyz", acct.AccountID)
	}
	if acct.State != model.StateUnknown {
		t.Errorf("State = %q, want unknown", acct.State)
	}
	if acct.CreatedAt.IsZero() || acct.UpdatedAt.IsZero() {
		t.Error("timestamps not set")
	}
	// The exchange must have used the authorization_code grant with a verifier.
	if gotForm.Get("grant_type") != "authorization_code" || gotForm.Get("code") != "the-code" {
		t.Errorf("token form = %v", gotForm)
	}
	if gotForm.Get("code_verifier") == "" || gotForm.Get("client_id") != DefaultClientID {
		t.Errorf("token form missing verifier/client_id: %v", gotForm)
	}
}

// TestLoginContextCancel confirms Run returns the context error when no callback
// ever arrives.
func TestLoginContextCancel(t *testing.T) {
	l := NewLogin(WithAuthBase("https://example.invalid"), WithCallbackPorts(0))
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	if _, err := l.Run(ctx, func(string) {}); err == nil {
		t.Fatal("Run with cancelled context = nil, want error")
	}
}

// TestLoginExchangeError confirms a non-2xx token response surfaces an error.
func TestLoginExchangeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	l := NewLogin(WithAuthBase(srv.URL), WithCallbackPorts(0))
	browser := func(authorizeURL string) {
		u, _ := url.Parse(authorizeURL)
		cb, _ := url.Parse(u.Query().Get("redirect_uri"))
		cb.RawQuery = url.Values{"code": {"c"}, "state": {u.Query().Get("state")}}.Encode()
		resp, err := http.Get(cb.String())
		if err == nil {
			resp.Body.Close()
		}
	}
	if _, err := l.Run(context.Background(), browser); err == nil {
		t.Fatal("Run with token 400 = nil, want error")
	}
}

// TestCallbackHandlerStateAndErrors covers the callback branches deterministically:
// wrong state (rejected, not delivered), OAuth error, missing code, then success.
func TestCallbackHandlerStateAndErrors(t *testing.T) {
	t.Run("state mismatch rejected without delivery", func(t *testing.T) {
		ch := make(chan result, 1)
		h := callbackHandler("good", ch)
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?state=bad&code=x", nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
		select {
		case <-ch:
			t.Error("mismatched state should not deliver a result")
		default:
		}
	})
	t.Run("oauth error delivered", func(t *testing.T) {
		ch := make(chan result, 1)
		h := callbackHandler("good", ch)
		h(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied", nil))
		if r := <-ch; r.err == nil {
			t.Error("want error result")
		}
	})
	t.Run("missing code delivered as error", func(t *testing.T) {
		ch := make(chan result, 1)
		h := callbackHandler("good", ch)
		h(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/callback?state=good", nil))
		if r := <-ch; r.err == nil {
			t.Error("want error for missing code")
		}
	})
	t.Run("success delivered once", func(t *testing.T) {
		ch := make(chan result, 1)
		h := callbackHandler("good", ch)
		h(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/callback?state=good&code=abc", nil))
		r := <-ch
		if r.err != nil || r.code != "abc" {
			t.Errorf("result = %+v, want code abc", r)
		}
	})
	t.Run("non-callback path 404", func(t *testing.T) {
		ch := make(chan result, 1)
		h := callbackHandler("good", ch)
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rec.Code)
		}
	})
}

// TestAccountIDFromIDToken covers the JWT claim extraction edge cases.
func TestAccountIDFromIDToken(t *testing.T) {
	if got := accountIDFromIDToken(makeIDToken(t, "acc-1")); got != "acc-1" {
		t.Errorf("valid token = %q, want acc-1", got)
	}
	for name, tok := range map[string]string{
		"not a jwt":       "notajwt",
		"two segments":    "a.b",
		"bad base64":      "a.!!!.c",
		"payload no auth": "h." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`)) + ".s",
	} {
		if got := accountIDFromIDToken(tok); got != "" {
			t.Errorf("%s: got %q, want empty", name, got)
		}
	}
}

// TestAuthorizeURLParams confirms the authorize URL carries the required
// identity + PKCE params.
func TestAuthorizeURLParams(t *testing.T) {
	l := NewLogin(WithAuthBase("https://auth.example"))
	raw := l.authorizeURL("http://localhost:1455/auth/callback", "chal", "st")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !strings.HasPrefix(raw, "https://auth.example/oauth/authorize?") {
		t.Errorf("base = %s", raw)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"response_type": "code", "code_challenge": "chal", "code_challenge_method": "S256",
		"state": "st", "id_token_add_organizations": "true", "scope": loginScope,
	} {
		if q.Get(k) != want {
			t.Errorf("param %s = %q, want %q", k, q.Get(k), want)
		}
	}
}
