package admin

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// fakeOAuthLogin is a scriptable OAuthLogin. It optionally prompts with an
// authorize URL, can block "in progress" until release is closed (to exercise the
// single-flight 409 and pending status), and returns a canned account/error.
type fakeOAuthLogin struct {
	authorizeURL string
	account      model.Account
	err          error
	release      chan struct{} // when non-nil, Run blocks until closed or ctx done
}

func (f *fakeOAuthLogin) Run(ctx context.Context, prompt func(string)) (model.Account, error) {
	if f.authorizeURL != "" && prompt != nil {
		prompt(f.authorizeURL)
	}
	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			return model.Account{}, ctx.Err()
		}
	}
	return f.account, f.err
}

// waitLoginStatus polls the status endpoint until it is no longer "pending".
func waitLoginStatus(t *testing.T, h *harness, cookie *http.Cookie, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		rec := h.do("GET", "/admin/api/accounts/login/status?id="+id, nil, func(r *http.Request) {
			r.AddCookie(cookie)
		})
		m := decodeBody(t, rec)
		if m["status"] != "pending" {
			return m
		}
		if time.Now().After(deadline) {
			t.Fatalf("login status still pending after 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAccountLoginUnavailable(t *testing.T) {
	h := newHarness(t) // no WithOAuthLogin
	cookie, csrf := h.authed()
	rec := h.do("POST", "/admin/api/accounts/login/begin", map[string]any{}, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("begin without OAuthLogin = %d, want 503", rec.Code)
	}
}

func TestAccountLoginBeginAndSucceed(t *testing.T) {
	fake := &fakeOAuthLogin{
		authorizeURL: "https://auth.openai.com/oauth/authorize?x=1",
		account:      model.Account{AccountID: "acc-1", AccessToken: "at", RefreshToken: "rt"},
	}
	h := newHarness(t, WithOAuthLogin(fake))
	cookie, csrf := h.authed()

	rec := h.do("POST", "/admin/api/accounts/login/begin", map[string]any{"label": "laptop"}, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("begin = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	m := decodeBody(t, rec)
	if m["authorize_url"] != fake.authorizeURL {
		t.Fatalf("authorize_url = %v, want %q", m["authorize_url"], fake.authorizeURL)
	}
	id, _ := m["login_id"].(string)
	if id == "" {
		t.Fatal("begin returned empty login_id")
	}

	st := waitLoginStatus(t, h, cookie, id)
	if st["status"] != "success" {
		t.Fatalf("status = %v, want success (%v)", st["status"], st)
	}
	acct, _ := st["account"].(map[string]any)
	if acct["account_id"] != "acc-1" || acct["label"] != "laptop" {
		t.Fatalf("stored account view = %v, want account_id=acc-1 label=laptop", acct)
	}
	// The account is actually pooled.
	if got, err := h.store.ListAccounts(context.Background()); err != nil || len(got) != 1 {
		t.Fatalf("ListAccounts = %d,%v; want 1,nil", len(got), err)
	}
}

func TestAccountLoginInFlightConflict(t *testing.T) {
	fake := &fakeOAuthLogin{
		authorizeURL: "https://auth.openai.com/oauth/authorize?x=1",
		account:      model.Account{AccountID: "acc-1"},
		release:      make(chan struct{}),
	}
	h := newHarness(t, WithOAuthLogin(fake))
	cookie, csrf := h.authed()
	mut := func(r *http.Request) { r.AddCookie(cookie); r.Header.Set(CSRFHeaderName, csrf) }

	rec := h.do("POST", "/admin/api/accounts/login/begin", map[string]any{}, mut)
	if rec.Code != http.StatusOK {
		t.Fatalf("first begin = %d, want 200", rec.Code)
	}
	id := decodeBody(t, rec)["login_id"].(string)

	// A second begin while the first is still in flight is refused.
	rec2 := h.do("POST", "/admin/api/accounts/login/begin", map[string]any{}, mut)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("concurrent begin = %d, want 409", rec2.Code)
	}
	// Status is pending while Run blocks.
	recS := h.do("GET", "/admin/api/accounts/login/status?id="+id, nil, func(r *http.Request) { r.AddCookie(cookie) })
	if decodeBody(t, recS)["status"] != "pending" {
		t.Fatalf("status while in flight = %v, want pending", recS.Body.String())
	}

	// Release the ceremony; it completes and stores the account.
	close(fake.release)
	if st := waitLoginStatus(t, h, cookie, id); st["status"] != "success" {
		t.Fatalf("status after release = %v, want success", st)
	}
}

func TestAccountLoginDuplicateAndError(t *testing.T) {
	// Duplicate: the ceremony yields an account whose ChatGPT id is already pooled.
	dup := &fakeOAuthLogin{authorizeURL: "u", account: model.Account{AccountID: "dupe"}}
	h := newHarness(t, WithOAuthLogin(dup))
	if _, err := h.store.InsertAccountUnique(context.Background(), model.Account{AccountID: "dupe", Label: "existing"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cookie, csrf := h.authed()
	rec := h.do("POST", "/admin/api/accounts/login/begin", map[string]any{}, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	id := decodeBody(t, rec)["login_id"].(string)
	st := waitLoginStatus(t, h, cookie, id)
	if st["status"] != "error" || st["error"] == "" {
		t.Fatalf("duplicate status = %v, want error", st)
	}

	// Unknown id → 404.
	recNF := h.do("GET", "/admin/api/accounts/login/status?id=nope", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if recNF.Code != http.StatusNotFound {
		t.Fatalf("status unknown id = %d, want 404", recNF.Code)
	}
}

func TestAccountLoginRunError(t *testing.T) {
	fake := &fakeOAuthLogin{authorizeURL: "u", err: context.DeadlineExceeded}
	h := newHarness(t, WithOAuthLogin(fake))
	cookie, csrf := h.authed()
	rec := h.do("POST", "/admin/api/accounts/login/begin", map[string]any{}, func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set(CSRFHeaderName, csrf)
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("begin = %d, want 200", rec.Code)
	}
	id := decodeBody(t, rec)["login_id"].(string)
	if st := waitLoginStatus(t, h, cookie, id); st["status"] != "error" {
		t.Fatalf("status after Run error = %v, want error", st)
	}
}
