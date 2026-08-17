package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/config"
	"github.com/go2-im/poolgate/internal/crypto"
	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/store"
)

// fakeStore is a minimal TokenStore that records the last UpdateTokens call and
// can be programmed to fail, so the persist-error path is exercised without the
// real SQLite store.
type fakeStore struct {
	err        error
	calls      int
	gotID      string
	gotAccess  string
	gotRefresh string

	// getAcct, when set, is returned by GetAccount (used to simulate the current
	// stored account). When nil, GetAccount returns getErr (default: a not-found
	// error). refresh() fails closed on a GetAccount error, so tests that expect a
	// successful refresh must seed getAcct with the account under refresh.
	getAcct *model.Account
	getErr  error
}

func (f *fakeStore) GetAccount(_ context.Context, id string) (model.Account, error) {
	if f.getAcct != nil {
		return *f.getAcct, nil
	}
	if f.getErr != nil {
		return model.Account{}, f.getErr
	}
	return model.Account{}, errors.New("not found")
}

func (f *fakeStore) UpdateTokens(_ context.Context, id, accessToken, refreshToken string) error {
	f.calls++
	f.gotID = id
	f.gotAccess = accessToken
	f.gotRefresh = refreshToken
	return f.err
}

// newTestStore builds an on-disk store in a temp dir with a random key.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	cipher, err := crypto.New(key)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	st, err := store.Open(cfg, cipher)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// jwtWithIss builds a minimal unsigned JWT carrying an `iss` claim, to prove the
// refresher ignores it when building the token endpoint URL.
func jwtWithIss(iss string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadJSON, _ := json.Marshal(map[string]string{"iss": iss})
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	return header + "." + payload + "."
}

func TestRefreshUsesPinnedIssuerIgnoringTokenIss(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		var req refreshRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.GrantType != "refresh_token" {
			t.Errorf("grant_type = %q, want refresh_token", req.GrantType)
		}
		if req.RefreshToken != "rt-original" {
			t.Errorf("refresh_token = %q, want rt-original", req.RefreshToken)
		}
		_ = json.NewEncoder(w).Encode(refreshResponse{
			AccessToken:  "at-new",
			RefreshToken: "rt-rotated",
		})
	}))
	defer srv.Close()

	acct, err := st.InsertAccount(ctx, model.Account{
		AccessToken:  "at-old",
		RefreshToken: "rt-original",
		// A hostile id_token pointing at a different issuer — must be ignored.
		IDToken: jwtWithIss("https://evil.example.com"),
		State:   model.StateOK,
	})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}

	// issuer is PINNED to the httptest server URL (stands in for auth.openai.com).
	r := NewRefresher(st, srv.URL, WithHTTPClient(srv.Client()))
	updated, err := r.RefreshAccount(ctx, acct)
	if err != nil {
		t.Fatalf("RefreshAccount: %v", err)
	}

	// The request must have hit the pinned issuer path, NOT anything derived
	// from the id_token's iss claim.
	if gotPath != "/" {
		t.Errorf("token endpoint path = %q, want / (pinned issuer)", gotPath)
	}
	if updated.AccessToken != "at-new" || updated.RefreshToken != "rt-rotated" {
		t.Errorf("tokens not updated: %+v", updated)
	}

	// Rotated tokens must be persisted atomically before returning.
	reloaded, err := st.GetAccount(ctx, acct.ID)
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if reloaded.AccessToken != "at-new" || reloaded.RefreshToken != "rt-rotated" {
		t.Errorf("persisted tokens = %q/%q, want at-new/rt-rotated",
			reloaded.AccessToken, reloaded.RefreshToken)
	}
}

func TestRefreshSingleFlightCoalesces(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	var calls int64
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		<-release // hold the handler so concurrent callers pile up on one in-flight call
		_ = json.NewEncoder(w).Encode(refreshResponse{AccessToken: "at-new", RefreshToken: "rt-new"})
	}))
	defer srv.Close()

	acct, err := st.InsertAccount(ctx, model.Account{
		AccessToken:  "at-old",
		RefreshToken: "rt-old",
		State:        model.StateOK,
	})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}

	r := NewRefresher(st, srv.URL, WithHTTPClient(srv.Client()))

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = r.RefreshAccount(ctx, acct)
		}(i)
	}
	// Let all callers pile up on the single in-flight call before unblocking the
	// handler (same idiom as golang.org/x/sync/singleflight's own tests). The
	// handler holds `release`, so the first call stays in-flight and the rest
	// coalesce onto it.
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()

	for i, e := range errs {
		if e != nil {
			t.Errorf("caller %d error: %v", i, e)
		}
	}
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Errorf("HTTP refresh calls = %d, want 1 (single-flight coalesced)", got)
	}
}

// TestWithClientID verifies the option overrides the client_id sent to the
// issuer (default is DefaultClientID).
func TestWithClientID(t *testing.T) {
	ctx := context.Background()

	var gotClientID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req refreshRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotClientID = req.ClientID
		_ = json.NewEncoder(w).Encode(refreshResponse{AccessToken: "at-new"})
	}))
	defer srv.Close()

	acct := model.Account{ID: "acct-1", RefreshToken: "rt-old", State: model.StateOK}
	fs := &fakeStore{getAcct: &acct}
	r := NewRefresher(fs, srv.URL, WithHTTPClient(srv.Client()), WithClientID("custom-client"))
	_, err := r.RefreshAccount(ctx, acct)
	if err != nil {
		t.Fatalf("RefreshAccount: %v", err)
	}
	if gotClientID != "custom-client" {
		t.Errorf("client_id = %q, want custom-client", gotClientID)
	}
}

// TestRefreshAdoptsAlreadyRotatedTokensWithoutReusingOldRefresh verifies that a
// staggered caller holding a stale snapshot adopts the already-rotated stored
// tokens instead of hitting the issuer again with a consumed refresh_token.
func TestRefreshAdoptsAlreadyRotatedTokensWithoutReusingOldRefresh(t *testing.T) {
	ctx := context.Background()

	var issuerHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuerHits++
		_ = json.NewEncoder(w).Encode(refreshResponse{AccessToken: "at-should-not-happen"})
	}))
	defer srv.Close()

	// Stored tokens have already moved on from the caller's stale snapshot.
	rotated := model.Account{ID: "acct-1", AccessToken: "at-new", RefreshToken: "rt-new", State: model.StateOK}
	fs := &fakeStore{getAcct: &rotated}
	r := NewRefresher(fs, srv.URL, WithHTTPClient(srv.Client()))

	stale := model.Account{ID: "acct-1", AccessToken: "at-old", RefreshToken: "rt-old", State: model.StateOK}
	got, err := r.RefreshAccount(ctx, stale)
	if err != nil {
		t.Fatalf("RefreshAccount: %v", err)
	}
	if got.AccessToken != "at-new" || got.RefreshToken != "rt-new" {
		t.Errorf("adopted tokens = %q/%q, want at-new/rt-new", got.AccessToken, got.RefreshToken)
	}
	if issuerHits != 0 {
		t.Errorf("issuer hit %d times; a stale caller must NOT reuse the old refresh_token", issuerHits)
	}
	if fs.calls != 0 {
		t.Errorf("UpdateTokens called %d times; adoption should not persist", fs.calls)
	}
}

// TestSingleflightPanicDoesNotWedgeWaiters verifies a panic in the refresh
// function is converted to an error and never leaves the singleflight entry
// wedged (which would block all future callers forever).
func TestSingleflightPanicDoesNotWedgeWaiters(t *testing.T) {
	var g singleflight
	_, err := g.Do("k", func() (model.Account, error) {
		panic("boom")
	})
	if err == nil {
		t.Fatal("panic should surface as an error")
	}
	// A subsequent call for the same key must proceed (entry not wedged).
	done := make(chan struct{})
	go func() {
		_, _ = g.Do("k", func() (model.Account, error) {
			return model.Account{ID: "ok"}, nil
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("second Do wedged after a prior panic")
	}
}

// TestRefreshFailsClosedWhenReReadFails verifies that if the authoritative
// GetAccount re-read fails, refresh aborts and never sends the caller's
// (possibly stale) refresh_token to the issuer.
func TestRefreshFailsClosedWhenReReadFails(t *testing.T) {
	ctx := context.Background()
	var issuerHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuerHits++
		_ = json.NewEncoder(w).Encode(refreshResponse{AccessToken: "at-new"})
	}))
	defer srv.Close()

	fs := &fakeStore{getErr: errors.New("db temporarily unavailable")}
	r := NewRefresher(fs, srv.URL, WithHTTPClient(srv.Client()))
	_, err := r.RefreshAccount(ctx, model.Account{ID: "acct-1", AccessToken: "at-old", RefreshToken: "rt-old", State: model.StateOK})
	if err == nil {
		t.Fatal("refresh must fail closed when the authoritative re-read fails")
	}
	if issuerHits != 0 {
		t.Errorf("issuer hit %d times; must not send the stale refresh_token when re-read failed", issuerHits)
	}
	if fs.calls != 0 {
		t.Errorf("UpdateTokens called %d times; refresh should have aborted", fs.calls)
	}
}

// TestRefreshKeepsOldRefreshTokenWhenNotRotated verifies that when the issuer
// omits a rotated refresh_token, the existing one is preserved and persisted.
func TestRefreshKeepsOldRefreshTokenWhenNotRotated(t *testing.T) {
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No refresh_token in the response, no id_token either.
		_ = json.NewEncoder(w).Encode(refreshResponse{AccessToken: "at-new"})
	}))
	defer srv.Close()

	acct := model.Account{ID: "acct-1", AccessToken: "at-old", RefreshToken: "rt-keep", IDToken: "id-old", State: model.StateOK}
	fs := &fakeStore{getAcct: &acct}
	r := NewRefresher(fs, srv.URL, WithHTTPClient(srv.Client()))
	updated, err := r.RefreshAccount(ctx, acct)
	if err != nil {
		t.Fatalf("RefreshAccount: %v", err)
	}
	if updated.AccessToken != "at-new" {
		t.Errorf("access token = %q, want at-new", updated.AccessToken)
	}
	if updated.RefreshToken != "rt-keep" {
		t.Errorf("refresh token = %q, want rt-keep (unrotated, preserved)", updated.RefreshToken)
	}
	// id_token was empty in the response, so the original must be preserved.
	if updated.IDToken != "id-old" {
		t.Errorf("id_token = %q, want id-old (preserved)", updated.IDToken)
	}
	// UpdatedAt must be stamped.
	if updated.UpdatedAt.IsZero() {
		t.Error("UpdatedAt not stamped")
	}
	if fs.calls != 1 || fs.gotRefresh != "rt-keep" || fs.gotAccess != "at-new" {
		t.Errorf("UpdateTokens got id=%q access=%q refresh=%q calls=%d",
			fs.gotID, fs.gotAccess, fs.gotRefresh, fs.calls)
	}
}

// TestRefreshErrorPaths table-drives every failure branch in refresh().
func TestRefreshErrorPaths(t *testing.T) {
	tests := []struct {
		name       string
		acct       model.Account
		issuer     string // if empty, an httptest server URL is substituted
		handler    http.HandlerFunc
		storeErr   error
		closeSrv   bool // close the server before the call to force a transport error
		wantSubstr string
		wantCalls  int // expected UpdateTokens calls
	}{
		{
			name:       "no refresh token",
			acct:       model.Account{ID: "a", RefreshToken: ""},
			issuer:     "http://unused.example",
			wantSubstr: "has no refresh token",
		},
		{
			name:       "build request bad url",
			acct:       model.Account{ID: "a", RefreshToken: "rt"},
			issuer:     "http://\x7f-bad-control-char",
			wantSubstr: "build refresh request",
		},
		{
			name:       "transport error",
			acct:       model.Account{ID: "a", RefreshToken: "rt"},
			handler:    func(w http.ResponseWriter, r *http.Request) {},
			closeSrv:   true,
			wantSubstr: "refresh request",
		},
		{
			name: "non-200 status invalid_grant",
			acct: model.Account{ID: "a", RefreshToken: "rt"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			},
			wantSubstr: "refresh failed: status 400",
		},
		{
			name: "invalid json body",
			acct: model.Account{ID: "a", RefreshToken: "rt"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`not-json{`))
			},
			wantSubstr: "decode refresh response",
		},
		{
			name: "missing access_token",
			acct: model.Account{ID: "a", RefreshToken: "rt"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(refreshResponse{RefreshToken: "rt-rotated"})
			},
			wantSubstr: "missing access_token",
		},
		{
			name: "persist error",
			acct: model.Account{ID: "a", RefreshToken: "rt"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(refreshResponse{AccessToken: "at-new", RefreshToken: "rt-new"})
			},
			storeErr:   errors.New("db locked"),
			wantSubstr: "persist rotated tokens",
			wantCalls:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			fs := &fakeStore{err: tt.storeErr, getAcct: &tt.acct}

			issuer := tt.issuer
			var opts []Option
			if tt.handler != nil {
				srv := httptest.NewServer(tt.handler)
				defer srv.Close()
				issuer = srv.URL
				opts = append(opts, WithHTTPClient(srv.Client()))
				if tt.closeSrv {
					srv.Close() // now Do() hits a closed listener -> transport error
				}
			}

			r := NewRefresher(fs, issuer, opts...)
			_, err := r.RefreshAccount(ctx, tt.acct)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantSubstr)
			}
			if !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantSubstr)
			}
			if fs.calls != tt.wantCalls {
				t.Errorf("UpdateTokens calls = %d, want %d", fs.calls, tt.wantCalls)
			}
		})
	}
}
