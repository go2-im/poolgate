package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/config"
	"github.com/go2-im/poolgate/internal/crypto"
	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/store"
)

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
