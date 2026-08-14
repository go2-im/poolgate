// Package oauth performs OAuth access-token refresh for pooled accounts.
//
// The token endpoint is PINNED to the configured issuer (default
// https://auth.openai.com/oauth/token, DESIGN.md §6 / §0 D6): any `iss` claim
// inside an imported id_token is ignored — poolgate never derives the refresh
// URL from token contents. Each account has a per-account single-flight so
// concurrent 401s (and any future health-probe refresh) coalesce into ONE HTTP
// refresh; the rotated refresh_token is persisted atomically (store.UpdateTokens
// runs inside a transaction) BEFORE any waiter is released. Reusing a rotated
// refresh_token permanently bricks the account, so coalescing is a correctness
// requirement, not an optimization (DESIGN.md §19.3).
package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// DefaultClientID is Codex's OAuth client id used for the refresh_token grant
// (verified against openai/codex login/src/auth/manager.rs).
const DefaultClientID = "app_EMoamEEZ73f0CkXaXp7hrann"

// TokenStore is the persistence surface oauth needs: atomic rotation write.
// *store.Store satisfies it.
type TokenStore interface {
	UpdateTokens(ctx context.Context, id, accessToken, refreshToken string) error
}

// Refresher refreshes account access tokens against a pinned issuer, coalescing
// concurrent refreshes per account.
type Refresher struct {
	store    TokenStore
	issuer   string // PINNED token endpoint; never derived from token `iss`
	clientID string
	httpc    *http.Client

	sf singleflight
}

// Option customizes a Refresher.
type Option func(*Refresher)

// WithHTTPClient overrides the HTTP client (tests inject an httptest client).
func WithHTTPClient(c *http.Client) Option { return func(r *Refresher) { r.httpc = c } }

// WithClientID overrides the OAuth client id.
func WithClientID(id string) Option { return func(r *Refresher) { r.clientID = id } }

// NewRefresher builds a Refresher. issuer is the PINNED token endpoint URL
// (e.g. cfg.Issuer); it is used verbatim and never taken from token claims.
func NewRefresher(st TokenStore, issuer string, opts ...Option) *Refresher {
	r := &Refresher{
		store:    st,
		issuer:   issuer,
		clientID: DefaultClientID,
		httpc:    &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// refreshRequest is the JSON body Codex sends to the token endpoint.
type refreshRequest struct {
	ClientID     string `json:"client_id"`
	GrantType    string `json:"grant_type"`
	RefreshToken string `json:"refresh_token"`
}

// refreshResponse mirrors the issuer's token response. All fields are optional;
// a rotated refresh_token may or may not be present.
type refreshResponse struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// RefreshAccount refreshes acct's tokens and returns the updated account. It is
// single-flighted per acct.ID: concurrent calls for the same account share ONE
// HTTP refresh and the same result. The rotated refresh_token is committed
// atomically before this returns.
func (r *Refresher) RefreshAccount(ctx context.Context, acct model.Account) (model.Account, error) {
	return r.sf.Do(acct.ID, func() (model.Account, error) {
		return r.refresh(ctx, acct)
	})
}

func (r *Refresher) refresh(ctx context.Context, acct model.Account) (model.Account, error) {
	if acct.RefreshToken == "" {
		return acct, fmt.Errorf("oauth: account %q has no refresh token", acct.ID)
	}

	body, err := json.Marshal(refreshRequest{
		ClientID:     r.clientID,
		GrantType:    "refresh_token",
		RefreshToken: acct.RefreshToken,
	})
	if err != nil {
		return acct, fmt.Errorf("oauth: marshal refresh request: %w", err)
	}

	// issuer is used verbatim — the token's `iss` claim is deliberately ignored.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.issuer, bytes.NewReader(body))
	if err != nil {
		return acct, fmt.Errorf("oauth: build refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.httpc.Do(req)
	if err != nil {
		return acct, fmt.Errorf("oauth: refresh request: %w", err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return acct, fmt.Errorf("oauth: refresh failed: status %d: %s", resp.StatusCode, string(rawBody))
	}

	var rr refreshResponse
	if err := json.Unmarshal(rawBody, &rr); err != nil {
		return acct, fmt.Errorf("oauth: decode refresh response: %w", err)
	}
	if rr.AccessToken == "" {
		return acct, fmt.Errorf("oauth: refresh response missing access_token")
	}

	// Rotation may or may not return a new refresh_token; keep the old one when
	// the issuer does not rotate it (mirrors Codex behavior).
	newRefresh := rr.RefreshToken
	if newRefresh == "" {
		newRefresh = acct.RefreshToken
	}

	// Persist ATOMICALLY before returning so waiters never observe a
	// half-rotated state (DESIGN.md §19.3 / §0 D6).
	if err := r.store.UpdateTokens(ctx, acct.ID, rr.AccessToken, newRefresh); err != nil {
		return acct, fmt.Errorf("oauth: persist rotated tokens: %w", err)
	}

	acct.AccessToken = rr.AccessToken
	acct.RefreshToken = newRefresh
	if rr.IDToken != "" {
		acct.IDToken = rr.IDToken
	}
	acct.UpdatedAt = time.Now().UTC()
	return acct, nil
}

// ---- single-flight --------------------------------------------------------

// singleflight coalesces concurrent calls sharing the same key into one
// execution, delivering the shared result to every caller. It is a minimal
// stand-in for golang.org/x/sync/singleflight to avoid a dependency.
type singleflight struct {
	mu sync.Mutex
	m  map[string]*sfCall
}

type sfCall struct {
	wg   sync.WaitGroup
	acct model.Account
	err  error
}

func (g *singleflight) Do(key string, fn func() (model.Account, error)) (model.Account, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*sfCall)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.acct, c.err
	}
	c := &sfCall{}
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	c.acct, c.err = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	return c.acct, c.err
}
