// login.go implements the interactive OAuth authorization-code + PKCE login
// (DESIGN.md §0 fixes / §23.6): a loopback callback on 127.0.0.1, a single-use
// random `state`, and an S256 code challenge. It lets an operator add a pooled
// account by signing in through the browser instead of pasting a Codex
// auth.json. The token endpoint and client id are the same pinned values the
// refresh path uses; the authorize base is likewise pinned and never derived
// from any token contents.
//
// The exact wire flow is verified against openai/codex (codex-rs/login):
// authorize at {authBase}/oauth/authorize with response_type=code, S256 PKCE,
// scope "openid profile email offline_access ...", redirect_uri
// http://localhost:{port}/auth/callback (port 1455, fallback 1457); the
// authorization_code exchange POSTs form-urlencoded to {authBase}/oauth/token;
// the ChatGPT account id is read from the id_token's
// "https://api.openai.com/auth".chatgpt_account_id claim.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// DefaultAuthBase is the PINNED OAuth base (authorize + token live under it). It
// is never derived from token contents (DESIGN.md §0 D6).
const DefaultAuthBase = "https://auth.openai.com"

// loginScope mirrors the Codex CLI's requested scopes. offline_access is what
// yields a refresh_token; the rest match the known-good client so the authorize
// server accepts the request.
const loginScope = "openid profile email offline_access"

// defaultCallbackPorts are the loopback ports registered for the Codex client's
// redirect_uri, tried in order. The redirect_uri host is always 127.0.0.1's
// "localhost" per the registration.
var defaultCallbackPorts = []int{1455, 1457}

// Login runs the interactive authorization-code + PKCE flow. Construct with
// NewLogin; the zero value is not usable.
type Login struct {
	authBase   string
	clientID   string
	originator string
	scope      string
	httpc      *http.Client
	now        func() time.Time
	ports      []int
	randRead   func([]byte) (int, error)
}

// LoginOption customizes a Login.
type LoginOption func(*Login)

// WithLoginHTTPClient overrides the HTTP client used for the token exchange.
func WithLoginHTTPClient(c *http.Client) LoginOption { return func(l *Login) { l.httpc = c } }

// WithAuthBase overrides the pinned authorize/token base URL (tests point it at
// an httptest server).
func WithAuthBase(base string) LoginOption {
	return func(l *Login) { l.authBase = strings.TrimRight(base, "/") }
}

// WithLoginClientID overrides the OAuth client id.
func WithLoginClientID(id string) LoginOption { return func(l *Login) { l.clientID = id } }

// WithCallbackPorts overrides the loopback callback ports tried in order. Tests
// pass {0} to bind an ephemeral port.
func WithCallbackPorts(ports ...int) LoginOption {
	return func(l *Login) {
		if len(ports) > 0 {
			l.ports = ports
		}
	}
}

// WithLoginClock injects the clock (default time.Now), used for account
// timestamps.
func WithLoginClock(now func() time.Time) LoginOption { return func(l *Login) { l.now = now } }

// WithLoginRand injects the randomness source for the PKCE verifier and state
// (default crypto/rand). Tests inject a deterministic reader.
func WithLoginRand(read func([]byte) (int, error)) LoginOption {
	return func(l *Login) { l.randRead = read }
}

// NewLogin builds a Login with the pinned Codex defaults.
func NewLogin(opts ...LoginOption) *Login {
	l := &Login{
		authBase:   DefaultAuthBase,
		clientID:   DefaultClientID,
		originator: "codex_cli_rs",
		scope:      loginScope,
		httpc:      &http.Client{Timeout: 30 * time.Second},
		now:        time.Now,
		ports:      defaultCallbackPorts,
		randRead:   rand.Read,
	}
	for _, o := range opts {
		o(l)
	}
	return l
}

// Run performs the full flow: it binds a loopback callback listener, builds the
// authorize URL (passed to prompt so the caller can print/open it), waits for
// the browser redirect, validates the single-use state, exchanges the code, and
// returns a model.Account carrying the fresh tokens. It blocks until the
// callback arrives or ctx is done.
func (l *Login) Run(ctx context.Context, prompt func(authorizeURL string)) (model.Account, error) {
	verifier, err := l.randomURLSafe(64)
	if err != nil {
		return model.Account{}, fmt.Errorf("oauth: generate PKCE verifier: %w", err)
	}
	state, err := l.randomURLSafe(32)
	if err != nil {
		return model.Account{}, fmt.Errorf("oauth: generate state: %w", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	ln, port, err := l.listen()
	if err != nil {
		return model.Account{}, err
	}
	defer ln.Close()

	redirectURI := fmt.Sprintf("http://localhost:%d/auth/callback", port)
	authorizeURL := l.authorizeURL(redirectURI, challenge, state)

	// The callback handler validates state and delivers the code exactly once.
	results := make(chan result, 1)
	srv := &http.Server{Handler: callbackHandler(state, results)}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	// The redirect_uri advertises "localhost", which may resolve to ::1 first on
	// some hosts. Also accept the callback on the IPv6 loopback (same port, still
	// loopback-only) so the browser reaches us regardless of resolution order.
	if ln6, err6 := net.Listen("tcp", fmt.Sprintf("[::1]:%d", port)); err6 == nil {
		defer ln6.Close()
		go func() { _ = srv.Serve(ln6) }()
	}

	if prompt != nil {
		prompt(authorizeURL)
	}

	var code string
	select {
	case <-ctx.Done():
		return model.Account{}, ctx.Err()
	case r := <-results:
		if r.err != nil {
			return model.Account{}, r.err
		}
		code = r.code
	}

	tok, err := l.exchange(ctx, code, redirectURI, verifier)
	if err != nil {
		return model.Account{}, err
	}
	return l.accountFromToken(tok), nil
}

// accountFromToken builds the pooled account carrying the freshly issued tokens.
// State starts Unknown so the health engine converges it on the first probe.
// Shared by the loopback (Run) and headless (CompleteManual) flows.
func (l *Login) accountFromToken(tok tokenResponse) model.Account {
	now := l.now().UTC()
	return model.Account{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		IDToken:      tok.IDToken,
		AccountID:    accountIDFromIDToken(tok.IDToken),
		State:        model.StateUnknown,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// ManualLogin is a headless (no-listener) login in progress. It holds the PKCE
// verifier, the single-use state, and the redirect_uri used to build the
// authorize URL so CompleteManual can validate the returned state and exchange
// the code. Treat it as opaque: obtain it from BeginManual and hand it back to
// CompleteManual.
type ManualLogin struct {
	verifier     string
	state        string
	redirectURI  string
	authorizeURL string
}

// AuthorizeURL is the URL the operator opens in a browser to sign in.
func (m *ManualLogin) AuthorizeURL() string { return m.authorizeURL }

// BeginManual starts a headless login: it builds the PKCE material + authorize
// URL against the first registered loopback redirect_uri (127.0.0.1:1455) WITHOUT
// binding a listener. Because nothing answers the loopback redirect on the
// operator's machine, they copy the resulting redirect URL (which carries
// ?code=&state=) back to CompleteManual — the "headless handoff" that works when
// the browser is NOT on the poolgate host (DESIGN §23.6). No port is bound, so
// multiple manual logins may be outstanding.
func (l *Login) BeginManual() (*ManualLogin, error) {
	verifier, err := l.randomURLSafe(64)
	if err != nil {
		return nil, fmt.Errorf("oauth: generate PKCE verifier: %w", err)
	}
	state, err := l.randomURLSafe(32)
	if err != nil {
		return nil, fmt.Errorf("oauth: generate state: %w", err)
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	redirectURI := fmt.Sprintf("http://localhost:%d/auth/callback", l.ports[0])
	return &ManualLogin{
		verifier:     verifier,
		state:        state,
		redirectURI:  redirectURI,
		authorizeURL: l.authorizeURL(redirectURI, challenge, state),
	}, nil
}

// CompleteManual validates the operator-pasted redirect (the full URL the browser
// was sent to, carrying code+state) against the pending login and exchanges the
// authorization code for tokens. The state MUST match (single-use CSRF guard); an
// OAuth error in the redirect, a state mismatch, or a missing code is rejected
// without an exchange.
func (l *Login) CompleteManual(ctx context.Context, m *ManualLogin, redirected string) (model.Account, error) {
	if m == nil {
		return model.Account{}, errors.New("oauth: nil manual login")
	}
	code, err := extractCallbackCode(redirected, m.state)
	if err != nil {
		return model.Account{}, err
	}
	tok, err := l.exchange(ctx, code, m.redirectURI, m.verifier)
	if err != nil {
		return model.Account{}, err
	}
	return l.accountFromToken(tok), nil
}

// extractCallbackCode parses the operator-pasted OAuth redirect and returns the
// authorization code after checking its state against wantState. It accepts the
// full redirect URL, a bare query string, or "?code=…&state=…", and requires a
// matching state — a bare code with no state is rejected so the CSRF guard is
// never silently skipped.
func extractCallbackCode(pasted, wantState string) (string, error) {
	pasted = strings.TrimSpace(pasted)
	if pasted == "" {
		return "", errors.New("oauth: empty callback")
	}
	var rawQuery string
	if u, err := url.Parse(pasted); err == nil && u.RawQuery != "" {
		rawQuery = u.RawQuery
	} else if i := strings.IndexByte(pasted, '?'); i >= 0 {
		rawQuery = pasted[i+1:]
	} else {
		rawQuery = pasted
	}
	if i := strings.IndexByte(rawQuery, '#'); i >= 0 {
		rawQuery = rawQuery[:i]
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", fmt.Errorf("oauth: parse callback: %w", err)
	}
	if e := values.Get("error"); e != "" {
		return "", fmt.Errorf("oauth: authorization denied: %s", e)
	}
	if values.Get("state") != wantState {
		return "", errors.New("oauth: state mismatch")
	}
	code := values.Get("code")
	if code == "" {
		return "", errors.New("oauth: callback missing authorization code")
	}
	return code, nil
}

// listen binds the first available loopback port from l.ports.
func (l *Login) listen() (net.Listener, int, error) {
	var lastErr error
	for _, p := range l.ports {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			lastErr = err
			continue
		}
		return ln, ln.Addr().(*net.TCPAddr).Port, nil
	}
	return nil, 0, fmt.Errorf("oauth: bind loopback callback port %v: %w", l.ports, lastErr)
}

// authorizeURL assembles the authorize endpoint URL with the PKCE + identity
// params (verified against openai/codex).
func (l *Login) authorizeURL(redirectURI, challenge, state string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", l.clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", l.scope)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("id_token_add_organizations", "true")
	q.Set("codex_cli_simplified_flow", "true")
	q.Set("originator", l.originator)
	q.Set("state", state)
	return l.authBase + "/oauth/authorize?" + q.Encode()
}

// callbackHandler serves the loopback redirect. It accepts exactly one callback
// whose state matches; anything else gets an error page and does not complete
// the flow (single-use state, DESIGN.md §0 fixes).
func callbackHandler(wantState string, results chan<- result) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/callback" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			deliver(w, results, "", fmt.Errorf("oauth: authorization denied: %s", e), false)
			return
		}
		if q.Get("state") != wantState {
			// A mismatched state may be a stale/forged callback; reject it without
			// completing so the real one can still arrive.
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		code := q.Get("code")
		if code == "" {
			deliver(w, results, "", errors.New("oauth: callback missing authorization code"), false)
			return
		}
		deliver(w, results, code, nil, true)
	}
}

// result is the outcome the callback handler hands back to Run.
type result struct {
	code string
	err  error
}

// deliver writes the browser response and, exactly once, sends the outcome to
// Run. The response is written AND flushed before signaling Run, so the deferred
// srv.Close() in Run cannot truncate the browser page. A full results channel (a
// second callback) is ignored.
func deliver(w http.ResponseWriter, results chan<- result, code string, err error, ok bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if ok {
		_, _ = io.WriteString(w, "<!doctype html><title>poolgate</title><body style=\"font-family:sans-serif\">"+
			"<h2>Signed in.</h2><p>You can close this tab and return to the terminal.</p></body>")
	} else {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "<!doctype html><title>poolgate</title><body style=\"font-family:sans-serif\">"+
			"<h2>Sign-in failed.</h2><p>Return to the terminal for details.</p></body>")
	}
	// Flush the page onto the wire before signaling Run, so a fast return + the
	// deferred srv.Close() cannot reset the connection mid-write.
	if f, okFlush := w.(http.Flusher); okFlush {
		f.Flush()
	}
	select {
	case results <- result{code: code, err: err}:
	default:
		// Already delivered; ignore the duplicate.
	}
}

// tokenResponse is the authorization_code exchange result.
type tokenResponse struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// exchange trades the authorization code for tokens (form-urlencoded POST to the
// pinned token endpoint), including the PKCE code_verifier.
func (l *Login) exchange(ctx context.Context, code, redirectURI, verifier string) (tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", l.clientID)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.authBase+"/oauth/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("oauth: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := l.httpc.Do(req)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("oauth: token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return tokenResponse{}, fmt.Errorf("oauth: token exchange failed: status %d", resp.StatusCode)
	}
	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return tokenResponse{}, fmt.Errorf("oauth: decode token response: %w", err)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		return tokenResponse{}, errors.New("oauth: token response missing access/refresh token")
	}
	return tok, nil
}

// randomURLSafe returns a base64url (no-pad) string from n random bytes. For the
// PKCE verifier n=64 yields ~86 chars, within the RFC 7636 43–128 range.
func (l *Login) randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := l.randRead(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// accountIDFromIDToken extracts chatgpt_account_id from the id_token's
// "https://api.openai.com/auth" claim namespace. It returns "" when the token is
// absent/unparseable or the claim is missing — the caller decides how to warn.
func accountIDFromIDToken(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Auth struct {
			ChatGPTAccountID string `json:"chatgpt_account_id"`
		} `json:"https://api.openai.com/auth"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Auth.ChatGPTAccountID
}
