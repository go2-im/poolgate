// oauthlogin.go implements the admin-UI "sign in with ChatGPT" account import: an
// interactive OAuth authorization-code + PKCE login driven from the browser
// instead of pasting a Codex auth.json (DESIGN.md §23.6). The heavy lifting lives
// in internal/oauth; this layer adapts its blocking Run into a begin/status pair
// the SPA can drive, and stores the resulting account exactly like the auth.json
// import (InsertAccountUnique + audit, 409 on a duplicate ChatGPT account).
//
// IMPORTANT constraint: the OAuth redirect_uri is a FIXED loopback port
// (127.0.0.1:1455, fallback 1457) registered with the Codex OAuth client, so the
// callback must land on the SAME machine as the browser and only ONE login can
// hold the port at a time. begin therefore refuses (409) while a login is in
// flight, and the whole flow only works when the operator's browser is on the
// poolgate host (or tunnels those ports).
package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/store"
)

// OAuthLogin runs the interactive OAuth authorization-code + PKCE browser login
// and returns the resulting pooled account. An adapter over *oauth.Login
// satisfies it; it is kept an interface (with an opaque handle for the headless
// flow) so this package stays decoupled from internal/oauth and is testable
// against a fake.
type OAuthLogin interface {
	// Run drives the loopback (co-located) flow: it binds the callback, invokes
	// prompt with the authorize URL, waits for the redirect, exchanges the code,
	// and returns the account. It blocks until the callback arrives or ctx is done.
	Run(ctx context.Context, prompt func(authorizeURL string)) (model.Account, error)
	// BeginManual starts the headless (no-listener) flow for a browser that is NOT
	// on this host: it returns the authorize URL to open plus an opaque handle to
	// pass back to CompleteManual. It binds no port.
	BeginManual() (authorizeURL string, handle any, err error)
	// CompleteManual validates the operator-pasted redirect URL against the handle
	// (single-use state check) and exchanges the code for the account.
	CompleteManual(ctx context.Context, handle any, redirected string) (model.Account, error)
}

// oauthLoginTimeout bounds how long a started login may wait for the browser
// callback before it is abandoned and the loopback port freed.
const oauthLoginTimeout = 5 * time.Minute

// oauthLoginState is the single in-flight (or most-recent) UI OAuth login. Only
// one exists at a time because the loopback callback port is exclusive. All
// fields are guarded by Server.oauthMu.
type oauthLoginState struct {
	id      string
	done    bool
	account *accountView // set on success
	errMsg  string       // set on failure (client-safe, no upstream detail)
	cancel  context.CancelFunc
}

// oauthBeginReq is the body of POST /admin/api/accounts/login/begin.
type oauthBeginReq struct {
	Label string `json:"label"`
}

// handleAccountLoginBegin starts an interactive OAuth login. It launches the
// blocking ceremony in the background, returns the authorize URL (for the SPA to
// open) plus a login id to poll, and refuses (409) while another login is in
// flight. Requires a wired OAuthLogin (503 otherwise).
func (s *Server) handleAccountLoginBegin(w http.ResponseWriter, r *http.Request) {
	if s.oauthLogin == nil {
		writeErr(w, http.StatusServiceUnavailable, errInternal, "interactive sign-in is not available")
		return
	}
	var req oauthBeginReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid request body")
		return
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		label = "login-" + s.now().UTC().Format("20060102-150405")
	}

	s.oauthMu.Lock()
	if s.oauthState != nil && !s.oauthState.done {
		s.oauthMu.Unlock()
		writeErr(w, http.StatusConflict, errConflict, "a sign-in is already in progress")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), oauthLoginTimeout)
	st := &oauthLoginState{id: newOAuthLoginID(), cancel: cancel}
	s.oauthState = st
	s.oauthMu.Unlock()

	urlCh := make(chan string, 1)
	doneCh := make(chan struct{})
	go func() {
		acct, err := s.oauthLogin.Run(ctx, func(u string) {
			select {
			case urlCh <- u:
			default:
			}
		})
		s.finalizeOAuthLogin(st, label, acct, err)
		cancel()
		close(doneCh)
	}()

	select {
	case u := <-urlCh:
		writeJSON(w, http.StatusOK, map[string]any{"login_id": st.id, "authorize_url": u})
	case <-doneCh:
		// Run returned before producing an authorize URL (e.g. the loopback callback
		// port is busy). Prefer a URL if it raced in, else surface the failure.
		select {
		case u := <-urlCh:
			writeJSON(w, http.StatusOK, map[string]any{"login_id": st.id, "authorize_url": u})
		default:
			s.oauthMu.Lock()
			msg := st.errMsg
			s.oauthMu.Unlock()
			if msg == "" {
				msg = "could not start sign-in"
			}
			writeErr(w, http.StatusInternalServerError, errInternal, msg)
		}
	case <-time.After(15 * time.Second):
		writeErr(w, http.StatusGatewayTimeout, errInternal, "sign-in did not start in time")
	}
}

// finalizeOAuthLogin records the ceremony outcome under st: on success it stores
// the account (same dedup as the auth.json import) and captures its secret-free
// view; on any failure it records a client-safe message. Never leaks upstream
// error detail.
func (s *Server) finalizeOAuthLogin(st *oauthLoginState, label string, acct model.Account, runErr error) {
	var (
		view   *accountView
		errMsg string
	)
	switch {
	case runErr != nil:
		errMsg = "sign-in failed or was cancelled"
	default:
		created, err := s.storeLoggedInAccount(context.Background(), acct, label)
		switch {
		case errors.Is(err, store.ErrAlreadyExists):
			errMsg = "an account with this ChatGPT account id is already pooled"
		case err != nil:
			errMsg = "could not store account"
		default:
			v := toAccountView(created)
			view = &v
		}
	}
	s.oauthMu.Lock()
	st.done = true
	st.account = view
	st.errMsg = errMsg
	s.oauthMu.Unlock()
}

// storeLoggedInAccount pools a freshly signed-in account under label, using the
// same non-destructive dedup as the auth.json import (store.ErrAlreadyExists when
// the ChatGPT account id is already pooled), and audits the success. Shared by
// the loopback and headless (paste) flows.
func (s *Server) storeLoggedInAccount(ctx context.Context, acct model.Account, label string) (model.Account, error) {
	acct.Label = label
	created, err := s.store.InsertAccountUnique(ctx, acct)
	if err != nil {
		return model.Account{}, err
	}
	s.audit(ctx, "account.login", created.ID, "label="+created.Label)
	return created, nil
}

// handleAccountLoginStatus reports the outcome of a login started by begin:
// {"status":"pending"} | {"status":"success","account":{…}} |
// {"status":"error","error":"…"}. Only the most-recent login id is tracked.
func (s *Server) handleAccountLoginStatus(w http.ResponseWriter, r *http.Request) {
	if s.oauthLogin == nil {
		writeErr(w, http.StatusServiceUnavailable, errInternal, "interactive sign-in is not available")
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, errBadRequest, "missing id")
		return
	}
	s.oauthMu.Lock()
	st := s.oauthState
	if st == nil || st.id != id {
		s.oauthMu.Unlock()
		writeErr(w, http.StatusNotFound, errNotFound, "no such sign-in")
		return
	}
	done, view, errMsg := st.done, st.account, st.errMsg
	s.oauthMu.Unlock()

	switch {
	case !done:
		writeJSON(w, http.StatusOK, map[string]any{"status": "pending"})
	case errMsg != "":
		writeJSON(w, http.StatusOK, map[string]any{"status": "error", "error": errMsg})
	default:
		writeJSON(w, http.StatusOK, map[string]any{"status": "success", "account": view})
	}
}

// newOAuthLoginID returns a 128-bit URL-safe random id used to correlate a
// begin with its status polls.
func newOAuthLoginID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read effectively never fails; fall back to a time-derived id
		// so a login can still proceed rather than 500.
		return "login-" + time.Now().UTC().Format("20060102150405.000000000")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---- headless (paste) flow ------------------------------------------------
//
// For a browser that is NOT on the poolgate host, the loopback callback can never
// reach us, so instead of binding a listener we hand the operator the authorize
// URL, let them sign in, and have them paste back the redirect URL (which carries
// ?code=&state=). We hold the pending login's opaque handle server-side keyed by
// a login id; the PKCE verifier + state never leave the server.

// manualLoginTTL bounds how long a pending paste login is retained.
const manualLoginTTL = 10 * time.Minute

// maxManualLogins caps outstanding paste logins so a flood of begins cannot grow
// the map without bound. The oldest is evicted when the cap is reached.
const maxManualLogins = 8

// manualLoginEntry is one pending headless login.
type manualLoginEntry struct {
	handle    any // opaque *oauth.ManualLogin, passed back to CompleteManual
	label     string
	createdAt time.Time
}

// handleAccountLoginManualBegin starts a headless login and returns the authorize
// URL to open plus a login id to hand to /manual/complete. Requires a wired
// OAuthLogin (503 otherwise).
func (s *Server) handleAccountLoginManualBegin(w http.ResponseWriter, r *http.Request) {
	if s.oauthLogin == nil {
		writeErr(w, http.StatusServiceUnavailable, errInternal, "interactive sign-in is not available")
		return
	}
	var req oauthBeginReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid request body")
		return
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		label = "login-" + s.now().UTC().Format("20060102-150405")
	}
	authorizeURL, handle, err := s.oauthLogin.BeginManual()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not start sign-in")
		return
	}
	id := newOAuthLoginID()
	s.manualMu.Lock()
	s.pruneManualLocked()
	if s.manualLogins == nil {
		s.manualLogins = make(map[string]manualLoginEntry)
	}
	s.manualLogins[id] = manualLoginEntry{handle: handle, label: label, createdAt: s.now().UTC()}
	s.manualMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"login_id": id, "authorize_url": authorizeURL})
}

// manualCompleteReq is the body of POST /admin/api/accounts/login/manual/complete.
type manualCompleteReq struct {
	LoginID    string `json:"login_id"`
	Redirected string `json:"redirected"`
}

// handleAccountLoginManualComplete validates the pasted redirect URL against a
// pending login, exchanges the code, and pools the account (same dedup as the
// auth.json import). The pending entry is consumed single-use.
func (s *Server) handleAccountLoginManualComplete(w http.ResponseWriter, r *http.Request) {
	if s.oauthLogin == nil {
		writeErr(w, http.StatusServiceUnavailable, errInternal, "interactive sign-in is not available")
		return
	}
	var req manualCompleteReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid request body")
		return
	}
	if req.LoginID == "" || strings.TrimSpace(req.Redirected) == "" {
		writeErr(w, http.StatusBadRequest, errBadRequest, "provide login_id and the redirected URL")
		return
	}
	s.manualMu.Lock()
	s.pruneManualLocked()
	entry, ok := s.manualLogins[req.LoginID]
	s.manualMu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, errNotFound, "no such sign-in (it may have expired — start again)")
		return
	}

	acct, err := s.oauthLogin.CompleteManual(r.Context(), entry.handle, req.Redirected)
	if err != nil {
		// A bad paste (state mismatch / missing code) or a failed exchange. The
		// authorization code was not consumed, so keep the pending entry and let the
		// operator re-paste. No upstream detail is surfaced.
		writeErr(w, http.StatusBadRequest, errBadRequest, "could not complete sign-in; check the pasted URL and try again")
		return
	}
	// The code was exchanged (single-use at the provider) — retire the pending entry.
	s.manualMu.Lock()
	delete(s.manualLogins, req.LoginID)
	s.manualMu.Unlock()

	created, err := s.storeLoggedInAccount(r.Context(), acct, entry.label)
	switch {
	case errors.Is(err, store.ErrAlreadyExists):
		writeErr(w, http.StatusConflict, errConflict, "an account with this ChatGPT account id is already pooled")
	case err != nil:
		writeErr(w, http.StatusInternalServerError, errInternal, "could not store account")
	default:
		writeJSON(w, http.StatusCreated, toAccountView(created))
	}
}

// pruneManualLocked drops expired pending logins and enforces the size cap by
// evicting the oldest. Caller holds s.manualMu.
func (s *Server) pruneManualLocked() {
	now := s.now().UTC()
	for id, e := range s.manualLogins {
		if now.Sub(e.createdAt) > manualLoginTTL {
			delete(s.manualLogins, id)
		}
	}
	for len(s.manualLogins) >= maxManualLogins {
		oldestID, first := "", true
		var oldest time.Time
		for id, e := range s.manualLogins {
			if first || e.createdAt.Before(oldest) {
				oldestID, oldest, first = id, e.createdAt, false
			}
		}
		if oldestID == "" {
			break
		}
		delete(s.manualLogins, oldestID)
	}
}
