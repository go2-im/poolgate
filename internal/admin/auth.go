// auth.go implements the admin authentication routes (DESIGN.md §16): passkey
// registration (bootstrap-token gated for the first, session gated for
// additional), passkey login, recovery-code login, logout, revoke-all, and the
// CSRF / me helpers. These handlers translate between HTTP and the ceremony /
// session managers; all WebAuthn verification lives in internal/webauthnsvc.
package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go2-im/poolgate/internal/adminauth"
	"github.com/go2-im/poolgate/internal/webauthnsvc"
)

// registerBeginReq is the body of POST /admin/register/begin.
type registerBeginReq struct {
	BootstrapToken string `json:"bootstrap_token"`
	Label          string `json:"label"`
}

// registerFinishReq is the body of POST /admin/register/finish. Credential is
// the raw WebAuthn attestation response, passed through verbatim to the ceremony.
type registerFinishReq struct {
	ChallengeID    string          `json:"challenge_id"`
	BootstrapToken string          `json:"bootstrap_token"`
	Label          string          `json:"label"`
	Credential     json.RawMessage `json:"credential"`
}

// beginResp is the shape returned by both begin ceremonies: the WebAuthn
// options object under "publicKey" plus a challenge id to echo at finish.
type beginResp struct {
	PublicKey   any    `json:"publicKey"`
	ChallengeID string `json:"challenge_id"`
}

// handleRegisterBegin starts a passkey registration. The first passkey is gated
// by a bootstrap token in the body; additional passkeys by the current session
// cookie (with CSRF). It returns the creation options plus a challenge id.
func (s *Server) handleRegisterBegin(w http.ResponseWriter, r *http.Request, at *attempt) {
	var req registerBeginReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid request body")
		return
	}
	sid, ok := s.registerSession(w, r)
	if !ok {
		return
	}
	gate := webauthnsvc.RegisterGate{BootstrapToken: req.BootstrapToken, Label: req.Label, SessionID: sid}

	creation, challengeID, err := s.webauthn.BeginRegistration(r.Context(), gate)
	if err != nil {
		s.writeRegisterErr(w, err, at)
		return
	}
	writeJSON(w, http.StatusOK, beginResp{PublicKey: creation.Response, ChallengeID: challengeID})
}

// handleRegisterFinish completes a passkey registration, mints a fresh session,
// and — for the first (bootstrap-gated) passkey — returns one-time recovery
// codes (shown exactly once).
func (s *Server) handleRegisterFinish(w http.ResponseWriter, r *http.Request, at *attempt) {
	var req registerFinishReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid request body")
		return
	}
	sid, ok := s.registerSession(w, r)
	if !ok {
		return
	}
	gate := webauthnsvc.RegisterGate{BootstrapToken: req.BootstrapToken, Label: req.Label, SessionID: sid}

	_, wasFirst, err := s.webauthn.FinishRegistration(r.Context(), gate, req.ChallengeID, req.Credential)
	if err != nil {
		s.writeRegisterErr(w, err, at)
		return
	}

	resp := map[string]any{"authenticated": true}
	// Recovery codes are minted for the actual bootstrap (first-passkey) ceremony
	// as determined by FinishRegistration — not from the client-supplied
	// BootstrapToken flag, which could disagree. Mint them BEFORE establishing the
	// session so a code-generation failure surfaces as a clean 500 (the operator
	// simply retries the bootstrap) rather than leaving a live session with no
	// recovery codes.
	if wasFirst {
		codes, cerr := s.sessions.GenerateRecoveryCodes(r.Context(), s.recovery)
		if cerr != nil {
			writeErr(w, http.StatusInternalServerError, errInternal, "could not generate recovery codes")
			return
		}
		resp["recovery_codes"] = codes
	}

	sess, err := s.sessions.RotateSession(r.Context(), sid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not create session")
		return
	}
	s.setSessionCookie(w, sess)

	s.audit(r.Context(), "auth.passkey_register", req.Label, "")
	writeJSON(w, http.StatusOK, resp)
}

// handleLoginBegin starts a passkey assertion ceremony. It is wrapped by the
// brute limiter (route "login") so a source IP already locked out from failed
// logins cannot keep starting new ceremonies; it reports neither success nor
// failure, so a begin never itself counts against the limiter.
func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request, _ *attempt) {
	assertion, challengeID, err := s.webauthn.BeginLogin(r.Context())
	if err != nil {
		if errors.Is(err, webauthnsvc.ErrNoCredentials) {
			writeErr(w, http.StatusBadRequest, errBadRequest, "no passkeys registered")
			return
		}
		writeErr(w, http.StatusInternalServerError, errInternal, "could not begin login")
		return
	}
	writeJSON(w, http.StatusOK, beginResp{PublicKey: assertion.Response, ChallengeID: challengeID})
}

// loginFinishReq is the body of POST /admin/login/finish.
type loginFinishReq struct {
	ChallengeID string          `json:"challenge_id"`
	Credential  json.RawMessage `json:"credential"`
}

// handleLoginFinish verifies a passkey assertion and, on success, mints a
// session cookie. Failures are counted by the rate-limiter.
func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request, at *attempt) {
	var req loginFinishReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid request body")
		return
	}
	if _, err := s.webauthn.FinishLogin(r.Context(), req.ChallengeID, req.Credential); err != nil {
		at.failed = true
		writeErr(w, http.StatusUnauthorized, errUnauthorized, "login failed")
		return
	}
	sess, err := s.sessions.CreateSession(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not create session")
		return
	}
	at.succeeded = true
	s.setSessionCookie(w, sess)
	s.audit(r.Context(), "auth.login", "", "method=passkey")
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true})
}

// recoveryReq is the body of POST /admin/login/recovery.
type recoveryReq struct {
	Code string `json:"code"`
}

// handleLoginRecovery consumes a one-time recovery code and mints a session.
// Failures are counted by the rate-limiter.
func (s *Server) handleLoginRecovery(w http.ResponseWriter, r *http.Request, at *attempt) {
	var req recoveryReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid request body")
		return
	}
	if err := s.sessions.VerifyRecoveryCode(r.Context(), req.Code); err != nil {
		if errors.Is(err, adminauth.ErrRecoveryCodeInvalid) {
			at.failed = true
			writeErr(w, http.StatusUnauthorized, errUnauthorized, "invalid recovery code")
			return
		}
		writeErr(w, http.StatusInternalServerError, errInternal, "could not verify recovery code")
		return
	}
	sess, err := s.sessions.CreateSession(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not create session")
		return
	}
	at.succeeded = true
	s.setSessionCookie(w, sess)
	s.audit(r.Context(), "auth.login", "", "method=recovery_code")
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true})
}

// handleLogout revokes the current session and clears the cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFromCtx(r.Context())
	if err := s.sessions.RevokeSession(r.Context(), sess.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not revoke session")
		return
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
}

// handleRevokeAll revokes every session (DESIGN.md §22.3) and clears the caller's
// cookie (the current session is among those revoked).
func (s *Server) handleRevokeAll(w http.ResponseWriter, r *http.Request) {
	n, err := s.sessions.RevokeAllSessions(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not revoke sessions")
		return
	}
	s.clearSessionCookie(w)
	s.audit(r.Context(), "auth.revoke_all_sessions", "", "count="+strconv.FormatInt(n, 10))
	writeJSON(w, http.StatusOK, map[string]any{"revoked": n})
}

// handleCSRF issues a CSRF token bound to the current session.
func (s *Server) handleCSRF(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFromCtx(r.Context())
	token, err := s.sessions.IssueCSRF(sess.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not issue CSRF token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"csrf_token": token})
}

// handleMe reports the authenticated operator identity + session timestamps.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFromCtx(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"operator":      "operator",
		"session": map[string]any{
			"created_at":   sess.CreatedAt,
			"last_seen_at": sess.LastSeenAt,
			"expires_at":   sess.ExpiresAt,
		},
	})
}

// registerSession resolves the session id for a registration request. With no
// session cookie it returns ("", true) — the bootstrap (first-passkey) path.
// With a session cookie it enforces CSRF (registering an additional passkey is
// state-changing) and returns (id, true) on success, or ("", false) after
// writing a 403 on CSRF failure.
func (s *Server) registerSession(w http.ResponseWriter, r *http.Request) (string, bool) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return "", true
	}
	if !s.sessions.VerifyCSRF(c.Value, r.Header.Get(CSRFHeaderName)) {
		writeErr(w, http.StatusForbidden, errForbidden, "missing or invalid CSRF token")
		return "", false
	}
	return c.Value, true
}

// writeRegisterErr maps a ceremony error to a status code without leaking which
// specific gate failed, and marks the attempt failed for the rate-limiter.
func (s *Server) writeRegisterErr(w http.ResponseWriter, err error, at *attempt) {
	switch {
	case errors.Is(err, webauthnsvc.ErrNotAuthorized):
		at.failed = true
		writeErr(w, http.StatusUnauthorized, errUnauthorized, "registration not authorized")
	case errors.Is(err, webauthnsvc.ErrNoAuthorizer):
		writeErr(w, http.StatusInternalServerError, errInternal, "registration unavailable")
	default:
		// A malformed attestation / expired challenge is a client error.
		writeErr(w, http.StatusBadRequest, errBadRequest, "registration failed")
	}
}
