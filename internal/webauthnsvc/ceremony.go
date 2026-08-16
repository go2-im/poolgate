// ceremony.go implements the WebAuthn registration and login ceremonies on top
// of the Stage-2 service wiring (DESIGN.md §16 / §22). It is deliberately a thin
// layer over go-webauthn: the raw Begin/Finish calls are wrapped so callers get
// typed errors, single-use challenges (via the Stage-2 ChallengeStore), and the
// admin-specific authorization gate:
//
//   - registering the FIRST passkey is gated by a valid single-use bootstrap
//     token (there is no session yet — this is the §17 first-run path);
//   - registering ADDITIONAL passkeys is gated by an existing valid admin session
//     (§16: "add a phone passkey + a hardware key backup" from the signed-in UI);
//   - login is not gated (it is how the operator authenticates) and, on success,
//     persists the bumped signature counter for clone detection (§8) and returns
//     the fixed operator identity so the HTTP layer can mint a session.
//
// The Finish* calls take the raw response body bytes rather than *http.Request so
// this package stays free of net/http and is trivially testable with a software
// authenticator; the admin HTTP layer (a later stage) reads the body and passes
// the bytes through.
package webauthnsvc

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/go2-im/poolgate/internal/model"
)

// Ceremony-layer sentinel errors. The HTTP layer switches on these to choose a
// status code without string matching; none of them leak which specific check
// failed (the gate errors are intentionally coarse).
var (
	// ErrNotAuthorized — the registration gate rejected the request: a first
	// passkey without a valid bootstrap token, or an additional passkey without a
	// valid session.
	ErrNotAuthorized = errors.New("webauthnsvc: registration not authorized")
	// ErrNoAuthorizer — a ceremony that needs the authorization gate was invoked
	// on a Service built without WithAuthorizer.
	ErrNoAuthorizer = errors.New("webauthnsvc: no authorizer configured")
	// ErrNoCredentials — a login ceremony was started with no passkeys registered.
	ErrNoCredentials = errors.New("webauthnsvc: no passkeys registered")
)

// Authorizer is the admin-auth surface the registration gate needs. *adminauth.
// Manager satisfies it. Keeping it an interface (rather than importing adminauth
// directly) keeps this package decoupled and unit-testable against a fake, and
// avoids any import cycle.
type Authorizer interface {
	// ConsumeBootstrapToken validates and single-use-consumes a bootstrap
	// registration token; a non-nil error means the token was missing, expired,
	// or already used.
	ConsumeBootstrapToken(ctx context.Context, token string) error
	// ValidateSession loads and validates an admin session (absolute lifetime +
	// idle timeout); a non-nil error means the session is missing/expired/idle.
	ValidateSession(ctx context.Context, id string) (model.Session, error)
}

// WithAuthorizer wires the authorization gate used by the registration
// ceremonies. It is optional at construction so the Stage-2 wiring tests need no
// authorizer, but the registration ceremonies return ErrNoAuthorizer without it.
func WithAuthorizer(a Authorizer) Option {
	return func(s *Service) {
		if a != nil {
			s.authz = a
		}
	}
}

// RegisterGate carries the caller-supplied authorization material for a
// registration ceremony. Exactly one field is consulted depending on whether any
// passkey already exists: BootstrapToken for the first passkey, SessionID for
// additional ones. Label is an optional human-facing name stored with the new
// credential.
type RegisterGate struct {
	BootstrapToken string
	SessionID      string
	Label          string
}

// BeginRegistration starts a registration ceremony for the operator identity. It
// authorizes the request up front (without consuming a single-use bootstrap
// token — that happens at Finish, only once the attestation verifies), builds the
// creation options, stashes the ceremony session under a fresh challenge id, and
// returns the options plus that id. The caller hands the options to the browser
// and presents the id again at FinishRegistration.
func (s *Service) BeginRegistration(ctx context.Context, gate RegisterGate) (*protocol.CredentialCreation, string, error) {
	if s.authz == nil {
		return nil, "", ErrNoAuthorizer
	}
	first, err := s.isFirstPasskey(ctx)
	if err != nil {
		return nil, "", err
	}
	// Non-consuming pre-check: for the first passkey we only require a token to be
	// present (it is verified+consumed at Finish); for additional passkeys we
	// fully validate the session now.
	if first {
		if gate.BootstrapToken == "" {
			return nil, "", ErrNotAuthorized
		}
	} else if err := s.validateSession(ctx, gate.SessionID); err != nil {
		return nil, "", err
	}

	user, err := s.OperatorUser(ctx)
	if err != nil {
		return nil, "", err
	}
	creation, session, err := s.wa.BeginRegistration(user, s.RegistrationOptions()...)
	if err != nil {
		return nil, "", fmt.Errorf("webauthnsvc: begin registration: %w", err)
	}
	id, err := s.challenges.Put(session)
	if err != nil {
		return nil, "", err
	}
	return creation, id, nil
}

// FinishRegistration completes a registration ceremony: it retrieves the pending
// challenge (single-use), verifies the attestation, enforces the authorization
// credential (consuming the bootstrap token for the first passkey, or validating
// the session for additional ones), and persists the new credential. It returns
// the stored credential and wasFirst — whether this ceremony was the
// bootstrap-gated first passkey (i.e. it consumed the bootstrap token) — so the
// caller mints one-time recovery codes based on the ACTUAL bootstrap path rather
// than on a client-supplied flag that could disagree.
//
// The gate is enforced only after the attestation verifies, so a malformed or
// forged response never burns the single-use bootstrap token.
func (s *Service) FinishRegistration(ctx context.Context, gate RegisterGate, challengeID string, responseBody []byte) (model.WebAuthnCredential, bool, error) {
	if s.authz == nil {
		return model.WebAuthnCredential{}, false, ErrNoAuthorizer
	}
	session, err := s.challenges.Take(challengeID)
	if err != nil {
		return model.WebAuthnCredential{}, false, err
	}
	first, err := s.isFirstPasskey(ctx)
	if err != nil {
		return model.WebAuthnCredential{}, false, err
	}

	user, err := s.OperatorUser(ctx)
	if err != nil {
		return model.WebAuthnCredential{}, false, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(responseBody)
	if err != nil {
		return model.WebAuthnCredential{}, false, fmt.Errorf("webauthnsvc: parse registration response: %w", err)
	}
	cred, err := s.wa.CreateCredential(user, *session, parsed)
	if err != nil {
		return model.WebAuthnCredential{}, false, fmt.Errorf("webauthnsvc: verify registration: %w", err)
	}

	// Attestation verified — now spend the single-use gate.
	if first {
		if err := s.authz.ConsumeBootstrapToken(ctx, gate.BootstrapToken); err != nil {
			return model.WebAuthnCredential{}, false, ErrNotAuthorized
		}
	} else if err := s.validateSession(ctx, gate.SessionID); err != nil {
		return model.WebAuthnCredential{}, false, err
	}

	m := credentialToModel(*cred)
	m.Label = gate.Label
	stored, err := s.store.InsertWebAuthnCredential(ctx, m)
	if err != nil {
		return model.WebAuthnCredential{}, false, fmt.Errorf("webauthnsvc: store credential: %w", err)
	}
	return stored, first, nil
}

// BeginLogin starts an assertion ceremony for the operator identity. It requires
// at least one registered passkey (ErrNoCredentials otherwise), builds the
// assertion options over the operator's credentials, and stashes the ceremony
// session under a fresh challenge id.
func (s *Service) BeginLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	user, err := s.OperatorUser(ctx)
	if err != nil {
		return nil, "", err
	}
	if len(user.WebAuthnCredentials()) == 0 {
		return nil, "", ErrNoCredentials
	}
	assertion, session, err := s.wa.BeginLogin(user)
	if err != nil {
		return nil, "", fmt.Errorf("webauthnsvc: begin login: %w", err)
	}
	id, err := s.challenges.Put(session)
	if err != nil {
		return nil, "", err
	}
	return assertion, id, nil
}

// FinishLogin completes an assertion ceremony: it retrieves the pending challenge
// (single-use), validates the assertion against the operator's stored
// credentials, and persists the bumped signature counter. Note: go-webauthn sets
// Authenticator.CloneWarning when the returned counter does not advance, but a
// non-advancing counter is EXPECTED for synced/multi-device passkeys (iCloud
// Keychain, password managers), which poolgate supports — so the warning is
// advisory and is NOT treated as a hard failure here (doing so would lock out
// legitimate synced passkeys). The counter is still persisted for observability.
func (s *Service) FinishLogin(ctx context.Context, challengeID string, responseBody []byte) (webauthn.User, error) {
	session, err := s.challenges.Take(challengeID)
	if err != nil {
		return nil, err
	}
	user, err := s.OperatorUser(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(responseBody)
	if err != nil {
		return nil, fmt.Errorf("webauthnsvc: parse login response: %w", err)
	}
	cred, err := s.wa.ValidateLogin(user, *session, parsed)
	if err != nil {
		return nil, fmt.Errorf("webauthnsvc: verify login: %w", err)
	}
	if err := s.persistSignCount(ctx, cred); err != nil {
		return nil, err
	}
	return user, nil
}

// persistSignCount writes the bumped signature counter of the just-used
// credential back to the store, keyed on the credential's opaque WebAuthn id.
func (s *Service) persistSignCount(ctx context.Context, cred *webauthn.Credential) error {
	row, err := s.store.GetWebAuthnCredentialByCredID(ctx, cred.ID)
	if err != nil {
		return fmt.Errorf("webauthnsvc: lookup credential: %w", err)
	}
	if err := s.store.UpdateWebAuthnSignCount(ctx, row.ID, cred.Authenticator.SignCount); err != nil {
		return fmt.Errorf("webauthnsvc: update sign count: %w", err)
	}
	return nil
}

// isFirstPasskey reports whether no passkey is registered yet (the first-run
// bootstrap path).
func (s *Service) isFirstPasskey(ctx context.Context) (bool, error) {
	n, err := s.store.CountWebAuthnCredentials(ctx)
	if err != nil {
		return false, fmt.Errorf("webauthnsvc: count credentials: %w", err)
	}
	return n == 0, nil
}

// validateSession runs the session gate for additional-passkey registration,
// mapping any authorizer failure to the coarse ErrNotAuthorized.
func (s *Service) validateSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return ErrNotAuthorized
	}
	if _, err := s.authz.ValidateSession(ctx, sessionID); err != nil {
		return ErrNotAuthorized
	}
	return nil
}
