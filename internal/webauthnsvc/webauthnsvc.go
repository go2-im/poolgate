// Package webauthnsvc holds poolgate's WebAuthn (passkey) core for the admin
// listener (DESIGN.md §3 / §16 / §0 fixes). This stage ships only the wiring
// that the later ceremony handlers build on — no Begin/Finish calls yet:
//
//   - RP resolution: the Relying Party ID and origin are resolved ONCE at
//     construction from the STATIC admin config (server.admin external_origin /
//     rp_id), never from per-request forwarded headers;
//   - a single fixed "operator" user (there is exactly one admin identity)
//     backed by the stored passkey credentials;
//   - lossless (de)serialization between go-webauthn's webauthn.Credential and
//     the persisted model columns (cred_id, public_key, sign_count, aaguid,
//     transports);
//   - a registration-options builder that allows platform, cross-platform, and
//     hybrid/caBLE authenticators (residentKey + userVerification preferred) so
//     QR / phone sign-in works;
//   - an in-memory challenge store (see challenge.go) for pending ceremonies.
//
// The clock and randomness source are injectable so everything is deterministic
// under test.
package webauthnsvc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/go2-im/poolgate/internal/config"
	"github.com/go2-im/poolgate/internal/model"
)

// RPDisplayName is the human-facing Relying Party name shown by authenticators.
const RPDisplayName = "poolgate admin"

// operatorName / operatorDisplayName are the fixed WebAuthn name/display-name for
// the single admin identity. There is exactly one operator, so these are
// constants rather than per-user data.
const (
	operatorName        = "operator"
	operatorDisplayName = "poolgate operator"
)

// Store is the persistence surface the WebAuthn core needs. *store.Store
// satisfies it. Keeping it an interface lets the service be unit-tested against
// a fake and keeps this package free of any direct SQL. Stage 3 extends it with
// the ceremony persistence methods (count / insert / lookup / sign-count).
type Store interface {
	ListWebAuthnCredentials(ctx context.Context) ([]model.WebAuthnCredential, error)
	CountWebAuthnCredentials(ctx context.Context) (int, error)
	InsertWebAuthnCredential(ctx context.Context, c model.WebAuthnCredential) (model.WebAuthnCredential, error)
	GetWebAuthnCredentialByCredID(ctx context.Context, credID []byte) (model.WebAuthnCredential, error)
	UpdateWebAuthnSignCount(ctx context.Context, id string, signCount uint32) error
}

// Service is the WebAuthn handle: it holds the configured *webauthn.WebAuthn
// (RP resolved once) plus the challenge store and injectable clock/rand. The
// zero value is not usable; construct with New.
type Service struct {
	wa           *webauthn.WebAuthn
	store        Store
	authz        Authorizer
	challenges   *ChallengeStore
	now          func() time.Time
	randr        io.Reader
	challengeTTL time.Duration
}

// Option customizes a Service.
type Option func(*Service)

// WithClock injects the time source (default time.Now, UTC). Tests use a fake
// clock to drive challenge expiry deterministically.
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// WithRand injects the randomness source (default crypto/rand.Reader). Tests use
// a deterministic reader.
func WithRand(r io.Reader) Option {
	return func(s *Service) {
		if r != nil {
			s.randr = r
		}
	}
}

// WithChallengeTTL overrides the pending-ceremony challenge TTL (default
// DefaultChallengeTTL).
func WithChallengeTTL(d time.Duration) Option {
	return func(s *Service) {
		if d > 0 {
			s.challengeTTL = d
		}
	}
}

// New builds a Service. It resolves the RP ID and origin ONCE from the static
// admin config (never from request headers), constructs the underlying
// *webauthn.WebAuthn, and wires an in-memory challenge store. The store must be
// non-nil.
func New(cfg model.Config, st Store, opts ...Option) (*Service, error) {
	if st == nil {
		return nil, errors.New("webauthnsvc: nil store")
	}
	rpID, origins, err := resolveRP(cfg.Server.Admin)
	if err != nil {
		return nil, err
	}
	s := &Service{
		store:        st,
		now:          func() time.Time { return time.Now().UTC() },
		randr:        rand.Reader,
		challengeTTL: DefaultChallengeTTL,
	}
	for _, opt := range opts {
		opt(s)
	}

	wcfg := &webauthn.Config{
		RPID:                  rpID,
		RPDisplayName:         RPDisplayName,
		RPOrigins:             origins,
		AttestationPreference: protocol.PreferNoAttestation,
		// Allow platform (Touch ID / Hello), cross-platform (security keys) and
		// hybrid/caBLE (QR / phone) by leaving AuthenticatorAttachment unset;
		// prefer discoverable credentials + user verification (DESIGN.md §16).
		AuthenticatorSelection: authenticatorSelection(),
	}
	wa, err := webauthn.New(wcfg)
	if err != nil {
		return nil, fmt.Errorf("webauthnsvc: build webauthn: %w", err)
	}
	s.wa = wa
	s.challenges = NewChallengeStore(s.challengeTTL, WithChallengeClock(s.now), WithChallengeRand(s.randr))
	return s, nil
}

// WebAuthn returns the configured *webauthn.WebAuthn handle for the later
// ceremony layer.
func (s *Service) WebAuthn() *webauthn.WebAuthn { return s.wa }

// Challenges returns the in-memory challenge store for pending ceremonies.
func (s *Service) Challenges() *ChallengeStore { return s.challenges }

// RPID returns the resolved Relying Party ID.
func (s *Service) RPID() string { return s.wa.Config.RPID }

// RPOrigins returns the resolved Relying Party origins.
func (s *Service) RPOrigins() []string { return s.wa.Config.RPOrigins }

// authenticatorSelection is the shared selection policy: no attachment filter
// (platform + cross-platform + hybrid all eligible), discoverable credentials
// preferred, user verification preferred (DESIGN.md §16).
func authenticatorSelection() protocol.AuthenticatorSelection {
	return protocol.AuthenticatorSelection{
		ResidentKey:      protocol.ResidentKeyRequirementPreferred,
		UserVerification: protocol.VerificationPreferred,
	}
}

// RegistrationOptions returns the registration ceremony options expressing the
// selection policy above plus "none" attestation. The actual BeginRegistration
// call belongs to a later stage; this helper keeps the option shape in one
// place so the ceremony layer and its tests stay consistent.
func (s *Service) RegistrationOptions() []webauthn.RegistrationOption {
	return []webauthn.RegistrationOption{
		webauthn.WithAuthenticatorSelection(authenticatorSelection()),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	}
}

// resolveRP derives the WebAuthn RP ID and origin list from the static admin
// listener config. external_origin wins when set; otherwise a loopback origin is
// synthesized from Host:Port. rp_id wins when set; otherwise it is the origin's
// hostname. This is the ONLY place RP identity is decided (DESIGN.md §0 fixes:
// resolved once, never from forwarded headers).
func resolveRP(admin model.ListenConfig) (rpID string, origins []string, err error) {
	// The origin is synthesized in ONE shared place (config.SynthesizeAdminOrigin)
	// so the WebAuthn RP origin can never diverge from the admin server's canonical
	// CORS/cookie origin — a past divergence (RP=localhost while the server said
	// 127.0.0.1) silently broke passkey registration.
	origin := config.SynthesizeAdminOrigin(admin)
	u, perr := url.Parse(origin)
	if perr != nil {
		return "", nil, fmt.Errorf("webauthnsvc: invalid admin external_origin %q: %w", origin, perr)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", nil, fmt.Errorf("webauthnsvc: admin external_origin %q must be an absolute origin (scheme://host)", origin)
	}
	rpID = strings.TrimSpace(admin.RPID)
	if rpID == "" {
		rpID = u.Hostname()
	}
	return rpID, []string{origin}, nil
}

// ---- operator user --------------------------------------------------------

// operatorID is the stable 32-byte WebAuthn user handle for the single admin
// identity. It is deterministic (there is exactly one operator) but opaque, and
// authentication decisions key on it rather than the display name.
func operatorID() []byte {
	sum := sha256.Sum256([]byte("poolgate-admin-operator-v1"))
	return sum[:]
}

// operatorUser adapts the stored passkey credentials to go-webauthn's User
// interface for the fixed operator identity.
type operatorUser struct {
	creds []webauthn.Credential
}

// OperatorUser loads every stored passkey and returns a webauthn.User for the
// fixed operator identity. The later ceremony layer passes this to
// BeginRegistration / BeginLogin.
func (s *Service) OperatorUser(ctx context.Context) (webauthn.User, error) {
	stored, err := s.store.ListWebAuthnCredentials(ctx)
	if err != nil {
		return nil, fmt.Errorf("webauthnsvc: list credentials: %w", err)
	}
	creds := make([]webauthn.Credential, 0, len(stored))
	for _, c := range stored {
		creds = append(creds, credentialFromModel(c))
	}
	return &operatorUser{creds: creds}, nil
}

func (u *operatorUser) WebAuthnID() []byte                         { return operatorID() }
func (u *operatorUser) WebAuthnName() string                       { return operatorName }
func (u *operatorUser) WebAuthnDisplayName() string                { return operatorDisplayName }
func (u *operatorUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// ---- credential (de)serialization -----------------------------------------

// credentialToModel maps a go-webauthn credential to the persisted model,
// carrying only the columns Stage 1 defined (cred_id, public_key, sign_count,
// aaguid, transports). Flags/attestation are not persisted in v1.
func credentialToModel(c webauthn.Credential) model.WebAuthnCredential {
	transports := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		transports = append(transports, string(t))
	}
	return model.WebAuthnCredential{
		CredID:     append([]byte(nil), c.ID...),
		PublicKey:  append([]byte(nil), c.PublicKey...),
		SignCount:  c.Authenticator.SignCount,
		AAGUID:     append([]byte(nil), c.Authenticator.AAGUID...),
		Transports: transports,
	}
}

// credentialFromModel reconstructs a go-webauthn credential from a stored row.
// It is the inverse of credentialToModel for the persisted columns.
func credentialFromModel(m model.WebAuthnCredential) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(m.Transports))
	for _, t := range m.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}
	return webauthn.Credential{
		ID:        append([]byte(nil), m.CredID...),
		PublicKey: append([]byte(nil), m.PublicKey...),
		Transport: transports,
		Authenticator: webauthn.Authenticator{
			AAGUID:    append([]byte(nil), m.AAGUID...),
			SignCount: m.SignCount,
		},
	}
}
