// Package adminauth holds poolgate's admin-authentication primitives, kept
// deliberately free of any HTTP concerns (DESIGN.md §16 / §22). It owns:
//
//   - admin session lifecycle — create, validate (absolute lifetime + idle
//     timeout), rotate (on register/login), revoke, and revoke-all;
//   - one-time recovery codes — generate N (plaintext shown once) and
//     verify+consume with a constant-time compare;
//   - bootstrap registration tokens — issue a short-TTL single-use token
//     (plaintext returned once) and consume it single-use;
//   - CSRF tokens — issue a session-bound token and verify it (stateless HMAC).
//
// Only SHA-256 hashes of recovery codes and bootstrap tokens are persisted; the
// plaintext never touches the store. The clock and the randomness source are
// injectable so every path is deterministic under test.
package adminauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/store"
)

// Store is the persistence surface adminauth needs; *store.Store satisfies it.
// Keeping it as an interface lets the manager be unit-tested against a fake and
// keeps this package free of any direct SQL.
type Store interface {
	InsertSession(ctx context.Context, s model.Session) (model.Session, error)
	GetSession(ctx context.Context, id string) (model.Session, error)
	TouchSession(ctx context.Context, id string, lastSeen time.Time) error
	DeleteSession(ctx context.Context, id string) error
	DeleteAllSessions(ctx context.Context) (int64, error)

	InsertRecoveryCode(ctx context.Context, rc model.RecoveryCode) (model.RecoveryCode, error)
	ListRecoveryCodes(ctx context.Context) ([]model.RecoveryCode, error)
	ConsumeRecoveryCode(ctx context.Context, id string, usedAt time.Time) error
	DeleteAllRecoveryCodes(ctx context.Context) (int64, error)

	InsertBootstrapToken(ctx context.Context, bt model.BootstrapToken) (model.BootstrapToken, error)
	ListBootstrapTokens(ctx context.Context) ([]model.BootstrapToken, error)
	ConsumeBootstrapToken(ctx context.Context, id string, usedAt time.Time) error
	DeleteAllBootstrapTokens(ctx context.Context) (int64, error)

	DeleteAllWebAuthnCredentials(ctx context.Context) (int64, error)
}

// Default lifecycle parameters (DESIGN.md §16 / §22.3). All are overridable via
// options so deployments and tests can tune them.
const (
	DefaultSessionLifetime = 12 * time.Hour
	DefaultIdleTimeout     = 30 * time.Minute
	DefaultBootstrapTTL    = 15 * time.Minute
	// DefaultRecoveryCodeCount is how many recovery codes GenerateRecoveryCodes
	// mints when the caller passes n <= 0.
	DefaultRecoveryCodeCount = 10
)

// Sentinel errors returned by the manager. Callers (and the later HTTP layer)
// switch on these to map to status codes without string matching.
var (
	// ErrSessionNotFound — no session with that id exists.
	ErrSessionNotFound = errors.New("adminauth: session not found")
	// ErrSessionExpired — the session passed its absolute lifetime.
	ErrSessionExpired = errors.New("adminauth: session expired")
	// ErrSessionIdle — the session exceeded the idle timeout since last seen.
	ErrSessionIdle = errors.New("adminauth: session idle timeout")
	// ErrRecoveryCodeInvalid — no unused recovery code matched.
	ErrRecoveryCodeInvalid = errors.New("adminauth: invalid recovery code")
	// ErrBootstrapTokenInvalid — no unused, unexpired bootstrap token matched.
	ErrBootstrapTokenInvalid = errors.New("adminauth: invalid bootstrap token")
)

// Manager provides the admin-auth primitives over a Store. The zero value is
// not usable; construct with New.
type Manager struct {
	store           Store
	now             func() time.Time
	randr           io.Reader
	sessionLifetime time.Duration
	idleTimeout     time.Duration
	bootstrapTTL    time.Duration
	csrfKey         []byte
}

// Option customizes a Manager.
type Option func(*Manager)

// WithClock injects the time source (default time.Now). Tests use a fake clock
// to drive expiry/idle transitions deterministically.
func WithClock(now func() time.Time) Option {
	return func(m *Manager) {
		if now != nil {
			m.now = now
		}
	}
}

// WithRand injects the randomness source (default crypto/rand.Reader). Tests use
// a deterministic reader.
func WithRand(r io.Reader) Option {
	return func(m *Manager) {
		if r != nil {
			m.randr = r
		}
	}
}

// WithSessionLifetime overrides the absolute session lifetime.
func WithSessionLifetime(d time.Duration) Option {
	return func(m *Manager) {
		if d > 0 {
			m.sessionLifetime = d
		}
	}
}

// WithIdleTimeout overrides the idle timeout.
func WithIdleTimeout(d time.Duration) Option {
	return func(m *Manager) {
		if d > 0 {
			m.idleTimeout = d
		}
	}
}

// WithBootstrapTTL overrides the bootstrap-token TTL.
func WithBootstrapTTL(d time.Duration) Option {
	return func(m *Manager) {
		if d > 0 {
			m.bootstrapTTL = d
		}
	}
}

// WithCSRFKey sets the HMAC key used to sign CSRF tokens. When unset, a random
// key is generated at construction (fine for a single process; supply a stable
// key if tokens must survive restarts).
func WithCSRFKey(key []byte) Option {
	return func(m *Manager) {
		if len(key) > 0 {
			m.csrfKey = append([]byte(nil), key...)
		}
	}
}

// New builds a Manager. The store must be non-nil.
func New(st Store, opts ...Option) (*Manager, error) {
	if st == nil {
		return nil, errors.New("adminauth: nil store")
	}
	m := &Manager{
		store:           st,
		now:             func() time.Time { return time.Now().UTC() },
		randr:           rand.Reader,
		sessionLifetime: DefaultSessionLifetime,
		idleTimeout:     DefaultIdleTimeout,
		bootstrapTTL:    DefaultBootstrapTTL,
	}
	for _, opt := range opts {
		opt(m)
	}
	if len(m.csrfKey) == 0 {
		key := make([]byte, 32)
		if _, err := io.ReadFull(m.randr, key); err != nil {
			return nil, fmt.Errorf("adminauth: generate csrf key: %w", err)
		}
		m.csrfKey = key
	}
	return m, nil
}

// ---- sessions -------------------------------------------------------------

// CreateSession mints a fresh session with created_at/last_seen_at = now and
// expires_at = now + lifetime, and persists it. Call this after a successful
// passkey login or registration.
func (m *Manager) CreateSession(ctx context.Context) (model.Session, error) {
	now := m.now().UTC()
	sess := model.Session{
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(m.sessionLifetime),
	}
	out, err := m.store.InsertSession(ctx, sess)
	if err != nil {
		return model.Session{}, fmt.Errorf("adminauth: create session: %w", err)
	}
	return out, nil
}

// ValidateSession loads the session, enforces the absolute lifetime and the
// idle timeout, and — when valid — slides the idle window by touching
// last_seen_at to now. Invalid sessions are revoked (deleted) and mapped to
// ErrSessionExpired / ErrSessionIdle / ErrSessionNotFound.
func (m *Manager) ValidateSession(ctx context.Context, id string) (model.Session, error) {
	if id == "" {
		return model.Session{}, ErrSessionNotFound
	}
	sess, err := m.store.GetSession(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return model.Session{}, ErrSessionNotFound
		}
		return model.Session{}, fmt.Errorf("adminauth: get session: %w", err)
	}
	now := m.now().UTC()
	if !now.Before(sess.ExpiresAt) {
		_ = m.store.DeleteSession(ctx, id)
		return model.Session{}, ErrSessionExpired
	}
	if now.Sub(sess.LastSeenAt) > m.idleTimeout {
		_ = m.store.DeleteSession(ctx, id)
		return model.Session{}, ErrSessionIdle
	}
	if err := m.store.TouchSession(ctx, id, now); err != nil {
		return model.Session{}, fmt.Errorf("adminauth: touch session: %w", err)
	}
	sess.LastSeenAt = now
	return sess, nil
}

// RotateSession issues a new session and revokes the old one, preserving no
// server-side state beyond a fresh lifetime. Use on privilege changes such as
// registering a new passkey or logging in (DESIGN.md §22.3). A missing old
// session is not an error — the new session is still returned.
func (m *Manager) RotateSession(ctx context.Context, oldID string) (model.Session, error) {
	fresh, err := m.CreateSession(ctx)
	if err != nil {
		return model.Session{}, err
	}
	if oldID != "" {
		if err := m.store.DeleteSession(ctx, oldID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return model.Session{}, fmt.Errorf("adminauth: rotate session: %w", err)
		}
	}
	return fresh, nil
}

// RevokeSession deletes one session. A missing session is treated as success
// (idempotent logout).
func (m *Manager) RevokeSession(ctx context.Context, id string) error {
	if err := m.store.DeleteSession(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("adminauth: revoke session: %w", err)
	}
	return nil
}

// RevokeAllSessions deletes every session ("revoke all sessions", §22.3) and
// returns the number revoked.
func (m *Manager) RevokeAllSessions(ctx context.Context) (int64, error) {
	n, err := m.store.DeleteAllSessions(ctx)
	if err != nil {
		return 0, fmt.Errorf("adminauth: revoke all sessions: %w", err)
	}
	return n, nil
}

// ---- recovery codes -------------------------------------------------------

// GenerateRecoveryCodes mints n one-time recovery codes, persists their SHA-256
// hashes, and returns the plaintext codes (shown to the operator exactly once).
// n <= 0 uses DefaultRecoveryCodeCount.
func (m *Manager) GenerateRecoveryCodes(ctx context.Context, n int) ([]string, error) {
	if n <= 0 {
		n = DefaultRecoveryCodeCount
	}
	codes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		code, err := m.randomRecoveryCode()
		if err != nil {
			return nil, err
		}
		if _, err := m.store.InsertRecoveryCode(ctx, model.RecoveryCode{Hash: hashSecret(code)}); err != nil {
			return nil, fmt.Errorf("adminauth: store recovery code: %w", err)
		}
		codes = append(codes, code)
	}
	return codes, nil
}

// VerifyRecoveryCode hashes the presented code, constant-time compares it
// against every unused stored hash, and — on a match — consumes it single-use.
// It returns ErrRecoveryCodeInvalid when nothing matches. The scan does not
// short-circuit, so its running time does not reveal which (if any) code
// matched.
func (m *Manager) VerifyRecoveryCode(ctx context.Context, code string) error {
	if code == "" {
		return ErrRecoveryCodeInvalid
	}
	presented := hashSecret(code)
	stored, err := m.store.ListRecoveryCodes(ctx)
	if err != nil {
		return fmt.Errorf("adminauth: list recovery codes: %w", err)
	}
	matchID := ""
	for _, rc := range stored {
		if rc.Used() {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(presented), []byte(rc.Hash)) == 1 {
			matchID = rc.ID
		}
	}
	if matchID == "" {
		return ErrRecoveryCodeInvalid
	}
	if err := m.store.ConsumeRecoveryCode(ctx, matchID, m.now().UTC()); err != nil {
		if errors.Is(err, store.ErrAlreadyUsed) || errors.Is(err, store.ErrNotFound) {
			// Lost a race to another consumer; treat as invalid (single-use).
			return ErrRecoveryCodeInvalid
		}
		return fmt.Errorf("adminauth: consume recovery code: %w", err)
	}
	return nil
}

// ---- bootstrap tokens -----------------------------------------------------

// IssueBootstrapToken mints a short-TTL single-use bootstrap registration token,
// persists only its SHA-256 hash + expiry, and returns the plaintext (printed
// once to the local console, never to durable logs — §0 fixes / §16).
func (m *Manager) IssueBootstrapToken(ctx context.Context) (string, model.BootstrapToken, error) {
	token, err := m.randomToken("pgbt")
	if err != nil {
		return "", model.BootstrapToken{}, err
	}
	bt, err := m.store.InsertBootstrapToken(ctx, model.BootstrapToken{
		TokenHash: hashSecret(token),
		ExpiresAt: m.now().UTC().Add(m.bootstrapTTL),
	})
	if err != nil {
		return "", model.BootstrapToken{}, fmt.Errorf("adminauth: store bootstrap token: %w", err)
	}
	return token, bt, nil
}

// ConsumeBootstrapToken validates and single-use-consumes a bootstrap token: it
// must hash-match a stored token that is unused and not expired (by the
// manager's clock). Returns ErrBootstrapTokenInvalid otherwise.
func (m *Manager) ConsumeBootstrapToken(ctx context.Context, token string) error {
	if token == "" {
		return ErrBootstrapTokenInvalid
	}
	presented := hashSecret(token)
	now := m.now().UTC()
	stored, err := m.store.ListBootstrapTokens(ctx)
	if err != nil {
		return fmt.Errorf("adminauth: list bootstrap tokens: %w", err)
	}
	matchID := ""
	for _, bt := range stored {
		if bt.Used() || !now.Before(bt.ExpiresAt) {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(presented), []byte(bt.TokenHash)) == 1 {
			matchID = bt.ID
		}
	}
	if matchID == "" {
		return ErrBootstrapTokenInvalid
	}
	if err := m.store.ConsumeBootstrapToken(ctx, matchID, now); err != nil {
		if errors.Is(err, store.ErrAlreadyUsed) || errors.Is(err, store.ErrNotFound) {
			return ErrBootstrapTokenInvalid
		}
		return fmt.Errorf("adminauth: consume bootstrap token: %w", err)
	}
	return nil
}

// ResetAuth is the full lockout escape hatch behind `poolgate admin reset-auth`
// (DESIGN.md §16): it removes all passkeys, invalidates recovery codes, revokes
// all sessions, clears any stale bootstrap tokens, then issues one fresh
// short-TTL single-use bootstrap token whose plaintext is returned to the
// caller (to print to the local console only).
func (m *Manager) ResetAuth(ctx context.Context) (string, ResetSummary, error) {
	var sum ResetSummary
	var err error
	if sum.PasskeysRemoved, err = m.store.DeleteAllWebAuthnCredentials(ctx); err != nil {
		return "", sum, fmt.Errorf("adminauth: reset passkeys: %w", err)
	}
	if sum.RecoveryCodesRemoved, err = m.store.DeleteAllRecoveryCodes(ctx); err != nil {
		return "", sum, fmt.Errorf("adminauth: reset recovery codes: %w", err)
	}
	if sum.SessionsRevoked, err = m.store.DeleteAllSessions(ctx); err != nil {
		return "", sum, fmt.Errorf("adminauth: reset sessions: %w", err)
	}
	if sum.BootstrapTokensCleared, err = m.store.DeleteAllBootstrapTokens(ctx); err != nil {
		return "", sum, fmt.Errorf("adminauth: reset bootstrap tokens: %w", err)
	}
	token, bt, err := m.IssueBootstrapToken(ctx)
	if err != nil {
		return "", sum, err
	}
	sum.BootstrapExpiresAt = bt.ExpiresAt
	return token, sum, nil
}

// ResetSummary reports what `admin reset-auth` wiped and when the fresh
// bootstrap token expires. It carries counts only — no secrets.
type ResetSummary struct {
	PasskeysRemoved        int64     `json:"passkeys_removed"`
	RecoveryCodesRemoved   int64     `json:"recovery_codes_removed"`
	SessionsRevoked        int64     `json:"sessions_revoked"`
	BootstrapTokensCleared int64     `json:"bootstrap_tokens_cleared"`
	BootstrapExpiresAt     time.Time `json:"bootstrap_expires_at"`
}

// ---- CSRF -----------------------------------------------------------------

// IssueCSRF returns a stateless CSRF token bound to sessionID: base64(nonce ||
// HMAC-SHA256(csrfKey, sessionID||nonce)). Verification recomputes the MAC, so
// no server-side storage is needed and tokens are unforgeable without the key.
func (m *Manager) IssueCSRF(sessionID string) (string, error) {
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(m.randr, nonce); err != nil {
		return "", fmt.Errorf("adminauth: csrf nonce: %w", err)
	}
	mac := m.csrfMAC(sessionID, nonce)
	return base64.RawURLEncoding.EncodeToString(append(nonce, mac...)), nil
}

// VerifyCSRF reports whether token is a valid CSRF token for sessionID. The MAC
// comparison is constant-time.
func (m *Manager) VerifyCSRF(sessionID, token string) bool {
	if sessionID == "" || token == "" {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 16+sha256.Size {
		return false
	}
	nonce, mac := raw[:16], raw[16:]
	want := m.csrfMAC(sessionID, nonce)
	return subtle.ConstantTimeCompare(mac, want) == 1
}

func (m *Manager) csrfMAC(sessionID string, nonce []byte) []byte {
	h := hmac.New(sha256.New, m.csrfKey)
	h.Write([]byte(sessionID))
	h.Write(nonce)
	return h.Sum(nil)
}

// ---- crypto helpers -------------------------------------------------------

// hashSecret returns the lowercase hex SHA-256 of a high-entropy secret. No salt
// is used: the inputs are random tokens/codes, so a per-secret salt adds nothing
// and a fixed store lookup by exact hash stays possible.
func hashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// recoveryCodeAlphabet formats codes in Crockford-ish base32 (uppercase, no
// padding), grouped for legibility.
var recoveryCodeAlphabet = base32.StdEncoding.WithPadding(base32.NoPadding)

// randomRecoveryCode returns a human-friendly 20-char code in 4 groups of 5,
// e.g. "K3F9Q-7Z2MT-...". It draws 15 random bytes (120 bits) → 24 base32 chars,
// trimmed and grouped.
func (m *Manager) randomRecoveryCode() (string, error) {
	buf := make([]byte, 15)
	if _, err := io.ReadFull(m.randr, buf); err != nil {
		return "", fmt.Errorf("adminauth: recovery code entropy: %w", err)
	}
	raw := recoveryCodeAlphabet.EncodeToString(buf) // 24 chars
	raw = raw[:20]
	var b strings.Builder
	for i := 0; i < len(raw); i += 5 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(raw[i : i+5])
	}
	return b.String(), nil
}

// randomToken returns "<prefix>_<48 hex chars>" from 24 random bytes.
func (m *Manager) randomToken(prefix string) (string, error) {
	buf := make([]byte, 24)
	if _, err := io.ReadFull(m.randr, buf); err != nil {
		return "", fmt.Errorf("adminauth: token entropy: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(buf), nil
}
