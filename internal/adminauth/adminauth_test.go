package adminauth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/config"
	"github.com/go2-im/poolgate/internal/crypto"
	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/store"
)

// ---- test doubles ---------------------------------------------------------

// fakeClock is a mutable, injectable clock.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *fakeClock                   { return &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)} }

// seqReader is a deterministic io.Reader whose bytes advance each read, so
// successive tokens/codes differ without needing real entropy.
type seqReader struct{ n byte }

func (r *seqReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.n
		r.n++
	}
	return len(p), nil
}

// failAfterReader succeeds for okReads calls, then errors — lets New build a
// csrf key before a later token/code read is forced to fail.
type failAfterReader struct {
	okReads int
	reads   int
}

func (r *failAfterReader) Read(p []byte) (int, error) {
	r.reads++
	if r.reads > r.okReads {
		return 0, errors.New("boom-rand")
	}
	for i := range p {
		p[i] = 0x7
	}
	return len(p), nil
}

var errInjected = errors.New("injected store error")

// fakeStore is an in-memory adminauth.Store with per-method error injection.
type fakeStore struct {
	sessions  map[string]model.Session
	recovery  []model.RecoveryCode
	bootstrap []model.BootstrapToken
	seq       int
	errs      map[string]error
}

func newFakeStore() *fakeStore {
	return &fakeStore{sessions: map[string]model.Session{}, errs: map[string]error{}}
}

func (f *fakeStore) fail(method string) error { return f.errs[method] }
func (f *fakeStore) nextID(p string) string {
	f.seq++
	return p + "_" + string(rune('a'+f.seq))
}

func (f *fakeStore) InsertSession(_ context.Context, s model.Session) (model.Session, error) {
	if e := f.fail("InsertSession"); e != nil {
		return model.Session{}, e
	}
	if s.ID == "" {
		s.ID = f.nextID("sess")
	}
	f.sessions[s.ID] = s
	return s, nil
}

func (f *fakeStore) GetSession(_ context.Context, id string) (model.Session, error) {
	if e := f.fail("GetSession"); e != nil {
		return model.Session{}, e
	}
	s, ok := f.sessions[id]
	if !ok {
		return model.Session{}, store.ErrNotFound
	}
	return s, nil
}

func (f *fakeStore) TouchSession(_ context.Context, id string, lastSeen time.Time) error {
	if e := f.fail("TouchSession"); e != nil {
		return e
	}
	s, ok := f.sessions[id]
	if !ok {
		return store.ErrNotFound
	}
	s.LastSeenAt = lastSeen
	f.sessions[id] = s
	return nil
}

func (f *fakeStore) DeleteSession(_ context.Context, id string) error {
	if e := f.fail("DeleteSession"); e != nil {
		return e
	}
	if _, ok := f.sessions[id]; !ok {
		return store.ErrNotFound
	}
	delete(f.sessions, id)
	return nil
}

func (f *fakeStore) DeleteAllSessions(_ context.Context) (int64, error) {
	if e := f.fail("DeleteAllSessions"); e != nil {
		return 0, e
	}
	n := int64(len(f.sessions))
	f.sessions = map[string]model.Session{}
	return n, nil
}

func (f *fakeStore) InsertRecoveryCode(_ context.Context, rc model.RecoveryCode) (model.RecoveryCode, error) {
	if e := f.fail("InsertRecoveryCode"); e != nil {
		return model.RecoveryCode{}, e
	}
	if rc.ID == "" {
		rc.ID = f.nextID("rec")
	}
	f.recovery = append(f.recovery, rc)
	return rc, nil
}

func (f *fakeStore) ListRecoveryCodes(_ context.Context) ([]model.RecoveryCode, error) {
	if e := f.fail("ListRecoveryCodes"); e != nil {
		return nil, e
	}
	return append([]model.RecoveryCode(nil), f.recovery...), nil
}

func (f *fakeStore) ConsumeRecoveryCode(_ context.Context, id string, usedAt time.Time) error {
	if e := f.fail("ConsumeRecoveryCode"); e != nil {
		return e
	}
	for i := range f.recovery {
		if f.recovery[i].ID == id {
			if f.recovery[i].Used() {
				return store.ErrAlreadyUsed
			}
			f.recovery[i].UsedAt = usedAt
			return nil
		}
	}
	return store.ErrNotFound
}

func (f *fakeStore) DeleteAllRecoveryCodes(_ context.Context) (int64, error) {
	if e := f.fail("DeleteAllRecoveryCodes"); e != nil {
		return 0, e
	}
	n := int64(len(f.recovery))
	f.recovery = nil
	return n, nil
}

func (f *fakeStore) InsertBootstrapToken(_ context.Context, bt model.BootstrapToken) (model.BootstrapToken, error) {
	if e := f.fail("InsertBootstrapToken"); e != nil {
		return model.BootstrapToken{}, e
	}
	if bt.ID == "" {
		bt.ID = f.nextID("bst")
	}
	f.bootstrap = append(f.bootstrap, bt)
	return bt, nil
}

func (f *fakeStore) ListBootstrapTokens(_ context.Context) ([]model.BootstrapToken, error) {
	if e := f.fail("ListBootstrapTokens"); e != nil {
		return nil, e
	}
	return append([]model.BootstrapToken(nil), f.bootstrap...), nil
}

func (f *fakeStore) ConsumeBootstrapToken(_ context.Context, id string, usedAt time.Time) error {
	if e := f.fail("ConsumeBootstrapToken"); e != nil {
		return e
	}
	for i := range f.bootstrap {
		if f.bootstrap[i].ID == id {
			if f.bootstrap[i].Used() {
				return store.ErrAlreadyUsed
			}
			f.bootstrap[i].UsedAt = usedAt
			return nil
		}
	}
	return store.ErrNotFound
}

func (f *fakeStore) DeleteAllBootstrapTokens(_ context.Context) (int64, error) {
	if e := f.fail("DeleteAllBootstrapTokens"); e != nil {
		return 0, e
	}
	n := int64(len(f.bootstrap))
	f.bootstrap = nil
	return n, nil
}

func (f *fakeStore) DeleteAllWebAuthnCredentials(_ context.Context) (int64, error) {
	if e := f.fail("DeleteAllWebAuthnCredentials"); e != nil {
		return 0, e
	}
	return 0, nil
}

// newRealStore opens a real SQLite store in a temp dir (t.TempDir) so happy
// paths exercise the actual persistence layer, not just the fake.
func newRealStore(t *testing.T) *store.Store {
	t.Helper()
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i + 3)
	}
	c, err := crypto.New(key)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	s, err := store.Open(cfg, c)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// ---- construction ---------------------------------------------------------

func TestNew(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) = nil error, want error")
	}
	// rand failure while generating the default csrf key.
	if _, err := New(newFakeStore(), WithRand(&failAfterReader{okReads: 0})); err == nil {
		t.Fatal("New with failing rand = nil error, want error")
	}
	// options with zero/nil values must be ignored (defaults kept).
	m, err := New(newFakeStore(),
		WithClock(nil), WithRand(nil),
		WithSessionLifetime(0), WithIdleTimeout(-1), WithBootstrapTTL(0),
		WithCSRFKey(nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m.sessionLifetime != DefaultSessionLifetime || m.idleTimeout != DefaultIdleTimeout || m.bootstrapTTL != DefaultBootstrapTTL {
		t.Fatalf("zero options overrode defaults: %+v", m)
	}
	// explicit overrides applied.
	m2, err := New(newFakeStore(),
		WithSessionLifetime(time.Hour), WithIdleTimeout(time.Minute),
		WithBootstrapTTL(2*time.Minute), WithCSRFKey([]byte("k")))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m2.sessionLifetime != time.Hour || m2.idleTimeout != time.Minute || m2.bootstrapTTL != 2*time.Minute {
		t.Fatalf("overrides not applied: %+v", m2)
	}
}

// ---- sessions --------------------------------------------------------------

func TestSessionLifecycle(t *testing.T) {
	st := newRealStore(t)
	clk := newClock()
	m, err := New(st, WithClock(clk.now), WithRand(&seqReader{}),
		WithSessionLifetime(time.Hour), WithIdleTimeout(10*time.Minute))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	sess, err := m.CreateSession(ctx)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sess.ID == "" {
		t.Fatal("CreateSession returned empty id")
	}
	if !sess.ExpiresAt.Equal(clk.now().Add(time.Hour)) {
		t.Fatalf("ExpiresAt = %v, want now+1h", sess.ExpiresAt)
	}

	// Validate within idle window slides last_seen.
	clk.advance(5 * time.Minute)
	got, err := m.ValidateSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if !got.LastSeenAt.Equal(clk.now()) {
		t.Fatalf("last_seen not touched: %v want %v", got.LastSeenAt, clk.now())
	}

	// Empty id and missing id map to not-found.
	if _, err := m.ValidateSession(ctx, ""); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("ValidateSession(empty) err = %v, want ErrSessionNotFound", err)
	}
	if _, err := m.ValidateSession(ctx, "nope"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("ValidateSession(missing) err = %v, want ErrSessionNotFound", err)
	}

	// Idle timeout: advance past idle but within lifetime.
	clk.advance(11 * time.Minute)
	if _, err := m.ValidateSession(ctx, sess.ID); !errors.Is(err, ErrSessionIdle) {
		t.Fatalf("ValidateSession(idle) err = %v, want ErrSessionIdle", err)
	}
	// It was revoked on idle detection.
	if _, err := st.GetSession(ctx, sess.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("idle session not revoked: %v", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	st := newRealStore(t)
	clk := newClock()
	m, _ := New(st, WithClock(clk.now), WithRand(&seqReader{}),
		WithSessionLifetime(time.Hour), WithIdleTimeout(2*time.Hour)) // idle > lifetime so expiry triggers first
	ctx := context.Background()
	sess, err := m.CreateSession(ctx)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	clk.advance(time.Hour + time.Second)
	if _, err := m.ValidateSession(ctx, sess.ID); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("ValidateSession(expired) err = %v, want ErrSessionExpired", err)
	}
	if _, err := st.GetSession(ctx, sess.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired session not revoked: %v", err)
	}
}

func TestRotateRevokeSessions(t *testing.T) {
	st := newRealStore(t)
	m, _ := New(st, WithRand(&seqReader{}))
	ctx := context.Background()

	old, _ := m.CreateSession(ctx)
	fresh, err := m.RotateSession(ctx, old.ID)
	if err != nil {
		t.Fatalf("RotateSession: %v", err)
	}
	if fresh.ID == old.ID {
		t.Fatal("RotateSession returned same id")
	}
	if _, err := st.GetSession(ctx, old.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old session survived rotate: %v", err)
	}
	// Rotate with empty old id is fine and with a missing old id is not an error.
	if _, err := m.RotateSession(ctx, ""); err != nil {
		t.Fatalf("RotateSession(empty old): %v", err)
	}
	if _, err := m.RotateSession(ctx, "missing"); err != nil {
		t.Fatalf("RotateSession(missing old): %v", err)
	}

	// RevokeSession: existing then missing (idempotent).
	if err := m.RevokeSession(ctx, fresh.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if err := m.RevokeSession(ctx, fresh.ID); err != nil {
		t.Fatalf("RevokeSession(again): %v", err)
	}

	// RevokeAll.
	_, _ = m.CreateSession(ctx)
	_, _ = m.CreateSession(ctx)
	n, err := m.RevokeAllSessions(ctx)
	if err != nil {
		t.Fatalf("RevokeAllSessions: %v", err)
	}
	if n < 2 {
		t.Fatalf("RevokeAllSessions n = %d, want >= 2", n)
	}
}

func TestSessionErrorPaths(t *testing.T) {
	ctx := context.Background()

	fs := newFakeStore()
	fs.errs["InsertSession"] = errInjected
	m, _ := New(fs, WithRand(&seqReader{}))
	if _, err := m.CreateSession(ctx); err == nil {
		t.Fatal("CreateSession with failing store = nil, want error")
	}

	// GetSession error (not ErrNotFound) propagates.
	fs2 := newFakeStore()
	fs2.errs["GetSession"] = errInjected
	m2, _ := New(fs2, WithRand(&seqReader{}))
	if _, err := m2.ValidateSession(ctx, "x"); err == nil || errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("ValidateSession get error = %v, want wrapped injected error", err)
	}

	// TouchSession error propagates.
	fs3 := newFakeStore()
	m3, _ := New(fs3, WithRand(&seqReader{}))
	s, _ := m3.CreateSession(ctx)
	fs3.errs["TouchSession"] = errInjected
	if _, err := m3.ValidateSession(ctx, s.ID); err == nil {
		t.Fatal("ValidateSession touch error = nil, want error")
	}

	// RotateSession: create ok but delete of old fails hard.
	fs4 := newFakeStore()
	m4, _ := New(fs4, WithRand(&seqReader{}))
	old, _ := m4.CreateSession(ctx)
	fs4.errs["DeleteSession"] = errInjected
	if _, err := m4.RotateSession(ctx, old.ID); err == nil {
		t.Fatal("RotateSession delete error = nil, want error")
	}
	// RevokeSession hard error.
	if err := m4.RevokeSession(ctx, old.ID); err == nil {
		t.Fatal("RevokeSession hard error = nil, want error")
	}
	// RotateSession create error.
	fs5 := newFakeStore()
	fs5.errs["InsertSession"] = errInjected
	m5, _ := New(fs5, WithRand(&seqReader{}))
	if _, err := m5.RotateSession(ctx, "old"); err == nil {
		t.Fatal("RotateSession create error = nil, want error")
	}
	// RevokeAll error.
	fs6 := newFakeStore()
	fs6.errs["DeleteAllSessions"] = errInjected
	m6, _ := New(fs6, WithRand(&seqReader{}))
	if _, err := m6.RevokeAllSessions(ctx); err == nil {
		t.Fatal("RevokeAllSessions error = nil, want error")
	}
}

// ---- recovery codes --------------------------------------------------------

func TestRecoveryCodes(t *testing.T) {
	st := newRealStore(t)
	clk := newClock()
	m, _ := New(st, WithClock(clk.now), WithRand(&seqReader{}))
	ctx := context.Background()

	// n <= 0 uses the default count.
	codes, err := m.GenerateRecoveryCodes(ctx, 0)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if len(codes) != DefaultRecoveryCodeCount {
		t.Fatalf("default count = %d, want %d", len(codes), DefaultRecoveryCodeCount)
	}
	for _, c := range codes {
		if len(c) != 23 || strings.Count(c, "-") != 3 { // 4 groups of 5 + 3 dashes
			t.Fatalf("recovery code %q not formatted xxxxx-xxxxx-xxxxx-xxxxx", c)
		}
	}
	// Codes must be unique.
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Fatalf("duplicate recovery code %q", c)
		}
		seen[c] = true
	}

	// Verify a valid code, then confirm it is single-use.
	if err := m.VerifyRecoveryCode(ctx, codes[2]); err != nil {
		t.Fatalf("VerifyRecoveryCode(valid): %v", err)
	}
	if err := m.VerifyRecoveryCode(ctx, codes[2]); !errors.Is(err, ErrRecoveryCodeInvalid) {
		t.Fatalf("VerifyRecoveryCode(reuse) = %v, want ErrRecoveryCodeInvalid", err)
	}
	// Empty and wrong codes are invalid.
	if err := m.VerifyRecoveryCode(ctx, ""); !errors.Is(err, ErrRecoveryCodeInvalid) {
		t.Fatalf("VerifyRecoveryCode(empty) = %v, want ErrRecoveryCodeInvalid", err)
	}
	if err := m.VerifyRecoveryCode(ctx, "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ"); !errors.Is(err, ErrRecoveryCodeInvalid) {
		t.Fatalf("VerifyRecoveryCode(wrong) = %v, want ErrRecoveryCodeInvalid", err)
	}
	// A different still-unused code remains valid.
	if err := m.VerifyRecoveryCode(ctx, codes[0]); err != nil {
		t.Fatalf("VerifyRecoveryCode(other valid): %v", err)
	}
}

func TestRecoveryCodeErrorPaths(t *testing.T) {
	ctx := context.Background()

	// entropy failure during generation.
	fs := newFakeStore()
	m, _ := New(fs, WithRand(&failAfterReader{okReads: 1})) // csrf key ok, code read fails
	if _, err := m.GenerateRecoveryCodes(ctx, 3); err == nil {
		t.Fatal("GenerateRecoveryCodes entropy error = nil, want error")
	}
	// store insert failure.
	fs2 := newFakeStore()
	fs2.errs["InsertRecoveryCode"] = errInjected
	m2, _ := New(fs2, WithRand(&seqReader{}))
	if _, err := m2.GenerateRecoveryCodes(ctx, 3); err == nil {
		t.Fatal("GenerateRecoveryCodes store error = nil, want error")
	}
	// list failure.
	fs3 := newFakeStore()
	fs3.errs["ListRecoveryCodes"] = errInjected
	m3, _ := New(fs3, WithRand(&seqReader{}))
	if err := m3.VerifyRecoveryCode(ctx, "abc"); err == nil || errors.Is(err, ErrRecoveryCodeInvalid) {
		t.Fatalf("VerifyRecoveryCode list error = %v, want wrapped injected error", err)
	}
	// consume race → ErrAlreadyUsed mapped to invalid.
	fs4 := newFakeStore()
	m4, _ := New(fs4, WithRand(&seqReader{}))
	codes, _ := m4.GenerateRecoveryCodes(ctx, 1)
	fs4.errs["ConsumeRecoveryCode"] = store.ErrAlreadyUsed
	if err := m4.VerifyRecoveryCode(ctx, codes[0]); !errors.Is(err, ErrRecoveryCodeInvalid) {
		t.Fatalf("VerifyRecoveryCode consume race = %v, want ErrRecoveryCodeInvalid", err)
	}
	// consume hard error propagates.
	fs5 := newFakeStore()
	m5, _ := New(fs5, WithRand(&seqReader{}))
	codes5, _ := m5.GenerateRecoveryCodes(ctx, 1)
	fs5.errs["ConsumeRecoveryCode"] = errInjected
	if err := m5.VerifyRecoveryCode(ctx, codes5[0]); err == nil || errors.Is(err, ErrRecoveryCodeInvalid) {
		t.Fatalf("VerifyRecoveryCode consume hard error = %v, want wrapped injected error", err)
	}
}

// ---- bootstrap tokens ------------------------------------------------------

func TestBootstrapTokens(t *testing.T) {
	st := newRealStore(t)
	clk := newClock()
	m, _ := New(st, WithClock(clk.now), WithRand(&seqReader{}), WithBootstrapTTL(15*time.Minute))
	ctx := context.Background()

	token, bt, err := m.IssueBootstrapToken(ctx)
	if err != nil {
		t.Fatalf("IssueBootstrapToken: %v", err)
	}
	if !strings.HasPrefix(token, "pgbt_") {
		t.Fatalf("token %q lacks pgbt_ prefix", token)
	}
	if !bt.ExpiresAt.Equal(clk.now().Add(15 * time.Minute)) {
		t.Fatalf("ExpiresAt = %v, want now+15m", bt.ExpiresAt)
	}
	// Plaintext must not be persisted — only its hash.
	stored, _ := st.ListBootstrapTokens(ctx)
	if len(stored) != 1 || stored[0].TokenHash == token {
		t.Fatalf("token stored in plaintext or wrong count: %+v", stored)
	}

	// Consume once succeeds, twice fails (single-use).
	if err := m.ConsumeBootstrapToken(ctx, token); err != nil {
		t.Fatalf("ConsumeBootstrapToken: %v", err)
	}
	if err := m.ConsumeBootstrapToken(ctx, token); !errors.Is(err, ErrBootstrapTokenInvalid) {
		t.Fatalf("ConsumeBootstrapToken(reuse) = %v, want ErrBootstrapTokenInvalid", err)
	}
	// Empty + wrong tokens invalid.
	if err := m.ConsumeBootstrapToken(ctx, ""); !errors.Is(err, ErrBootstrapTokenInvalid) {
		t.Fatalf("ConsumeBootstrapToken(empty) = %v, want invalid", err)
	}
	if err := m.ConsumeBootstrapToken(ctx, "pgbt_deadbeef"); !errors.Is(err, ErrBootstrapTokenInvalid) {
		t.Fatalf("ConsumeBootstrapToken(wrong) = %v, want invalid", err)
	}

	// Expired token cannot be consumed.
	token2, _, _ := m.IssueBootstrapToken(ctx)
	clk.advance(16 * time.Minute)
	if err := m.ConsumeBootstrapToken(ctx, token2); !errors.Is(err, ErrBootstrapTokenInvalid) {
		t.Fatalf("ConsumeBootstrapToken(expired) = %v, want invalid", err)
	}
}

func TestBootstrapTokenErrorPaths(t *testing.T) {
	ctx := context.Background()

	// entropy failure.
	fs := newFakeStore()
	m, _ := New(fs, WithRand(&failAfterReader{okReads: 1}))
	if _, _, err := m.IssueBootstrapToken(ctx); err == nil {
		t.Fatal("IssueBootstrapToken entropy error = nil, want error")
	}
	// store insert failure.
	fs2 := newFakeStore()
	fs2.errs["InsertBootstrapToken"] = errInjected
	m2, _ := New(fs2, WithRand(&seqReader{}))
	if _, _, err := m2.IssueBootstrapToken(ctx); err == nil {
		t.Fatal("IssueBootstrapToken store error = nil, want error")
	}
	// list failure on consume.
	fs3 := newFakeStore()
	fs3.errs["ListBootstrapTokens"] = errInjected
	m3, _ := New(fs3, WithRand(&seqReader{}))
	if err := m3.ConsumeBootstrapToken(ctx, "pgbt_x"); err == nil || errors.Is(err, ErrBootstrapTokenInvalid) {
		t.Fatalf("ConsumeBootstrapToken list error = %v, want wrapped injected error", err)
	}
	// consume race.
	fs4 := newFakeStore()
	m4, _ := New(fs4, WithRand(&seqReader{}))
	tok, _, _ := m4.IssueBootstrapToken(ctx)
	fs4.errs["ConsumeBootstrapToken"] = store.ErrAlreadyUsed
	if err := m4.ConsumeBootstrapToken(ctx, tok); !errors.Is(err, ErrBootstrapTokenInvalid) {
		t.Fatalf("ConsumeBootstrapToken race = %v, want invalid", err)
	}
	// consume hard error.
	fs5 := newFakeStore()
	m5, _ := New(fs5, WithRand(&seqReader{}))
	tok5, _, _ := m5.IssueBootstrapToken(ctx)
	fs5.errs["ConsumeBootstrapToken"] = errInjected
	if err := m5.ConsumeBootstrapToken(ctx, tok5); err == nil || errors.Is(err, ErrBootstrapTokenInvalid) {
		t.Fatalf("ConsumeBootstrapToken hard error = %v, want wrapped injected error", err)
	}
}

// ---- reset-auth ------------------------------------------------------------

func TestResetAuth(t *testing.T) {
	st := newRealStore(t)
	clk := newClock()
	m, _ := New(st, WithClock(clk.now), WithRand(&seqReader{}))
	ctx := context.Background()

	// Seed some state.
	_, _ = m.CreateSession(ctx)
	_, _ = m.GenerateRecoveryCodes(ctx, 3)
	_, _, _ = m.IssueBootstrapToken(ctx)

	token, sum, err := m.ResetAuth(ctx)
	if err != nil {
		t.Fatalf("ResetAuth: %v", err)
	}
	if !strings.HasPrefix(token, "pgbt_") {
		t.Fatalf("reset token %q lacks pgbt_ prefix", token)
	}
	if sum.RecoveryCodesRemoved != 3 || sum.SessionsRevoked != 1 {
		t.Fatalf("reset summary counts wrong: %+v", sum)
	}
	// Old recovery codes/sessions gone; exactly one fresh bootstrap token.
	if codes, _ := st.ListRecoveryCodes(ctx); len(codes) != 0 {
		t.Fatalf("recovery codes survived reset: %d", len(codes))
	}
	toks, _ := st.ListBootstrapTokens(ctx)
	if len(toks) != 1 {
		t.Fatalf("bootstrap tokens after reset = %d, want 1 fresh", len(toks))
	}
	// The freshly issued token is consumable.
	if err := m.ConsumeBootstrapToken(ctx, token); err != nil {
		t.Fatalf("ConsumeBootstrapToken(fresh reset token): %v", err)
	}
}

func TestResetAuthErrorPaths(t *testing.T) {
	ctx := context.Background()
	for _, method := range []string{
		"DeleteAllWebAuthnCredentials", "DeleteAllRecoveryCodes",
		"DeleteAllSessions", "DeleteAllBootstrapTokens", "InsertBootstrapToken",
	} {
		fs := newFakeStore()
		fs.errs[method] = errInjected
		m, _ := New(fs, WithRand(&seqReader{}))
		if _, _, err := m.ResetAuth(ctx); err == nil {
			t.Fatalf("ResetAuth with %s failing = nil, want error", method)
		}
	}
}

// ---- CSRF ------------------------------------------------------------------

func TestCSRF(t *testing.T) {
	m, _ := New(newFakeStore(), WithRand(&seqReader{}), WithCSRFKey([]byte("csrf-signing-key")))
	const sid = "sess_abc"

	token, err := m.IssueCSRF(sid)
	if err != nil {
		t.Fatalf("IssueCSRF: %v", err)
	}
	if !m.VerifyCSRF(sid, token) {
		t.Fatal("VerifyCSRF(valid) = false, want true")
	}
	// Wrong session id fails (token is session-bound).
	if m.VerifyCSRF("other", token) {
		t.Fatal("VerifyCSRF(wrong session) = true, want false")
	}
	// Empty inputs, bad base64, wrong length all fail.
	if m.VerifyCSRF("", token) || m.VerifyCSRF(sid, "") {
		t.Fatal("VerifyCSRF(empty) = true, want false")
	}
	if m.VerifyCSRF(sid, "!!!not-base64!!!") {
		t.Fatal("VerifyCSRF(bad base64) = true, want false")
	}
	if m.VerifyCSRF(sid, "AAAA") { // valid base64 but wrong length
		t.Fatal("VerifyCSRF(short) = true, want false")
	}
	// A token from a different key must not verify.
	other, _ := New(newFakeStore(), WithRand(&seqReader{}), WithCSRFKey([]byte("different-key")))
	otherTok, _ := other.IssueCSRF(sid)
	if m.VerifyCSRF(sid, otherTok) {
		t.Fatal("VerifyCSRF(foreign key) = true, want false")
	}

	// IssueCSRF rand failure. csrf key is supplied, so New consumes no
	// randomness; the first (failing) read is IssueCSRF's nonce.
	mf, _ := New(newFakeStore(), WithRand(&failAfterReader{okReads: 0}), WithCSRFKey([]byte("k")))
	if _, err := mf.IssueCSRF(sid); err == nil {
		t.Fatal("IssueCSRF rand error = nil, want error")
	}
}
