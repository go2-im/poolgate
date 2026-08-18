package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// ---- webauthn credentials -------------------------------------------------

func TestWebAuthnCredentialCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Missing cred_id / public_key are rejected.
	if _, err := s.InsertWebAuthnCredential(ctx, model.WebAuthnCredential{PublicKey: []byte("k")}); err == nil {
		t.Fatal("InsertWebAuthnCredential(no cred_id) = nil, want error")
	}
	if _, err := s.InsertWebAuthnCredential(ctx, model.WebAuthnCredential{CredID: []byte("c")}); err == nil {
		t.Fatal("InsertWebAuthnCredential(no public_key) = nil, want error")
	}

	c := model.WebAuthnCredential{
		CredID:     []byte{0x01, 0x02, 0x03},
		PublicKey:  []byte{0x0a, 0x0b},
		SignCount:  5,
		AAGUID:     []byte{0xff},
		Transports: []string{"usb", "hybrid"},
		Flags:      0x1d, // UP|UV|BE|BS (a synced/backup-eligible passkey)
		Label:      "phone",
	}
	got, err := s.InsertWebAuthnCredential(ctx, c)
	if err != nil {
		t.Fatalf("InsertWebAuthnCredential: %v", err)
	}
	if got.ID == "" {
		t.Fatal("insert did not assign an id")
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("insert did not default created_at")
	}

	// Look up by cred_id round-trips all fields.
	loaded, err := s.GetWebAuthnCredentialByCredID(ctx, []byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("GetWebAuthnCredentialByCredID: %v", err)
	}
	if loaded.ID != got.ID || loaded.SignCount != 5 || loaded.Label != "phone" {
		t.Fatalf("loaded mismatch: %+v", loaded)
	}
	if loaded.Flags != 0x1d {
		t.Fatalf("loaded Flags = %#x, want 0x1d (round-trip of BE/BS flags)", loaded.Flags)
	}
	if len(loaded.Transports) != 2 || loaded.Transports[0] != "usb" {
		t.Fatalf("transports mismatch: %+v", loaded.Transports)
	}

	// Missing cred_id → ErrNotFound.
	if _, err := s.GetWebAuthnCredentialByCredID(ctx, []byte{0x09}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetWebAuthnCredentialByCredID(missing) = %v, want ErrNotFound", err)
	}

	// UpdateWebAuthnSignCount.
	if err := s.UpdateWebAuthnSignCount(ctx, got.ID, 42); err != nil {
		t.Fatalf("UpdateWebAuthnSignCount: %v", err)
	}
	loaded, _ = s.GetWebAuthnCredentialByCredID(ctx, []byte{0x01, 0x02, 0x03})
	if loaded.SignCount != 42 {
		t.Fatalf("sign_count = %d, want 42", loaded.SignCount)
	}
	if err := s.UpdateWebAuthnSignCount(ctx, "nope", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateWebAuthnSignCount(missing) = %v, want ErrNotFound", err)
	}

	// Count + List.
	n, err := s.CountWebAuthnCredentials(ctx)
	if err != nil || n != 1 {
		t.Fatalf("CountWebAuthnCredentials = %d, %v; want 1, nil", n, err)
	}
	list, err := s.ListWebAuthnCredentials(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListWebAuthnCredentials = %d, %v; want 1, nil", len(list), err)
	}
	if list[0].Flags != 0x1d {
		t.Fatalf("listed Flags = %#x, want 0x1d", list[0].Flags)
	}

	// Duplicate cred_id is rejected by the UNIQUE constraint.
	if _, err := s.InsertWebAuthnCredential(ctx, model.WebAuthnCredential{CredID: []byte{0x01, 0x02, 0x03}, PublicKey: []byte{0x01}}); err == nil {
		t.Fatal("duplicate cred_id insert = nil, want unique-constraint error")
	}

	// DeleteAll wipes and reports the count.
	del, err := s.DeleteAllWebAuthnCredentials(ctx)
	if err != nil || del != 1 {
		t.Fatalf("DeleteAllWebAuthnCredentials = %d, %v; want 1, nil", del, err)
	}
	if n, _ := s.CountWebAuthnCredentials(ctx); n != 0 {
		t.Fatalf("count after delete-all = %d, want 0", n)
	}
}

// ---- sessions -------------------------------------------------------------

func TestSessionCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// expires_at is required.
	if _, err := s.InsertSession(ctx, model.Session{}); err == nil {
		t.Fatal("InsertSession(no expires_at) = nil, want error")
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	sess, err := s.InsertSession(ctx, model.Session{ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("InsertSession: %v", err)
	}
	if sess.ID == "" || sess.CreatedAt.IsZero() || sess.LastSeenAt.IsZero() {
		t.Fatalf("insert did not default id/timestamps: %+v", sess)
	}

	got, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !got.ExpiresAt.Equal(sess.ExpiresAt) {
		t.Fatalf("expires_at round-trip: %v vs %v", got.ExpiresAt, sess.ExpiresAt)
	}
	if _, err := s.GetSession(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSession(missing) = %v, want ErrNotFound", err)
	}

	// Touch slides last_seen_at.
	later := now.Add(30 * time.Minute)
	if err := s.TouchSession(ctx, sess.ID, later); err != nil {
		t.Fatalf("TouchSession: %v", err)
	}
	got, _ = s.GetSession(ctx, sess.ID)
	if !got.LastSeenAt.Equal(later) {
		t.Fatalf("last_seen_at = %v, want %v", got.LastSeenAt, later)
	}
	if err := s.TouchSession(ctx, "missing", later); !errors.Is(err, ErrNotFound) {
		t.Fatalf("TouchSession(missing) = %v, want ErrNotFound", err)
	}

	// Delete one.
	if err := s.DeleteSession(ctx, sess.ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if err := s.DeleteSession(ctx, sess.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteSession(again) = %v, want ErrNotFound", err)
	}

	// Delete-all reports the count.
	for i := 0; i < 3; i++ {
		if _, err := s.InsertSession(ctx, model.Session{ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatalf("InsertSession loop: %v", err)
		}
	}
	n, err := s.DeleteAllSessions(ctx)
	if err != nil || n != 3 {
		t.Fatalf("DeleteAllSessions = %d, %v; want 3, nil", n, err)
	}
}

// ---- recovery codes -------------------------------------------------------

func TestRecoveryCodeCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.InsertRecoveryCode(ctx, model.RecoveryCode{}); err == nil {
		t.Fatal("InsertRecoveryCode(no hash) = nil, want error")
	}

	rc, err := s.InsertRecoveryCode(ctx, model.RecoveryCode{Hash: "hash-1"})
	if err != nil {
		t.Fatalf("InsertRecoveryCode: %v", err)
	}
	if rc.ID == "" {
		t.Fatal("insert did not assign id")
	}
	if _, err := s.InsertRecoveryCode(ctx, model.RecoveryCode{Hash: "hash-2"}); err != nil {
		t.Fatalf("InsertRecoveryCode 2: %v", err)
	}

	list, err := s.ListRecoveryCodes(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListRecoveryCodes = %d, %v; want 2, nil", len(list), err)
	}
	for _, c := range list {
		if c.Used() {
			t.Fatalf("fresh recovery code marked used: %+v", c)
		}
	}

	// Consume once, then again → ErrAlreadyUsed. Missing id → ErrNotFound.
	used := time.Now().UTC()
	if err := s.ConsumeRecoveryCode(ctx, rc.ID, used); err != nil {
		t.Fatalf("ConsumeRecoveryCode: %v", err)
	}
	if err := s.ConsumeRecoveryCode(ctx, rc.ID, used); !errors.Is(err, ErrAlreadyUsed) {
		t.Fatalf("ConsumeRecoveryCode(again) = %v, want ErrAlreadyUsed", err)
	}
	if err := s.ConsumeRecoveryCode(ctx, "missing", used); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ConsumeRecoveryCode(missing) = %v, want ErrNotFound", err)
	}
	// The consumed code now reports Used.
	list, _ = s.ListRecoveryCodes(ctx)
	var found bool
	for _, c := range list {
		if c.ID == rc.ID {
			found = true
			if !c.Used() {
				t.Fatalf("consumed code not marked used: %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("consumed code missing from list")
	}

	n, err := s.DeleteAllRecoveryCodes(ctx)
	if err != nil || n != 2 {
		t.Fatalf("DeleteAllRecoveryCodes = %d, %v; want 2, nil", n, err)
	}
}

// ---- bootstrap tokens -----------------------------------------------------

func TestBootstrapTokenCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Missing hash / expiry rejected.
	if _, err := s.InsertBootstrapToken(ctx, model.BootstrapToken{ExpiresAt: time.Now()}); err == nil {
		t.Fatal("InsertBootstrapToken(no hash) = nil, want error")
	}
	if _, err := s.InsertBootstrapToken(ctx, model.BootstrapToken{TokenHash: "h"}); err == nil {
		t.Fatal("InsertBootstrapToken(no expiry) = nil, want error")
	}

	exp := time.Now().UTC().Add(15 * time.Minute)
	bt, err := s.InsertBootstrapToken(ctx, model.BootstrapToken{TokenHash: "tok-hash", ExpiresAt: exp})
	if err != nil {
		t.Fatalf("InsertBootstrapToken: %v", err)
	}
	if bt.ID == "" {
		t.Fatal("insert did not assign id")
	}

	list, err := s.ListBootstrapTokens(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListBootstrapTokens = %d, %v; want 1, nil", len(list), err)
	}
	if list[0].Used() || !list[0].ExpiresAt.Equal(exp) {
		t.Fatalf("bootstrap token round-trip wrong: %+v", list[0])
	}

	used := time.Now().UTC()
	if err := s.ConsumeBootstrapToken(ctx, bt.ID, used); err != nil {
		t.Fatalf("ConsumeBootstrapToken: %v", err)
	}
	if err := s.ConsumeBootstrapToken(ctx, bt.ID, used); !errors.Is(err, ErrAlreadyUsed) {
		t.Fatalf("ConsumeBootstrapToken(again) = %v, want ErrAlreadyUsed", err)
	}
	if err := s.ConsumeBootstrapToken(ctx, "missing", used); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ConsumeBootstrapToken(missing) = %v, want ErrNotFound", err)
	}

	n, err := s.DeleteAllBootstrapTokens(ctx)
	if err != nil || n != 1 {
		t.Fatalf("DeleteAllBootstrapTokens = %d, %v; want 1, nil", n, err)
	}
}

// TestSchemaVersionV3 confirms migration v3 landed and the new tables exist.
func TestSchemaVersionV3(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	v, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v < 3 {
		t.Fatalf("SchemaVersion = %d, want >= 3", v)
	}
	for _, tbl := range []string{"webauthn_credentials", "sessions", "recovery_codes", "bootstrap_tokens"} {
		var name string
		if err := s.db.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&name); err != nil {
			t.Fatalf("table %q missing after v3 migration: %v", tbl, err)
		}
	}
}
