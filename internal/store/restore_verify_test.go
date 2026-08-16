package store

import (
	"context"
	"testing"

	"github.com/go2-im/poolgate/internal/config"
	"github.com/go2-im/poolgate/internal/crypto"
	"github.com/go2-im/poolgate/internal/model"
)

func TestVerifyRestoreBundle(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i + 7)
	}
	c, err := crypto.New(key)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	s, err := Open(cfg, c)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.InsertAccount(context.Background(), model.Account{
		Label: "a", AccessToken: "at-secret", RefreshToken: "rt-secret",
	}); err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	_ = s.Close()

	db, _, err := Snapshot(cfg)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Correct key + valid image passes.
	if err := VerifyRestoreBundle(db, key); err != nil {
		t.Fatalf("VerifyRestoreBundle(correct key) = %v, want nil", err)
	}

	// Wrong key fails the sample decrypt.
	wrong := make([]byte, crypto.KeySize)
	for i := range wrong {
		wrong[i] = byte(255 - i)
	}
	if err := VerifyRestoreBundle(db, wrong); err == nil {
		t.Fatal("VerifyRestoreBundle(wrong key) = nil, want mismatch error")
	}

	// Corrupt image fails integrity_check (or opens as not-a-DB).
	garbage := append([]byte("SQLite format 3\x00"), []byte("not a real database")...)
	if err := VerifyRestoreBundle(garbage, key); err == nil {
		t.Fatal("VerifyRestoreBundle(garbage) = nil, want error")
	}
}

func TestCurrentSchemaVersion(t *testing.T) {
	if CurrentSchemaVersion() != len(migrations) {
		t.Fatalf("CurrentSchemaVersion = %d, want %d", CurrentSchemaVersion(), len(migrations))
	}
}
