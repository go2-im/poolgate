package store

import (
	"context"
	"testing"

	"github.com/go2-im/poolgate/internal/config"
	"github.com/go2-im/poolgate/internal/crypto"
	"github.com/go2-im/poolgate/internal/model"
)

// TestRotateSecretsReEncrypts verifies master-key rotation: after RotateSecrets,
// secrets decrypt under the NEW cipher (reopened store) and NOT under the old one.
func TestRotateSecretsReEncrypts(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.DataDir = t.TempDir()

	oldKey := bytesKey(1)
	oldCipher, _ := crypto.New(oldKey)
	s, err := Open(cfg, oldCipher)
	if err != nil {
		t.Fatalf("open old: %v", err)
	}

	acct, err := s.InsertAccount(ctx, model.Account{
		Label: "a1", AccessToken: "ACCESS-SECRET", RefreshToken: "REFRESH-SECRET",
		AccountID: "acc-1", State: model.StateOK,
	})
	if err != nil {
		t.Fatalf("insert account: %v", err)
	}
	ch, err := s.InsertNotifyChannel(ctx, model.NotifyChannel{
		Type: model.ChannelDingTalk, Name: "dt", Enabled: true,
		Config: model.NotifyConfig{URL: "https://hook.example", Secret: "SIGN-SECRET"},
	})
	if err != nil {
		t.Fatalf("insert channel: %v", err)
	}

	newKey := bytesKey(200)
	newCipher, _ := crypto.New(newKey)
	nAcc, nCh, err := s.RotateSecrets(ctx, newCipher)
	if err != nil {
		t.Fatalf("RotateSecrets: %v", err)
	}
	if nAcc != 1 || nCh != 1 {
		t.Fatalf("rotated %d accounts / %d channels, want 1/1", nAcc, nCh)
	}
	_ = s.Close()

	// Reopen with the NEW key: secrets must decrypt to the original plaintext.
	sNew, err := Open(cfg, newCipher)
	if err != nil {
		t.Fatalf("open new: %v", err)
	}
	defer sNew.Close()
	got, err := sNew.GetAccount(ctx, acct.ID)
	if err != nil {
		t.Fatalf("GetAccount under new key: %v", err)
	}
	if got.AccessToken != "ACCESS-SECRET" || got.RefreshToken != "REFRESH-SECRET" {
		t.Errorf("tokens under new key = %q/%q, want the originals", got.AccessToken, got.RefreshToken)
	}
	gotCh, err := sNew.GetNotifyChannel(ctx, ch.ID)
	if err != nil {
		t.Fatalf("GetNotifyChannel under new key: %v", err)
	}
	if gotCh.Config.Secret != "SIGN-SECRET" || gotCh.Config.URL != "https://hook.example" {
		t.Errorf("channel config under new key = %+v, want the originals", gotCh.Config)
	}

	// The OLD key must no longer decrypt the rotated secrets.
	sOld, err := Open(cfg, oldCipher)
	if err != nil {
		t.Fatalf("open old-again: %v", err)
	}
	defer sOld.Close()
	if _, err := sOld.GetAccount(ctx, acct.ID); err == nil {
		t.Error("GetAccount succeeded under the OLD key after rotation, want a decrypt failure")
	}
}

func bytesKey(seed byte) []byte {
	k := make([]byte, crypto.KeySize)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}
