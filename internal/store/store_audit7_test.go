package store

import (
	"context"
	"errors"
	"testing"

	"github.com/go2-im/poolgate/internal/model"
)

func TestInsertAccountUnique(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.InsertAccountUnique(ctx, model.Account{AccountID: "acc-1", AccessToken: "a", RefreshToken: "r"}); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	// A second insert with the same account_id is REFUSED (no overwrite).
	if _, err := s.InsertAccountUnique(ctx, model.Account{AccountID: "acc-1", AccessToken: "a2", RefreshToken: "r2"}); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate insert = %v, want ErrAlreadyExists", err)
	}
	// The live row still has the ORIGINAL token (never rolled back).
	all, _ := s.ListAccounts(ctx)
	if len(all) != 1 || all[0].AccessToken != "a" {
		t.Fatalf("row = %+v, want single row with original token", all)
	}
	// Empty account_id always inserts a distinct row.
	c1, err := s.InsertAccountUnique(ctx, model.Account{AccessToken: "x"})
	if err != nil {
		t.Fatalf("empty insert 1: %v", err)
	}
	c2, err := s.InsertAccountUnique(ctx, model.Account{AccessToken: "y"})
	if err != nil {
		t.Fatalf("empty insert 2: %v", err)
	}
	if c1.ID == c2.ID {
		t.Fatal("empty account_id must not dedupe")
	}
}

func TestUpsertReplaceClearsPendingJournal(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	a, err := s.InsertAccount(ctx, model.Account{AccountID: "acc-1", AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	// A pending rotation journal exists for the account.
	if err := s.writeRotationJournal(a.ID, "aJ", "rJ"); err != nil {
		t.Fatalf("writeRotationJournal: %v", err)
	}
	// A login replace (fresh creds) must clear the pending journal so it can't later
	// overwrite the new credentials.
	replaced, updated, err := s.UpsertAccountByAccountID(ctx, model.Account{AccountID: "acc-1", AccessToken: "aNew", RefreshToken: "rNew"})
	if err != nil || !updated {
		t.Fatalf("replace: updated=%v err=%v", updated, err)
	}
	if replaced.RefreshToken != "rNew" {
		t.Fatalf("token = %q, want rNew", replaced.RefreshToken)
	}
	if _, ok, _ := s.readRotationJournal(a.ID); ok {
		t.Fatal("replace must clear the pending rotation journal")
	}
}

func TestDeleteAccountRemovesJournal(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	if err := s.writeRotationJournal(a.ID, "aJ", "rJ"); err != nil {
		t.Fatalf("writeRotationJournal: %v", err)
	}
	if err := s.DeleteAccount(ctx, a.ID); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}
	if _, ok, _ := s.readRotationJournal(a.ID); ok {
		t.Fatal("DeleteAccount must remove the account's rotation journal")
	}
}

func TestPendingRotationIDs(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	if ids, err := s.PendingRotationIDs(); err != nil || len(ids) != 0 {
		t.Fatalf("initial pending = %v err %v, want empty", ids, err)
	}
	a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	if err := s.writeRotationJournal(a.ID, "aJ", "rJ"); err != nil {
		t.Fatalf("writeRotationJournal: %v", err)
	}
	ids, err := s.PendingRotationIDs()
	if err != nil {
		t.Fatalf("PendingRotationIDs: %v", err)
	}
	if len(ids) != 1 || ids[0] != a.ID {
		t.Fatalf("pending = %v, want [%s]", ids, a.ID)
	}
	// The standalone helper (no open DB) sees the same journal.
	at, err := PendingRotationIDsAt(dir)
	if err != nil || len(at) != 1 || at[0] != a.ID {
		t.Fatalf("PendingRotationIDsAt = %v err %v, want [%s]", at, err, a.ID)
	}
	if empty, err := PendingRotationIDsAt(""); err != nil || empty != nil {
		t.Fatalf("PendingRotationIDsAt(\"\") = %v err %v, want nil", empty, err)
	}
}
