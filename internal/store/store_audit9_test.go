package store

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/go2-im/poolgate/internal/model"
)

// TestJournalNewestWinsBySeq proves recovery picks the highest-Seq survivor: an
// OLDER committed <id>.json must never shadow a NEWER <id>.json.tmp (the audit's
// token-loss scenario), and flush then applies the newer token.
func TestJournalNewestWinsBySeq(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	// Committed .json with the OLDER content (Seq 1).
	if err := s.writeRotationJournal(a.ID, "aOld", "rOld"); err != nil {
		t.Fatalf("writeRotationJournal: %v", err)
	}
	// Craft a NEWER (Seq 2) mid-write .tmp directly, as a crash-before-rename would
	// leave alongside the older .json.
	jp, _ := s.rotationJournalPath(a.ID)
	sa, err := s.cipher.Seal("aNew")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	sr, err := s.cipher.Seal("rNew")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	data, _ := json.Marshal(rotationJournalEntry{Access: sa, Refresh: sr, At: "t", Seq: 2})
	if err := os.WriteFile(jp+".tmp", data, 0o600); err != nil {
		t.Fatalf("write newer .tmp: %v", err)
	}

	// readRotationJournal must return the higher-Seq (.tmp) entry, not the older .json.
	e, ok, err := s.readRotationJournal(a.ID)
	if err != nil || !ok {
		t.Fatalf("readRotationJournal ok=%v err=%v", ok, err)
	}
	if e.Refresh != "rNew" {
		t.Fatalf("recovery picked stale entry %q, want rNew (newest by Seq)", e.Refresh)
	}
	// Flush applies the NEWER token to the DB.
	if err := s.FlushPendingRotation(ctx, a.ID); err != nil {
		t.Fatalf("FlushPendingRotation: %v", err)
	}
	got, _ := s.GetAccount(ctx, a.ID)
	if got.RefreshToken != "rNew" {
		t.Fatalf("flush applied stale token %q, want rNew", got.RefreshToken)
	}
}

// TestCommitRotatedTokensCASMatchWrites proves the happy CAS path: when the DB token
// still equals expectedRefresh, the commit overwrites and clears the journal.
func TestCommitRotatedTokensCASMatchWrites(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	if err := s.CommitRotatedTokens(ctx, a.ID, "r0", "a1", "r1"); err != nil {
		t.Fatalf("CommitRotatedTokens: %v", err)
	}
	got, _ := s.GetAccount(ctx, a.ID)
	if got.AccessToken != "a1" || got.RefreshToken != "r1" {
		t.Fatalf("CAS-match commit did not persist: %+v", got)
	}
	if _, ok, _ := s.readRotationJournal(a.ID); ok {
		t.Fatal("journal should be cleared after a successful commit")
	}
}
