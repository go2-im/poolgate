package store

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/go2-im/poolgate/internal/model"
)

// TestJournalNewerGenerationWins proves recovery picks the highest-generation
// survivor: an OLDER committed <id>.json (lower target version) must never shadow a
// NEWER <id>.json.tmp (higher target version) — the audit's token-loss scenario — and
// flush then applies the newer token, gated on the DB still being at the newer entry's
// base version.
func TestJournalNewerGenerationWins(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	// Advance the account to credential_version 1 (gen-1 applied), so a base-1 -> 2
	// pending rotation is coherent.
	if _, _, err := s.CommitRotatedTokens(ctx, a.ID, 0, "a1", "r1"); err != nil {
		t.Fatalf("seed gen-1: %v", err)
	}

	// A leftover OLDER committed .json for the already-applied gen 1 (base 0 -> 1).
	if err := s.writeRotationJournal(a.ID, "aOld", "rOld", 0, 1, "refresh"); err != nil {
		t.Fatalf("writeRotationJournal: %v", err)
	}
	// Craft a NEWER (gen 2, base 1 -> 2) mid-write .tmp directly, as a crash-before-rename
	// would leave alongside the older .json.
	jp, _ := s.rotationJournalPath(a.ID)
	sa, err := s.cipher.Seal("aNew")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	sr, err := s.cipher.Seal("rNew")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	data, _ := json.Marshal(rotationJournalEntry{Access: sa, Refresh: sr, At: "t", Seq: 2, BaseVersion: 1, TargetVersion: 2, Operation: "refresh"})
	if err := os.WriteFile(jp+".tmp", data, 0o600); err != nil {
		t.Fatalf("write newer .tmp: %v", err)
	}

	// readRotationJournal must return the higher-target (.tmp) entry, not the older .json.
	e, ok, err := s.readRotationJournal(a.ID)
	if err != nil || !ok {
		t.Fatalf("readRotationJournal ok=%v err=%v", ok, err)
	}
	if e.Refresh != "rNew" {
		t.Fatalf("recovery picked stale entry %q, want rNew (newest generation)", e.Refresh)
	}
	// Flush applies the NEWER token to the DB and lands the account at version 2.
	if err := s.FlushPendingRotation(ctx, a.ID); err != nil {
		t.Fatalf("FlushPendingRotation: %v", err)
	}
	got, _ := s.GetAccount(ctx, a.ID)
	if got.RefreshToken != "rNew" {
		t.Fatalf("flush applied stale token %q, want rNew", got.RefreshToken)
	}
	if got.CredentialVersion != 2 {
		t.Fatalf("credential_version = %d, want 2", got.CredentialVersion)
	}
}

// TestJournalNewerHelperOrdersByTargetThenSeq unit-tests the ordering predicate:
// higher target version wins; equal target falls back to higher Seq.
func TestJournalNewerHelperOrdersByTargetThenSeq(t *testing.T) {
	older := rotationJournalEntry{TargetVersion: 1, Seq: 9}
	newer := rotationJournalEntry{TargetVersion: 2, Seq: 1}
	if !journalNewer(newer, older) || journalNewer(older, newer) {
		t.Fatal("higher TargetVersion must win regardless of Seq")
	}
	lowSeq := rotationJournalEntry{TargetVersion: 5, Seq: 1}
	highSeq := rotationJournalEntry{TargetVersion: 5, Seq: 2}
	if !journalNewer(highSeq, lowSeq) || journalNewer(lowSeq, highSeq) {
		t.Fatal("equal TargetVersion must tie-break on higher Seq")
	}
}

// TestCommitRotatedTokensCASMatchWrites proves the happy CAS path: when the DB
// credential_version still equals the base, the commit overwrites and clears the journal.
func TestCommitRotatedTokensCASMatchWrites(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	if _, applied, err := s.CommitRotatedTokens(ctx, a.ID, 0, "a1", "r1"); err != nil || !applied {
		t.Fatalf("CommitRotatedTokens: applied=%v err=%v", applied, err)
	}
	got, _ := s.GetAccount(ctx, a.ID)
	if got.AccessToken != "a1" || got.RefreshToken != "r1" {
		t.Fatalf("CAS-match commit did not persist: %+v", got)
	}
	if _, ok, _ := s.readRotationJournal(a.ID); ok {
		t.Fatal("journal should be cleared after a successful commit")
	}
}
