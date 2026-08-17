package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/go2-im/poolgate/internal/model"
)

// TestCredentialVersionMonotonic proves every credential mutation bumps
// credential_version: insert starts at 0, an online-refresh commit -> 1, an
// interactive login-replace -> 2.
func TestCredentialVersionMonotonic(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	a, err := s.InsertAccount(ctx, model.Account{AccountID: "acc-1", AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	// Re-read from the DB so we verify migration v14's DEFAULT 0 column, not the
	// zero-valued input struct InsertAccount echoes back.
	fresh, err := s.GetAccount(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if fresh.CredentialVersion != 0 {
		t.Fatalf("fresh account DB version = %d, want 0", fresh.CredentialVersion)
	}
	if _, applied, err := s.CommitRotatedTokens(ctx, a.ID, 0, "a1", "r1"); err != nil || !applied {
		t.Fatalf("refresh commit: applied=%v err=%v", applied, err)
	}
	v1, _ := s.GetAccount(ctx, a.ID)
	if v1.CredentialVersion != 1 {
		t.Fatalf("after refresh version = %d, want 1", v1.CredentialVersion)
	}
	replaced, updated, err := s.UpsertAccountByAccountID(ctx, model.Account{AccountID: "acc-1", AccessToken: "a2", RefreshToken: "r2"})
	if err != nil || !updated {
		t.Fatalf("login replace: updated=%v err=%v", updated, err)
	}
	if replaced.CredentialVersion != 2 {
		t.Fatalf("after login version = %d, want 2", replaced.CredentialVersion)
	}
}

// TestConcurrentRefreshSupersededByLogin proves the P1#3/P2#7 fix: a login that bumps
// the credential generation wins, and an in-flight refresh that read the OLD base
// version is superseded — its commit does NOT clobber the fresh login credentials,
// and it reports the login's creds as the authoritative winner.
func TestConcurrentRefreshSupersededByLogin(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	a, err := s.InsertAccount(ctx, model.Account{AccountID: "acc-1", AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	base := a.CredentialVersion // a refresh reads base 0 here

	// A login replaces the credentials first, bumping the version to 1.
	if _, updated, err := s.UpsertAccountByAccountID(ctx, model.Account{AccountID: "acc-1", AccessToken: "aLogin", RefreshToken: "rLogin"}); err != nil || !updated {
		t.Fatalf("login replace: updated=%v err=%v", updated, err)
	}

	// The in-flight refresh now commits against the STALE base 0: superseded.
	winner, applied, err := s.CommitRotatedTokens(ctx, a.ID, base, "aRefresh", "rRefresh")
	if err != nil {
		t.Fatalf("superseded commit err: %v", err)
	}
	if applied {
		t.Fatal("stale-base refresh commit must NOT apply over the newer login generation")
	}
	if winner.RefreshToken != "rLogin" || winner.AccessToken != "aLogin" {
		t.Fatalf("winner = %q/%q, want the login creds aLogin/rLogin", winner.AccessToken, winner.RefreshToken)
	}
	// The DB retained the login credentials (refresh did not clobber them).
	got, _ := s.GetAccount(ctx, a.ID)
	if got.RefreshToken != "rLogin" {
		t.Fatalf("DB token = %q, want rLogin (login won)", got.RefreshToken)
	}
	if _, ok, _ := s.readRotationJournal(a.ID); ok {
		t.Fatal("superseded refresh must not leave a journal")
	}
}

// TestFlushAlreadyAppliedDropsJournal proves a journal whose target generation the DB
// has already reached (or passed) is dropped without re-writing tokens.
func TestFlushAlreadyAppliedDropsJournal(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	// Advance to version 1.
	if _, _, err := s.CommitRotatedTokens(ctx, a.ID, 0, "a1", "r1"); err != nil {
		t.Fatalf("seed v1: %v", err)
	}
	// A stale journal for the ALREADY-APPLIED gen 1 (base 0 -> target 1).
	if err := s.writeRotationJournal(a.ID, "aStale", "rStale", 0, 1, "refresh"); err != nil {
		t.Fatalf("writeRotationJournal: %v", err)
	}
	if err := s.FlushPendingRotation(ctx, a.ID); err != nil {
		t.Fatalf("flush: %v", err)
	}
	got, _ := s.GetAccount(ctx, a.ID)
	if got.RefreshToken != "r1" || got.CredentialVersion != 1 {
		t.Fatalf("already-applied journal must not rewrite tokens: %+v", got)
	}
	if _, ok, _ := s.readRotationJournal(a.ID); ok {
		t.Fatal("already-applied journal should be dropped")
	}
}

// TestFlushAmbiguousFailsClosed proves a journal that cannot be proven coherent with
// the DB version (base above the DB version) is RETAINED and surfaces an error, so the
// account stays blocked rather than reusing a possibly-consumed token.
func TestFlushAmbiguousFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	// DB is at version 0; a journal claims base 5 -> 6 (impossible to reconcile).
	if err := s.writeRotationJournal(a.ID, "aX", "rX", 5, 6, "refresh"); err != nil {
		t.Fatalf("writeRotationJournal: %v", err)
	}
	if err := s.FlushPendingRotation(ctx, a.ID); err == nil {
		t.Fatal("ambiguous journal must fail closed")
	}
	got, _ := s.GetAccount(ctx, a.ID)
	if got.RefreshToken != "r0" {
		t.Fatalf("ambiguous flush must not rewrite tokens: %+v", got)
	}
	if _, ok, _ := s.readRotationJournal(a.ID); !ok {
		t.Fatal("ambiguous journal must be RETAINED for later inspection")
	}
	// It also keeps the account listed as pending (backup/rekey refuse).
	if ids, _ := s.PendingRotationIDs(); len(ids) != 1 || ids[0] != a.ID {
		t.Fatalf("pending = %v, want [%s]", ids, a.ID)
	}
}

// TestFlushLegacyJournalAppliedUnconditionally proves a pre-v14 journal (no version
// metadata, TargetVersion 0) is applied unconditionally and bumps the version,
// preserving the historical flush-on-startup behavior.
func TestFlushLegacyJournalAppliedUnconditionally(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	// Advance to version 3 to prove the legacy apply bumps from wherever the DB is.
	for i := 0; i < 3; i++ {
		if _, _, err := s.CommitRotatedTokens(ctx, a.ID, int64(i), "a", "r"); err != nil {
			t.Fatalf("seed rotation %d: %v", i, err)
		}
	}
	// Hand-write a LEGACY entry (base/target absent -> both 0) with sealed tokens.
	if err := os.MkdirAll(s.rotationsDir(), 0o700); err != nil {
		t.Fatalf("mkdir rotations: %v", err)
	}
	jp, _ := s.rotationJournalPath(a.ID)
	sa, _ := s.cipher.Seal("aLegacy")
	sr, _ := s.cipher.Seal("rLegacy")
	data, _ := json.Marshal(rotationJournalEntry{Access: sa, Refresh: sr, At: "t", Seq: 1})
	if err := os.WriteFile(jp, data, 0o600); err != nil {
		t.Fatalf("write legacy journal: %v", err)
	}
	if err := s.FlushPendingRotation(ctx, a.ID); err != nil {
		t.Fatalf("flush legacy: %v", err)
	}
	got, _ := s.GetAccount(ctx, a.ID)
	if got.RefreshToken != "rLegacy" {
		t.Fatalf("legacy journal not applied: %+v", got)
	}
	if got.CredentialVersion != 4 {
		t.Fatalf("legacy apply version = %d, want 4 (bumped from 3)", got.CredentialVersion)
	}
	if _, ok, _ := s.readRotationJournal(a.ID); ok {
		t.Fatal("legacy journal should be removed after apply")
	}
}

// TestCorruptSiblingHandling proves the corrupt-aware recovery policy (P1#2 fix,
// refined for D10 seamless recovery):
//   - the STRICT readRotationJournal still surfaces an error whenever any candidate is
//     corrupt (conservative oracle);
//   - flush APPLIES a valid, coherent (dbVer==base) candidate and cleans up the corrupt
//     sibling, because a coherent newer generation would require the DB to be past base
//     (so the corrupt sibling is provably garbage);
//   - but when the valid candidate is already-applied (drop territory) and a corrupt
//     sibling is present, flush FAILS CLOSED — the corrupt one could be a lost newer
//     generation, so we must not silently drop and reuse the DB token.
func TestCorruptSiblingHandling(t *testing.T) {
	ctx := context.Background()

	// Case 1: valid coherent .json (base0->1, dbVer 0) + corrupt .tmp → flush applies
	// the valid entry and cleans up both files.
	t.Run("applicable_valid_beside_corrupt_applies", func(t *testing.T) {
		dir := t.TempDir()
		s := openStoreDir(t, dir)
		a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
		if err != nil {
			t.Fatalf("InsertAccount: %v", err)
		}
		if err := s.writeRotationJournal(a.ID, "aValid", "rValid", 0, 1, "refresh"); err != nil {
			t.Fatalf("writeRotationJournal: %v", err)
		}
		jp, _ := s.rotationJournalPath(a.ID)
		if err := os.WriteFile(jp+".tmp", []byte("not json"), 0o600); err != nil {
			t.Fatalf("write corrupt tmp: %v", err)
		}
		// The STRICT reader still fails closed on any corruption.
		if _, _, err := s.readRotationJournal(a.ID); err == nil {
			t.Fatal("strict readRotationJournal must error when any candidate is corrupt")
		}
		// Flush applies the coherent valid entry (the corrupt .tmp is provably garbage).
		if err := s.FlushPendingRotation(ctx, a.ID); err != nil {
			t.Fatalf("flush should apply the coherent valid entry, got %v", err)
		}
		got, _ := s.GetAccount(ctx, a.ID)
		if got.RefreshToken != "rValid" || got.CredentialVersion != 1 {
			t.Fatalf("flush must apply the valid entry: %+v", got)
		}
		// Both journal files (incl. the corrupt .tmp) are cleaned up — backup/rekey unblocked.
		if ids, _ := s.PendingRotationIDs(); len(ids) != 0 {
			t.Fatalf("corrupt sibling should be cleaned up on apply, pending=%v", ids)
		}
	})

	// Case 2: already-applied valid .json (base0->1, dbVer 1) + corrupt .tmp (could be a
	// lost newer gen) → flush FAILS CLOSED and retains the journal.
	t.Run("already_applied_beside_corrupt_fails_closed", func(t *testing.T) {
		dir := t.TempDir()
		s := openStoreDir(t, dir)
		a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
		if err != nil {
			t.Fatalf("InsertAccount: %v", err)
		}
		if _, _, err := s.CommitRotatedTokens(ctx, a.ID, 0, "a1", "r1"); err != nil {
			t.Fatalf("seed v1: %v", err)
		}
		// A stale already-applied .json (base0->1) plus a corrupt .tmp.
		if err := s.writeRotationJournal(a.ID, "aStale", "rStale", 0, 1, "refresh"); err != nil {
			t.Fatalf("writeRotationJournal: %v", err)
		}
		jp, _ := s.rotationJournalPath(a.ID)
		if err := os.WriteFile(jp+".tmp", []byte("garbage"), 0o600); err != nil {
			t.Fatalf("write corrupt tmp: %v", err)
		}
		if err := s.FlushPendingRotation(ctx, a.ID); err == nil {
			t.Fatal("already-applied valid + corrupt sibling must fail closed")
		}
		if got, _ := s.GetAccount(ctx, a.ID); got.RefreshToken != "r1" {
			t.Fatalf("fail-closed flush must not change tokens: %+v", got)
		}
		if ids, _ := s.PendingRotationIDs(); len(ids) != 1 {
			t.Fatalf("fail-closed must retain the journal, pending=%v", ids)
		}
	})

	// Case 3: corrupt .tmp alone (no valid candidate) → flush fails closed.
	t.Run("corrupt_only_fails_closed", func(t *testing.T) {
		dir := t.TempDir()
		s := openStoreDir(t, dir)
		a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
		if err != nil {
			t.Fatalf("InsertAccount: %v", err)
		}
		if err := os.MkdirAll(s.rotationsDir(), 0o700); err != nil {
			t.Fatalf("mkdir rotations: %v", err)
		}
		jp, _ := s.rotationJournalPath(a.ID)
		if err := os.WriteFile(jp+".tmp", []byte("not json"), 0o600); err != nil {
			t.Fatalf("write corrupt tmp: %v", err)
		}
		if err := s.FlushPendingRotation(ctx, a.ID); err == nil {
			t.Fatal("corrupt-only journal must fail closed")
		}
	})

	// Case 4: a version-less LEGACY journal beside a corrupt sibling cannot be ordered → fail closed.
	t.Run("legacy_beside_corrupt_fails_closed", func(t *testing.T) {
		dir := t.TempDir()
		s := openStoreDir(t, dir)
		a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
		if err != nil {
			t.Fatalf("InsertAccount: %v", err)
		}
		if err := os.MkdirAll(s.rotationsDir(), 0o700); err != nil {
			t.Fatalf("mkdir rotations: %v", err)
		}
		jp, _ := s.rotationJournalPath(a.ID)
		sa, _ := s.cipher.Seal("aLegacy")
		sr, _ := s.cipher.Seal("rLegacy")
		data, _ := json.Marshal(rotationJournalEntry{Access: sa, Refresh: sr, At: "t", Seq: 1}) // target 0 = legacy
		if err := os.WriteFile(jp, data, 0o600); err != nil {
			t.Fatalf("write legacy journal: %v", err)
		}
		if err := os.WriteFile(jp+".tmp", []byte("garbage"), 0o600); err != nil {
			t.Fatalf("write corrupt tmp: %v", err)
		}
		if err := s.FlushPendingRotation(ctx, a.ID); err == nil {
			t.Fatal("legacy journal beside a corrupt sibling must fail closed")
		}
		if got, _ := s.GetAccount(ctx, a.ID); got.RefreshToken != "r0" {
			t.Fatalf("fail-closed legacy flush must not rewrite tokens: %+v", got)
		}
	})

	// Case 5: an unsafe id surfaces the path error through flush.
	t.Run("unsafe_id_path_error", func(t *testing.T) {
		dir := t.TempDir()
		s := openStoreDir(t, dir)
		if err := s.FlushPendingRotation(ctx, "a/b"); err == nil {
			t.Fatal("flush with an unsafe id must surface the path error")
		}
	})
}

// TestUpdateTokensCASBranches directly exercises the version compare-and-swap: a
// matching base applies, a mismatched base on an existing row is a superseded no-op
// (applied=false, nil error), and a missing row is ErrNotFound.
func TestUpdateTokensCASBranches(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	// Matching base 0 -> applies, version becomes 1.
	if applied, err := s.updateTokensCAS(ctx, a.ID, 0, 1, "a1", "r1"); err != nil || !applied {
		t.Fatalf("CAS match: applied=%v err=%v", applied, err)
	}
	// Mismatched base (row now at 1) -> superseded no-op.
	if applied, err := s.updateTokensCAS(ctx, a.ID, 0, 1, "aX", "rX"); err != nil || applied {
		t.Fatalf("CAS mismatch: applied=%v err=%v, want (false,nil)", applied, err)
	}
	if got, _ := s.GetAccount(ctx, a.ID); got.RefreshToken != "r1" {
		t.Fatalf("superseded CAS must not overwrite: %+v", got)
	}
	// Missing row -> ErrNotFound.
	if _, err := s.updateTokensCAS(ctx, "acct_missing", 0, 1, "a", "r"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("CAS on missing row = %v, want ErrNotFound", err)
	}
	// An unsafe id is rejected by readRotationJournal before any file access.
	if _, _, err := s.readRotationJournal("a/b"); err == nil {
		t.Fatal("readRotationJournal must reject an unsafe id")
	}
	// A closed DB surfaces the begin-tx error branch.
	_ = s.DB().Close()
	if _, err := s.updateTokensCAS(ctx, a.ID, 1, 2, "a", "r"); err == nil {
		t.Fatal("updateTokensCAS must surface a begin-tx error on a closed DB")
	}
}

// TestCommitRotatedTokensReReadError proves a non-ErrNotFound re-read failure inside
// the commit surfaces (rather than silently proceeding): with the DB closed, the
// authoritative GetAccount errors and the commit aborts.
func TestCommitRotatedTokensReReadError(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	_ = s.DB().Close() // subsequent GetAccount errors (not ErrNotFound)
	if _, _, err := s.CommitRotatedTokens(ctx, a.ID, 0, "a1", "r1"); err == nil {
		t.Fatal("commit must surface a re-read error when the DB is unavailable")
	}
}

// TestFlushReReadError proves the flush path surfaces a non-ErrNotFound re-read
// failure and RETAINS the journal (fail-closed) rather than dropping it.
func TestFlushReReadError(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	if err := s.writeRotationJournal(a.ID, "aP", "rP", 0, 1, "refresh"); err != nil {
		t.Fatalf("writeRotationJournal: %v", err)
	}
	_ = s.DB().Close()
	if err := s.FlushPendingRotation(ctx, a.ID); err == nil {
		t.Fatal("flush must surface a re-read error when the DB is unavailable")
	}
	// Journal is retained (the file read still works on a closed DB).
	if _, ok, _ := s.readRotationJournal(a.ID); !ok {
		t.Fatal("flush re-read error must retain the journal")
	}
}

// TestUpsertAndUniqueLookupErrors covers the non-ErrNoRows lookup-error branches of
// the two credential-insert paths (login-upsert and file-import), which surface a
// wrapped error rather than silently inserting a duplicate.
func TestUpsertAndUniqueLookupErrors(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	if _, err := s.InsertAccount(ctx, model.Account{AccountID: "acc-1", AccessToken: "a0", RefreshToken: "r0", State: model.StateOK}); err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	_ = s.DB().Close() // the account_id lookup SELECT now errors (not sql.ErrNoRows)

	if _, _, err := s.UpsertAccountByAccountID(ctx, model.Account{AccountID: "acc-1", AccessToken: "a1", RefreshToken: "r1"}); err == nil {
		t.Fatal("UpsertAccountByAccountID must surface a lookup error")
	}
	if _, err := s.InsertAccountUnique(ctx, model.Account{AccountID: "acc-1", AccessToken: "a2", RefreshToken: "r2"}); err == nil {
		t.Fatal("InsertAccountUnique must surface a lookup error")
	}
}

// TestUpsertReplaceJournalWriteError proves the login-replace path fails (leaving the
// row unchanged) when the recovery journal cannot be written first — never overwriting
// credentials without a durable recovery copy.
func TestUpsertReplaceJournalWriteError(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	if _, err := s.InsertAccount(ctx, model.Account{AccountID: "acc-1", AccessToken: "a0", RefreshToken: "r0", State: model.StateOK}); err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	// Occupy the rotations dir path with a FILE so writeRotationJournal (MkdirAll) fails.
	_ = os.RemoveAll(s.rotationsDir())
	if err := os.WriteFile(s.rotationsDir(), []byte("x"), 0o600); err != nil {
		t.Fatalf("occupy rotations path: %v", err)
	}
	if _, _, err := s.UpsertAccountByAccountID(ctx, model.Account{AccountID: "acc-1", AccessToken: "aNew", RefreshToken: "rNew"}); err == nil {
		t.Fatal("login replace must fail when the recovery journal cannot be written")
	}
	// The original credentials are untouched (nothing overwritten without a journal).
	all, _ := s.ListAccounts(ctx)
	if len(all) != 1 || all[0].RefreshToken != "r0" || all[0].CredentialVersion != 0 {
		t.Fatalf("failed journal write must leave creds unchanged: %+v", all)
	}
}

// TestWriteRotationJournalOpenError covers the temp-file open failure branch: a
// read-only rotations dir lets MkdirAll succeed (dir exists) but blocks creating the
// .tmp file.
func TestWriteRotationJournalOpenError(t *testing.T) {
	s := openStoreDir(t, t.TempDir())
	if err := os.MkdirAll(s.rotationsDir(), 0o500); err != nil {
		t.Fatalf("mkdir read-only rotations: %v", err)
	}
	defer func() { _ = os.Chmod(s.rotationsDir(), 0o700) }()
	if err := s.writeRotationJournal("acct_ro", "a", "r", 0, 1, "refresh"); err == nil {
		t.Fatal("writeRotationJournal should fail when the .tmp file cannot be created")
	}
}

// TestDeleteAccountSucceedsDespiteUndeletableJournal proves the P1#4 ordering: the DB
// row is deleted first, so a failure to remove the (now-moot) rotation journal does
// NOT fail the already-committed delete — the account is gone and the orphan journal
// is left for the next startup replay to drop. (Contrast the old journal-first order,
// which could destroy a STILL-LIVE account's recovery journal if the DB delete failed.)
func TestDeleteAccountSucceedsDespiteUndeletableJournal(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	// Make the journal path a NON-EMPTY directory so os.Remove fails.
	jp, _ := s.rotationJournalPath(a.ID)
	if err := os.MkdirAll(jp, 0o700); err != nil {
		t.Fatalf("mkdir journal-as-dir: %v", err)
	}
	if err := os.WriteFile(jp+"/block", []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	if err := s.DeleteAccount(ctx, a.ID); err != nil {
		t.Fatalf("DeleteAccount must succeed even when the moot journal can't be removed: %v", err)
	}
	if _, err := s.GetAccount(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("account must be deleted (DB row gone): got err %v", err)
	}
}

// TestReplayMultipleAccountsOnOpen proves Open's startup replay reconciles a
// pending versioned rotation while dropping an already-applied one, across accounts.
func TestReplayMultipleAccountsOnOpen(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	pending, err := s.InsertAccount(ctx, model.Account{AccessToken: "p0", RefreshToken: "pr0", State: model.StateOK})
	if err != nil {
		t.Fatalf("insert pending: %v", err)
	}
	done, err := s.InsertAccount(ctx, model.Account{AccessToken: "d0", RefreshToken: "dr0", State: model.StateOK})
	if err != nil {
		t.Fatalf("insert done: %v", err)
	}
	// pending: a base 0 -> 1 rotation journaled but NOT applied (DB still at v0).
	if err := s.writeRotationJournal(pending.ID, "p1", "pr1", 0, 1, "refresh"); err != nil {
		t.Fatalf("journal pending: %v", err)
	}
	// done: apply gen 1 to the DB, then leave a stale base 0 -> 1 journal behind.
	if _, _, err := s.CommitRotatedTokens(ctx, done.ID, 0, "d1", "dr1"); err != nil {
		t.Fatalf("commit done: %v", err)
	}
	if err := s.writeRotationJournal(done.ID, "dStale", "drStale", 0, 1, "refresh"); err != nil {
		t.Fatalf("journal done stale: %v", err)
	}
	_ = s.Close()

	s2 := openStoreDir(t, dir) // Open replays both journals
	gotPending, _ := s2.GetAccount(ctx, pending.ID)
	if gotPending.RefreshToken != "pr1" || gotPending.CredentialVersion != 1 {
		t.Fatalf("pending replay = %+v, want pr1 @ v1", gotPending)
	}
	gotDone, _ := s2.GetAccount(ctx, done.ID)
	if gotDone.RefreshToken != "dr1" || gotDone.CredentialVersion != 1 {
		t.Fatalf("done must keep applied creds (stale journal dropped): %+v", gotDone)
	}
	if ids, _ := s2.PendingRotationIDs(); len(ids) != 0 {
		t.Fatalf("no journals should remain after replay, got %v", ids)
	}
}
