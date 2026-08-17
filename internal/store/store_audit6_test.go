package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// TestUpsertAccountByAccountID covers dedupe-on-import: a new account_id inserts, a
// repeat account_id refreshes the SAME row (tokens updated, state reset, no new
// row), and an empty account_id always inserts a distinct row.
func TestUpsertAccountByAccountID(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a, updated, err := s.UpsertAccountByAccountID(ctx, model.Account{
		AccountID: "acc-1", AccessToken: "at1", RefreshToken: "rt1", State: model.StateOK,
	})
	if err != nil || updated {
		t.Fatalf("first upsert: updated=%v err=%v", updated, err)
	}

	b, updated, err := s.UpsertAccountByAccountID(ctx, model.Account{
		AccountID: "acc-1", AccessToken: "at2", RefreshToken: "rt2", State: model.StateOK,
	})
	if err != nil || !updated {
		t.Fatalf("second upsert: updated=%v err=%v", updated, err)
	}
	if b.ID != a.ID {
		t.Fatalf("upsert created a new row %q, want reuse of %q", b.ID, a.ID)
	}
	if b.AccessToken != "at2" || b.RefreshToken != "rt2" {
		t.Fatalf("tokens not refreshed on upsert: %+v", b)
	}
	if b.State != model.StateUnknown {
		t.Fatalf("state = %q, want unknown after re-credentialing", b.State)
	}
	if all, _ := s.ListAccounts(ctx); len(all) != 1 {
		t.Fatalf("account count = %d, want 1 (deduped)", len(all))
	}

	// Empty account_id never dedupes.
	c1, _, err := s.UpsertAccountByAccountID(ctx, model.Account{AccessToken: "x", RefreshToken: "y"})
	if err != nil {
		t.Fatalf("empty-account_id upsert 1: %v", err)
	}
	c2, _, err := s.UpsertAccountByAccountID(ctx, model.Account{AccessToken: "p", RefreshToken: "q"})
	if err != nil {
		t.Fatalf("empty-account_id upsert 2: %v", err)
	}
	if c1.ID == c2.ID {
		t.Fatal("empty account_id must not dedupe")
	}
}

// TestAccountAccountIDUniqueIndex proves the v13 partial unique index rejects a
// second direct insert with the same non-empty account_id (empty stays exempt).
func TestAccountAccountIDUniqueIndex(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.InsertAccount(ctx, model.Account{AccountID: "dup", AccessToken: "a", RefreshToken: "b"}); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if _, err := s.InsertAccount(ctx, model.Account{AccountID: "dup", AccessToken: "c", RefreshToken: "d"}); err == nil {
		t.Fatal("second insert with same account_id should violate the unique index")
	}
	// Empty account_id rows are exempt from the partial index.
	if _, err := s.InsertAccount(ctx, model.Account{AccessToken: "e", RefreshToken: "f"}); err != nil {
		t.Fatalf("first empty-account_id insert: %v", err)
	}
	if _, err := s.InsertAccount(ctx, model.Account{AccessToken: "g", RefreshToken: "h"}); err != nil {
		t.Fatalf("second empty-account_id insert should be allowed: %v", err)
	}
}

// TestCreateDefaultResourcesAtomic proves first-run bootstrap is transactional: a
// successful call creates group+endpoint+key, and a failing call (duplicate group
// name) creates nothing (the endpoint it would have added is absent).
func TestCreateDefaultResourcesAtomic(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	acct, err := s.InsertAccount(ctx, model.Account{AccountID: "a1", AccessToken: "x", RefreshToken: "y", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	_, key, err := s.CreateDefaultResources(ctx,
		model.PolicyGroup{Name: "default", Strategy: model.StrategyFallback, MemberAccountIDs: []string{acct.ID}},
		"default",
		model.ApiKey{Key: "sk-abc", Label: "default", Endpoints: []string{"default"}})
	if err != nil {
		t.Fatalf("CreateDefaultResources: %v", err)
	}
	if key.KeyHash == "" || key.KeyHash == "sk-abc" {
		t.Fatalf("key not hashed: %q", key.KeyHash)
	}
	if _, err := s.GetEndpoint(ctx, "default"); err != nil {
		t.Fatalf("endpoint not created: %v", err)
	}

	// A second call reusing the group name must fail AND leave no partial state
	// (the "default2" endpoint must not exist).
	if _, _, err := s.CreateDefaultResources(ctx,
		model.PolicyGroup{Name: "default", Strategy: model.StrategyFallback, MemberAccountIDs: []string{acct.ID}},
		"default2",
		model.ApiKey{Key: "sk-def", Label: "default", Endpoints: []string{"default2"}}); err == nil {
		t.Fatal("duplicate group name should fail")
	}
	if _, err := s.GetEndpoint(ctx, "default2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rolled-back bootstrap left endpoint default2: %v", err)
	}
}

// TestCreateDefaultResourcesRejectsMissingMember proves the member-existence guard
// runs inside the transaction and rolls the whole bootstrap back.
func TestCreateDefaultResourcesRejectsMissingMember(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, _, err := s.CreateDefaultResources(ctx,
		model.PolicyGroup{Name: "g", Strategy: model.StrategyFallback, MemberAccountIDs: []string{"acct_missing"}},
		"ep", model.ApiKey{Key: "sk-x", Endpoints: []string{"ep"}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing member = %v, want ErrNotFound", err)
	}
	if _, err := s.GetEndpoint(ctx, "ep"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("endpoint should not exist after rollback: %v", err)
	}
}

// TestCommitRotatedTokensAndFlush covers the durable rotation journal: a commit
// updates tokens and clears the journal; a hand-written pending journal is applied
// by FlushPendingRotation; and flush is a no-op with no journal.
func TestCommitRotatedTokensAndFlush(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir) // on-disk store (deterministic key) so the journal dir exists
	ctx := context.Background()
	acct, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}

	if err := s.CommitRotatedTokens(ctx, acct.ID, "a1", "r1"); err != nil {
		t.Fatalf("CommitRotatedTokens: %v", err)
	}
	got, _ := s.GetAccount(ctx, acct.ID)
	if got.AccessToken != "a1" || got.RefreshToken != "r1" {
		t.Fatalf("tokens not committed: %+v", got)
	}
	if _, ok, _ := s.readRotationJournal(acct.ID); ok {
		t.Fatal("journal should be cleared after a successful commit")
	}

	// Simulate a rotation that was journaled but not yet persisted, then flush it.
	if err := s.writeRotationJournal(acct.ID, "a2", "r2"); err != nil {
		t.Fatalf("writeRotationJournal: %v", err)
	}
	if err := s.FlushPendingRotation(ctx, acct.ID); err != nil {
		t.Fatalf("FlushPendingRotation: %v", err)
	}
	got2, _ := s.GetAccount(ctx, acct.ID)
	if got2.AccessToken != "a2" || got2.RefreshToken != "r2" {
		t.Fatalf("flush did not apply journal: %+v", got2)
	}
	if _, ok, _ := s.readRotationJournal(acct.ID); ok {
		t.Fatal("journal should be removed after flush")
	}
	// No-op when nothing pending.
	if err := s.FlushPendingRotation(ctx, acct.ID); err != nil {
		t.Fatalf("flush no-op: %v", err)
	}
	// A journal for a deleted account is dropped (not a hard error).
	if err := s.writeRotationJournal("acct_gone", "a", "r"); err != nil {
		t.Fatalf("writeRotationJournal(gone): %v", err)
	}
	if err := s.FlushPendingRotation(ctx, "acct_gone"); err != nil {
		t.Fatalf("flush of moot journal should succeed: %v", err)
	}
	if _, ok, _ := s.readRotationJournal("acct_gone"); ok {
		t.Fatal("moot journal should be dropped")
	}
}

// TestReplayTokenRotationsOnOpen proves a rotation journaled but not persisted
// before a restart is reconciled when the store is next opened.
func TestReplayTokenRotationsOnOpen(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	acct, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	// Journal a rotation WITHOUT applying it to the DB (crash-after-journal sim).
	if err := s.writeRotationJournal(acct.ID, "a9", "r9"); err != nil {
		t.Fatalf("writeRotationJournal: %v", err)
	}
	_ = s.Close()

	// Reopen the same data dir (same deterministic key): Open replays the journal.
	s2 := openStoreDir(t, dir)
	got, err := s2.GetAccount(ctx, acct.ID)
	if err != nil {
		t.Fatalf("GetAccount after reopen: %v", err)
	}
	if got.RefreshToken != "r9" || got.AccessToken != "a9" {
		t.Fatalf("replay did not apply the journaled rotation: %+v", got)
	}
	if _, ok, _ := s2.readRotationJournal(acct.ID); ok {
		t.Fatal("journal should be gone after replay")
	}
}

// TestMigrateV13DedupesDuplicateAccounts exercises the real v13 migration: it opens
// a store pinned to v12 (index absent), creates two accounts sharing an account_id
// plus a group referencing both, then reopens with v13 restored and asserts the
// newest survivor is kept, the group is repointed to it, and the unique index is
// enforced afterward.
func TestMigrateV13DedupesDuplicateAccounts(t *testing.T) {
	dir := t.TempDir()
	orig := migrations
	defer func() { migrations = orig }()

	// Pin migrations to <= v12 so duplicate account_ids can be created.
	var pre []migration
	for _, m := range orig {
		if m.version <= 12 {
			pre = append(pre, m)
		}
	}
	migrations = pre

	ctx := context.Background()
	s := openStoreDir(t, dir)
	older := time.Now().UTC().Add(-time.Hour)
	newer := time.Now().UTC()
	a1, err := s.InsertAccount(ctx, model.Account{AccountID: "acc-x", AccessToken: "old", RefreshToken: "oldr", State: model.StateOK, UpdatedAt: older})
	if err != nil {
		t.Fatalf("insert a1: %v", err)
	}
	a2, err := s.InsertAccount(ctx, model.Account{AccountID: "acc-x", AccessToken: "new", RefreshToken: "newr", State: model.StateOK, UpdatedAt: newer})
	if err != nil {
		t.Fatalf("insert a2: %v", err)
	}
	if _, err := s.InsertPolicyGroup(ctx, model.PolicyGroup{Name: "g", Strategy: model.StrategyFallback, MemberAccountIDs: []string{a1.ID, a2.ID}}); err != nil {
		t.Fatalf("insert group: %v", err)
	}
	_ = s.Close()

	// Restore full migrations (incl. v13) and reopen → v13 dedupes.
	migrations = orig
	s2 := openStoreDir(t, dir)

	all, err := s2.ListAccounts(ctx)
	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("after v13 dedup, account count = %d, want 1", len(all))
	}
	// The newest row (a2) survived with its tokens.
	if all[0].ID != a2.ID || all[0].AccessToken != "new" {
		t.Fatalf("survivor = %+v, want a2 (%q) with newest tokens", all[0], a2.ID)
	}
	// The group was repointed to the survivor (exactly one member = a2).
	grp, err := s2.GetPolicyGroup(ctx, groupIDByName(t, s2, "g"))
	if err != nil {
		t.Fatalf("get group: %v", err)
	}
	if len(grp.MemberAccountIDs) != 1 || grp.MemberAccountIDs[0] != a2.ID {
		t.Fatalf("group members = %v, want [%s]", grp.MemberAccountIDs, a2.ID)
	}
	// Uniqueness is now enforced.
	if _, err := s2.InsertAccount(ctx, model.Account{AccountID: "acc-x", AccessToken: "z", RefreshToken: "z"}); err == nil {
		t.Fatal("post-v13 insert of duplicate account_id should fail")
	}
}

// groupIDByName resolves a policy group id by name for tests.
func groupIDByName(t *testing.T, s *Store, name string) string {
	t.Helper()
	var id string
	if err := s.db.QueryRowContext(context.Background(),
		`SELECT id FROM policy_groups WHERE name = ?`, name).Scan(&id); err != nil {
		t.Fatalf("groupIDByName(%q): %v", name, err)
	}
	return id
}

// TestRotationJournalHelpers covers the low-level journal/durability helpers and
// their error branches (transient-error classification, unsafe-id rejection,
// dir/file fsync failures, corrupt-journal decode).
func TestRotationJournalHelpers(t *testing.T) {
	if isTransientStoreErr(nil) {
		t.Fatal("nil must not be transient")
	}
	for _, msg := range []string{"database is locked", "SQLITE_BUSY", "database is busy", "database table is locked"} {
		if !isTransientStoreErr(errors.New(msg)) {
			t.Errorf("want transient: %q", msg)
		}
	}
	if isTransientStoreErr(errors.New("near \"x\": syntax error")) {
		t.Error("non-transient error misclassified as transient")
	}

	s := openStoreDir(t, t.TempDir())
	for _, bad := range []string{"", "..", "a" + string(os.PathSeparator) + "b"} {
		if _, err := s.rotationJournalPath(bad); err == nil {
			t.Errorf("rotationJournalPath(%q) = nil error, want rejection", bad)
		}
	}

	// syncDirStore / fsyncFile surface errors on a missing path and succeed on real ones.
	if err := syncDirStore(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("syncDirStore(missing) should error")
	}
	if err := fsyncFile(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("fsyncFile(missing) should error")
	}
	d := t.TempDir()
	f := filepath.Join(d, "x")
	if err := os.WriteFile(f, []byte("y"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := fsyncFile(f); err != nil {
		t.Errorf("fsyncFile(real) = %v", err)
	}
	if err := syncDirStore(d); err != nil {
		t.Errorf("syncDirStore(real) = %v", err)
	}

	// A corrupt journal file surfaces a decode error rather than silently ignoring it.
	if err := os.MkdirAll(s.rotationsDir(), 0o700); err != nil {
		t.Fatalf("mkdir rotations: %v", err)
	}
	p, err := s.rotationJournalPath("acct_x")
	if err != nil {
		t.Fatalf("path: %v", err)
	}
	if err := os.WriteFile(p, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write corrupt journal: %v", err)
	}
	if _, _, err := s.readRotationJournal("acct_x"); err == nil {
		t.Error("corrupt journal should surface a decode error")
	}
}

// TestCommitRotatedTokensErrorPaths covers the failure branches of the durable
// commit: a failed DB write RETAINS the journal, a dataDir-less store falls back to
// a direct write, and a rotations dir that cannot be created surfaces an error.
func TestCommitRotatedTokensErrorPaths(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()

	// DB write fails for a missing account → error returned AND journal retained.
	if err := s.CommitRotatedTokens(ctx, "acct_none", "a", "r"); err == nil {
		t.Fatal("commit for a missing account should error")
	}
	if _, ok, _ := s.readRotationJournal("acct_none"); !ok {
		t.Fatal("journal must be RETAINED when the DB write fails")
	}

	// A dataDir-less store cannot journal; it falls back to a direct retrying write.
	acct, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	bare := &Store{db: s.DB(), cipher: s.cipher, dataDir: ""}
	if err := bare.CommitRotatedTokens(ctx, acct.ID, "a5", "r5"); err != nil {
		t.Fatalf("dataDir-less commit: %v", err)
	}
	if got, _ := s.GetAccount(ctx, acct.ID); got.RefreshToken != "r5" {
		t.Fatalf("dataDir-less commit did not persist: %+v", got)
	}

	// writeRotationJournal fails when the rotations dir path is occupied by a file.
	dir2 := t.TempDir()
	s2 := openStoreDir(t, dir2)
	if err := os.WriteFile(s2.rotationsDir(), []byte("x"), 0o600); err != nil {
		t.Fatalf("occupy rotations dir path: %v", err)
	}
	if err := s2.writeRotationJournal("acct_z", "a", "r"); err == nil {
		t.Fatal("writeRotationJournal should fail when the rotations dir path is a file")
	}
}

// TestRotationJournalMoreErrorBranches covers additional journal failure branches:
// an undecryptable entry, flush surfacing that read error, a commit whose journal
// write fails, and a remove that cannot delete the journal path.
func TestRotationJournalMoreErrorBranches(t *testing.T) {
	ctx := context.Background()

	// Undecryptable journal values → readRotationJournal (and Flush) error.
	s := openStoreDir(t, t.TempDir())
	if err := os.MkdirAll(s.rotationsDir(), 0o700); err != nil {
		t.Fatalf("mkdir rotations: %v", err)
	}
	p, _ := s.rotationJournalPath("acct_bad")
	if err := os.WriteFile(p, []byte(`{"access":"not-sealed","refresh":"nope","at":"t"}`), 0o600); err != nil {
		t.Fatalf("write bad journal: %v", err)
	}
	if _, _, err := s.readRotationJournal("acct_bad"); err == nil {
		t.Fatal("undecryptable journal values should error")
	}
	if err := s.FlushPendingRotation(ctx, "acct_bad"); err == nil {
		t.Fatal("flush of a corrupt journal should error")
	}

	// CommitRotatedTokens surfaces a journal-write failure (rotations path is a file).
	s2 := openStoreDir(t, t.TempDir())
	_ = os.RemoveAll(s2.rotationsDir())
	if err := os.WriteFile(s2.rotationsDir(), []byte("x"), 0o600); err != nil {
		t.Fatalf("occupy rotations path: %v", err)
	}
	acct, err := s2.InsertAccount(ctx, model.Account{AccessToken: "a", RefreshToken: "r", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	if err := s2.CommitRotatedTokens(ctx, acct.ID, "a2", "r2"); err == nil {
		t.Fatal("commit should fail when the journal cannot be written")
	}

	// removeRotationJournal errors when the journal path is a non-empty directory.
	s3 := openStoreDir(t, t.TempDir())
	jp, _ := s3.rotationJournalPath("acct_dir")
	if err := os.MkdirAll(jp, 0o700); err != nil {
		t.Fatalf("mkdir journal-as-dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(jp, "block"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	if err := s3.removeRotationJournal("acct_dir"); err == nil {
		t.Fatal("removeRotationJournal should error when the path is a non-empty dir")
	}
}

func TestPreMigrationSnapshotErrors(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	// Make the final snapshot path a non-empty directory so the publish rename fails.
	final := filepath.Join(dir, "poolgate.pre-migration-v7.db")
	if err := os.MkdirAll(final, 0o700); err != nil {
		t.Fatalf("mkdir final-as-dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(final, "block"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	if err := s.preMigrationSnapshot(ctx, 7); err == nil {
		t.Fatal("preMigrationSnapshot should fail when the target path is a non-empty dir")
	}
}

func TestWriteRotationJournalRenameFails(t *testing.T) {
	s := openStoreDir(t, t.TempDir())
	if err := os.MkdirAll(s.rotationsDir(), 0o700); err != nil {
		t.Fatalf("mkdir rotations: %v", err)
	}
	// Occupy the final journal path with a non-empty directory so the publish rename fails.
	jp, _ := s.rotationJournalPath("acct_rn")
	if err := os.MkdirAll(jp, 0o700); err != nil {
		t.Fatalf("mkdir journal-as-dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(jp, "block"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	if err := s.writeRotationJournal("acct_rn", "a", "r"); err == nil {
		t.Fatal("writeRotationJournal should fail when the target path is a non-empty dir")
	}
}

func TestCreateDefaultResourcesRollsBackOnEndpointConflict(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	acct, err := s.InsertAccount(ctx, model.Account{AccountID: "a1", AccessToken: "x", RefreshToken: "y", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	if _, _, err := s.CreateDefaultResources(ctx,
		model.PolicyGroup{Name: "g1", Strategy: model.StrategyFallback, MemberAccountIDs: []string{acct.ID}},
		"default", model.ApiKey{Key: "sk-1", Endpoints: []string{"default"}}); err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	// A different group name but a DUPLICATE endpoint name: the endpoint insert fails
	// inside the tx, so the whole bootstrap (incl. group g2) rolls back.
	if _, _, err := s.CreateDefaultResources(ctx,
		model.PolicyGroup{Name: "g2", Strategy: model.StrategyFallback, MemberAccountIDs: []string{acct.ID}},
		"default", model.ApiKey{Key: "sk-2", Endpoints: []string{"default"}}); err == nil {
		t.Fatal("duplicate endpoint name should fail the bootstrap")
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_groups WHERE name = 'g2'`).Scan(&n); err != nil {
		t.Fatalf("count g2: %v", err)
	}
	if n != 0 {
		t.Fatal("group g2 should not exist after endpoint-conflict rollback")
	}
}

func TestPreMigrationSnapshotVacuumError(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	// Make the data dir read-only so VACUUM INTO cannot create its temp file.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	if err := s.preMigrationSnapshot(context.Background(), 3); err == nil {
		t.Fatal("preMigrationSnapshot should fail when the data dir is read-only")
	}
}

func TestRotationJournalEdgeBranches(t *testing.T) {
	ctx := context.Background()
	s := openStoreDir(t, t.TempDir())
	if err := os.MkdirAll(s.rotationsDir(), 0o700); err != nil {
		t.Fatalf("mkdir rotations: %v", err)
	}
	// readRotationJournal on a path that is a directory → non-ErrNotExist error.
	jp, _ := s.rotationJournalPath("acct_d")
	if err := os.Mkdir(jp, 0o700); err != nil {
		t.Fatalf("mkdir journal-as-dir: %v", err)
	}
	if _, _, err := s.readRotationJournal("acct_d"); err == nil {
		t.Fatal("readRotationJournal on a directory should error")
	}
	if err := os.Remove(jp); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	// removeRotationJournal tolerates an absent journal (ErrNotExist) when the dir exists.
	if err := s.removeRotationJournal("acct_absent"); err != nil {
		t.Fatalf("removeRotationJournal(absent) = %v, want nil", err)
	}
	// FlushPendingRotation is a no-op when nothing is pending.
	if err := s.FlushPendingRotation(ctx, "acct_absent"); err != nil {
		t.Fatalf("flush(absent) = %v", err)
	}
}

func TestRotationDataDirlessBranches(t *testing.T) {
	ctx := context.Background()
	s := openStoreDir(t, t.TempDir())
	bare := &Store{db: s.DB(), cipher: s.cipher, dataDir: ""}
	// replay + flush are no-ops with no data dir to journal into.
	bare.replayTokenRotations(ctx)
	if err := bare.FlushPendingRotation(ctx, "acct_x"); err != nil {
		t.Fatalf("bare flush = %v, want nil", err)
	}
	// A bare-store commit still surfaces the DB error for a missing account.
	if err := bare.CommitRotatedTokens(ctx, "acct_missing", "a", "r"); err == nil {
		t.Fatal("bare commit for a missing account should error")
	}
}
