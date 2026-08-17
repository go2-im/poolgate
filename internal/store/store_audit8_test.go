package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/go2-im/poolgate/internal/model"
)

// TestRecoverCompleteTmpJournal proves a complete-but-unrenamed <id>.json.tmp (a
// crash between fsync and rename) is still recovered: it counts as pending, and
// flush applies it and removes both files.
func TestRecoverCompleteTmpJournal(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	// Produce a committed journal, then rename it to .tmp to simulate a crash that
	// happened after fsync+close but before the rename to <id>.json.
	if err := s.writeRotationJournal(a.ID, "aT", "rT"); err != nil {
		t.Fatalf("writeRotationJournal: %v", err)
	}
	jp, _ := s.rotationJournalPath(a.ID)
	if err := os.Rename(jp, jp+".tmp"); err != nil {
		t.Fatalf("rename to .tmp: %v", err)
	}

	// The .tmp is counted as pending (backup/rekey would refuse).
	ids, err := s.PendingRotationIDs()
	if err != nil {
		t.Fatalf("PendingRotationIDs: %v", err)
	}
	if len(ids) != 1 || ids[0] != a.ID {
		t.Fatalf("pending = %v, want [%s] (from .tmp)", ids, a.ID)
	}
	// Flush recovers it and clears both files.
	if err := s.FlushPendingRotation(ctx, a.ID); err != nil {
		t.Fatalf("FlushPendingRotation: %v", err)
	}
	got, _ := s.GetAccount(ctx, a.ID)
	if got.AccessToken != "aT" || got.RefreshToken != "rT" {
		t.Fatalf("recovered tokens = %+v, want aT/rT", got)
	}
	if _, err := os.Stat(jp + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf(".tmp should be removed after flush: %v", err)
	}
	if ids, _ := s.PendingRotationIDs(); len(ids) != 0 {
		t.Fatalf("pending after flush = %v, want empty", ids)
	}
}

// TestPendingRotationIDsAtSurfacesReadError proves the check is fail-closed: a
// rotations path that is a FILE (not a dir) makes ReadDir error, which surfaces
// rather than being treated as "no pending journals".
func TestPendingRotationIDsAtSurfacesReadError(t *testing.T) {
	dir := t.TempDir()
	// Occupy the rotations path with a file so os.ReadDir fails with ENOTDIR.
	if err := os.WriteFile(filepath.Join(dir, "rotations"), []byte("x"), 0o600); err != nil {
		t.Fatalf("occupy rotations path: %v", err)
	}
	if _, err := PendingRotationIDsAt(dir); err == nil {
		t.Fatal("PendingRotationIDsAt should surface a directory-read error (fail-closed)")
	}
}

// TestCorruptTmpJournalStaysPending proves a partial/corrupt .tmp is NOT silently
// ignored: it keeps the account listed as pending (so backup/rekey refuse) and
// flush surfaces the decode error rather than reusing the stale DB token.
func TestCorruptTmpJournalStaysPending(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()
	if err := os.MkdirAll(RotationsDir(dir), 0o700); err != nil {
		t.Fatalf("mkdir rotations: %v", err)
	}
	if err := os.WriteFile(filepath.Join(RotationsDir(dir), "acct_x.json.tmp"), []byte("not json"), 0o600); err != nil {
		t.Fatalf("write corrupt tmp: %v", err)
	}
	ids, err := s.PendingRotationIDs()
	if err != nil {
		t.Fatalf("PendingRotationIDs: %v", err)
	}
	if len(ids) != 1 || ids[0] != "acct_x" {
		t.Fatalf("pending = %v, want [acct_x] (corrupt .tmp still pending)", ids)
	}
	if err := s.FlushPendingRotation(ctx, "acct_x"); err == nil {
		t.Fatal("flush of a corrupt .tmp should surface the decode error")
	}
}
