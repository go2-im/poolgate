package store

import (
	"context"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// TestLastRefreshedAtBumpedOnTokenWrite proves last_refreshed_at is written by
// credential-token operations (online-refresh commit + login-replace) but NOT by a
// bare insert (which falls back to created_at for proactive-refresh timing).
func TestLastRefreshedAtBumpedOnTokenWrite(t *testing.T) {
	dir := t.TempDir()
	s := openStoreDir(t, dir)
	ctx := context.Background()

	a, err := s.InsertAccount(ctx, model.Account{AccountID: "acc-1", AccessToken: "a0", RefreshToken: "r0", State: model.StateOK})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	if got, _ := s.GetAccount(ctx, a.ID); !got.LastRefreshedAt.IsZero() {
		t.Fatalf("bare insert should leave last_refreshed_at unset (got %v)", got.LastRefreshedAt)
	}

	// An online-refresh commit bumps it.
	before := time.Now().UTC().Add(-time.Second)
	if _, applied, err := s.CommitRotatedTokens(ctx, a.ID, 0, "a1", "r1"); err != nil || !applied {
		t.Fatalf("CommitRotatedTokens: applied=%v err=%v", applied, err)
	}
	got1, _ := s.GetAccount(ctx, a.ID)
	if got1.LastRefreshedAt.Before(before) {
		t.Fatalf("commit must bump last_refreshed_at (got %v, before %v)", got1.LastRefreshedAt, before)
	}

	// A login-replace also bumps it (to a fresh time).
	before2 := time.Now().UTC().Add(-time.Second)
	if _, updated, err := s.UpsertAccountByAccountID(ctx, model.Account{AccountID: "acc-1", AccessToken: "a2", RefreshToken: "r2"}); err != nil || !updated {
		t.Fatalf("login replace: updated=%v err=%v", updated, err)
	}
	got2, _ := s.GetAccount(ctx, a.ID)
	if got2.LastRefreshedAt.Before(before2) {
		t.Fatalf("login replace must bump last_refreshed_at (got %v, before %v)", got2.LastRefreshedAt, before2)
	}
}

// TestMigrationV15SeedsLastRefreshedFromUpdatedAt proves the v15 migration seeds
// last_refreshed_at from an existing row's updated_at (so upgraded installs are not
// all immediately due for a proactive refresh).
func TestMigrationV15SeedsLastRefreshedFromUpdatedAt(t *testing.T) {
	dir := t.TempDir()
	orig := migrations
	defer func() { migrations = orig }()

	// Pin to <= v14 (no last_refreshed_at column yet), insert a row, then reopen with
	// v15 to run the seed.
	var pre []migration
	for _, m := range orig {
		if m.version <= 14 {
			pre = append(pre, m)
		}
	}
	migrations = pre

	ctx := context.Background()
	s := openStoreDir(t, dir)
	upd := time.Now().UTC().Add(-3 * time.Hour)
	a, err := s.InsertAccount(ctx, model.Account{AccessToken: "a", RefreshToken: "r", State: model.StateOK, CreatedAt: upd, UpdatedAt: upd})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	_ = s.Close()

	migrations = orig // restore v15
	s2 := openStoreDir(t, dir)
	got, err := s2.GetAccount(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if !got.LastRefreshedAt.Equal(got.UpdatedAt) || got.LastRefreshedAt.IsZero() {
		t.Fatalf("v15 must seed last_refreshed_at from updated_at: last=%v updated=%v", got.LastRefreshedAt, got.UpdatedAt)
	}
}
