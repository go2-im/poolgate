package store

import (
	"context"
	"strings"
	"testing"

	"github.com/go2-im/poolgate/internal/config"
	"github.com/go2-im/poolgate/internal/crypto"
	"github.com/go2-im/poolgate/internal/model"
)

// newTestStore opens a store rooted at a fresh temp dir with a random cipher.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i + 1)
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
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestMigrateIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Open already ran Migrate once; run it several more times.
	for i := 0; i < 3; i++ {
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("Migrate (run %d): %v", i, err)
		}
	}

	// schema_migrations should hold exactly one row per shipped migration.
	var count int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if count != len(migrations) {
		t.Fatalf("schema_migrations rows = %d, want %d", count, len(migrations))
	}

	v, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if want := migrations[len(migrations)-1].version; v != want {
		t.Fatalf("SchemaVersion = %d, want %d", v, want)
	}
}

func TestAccountRoundTripEncryptedAtRest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	const (
		access  = "sk-access-token-SECRET-abc123"
		refresh = "rt-refresh-token-SECRET-xyz789"
	)
	in := model.Account{
		Label:        "primary",
		AccessToken:  access,
		RefreshToken: refresh,
		AccountID:    "acct-header-id",
		IDToken:      "jwt.id.token",
		State:        model.StateUnknown,
	}

	stored, err := s.InsertAccount(ctx, in)
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	if stored.ID == "" {
		t.Fatal("InsertAccount did not assign an id")
	}

	got, err := s.GetAccount(ctx, stored.ID)
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if got.AccessToken != access || got.RefreshToken != refresh {
		t.Fatalf("token round-trip mismatch: got access=%q refresh=%q", got.AccessToken, got.RefreshToken)
	}
	if got.AccountID != in.AccountID || got.Label != in.Label || got.State != in.State {
		t.Fatalf("account field mismatch: %+v", got)
	}

	// Assert the raw DB cells are NOT plaintext.
	var rawAccess, rawRefresh string
	if err := s.db.QueryRowContext(ctx,
		`SELECT access_token, refresh_token FROM accounts WHERE id = ?`, stored.ID,
	).Scan(&rawAccess, &rawRefresh); err != nil {
		t.Fatalf("read raw cells: %v", err)
	}
	if strings.Contains(rawAccess, "SECRET") || rawAccess == access {
		t.Fatalf("access_token stored in plaintext: %q", rawAccess)
	}
	if strings.Contains(rawRefresh, "SECRET") || rawRefresh == refresh {
		t.Fatalf("refresh_token stored in plaintext: %q", rawRefresh)
	}
}

func TestListAccounts(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for _, lbl := range []string{"a", "b", "c"} {
		if _, err := s.InsertAccount(ctx, model.Account{
			Label: lbl, AccessToken: "at-" + lbl, RefreshToken: "rt-" + lbl,
		}); err != nil {
			t.Fatalf("InsertAccount %q: %v", lbl, err)
		}
	}
	list, err := s.ListAccounts(ctx)
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("ListAccounts len = %d, want 3", len(list))
	}
	for _, a := range list {
		if !strings.HasPrefix(a.AccessToken, "at-") {
			t.Fatalf("decrypt on list failed: %q", a.AccessToken)
		}
	}
}

func TestUpdateTokensAtomic(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	stored, err := s.InsertAccount(ctx, model.Account{
		AccessToken: "at-old", RefreshToken: "rt-old",
	})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	before, err := s.GetAccount(ctx, stored.ID)
	if err != nil {
		t.Fatalf("GetAccount before: %v", err)
	}

	if err := s.UpdateTokens(ctx, stored.ID, "at-new", "rt-new"); err != nil {
		t.Fatalf("UpdateTokens: %v", err)
	}
	after, err := s.GetAccount(ctx, stored.ID)
	if err != nil {
		t.Fatalf("GetAccount after: %v", err)
	}
	if after.AccessToken != "at-new" || after.RefreshToken != "rt-new" {
		t.Fatalf("tokens not rotated: access=%q refresh=%q", after.AccessToken, after.RefreshToken)
	}
	if !after.UpdatedAt.After(before.UpdatedAt) && !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("updated_at went backwards: before=%v after=%v", before.UpdatedAt, after.UpdatedAt)
	}

	// Unknown id => ErrNotFound, no mutation.
	if err := s.UpdateTokens(ctx, "nope", "x", "y"); err != ErrNotFound {
		t.Fatalf("UpdateTokens(unknown) err = %v, want ErrNotFound", err)
	}
}

func TestApiKeyLookup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	in := model.ApiKey{Key: "sk-proxy-key-123", Label: "cli", Endpoints: []string{"prod"}}
	if _, err := s.InsertApiKey(ctx, in); err != nil {
		t.Fatalf("InsertApiKey: %v", err)
	}
	got, err := s.GetApiKeyByKey(ctx, "sk-proxy-key-123")
	if err != nil {
		t.Fatalf("GetApiKeyByKey: %v", err)
	}
	if got.Label != "cli" || len(got.Endpoints) != 1 || got.Endpoints[0] != "prod" {
		t.Fatalf("api key mismatch: %+v", got)
	}
	if _, err := s.GetApiKeyByKey(ctx, "sk-missing"); err != ErrNotFound {
		t.Fatalf("GetApiKeyByKey(missing) err = %v, want ErrNotFound", err)
	}

	list, err := s.ListApiKeys(ctx)
	if err != nil {
		t.Fatalf("ListApiKeys: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ListApiKeys len = %d, want 1", len(list))
	}
}

func TestResolveEndpoint(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a1, err := s.InsertAccount(ctx, model.Account{Label: "a1", AccessToken: "at1", RefreshToken: "rt1"})
	if err != nil {
		t.Fatalf("InsertAccount a1: %v", err)
	}
	a2, err := s.InsertAccount(ctx, model.Account{Label: "a2", AccessToken: "at2", RefreshToken: "rt2"})
	if err != nil {
		t.Fatalf("InsertAccount a2: %v", err)
	}

	grp, err := s.InsertPolicyGroup(ctx, model.PolicyGroup{
		Name:             "primary-pool",
		Strategy:         model.StrategyFallback,
		MemberAccountIDs: []string{a1.ID, a2.ID},
	})
	if err != nil {
		t.Fatalf("InsertPolicyGroup: %v", err)
	}
	if _, err := s.InsertEndpoint(ctx, model.Endpoint{Name: "prod", GroupID: grp.ID}); err != nil {
		t.Fatalf("InsertEndpoint: %v", err)
	}

	gotGrp, err := s.GetPolicyGroup(ctx, grp.ID)
	if err != nil {
		t.Fatalf("GetPolicyGroup: %v", err)
	}
	if gotGrp.Strategy != model.StrategyFallback || len(gotGrp.MemberAccountIDs) != 2 {
		t.Fatalf("group mismatch: %+v", gotGrp)
	}

	ep, group, accts, err := s.ResolveEndpoint(ctx, "prod")
	if err != nil {
		t.Fatalf("ResolveEndpoint: %v", err)
	}
	if ep.Name != "prod" || group.ID != grp.ID {
		t.Fatalf("resolve endpoint/group mismatch: ep=%+v group=%+v", ep, group)
	}
	if len(accts) != 2 || accts[0].ID != a1.ID || accts[1].ID != a2.ID {
		t.Fatalf("resolved members wrong order/count: %+v", accts)
	}
	// Ordered member accounts come back decrypted.
	if accts[0].AccessToken != "at1" || accts[1].AccessToken != "at2" {
		t.Fatalf("resolved members not decrypted: %q %q", accts[0].AccessToken, accts[1].AccessToken)
	}

	if _, _, _, err := s.ResolveEndpoint(ctx, "missing"); err != ErrNotFound {
		t.Fatalf("ResolveEndpoint(missing) err = %v, want ErrNotFound", err)
	}
}
