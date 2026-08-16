package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/config"
	"github.com/go2-im/poolgate/internal/crypto"
	"github.com/go2-im/poolgate/internal/model"
)

// newClosedStore returns a store whose underlying *sql.DB has been closed, so
// that every subsequent query/exec returns "sql: database is closed". This is
// the cheapest way to drive the error branches of the CRUD methods.
func newClosedStore(t *testing.T) *Store {
	t.Helper()
	s := newTestStore(t)
	if err := s.db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	return s
}

// ---- Open error paths -----------------------------------------------------

func TestOpenErrors(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	c, err := crypto.New(key)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}

	t.Run("nil cipher", func(t *testing.T) {
		cfg := config.Default()
		cfg.DataDir = t.TempDir()
		if _, err := Open(cfg, nil); err == nil {
			t.Fatal("Open with nil cipher: want error, got nil")
		}
	})

	t.Run("empty data dir", func(t *testing.T) {
		cfg := config.Default()
		cfg.DataDir = ""
		if _, err := Open(cfg, c); err == nil {
			t.Fatal("Open with empty data dir: want error, got nil")
		}
	})

	t.Run("mkdir fails when parent is a file", func(t *testing.T) {
		// Create a regular file, then ask Open to create a subdir *under* it,
		// which MkdirAll cannot do (parent is not a directory).
		f := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}
		cfg := config.Default()
		cfg.DataDir = filepath.Join(f, "sub")
		if _, err := Open(cfg, c); err == nil {
			t.Fatal("Open with unusable data dir: want error, got nil")
		}
	})
}

// TestDBAccessor exercises the DB() accessor.
func TestDBAccessor(t *testing.T) {
	s := newTestStore(t)
	if s.DB() == nil {
		t.Fatal("DB() returned nil")
	}
	if s.DB() != s.db {
		t.Fatal("DB() did not return the underlying handle")
	}
}

// ---- UpdateState ----------------------------------------------------------

func TestUpdateState(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	stored, err := s.InsertAccount(ctx, model.Account{AccessToken: "at", RefreshToken: "rt"})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}

	if err := s.UpdateState(ctx, stored.ID, model.StateCooldown); err != nil {
		t.Fatalf("UpdateState: %v", err)
	}
	got, err := s.GetAccount(ctx, stored.ID)
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if got.State != model.StateCooldown {
		t.Fatalf("state = %q, want %q", got.State, model.StateCooldown)
	}

	// Unknown id => ErrNotFound.
	if err := s.UpdateState(ctx, "nope", model.StateDead); err != ErrNotFound {
		t.Fatalf("UpdateState(unknown) err = %v, want ErrNotFound", err)
	}
}

func TestUpdateStateExecError(t *testing.T) {
	s := newClosedStore(t)
	if err := s.UpdateState(context.Background(), "any", model.StateOK); err == nil {
		t.Fatal("UpdateState on closed db: want error, got nil")
	}
}

func TestGetAccountStateAndUpdateStateAndTiming(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	stored, err := s.InsertAccount(ctx, model.Account{AccessToken: "at", RefreshToken: "rt"})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}

	// Fresh account state is readable.
	st, err := s.GetAccountState(ctx, stored.ID)
	if err != nil {
		t.Fatalf("GetAccountState: %v", err)
	}
	if st != model.StateUnknown {
		t.Fatalf("initial state = %q, want %q", st, model.StateUnknown)
	}

	// Atomic state+timing write lands both.
	cooldown := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	next := cooldown.Add(time.Minute)
	timing := model.AccountTiming{
		CooldownUntil: cooldown, NextProbeAt: next,
		ConsecutiveFailures: 3, BackoffLevel: 2, ConcurrencyCap: 5,
	}
	if err := s.UpdateStateAndTiming(ctx, stored.ID, model.StateCooldown, timing); err != nil {
		t.Fatalf("UpdateStateAndTiming: %v", err)
	}
	st, err = s.GetAccountState(ctx, stored.ID)
	if err != nil {
		t.Fatalf("GetAccountState: %v", err)
	}
	if st != model.StateCooldown {
		t.Fatalf("state = %q, want cooldown", st)
	}
	gotT, err := s.GetAccountTiming(ctx, stored.ID)
	if err != nil {
		t.Fatalf("GetAccountTiming: %v", err)
	}
	if !gotT.CooldownUntil.Equal(cooldown) || gotT.ConsecutiveFailures != 3 ||
		gotT.BackoffLevel != 2 || gotT.ConcurrencyCap != 5 {
		t.Fatalf("timing round-trip mismatch: %+v", gotT)
	}

	// Unknown id => ErrNotFound on both.
	if _, err := s.GetAccountState(ctx, "nope"); err != ErrNotFound {
		t.Fatalf("GetAccountState(unknown) = %v, want ErrNotFound", err)
	}
	if err := s.UpdateStateAndTiming(ctx, "nope", model.StateOK, model.AccountTiming{}); err != ErrNotFound {
		t.Fatalf("UpdateStateAndTiming(unknown) = %v, want ErrNotFound", err)
	}
}

func TestGetAccountStateAndUpdateStateAndTimingExecError(t *testing.T) {
	s := newClosedStore(t)
	if _, err := s.GetAccountState(context.Background(), "any"); err == nil {
		t.Fatal("GetAccountState on closed db: want error")
	}
	if err := s.UpdateStateAndTiming(context.Background(), "any", model.StateOK, model.AccountTiming{}); err == nil {
		t.Fatal("UpdateStateAndTiming on closed db: want error")
	}
}

// ---- ListEndpointNames ----------------------------------------------------

func TestListEndpointNames(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	grp, err := s.InsertPolicyGroup(ctx, model.PolicyGroup{Name: "g", Strategy: model.StrategyFallback})
	if err != nil {
		t.Fatalf("InsertPolicyGroup: %v", err)
	}
	for _, name := range []string{"beta", "alpha", "gamma"} {
		if _, err := s.InsertEndpoint(ctx, model.Endpoint{Name: name, GroupID: grp.ID}); err != nil {
			t.Fatalf("InsertEndpoint %q: %v", name, err)
		}
	}

	names, err := s.ListEndpointNames(ctx)
	if err != nil {
		t.Fatalf("ListEndpointNames: %v", err)
	}
	// Ordered by name.
	want := []string{"alpha", "beta", "gamma"}
	if len(names) != len(want) {
		t.Fatalf("ListEndpointNames len = %d, want %d", len(names), len(want))
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("names[%d] = %q, want %q", i, names[i], want[i])
		}
	}
}

func TestListEndpointNamesQueryError(t *testing.T) {
	s := newClosedStore(t)
	if _, err := s.ListEndpointNames(context.Background()); err == nil {
		t.Fatal("ListEndpointNames on closed db: want error, got nil")
	}
}

// ---- scanAccount decrypt error paths --------------------------------------

func TestGetAccountDecryptErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("corrupt access token", func(t *testing.T) {
		s := newTestStore(t)
		stored, err := s.InsertAccount(ctx, model.Account{AccessToken: "at", RefreshToken: "rt"})
		if err != nil {
			t.Fatalf("InsertAccount: %v", err)
		}
		if _, err := s.db.ExecContext(ctx,
			`UPDATE accounts SET access_token = ? WHERE id = ?`, "!!!not-base64!!!", stored.ID); err != nil {
			t.Fatalf("corrupt access: %v", err)
		}
		if _, err := s.GetAccount(ctx, stored.ID); err == nil {
			t.Fatal("GetAccount with corrupt access token: want error, got nil")
		}
	})

	t.Run("corrupt refresh token", func(t *testing.T) {
		s := newTestStore(t)
		stored, err := s.InsertAccount(ctx, model.Account{AccessToken: "at", RefreshToken: "rt"})
		if err != nil {
			t.Fatalf("InsertAccount: %v", err)
		}
		// Leave access valid so the failure surfaces on the refresh column.
		if _, err := s.db.ExecContext(ctx,
			`UPDATE accounts SET refresh_token = ? WHERE id = ?`, "!!!not-base64!!!", stored.ID); err != nil {
			t.Fatalf("corrupt refresh: %v", err)
		}
		if _, err := s.GetAccount(ctx, stored.ID); err == nil {
			t.Fatal("GetAccount with corrupt refresh token: want error, got nil")
		}
	})
}

// TestGetAccountNotFound covers the scanAccount ErrNoRows -> ErrNotFound branch.
func TestGetAccountNotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetAccount(context.Background(), "missing"); err != ErrNotFound {
		t.Fatalf("GetAccount(missing) err = %v, want ErrNotFound", err)
	}
}

// TestGetAccountParseTimeFallback covers parseTime's invalid-input branch:
// a corrupt timestamp cell decodes to the zero time rather than erroring.
func TestGetAccountParseTimeFallback(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	stored, err := s.InsertAccount(ctx, model.Account{AccessToken: "at", RefreshToken: "rt"})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE accounts SET created_at = ? WHERE id = ?`, "not-a-timestamp", stored.ID); err != nil {
		t.Fatalf("corrupt created_at: %v", err)
	}
	got, err := s.GetAccount(ctx, stored.ID)
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if !got.CreatedAt.IsZero() {
		t.Fatalf("created_at = %v, want zero time", got.CreatedAt)
	}
}

// ---- list query error paths -----------------------------------------------

func TestListQueryErrors(t *testing.T) {
	s := newClosedStore(t)
	ctx := context.Background()
	if _, err := s.ListAccounts(ctx); err == nil {
		t.Fatal("ListAccounts on closed db: want error, got nil")
	}
	if _, err := s.ListApiKeys(ctx); err == nil {
		t.Fatal("ListApiKeys on closed db: want error, got nil")
	}
}

// TestListAccountsScanError drives the per-row scan error branch of
// ListAccounts by corrupting an encrypted cell.
func TestListAccountsScanError(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	stored, err := s.InsertAccount(ctx, model.Account{AccessToken: "at", RefreshToken: "rt"})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE accounts SET access_token = ? WHERE id = ?`, "!!!bad!!!", stored.ID); err != nil {
		t.Fatalf("corrupt access: %v", err)
	}
	if _, err := s.ListAccounts(ctx); err == nil {
		t.Fatal("ListAccounts with corrupt row: want error, got nil")
	}
}

// TestListApiKeysScanError drives the per-row scan error branch of ListApiKeys
// by corrupting the endpoints JSON so json.Unmarshal fails.
func TestListApiKeysScanError(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.InsertApiKey(ctx, model.ApiKey{Key: "k1"}); err != nil {
		t.Fatalf("InsertApiKey: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE api_keys SET endpoints = ? WHERE key = ?`, "not-json", "k1"); err != nil {
		t.Fatalf("corrupt endpoints: %v", err)
	}
	if _, err := s.ListApiKeys(ctx); err == nil {
		t.Fatal("ListApiKeys with corrupt row: want error, got nil")
	}
}

// TestGetApiKeyUnmarshalError covers scanApiKey's json.Unmarshal error branch.
func TestGetApiKeyUnmarshalError(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.InsertApiKey(ctx, model.ApiKey{Key: "k1"}); err != nil {
		t.Fatalf("InsertApiKey: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE api_keys SET endpoints = ? WHERE key = ?`, "{bad", "k1"); err != nil {
		t.Fatalf("corrupt endpoints: %v", err)
	}
	if _, err := s.GetApiKeyByKey(ctx, "k1"); err == nil {
		t.Fatal("GetApiKeyByKey with corrupt endpoints: want error, got nil")
	}
}

// TestInsertApiKeyDefaultsEndpoints verifies the nil-endpoints normalization
// and round-trips an empty (all-endpoints) scope.
func TestInsertApiKeyDefaultsEndpoints(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	stored, err := s.InsertApiKey(ctx, model.ApiKey{Key: "k-nil"})
	if err != nil {
		t.Fatalf("InsertApiKey: %v", err)
	}
	if stored.ID == "" {
		t.Fatal("InsertApiKey did not assign an id")
	}
	if stored.Endpoints == nil || len(stored.Endpoints) != 0 {
		t.Fatalf("Endpoints = %#v, want empty non-nil slice", stored.Endpoints)
	}
	got, err := s.GetApiKeyByKey(ctx, "k-nil")
	if err != nil {
		t.Fatalf("GetApiKeyByKey: %v", err)
	}
	if len(got.Endpoints) != 0 {
		t.Fatalf("round-tripped Endpoints = %#v, want empty", got.Endpoints)
	}
}

// ---- duplicate-key / constraint insert error paths ------------------------

func TestInsertDuplicateErrors(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	t.Run("account duplicate id", func(t *testing.T) {
		a := model.Account{ID: "acct_dup", AccessToken: "at", RefreshToken: "rt"}
		if _, err := s.InsertAccount(ctx, a); err != nil {
			t.Fatalf("first InsertAccount: %v", err)
		}
		if _, err := s.InsertAccount(ctx, a); err == nil {
			t.Fatal("duplicate InsertAccount: want error, got nil")
		}
	})

	t.Run("api key duplicate key", func(t *testing.T) {
		k := model.ApiKey{Key: "dup-key"}
		if _, err := s.InsertApiKey(ctx, k); err != nil {
			t.Fatalf("first InsertApiKey: %v", err)
		}
		if _, err := s.InsertApiKey(ctx, k); err == nil {
			t.Fatal("duplicate InsertApiKey: want error, got nil")
		}
	})

	t.Run("policy group duplicate name", func(t *testing.T) {
		g := model.PolicyGroup{Name: "dup-group", Strategy: model.StrategyFallback}
		if _, err := s.InsertPolicyGroup(ctx, g); err != nil {
			t.Fatalf("first InsertPolicyGroup: %v", err)
		}
		if _, err := s.InsertPolicyGroup(ctx, g); err == nil {
			t.Fatal("duplicate InsertPolicyGroup: want error, got nil")
		}
	})

	t.Run("endpoint duplicate name", func(t *testing.T) {
		grp, err := s.InsertPolicyGroup(ctx, model.PolicyGroup{Name: "grp-for-ep", Strategy: model.StrategyFallback})
		if err != nil {
			t.Fatalf("InsertPolicyGroup: %v", err)
		}
		e := model.Endpoint{Name: "dup-ep", GroupID: grp.ID}
		if _, err := s.InsertEndpoint(ctx, e); err != nil {
			t.Fatalf("first InsertEndpoint: %v", err)
		}
		if _, err := s.InsertEndpoint(ctx, e); err == nil {
			t.Fatal("duplicate InsertEndpoint: want error, got nil")
		}
	})
}

// TestInsertPolicyGroupMemberError drives the group-member insert error branch
// (and its rollback): duplicate member ids violate the composite primary key.
func TestInsertPolicyGroupMemberError(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, err := s.InsertPolicyGroup(ctx, model.PolicyGroup{
		Name:             "dupe-members",
		Strategy:         model.StrategyFallback,
		MemberAccountIDs: []string{"acct_x", "acct_x"}, // duplicate -> PK violation
	})
	if err == nil {
		t.Fatal("InsertPolicyGroup with duplicate members: want error, got nil")
	}
	// Rollback must have removed the half-written group.
	if _, err := s.GetPolicyGroup(ctx, "dupe-members"); err == nil {
		t.Fatal("group should not exist after rollback")
	}
}

// ---- policy group / endpoint get error paths ------------------------------

func TestGetPolicyGroupNotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetPolicyGroup(context.Background(), "nope"); err != ErrNotFound {
		t.Fatalf("GetPolicyGroup(missing) err = %v, want ErrNotFound", err)
	}
}

func TestGetEndpointNotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetEndpoint(context.Background(), "nope"); err != ErrNotFound {
		t.Fatalf("GetEndpoint(missing) err = %v, want ErrNotFound", err)
	}
}

// TestResolveEndpointMissingMember drives ResolveEndpoint's member-load error
// branch: the group references an account id that has no accounts row.
func TestResolveEndpointMissingMember(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	grp, err := s.InsertPolicyGroup(ctx, model.PolicyGroup{
		Name:             "ghost-pool",
		Strategy:         model.StrategyFallback,
		MemberAccountIDs: []string{"acct_ghost"}, // no matching account row
	})
	if err != nil {
		t.Fatalf("InsertPolicyGroup: %v", err)
	}
	if _, err := s.InsertEndpoint(ctx, model.Endpoint{Name: "ghost-ep", GroupID: grp.ID}); err != nil {
		t.Fatalf("InsertEndpoint: %v", err)
	}
	if _, _, _, err := s.ResolveEndpoint(ctx, "ghost-ep"); err == nil {
		t.Fatal("ResolveEndpoint with missing member: want error, got nil")
	}
}

// ---- SchemaVersion / Migrate error paths ----------------------------------

func TestSchemaVersionQueryError(t *testing.T) {
	s := newClosedStore(t)
	if _, err := s.SchemaVersion(context.Background()); err == nil {
		t.Fatal("SchemaVersion on closed db: want error, got nil")
	}
}

func TestMigrateExecError(t *testing.T) {
	s := newClosedStore(t)
	if err := s.Migrate(context.Background()); err == nil {
		t.Fatal("Migrate on closed db: want error, got nil")
	}
}

// TestGetAccountQueryError drives the scanAccount non-ErrNoRows error branch
// via a closed handle.
func TestGetAccountQueryError(t *testing.T) {
	s := newClosedStore(t)
	if _, err := s.GetAccount(context.Background(), "any"); err == nil {
		t.Fatal("GetAccount on closed db: want error, got nil")
	}
}

// TestUpdateTokensBeginError drives the BeginTx error branch of UpdateTokens
// (the correctness-critical atomic rotation path, DESIGN §0 D6 / §19.3).
func TestUpdateTokensBeginError(t *testing.T) {
	s := newClosedStore(t)
	if err := s.UpdateTokens(context.Background(), "any", "at", "rt"); err == nil {
		t.Fatal("UpdateTokens on closed db: want error, got nil")
	}
}

// TestGetPolicyGroupQueryError drives GetPolicyGroup's non-ErrNoRows error
// branch via a closed handle.
func TestGetPolicyGroupQueryError(t *testing.T) {
	s := newClosedStore(t)
	if _, err := s.GetPolicyGroup(context.Background(), "any"); err == nil {
		t.Fatal("GetPolicyGroup on closed db: want error, got nil")
	}
}

// TestGetEndpointQueryError drives GetEndpoint's non-ErrNoRows error branch.
func TestGetEndpointQueryError(t *testing.T) {
	s := newClosedStore(t)
	if _, err := s.GetEndpoint(context.Background(), "any"); err == nil {
		t.Fatal("GetEndpoint on closed db: want error, got nil")
	}
}

func TestUpdateAccountMeta(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a, err := s.InsertAccount(ctx, model.Account{
		Label: "old", AccessToken: "at", RefreshToken: "rt", AccountID: "acc-1",
		State: model.StateOK, ConcurrencyCap: 1,
	})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	if err := s.UpdateAccountMeta(ctx, a.ID, "new", 7); err != nil {
		t.Fatalf("UpdateAccountMeta: %v", err)
	}
	got, err := s.GetAccount(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if got.Label != "new" || got.ConcurrencyCap != 7 {
		t.Errorf("after update: label=%q cap=%d, want new/7", got.Label, got.ConcurrencyCap)
	}
	// Tokens must be untouched by a meta update.
	if got.AccessToken != "at" || got.RefreshToken != "rt" {
		t.Errorf("meta update disturbed tokens: %q/%q", got.AccessToken, got.RefreshToken)
	}
	if err := s.UpdateAccountMeta(ctx, "missing", "x", 0); err != ErrNotFound {
		t.Errorf("UpdateAccountMeta(missing) = %v, want ErrNotFound", err)
	}
}
