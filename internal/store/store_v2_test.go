package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// insertTestAccount inserts a minimal account and returns its id.
func insertTestAccount(t *testing.T, s *Store) string {
	t.Helper()
	a, err := s.InsertAccount(context.Background(), model.Account{
		Label:        "acct",
		AccessToken:  "acc",
		RefreshToken: "ref",
		AccountID:    "chatgpt-1",
	})
	if err != nil {
		t.Fatalf("InsertAccount: %v", err)
	}
	return a.ID
}

func TestMigrateV2SchemaPresent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// v2 must be the current schema version.
	v, err := s.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v < 2 {
		t.Fatalf("SchemaVersion = %d, want >= 2", v)
	}

	// New tables exist.
	for _, tbl := range []string{"usage_snapshots", "health_checks"} {
		var name string
		err := s.db.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&name)
		if err != nil {
			t.Fatalf("table %q missing: %v", tbl, err)
		}
	}

	// New account timing columns exist and re-running Migrate is a no-op (the
	// ALTER TABLE ADD COLUMN statements are inside the guarded v2 migration).
	for i := 0; i < 3; i++ {
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("re-Migrate (%d): %v", i, err)
		}
	}
	// Confirm the columns are queryable.
	id := insertTestAccount(t, s)
	if _, err := s.GetAccountTiming(ctx, id); err != nil {
		t.Fatalf("GetAccountTiming after re-migrate: %v", err)
	}
}

func TestUsageSnapshotRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := insertTestAccount(t, s)

	captured := time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)
	snap := model.UsageSnapshot{
		AccountID:  id,
		PlanType:   "plus",
		CapturedAt: captured,
		Windows: []model.UsageWindow{
			{Name: "primary", UsedPercent: 12.5, WindowSeconds: 18000, ResetsAt: captured.Add(time.Hour)},
			{Name: "secondary", UsedPercent: 40, WindowSeconds: 604800, ResetsAt: captured.Add(24 * time.Hour)},
		},
	}
	saved, err := s.SaveUsageSnapshot(ctx, snap)
	if err != nil {
		t.Fatalf("SaveUsageSnapshot: %v", err)
	}
	if saved.ID == "" {
		t.Fatal("saved snapshot has empty ID")
	}

	got, err := s.GetLatestUsage(ctx, id)
	if err != nil {
		t.Fatalf("GetLatestUsage: %v", err)
	}
	if got.PlanType != "plus" {
		t.Errorf("PlanType = %q", got.PlanType)
	}
	if !got.CapturedAt.Equal(captured) {
		t.Errorf("CapturedAt = %v, want %v", got.CapturedAt, captured)
	}
	if len(got.Windows) != 2 {
		t.Fatalf("len(Windows) = %d, want 2", len(got.Windows))
	}
	if got.Windows[0].Name != "primary" || got.Windows[0].UsedPercent != 12.5 || got.Windows[0].WindowSeconds != 18000 {
		t.Errorf("window[0] = %+v", got.Windows[0])
	}
	if !got.Windows[0].ResetsAt.Equal(captured.Add(time.Hour)) {
		t.Errorf("window[0].ResetsAt = %v", got.Windows[0].ResetsAt)
	}
}

func TestGetLatestUsageReturnsNewest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := insertTestAccount(t, s)

	base := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)
	for i, pt := range []string{"free", "plus", "pro"} {
		_, err := s.SaveUsageSnapshot(ctx, model.UsageSnapshot{
			AccountID:  id,
			PlanType:   pt,
			CapturedAt: base.Add(time.Duration(i) * time.Hour),
		})
		if err != nil {
			t.Fatalf("SaveUsageSnapshot %d: %v", i, err)
		}
	}
	got, err := s.GetLatestUsage(ctx, id)
	if err != nil {
		t.Fatalf("GetLatestUsage: %v", err)
	}
	if got.PlanType != "pro" {
		t.Errorf("latest PlanType = %q, want pro", got.PlanType)
	}
}

func TestGetLatestUsageNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := insertTestAccount(t, s)

	if _, err := s.GetLatestUsage(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestSaveUsageSnapshotMissingAccountID(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.SaveUsageSnapshot(context.Background(), model.UsageSnapshot{PlanType: "plus"}); err == nil {
		t.Fatal("expected error for missing account_id")
	}
}

func TestSaveUsageSnapshotEmptyWindows(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := insertTestAccount(t, s)

	if _, err := s.SaveUsageSnapshot(ctx, model.UsageSnapshot{AccountID: id, PlanType: "free"}); err != nil {
		t.Fatalf("SaveUsageSnapshot: %v", err)
	}
	got, err := s.GetLatestUsage(ctx, id)
	if err != nil {
		t.Fatalf("GetLatestUsage: %v", err)
	}
	if len(got.Windows) != 0 {
		t.Errorf("len(Windows) = %d, want 0", len(got.Windows))
	}
}

func TestHealthCheckRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := insertTestAccount(t, s)

	base := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	records := []model.HealthCheck{
		{AccountID: id, Kind: model.HealthKindUsagePoll, OK: true, Detail: "ok", LatencyMS: 120, At: base},
		{AccountID: id, Kind: model.HealthKindAuthCheck, OK: false, Detail: "401", LatencyMS: 80, At: base.Add(time.Minute)},
	}
	for _, hc := range records {
		saved, err := s.RecordHealthCheck(ctx, hc)
		if err != nil {
			t.Fatalf("RecordHealthCheck: %v", err)
		}
		if saved.ID == "" {
			t.Fatal("health check has empty id")
		}
	}

	got, err := s.ListHealthChecks(ctx, id, 0)
	if err != nil {
		t.Fatalf("ListHealthChecks: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	// Newest-first ordering: the auth_check (later At) comes first.
	if got[0].Kind != model.HealthKindAuthCheck || got[0].OK {
		t.Errorf("got[0] = %+v", got[0])
	}
	if got[1].Kind != model.HealthKindUsagePoll || !got[1].OK || got[1].LatencyMS != 120 {
		t.Errorf("got[1] = %+v", got[1])
	}

	// Limit clamps the result set.
	limited, err := s.ListHealthChecks(ctx, id, 1)
	if err != nil {
		t.Fatalf("ListHealthChecks limit: %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("limited len = %d, want 1", len(limited))
	}
}

func TestRecordHealthCheckMissingAccountID(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.RecordHealthCheck(context.Background(), model.HealthCheck{Kind: model.HealthKindUsagePoll}); err == nil {
		t.Fatal("expected error for missing account_id")
	}
}

func TestAccountTimingDefaultsAndUpdate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := insertTestAccount(t, s)

	// Defaults: zero timestamps (NULL) and zero counters.
	def, err := s.GetAccountTiming(ctx, id)
	if err != nil {
		t.Fatalf("GetAccountTiming: %v", err)
	}
	if !def.CooldownUntil.IsZero() || !def.NextProbeAt.IsZero() {
		t.Errorf("default timestamps not zero: %+v", def)
	}
	if def.ConsecutiveFailures != 0 || def.BackoffLevel != 0 || def.ConcurrencyCap != 0 {
		t.Errorf("default counters not zero: %+v", def)
	}

	// Update with real timestamps + counters.
	cooldown := time.Date(2026, 8, 14, 13, 0, 0, 0, time.UTC)
	nextProbe := time.Date(2026, 8, 14, 13, 5, 0, 0, time.UTC)
	want := model.AccountTiming{
		CooldownUntil:       cooldown,
		NextProbeAt:         nextProbe,
		ConsecutiveFailures: 3,
		BackoffLevel:        2,
		ConcurrencyCap:      5,
	}
	if err := s.SetAccountTiming(ctx, id, want); err != nil {
		t.Fatalf("SetAccountTiming: %v", err)
	}
	got, err := s.GetAccountTiming(ctx, id)
	if err != nil {
		t.Fatalf("GetAccountTiming after set: %v", err)
	}
	if !got.CooldownUntil.Equal(cooldown) || !got.NextProbeAt.Equal(nextProbe) {
		t.Errorf("timestamps = %+v, want cooldown=%v next=%v", got, cooldown, nextProbe)
	}
	// concurrency_cap is admin-owned and NOT written by SetAccountTiming, so it
	// stays at the column default regardless of what the timing struct carried.
	if got.ConsecutiveFailures != 3 || got.BackoffLevel != 2 || got.ConcurrencyCap != 0 {
		t.Errorf("counters = %+v", got)
	}

	// Setting zero timestamps writes NULL again (round-trips to zero time).
	if err := s.SetAccountTiming(ctx, id, model.AccountTiming{ConsecutiveFailures: 0}); err != nil {
		t.Fatalf("SetAccountTiming reset: %v", err)
	}
	reset, err := s.GetAccountTiming(ctx, id)
	if err != nil {
		t.Fatalf("GetAccountTiming reset: %v", err)
	}
	if !reset.CooldownUntil.IsZero() || !reset.NextProbeAt.IsZero() {
		t.Errorf("reset timestamps not zero: %+v", reset)
	}
}

func TestAccountTimingNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if _, err := s.GetAccountTiming(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAccountTiming err = %v, want ErrNotFound", err)
	}
	if err := s.SetAccountTiming(ctx, "nope", model.AccountTiming{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetAccountTiming err = %v, want ErrNotFound", err)
	}
}
