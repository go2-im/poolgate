package store

import (
	"context"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

func TestRequestLogInsertAndList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

	seed := []model.RequestLog{
		{At: base.Add(1 * time.Minute), Endpoint: "prod", Model: "gpt-5", SessionID: "s1", APIKeyID: "k1", AccountID: "a1", Status: 200, TokensIn: 10, TokensOut: 20},
		{At: base.Add(2 * time.Minute), Endpoint: "prod", Model: "gpt-4", SessionID: "s1", APIKeyID: "k1", AccountID: "a2", Status: 429, TokensIn: 5, TokensOut: 0},
		{At: base.Add(3 * time.Minute), Endpoint: "dev", Model: "gpt-5", SessionID: "s2", APIKeyID: "k2", AccountID: "a1", Status: 200, TokensIn: 7, TokensOut: 3},
	}
	for _, l := range seed {
		if _, err := s.InsertRequestLog(ctx, l); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	// Newest-first, no filter.
	all, err := s.ListRequestLogs(ctx, model.RequestLogFilter{}, 100, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 3 || all[0].Model != "gpt-5" || !all[0].At.After(all[1].At) {
		t.Fatalf("expected 3 newest-first, got %d", len(all))
	}

	// Facet filters.
	byModel, _ := s.ListRequestLogs(ctx, model.RequestLogFilter{Model: "gpt-5"}, 100, 0)
	if len(byModel) != 2 {
		t.Errorf("model filter = %d, want 2", len(byModel))
	}
	bySession, _ := s.ListRequestLogs(ctx, model.RequestLogFilter{SessionID: "s1"}, 100, 0)
	if len(bySession) != 2 {
		t.Errorf("session filter = %d, want 2", len(bySession))
	}
	byStatus, _ := s.ListRequestLogs(ctx, model.RequestLogFilter{Status: 429}, 100, 0)
	if len(byStatus) != 1 || byStatus[0].AccountID != "a2" {
		t.Errorf("status filter wrong: %+v", byStatus)
	}
	composite, _ := s.ListRequestLogs(ctx, model.RequestLogFilter{Model: "gpt-5", AccountID: "a1"}, 100, 0)
	if len(composite) != 2 {
		t.Errorf("composite filter = %d, want 2", len(composite))
	}

	// Time window [since, until).
	win, _ := s.ListRequestLogs(ctx, model.RequestLogFilter{Since: base.Add(2 * time.Minute), Until: base.Add(3 * time.Minute)}, 100, 0)
	if len(win) != 1 || win[0].Model != "gpt-4" {
		t.Errorf("time window wrong: %+v", win)
	}

	// Pagination.
	page1, _ := s.ListRequestLogs(ctx, model.RequestLogFilter{}, 2, 0)
	page2, _ := s.ListRequestLogs(ctx, model.RequestLogFilter{}, 2, 2)
	if len(page1) != 2 || len(page2) != 1 {
		t.Errorf("pagination wrong: %d + %d", len(page1), len(page2))
	}
}

func TestCountRequestLogs(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	logs := []model.RequestLog{
		{Model: "gpt-5", Status: 200, TokensIn: 10, TokensOut: 20},
		{Model: "gpt-5", Status: 200, TokensIn: 1, TokensOut: 2},
		{Model: "gpt-5", Status: 500, TokensIn: 3, TokensOut: 0},
		{Model: "other", Status: 200, TokensIn: 100, TokensOut: 100},
	}
	for _, l := range logs {
		if _, err := s.InsertRequestLog(ctx, l); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	c, err := s.CountRequestLogs(ctx, model.RequestLogFilter{Model: "gpt-5"})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if c.Total != 3 || c.Success != 2 || c.Error != 1 {
		t.Errorf("counts = %+v, want total3/success2/error1", c)
	}
	if c.TokensIn != 14 || c.TokensOut != 22 {
		t.Errorf("token sums = %d/%d, want 14/22", c.TokensIn, c.TokensOut)
	}
}

func TestPruneRequestLogs(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	old := model.RequestLog{At: base.Add(-48 * time.Hour), Model: "old"}
	fresh := model.RequestLog{At: base, Model: "fresh"}
	if _, err := s.InsertRequestLog(ctx, old); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertRequestLog(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	n, err := s.PruneRequestLogs(ctx, base.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned = %d, want 1", n)
	}
	remaining, _ := s.ListRequestLogs(ctx, model.RequestLogFilter{}, 100, 0)
	if len(remaining) != 1 || remaining[0].Model != "fresh" {
		t.Errorf("after prune: %+v", remaining)
	}
}

func TestRequestLogTimeOrderingAcrossFractionWidths(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sec := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)

	// Same second, differing sub-second fraction widths — the case where naive
	// variable-width RFC3339 string comparison misorders / misfilters.
	times := []time.Time{
		sec,                             // .000000000 (whole second)
		sec.Add(500 * time.Millisecond), // .5
		sec.Add(123455 * time.Microsecond),
		sec.Add(123456 * time.Microsecond),
	}
	for i, at := range times {
		if _, err := s.InsertRequestLog(ctx, model.RequestLog{At: at, Model: "m", SessionID: "s"}); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}

	// Newest-first ordering must be chronological.
	all, err := s.ListRequestLogs(ctx, model.RequestLogFilter{}, 100, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("got %d rows, want 4", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].At.Before(all[i].At) {
			t.Errorf("row %d (%v) is older than row %d (%v) — not newest-first",
				i-1, all[i-1].At, i, all[i].At)
		}
	}

	// A whole-second `since` (as the UI sends) must include the same-second
	// sub-second rows — matching model.RequestLogFilter.Matches.
	f := model.RequestLogFilter{Since: sec}
	got, _ := s.ListRequestLogs(ctx, f, 100, 0)
	if len(got) != 4 {
		t.Errorf("since=whole-second returned %d, want 4 (all >= since)", len(got))
	}
	for _, l := range got {
		if !f.Matches(l) {
			t.Errorf("SQL returned a row Matches rejects: %v", l.At)
		}
	}
}

func TestRequestLogMigrationV5(t *testing.T) {
	s := newTestStore(t)
	v, err := s.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v < 5 {
		t.Fatalf("SchemaVersion = %d, want >= 5 (request_logs)", v)
	}
}
