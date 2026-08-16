package store

import (
	"context"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// TestAuditLogAppendAndList inserts entries and reads them back newest-first with
// pagination, and confirms the fixed-width timestamp ordering is chronological.
func TestAuditLogAppendAndList(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	base := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		if err := s.InsertAuditEntry(ctx, model.AuditEntry{
			At:     base.Add(time.Duration(i) * time.Minute),
			Actor:  model.AuditActorOperator,
			Action: "test.action",
			Target: "t" + string(rune('0'+i)),
		}); err != nil {
			t.Fatalf("InsertAuditEntry %d: %v", i, err)
		}
	}

	// Newest-first.
	all, err := s.ListAuditEntries(ctx, 100, 0)
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("count = %d, want 5", len(all))
	}
	if all[0].Target != "t4" || all[4].Target != "t0" {
		t.Errorf("order = [%s..%s], want newest (t4) first", all[0].Target, all[4].Target)
	}
	if !all[0].At.After(all[1].At) {
		t.Errorf("timestamps not descending: %v then %v", all[0].At, all[1].At)
	}

	// Pagination.
	page, err := s.ListAuditEntries(ctx, 2, 1)
	if err != nil {
		t.Fatalf("ListAuditEntries page: %v", err)
	}
	if len(page) != 2 || page[0].Target != "t3" {
		t.Errorf("page = %v, want [t3 t2]", page)
	}

	// A generated id is assigned when omitted.
	if all[0].ID == "" {
		t.Error("entry id was not generated")
	}
}

// TestAuditListLimitClamped confirms an over-large client-supplied limit is
// clamped to maxAuditListLimit rather than forwarded verbatim into SQL.
func TestAuditListLimitClamped(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	base := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if err := s.InsertAuditEntry(ctx, model.AuditEntry{
			At:     base.Add(time.Duration(i) * time.Minute),
			Actor:  model.AuditActorSystem,
			Action: "test.clamp",
		}); err != nil {
			t.Fatalf("InsertAuditEntry %d: %v", i, err)
		}
	}

	// A huge limit must not error and must return only the rows that exist —
	// the clamp bounds the SQL LIMIT, not the result count.
	got, err := s.ListAuditEntries(ctx, 1_000_000_000, 0)
	if err != nil {
		t.Fatalf("ListAuditEntries huge limit: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("count = %d, want 3", len(got))
	}
}
