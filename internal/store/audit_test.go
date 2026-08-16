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

func TestAuditChainDetectsTampering(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	for i := 0; i < 4; i++ {
		if err := s.InsertAuditEntry(ctx, model.AuditEntry{
			Actor: model.AuditActorOperator, Action: "test.act", Target: "t" + string(rune('0'+i)),
		}); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}

	// Intact chain verifies.
	ok, count, broken, err := s.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok || count != 4 || broken != "" {
		t.Fatalf("intact chain: ok=%v count=%d broken=%q, want true/4/''", ok, count, broken)
	}

	// Tamper with a row's detail directly (bypassing the store API).
	var victim string
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM audit_log ORDER BY rowid ASC LIMIT 1 OFFSET 2`).Scan(&victim); err != nil {
		t.Fatalf("pick victim: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE audit_log SET detail = 'FORGED' WHERE id = ?`, victim); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	ok, _, broken, err = s.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("verify after tamper: %v", err)
	}
	if ok || broken != victim {
		t.Errorf("tampered chain: ok=%v broken=%q, want false and broken=%s", ok, broken, victim)
	}
}

func TestAuditChainDetectsDeletion(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	for i := 0; i < 3; i++ {
		_ = s.InsertAuditEntry(ctx, model.AuditEntry{Actor: model.AuditActorSystem, Action: "a"})
	}
	// Delete the middle row: the row after it no longer chains to the right prev.
	var mid string
	_ = s.db.QueryRowContext(ctx, `SELECT id FROM audit_log ORDER BY rowid ASC LIMIT 1 OFFSET 1`).Scan(&mid)
	if _, err := s.db.ExecContext(ctx, `DELETE FROM audit_log WHERE id = ?`, mid); err != nil {
		t.Fatalf("delete: %v", err)
	}
	ok, _, _, err := s.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Error("chain verified as intact after a mid-row deletion, want broken")
	}
}

func TestAuditChainSkipsLegacyBaselineAndVerifiesNewRows(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	base := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	// Simulate pre-v9 rows: inserted directly with empty hash (as migration v9's
	// column default leaves them on an upgraded DB).
	for i := 0; i < 3; i++ {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO audit_log (id, at, actor, action, target, detail, hash) VALUES (?, ?, 'system', 'legacy', '', '', '')`,
			"legacy_"+string(rune('0'+i)), formatTimeFixed(base.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatalf("seed legacy %d: %v", i, err)
		}
	}
	// New (v9) rows chain onto the empty baseline tip.
	for i := 0; i < 3; i++ {
		if err := s.InsertAuditEntry(ctx, model.AuditEntry{Actor: model.AuditActorOperator, Action: "new.act"}); err != nil {
			t.Fatalf("insert new %d: %v", i, err)
		}
	}

	ok, count, broken, err := s.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok || count != 6 || broken != "" {
		t.Fatalf("upgraded chain: ok=%v count=%d broken=%q, want true/6/''", ok, count, broken)
	}

	// Tampering a NEW (hashed) row is still detected past the baseline.
	var victim string
	_ = s.db.QueryRowContext(ctx, `SELECT id FROM audit_log WHERE hash != '' ORDER BY rowid ASC LIMIT 1 OFFSET 1`).Scan(&victim)
	if _, err := s.db.ExecContext(ctx, `UPDATE audit_log SET detail = 'X' WHERE id = ?`, victim); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if ok, _, broken, _ := s.VerifyAuditChain(ctx); ok || broken != victim {
		t.Errorf("post-baseline tamper: ok=%v broken=%q, want false/%s", ok, broken, victim)
	}
}
