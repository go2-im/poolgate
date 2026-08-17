package health

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// TestProactiveRefreshLogic covers maybeProactiveRefresh's decision branches: only
// ok/unknown accounts are eligible; a stale last-write triggers a refresh; a fresh one
// (via last_refreshed_at OR the created_at fallback) does not; a never-recorded
// account is exercised once; and a zero interval disables it.
func TestProactiveRefreshLogic(t *testing.T) {
	ctx := context.Background()
	now := baseTime

	cases := []struct {
		name     string
		interval time.Duration
		acct     model.Account
		want     int // expected refresher calls
	}{
		{"ok + stale last_refreshed → refresh", 12 * time.Hour,
			model.Account{ID: "a", State: model.StateOK, LastRefreshedAt: now.Add(-13 * time.Hour)}, 1},
		{"unknown + stale → refresh (eligible)", 12 * time.Hour,
			model.Account{ID: "a", State: model.StateUnknown, LastRefreshedAt: now.Add(-13 * time.Hour)}, 1},
		{"ok + fresh last_refreshed → skip", 12 * time.Hour,
			model.Account{ID: "a", State: model.StateOK, LastRefreshedAt: now.Add(-1 * time.Hour)}, 0},
		{"ok + zero last_refreshed but fresh created_at → skip (fallback)", 12 * time.Hour,
			model.Account{ID: "a", State: model.StateOK, CreatedAt: now.Add(-1 * time.Hour)}, 0},
		{"ok + zero last_refreshed + stale created_at → refresh", 12 * time.Hour,
			model.Account{ID: "a", State: model.StateOK, CreatedAt: now.Add(-13 * time.Hour)}, 1},
		{"ok + never recorded (both zero) → refresh once", 12 * time.Hour,
			model.Account{ID: "a", State: model.StateOK}, 1},
		{"disabled (0 interval) → skip even if stale", 0,
			model.Account{ID: "a", State: model.StateOK, LastRefreshedAt: now.Add(-100 * time.Hour)}, 0},
		{"expired + stale → skip (excluded state)", 12 * time.Hour,
			model.Account{ID: "a", State: model.StateExpired, LastRefreshedAt: now.Add(-100 * time.Hour)}, 0},
		{"cooldown + stale → skip (excluded state)", 12 * time.Hour,
			model.Account{ID: "a", State: model.StateCooldown, LastRefreshedAt: now.Add(-100 * time.Hour)}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rf := &fakeRefresher{}
			e, _ := newTestEngine(t, newFakeStore(), &fakeUsage{}, rf, WithProactiveRefresh(tc.interval))
			e.maybeProactiveRefresh(ctx, tc.acct, now)
			if rf.seen != tc.want {
				t.Fatalf("refresher calls = %d, want %d", rf.seen, tc.want)
			}
		})
	}
}

// TestProactiveRefreshFailureDefers proves a FAILED proactive refresh still defers the
// next attempt by the interval (via the per-account last-attempt time), so a
// persistently-failing account is not retried every tick.
func TestProactiveRefreshFailureDefers(t *testing.T) {
	ctx := context.Background()
	now := baseTime
	rf := &fakeRefresher{err: errors.New("issuer down")}
	e, _ := newTestEngine(t, newFakeStore(), &fakeUsage{}, rf, WithProactiveRefresh(12*time.Hour))
	acct := model.Account{ID: "a", State: model.StateOK, LastRefreshedAt: now.Add(-24 * time.Hour)}

	e.maybeProactiveRefresh(ctx, acct, now) // attempt 1 (fails)
	if rf.seen != 1 {
		t.Fatalf("after first attempt: refresher calls = %d, want 1", rf.seen)
	}
	// A second tick shortly after must NOT retry — the failed attempt deferred it.
	e.maybeProactiveRefresh(ctx, acct, now.Add(1*time.Minute))
	if rf.seen != 1 {
		t.Fatalf("failed attempt must defer the next: refresher calls = %d, want still 1", rf.seen)
	}
	// Once the interval elapses past the attempt, it retries.
	e.maybeProactiveRefresh(ctx, acct, now.Add(13*time.Hour))
	if rf.seen != 2 {
		t.Fatalf("after the interval a retry is allowed: refresher calls = %d, want 2", rf.seen)
	}
}

// TestTickProactiveRefresh proves the scheduler loop wires proactive refresh: a stale
// ok account is refreshed during Tick (the healthy usage-poll probe itself never
// refreshes, so the single call is the proactive one); a fresh account is not.
func TestTickProactiveRefresh(t *testing.T) {
	ctx := context.Background()

	t.Run("stale ok account is proactively refreshed", func(t *testing.T) {
		stale := model.Account{ID: "a", State: model.StateOK, LastRefreshedAt: baseTime.Add(-24 * time.Hour)}
		rf := &fakeRefresher{}
		e, _ := newTestEngine(t, newFakeStore(stale), &fakeUsage{}, rf, WithProactiveRefresh(12*time.Hour))
		if err := e.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if rf.seen != 1 {
			t.Fatalf("refresher calls = %d, want 1 (proactive)", rf.seen)
		}
	})

	t.Run("fresh ok account is not proactively refreshed", func(t *testing.T) {
		fresh := model.Account{ID: "a", State: model.StateOK, LastRefreshedAt: baseTime.Add(-1 * time.Hour)}
		rf := &fakeRefresher{}
		e, _ := newTestEngine(t, newFakeStore(fresh), &fakeUsage{}, rf, WithProactiveRefresh(12*time.Hour))
		if err := e.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if rf.seen != 0 {
			t.Fatalf("refresher calls = %d, want 0 (fresh, no proactive)", rf.seen)
		}
	})
}
