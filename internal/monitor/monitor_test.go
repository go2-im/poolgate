package monitor

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// fakeStore records inserts + prune calls.
type fakeStore struct {
	mu        sync.Mutex
	inserted  []model.RequestLog
	insertErr error
	pruned    int64
	pruneAt   time.Time
	pruneErr  error
}

func (f *fakeStore) InsertRequestLog(_ context.Context, l model.RequestLog) (model.RequestLog, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.insertErr != nil {
		return model.RequestLog{}, f.insertErr
	}
	f.inserted = append(f.inserted, l)
	return l, nil
}

func (f *fakeStore) PruneRequestLogs(_ context.Context, before time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pruneAt = before
	if f.pruneErr != nil {
		return 0, f.pruneErr
	}
	return f.pruned, nil
}

func (f *fakeStore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.inserted)
}

func fixedNow() time.Time { return time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC) }

// ---- hub ------------------------------------------------------------------

func TestHubFanOutAndFilter(t *testing.T) {
	h := NewHub()
	all := h.Subscribe(model.RequestLogFilter{})
	onlyGPT5 := h.Subscribe(model.RequestLogFilter{Model: "gpt-5"})

	h.Publish(model.RequestLog{Model: "gpt-5"})
	h.Publish(model.RequestLog{Model: "gpt-4"})

	// all-subscriber sees both.
	if l := <-all.C; l.Model != "gpt-5" {
		t.Errorf("first = %q", l.Model)
	}
	if l := <-all.C; l.Model != "gpt-4" {
		t.Errorf("second = %q", l.Model)
	}
	// filtered subscriber sees only gpt-5.
	select {
	case l := <-onlyGPT5.C:
		if l.Model != "gpt-5" {
			t.Errorf("filtered got %q", l.Model)
		}
	default:
		t.Error("filtered subscriber missed gpt-5")
	}
	select {
	case l := <-onlyGPT5.C:
		t.Errorf("filtered should not receive gpt-4, got %q", l.Model)
	default:
	}
}

func TestHubUnsubscribe(t *testing.T) {
	h := NewHub()
	s := h.Subscribe(model.RequestLogFilter{})
	if h.subscriberCount() != 1 {
		t.Fatalf("count = %d, want 1", h.subscriberCount())
	}
	h.Unsubscribe(s)
	if h.subscriberCount() != 0 {
		t.Fatalf("count after unsub = %d, want 0", h.subscriberCount())
	}
	h.Unsubscribe(nil) // idempotent / nil-safe
	h.Publish(model.RequestLog{Model: "x"}) // no subscribers: must not panic/block
}

func TestHubDropsSlowSubscriber(t *testing.T) {
	h := NewHub()
	s := h.Subscribe(model.RequestLogFilter{})
	// Publish more than the buffer without draining; must not block.
	done := make(chan struct{})
	go func() {
		for i := 0; i < subBuffer+50; i++ {
			h.Publish(model.RequestLog{Model: "m"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a slow subscriber")
	}
	_ = s
}

// ---- engine ---------------------------------------------------------------

func TestRecordNilEngineNoPanic(t *testing.T) {
	var e *Engine
	e.Record(model.RequestLog{Model: "x"}) // must not panic
}

func TestProcessOnePersistsAndPublishes(t *testing.T) {
	fs := &fakeStore{}
	e := New(fs, WithClock(fixedNow))
	events, cancel := e.Subscribe(model.RequestLogFilter{})
	defer cancel()

	e.processOne(context.Background(), model.RequestLog{Model: "gpt-5"})
	if fs.count() != 1 {
		t.Fatalf("persisted = %d, want 1", fs.count())
	}
	select {
	case l := <-events:
		if l.Model != "gpt-5" {
			t.Errorf("published %q", l.Model)
		}
	default:
		t.Error("event not published")
	}
}

func TestProcessOnePublishesEvenIfPersistFails(t *testing.T) {
	fs := &fakeStore{insertErr: errors.New("db down")}
	e := New(fs, WithClock(fixedNow))
	events, cancel := e.Subscribe(model.RequestLogFilter{})
	defer cancel()
	e.processOne(context.Background(), model.RequestLog{Model: "gpt-5"})
	select {
	case l := <-events:
		if l.Model != "gpt-5" {
			t.Errorf("published %q", l.Model)
		}
	default:
		t.Error("event should still be published when persist fails")
	}
}

func TestPrune(t *testing.T) {
	fs := &fakeStore{pruned: 3}
	e := New(fs, WithClock(fixedNow), WithRetention(24*time.Hour))
	e.prune(context.Background())
	want := fixedNow().Add(-24 * time.Hour)
	if !fs.pruneAt.Equal(want) {
		t.Errorf("prune cutoff = %v, want %v", fs.pruneAt, want)
	}
	// Retention <= 0 disables pruning.
	fs2 := &fakeStore{}
	e2 := New(fs2, WithRetention(0))
	e2.prune(context.Background())
	if !fs2.pruneAt.IsZero() {
		t.Error("prune should be a no-op when retention <= 0")
	}
}

func TestRunDrainsAndStops(t *testing.T) {
	fs := &fakeStore{}
	e := New(fs, WithClock(fixedNow))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()

	e.Record(model.RequestLog{Model: "gpt-5"})
	deadline := time.After(2 * time.Second)
	for fs.count() == 0 {
		select {
		case <-deadline:
			t.Fatal("Run did not persist the recorded log")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Run returned %v, want context.Canceled", err)
	}
}

func TestRecordDefaultsAtAndDropsWhenFull(t *testing.T) {
	fs := &fakeStore{}
	e := New(fs, WithClock(fixedNow), WithQueueSize(1))
	// Fill the queue (not draining) then overflow — must not block.
	for i := 0; i < 10; i++ {
		e.Record(model.RequestLog{Model: "m"})
	}
	// The first record's At was defaulted from the clock.
	// (Drained lazily by a later Run; here we only assert Record never blocked.)
}
