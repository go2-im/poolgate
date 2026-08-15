// Package monitor is poolgate's real-time request monitor backend (DESIGN.md §15
// / §24.1). The gateway hands each completed request to Record (non-blocking); a
// background Run goroutine persists it to request_logs and fans it out to live
// SSE subscribers via the Hub, and periodically prunes old rows.
//
// # Concurrency model
//
// Record only enqueues (dropping on a full queue, logged), so proxy request
// handling is never stalled by monitor I/O — mirroring internal/notify. The
// synchronous persistence + broadcast lives in Run's drain loop and is directly
// unit-tested via processOne.
package monitor

import (
	"context"
	"log/slog"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// Store is the persistence surface the monitor needs. *store.Store satisfies it.
type Store interface {
	InsertRequestLog(ctx context.Context, l model.RequestLog) (model.RequestLog, error)
	PruneRequestLogs(ctx context.Context, before time.Time) (int64, error)
}

// Defaults for the recorder.
const (
	defaultQueueSize     = 512
	defaultRetention     = 7 * 24 * time.Hour
	defaultPruneInterval = 1 * time.Hour
)

// Engine records request logs and drives the live stream. Construct with New.
type Engine struct {
	store     Store
	hub       *Hub
	now       func() time.Time
	logger    *slog.Logger
	retention time.Duration
	pruneIvl  time.Duration
	queue     chan model.RequestLog
}

// Option customizes an Engine.
type Option func(*Engine)

// WithClock injects the time source (default time.Now, UTC).
func WithClock(now func() time.Time) Option {
	return func(e *Engine) {
		if now != nil {
			e.now = now
		}
	}
}

// WithLogger sets the structured logger.
func WithLogger(l *slog.Logger) Option {
	return func(e *Engine) {
		if l != nil {
			e.logger = l
		}
	}
}

// WithRetention overrides how long request logs are kept before pruning
// (default 7d). A value <= 0 disables pruning.
func WithRetention(d time.Duration) Option { return func(e *Engine) { e.retention = d } }

// WithQueueSize overrides the record queue depth (default 512).
func WithQueueSize(n int) Option {
	return func(e *Engine) {
		if n > 0 {
			e.queue = make(chan model.RequestLog, n)
		}
	}
}

// New builds a monitor Engine over st.
func New(st Store, opts ...Option) *Engine {
	e := &Engine{
		store:     st,
		hub:       NewHub(),
		now:       func() time.Time { return time.Now().UTC() },
		logger:    slog.Default(),
		retention: defaultRetention,
		pruneIvl:  defaultPruneInterval,
		queue:     make(chan model.RequestLog, defaultQueueSize),
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Hub exposes the fan-out for the admin SSE handler to Subscribe/Unsubscribe.
func (e *Engine) Hub() *Hub { return e.hub }

// Subscribe registers a filtered live feed and returns its receive channel plus a
// cancel func the caller MUST invoke when done (e.g. on SSE client disconnect).
// This adapter keeps SSE consumers decoupled from the concrete Subscription type.
func (e *Engine) Subscribe(f model.RequestLogFilter) (<-chan model.RequestLog, func()) {
	sub := e.hub.Subscribe(f)
	return sub.C, func() { e.hub.Unsubscribe(sub) }
}

// Record enqueues a completed request log for persistence + live broadcast. It
// never blocks: a full queue drops the record (logged). Safe on a nil Engine so
// callers can wire an optional recorder.
func (e *Engine) Record(l model.RequestLog) {
	if e == nil {
		return
	}
	if l.At.IsZero() {
		l.At = e.now()
	}
	select {
	case e.queue <- l:
	default:
		e.logger.Warn("monitor: record queue full, dropping request log",
			slog.String("endpoint", l.Endpoint))
	}
}

// Run drains the queue (persist + broadcast) and prunes old rows until ctx is
// cancelled (then returns ctx.Err()).
func (e *Engine) Run(ctx context.Context) error {
	var pruneC <-chan time.Time
	if e.retention > 0 && e.pruneIvl > 0 {
		t := time.NewTicker(e.pruneIvl)
		defer t.Stop()
		pruneC = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case l := <-e.queue:
			e.processOne(ctx, l)
		case <-pruneC:
			e.prune(ctx)
		}
	}
}

// processOne persists a record then broadcasts it. Persistence failures are
// logged but do not drop the live event (the UI still sees it).
func (e *Engine) processOne(ctx context.Context, l model.RequestLog) {
	stored, err := e.store.InsertRequestLog(ctx, l)
	if err != nil {
		e.logger.Warn("monitor: persist request log failed", slog.Any("err", err))
		stored = l // fall back to the in-memory record for the live stream
	}
	e.hub.Publish(stored)
}

// prune removes request logs older than the retention window.
func (e *Engine) prune(ctx context.Context) {
	if e.retention <= 0 {
		return
	}
	if _, err := e.store.PruneRequestLogs(ctx, e.now().Add(-e.retention)); err != nil {
		e.logger.Warn("monitor: prune request logs failed", slog.Any("err", err))
	}
}
