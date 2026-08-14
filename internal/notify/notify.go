// Package notify is poolgate's notification/alerting backend (DESIGN.md §11). It
// turns secret-free model.NotifyEvent values emitted by the health and policy
// engines into deliveries over user-configured channels (DingTalk / WeCom /
// custom webhook), with:
//
//   - an SSRF-guarded egress client (ssrf.go): HTTPS-only, resolve-then-connect,
//     blocking private/loopback/link-local/metadata/ULA addresses, re-validated
//     at connect time (anti DNS-rebinding);
//   - per-channel event subscriptions + a quota_low headroom threshold;
//   - per-(channel, kind, account) dedup/rate-limit so one flapping account does
//     not spam a channel;
//   - bounded retries with a per-attempt timeout; and
//   - strict payload hygiene — events carry no secrets, and delivery errors never
//     echo channel URLs/secrets.
//
// # Concurrency model
//
// The health/gateway hot paths call Emit (non-blocking): the event is queued to a
// buffered channel and a background Run goroutine dispatches it with a fresh
// timeout context, so notification I/O never blocks account-state transitions or
// request routing. dispatch (the synchronous core) is directly unit-tested.
package notify

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// ChannelStore is the persistence surface the engine needs: the current set of
// configured channels (with their decrypted Config). *store.Store satisfies it.
type ChannelStore interface {
	ListNotifyChannels(ctx context.Context) ([]model.NotifyChannel, error)
}

// Defaults for the dispatcher.
const (
	defaultQueueSize      = 256
	defaultRetries        = 2
	defaultTimeout        = 10 * time.Second
	defaultDedupWindow    = 10 * time.Minute
	defaultQuotaLowPct    = 15.0 // headroom% at/below which quota_low is forwarded when a channel sets no MinHeadroom
	retryBackoff          = 500 * time.Millisecond
	dedupGCInterval       = 30 * time.Minute
	dedupEntryMaxLifetime = 24 * time.Hour
)

// Engine is the notification dispatcher. Construct with New; the zero value is not
// usable. It is safe for concurrent Emit calls.
type Engine struct {
	store  ChannelStore
	client *http.Client
	now    func() time.Time
	logger *slog.Logger

	retries int
	timeout time.Duration
	sleep   func(ctx context.Context, d time.Duration) error

	queue chan model.NotifyEvent

	mu       sync.Mutex
	lastSent map[string]time.Time // dedup key -> last successful send time
}

// Option customizes an Engine.
type Option func(*Engine)

// WithHTTPClient overrides the egress HTTP client. Production uses the built-in
// SSRF-guarded client; tests inject a client pointed at an httptest server.
func WithHTTPClient(c *http.Client) Option { return func(e *Engine) { e.client = c } }

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

// WithRetries overrides the number of retry attempts after the first (default 2).
func WithRetries(n int) Option {
	return func(e *Engine) {
		if n >= 0 {
			e.retries = n
		}
	}
}

// WithTimeout overrides the per-delivery timeout (default 10s).
func WithTimeout(d time.Duration) Option {
	return func(e *Engine) {
		if d > 0 {
			e.timeout = d
		}
	}
}

// WithSleep injects the retry-backoff sleep (default a real timer); tests pass a
// no-op for determinism.
func WithSleep(fn func(ctx context.Context, d time.Duration) error) Option {
	return func(e *Engine) {
		if fn != nil {
			e.sleep = fn
		}
	}
}

// New builds a notification Engine over st. By default it uses the SSRF-guarded
// egress client.
func New(st ChannelStore, opts ...Option) *Engine {
	e := &Engine{
		store:    st,
		now:      func() time.Time { return time.Now().UTC() },
		logger:   slog.Default(),
		retries:  defaultRetries,
		timeout:  defaultTimeout,
		sleep:    realSleep,
		queue:    make(chan model.NotifyEvent, defaultQueueSize),
		lastSent: make(map[string]time.Time),
	}
	for _, o := range opts {
		o(e)
	}
	if e.client == nil {
		e.client = newGuardedClient(e.timeout)
	}
	return e
}

// Emit queues ev for asynchronous delivery. It never blocks: if the queue is full
// the event is dropped and logged (a notification is best-effort and must not
// stall the hot path). Safe to call with a nil Engine (no-op), so callers can
// wire an optional sink.
func (e *Engine) Emit(ev model.NotifyEvent) {
	if e == nil {
		return
	}
	if ev.At.IsZero() {
		ev.At = e.now()
	}
	select {
	case e.queue <- ev:
	default:
		e.logger.Warn("notify: event queue full, dropping event", slog.String("kind", string(ev.Kind)))
	}
}

// Run drains the queue and dispatches events until ctx is cancelled (then returns
// ctx.Err()). It also periodically prunes the dedup map.
func (e *Engine) Run(ctx context.Context) error {
	gc := time.NewTicker(dedupGCInterval)
	defer gc.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev := <-e.queue:
			e.dispatch(ctx, ev)
		case <-gc.C:
			e.gcDedup()
		}
	}
}

// dispatch is the synchronous delivery core (directly unit-tested): it loads the
// current channels, and for each enabled, subscribed, threshold-passing,
// non-deduped channel it delivers the event with bounded retries.
func (e *Engine) dispatch(ctx context.Context, ev model.NotifyEvent) {
	channels, err := e.store.ListNotifyChannels(ctx)
	if err != nil {
		e.logger.Warn("notify: list channels failed", slog.Any("err", err))
		return
	}
	for _, ch := range channels {
		if !e.shouldSend(ch, ev) {
			continue
		}
		if err := e.deliver(ctx, ch, ev); err != nil {
			// Errors are pre-redacted by the senders (no URL/secret).
			e.logger.Warn("notify: delivery failed",
				slog.String("channel", ch.ID),
				slog.String("type", string(ch.Type)),
				slog.String("kind", string(ev.Kind)),
				slog.Any("err", err))
			continue
		}
		e.markSent(ch, ev)
	}
}

// shouldSend applies the enable/subscription/threshold/dedup gates. It does not
// perform I/O.
func (e *Engine) shouldSend(ch model.NotifyChannel, ev model.NotifyEvent) bool {
	if !ch.Enabled {
		return false
	}
	if !ch.Subscribes(ev.Kind) {
		return false
	}
	if ev.Kind == model.EventQuotaLow {
		threshold := ch.MinHeadroom
		if threshold <= 0 {
			threshold = defaultQuotaLowPct
		}
		if ev.Headroom > threshold {
			return false
		}
	}
	return !e.deduped(ch, ev)
}

// deduped reports whether an identical (channel, kind, account, endpoint) alert
// was sent within the channel's dedup window.
func (e *Engine) deduped(ch model.NotifyChannel, ev model.NotifyEvent) bool {
	window := time.Duration(ch.DedupSeconds) * time.Second
	if window <= 0 {
		window = defaultDedupWindow
	}
	// The dedup entry is garbage-collected after dedupEntryMaxLifetime, so a
	// configured window longer than that could not actually be honored (the entry
	// would be gone). Clamp so the effective window never exceeds GC retention.
	if window > dedupEntryMaxLifetime {
		window = dedupEntryMaxLifetime
	}
	key := ch.ID + "|" + ev.DedupKey()
	e.mu.Lock()
	defer e.mu.Unlock()
	last, ok := e.lastSent[key]
	return ok && e.now().Sub(last) < window
}

// markSent records a successful delivery for dedup accounting.
func (e *Engine) markSent(ch model.NotifyChannel, ev model.NotifyEvent) {
	key := ch.ID + "|" + ev.DedupKey()
	e.mu.Lock()
	e.lastSent[key] = e.now()
	e.mu.Unlock()
}

// gcDedup drops dedup entries older than dedupEntryMaxLifetime so the map does not
// grow without bound.
func (e *Engine) gcDedup() {
	cutoff := e.now().Add(-dedupEntryMaxLifetime)
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, t := range e.lastSent {
		if t.Before(cutoff) {
			delete(e.lastSent, k)
		}
	}
}

// deliver sends one event to one channel with bounded retries + a per-attempt
// timeout. Retries only run on a transient error; a permanent failure (bad
// scheme/config, unknown type, malformed template, upstream errcode rejection)
// returns immediately so a misconfigured channel does not burn every attempt +
// backoff. SSRF blocks are treated as transient (they may be a transient DNS
// state) and are retried within the cap.
func (e *Engine) deliver(ctx context.Context, ch model.NotifyChannel, ev model.NotifyEvent) error {
	var lastErr error
	for attempt := 0; attempt <= e.retries; attempt++ {
		if attempt > 0 {
			if err := e.sleep(ctx, retryBackoff); err != nil {
				return err // ctx cancelled
			}
		}
		attemptCtx, cancel := context.WithTimeout(ctx, e.timeout)
		err := send(attemptCtx, e.client, e.now, ch, ev)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		if isPermanent(err) {
			return err
		}
	}
	return lastErr
}

// isPermanent reports whether a delivery error can never succeed on retry.
func isPermanent(err error) bool {
	return errors.Is(err, errPermanent) || errors.Is(err, ErrInsecureScheme)
}

// Test delivers a synthetic test alert to a single channel, bypassing dedup and
// subscription filters (the admin "send test" action, DESIGN.md §11). It is
// synchronous so the admin API can report success/failure directly.
func (e *Engine) Test(ctx context.Context, ch model.NotifyChannel) error {
	ev := model.NotifyEvent{
		Kind:    model.EventStartupBindWarning, // benign kind; only Message is shown
		Message: "poolgate notification test — if you can read this, the channel works.",
		At:      e.now(),
	}
	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	return send(ctx, e.client, e.now, ch, ev)
}

// realSleep waits d or until ctx is cancelled.
func realSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
