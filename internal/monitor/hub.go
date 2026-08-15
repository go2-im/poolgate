// hub.go is the monitor's in-process publish/subscribe fan-out for the live SSE
// stream (DESIGN.md §15). Each subscriber carries its own RequestLogFilter (the
// same predicate the SQL history query uses), so a filtered live view and a
// filtered history view agree. Publish is NON-BLOCKING: a subscriber whose
// buffer is full drops the event rather than stalling the proxy hot path.
package monitor

import (
	"sync"

	"github.com/go2-im/poolgate/internal/model"
)

// subBuffer bounds how many pending events a single slow subscriber may hold
// before new events are dropped for it.
const subBuffer = 64

// Subscription is a live request-log feed for one SSE client.
type Subscription struct {
	C      <-chan model.RequestLog
	ch     chan model.RequestLog
	filter model.RequestLogFilter
	id     uint64
}

// Hub fans out request logs to the set of current subscribers. Safe for
// concurrent Subscribe / Unsubscribe / Publish.
type Hub struct {
	mu   sync.Mutex
	subs map[uint64]*Subscription
	seq  uint64
}

// NewHub returns an empty Hub.
func NewHub() *Hub {
	return &Hub{subs: make(map[uint64]*Subscription)}
}

// Subscribe registers a filtered feed and returns its Subscription. The caller
// MUST Unsubscribe when done (e.g. on client disconnect) to free the slot.
func (h *Hub) Subscribe(filter model.RequestLogFilter) *Subscription {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq++
	ch := make(chan model.RequestLog, subBuffer)
	s := &Subscription{C: ch, ch: ch, filter: filter, id: h.seq}
	h.subs[s.id] = s
	return s
}

// Unsubscribe removes a subscription. Idempotent.
func (h *Hub) Unsubscribe(s *Subscription) {
	if s == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.subs, s.id)
}

// Publish delivers a log to every subscriber whose filter matches, without
// blocking: a full subscriber buffer drops the event for that subscriber only.
func (h *Hub) Publish(l model.RequestLog) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.subs {
		if !s.filter.Matches(l) {
			continue
		}
		select {
		case s.ch <- l:
		default:
			// Slow subscriber: drop this event for it (live view is best-effort;
			// the SQL history is the durable record).
		}
	}
}

// subscriberCount reports the current number of subscribers (for tests/metrics).
func (h *Hub) subscriberCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}
