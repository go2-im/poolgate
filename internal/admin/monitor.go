// monitor.go implements the session-guarded real-time monitor routes (DESIGN.md
// §15 / §24.1): a filtered request-log history, headline counters, and a live SSE
// stream. Records are secret-free (built by the gateway), and the client-supplied
// filter facets are parsed defensively. The live filter uses the SAME predicate
// as the history query so the two views agree.
package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// parseLogFilter reads the monitor filter facets from the query string. Unknown
// or malformed values are ignored (treated as "no filter" for that facet).
func parseLogFilter(r *http.Request) model.RequestLogFilter {
	q := r.URL.Query()
	f := model.RequestLogFilter{
		SessionID: model.SanitizeField(q.Get("session")),
		APIKeyID:  model.SanitizeField(q.Get("api_key")),
		Model:     model.SanitizeField(q.Get("model")),
		Endpoint:  model.SanitizeField(q.Get("endpoint")),
		AccountID: model.SanitizeField(q.Get("account")),
	}
	if s := q.Get("status"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			f.Status = n
		}
	}
	if s := q.Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			f.Since = t.UTC()
		}
	}
	if s := q.Get("until"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			f.Until = t.UTC()
		}
	}
	return f
}

// handleMonitorLogs returns a filtered, paginated slice of request-log history.
func (s *Server) handleMonitorLogs(w http.ResponseWriter, r *http.Request) {
	f := parseLogFilter(r)
	q := r.URL.Query()
	limit, offset := 100, 0
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			offset = n
		}
	}
	logs, err := s.store.ListRequestLogs(r.Context(), f, limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not read request logs")
		return
	}
	if logs == nil {
		logs = []model.RequestLog{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs})
}

// handleMonitorCounters returns the 3–4 headline counters for the filtered window.
func (s *Server) handleMonitorCounters(w http.ResponseWriter, r *http.Request) {
	f := parseLogFilter(r)
	c, err := s.store.CountRequestLogs(r.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not read counters")
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// handleMonitorStream is the live SSE feed of new request records matching the
// filter. It requires a wired MonitorStream (503 otherwise). It writes an initial
// comment, then one `data:` event per record, plus periodic keep-alive comments
// so idle connections survive proxies. It returns when the client disconnects.
func (s *Server) handleMonitorStream(w http.ResponseWriter, r *http.Request) {
	if s.monitor == nil {
		writeErr(w, http.StatusServiceUnavailable, errInternal, "live monitor is not enabled")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, errInternal, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	events, cancel := s.monitor.Subscribe(parseLogFilter(r))
	defer cancel()

	// A bounded write deadline ensures a client that stops reading but holds the
	// socket open cannot wedge this goroutine in a blocking Write forever (which
	// would leak the goroutine + Hub subscription): a stalled write errors, the
	// handler returns, and defer cancel() unsubscribes. Best-effort — ignored if
	// the ResponseWriter does not support deadlines.
	rc := http.NewResponseController(w)
	writeFrame := func(b []byte) error {
		_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, err := w.Write(b)
		return err
	}

	// Initial comment opens the stream immediately.
	if err := writeFrame([]byte(": connected\n\n")); err != nil {
		return
	}
	flusher.Flush()

	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			if err := writeFrame([]byte(": ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case l, open := <-events:
			if !open {
				return
			}
			b, err := json.Marshal(l)
			if err != nil {
				continue
			}
			// The record is secret-free and sanitized (no newlines), so a single
			// data: line is safe SSE framing.
			if err := writeFrame(append([]byte("data: "), append(b, '\n', '\n')...)); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
