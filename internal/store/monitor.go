// monitor.go adds request-log persistence + querying for the real-time monitor
// (DESIGN.md §15 / §24.1) over the request_logs table (migration v5). Rows are
// secret-free; the query surface filters in SQL on the monitor's facets
// (session / api-key / model + endpoint / account / status / time-range) with
// pagination, plus a headline-counter summary and a retention prune.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// InsertRequestLog appends one request record. If l.ID is empty a random id is
// generated; if At is zero it defaults to now. The stored record is returned.
func (s *Store) InsertRequestLog(ctx context.Context, l model.RequestLog) (model.RequestLog, error) {
	if l.ID == "" {
		l.ID = newID("req")
	}
	if l.At.IsZero() {
		l.At = time.Now().UTC()
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO request_logs
	(id, at, endpoint, policy, account_id, account_label, model, api_key_id, api_key_label,
	 session_id, status, latency_ms, tokens_in, tokens_out, trace, error_type)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		l.ID, formatTimeFixed(l.At), l.Endpoint, l.Policy, l.AccountID, l.AccountLabel, l.Model,
		l.APIKeyID, l.APIKeyLabel, l.SessionID, l.Status, l.LatencyMS, l.TokensIn, l.TokensOut,
		l.Trace, l.ErrorType,
	); err != nil {
		return model.RequestLog{}, fmt.Errorf("store: insert request log: %w", err)
	}
	return l, nil
}

// whereFromFilter builds the SQL WHERE clause + args for a RequestLogFilter.
func whereFromFilter(f model.RequestLogFilter) (string, []any) {
	var (
		clauses []string
		args    []any
	)
	add := func(col string, v any) { clauses = append(clauses, col+" = ?"); args = append(args, v) }
	if f.SessionID != "" {
		add("session_id", f.SessionID)
	}
	if f.APIKeyID != "" {
		add("api_key_id", f.APIKeyID)
	}
	if f.Model != "" {
		add("model", f.Model)
	}
	if f.Endpoint != "" {
		add("endpoint", f.Endpoint)
	}
	if f.AccountID != "" {
		add("account_id", f.AccountID)
	}
	if f.Status != 0 {
		add("status", f.Status)
	}
	if !f.Since.IsZero() {
		clauses = append(clauses, "at >= ?")
		args = append(args, formatTimeFixed(f.Since))
	}
	if !f.Until.IsZero() {
		clauses = append(clauses, "at < ?")
		args = append(args, formatTimeFixed(f.Until))
	}
	if len(clauses) == 0 {
		return "", nil
	}
	where := " WHERE " + clauses[0]
	for _, c := range clauses[1:] {
		where += " AND " + c
	}
	return where, args
}

// ListRequestLogs returns newest-first request logs matching the filter, paged by
// limit/offset (limit <= 0 defaults to 100, capped at 1000).
func (s *Store) ListRequestLogs(ctx context.Context, f model.RequestLogFilter, limit, offset int) ([]model.RequestLog, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}
	where, args := whereFromFilter(f)
	q := `SELECT id, at, endpoint, policy, account_id, account_label, model, api_key_id, api_key_label,
	session_id, status, latency_ms, tokens_in, tokens_out, trace, error_type
FROM request_logs` + where + ` ORDER BY at DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list request logs: %w", err)
	}
	defer rows.Close()

	var out []model.RequestLog
	for rows.Next() {
		var (
			l  model.RequestLog
			at string
		)
		if err := rows.Scan(&l.ID, &at, &l.Endpoint, &l.Policy, &l.AccountID, &l.AccountLabel,
			&l.Model, &l.APIKeyID, &l.APIKeyLabel, &l.SessionID, &l.Status, &l.LatencyMS,
			&l.TokensIn, &l.TokensOut, &l.Trace, &l.ErrorType); err != nil {
			return nil, fmt.Errorf("store: scan request log: %w", err)
		}
		l.At = parseTime(at)
		out = append(out, l)
	}
	return out, rows.Err()
}

// RequestCounters is the headline-counter summary over a filtered window
// (DESIGN.md §15: 3–4 counters).
type RequestCounters struct {
	Total     int `json:"total"`
	Success   int `json:"success"` // 2xx
	Error     int `json:"error"`   // non-2xx (incl. 0 = transport failure)
	TokensIn  int `json:"tokens_in"`
	TokensOut int `json:"tokens_out"`
}

// CountRequestLogs returns the headline counters for logs matching the filter.
func (s *Store) CountRequestLogs(ctx context.Context, f model.RequestLogFilter) (RequestCounters, error) {
	where, args := whereFromFilter(f)
	q := `SELECT
	COUNT(*),
	COALESCE(SUM(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END), 0),
	COALESCE(SUM(tokens_in), 0),
	COALESCE(SUM(tokens_out), 0)
FROM request_logs` + where
	var c RequestCounters
	if err := s.db.QueryRowContext(ctx, q, args...).Scan(&c.Total, &c.Success, &c.TokensIn, &c.TokensOut); err != nil {
		return RequestCounters{}, fmt.Errorf("store: count request logs: %w", err)
	}
	c.Error = c.Total - c.Success
	return c, nil
}

// PruneRequestLogs deletes request logs older than the cutoff, returning the
// number removed (DESIGN.md §15 retention).
func (s *Store) PruneRequestLogs(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM request_logs WHERE at < ?`, formatTimeFixed(before))
	if err != nil {
		return 0, fmt.Errorf("store: prune request logs: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: prune request logs rows: %w", err)
	}
	return n, nil
}
