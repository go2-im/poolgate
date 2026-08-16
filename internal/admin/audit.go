// audit.go implements the append-only audit log surface (DESIGN.md §22): a
// helper the mutating handlers call to record a secret-free action, and a
// session-guarded read endpoint. Writes are best-effort — a failed audit insert
// must never fail the underlying action — but the entries themselves are
// immutable (the store exposes no update/delete).
package admin

import (
	"context"
	"net/http"
	"strconv"

	"github.com/go2-im/poolgate/internal/model"
)

// audit records one operator action. It is best-effort: an insert error is
// swallowed so auditing can never break the action being audited. Actor is
// always the operator (these are called from session-guarded handlers). target
// and detail must be secret-free (ids/labels/counts only).
func (s *Server) audit(ctx context.Context, action, target, detail string) {
	_ = s.store.InsertAuditEntry(ctx, model.AuditEntry{
		At:     s.now(),
		Actor:  model.AuditActorOperator,
		Action: action,
		Target: target,
		Detail: detail,
	})
}

// auditEntryView is the JSON projection of an audit entry.
type auditEntryView struct {
	ID     string `json:"id"`
	At     string `json:"at"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
	Detail string `json:"detail"`
}

// handleAuditList returns recent audit entries, newest-first, paginated via
// ?limit=&offset=.
func (s *Server) handleAuditList(w http.ResponseWriter, r *http.Request) {
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
	entries, err := s.store.ListAuditEntries(r.Context(), limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not read audit log")
		return
	}
	views := make([]auditEntryView, 0, len(entries))
	for _, e := range entries {
		views = append(views, auditEntryView{
			ID:     e.ID,
			At:     e.At.Format(rfc3339),
			Actor:  e.Actor,
			Action: e.Action,
			Target: e.Target,
			Detail: e.Detail,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": views})
}