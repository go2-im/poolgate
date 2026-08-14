// notify.go implements the session-guarded notification-channel routes
// (DESIGN.md §11): channel list/get/create/patch/delete plus a "send test"
// action. Channel Config carries secrets (webhook URL, signing secret) and is
// therefore NEVER serialized back to the client — the API returns only a
// secret-free projection (type/name/enabled/events/thresholds/timestamps).
// Secrets are write-only: supplied on create/patch, stored field-encrypted, and
// never read back.
package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go2-im/poolgate/internal/model"
)

// notifyChannelView is the secret-free projection of a channel. It deliberately
// omits Config (URL / signing secret) entirely.
type notifyChannelView struct {
	ID           string                  `json:"id"`
	Type         model.NotifyChannelType `json:"type"`
	Name         string                  `json:"name"`
	Enabled      bool                    `json:"enabled"`
	Events       []model.NotifyEventKind `json:"events"`
	MinHeadroom  float64                 `json:"min_headroom"`
	DedupSeconds int                     `json:"dedup_seconds"`
	CreatedAt    string                  `json:"created_at"`
	UpdatedAt    string                  `json:"updated_at"`
}

func toNotifyChannelView(ch model.NotifyChannel) notifyChannelView {
	events := ch.Events
	if events == nil {
		events = []model.NotifyEventKind{}
	}
	return notifyChannelView{
		ID:           ch.ID,
		Type:         ch.Type,
		Name:         ch.Name,
		Enabled:      ch.Enabled,
		Events:       events,
		MinHeadroom:  ch.MinHeadroom,
		DedupSeconds: ch.DedupSeconds,
		CreatedAt:    ch.CreatedAt.Format(rfc3339),
		UpdatedAt:    ch.UpdatedAt.Format(rfc3339),
	}
}

// notifyConfigReq is the secret-carrying config sub-object on create/patch.
type notifyConfigReq struct {
	URL      string            `json:"url"`
	Secret   string            `json:"secret"`
	Method   string            `json:"method"`
	Headers  map[string]string `json:"headers"`
	Template string            `json:"template"`
}

func (c notifyConfigReq) toModel() model.NotifyConfig {
	return model.NotifyConfig{
		URL:      c.URL,
		Secret:   c.Secret,
		Method:   c.Method,
		Headers:  c.Headers,
		Template: c.Template,
	}
}

// notifyChannelCreateReq is the body of POST /admin/api/notify/channels.
type notifyChannelCreateReq struct {
	Type         model.NotifyChannelType `json:"type"`
	Name         string                  `json:"name"`
	Enabled      *bool                   `json:"enabled"`
	Events       []model.NotifyEventKind `json:"events"`
	MinHeadroom  float64                 `json:"min_headroom"`
	DedupSeconds int                     `json:"dedup_seconds"`
	Config       notifyConfigReq         `json:"config"`
}

// notifyChannelPatchReq is the body of PATCH /admin/api/notify/channels/{id}. All
// fields are optional; a nil pointer leaves that attribute unchanged. Config, when
// present, replaces the stored config wholesale (it carries the secrets).
type notifyChannelPatchReq struct {
	Name         *string                  `json:"name"`
	Enabled      *bool                    `json:"enabled"`
	Events       *[]model.NotifyEventKind `json:"events"`
	MinHeadroom  *float64                 `json:"min_headroom"`
	DedupSeconds *int                     `json:"dedup_seconds"`
	Config       *notifyConfigReq         `json:"config"`
}

// handleNotifyChannelsList returns every configured channel (secret-free).
func (s *Server) handleNotifyChannelsList(w http.ResponseWriter, r *http.Request) {
	channels, err := s.store.ListNotifyChannels(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not list notify channels")
		return
	}
	views := make([]notifyChannelView, 0, len(channels))
	for _, ch := range channels {
		views = append(views, toNotifyChannelView(ch))
	}
	writeJSON(w, http.StatusOK, map[string]any{"channels": views})
}

// handleNotifyChannelGet returns one channel by id (secret-free).
func (s *Server) handleNotifyChannelGet(w http.ResponseWriter, r *http.Request) {
	ch, err := s.store.GetNotifyChannel(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "notify channel")
		return
	}
	writeJSON(w, http.StatusOK, toNotifyChannelView(ch))
}

// handleNotifyChannelCreate validates and stores a new channel. The config
// (including secrets) is field-encrypted by the store; the response is secret-free.
func (s *Server) handleNotifyChannelCreate(w http.ResponseWriter, r *http.Request) {
	var req notifyChannelCreateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid request body")
		return
	}
	if !req.Type.Valid() {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid channel type")
		return
	}
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, errBadRequest, "name is required")
		return
	}
	if err := validateNotifyConfig(req.Config); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, err.Error())
		return
	}
	if !validEventKinds(req.Events) {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid event kind")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if req.Events == nil {
		req.Events = []model.NotifyEventKind{}
	}
	created, err := s.store.InsertNotifyChannel(r.Context(), model.NotifyChannel{
		Type:         req.Type,
		Name:         req.Name,
		Enabled:      enabled,
		Events:       req.Events,
		MinHeadroom:  req.MinHeadroom,
		DedupSeconds: req.DedupSeconds,
		Config:       req.Config.toModel(),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not store notify channel")
		return
	}
	writeJSON(w, http.StatusCreated, toNotifyChannelView(created))
}

// handleNotifyChannelPatch updates a channel's mutable attributes and/or config.
func (s *Server) handleNotifyChannelPatch(w http.ResponseWriter, r *http.Request) {
	var req notifyChannelPatchReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid request body")
		return
	}
	ch, err := s.store.GetNotifyChannel(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "notify channel")
		return
	}
	if req.Name != nil {
		ch.Name = *req.Name
	}
	if req.Enabled != nil {
		ch.Enabled = *req.Enabled
	}
	if req.Events != nil {
		if !validEventKinds(*req.Events) {
			writeErr(w, http.StatusBadRequest, errBadRequest, "invalid event kind")
			return
		}
		ch.Events = *req.Events
	}
	if req.MinHeadroom != nil {
		ch.MinHeadroom = *req.MinHeadroom
	}
	if req.DedupSeconds != nil {
		ch.DedupSeconds = *req.DedupSeconds
	}
	if req.Config != nil {
		if err := validateNotifyConfig(*req.Config); err != nil {
			writeErr(w, http.StatusBadRequest, errBadRequest, err.Error())
			return
		}
		ch.Config = req.Config.toModel()
	}
	if err := s.store.UpdateNotifyChannel(r.Context(), ch); err != nil {
		s.writeStoreErr(w, err, "notify channel")
		return
	}
	writeJSON(w, http.StatusOK, toNotifyChannelView(ch))
}

// handleNotifyChannelDelete removes one channel by id.
func (s *Server) handleNotifyChannelDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteNotifyChannel(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreErr(w, err, "notify channel")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// handleNotifyChannelTest sends a synthetic alert to one channel to verify it is
// configured correctly. Requires a wired Notifier (503 otherwise). A delivery
// failure maps to 502 with a secret-free message.
func (s *Server) handleNotifyChannelTest(w http.ResponseWriter, r *http.Request) {
	if s.notifier == nil {
		writeErr(w, http.StatusServiceUnavailable, errInternal, "notifications are not enabled")
		return
	}
	ch, err := s.store.GetNotifyChannel(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "notify channel")
		return
	}
	if err := s.notifier.Test(r.Context(), ch); err != nil {
		writeErr(w, http.StatusBadGateway, errInternal, "test delivery failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// validateNotifyConfig enforces the HTTPS-only rule at the API boundary (the SSRF
// guard re-enforces it, plus the IP policy, at send time).
func validateNotifyConfig(c notifyConfigReq) error {
	return validateHTTPSURL(c.URL)
}

// validateHTTPSURL requires a well-formed https URL with a host. This is the
// cheap boundary gate; internal/notify's SSRF guard additionally blocks
// private/loopback/metadata IPs at connect time.
func validateHTTPSURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("config.url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("config.url is not a valid URL")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("config.url must use https")
	}
	if u.Host == "" {
		return fmt.Errorf("config.url has no host")
	}
	return nil
}

// validEventKinds reports whether every kind in the list is recognized. An empty
// list is valid (subscribe to all).
func validEventKinds(kinds []model.NotifyEventKind) bool {
	for _, k := range kinds {
		if !k.Valid() {
			return false
		}
	}
	return true
}
