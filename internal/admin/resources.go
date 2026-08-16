// resources.go implements the session-guarded resource routes (DESIGN.md §3 /
// §13): account import + list/get/delete, api-key list/create/delete, endpoint
// list/create/delete, policy-group list/create/patch/delete, and the read-only
// usage / health / status views. Secrets never cross this boundary: account
// tokens are never serialized, and an api key's secret is masked everywhere
// except the one-time create response (DESIGN.md §5 / §22).
package admin

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go2-im/poolgate/internal/authimport"
	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/store"
)

// accountView is the secret-free projection of an account returned by the API.
// It deliberately omits access_token / refresh_token / id_token.
type accountView struct {
	ID        string             `json:"id"`
	Label     string             `json:"label"`
	AccountID string             `json:"account_id"`
	State     model.AccountState `json:"state"`
	CreatedAt string             `json:"created_at"`
	UpdatedAt string             `json:"updated_at"`
}

func toAccountView(a model.Account) accountView {
	return accountView{
		ID:        a.ID,
		Label:     a.Label,
		AccountID: a.AccountID,
		State:     a.State,
		CreatedAt: a.CreatedAt.Format(rfc3339),
		UpdatedAt: a.UpdatedAt.Format(rfc3339),
	}
}

// rfc3339 is the timestamp format used in JSON responses.
const rfc3339 = "2006-01-02T15:04:05Z07:00"

// apiKeyView masks the secret; Key is populated (unmasked) only in the one-time
// create response.
type apiKeyView struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Endpoints   []string `json:"endpoints"`
	KeyMasked   string   `json:"key_masked"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
	IPAllowlist []string `json:"ip_allowlist"`
	Key         string   `json:"key,omitempty"`
}

func toApiKeyView(k model.ApiKey) apiKeyView {
	allow := k.IPAllowlist
	if allow == nil {
		allow = []string{}
	}
	v := apiKeyView{
		ID:          k.ID,
		Label:       k.Label,
		Endpoints:   k.Endpoints,
		KeyMasked:   maskKey(k.Key),
		IPAllowlist: allow,
	}
	if !k.ExpiresAt.IsZero() {
		v.ExpiresAt = k.ExpiresAt.Format(rfc3339)
	}
	return v
}

// maskKey shows only a short suffix of an sk- key, e.g. "sk-…a1b2".
func maskKey(key string) string {
	const tail = 4
	if len(key) <= tail {
		return "sk-…"
	}
	return "sk-…" + key[len(key)-tail:]
}

// ---- accounts -------------------------------------------------------------

// importReq is the body of POST /admin/api/accounts/import: either inline
// auth.json content or a path to it, plus an optional label.
type importReq struct {
	Content string `json:"content"`
	Path    string `json:"path"`
	Label   string `json:"label"`
}

// handleAccountImport imports a Codex auth.json (content or path) into the pool
// via internal/authimport + the store, returning the created account with NO
// secrets (DESIGN.md §17).
func (s *Server) handleAccountImport(w http.ResponseWriter, r *http.Request) {
	var req importReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid request body")
		return
	}
	if (req.Content == "") == (req.Path == "") {
		writeErr(w, http.StatusBadRequest, errBadRequest, "provide exactly one of content or path")
		return
	}
	var (
		acct model.Account
		err  error
	)
	if req.Content != "" {
		acct, err = authimport.Parse([]byte(req.Content))
	} else {
		acct, err = authimport.ParseFile(req.Path)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, "could not parse auth.json")
		return
	}
	acct.Label = req.Label
	created, err := s.store.InsertAccount(r.Context(), acct)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not store account")
		return
	}
	s.audit(r.Context(), "account.import", created.ID, "label="+created.Label)
	writeJSON(w, http.StatusCreated, toAccountView(created))
}

// handleAccountsList returns every pooled account (secret-free).
func (s *Server) handleAccountsList(w http.ResponseWriter, r *http.Request) {
	accts, err := s.store.ListAccounts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not list accounts")
		return
	}
	views := make([]accountView, 0, len(accts))
	for _, a := range accts {
		views = append(views, toAccountView(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": views})
}

// handleAccountGet returns one account by id (secret-free).
func (s *Server) handleAccountGet(w http.ResponseWriter, r *http.Request) {
	a, err := s.store.GetAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "account")
		return
	}
	writeJSON(w, http.StatusOK, toAccountView(a))
}

// handleAccountDelete removes one account by id.
func (s *Server) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteAccount(r.Context(), id); err != nil {
		s.writeStoreErr(w, err, "account")
		return
	}
	s.audit(r.Context(), "account.delete", id, "")
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// ---- api keys -------------------------------------------------------------

// apiKeyCreateReq is the body of POST /admin/api/api_keys.
type apiKeyCreateReq struct {
	Label     string   `json:"label"`
	Endpoints []string `json:"endpoints"`
	// ExpiresAt is an optional RFC3339 expiry; empty/omitted = never expires.
	ExpiresAt string `json:"expires_at"`
	// IPAllowlist is an optional list of IPs/CIDRs; empty = any IP.
	IPAllowlist []string `json:"ip_allowlist"`
}

// handleApiKeysList returns every inbound key with its secret masked.
func (s *Server) handleApiKeysList(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListApiKeys(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not list api keys")
		return
	}
	views := make([]apiKeyView, 0, len(keys))
	for _, k := range keys {
		views = append(views, toApiKeyView(k))
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_keys": views})
}

// handleApiKeyCreate mints a fresh sk- key, stores it, and returns the full
// secret exactly once (subsequent reads are masked). Optional expiry + IP
// allowlist are validated at the boundary.
func (s *Server) handleApiKeyCreate(w http.ResponseWriter, r *http.Request) {
	var req apiKeyCreateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid request body")
		return
	}
	expiresAt, err := parseOptionalExpiry(req.ExpiresAt)
	if err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, err.Error())
		return
	}
	if err := validateIPAllowlist(req.IPAllowlist); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, err.Error())
		return
	}
	secret, err := newSecretKey()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not generate key")
		return
	}
	if req.Endpoints == nil {
		req.Endpoints = []string{}
	}
	if req.IPAllowlist == nil {
		req.IPAllowlist = []string{}
	}
	created, err := s.store.InsertApiKey(r.Context(), model.ApiKey{
		Key: secret, Label: req.Label, Endpoints: req.Endpoints,
		ExpiresAt: expiresAt, IPAllowlist: req.IPAllowlist,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not store api key")
		return
	}
	view := toApiKeyView(created)
	view.Key = created.Key // shown once
	s.audit(r.Context(), "apikey.create", created.ID, "label="+created.Label)
	writeJSON(w, http.StatusCreated, view)
}

// handleApiKeyRotate mints a new secret for an existing key (same id/label/scope/
// expiry/allowlist) and returns it once. The old secret stops working.
func (s *Server) handleApiKeyRotate(w http.ResponseWriter, r *http.Request) {
	secret, err := newSecretKey()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not generate key")
		return
	}
	rotated, err := s.store.RotateApiKey(r.Context(), r.PathValue("id"), secret)
	if err != nil {
		s.writeStoreErr(w, err, "api key")
		return
	}
	view := toApiKeyView(rotated)
	view.Key = rotated.Key // shown once
	s.audit(r.Context(), "apikey.rotate", rotated.ID, "")
	writeJSON(w, http.StatusOK, view)
}

// parseOptionalExpiry parses an optional RFC3339 timestamp; "" = zero (never).
func parseOptionalExpiry(s string) (time.Time, error) {
	if strings.TrimSpace(s) == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("expires_at must be RFC3339 (e.g. 2027-01-02T15:04:05Z)")
	}
	return t.UTC(), nil
}

// validateIPAllowlist rejects malformed entries (each must be an IP or CIDR).
func validateIPAllowlist(entries []string) error {
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			return fmt.Errorf("ip_allowlist entries must be non-empty")
		}
		if strings.Contains(e, "/") {
			if _, _, err := net.ParseCIDR(e); err != nil {
				return fmt.Errorf("ip_allowlist entry %q is not a valid CIDR", e)
			}
			continue
		}
		if net.ParseIP(e) == nil {
			return fmt.Errorf("ip_allowlist entry %q is not a valid IP or CIDR", e)
		}
	}
	return nil
}

// handleApiKeyDelete removes one inbound key by id.
func (s *Server) handleApiKeyDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteApiKey(r.Context(), id); err != nil {
		s.writeStoreErr(w, err, "api key")
		return
	}
	s.audit(r.Context(), "apikey.delete", id, "")
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// newSecretKey returns a fresh "sk-<48 hex>" inbound key.
func newSecretKey() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "sk-" + hex.EncodeToString(buf), nil
}

// ---- endpoints ------------------------------------------------------------

// endpointCreateReq is the body of POST /admin/api/endpoints.
type endpointCreateReq struct {
	Name    string `json:"name"`
	GroupID string `json:"group_id"`
}

// handleEndpointsList returns every endpoint.
func (s *Server) handleEndpointsList(w http.ResponseWriter, r *http.Request) {
	eps, err := s.store.ListEndpoints(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not list endpoints")
		return
	}
	if eps == nil {
		eps = []model.Endpoint{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": eps})
}

// handleEndpointCreate binds a named route to a policy group.
func (s *Server) handleEndpointCreate(w http.ResponseWriter, r *http.Request) {
	var req endpointCreateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid request body")
		return
	}
	if req.Name == "" || req.GroupID == "" {
		writeErr(w, http.StatusBadRequest, errBadRequest, "name and group_id are required")
		return
	}
	ep, err := s.store.InsertEndpoint(r.Context(), model.Endpoint{Name: req.Name, GroupID: req.GroupID})
	if err != nil {
		// A bad group_id (FK) or duplicate name surfaces as a conflict.
		writeErr(w, http.StatusConflict, errConflict, "could not create endpoint (name in use or unknown group)")
		return
	}
	s.audit(r.Context(), "endpoint.create", ep.Name, "group="+ep.GroupID)
	writeJSON(w, http.StatusCreated, ep)
}

// handleEndpointDelete removes one endpoint by name.
func (s *Server) handleEndpointDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.store.DeleteEndpoint(r.Context(), name); err != nil {
		s.writeStoreErr(w, err, "endpoint")
		return
	}
	s.audit(r.Context(), "endpoint.delete", name, "")
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// ---- policy groups --------------------------------------------------------

// policyGroupCreateReq is the body of POST /admin/api/policy_groups.
type policyGroupCreateReq struct {
	Name             string         `json:"name"`
	Strategy         model.Strategy `json:"strategy"`
	MemberAccountIDs []string       `json:"member_account_ids"`
}

// policyGroupPatchReq is the body of PATCH /admin/api/policy_groups/{id}. Both
// fields are optional; a nil pointer leaves that attribute unchanged.
type policyGroupPatchReq struct {
	Strategy         *model.Strategy `json:"strategy"`
	MemberAccountIDs *[]string       `json:"member_account_ids"`
}

// handlePolicyGroupsList returns every policy group.
func (s *Server) handlePolicyGroupsList(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.ListPolicyGroups(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not list policy groups")
		return
	}
	if groups == nil {
		groups = []model.PolicyGroup{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy_groups": groups})
}

// handlePolicyGroupCreate creates a policy group after validating its strategy.
func (s *Server) handlePolicyGroupCreate(w http.ResponseWriter, r *http.Request) {
	var req policyGroupCreateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, errBadRequest, "name is required")
		return
	}
	if !validStrategy(req.Strategy) {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid strategy")
		return
	}
	if req.MemberAccountIDs == nil {
		req.MemberAccountIDs = []string{}
	}
	g, err := s.store.InsertPolicyGroup(r.Context(), model.PolicyGroup{
		Name: req.Name, Strategy: req.Strategy, MemberAccountIDs: req.MemberAccountIDs,
	})
	if err != nil {
		writeErr(w, http.StatusConflict, errConflict, "could not create policy group (name in use)")
		return
	}
	s.audit(r.Context(), "policygroup.create", g.ID, "name="+g.Name)
	writeJSON(w, http.StatusCreated, g)
}

// handlePolicyGroupPatch updates a policy group's strategy and/or members.
func (s *Server) handlePolicyGroupPatch(w http.ResponseWriter, r *http.Request) {
	var req policyGroupPatchReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, errBadRequest, "invalid request body")
		return
	}
	g, err := s.store.GetPolicyGroup(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "policy group")
		return
	}
	if req.Strategy != nil {
		if !validStrategy(*req.Strategy) {
			writeErr(w, http.StatusBadRequest, errBadRequest, "invalid strategy")
			return
		}
		g.Strategy = *req.Strategy
	}
	if req.MemberAccountIDs != nil {
		g.MemberAccountIDs = *req.MemberAccountIDs
	}
	if err := s.store.UpdatePolicyGroup(r.Context(), g); err != nil {
		s.writeStoreErr(w, err, "policy group")
		return
	}
	s.audit(r.Context(), "policygroup.update", g.ID, "")
	writeJSON(w, http.StatusOK, g)
}

// handlePolicyGroupDelete removes one policy group by id.
func (s *Server) handlePolicyGroupDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.store.DeletePolicyGroup(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, errNotFound, "policy group not found")
		return
	}
	if err != nil {
		// A referencing endpoint (FK RESTRICT) blocks deletion.
		writeErr(w, http.StatusConflict, errConflict, "policy group is still bound to an endpoint")
		return
	}
	s.audit(r.Context(), "policygroup.delete", id, "")
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// validStrategy reports whether st is one of the three v1 strategies.
func validStrategy(st model.Strategy) bool {
	switch st {
	case model.StrategyFallback, model.StrategyBestQuota, model.StrategyLoadBalance:
		return true
	default:
		return false
	}
}

// ---- usage / health / status ---------------------------------------------

// handleUsage returns the latest usage snapshot per account (secret-free).
func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	accts, err := s.store.ListAccounts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not read usage")
		return
	}
	type row struct {
		AccountID string              `json:"account_id"`
		PlanType  string              `json:"plan_type"`
		Windows   []model.UsageWindow `json:"windows"`
	}
	out := make([]row, 0, len(accts))
	for _, a := range accts {
		snap, err := s.store.GetLatestUsage(r.Context(), a.ID)
		if errors.Is(err, store.ErrNotFound) {
			out = append(out, row{AccountID: a.ID, Windows: []model.UsageWindow{}})
			continue
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, errInternal, "could not read usage")
			return
		}
		out = append(out, row{AccountID: a.ID, PlanType: snap.PlanType, Windows: snap.Windows})
	}
	writeJSON(w, http.StatusOK, map[string]any{"usage": out})
}

// handleHealth returns recent health-check history per account (secret-free).
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	accts, err := s.store.ListAccounts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not read health")
		return
	}
	type row struct {
		AccountID string              `json:"account_id"`
		State     model.AccountState  `json:"state"`
		Checks    []model.HealthCheck `json:"checks"`
	}
	out := make([]row, 0, len(accts))
	for _, a := range accts {
		checks, err := s.store.ListHealthChecks(r.Context(), a.ID, 10)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, errInternal, "could not read health")
			return
		}
		if checks == nil {
			checks = []model.HealthCheck{}
		}
		out = append(out, row{AccountID: a.ID, State: a.State, Checks: checks})
	}
	writeJSON(w, http.StatusOK, map[string]any{"health": out})
}

// handleStatus returns a compact system summary: schema version + counts. It
// leaks no secrets and no account ids.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	version, err := s.store.SchemaVersion(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not read status")
		return
	}
	accts, err := s.store.ListAccounts(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not read status")
		return
	}
	eps, err := s.store.ListEndpoints(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not read status")
		return
	}
	groups, err := s.store.ListPolicyGroups(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, errInternal, "could not read status")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": version,
		"accounts":       len(accts),
		"endpoints":      len(eps),
		"policy_groups":  len(groups),
	})
}

// handleSettings returns the read-only, server-authoritative admin origin +
// WebAuthn Relying Party ID so the Settings page can display the passkey scope
// (DESIGN.md §16). These are resolved ONCE at startup from static config (never
// from per-request headers), so the values shown are exactly what the login /
// registration ceremonies enforce. It leaks no secrets. external_origin is empty
// when the origin was synthesized from Host:Port rather than configured.
func (s *Server) handleSettings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"origin":          s.origin,
		"external_origin": s.extOrigin,
		"rp_id":           s.webauthn.RPID(),
		"secure":          s.secure,
	})
}

// writeStoreErr maps a store error to a not-found or internal response.
func (s *Server) writeStoreErr(w http.ResponseWriter, err error, what string) {
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, errNotFound, what+" not found")
		return
	}
	writeErr(w, http.StatusInternalServerError, errInternal, "storage error")
}
