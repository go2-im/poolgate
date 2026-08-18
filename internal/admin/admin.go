// Package admin is poolgate's loopback admin HTTP API (DESIGN.md §3 / §16 /
// §22). It is a JSON-only backend — there is no server-rendered UI here; a React
// frontend (later phase) is served as static assets and talks to these routes.
// The admin listener is separate from the proxy listener and is expected to bind
// loopback only.
//
// Everything the package needs is expressed as small interfaces (Store,
// SessionManager, Ceremonies) so the HTTP surface is unit-tested against fakes
// with an injectable clock; *store.Store, *adminauth.Manager and
// *webauthnsvc.Service satisfy them in production (see admin_wiring_test.go).
//
// Cross-cutting behavior lives in middleware (see middleware.go): strict
// security headers + CSP on every response, same-origin CORS, a session-auth
// guard on everything except the auth/bootstrap endpoints, a CSRF check on
// state-changing methods, and anti-brute-force rate-limit + lockout on the
// login / recovery / bootstrap paths.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/go2-im/poolgate/internal/config"
	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/store"
	"github.com/go2-im/poolgate/internal/webauthnsvc"
)

// SessionCookieName is the admin session cookie. It is HttpOnly + SameSite=Strict
// and Secure whenever the resolved admin origin is https.
const SessionCookieName = "pg_admin_session"

// CSRFHeaderName is the header carrying the CSRF token on state-changing requests.
const CSRFHeaderName = "X-CSRF-Token"

// Store is the persistence surface the admin API needs. *store.Store satisfies it.
type Store interface {
	// accounts
	InsertAccount(ctx context.Context, a model.Account) (model.Account, error)
	InsertAccountUnique(ctx context.Context, a model.Account) (model.Account, error)
	GetAccount(ctx context.Context, id string) (model.Account, error)
	ListAccounts(ctx context.Context) ([]model.Account, error)
	DeleteAccount(ctx context.Context, id string) error
	UpdateAccountMeta(ctx context.Context, id, label string, concurrencyCap int) error
	// api keys
	InsertApiKey(ctx context.Context, k model.ApiKey) (model.ApiKey, error)
	ListApiKeys(ctx context.Context) ([]model.ApiKey, error)
	GetApiKeyByID(ctx context.Context, id string) (model.ApiKey, error)
	RotateApiKey(ctx context.Context, id, newKey string) (model.ApiKey, error)
	DeleteApiKey(ctx context.Context, id string) error
	// endpoints
	InsertEndpoint(ctx context.Context, e model.Endpoint) (model.Endpoint, error)
	GetEndpoint(ctx context.Context, name string) (model.Endpoint, error)
	ListEndpoints(ctx context.Context) ([]model.Endpoint, error)
	DeleteEndpoint(ctx context.Context, name string) error
	// policy groups
	InsertPolicyGroup(ctx context.Context, g model.PolicyGroup) (model.PolicyGroup, error)
	GetPolicyGroup(ctx context.Context, id string) (model.PolicyGroup, error)
	ListPolicyGroups(ctx context.Context) ([]model.PolicyGroup, error)
	UpdatePolicyGroup(ctx context.Context, g model.PolicyGroup) error
	DeletePolicyGroup(ctx context.Context, id string) error
	// usage / health / status
	GetLatestUsage(ctx context.Context, accountID string) (model.UsageSnapshot, error)
	ListHealthChecks(ctx context.Context, accountID string, limit int) ([]model.HealthCheck, error)
	SchemaVersion(ctx context.Context) (int, error)
	// notify channels
	InsertNotifyChannel(ctx context.Context, ch model.NotifyChannel) (model.NotifyChannel, error)
	GetNotifyChannel(ctx context.Context, id string) (model.NotifyChannel, error)
	ListNotifyChannels(ctx context.Context) ([]model.NotifyChannel, error)
	UpdateNotifyChannel(ctx context.Context, ch model.NotifyChannel) error
	DeleteNotifyChannel(ctx context.Context, id string) error
	// request logs (real-time monitor, DESIGN.md §15)
	ListRequestLogs(ctx context.Context, f model.RequestLogFilter, limit, offset int) ([]model.RequestLog, error)
	CountRequestLogs(ctx context.Context, f model.RequestLogFilter) (store.RequestCounters, error)
	// audit log (append-only, DESIGN.md §22)
	InsertAuditEntry(ctx context.Context, e model.AuditEntry) error
	ListAuditEntries(ctx context.Context, limit, offset int) ([]model.AuditEntry, error)
	VerifyAuditChain(ctx context.Context) (valid bool, count int, brokenID string, err error)
}

// Notifier is the optional notification surface used by the channel "send test"
// action (DESIGN.md §11). *notify.Engine satisfies it. When no Notifier is wired,
// the test endpoint returns 503.
type Notifier interface {
	Test(ctx context.Context, ch model.NotifyChannel) error
}

// MonitorStream is the optional live request-log feed for the SSE monitor
// endpoint (DESIGN.md §15). *monitor.Engine satisfies it. Subscribe returns a
// filtered receive channel plus a cancel func the handler calls on disconnect.
// When unset, GET /admin/api/monitor/stream returns 503.
type MonitorStream interface {
	Subscribe(f model.RequestLogFilter) (<-chan model.RequestLog, func())
}

// ClockSkewSource optionally reports the most recently measured host↔upstream
// clock skew (DESIGN.md §21.4) for the status endpoint. *health.Engine satisfies
// it. When unset, GET /admin/api/status simply omits the clock-skew fields.
type ClockSkewSource interface {
	ClockSkew() (skew time.Duration, at time.Time, ok bool)
}

// SessionManager is the admin-auth surface for sessions, CSRF and recovery
// codes. *adminauth.Manager satisfies it.
type SessionManager interface {
	CreateSession(ctx context.Context) (model.Session, error)
	ValidateSession(ctx context.Context, id string) (model.Session, error)
	RotateSession(ctx context.Context, oldID string) (model.Session, error)
	RevokeSession(ctx context.Context, id string) error
	RevokeAllSessions(ctx context.Context) (int64, error)
	IssueCSRF(sessionID string) (string, error)
	VerifyCSRF(sessionID, token string) bool
	VerifyRecoveryCode(ctx context.Context, code string) error
	GenerateRecoveryCodes(ctx context.Context, n int) ([]string, error)
}

// Ceremonies is the WebAuthn ceremony surface. *webauthnsvc.Service satisfies it.
type Ceremonies interface {
	BeginRegistration(ctx context.Context, gate webauthnsvc.RegisterGate) (*protocol.CredentialCreation, string, error)
	FinishRegistration(ctx context.Context, gate webauthnsvc.RegisterGate, challengeID string, body []byte) (model.WebAuthnCredential, bool, error)
	BeginLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error)
	FinishLogin(ctx context.Context, challengeID string, body []byte) (webauthn.User, error)
	// RPID returns the resolved WebAuthn Relying Party ID, surfaced read-only by
	// the settings endpoint so the operator can confirm the passkey scope.
	RPID() string
}

// Server wires the admin API. Construct with New; the zero value is not usable.
type Server struct {
	store    Store
	sessions SessionManager
	webauthn Ceremonies
	notifier Notifier
	monitor  MonitorStream
	skew     ClockSkewSource
	spa      http.Handler

	// oauthLogin drives the optional admin-UI "sign in with ChatGPT" account
	// import. When nil, the /admin/api/accounts/login/* endpoints return 503.
	// oauthMu guards oauthState, the single in-flight/most-recent login (the
	// loopback callback port is exclusive, so only one runs at a time).
	oauthLogin OAuthLogin
	oauthMu    sync.Mutex
	oauthState *oauthLoginState

	origin    string // canonical admin origin (scheme://host[:port]) for CORS
	extOrigin string // configured external_origin (may be empty when synthesized)
	proxyBase string // configured proxy base URL (http://host:port), a hint for the client-config generator
	secure    bool   // set the Secure cookie flag (origin is https)
	now       func() time.Time
	logger    *slog.Logger
	limiter   *limiter
	recovery  int // number of recovery codes minted with the first passkey

	// anti-brute-force tunables, applied to the limiter in New.
	limiterMaxFailures int
	limiterWindow      time.Duration
	limiterLockout     time.Duration

	// trustedProxies are reverse-proxy networks whose X-Forwarded-For is trusted
	// when resolving the client IP for the brute-force limiter key. Empty => the
	// direct peer address is used and X-Forwarded-For is ignored.
	trustedProxies []*net.IPNet
}

// Option customizes a Server.
type Option func(*Server)

// WithClock injects the time source (default time.Now, UTC), shared with the
// rate-limiter so lockouts are deterministic under test.
func WithClock(now func() time.Time) Option {
	return func(s *Server) {
		if now != nil {
			s.now = now
		}
	}
}

// WithRateLimit overrides the anti-brute-force parameters (max failures within
// the window before a lockout, and the lockout duration).
func WithRateLimit(maxFailures int, window, lockout time.Duration) Option {
	return func(s *Server) {
		if maxFailures > 0 {
			s.limiterMaxFailures = maxFailures
		}
		if window > 0 {
			s.limiterWindow = window
		}
		if lockout > 0 {
			s.limiterLockout = lockout
		}
	}
}

// WithTrustedProxies sets the reverse-proxy networks whose X-Forwarded-For is
// trusted when resolving the client IP for the brute-force limiter. Empty (the
// default) ignores X-Forwarded-For and keys the limiter on the direct peer.
func WithTrustedProxies(nets []*net.IPNet) Option {
	return func(s *Server) { s.trustedProxies = nets }
}

// WithRecoveryCodeCount overrides how many one-time recovery codes are minted and
// returned (once) when the first passkey is registered. 0 keeps the default.
func WithRecoveryCodeCount(n int) Option {
	return func(s *Server) {
		if n >= 0 {
			s.recovery = n
		}
	}
}

// WithNotifier wires the optional notification surface used by the channel "send
// test" action. When unset, POST …/notify/channels/{id}/test returns 503.
func WithNotifier(n Notifier) Option {
	return func(s *Server) { s.notifier = n }
}

// WithMonitor wires the optional live request-log feed for the SSE monitor
// endpoint. When unset, GET …/monitor/stream returns 503 (history + counters
// still work directly from the store).
func WithMonitor(m MonitorStream) Option {
	return func(s *Server) { s.monitor = m }
}

// WithClockSkew wires the optional clock-skew reporter surfaced by the status
// endpoint (DESIGN.md §21.4). When unset, the status response omits the skew
// fields.
func WithClockSkew(src ClockSkewSource) Option {
	return func(s *Server) { s.skew = src }
}

// WithOAuthLogin wires the optional interactive OAuth login used by the admin-UI
// "sign in with ChatGPT" account import. When unset, POST/GET
// /admin/api/accounts/login/* return 503.
func WithOAuthLogin(l OAuthLogin) Option {
	return func(s *Server) {
		if l != nil {
			s.oauthLogin = l
		}
	}
}

// WithLogger injects the structured logger (default slog.Default()). It is used
// only for best-effort diagnostics such as a failed audit-log write; it never
// carries request bodies or secrets.
func WithLogger(l *slog.Logger) Option {
	return func(s *Server) {
		if l != nil {
			s.logger = l
		}
	}
}

// WithSPA mounts the embedded admin single-page app (DESIGN.md §9 phase 4) as an
// UNAUTHENTICATED catch-all so the login UI loads before a session exists. When
// unset, non-API routes 404 (headless / API-only deployments). The handler must
// itself refuse the /admin/ namespace.
func WithSPA(h http.Handler) Option {
	return func(s *Server) { s.spa = h }
}

// New builds a Server. All three collaborators must be non-nil. The admin origin
// is resolved once from the static admin listener config (never per-request) and
// used for same-origin CORS and the cookie Secure flag.
func New(cfg model.Config, st Store, sessions SessionManager, wa Ceremonies, opts ...Option) (*Server, error) {
	if st == nil || sessions == nil || wa == nil {
		return nil, errors.New("admin: nil dependency")
	}
	origin, secure, err := resolveOrigin(cfg.Server.Admin)
	if err != nil {
		return nil, err
	}
	s := &Server{
		store:     st,
		sessions:  sessions,
		webauthn:  wa,
		origin:    origin,
		extOrigin: strings.TrimSpace(cfg.Server.Admin.ExternalOrigin),
		proxyBase: proxyBaseURL(cfg.Server.Proxy),
		secure:    secure,
		now:       func() time.Time { return time.Now().UTC() },
		logger:    slog.Default(),
		recovery:  defaultRecoveryCodes,
	}
	s.limiterMaxFailures = defaultMaxFailures
	s.limiterWindow = defaultBruteWindow
	s.limiterLockout = defaultLockout
	for _, opt := range opts {
		opt(s)
	}
	s.limiter = newLimiter(s.limiterMaxFailures, s.limiterWindow, s.limiterLockout, s.now)
	return s, nil
}

// Origin returns the resolved canonical admin origin.
func (s *Server) Origin() string { return s.origin }

// Handler builds the admin router with all middleware applied. The returned
// handler sets strict security headers + CSP on every response and enforces
// same-origin CORS around the route mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.routes(mux)
	return securityHeaders(s.cors(mux))
}

// routes registers every admin route on mux. Public auth/bootstrap endpoints are
// registered directly; resource endpoints are wrapped by the session guard
// (which also enforces CSRF on state-changing methods).
func (s *Server) routes(mux *http.ServeMux) {
	// ---- auth / bootstrap (public: no session guard) ----
	mux.HandleFunc("POST /admin/register/begin", s.brute("register", s.handleRegisterBegin))
	mux.HandleFunc("POST /admin/register/finish", s.brute("register", s.handleRegisterFinish))
	mux.HandleFunc("POST /admin/login/begin", s.brute("login", s.handleLoginBegin))
	mux.HandleFunc("POST /admin/login/finish", s.brute("login", s.handleLoginFinish))
	mux.HandleFunc("POST /admin/login/recovery", s.brute("recovery", s.handleLoginRecovery))

	// ---- session-scoped auth actions (guarded) ----
	mux.HandleFunc("POST /admin/logout", s.guard(s.handleLogout))
	mux.HandleFunc("POST /admin/sessions/revoke-all", s.guard(s.handleRevokeAll))
	mux.HandleFunc("GET /admin/csrf", s.guard(s.handleCSRF))
	mux.HandleFunc("GET /admin/me", s.guard(s.handleMe))

	// ---- resources (guarded) ----
	mux.HandleFunc("POST /admin/api/accounts/import", s.guard(s.handleAccountImport))
	mux.HandleFunc("POST /admin/api/accounts/login/begin", s.guard(s.handleAccountLoginBegin))
	mux.HandleFunc("GET /admin/api/accounts/login/status", s.guard(s.handleAccountLoginStatus))
	mux.HandleFunc("GET /admin/api/accounts", s.guard(s.handleAccountsList))
	mux.HandleFunc("GET /admin/api/accounts/{id}", s.guard(s.handleAccountGet))
	mux.HandleFunc("PATCH /admin/api/accounts/{id}", s.guard(s.handleAccountPatch))
	mux.HandleFunc("DELETE /admin/api/accounts/{id}", s.guard(s.handleAccountDelete))

	mux.HandleFunc("GET /admin/api/api_keys", s.guard(s.handleApiKeysList))
	mux.HandleFunc("POST /admin/api/api_keys", s.guard(s.handleApiKeyCreate))
	mux.HandleFunc("POST /admin/api/api_keys/{id}/rotate", s.guard(s.handleApiKeyRotate))
	mux.HandleFunc("DELETE /admin/api/api_keys/{id}", s.guard(s.handleApiKeyDelete))

	mux.HandleFunc("GET /admin/api/endpoints", s.guard(s.handleEndpointsList))
	mux.HandleFunc("POST /admin/api/endpoints", s.guard(s.handleEndpointCreate))
	mux.HandleFunc("DELETE /admin/api/endpoints/{name}", s.guard(s.handleEndpointDelete))

	mux.HandleFunc("GET /admin/api/policy_groups", s.guard(s.handlePolicyGroupsList))
	mux.HandleFunc("POST /admin/api/policy_groups", s.guard(s.handlePolicyGroupCreate))
	mux.HandleFunc("PATCH /admin/api/policy_groups/{id}", s.guard(s.handlePolicyGroupPatch))
	mux.HandleFunc("DELETE /admin/api/policy_groups/{id}", s.guard(s.handlePolicyGroupDelete))

	mux.HandleFunc("GET /admin/api/usage", s.guard(s.handleUsage))
	mux.HandleFunc("GET /admin/api/health", s.guard(s.handleHealth))
	mux.HandleFunc("GET /admin/api/status", s.guard(s.handleStatus))
	mux.HandleFunc("GET /admin/api/settings", s.guard(s.handleSettings))

	mux.HandleFunc("GET /admin/api/notify/channels", s.guard(s.handleNotifyChannelsList))
	mux.HandleFunc("POST /admin/api/notify/channels", s.guard(s.handleNotifyChannelCreate))
	mux.HandleFunc("GET /admin/api/notify/channels/{id}", s.guard(s.handleNotifyChannelGet))
	mux.HandleFunc("PATCH /admin/api/notify/channels/{id}", s.guard(s.handleNotifyChannelPatch))
	mux.HandleFunc("DELETE /admin/api/notify/channels/{id}", s.guard(s.handleNotifyChannelDelete))
	mux.HandleFunc("POST /admin/api/notify/channels/{id}/test", s.guard(s.handleNotifyChannelTest))

	mux.HandleFunc("GET /admin/api/monitor/logs", s.guard(s.handleMonitorLogs))
	mux.HandleFunc("GET /admin/api/monitor/counters", s.guard(s.handleMonitorCounters))
	mux.HandleFunc("GET /admin/api/monitor/stream", s.guard(s.handleMonitorStream))

	mux.HandleFunc("GET /admin/api/audit", s.guard(s.handleAuditList))
	mux.HandleFunc("GET /admin/api/audit/verify", s.guard(s.handleAuditVerify))

	// Embedded SPA (unauthenticated catch-all): serves the admin UI + assets and
	// falls back to index.html for client-side routes. Registered last / most
	// general; the specific /admin/... patterns above take precedence, and the
	// handler itself refuses the /admin/ namespace.
	if s.spa != nil {
		mux.Handle("GET /", s.spa)
	}
}

// ---- origin resolution ----------------------------------------------------

// resolveOrigin derives the canonical admin origin from the static admin
// listener config: external_origin wins; otherwise a loopback http origin is
// synthesized from Host:Port. It never consults request headers (DESIGN.md §0
// fixes). secure reports whether the scheme is https (drives the cookie flag).
func resolveOrigin(admin model.ListenConfig) (origin string, secure bool, err error) {
	origin = config.SynthesizeAdminOrigin(admin)
	u, perr := url.Parse(origin)
	if perr != nil || u.Scheme == "" || u.Host == "" {
		return "", false, fmt.Errorf("admin: invalid admin origin %q", origin)
	}
	return origin, u.Scheme == "https", nil
}

// proxyBaseURL synthesizes the proxy listener's base URL (always http — the
// proxy listener is plain, TLS is expected to be terminated by a front proxy) as
// a starting hint for the client-config generator. It is not authoritative: when
// poolgate is fronted, the operator edits it to their external hostname.
func proxyBaseURL(proxy model.ListenConfig) string {
	host := strings.TrimSpace(proxy.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	port := proxy.Port
	if port == 0 {
		port = 8787
	}
	return fmt.Sprintf("http://%s:%d", host, port)
}

// ---- JSON + error helpers -------------------------------------------------

// apiError is poolgate's OpenAI-compatible error envelope (DESIGN.md §19.4).
type apiError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code,omitempty"`
	Param   string `json:"param,omitempty"`
}

const (
	errUnauthorized = "poolgate_unauthorized"
	errForbidden    = "poolgate_forbidden"
	errNotFound     = "poolgate_not_found"
	errBadRequest   = "poolgate_bad_request"
	errConflict     = "poolgate_conflict"
	errRateLimited  = "poolgate_rate_limited"
	errInternal     = "poolgate_internal"
)

// writeJSON writes v as an indented JSON body with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

// writeErr writes the error envelope with the given status/type/message.
func writeErr(w http.ResponseWriter, status int, typ, msg string) {
	writeJSON(w, status, map[string]apiError{"error": {Message: msg, Type: typ}})
}

// decodeJSON strictly decodes the request body into dst, rejecting unknown
// fields and trailing data. It caps the body to guard against abuse.
func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	// Reject any trailing tokens after the first JSON value.
	if dec.More() {
		return errors.New("admin: unexpected trailing JSON")
	}
	return nil
}
