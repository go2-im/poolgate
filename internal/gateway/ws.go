// ws.go implements the WebSocket transport for the /responses surface (DESIGN.md
// §0 D2/D3 / §19.1). Codex tries a WebSocket `/responses` upgrade before falling
// back to HTTP POST+SSE; poolgate accepts that upgrade and transparently proxies
// frames to the pinned upstream account.
//
// Turn affinity: a turn is pinned to one backend for the LIFETIME OF THE
// CONNECTION — poolgate selects one account per accepted WS connection and never
// switches it mid-connection. This is the correct realization of §19.1 because
// Codex continues a turn on the same connection (connection-scoped
// `previous_response_id`), and a dropped connection loses server-side turn state
// regardless. When the client also sends an `x-codex-turn-state` value as an
// upgrade header (older clients / intermediaries), that value additionally pins
// re-connections to the same backend via a short-TTL map; the current client
// carries turn-state inside WS messages, which poolgate deliberately does NOT
// parse (it stays a transport-level proxy, not an upstream-message parser).
//
// Failover is pre-first-frame, mirroring the HTTP pre-first-byte boundary
// (§19.2): poolgate dials the upstream WS for the selected account and only
// ACCEPTS the client upgrade once a working upstream connection exists. A dial
// failure is a normal HTTP error the client sees (no 101 yet), and poolgate
// advances to the next candidate per the group strategy. Once frames flow, an
// error on either side closes both — the turn is not migrated (its server-side
// state is gone).
package gateway

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/policy"
)

const (
	// wsReadLimit caps a single inbound WS message (both directions) to bound
	// memory, matching the 32 MiB HTTP body cap.
	wsReadLimit = 32 << 20
	// wsDialTimeout bounds the upstream WS handshake so a stuck upstream doesn't
	// hang the client's pending upgrade.
	wsDialTimeout = 30 * time.Second
	// wsAffinityTTL is how long an x-codex-turn-state → account pin survives.
	wsAffinityTTL = 10 * time.Minute
	// wsPingInterval/wsPingTimeout bound liveness: poolgate pings the client
	// periodically and, if no pong arrives in time, tears the connection down so a
	// dead/half-open peer cannot pin a concurrency slot indefinitely.
	wsPingInterval = 30 * time.Second
	wsPingTimeout  = 10 * time.Second
	// DefaultWSOpenAIBeta is synthesized when the client omits OpenAI-Beta on a WS
	// upgrade (verified against openai/codex: responses_websockets=<date>).
	DefaultWSOpenAIBeta = "responses_websockets=2026-02-06"
)

// wsAffinity is a small TTL map pinning an x-codex-turn-state token to an account
// id across reconnects. It is safe for concurrent use.
type wsAffinity struct {
	mu  sync.Mutex
	m   map[string]wsAffEntry
	ttl time.Duration
	now func() time.Time
}

type wsAffEntry struct {
	accountID string
	expiry    time.Time
}

func newWSAffinity() *wsAffinity {
	return &wsAffinity{m: make(map[string]wsAffEntry), ttl: wsAffinityTTL, now: time.Now}
}

// get returns the pinned account id for a turn-state token if present and unexpired.
func (a *wsAffinity) get(key string) (string, bool) {
	if key == "" {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.m[key]
	if !ok {
		return "", false
	}
	if a.now().After(e.expiry) {
		delete(a.m, key)
		return "", false
	}
	return e.accountID, true
}

// set records (or refreshes) a turn-state → account pin and opportunistically
// evicts expired entries so the map cannot grow unbounded.
func (a *wsAffinity) set(key, accountID string) {
	if key == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for k, e := range a.m {
		if now.After(e.expiry) {
			delete(a.m, k)
		}
	}
	a.m[key] = wsAffEntry{accountID: accountID, expiry: now.Add(a.ttl)}
}

// delete removes a pin (used when the pinned backend fails).
func (a *wsAffinity) delete(key string) {
	if key == "" {
		return
	}
	a.mu.Lock()
	delete(a.m, key)
	a.mu.Unlock()
}

// handleResponsesWS serves the WebSocket transport: identical inbound auth to the
// HTTP path, then strategy-driven account selection with pre-first-frame failover
// (dial upstream, then accept the client), then a transparent bidirectional relay.
func (g *Gateway) handleResponsesWS(w http.ResponseWriter, r *http.Request) {
	if !isWebSocketUpgrade(r) {
		writeError(w, http.StatusBadRequest, "poolgate_bad_request",
			"bad_request", "GET /responses requires a websocket upgrade; use POST for HTTP+SSE")
		return
	}

	apiKey, endpoint, group, accounts, ok := g.authorizeInbound(w, r)
	if !ok {
		return
	}

	rec := &requestRecord{
		g:     g,
		start: time.Now(),
		log: model.RequestLog{
			Endpoint:    endpoint,
			Policy:      group.Name,
			APIKeyID:    apiKey.ID,
			APIKeyLabel: apiKey.Label,
			SessionID:   sessionID(r, apiKey),
		},
	}

	eligible := eligibleAccounts(group, accounts)
	if len(eligible) == 0 {
		g.emitNoHealthyMember(endpoint, group)
		rec.finish(http.StatusServiceUnavailable, model.Account{}, "no_healthy_account", 0, 0)
		writeError(w, http.StatusServiceUnavailable, "poolgate_no_healthy_account",
			"no_healthy_account", "no healthy account available for endpoint "+endpoint)
		return
	}

	// Egress allowlist check on the https form (host-based); the dial uses wss.
	target := g.upstreamBase + "/responses"
	if err := g.checkEgress(target); err != nil {
		rec.finish(http.StatusBadGateway, model.Account{}, "egress_refused", 0, 0)
		writeError(w, http.StatusBadGateway, "poolgate_egress_refused", "egress_refused", err.Error())
		return
	}

	ctx := r.Context()
	view := g.buildView(ctx, group, eligible)
	byID := make(map[string]int, len(eligible))
	for i, a := range eligible {
		byID[a.ID] = i
	}
	turnState := r.Header.Get("x-codex-turn-state")
	// The account this turn-state token is currently pinned to (if any), captured
	// once so we only unpin it when that specific account fails to dial.
	pinnedID, _ := g.wsAff.get(turnState)

	var lastStatus int
	triedAny := false
	pinnedTried := false
	bpDeadline := time.Now().Add(g.queueWait)
	for {
		acct, okSel := g.selectWSCandidate(group, eligible, view, turnState, &pinnedTried)
		if !okSel {
			// Nothing selectable. Same bounded-queue backpressure as the HTTP path.
			if !triedAny && g.anyCapped(eligible, view) {
				if g.waitForSlot(ctx, eligible, view, bpDeadline) {
					continue
				}
				rec.finish(http.StatusTooManyRequests, model.Account{}, "backpressure", 0, 0)
				w.Header().Set("Retry-After", strconv.Itoa(g.retryAfterSecs))
				writeError(w, http.StatusTooManyRequests, "poolgate_backpressure",
					"backpressure", "all accounts are at their concurrency limit; retry after a moment")
				return
			}
			break
		}
		if !g.inflight.tryAdd(acct.ID, view.caps[acct.ID]) {
			continue
		}
		triedAny = true

		uc, status, retryAfter, derr := g.dialUpstreamWS(ctx, r, acct, target)
		if derr != nil {
			g.inflight.done(acct.ID)
			rec.trace = append(rec.trace, traceEntry(acct.ID, status))
			lastStatus = status
			g.logger.Warn("account ws dial failed pre-accept",
				"endpoint", endpoint, "account", acct.ID, "status", status)
			g.recordFailure(ctx, eligible, byID, view, acct, status, retryAfter)
			if turnState != "" && acct.ID == pinnedID {
				g.wsAff.delete(turnState) // only unpin when the PINNED backend failed
			}
			continue
		}

		// Commit: a working upstream exists. Pin affinity and relay. The slot is
		// released via defer so a panic in the relay path cannot leak it.
		g.wsAff.set(turnState, acct.ID)
		rec.trace = append(rec.trace, acct.ID+":ws")
		committed := false
		func() {
			defer g.inflight.done(acct.ID)
			committed = g.serveWSPair(ctx, w, r, uc)
		}()
		if committed {
			rec.finish(http.StatusSwitchingProtocols, acct, "", 0, 0)
		} else {
			rec.finish(http.StatusBadGateway, acct, "ws_accept_failed", 0, 0)
		}
		return
	}

	rec.finish(http.StatusBadGateway, model.Account{}, "all_exhausted", 0, 0)
	writeError(w, http.StatusBadGateway, "poolgate_all_exhausted",
		"all_exhausted", "all accounts failed the websocket handshake (last upstream status "+strconv.Itoa(lastStatus)+")")
}

// selectWSCandidate picks the next account to try: the affinity-pinned account
// first (once, if still selectable), then the group strategy over the live view.
func (g *Gateway) selectWSCandidate(group model.PolicyGroup, eligible []model.Account, view *routeView, turnState string, pinnedTried *bool) (model.Account, bool) {
	if turnState != "" && !*pinnedTried {
		*pinnedTried = true
		if id, ok := g.wsAff.get(turnState); ok && view.IsHealthy(id) {
			if a, in := accountByID(eligible, id); in {
				return a, true
			}
		}
	}
	acct, err := policy.Select(group.Strategy, eligible, view)
	if err != nil {
		return model.Account{}, false
	}
	return acct, true
}

// dialUpstreamWS opens the upstream WebSocket for acct with the translation-gateway
// header rewrite (Authorization + ChatGPT-Account-ID together) and preserved Codex
// identity/correlation headers. On failure it returns the upstream HTTP status (0
// for a transport error) and Retry-After so the caller can drive health/failover.
func (g *Gateway) dialUpstreamWS(ctx context.Context, r *http.Request, acct model.Account, httpsTarget string) (*websocket.Conn, int, time.Duration, error) {
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+acct.AccessToken)
	hdr.Set("ChatGPT-Account-ID", acct.AccountID)
	hdr.Set("originator", headerOrDefault(r, "originator", DefaultOriginator))
	hdr.Set("User-Agent", headerOrDefault(r, "User-Agent", DefaultUserAgent))
	hdr.Set("OpenAI-Beta", headerOrDefault(r, "OpenAI-Beta", DefaultWSOpenAIBeta))
	// Forward Codex correlation headers verbatim (never secrets — those are the
	// rewritten Authorization/account id above).
	for _, h := range []string{"X-Codex-Turn-State", "X-Client-Request-Id", "X-Codex-Installation-Id", "X-Codex-Routing-Hint"} {
		if v := r.Header.Get(h); v != "" {
			hdr.Set(h, v)
		}
	}

	dctx, cancel := context.WithTimeout(ctx, wsDialTimeout)
	defer cancel()
	uc, resp, err := websocket.Dial(dctx, toWSURL(httpsTarget), &websocket.DialOptions{
		HTTPClient:   g.httpc,
		HTTPHeader:   hdr,
		Subprotocols: clientSubprotocols(r),
	})
	if err != nil {
		status := 0
		var ra time.Duration
		if resp != nil {
			status = resp.StatusCode
			ra = parseRetryAfter(resp.Header.Get("Retry-After"))
			_ = resp.Body.Close()
		}
		return nil, status, ra, err
	}
	return uc, 0, 0, nil
}

// serveWSPair accepts the client upgrade (negotiating the same subprotocol the
// upstream chose) and relays frames until either side closes. It returns true
// once the client upgrade was accepted (committed), false if the accept failed.
func (g *Gateway) serveWSPair(ctx context.Context, w http.ResponseWriter, r *http.Request, upstream *websocket.Conn) bool {
	opts := &websocket.AcceptOptions{
		// Auth is the bearer sk- key, not a cookie, so the browser same-origin
		// (CSRF) check is irrelevant for this machine-to-machine proxy.
		InsecureSkipVerify: true,
	}
	if sp := upstream.Subprotocol(); sp != "" {
		opts.Subprotocols = []string{sp}
	}
	client, err := websocket.Accept(w, r, opts)
	if err != nil {
		upstream.Close(websocket.StatusInternalError, "client upgrade failed")
		return false
	}
	client.SetReadLimit(wsReadLimit)
	upstream.SetReadLimit(wsReadLimit)
	g.pumpWS(ctx, client, upstream)
	return true
}

// pumpWS relays whole messages in both directions until either side errors/closes,
// then closes both so the second direction's blocked Read unblocks. It waits for
// both relay goroutines to exit, so no goroutine leaks past the connection. A
// heartbeat pings the client so a silent/half-open peer is reaped (releasing its
// concurrency slot) rather than pinning it until OS TCP keepalive.
func (g *Gateway) pumpWS(ctx context.Context, client, upstream *websocket.Conn) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{}, 2)
	relay := func(dst, src *websocket.Conn) {
		defer func() { cancel(); done <- struct{}{} }()
		for {
			typ, data, err := src.Read(ctx)
			if err != nil {
				return
			}
			if err := dst.Write(ctx, typ, data); err != nil {
				return
			}
		}
	}
	go relay(upstream, client) // client → upstream
	go relay(client, upstream) // upstream → client
	go g.wsHeartbeat(ctx, cancel, client)

	<-done
	// One side finished; close both so the other Read returns promptly.
	client.Close(websocket.StatusNormalClosure, "")
	upstream.Close(websocket.StatusNormalClosure, "")
	<-done
}

// wsHeartbeat pings client every wsPingInterval and cancels the relay if a pong
// does not arrive within wsPingTimeout (a dead or half-open peer). It exits when
// ctx is cancelled (the connection closed), so it never outlives the connection.
func (g *Gateway) wsHeartbeat(ctx context.Context, cancel context.CancelFunc, client *websocket.Conn) {
	t := time.NewTicker(wsPingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, pcancel := context.WithTimeout(ctx, wsPingTimeout)
			err := client.Ping(pctx)
			pcancel()
			if err != nil {
				cancel()
				return
			}
		}
	}
}

// ---- ws helpers -----------------------------------------------------------

// toWSURL converts an http(s) upstream URL to its ws(s) equivalent for dialing.
func toWSURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}
	return u.String()
}

// clientSubprotocols parses the client's Sec-WebSocket-Protocol offer so the
// upstream dial requests the same subprotocols (transparent negotiation).
func clientSubprotocols(r *http.Request) []string {
	var out []string
	for _, v := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// accountByID returns the eligible account with id, if present.
func accountByID(eligible []model.Account, id string) (model.Account, bool) {
	for _, a := range eligible {
		if a.ID == id {
			return a, true
		}
	}
	return model.Account{}, false
}

// traceEntry formats an "account:status" trace crumb.
func traceEntry(id string, status int) string { return id + ":" + strconv.Itoa(status) }

