package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/go2-im/poolgate/internal/model"
)

// wsUpstream is a fake Codex WS upstream. For each upgrade it inspects the
// ChatGPT-Account-ID header: if that id is in reject, it answers the given HTTP
// status WITHOUT upgrading (exercising pre-accept failover); otherwise it accepts
// and echoes every message. It records, per accepted connection, the account id
// and the rewritten Authorization it saw.
type wsUpstream struct {
	srv    *httptest.Server
	reject map[string]int

	mu       sync.Mutex
	accepted []wsSeen
}

type wsSeen struct {
	accountID string
	auth      string
	beta      string
}

func newWSUpstream(t *testing.T, reject map[string]int) *wsUpstream {
	t.Helper()
	u := &wsUpstream{reject: reject}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acctID := r.Header.Get("ChatGPT-Account-ID")
		if status, bad := u.reject[acctID]; bad {
			http.Error(w, "rejected", status)
			return
		}
		// A plain (non-upgrade) POST exercises the HTTP transport path; answer it
		// with a normal SSE 200 so http-only routing tests see the HTTP path served
		// rather than the WS library's 426 upgrade-required response.
		if !isWebSocketUpgrade(r) {
			streamOK(w)
			return
		}
		u.mu.Lock()
		u.accepted = append(u.accepted, wsSeen{
			accountID: acctID,
			auth:      r.Header.Get("Authorization"),
			beta:      r.Header.Get("OpenAI-Beta"),
		})
		u.mu.Unlock()

		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer c.CloseNow()
		c.SetReadLimit(wsReadLimit)
		for {
			typ, data, err := c.Read(r.Context())
			if err != nil {
				return
			}
			if err := c.Write(r.Context(), typ, data); err != nil {
				return
			}
		}
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *wsUpstream) seen() []wsSeen {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]wsSeen, len(u.accepted))
	copy(out, u.accepted)
	return out
}

// wsDial dials poolgate's WS endpoint. turnState (if non-empty) is sent as the
// x-codex-turn-state upgrade header.
func wsDial(t *testing.T, poolgateURL, endpoint, key, turnState string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer "+key)
	if turnState != "" {
		hdr.Set("x-codex-turn-state", turnState)
	}
	wsURL := strings.Replace(poolgateURL, "http://", "ws://", 1) + "/e/" + endpoint + "/v1/responses"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: hdr})
}

func TestWS_HappyPathRewriteAndEcho(t *testing.T) {
	f := newFixture(t)
	up := newWSUpstream(t, nil)
	f.cfg.UpstreamAllowlist = []string{mustHost(t, up.srv.URL)}
	gw := New(f.st, f.cfg, WithUpstreamBase(up.srv.URL), WithHTTPClient(up.srv.Client()))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	c, _, err := wsDial(t, srv.URL, "default", f.apiKey, "")
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer c.CloseNow()

	ctx := context.Background()
	if err := c.Write(ctx, websocket.MessageText, []byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	typ, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if typ != websocket.MessageText || string(data) != "ping" {
		t.Errorf("echo = %q (%v), want ping text", data, typ)
	}

	seen := up.seen()
	if len(seen) != 1 {
		t.Fatalf("upstream accepted %d connections, want 1", len(seen))
	}
	if seen[0].auth != "Bearer acct-access-token" || seen[0].accountID != "acct-chatgpt-id" {
		t.Errorf("upstream saw auth=%q accountID=%q, want the rewritten pair", seen[0].auth, seen[0].accountID)
	}
	if seen[0].beta == "" {
		t.Errorf("upstream saw empty OpenAI-Beta, want a default")
	}
}

func TestWS_RejectsBadKey(t *testing.T) {
	f := newFixture(t)
	up := newWSUpstream(t, nil)
	f.cfg.UpstreamAllowlist = []string{mustHost(t, up.srv.URL)}
	gw := New(f.st, f.cfg, WithUpstreamBase(up.srv.URL), WithHTTPClient(up.srv.Client()))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	_, resp, err := wsDial(t, srv.URL, "default", "sk-wrong", "")
	if err == nil {
		t.Fatal("dial with bad key succeeded, want failure")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %v, want 401", resp)
	}
	if len(up.seen()) != 0 {
		t.Errorf("upstream was contacted despite a bad inbound key")
	}
}

func TestWS_NonUpgradeGetIs400(t *testing.T) {
	f := newFixture(t)
	up := newWSUpstream(t, nil)
	f.cfg.UpstreamAllowlist = []string{mustHost(t, up.srv.URL)}
	gw := New(f.st, f.cfg, WithUpstreamBase(up.srv.URL), WithHTTPClient(up.srv.Client()))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/e/default/v1/responses", nil)
	req.Header.Set("Authorization", "Bearer "+f.apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("plain GET status = %d, want 400", resp.StatusCode)
	}
}

// newTwoAccountFixture is defined in gateway_more_test.go (accounts id-bad/id-good
// under a fallback group, key sk-two-000). setStrategy flips the default group's
// strategy for tests that need round-robin.
func setStrategy(t *testing.T, f *twoAccountFixture, s model.Strategy) {
	t.Helper()
	ctx := context.Background()
	groups, err := f.st.ListPolicyGroups(ctx)
	if err != nil || len(groups) == 0 {
		t.Fatalf("ListPolicyGroups: %v", err)
	}
	g := groups[0]
	g.Strategy = s
	if err := f.st.UpdatePolicyGroup(ctx, g); err != nil {
		t.Fatalf("UpdatePolicyGroup: %v", err)
	}
}

func TestWS_FailsOverToHealthyAccount(t *testing.T) {
	f := newTwoAccountFixture(t) // fallback: id-bad first, then id-good
	// The first member (id-bad) is rejected upstream; failover must reach id-good.
	up := newWSUpstream(t, map[string]int{"id-bad": http.StatusUnauthorized})
	f.cfg.UpstreamAllowlist = []string{mustHost(t, up.srv.URL)}
	gw := New(f.st, f.cfg, WithUpstreamBase(up.srv.URL), WithHTTPClient(up.srv.Client()))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	c, _, err := wsDial(t, srv.URL, "default", f.apiKey, "")
	if err != nil {
		t.Fatalf("ws dial (expected failover to id-good): %v", err)
	}
	defer c.CloseNow()
	if err := c.Write(context.Background(), websocket.MessageText, []byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := c.Read(context.Background()); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	seen := up.seen()
	if len(seen) != 1 || seen[0].accountID != "id-good" {
		t.Fatalf("accepted=%+v, want exactly id-good after failover", seen)
	}
}

func TestWS_NonRetryable4xxRelayedNotFailedOver(t *testing.T) {
	f := newTwoAccountFixture(t) // fallback: id-bad first, then id-good
	// id-bad returns a non-retryable client error (400) on the handshake. This is
	// not an account problem, so poolgate must relay it and NOT fail over to
	// id-good (which would amplify one bad request and mask the real status).
	up := newWSUpstream(t, map[string]int{"id-bad": http.StatusBadRequest})
	f.cfg.UpstreamAllowlist = []string{mustHost(t, up.srv.URL)}
	gw := New(f.st, f.cfg, WithUpstreamBase(up.srv.URL), WithHTTPClient(up.srv.Client()))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	_, resp, err := wsDial(t, srv.URL, "default", f.apiKey, "")
	if err == nil {
		t.Fatal("ws dial should fail (upstream 400 relayed), not succeed via failover")
	}
	if resp == nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("client saw status %v, want 400 relayed verbatim", resp)
	}
	if len(up.seen()) != 0 {
		t.Errorf("upstream accepted %+v; a non-retryable 4xx must not fail over to another account", up.seen())
	}
}

func TestWS_TurnStateAffinityPinsBackend(t *testing.T) {
	f := newTwoAccountFixture(t)
	setStrategy(t, f, model.StrategyLoadBalance)
	up := newWSUpstream(t, nil)
	f.cfg.UpstreamAllowlist = []string{mustHost(t, up.srv.URL)}
	gw := New(f.st, f.cfg, WithUpstreamBase(up.srv.URL), WithHTTPClient(up.srv.Client()))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	dialOnce := func(turnState string) {
		c, _, err := wsDial(t, srv.URL, "default", f.apiKey, turnState)
		if err != nil {
			t.Fatalf("dial (turn=%q): %v", turnState, err)
		}
		// Exchange one message then close so the upstream records the connection.
		_ = c.Write(context.Background(), websocket.MessageText, []byte("x"))
		_, _, _ = c.Read(context.Background())
		c.Close(websocket.StatusNormalClosure, "")
		time.Sleep(20 * time.Millisecond) // let the upstream finish recording
	}

	dialOnce("T1") // conn1: round-robin picks the first member, pins T1→that account
	dialOnce("T1") // conn2: affinity must re-pin to the SAME account (not round-robin's next)
	dialOnce("T2") // conn3: a new turn falls back to round-robin (the other account)

	seen := up.seen()
	if len(seen) != 3 {
		t.Fatalf("accepted %d connections, want 3", len(seen))
	}
	if seen[0].accountID != seen[1].accountID {
		t.Errorf("affinity failed: conn1=%s conn2=%s, want same account", seen[0].accountID, seen[1].accountID)
	}
	if seen[2].accountID == seen[0].accountID {
		t.Errorf("round-robin broken: conn3=%s should differ from the pinned account %s", seen[2].accountID, seen[0].accountID)
	}
}

func TestNormalizeTransport(t *testing.T) {
	cases := map[string]string{
		"both": TransportBoth, "http-only": TransportHTTPOnly, "ws-only": TransportWSOnly,
		"": TransportBoth, "bogus": TransportBoth,
	}
	for in, want := range cases {
		if got := normalizeTransport(in); got != want {
			t.Errorf("normalizeTransport(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTransportHTTPOnlyRefusesWSUpgrade(t *testing.T) {
	f := newFixture(t)
	up := newWSUpstream(t, nil)
	f.cfg.UpstreamAllowlist = []string{mustHost(t, up.srv.URL)}
	f.cfg.Server.Transport = "http-only"
	gw := New(f.st, f.cfg, WithUpstreamBase(up.srv.URL), WithHTTPClient(up.srv.Client()))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	// WS upgrade must be refused (501) so Codex falls back to HTTP+SSE.
	_, resp, err := wsDial(t, srv.URL, "default", f.apiKey, "")
	if err == nil {
		t.Fatal("ws dial succeeded under http-only, want refusal")
	}
	if resp == nil || resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %v, want 501", resp)
	}
	if len(up.seen()) != 0 {
		t.Errorf("upstream contacted despite http-only WS refusal")
	}

	// POST HTTP path still works (upstream WS server also answers /responses over
	// plain POST? No — assert the request is at least authorized + routed, i.e. not
	// a transport refusal). A 200/5xx from the fake WS upstream's non-WS path is
	// fine; the point is it's NOT a 426.
	postReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/default/v1/responses",
		strings.NewReader(`{"model":"gpt-5"}`))
	postReq.Header.Set("Authorization", "Bearer "+f.apiKey)
	postResp, err := http.DefaultClient.Do(postReq)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer postResp.Body.Close()
	if postResp.StatusCode == http.StatusUpgradeRequired {
		t.Errorf("http-only POST returned 426, want the HTTP path to be served")
	}
}

func TestTransportWSOnlyRefusesHTTPPost(t *testing.T) {
	f := newFixture(t)
	up := newWSUpstream(t, nil)
	f.cfg.UpstreamAllowlist = []string{mustHost(t, up.srv.URL)}
	f.cfg.Server.Transport = "ws-only"
	gw := New(f.st, f.cfg, WithUpstreamBase(up.srv.URL), WithHTTPClient(up.srv.Client()))
	srv := httptest.NewServer(gw.Routes())
	defer srv.Close()

	// Plain HTTP POST must be refused with 426 Upgrade Required.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/e/default/v1/responses",
		strings.NewReader(`{"model":"gpt-5"}`))
	req.Header.Set("Authorization", "Bearer "+f.apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("ws-only POST status = %d, want 426", resp.StatusCode)
	}

	// WS still works.
	c, _, err := wsDial(t, srv.URL, "default", f.apiKey, "")
	if err != nil {
		t.Fatalf("ws dial under ws-only: %v", err)
	}
	c.CloseNow()
}
