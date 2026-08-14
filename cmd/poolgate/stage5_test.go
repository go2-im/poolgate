package main

// Stage 5 tests: the admin listener wiring (buildAdminHandler / serveAdmin /
// serveBoth) and the end-to-end bootstrap-token -> first-passkey registration ->
// login flow driven through the real admin HTTP API with a software
// authenticator. The two listeners are proven to start together, respond, and
// shut down gracefully; a bind failure on either is surfaced.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/go2-im/poolgate/internal/gateway"
	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/store"
)

// ---- software authenticator (ES256 / P-256, "none" attestation) ------------
//
// A minimal in-process WebAuthn authenticator, mirroring just enough of the
// CTAP2/WebAuthn wire format for go-webauthn's verifier to accept a full
// begin->finish register and begin->finish login ceremony deterministically.

type swAuthenticator struct {
	rpID    string
	origin  string
	credID  []byte
	priv    *ecdsa.PrivateKey
	signCnt uint32
}

func newSWAuthenticator(t *testing.T, rpID, origin string) *swAuthenticator {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("cred id: %v", err)
	}
	return &swAuthenticator{rpID: rpID, origin: origin, credID: credID, priv: priv}
}

func (a *swAuthenticator) coseKey(t *testing.T) []byte {
	t.Helper()
	x := a.priv.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.priv.PublicKey.Y.FillBytes(make([]byte, 32))
	b, err := cbor.Marshal(map[int]interface{}{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		t.Fatalf("cbor cose key: %v", err)
	}
	return b
}

func (a *swAuthenticator) authData(t *testing.T, attested bool) []byte {
	t.Helper()
	rpIDHash := sha256.Sum256([]byte(a.rpID))
	var buf bytes.Buffer
	buf.Write(rpIDHash[:])
	flags := byte(0x01 | 0x04) // UP | UV
	if attested {
		flags |= 0x40 // AT
	}
	buf.WriteByte(flags)
	cnt := make([]byte, 4)
	binary.BigEndian.PutUint32(cnt, a.signCnt)
	buf.Write(cnt)
	if attested {
		buf.Write(make([]byte, 16)) // zero AAGUID
		credLen := make([]byte, 2)
		binary.BigEndian.PutUint16(credLen, uint16(len(a.credID)))
		buf.Write(credLen)
		buf.Write(a.credID)
		buf.Write(a.coseKey(t))
	}
	return buf.Bytes()
}

func (a *swAuthenticator) clientDataJSON(t *testing.T, typ, challenge string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{"type": typ, "challenge": challenge, "origin": a.origin})
	if err != nil {
		t.Fatalf("client data json: %v", err)
	}
	return b
}

func (a *swAuthenticator) register(t *testing.T, challenge string) json.RawMessage {
	t.Helper()
	cdj := a.clientDataJSON(t, "webauthn.create", challenge)
	attBytes, err := cbor.Marshal(map[string]interface{}{
		"fmt": "none", "attStmt": map[string]interface{}{}, "authData": a.authData(t, true),
	})
	if err != nil {
		t.Fatalf("cbor attestation: %v", err)
	}
	return swJSON(t, map[string]interface{}{
		"id": swB64(a.credID), "rawId": swB64(a.credID), "type": "public-key",
		"response": map[string]interface{}{
			"attestationObject": swB64(attBytes), "clientDataJSON": swB64(cdj),
		},
	})
}

func (a *swAuthenticator) login(t *testing.T, challenge string) json.RawMessage {
	t.Helper()
	a.signCnt++
	cdj := a.clientDataJSON(t, "webauthn.get", challenge)
	authData := a.authData(t, false)
	cdjHash := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte(nil), authData...), cdjHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return swJSON(t, map[string]interface{}{
		"id": swB64(a.credID), "rawId": swB64(a.credID), "type": "public-key",
		"response": map[string]interface{}{
			"authenticatorData": swB64(authData), "clientDataJSON": swB64(cdj), "signature": swB64(sig),
		},
	})
}

func swB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func swJSON(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	return b
}

// beginEnvelope is the shape both admin begin ceremonies return.
type beginEnvelope struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
	} `json:"publicKey"`
	ChallengeID string `json:"challenge_id"`
}

// ---- end-to-end: init bootstrap token -> first passkey -> login ------------

// TestBootstrapFirstPasskeyEndToEnd proves the init/reset-auth bootstrap token
// registers the first passkey through the real admin HTTP API (register/begin +
// register/finish), returns one-time recovery codes, consumes the token
// single-use, and that the freshly registered passkey then authenticates via
// login/begin + login/finish.
func TestBootstrapFirstPasskeyEndToEnd(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(envDataDir, dataDir)
	t.Setenv(envMasterKey, "")

	// init: issues a real single-use bootstrap token (printed once).
	var initOut bytes.Buffer
	if err := cmdInit(nil, &initOut); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}
	token := extractBootstrapToken(t, initOut.String())

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	st, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer st.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	handler, err := buildAdminHandler(cfg, st, logger, nil)
	if err != nil {
		t.Fatalf("buildAdminHandler: %v", err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// The RP id/origin come from static admin config (default loopback).
	auth := newSWAuthenticator(t, "127.0.0.1", "http://127.0.0.1:7070")

	// (1) register/begin gated by the bootstrap token.
	var begin beginEnvelope
	if code := postAdminJSON(t, client, srv.URL+"/admin/register/begin",
		map[string]any{"bootstrap_token": token, "label": "primary"}, &begin); code != http.StatusOK {
		t.Fatalf("register/begin status = %d, want 200", code)
	}
	if begin.ChallengeID == "" || begin.PublicKey.Challenge == "" {
		t.Fatalf("register/begin returned empty challenge: %+v", begin)
	}

	// (2) register/finish with the attestation: mints a session + recovery codes.
	var finish struct {
		Authenticated bool     `json:"authenticated"`
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if code := postAdminJSON(t, client, srv.URL+"/admin/register/finish", map[string]any{
		"bootstrap_token": token,
		"challenge_id":    begin.ChallengeID,
		"credential":      auth.register(t, begin.PublicKey.Challenge),
	}, &finish); code != http.StatusOK {
		t.Fatalf("register/finish status = %d, want 200", code)
	}
	if !finish.Authenticated {
		t.Fatal("register/finish did not authenticate")
	}
	if len(finish.RecoveryCodes) == 0 {
		t.Fatal("register/finish returned no recovery codes for the first passkey")
	}

	ctx := context.Background()
	if n, _ := st.CountWebAuthnCredentials(ctx); n != 1 {
		t.Fatalf("stored passkeys = %d, want 1", n)
	}
	// The bootstrap token was single-use consumed: no unused tokens remain.
	toks, _ := st.ListBootstrapTokens(ctx)
	for _, bt := range toks {
		if !bt.Used() {
			t.Fatal("bootstrap token still unused after first-passkey registration")
		}
	}

	// (3) log in with the freshly registered passkey (fresh cookie jar so we rely
	// only on the stored credential, not the registration session).
	jar2, _ := cookiejar.New(nil)
	loginClient := &http.Client{Jar: jar2}
	var loginBegin beginEnvelope
	if code := postAdminJSON(t, loginClient, srv.URL+"/admin/login/begin", map[string]any{}, &loginBegin); code != http.StatusOK {
		t.Fatalf("login/begin status = %d, want 200", code)
	}
	var loginFinish struct {
		Authenticated bool `json:"authenticated"`
	}
	if code := postAdminJSON(t, loginClient, srv.URL+"/admin/login/finish", map[string]any{
		"challenge_id": loginBegin.ChallengeID,
		"credential":   auth.login(t, loginBegin.PublicKey.Challenge),
	}, &loginFinish); code != http.StatusOK {
		t.Fatalf("login/finish status = %d, want 200", code)
	}
	if !loginFinish.Authenticated {
		t.Fatal("login/finish did not authenticate the registered passkey")
	}

	// The authenticated session reaches a guarded endpoint.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/admin/me", nil)
	resp, err := loginClient.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/me: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/me after login = %d, want 200", resp.StatusCode)
	}
}

// postAdminJSON POSTs body as JSON, decodes the response into out (when non-nil),
// and returns the status code.
func postAdminJSON(t *testing.T, client *http.Client, url string, body any, out any) int {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("build POST %s: %v", url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode %s response: %v", url, err)
		}
	}
	return resp.StatusCode
}

// ---- buildAdminHandler ------------------------------------------------------

// TestBuildAdminHandlerError covers the construction error path: an invalid
// admin external_origin makes the WebAuthn RP resolution fail.
func TestBuildAdminHandlerError(t *testing.T) {
	cfg := configForTest(t)
	cfg.Server.Admin.ExternalOrigin = "://not-a-valid-origin"
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	st := openStoreForTest(t, cfg)
	defer st.Close()
	if _, err := buildAdminHandler(cfg, st, logger, nil); err == nil {
		t.Fatal("buildAdminHandler with invalid admin origin = nil, want error")
	}
}

// ---- serveBoth / serveAdmin -------------------------------------------------

// TestServeBothSmoke starts both listeners on ephemeral ports, hits the proxy
// /healthz and the admin API (security headers + a 401 on an unauthenticated
// guarded route), then cancels for a clean shutdown of both.
func TestServeBothSmoke(t *testing.T) {
	cfg := configForTest(t)
	cfg.Server.Proxy.Port = 0
	cfg.Server.Admin.Port = 0
	st := openStoreForTest(t, cfg)
	defer st.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	gw := gateway.New(st, cfg, gateway.WithLogger(logger))
	adminHandler, err := buildAdminHandler(cfg, st, logger, nil)
	if err != nil {
		t.Fatalf("buildAdminHandler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	proxyCh := make(chan string, 1)
	adminCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- serveBoth(ctx, cfg, gw, adminHandler, logger,
			func(a string) { proxyCh <- a }, func(a string) { adminCh <- a })
	}()

	proxyAddr := waitAddr(t, proxyCh)
	adminAddr := waitAddr(t, adminCh)

	// Proxy health endpoint is alive.
	resp, err := http.Get("http://" + proxyAddr + "/healthz")
	if err != nil {
		cancel()
		t.Fatalf("GET /healthz: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		t.Fatalf("/healthz = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// Admin API responds with strict security headers + CSP and gates the route.
	aresp, err := http.Get("http://" + adminAddr + "/admin/me")
	if err != nil {
		cancel()
		t.Fatalf("GET /admin/me: %v", err)
	}
	if aresp.StatusCode != http.StatusUnauthorized {
		aresp.Body.Close()
		cancel()
		t.Fatalf("/admin/me unauthenticated = %d, want 401", aresp.StatusCode)
	}
	if csp := aresp.Header.Get("Content-Security-Policy"); csp == "" {
		aresp.Body.Close()
		cancel()
		t.Fatal("admin response missing Content-Security-Policy header")
	}
	aresp.Body.Close()

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serveBoth = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveBoth did not return after cancel")
	}
}

// TestServeBothProxyListenError forces the proxy bind to fail (invalid port);
// serveBoth must surface the error and bring the admin peer down too.
func TestServeBothProxyListenError(t *testing.T) {
	cfg := configForTest(t)
	cfg.Server.Proxy.Port = 999999 // invalid TCP port
	cfg.Server.Admin.Port = 0
	st := openStoreForTest(t, cfg)
	defer st.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	gw := gateway.New(st, cfg, gateway.WithLogger(logger))
	adminHandler, err := buildAdminHandler(cfg, st, logger, nil)
	if err != nil {
		t.Fatalf("buildAdminHandler: %v", err)
	}
	if err := serveBoth(context.Background(), cfg, gw, adminHandler, logger, nil, nil); err == nil {
		t.Fatal("serveBoth with invalid proxy port = nil, want listen error")
	}
}

// TestServeBothAdminListenError forces the admin bind to fail while the proxy
// binds fine; serveBoth must still surface the admin error.
func TestServeBothAdminListenError(t *testing.T) {
	cfg := configForTest(t)
	cfg.Server.Proxy.Port = 0
	cfg.Server.Admin.Port = 999999 // invalid TCP port
	st := openStoreForTest(t, cfg)
	defer st.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	gw := gateway.New(st, cfg, gateway.WithLogger(logger))
	adminHandler, err := buildAdminHandler(cfg, st, logger, nil)
	if err != nil {
		t.Fatalf("buildAdminHandler: %v", err)
	}
	if err := serveBoth(context.Background(), cfg, gw, adminHandler, logger, nil, nil); err == nil {
		t.Fatal("serveBoth with invalid admin port = nil, want listen error")
	}
}

// TestServeAdminNonLoopbackNotice binds the admin listener to a non-loopback
// host so the informational notice branch runs, then cancels.
func TestServeAdminNonLoopbackNotice(t *testing.T) {
	cfg := configForTest(t)
	cfg.Server.Admin.Host = "0.0.0.0"
	cfg.Server.Admin.Port = 0
	st := openStoreForTest(t, cfg)
	defer st.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	adminHandler, err := buildAdminHandler(cfg, st, logger, nil)
	if err != nil {
		t.Fatalf("buildAdminHandler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() { errCh <- serveAdmin(ctx, cfg, adminHandler, logger, func(a string) { ready <- a }) }()
	waitAddr(t, ready)
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serveAdmin = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveAdmin did not return after cancel")
	}
}

// TestCmdServeBuildAdminHandlerError drives cmdServe with an invalid admin
// external_origin so the buildAdminHandler error path inside cmdServe runs.
func TestCmdServeBuildAdminHandlerError(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(envDataDir, dataDir)
	t.Setenv(envMasterKey, "")
	if err := writeConfigFile(dataDir,
		"server:\n  admin:\n    external_origin: \"://bad\"\n  proxy:\n    port: 0\n"); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := cmdInit(nil, io.Discard); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}
	if err := cmdServe(context.Background(), nil, io.Discard); err == nil {
		t.Fatal("cmdServe with invalid admin origin = nil, want error")
	}
}

// ---- shared helpers ---------------------------------------------------------

func configForTest(t *testing.T) model.Config {
	t.Helper()
	t.Setenv(envDataDir, t.TempDir())
	t.Setenv(envMasterKey, "")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	return cfg
}

func openStoreForTest(t *testing.T, cfg model.Config) *store.Store {
	t.Helper()
	st, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	return st
}

func waitAddr(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case a := <-ch:
		return a
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for listener address")
		return ""
	}
}

func writeConfigFile(dataDir, body string) error {
	return os.WriteFile(filepath.Join(dataDir, configFile), []byte(body), 0o600)
}
