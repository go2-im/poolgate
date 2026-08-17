package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/gateway"
)

// writeAuthJSON drops a minimal but valid Codex auth.json in a fresh temp dir
// and returns its path.
func writeAuthJSON(t *testing.T) string {
	t.Helper()
	authPath := filepath.Join(t.TempDir(), "auth.json")
	const authJSON = `{"tokens":{"access_token":"acct-access","refresh_token":"acct-refresh","account_id":"acct-123","id_token":"h.p.s"}}`
	if err := os.WriteFile(authPath, []byte(authJSON), 0o600); err != nil {
		t.Fatalf("write auth.json: %v", err)
	}
	return authPath
}

// TestLoadConfigProxyEnvOverride covers the POOLGATE_PROXY_HOST/PORT overrides
// loadConfig applies on top of the resolved config — the mechanism the Docker
// image uses to bind the proxy to a reachable (non-loopback) address. The admin
// listener is intentionally left untouched (stays loopback).
func TestLoadConfigProxyEnvOverride(t *testing.T) {
	// A data dir with no config.yaml → defaults (proxy host 127.0.0.1).
	t.Setenv(envDataDir, t.TempDir())

	// No override → default loopback proxy host.
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Server.Proxy.Host != "127.0.0.1" {
		t.Fatalf("default proxy host = %q, want 127.0.0.1", cfg.Server.Proxy.Host)
	}
	adminHost := cfg.Server.Admin.Host

	// Overrides applied.
	t.Setenv(envProxyHost, "0.0.0.0")
	t.Setenv(envProxyPort, "9999")
	cfg, err = loadConfig()
	if err != nil {
		t.Fatalf("loadConfig (override): %v", err)
	}
	if cfg.Server.Proxy.Host != "0.0.0.0" {
		t.Errorf("proxy host = %q, want 0.0.0.0", cfg.Server.Proxy.Host)
	}
	if cfg.Server.Proxy.Port != 9999 {
		t.Errorf("proxy port = %d, want 9999", cfg.Server.Proxy.Port)
	}
	if cfg.Server.Admin.Host != adminHost {
		t.Errorf("admin host changed to %q; proxy override must not touch admin", cfg.Server.Admin.Host)
	}

	// A non-numeric or out-of-range port now fails fast instead of being silently
	// ignored (which had left the proxy on a surprising default).
	t.Setenv(envProxyPort, "not-a-port")
	if _, err := loadConfig(); err == nil {
		t.Errorf("bad POOLGATE_PROXY_PORT should error, not be silently ignored")
	}
	t.Setenv(envProxyPort, "70000")
	if _, err := loadConfig(); err == nil {
		t.Errorf("out-of-range POOLGATE_PROXY_PORT should error")
	}
}

func TestLoadConfigTrustedProxies(t *testing.T) {
	t.Setenv(envDataDir, t.TempDir())
	t.Setenv(envTrustedProxies, "10.0.0.0/8, 127.0.0.1 ,")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if len(cfg.Server.TrustedProxies) != 2 {
		t.Fatalf("trusted proxies = %v, want 2 (blank trimmed)", cfg.Server.TrustedProxies)
	}
	// An invalid spec fails fast.
	t.Setenv(envTrustedProxies, "not-an-ip")
	if _, err := loadConfig(); err == nil {
		t.Error("invalid POOLGATE_TRUSTED_PROXIES should error")
	}
}

// TestRunVersion covers the version subcommand + its flag aliases: each returns
// nil and prints a single line carrying the injected version string and the Go
// runtime version, to stdout (not stderr).
func TestRunVersion(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}, {"-v"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out, errBuf bytes.Buffer
			if err := run(context.Background(), args, &out, &errBuf); err != nil {
				t.Fatalf("run(%v) err = %v, want nil", args, err)
			}
			got := out.String()
			if !strings.Contains(got, "poolgate ") || !strings.Contains(got, version) {
				t.Errorf("stdout missing version: %q", got)
			}
			if !strings.Contains(got, runtime.Version()) {
				t.Errorf("stdout missing go runtime version: %q", got)
			}
			if errBuf.Len() != 0 {
				t.Errorf("version wrote to stderr: %q", errBuf.String())
			}
		})
	}
}

// TestRunUsage covers the run() dispatcher's usage/help branches: no args and
// an unknown command both return errUsage (exit 2) and print usage to stderr;
// the help aliases return nil and also print usage.
func TestRunUsage(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  error
		wantHelp bool
	}{
		{name: "no args", args: nil, wantErr: errUsage, wantHelp: true},
		{name: "unknown command", args: []string{"bogus"}, wantErr: errUsage, wantHelp: true},
		{name: "help", args: []string{"help"}, wantErr: nil, wantHelp: true},
		{name: "-h", args: []string{"-h"}, wantErr: nil, wantHelp: true},
		{name: "--help", args: []string{"--help"}, wantErr: nil, wantHelp: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			err := run(context.Background(), tc.args, &out, &errBuf)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("run(%v) err = %v, want %v", tc.args, err, tc.wantErr)
			}
			if tc.wantHelp && !strings.Contains(errBuf.String(), "usage:") {
				t.Errorf("stderr missing usage banner: %q", errBuf.String())
			}
			if tc.name == "unknown command" && !strings.Contains(errBuf.String(), "unknown command") {
				t.Errorf("stderr missing unknown-command line: %q", errBuf.String())
			}
		})
	}
}

// TestRunInitImportDispatch drives run("init") then run("import") end-to-end
// against a temp data dir, exercising the happy dispatch path through run().
func TestRunInitImportDispatch(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(envDataDir, dataDir)
	t.Setenv(envMasterKey, "")

	var out, errBuf bytes.Buffer
	if err := run(context.Background(), []string{"init"}, &out, &errBuf); err != nil {
		t.Fatalf("run init: %v (stderr=%q)", err, errBuf.String())
	}
	if !strings.Contains(out.String(), "poolgate initialized") {
		t.Errorf("init stdout missing banner: %q", out.String())
	}

	out.Reset()
	errBuf.Reset()
	authPath := writeAuthJSON(t)
	if err := run(context.Background(), []string{"import", authPath}, &out, &errBuf); err != nil {
		t.Fatalf("run import: %v (stderr=%q)", err, errBuf.String())
	}
	if !strings.Contains(out.String(), "imported account") {
		t.Errorf("import stdout missing confirmation: %q", out.String())
	}
	// A second import re-uses the existing endpoint (the "already exists" branch).
	out.Reset()
	authPath2 := writeAuthJSON(t)
	if err := run(context.Background(), []string{"import", authPath2}, &out, &errBuf); err != nil {
		t.Fatalf("run import (second): %v", err)
	}
	if !strings.Contains(out.String(), "already exists") {
		t.Errorf("second import should reuse endpoint, stdout=%q", out.String())
	}
}

// TestCmdImportArgErrors covers the two early cmdImport error paths: missing
// argument and an unparseable/missing auth.json file.
func TestCmdImportArgErrors(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(envDataDir, dataDir)
	t.Setenv(envMasterKey, "")
	if err := cmdInit(nil, io.Discard); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}

	if err := cmdImport(nil, io.Discard); err == nil {
		t.Fatal("cmdImport(nil) = nil, want usage error")
	}

	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	if err := cmdImport([]string{missing}, io.Discard); err == nil {
		t.Fatal("cmdImport(missing file) = nil, want parse error")
	}
}

// TestLoadConfigParseError writes a malformed config.yaml so config.Load fails;
// every subcommand routed through loadConfig must surface that error.
func TestLoadConfigParseError(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(envDataDir, dataDir)
	// Malformed YAML (a mapping value that is actually a broken sequence).
	if err := os.WriteFile(filepath.Join(dataDir, configFile), []byte("server: [unterminated\n"), 0o600); err != nil {
		t.Fatalf("write bad config: %v", err)
	}

	if _, err := loadConfig(); err == nil {
		t.Fatal("loadConfig with malformed yaml = nil, want error")
	}
	// The error must propagate through cmdInit / cmdImport / cmdServe.
	if err := cmdInit(nil, io.Discard); err == nil {
		t.Fatal("cmdInit with bad config = nil, want error")
	}
	if err := cmdImport([]string{"whatever.json"}, io.Discard); err == nil {
		t.Fatal("cmdImport with bad config = nil, want error")
	}
	if err := cmdServe(context.Background(), nil, io.Discard); err == nil {
		t.Fatal("cmdServe with bad config = nil, want error")
	}

	// And through run(), which should print the diagnostic to stderr.
	var errBuf bytes.Buffer
	if err := run(context.Background(), []string{"init"}, io.Discard, &errBuf); err == nil {
		t.Fatal("run init with bad config = nil, want error")
	}
	if !strings.Contains(errBuf.String(), "poolgate init:") {
		t.Errorf("run stderr missing diagnostic prefix: %q", errBuf.String())
	}
}

// TestOpenStoreEnvKeyMissing selects the env master-key source with no key in
// the environment, exercising openStore's env branch + error wrapping.
func TestOpenStoreEnvKeyMissing(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(envDataDir, dataDir)
	t.Setenv(envMasterKey, "")
	if err := os.WriteFile(filepath.Join(dataDir, configFile), []byte("master_key_source: env\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := cmdInit(nil, io.Discard)
	if err == nil {
		t.Fatal("cmdInit with env source + empty key = nil, want error")
	}
	if !strings.Contains(err.Error(), "load master key") {
		t.Errorf("error = %v, want load-master-key wrap", err)
	}
}

// TestCmdInitMkdirError points the data dir under a read-only parent so that
// config.yaml is simply absent (loadConfig succeeds) but os.MkdirAll fails,
// exercising cmdInit's create-data-dir error path.
func TestCmdInitMkdirError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions")
	}
	base := t.TempDir()
	readonly := filepath.Join(base, "ro")
	if err := os.Mkdir(readonly, 0o500); err != nil {
		t.Fatalf("mkdir readonly: %v", err)
	}
	// Restore write bit so t.TempDir cleanup can remove it.
	t.Cleanup(func() { _ = os.Chmod(readonly, 0o700) })

	// config.yaml under readonly/sub does not exist -> loadConfig returns
	// defaults; MkdirAll(readonly/sub) then fails with EACCES.
	t.Setenv(envDataDir, filepath.Join(readonly, "sub"))
	t.Setenv(envMasterKey, "")

	err := cmdInit(nil, io.Discard)
	if err == nil {
		t.Fatal("cmdInit with un-creatable data dir = nil, want error")
	}
	if !strings.Contains(err.Error(), "create data dir") {
		t.Errorf("error = %v, want create-data-dir wrap", err)
	}
}

// TestServeGatewaySmoke boots the gateway through serveGateway on an ephemeral
// port, hits /healthz + /readyz, then cancels the context and asserts a clean
// (nil) shutdown. This is the `serve` smoke test.
func TestServeGatewaySmoke(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(envDataDir, dataDir)
	t.Setenv(envMasterKey, "")
	if err := cmdInit(nil, io.Discard); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}
	if err := cmdImport([]string{writeAuthJSON(t)}, io.Discard); err != nil {
		t.Fatalf("cmdImport: %v", err)
	}

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	// Ephemeral port: avoids clashing with the fixed default 8787.
	cfg.Server.Proxy.Port = 0
	st, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer st.Close()

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	gw := gateway.New(st, cfg, gateway.WithLogger(logger))

	ctx, cancel := context.WithCancel(context.Background())
	addrCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- serveGateway(ctx, cfg, gw, logger, func(addr string) { addrCh <- addr })
	}()

	var addr string
	select {
	case addr = <-addrCh:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("timed out waiting for listener to come up")
	}

	base := "http://" + addr
	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(base + path)
		if err != nil {
			cancel()
			t.Fatalf("GET %s: %v", path, err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			cancel()
			t.Fatalf("GET %s status = %d, want 200", path, resp.StatusCode)
		}
		resp.Body.Close()
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serveGateway returned %v, want nil after graceful shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveGateway did not return after context cancel")
	}
}

// TestCmdServeContextCancel drives the full cmdServe wiring (loadConfig ->
// openStore -> gateway.New -> serveGateway) with an ephemeral port and a
// context cancelled shortly after start, asserting a clean return.
func TestCmdServeContextCancel(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(envDataDir, dataDir)
	t.Setenv(envMasterKey, "")
	// Bind to an ephemeral port so the fixed default can't collide.
	if err := os.WriteFile(filepath.Join(dataDir, configFile),
		[]byte("server:\n  proxy:\n    host: 127.0.0.1\n    port: 0\n  admin:\n    host: 127.0.0.1\n    port: 0\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := cmdInit(nil, io.Discard); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- cmdServe(ctx, nil, io.Discard) }()
	// Give the listener a beat to come up, then request shutdown.
	time.Sleep(150 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("cmdServe = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cmdServe did not return after cancel")
	}
}

// TestServeGatewayListenError forces net.Listen to fail via an out-of-range
// port, covering serveGateway's bind-error path.
func TestServeGatewayListenError(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(envDataDir, dataDir)
	t.Setenv(envMasterKey, "")
	if err := cmdInit(nil, io.Discard); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	cfg.Server.Proxy.Port = 999999 // invalid TCP port -> Listen fails
	st, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer st.Close()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	gw := gateway.New(st, cfg, gateway.WithLogger(logger))

	if err := serveGateway(context.Background(), cfg, gw, logger, nil); err == nil {
		t.Fatal("serveGateway with invalid port = nil, want listen error")
	}
}

// TestUsageBanner ensures usage() writes the documented environment + command
// help to the provided writer.
func TestUsageBanner(t *testing.T) {
	var buf bytes.Buffer
	usage(&buf)
	for _, want := range []string{"poolgate init", "poolgate import", "poolgate serve", envDataDir, envMasterKey} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("usage banner missing %q", want)
		}
	}
}

// TestRunImportError covers run()'s import error branch, including the stderr
// diagnostic line.
func TestRunImportError(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(envDataDir, dataDir)
	t.Setenv(envMasterKey, "")
	if err := cmdInit(nil, io.Discard); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}
	var errBuf bytes.Buffer
	err := run(context.Background(), []string{"import", filepath.Join(t.TempDir(), "nope.json")}, io.Discard, &errBuf)
	if err == nil {
		t.Fatal("run import(missing) = nil, want error")
	}
	if !strings.Contains(errBuf.String(), "poolgate import:") {
		t.Errorf("stderr missing import diagnostic: %q", errBuf.String())
	}
}

// TestRunServeDispatch covers run()'s serve branch: it dispatches cmdServe on an
// ephemeral port and returns nil once the context is cancelled.
func TestRunServeDispatch(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(envDataDir, dataDir)
	t.Setenv(envMasterKey, "")
	if err := os.WriteFile(filepath.Join(dataDir, configFile),
		[]byte("server:\n  proxy:\n    host: 127.0.0.1\n    port: 0\n  admin:\n    host: 127.0.0.1\n    port: 0\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := cmdInit(nil, io.Discard); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- run(ctx, []string{"serve"}, io.Discard, io.Discard) }()
	time.Sleep(150 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("run serve = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run serve did not return after cancel")
	}
}

func TestLoadConfigBackpressureWait(t *testing.T) {
	dir := t.TempDir()
	// Valid duration parses.
	if err := os.WriteFile(filepath.Join(dir, configFile), []byte("server:\n  backpressure_wait: \"250ms\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(envDataDir, dir)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig(valid): %v", err)
	}
	if got := backpressureWait(cfg); got != 250*time.Millisecond {
		t.Errorf("backpressureWait = %v, want 250ms", got)
	}

	// Invalid duration fails fast.
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, configFile), []byte("server:\n  backpressure_wait: \"nope\"\n"), 0o600); err != nil {
		t.Fatalf("write config2: %v", err)
	}
	t.Setenv(envDataDir, dir2)
	if _, err := loadConfig(); err == nil {
		t.Errorf("loadConfig with invalid backpressure_wait should error")
	}
}
