// Command poolgate is the walking-skeleton CLI for Phase 2a (DESIGN.md §0 / §17).
//
// Subcommands:
//
//	poolgate init            create data dir + master key, migrate DB, print a
//	                         short-TTL bootstrap token stub. Never imports an account.
//	poolgate import <path>   parse a Codex auth.json and store the account; create
//	                         a default fallback group + endpoint + sk- key if none.
//	poolgate serve           start the proxy listener (loopback default) with the
//	                         translation gateway + /healthz + /readyz.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go2-im/poolgate/internal/admin"
	"github.com/go2-im/poolgate/internal/adminauth"
	"github.com/go2-im/poolgate/internal/authimport"
	"github.com/go2-im/poolgate/internal/config"
	"github.com/go2-im/poolgate/internal/crypto"
	"github.com/go2-im/poolgate/internal/gateway"
	"github.com/go2-im/poolgate/internal/health"
	"github.com/go2-im/poolgate/internal/lock"
	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/monitor"
	"github.com/go2-im/poolgate/internal/notify"
	"github.com/go2-im/poolgate/internal/oauth"
	"github.com/go2-im/poolgate/internal/store"
	usagepkg "github.com/go2-im/poolgate/internal/usage"
	"github.com/go2-im/poolgate/internal/webauthnsvc"
	"github.com/go2-im/poolgate/internal/webui"
)

// errUsage is a sentinel returned by run for a usage error (unknown/missing
// command). main maps it to exit code 2; genuine failures map to exit code 1.
var errUsage = errors.New("usage")

// Build metadata, injected at release time via -ldflags -X (see .goreleaser.yaml
// / docs/BUILD.md). They keep their defaults for `go build` / `go install`
// (source builds), so `poolgate version` still works without a release toolchain.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const (
	// defaultGroupName / defaultEndpointName are created by `import` when the
	// store has no policy group / endpoint yet.
	defaultGroupName    = "default"
	defaultEndpointName = "default"

	// masterKeyFile is the keyfile name under the data dir (keyfile source).
	masterKeyFile = "master.key"
	// lockFile is the single-instance advisory lockfile under the data dir.
	lockFile = "poolgate.lock"
	// configFile is the YAML config name under the data dir.
	configFile = "config.yaml"
	// envMasterKey is the env var read when master_key_source=env.
	envMasterKey = "POOLGATE_MASTER_KEY"
	// envDataDir overrides the data dir for all subcommands.
	envDataDir = "POOLGATE_DATA_DIR"
	// envProxyHost / envProxyPort override the proxy listener bind. The proxy
	// default is loopback (127.0.0.1), which is unreachable from outside a
	// container; setting POOLGATE_PROXY_HOST=0.0.0.0 (as the Docker image does)
	// makes the published port reachable. The admin listener intentionally has
	// no such override — keep it loopback/private (DESIGN §3).
	envProxyHost = "POOLGATE_PROXY_HOST"
	envProxyPort = "POOLGATE_PROXY_PORT"
	// envBackupPassphrase supplies the passphrase for `backup`/`restore` when
	// --passphrase-file is not given. It is never written to logs.
	envBackupPassphrase = "POOLGATE_BACKUP_PASSPHRASE"
)

func main() {
	// SIGTERM / Ctrl-C cancels the root context so `serve` drains and shuts down
	// both listeners gracefully (DESIGN.md §21.2).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	switch {
	case err == nil:
		return
	case errors.Is(err, errUsage):
		os.Exit(2)
	default:
		os.Exit(1)
	}
}

// run is the testable entrypoint: it dispatches a subcommand and returns an
// error instead of calling os.Exit. errUsage signals a usage error (exit 2);
// any other error is a runtime failure (exit 1). Output is written to stdout,
// diagnostics/usage to stderr.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) < 1 {
		usage(stderr)
		return errUsage
	}
	cmd, rest := args[0], args[1:]

	switch cmd {
	case "version", "--version", "-v":
		printVersion(stdout)
		return nil
	case "init":
		if err := cmdInit(rest, stdout); err != nil {
			fmt.Fprintf(stderr, "poolgate %s: %v\n", cmd, err)
			return err
		}
	case "import":
		if err := cmdImport(rest, stdout); err != nil {
			fmt.Fprintf(stderr, "poolgate %s: %v\n", cmd, err)
			return err
		}
	case "serve":
		if err := cmdServe(ctx, rest, stdout); err != nil {
			fmt.Fprintf(stderr, "poolgate %s: %v\n", cmd, err)
			return err
		}
	case "admin":
		if err := cmdAdmin(rest, stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "poolgate %s: %v\n", cmd, err)
			return err
		}
	case "backup":
		if err := cmdBackup(rest, stdout); err != nil {
			fmt.Fprintf(stderr, "poolgate %s: %v\n", cmd, err)
			return err
		}
	case "restore":
		if err := cmdRestore(rest, stdout); err != nil {
			fmt.Fprintf(stderr, "poolgate %s: %v\n", cmd, err)
			return err
		}
	case "-h", "--help", "help":
		usage(stderr)
		return nil
	default:
		fmt.Fprintf(stderr, "poolgate: unknown command %q\n\n", cmd)
		usage(stderr)
		return errUsage
	}
	return nil
}

func usage(w io.Writer) {
	fmt.Fprint(w, `poolgate — Codex/ChatGPT account pool gateway (Phase 2a)

usage:
  poolgate init                 initialize data dir, master key, and DB
  poolgate import <auth.json>   import a Codex account (explicit, never automatic)
                                [--strategy fallback|best-quota|load-balance]
  poolgate serve                start the proxy + admin listeners + health scheduler
  poolgate admin reset-auth     wipe all passkeys/recovery codes/sessions and
                                print a fresh single-use bootstrap token
  poolgate backup               write a passphrase-wrapped backup bundle
                                (master key + DB snapshot) [--out <file>]
                                [--passphrase-file <path>]
  poolgate restore <bundle>     restore a bundle into the data dir
                                [--passphrase-file <path>] [--force]
  poolgate version              print version, commit, and build date

environment:
  POOLGATE_DATA_DIR   override the data directory (default: `+config.DefaultDataDir+`)
  POOLGATE_MASTER_KEY base64 master key (when master_key_source=env)
  POOLGATE_BACKUP_PASSPHRASE  passphrase for backup/restore (or --passphrase-file)
`)
}

// printVersion writes the build metadata as a single line. The values are the
// ldflags-injected version/commit/date (defaults for source builds).
func printVersion(w io.Writer) {
	fmt.Fprintf(w, "poolgate %s (commit %s, built %s, %s)\n",
		version, commit, date, runtime.Version())
}

// loadConfig returns the effective config, honoring POOLGATE_DATA_DIR and a
// config.yaml under the data dir when present.
func loadConfig() (model.Config, error) {
	dataDir := os.Getenv(envDataDir)
	// Look for a config file in the data dir (if the data dir is known).
	var cfgPath string
	if dataDir != "" {
		cfgPath = filepath.Join(dataDir, configFile)
	} else {
		cfgPath = filepath.Join(config.DefaultDataDir, configFile)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return model.Config{}, err
	}
	if dataDir != "" {
		cfg.DataDir = dataDir
	}
	// Env overrides for the proxy bind (containers need a non-loopback host).
	if v := strings.TrimSpace(os.Getenv(envProxyHost)); v != "" {
		cfg.Server.Proxy.Host = v
	}
	if v := strings.TrimSpace(os.Getenv(envProxyPort)); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p <= 65535 {
			cfg.Server.Proxy.Port = p
		}
	}
	return cfg, nil
}

// loadMasterKey resolves the raw master key bytes per cfg.MasterKeySource: from
// POOLGATE_MASTER_KEY (env) or a keyfile under the data dir (default; created if
// absent). Shared by openStore and the backup/restore commands.
func loadMasterKey(cfg model.Config) ([]byte, error) {
	switch cfg.MasterKeySource {
	case "env":
		return crypto.LoadKeyFromEnv(envMasterKey)
	default: // keyfile (keychain is a later phase)
		return crypto.LoadOrCreateKeyfile(filepath.Join(cfg.DataDir, masterKeyFile))
	}
}

// openStore loads the master key per cfg.MasterKeySource, builds the cipher, and
// opens the store (running migrations). Used by import and serve.
func openStore(cfg model.Config) (*store.Store, error) {
	key, err := loadMasterKey(cfg)
	if err != nil {
		return nil, fmt.Errorf("load master key: %w", err)
	}
	cipher, err := crypto.New(key)
	if err != nil {
		return nil, err
	}
	return store.Open(cfg, cipher)
}

// cmdInit provisions the data dir, master key, and DB schema. Idempotent. It
// prints a short-TTL single-use bootstrap token stub and never imports accounts.
func cmdInit(_ []string, stdout io.Writer) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	// Open store: this generates the keyfile (if keyfile source) and migrates.
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	ver, err := st.SchemaVersion(context.Background())
	if err != nil {
		return err
	}

	// Issue a real short-TTL single-use bootstrap token via the same path
	// `admin reset-auth` uses (DESIGN.md §16 / §17). The plaintext is printed
	// once below and never written to durable logs; only its hash is persisted.
	mgr, err := newAdminManager(st)
	if err != nil {
		return err
	}
	token, bt, err := mgr.IssueBootstrapToken(context.Background())
	if err != nil {
		return err
	}
	ttl := time.Until(bt.ExpiresAt).Round(time.Second)

	fmt.Fprintf(stdout, "poolgate initialized.\n")
	fmt.Fprintf(stdout, "  data dir:       %s\n", cfg.DataDir)
	fmt.Fprintf(stdout, "  schema version: %d\n", ver)
	fmt.Fprintf(stdout, "  proxy bind:     %s:%d\n", cfg.Server.Proxy.Host, cfg.Server.Proxy.Port)
	fmt.Fprintf(stdout, "\nBootstrap token (single-use, expires in %s — not written to logs):\n  %s\n",
		ttl, token)
	fmt.Fprintf(stdout, "\nNext: `poolgate import <auth.json>` to add an account, then `poolgate serve`.\n")
	return nil
}

// newAdminManager builds the admin-auth manager over the store. Both `init` and
// `admin reset-auth` route bootstrap-token issuance through this single path so
// the token is always persisted (hashed) and consumable (DESIGN.md §16 / §17).
func newAdminManager(st *store.Store) (*adminauth.Manager, error) {
	return adminauth.New(st)
}

// cmdAdmin dispatches the `poolgate admin <subcommand>` group. Currently only
// `reset-auth` (the local lockout escape hatch, DESIGN.md §16) is implemented.
func cmdAdmin(args []string, stdout, stderr io.Writer) error {
	if len(args) < 1 {
		fmt.Fprint(stderr, "usage: poolgate admin reset-auth\n")
		return errUsage
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "reset-auth":
		return cmdAdminResetAuth(rest, stdout)
	default:
		fmt.Fprintf(stderr, "poolgate admin: unknown subcommand %q\n\nusage: poolgate admin reset-auth\n", sub)
		return errUsage
	}
}

// cmdAdminResetAuth performs a full admin-login reset: it removes all passkeys,
// invalidates recovery codes, revokes all sessions, clears stale bootstrap
// tokens, and prints a fresh short-TTL single-use bootstrap token to stdout
// (never to durable logs — DESIGN.md §16 / §0 fixes).
func cmdAdminResetAuth(_ []string, stdout io.Writer) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	mgr, err := newAdminManager(st)
	if err != nil {
		return err
	}
	token, sum, err := mgr.ResetAuth(context.Background())
	if err != nil {
		return err
	}
	ttl := time.Until(sum.BootstrapExpiresAt).Round(time.Second)

	fmt.Fprintf(stdout, "admin auth reset.\n")
	fmt.Fprintf(stdout, "  passkeys removed:         %d\n", sum.PasskeysRemoved)
	fmt.Fprintf(stdout, "  recovery codes removed:   %d\n", sum.RecoveryCodesRemoved)
	fmt.Fprintf(stdout, "  sessions revoked:         %d\n", sum.SessionsRevoked)
	fmt.Fprintf(stdout, "  bootstrap tokens cleared: %d\n", sum.BootstrapTokensCleared)
	fmt.Fprintf(stdout, "\nBootstrap token (single-use, expires in %s — not written to logs):\n  %s\n",
		ttl, token)
	fmt.Fprintf(stdout, "\nRegister a new passkey with this token, then it is consumed.\n")
	return nil
}

// cmdImport parses a Codex auth.json and stores the account. If the store has no
// policy group / endpoint / key yet, it creates a default group over the imported
// account (strategy from --strategy, default fallback), a `default` endpoint, and
// one sk- key (printed once).
func cmdImport(args []string, stdout io.Writer) error {
	path, strategy, err := parseImportArgs(args)
	if err != nil {
		return err
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()

	acct, err := authimport.ParseFile(path)
	if err != nil {
		return err
	}
	acct.Label = "imported-" + time.Now().UTC().Format("20060102-150405")
	acct, err = st.InsertAccount(ctx, acct)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "imported account %s (label %q, state %s)\n", acct.ID, acct.Label, acct.State)

	// Create default group + endpoint + key if none exists yet.
	if _, err := st.GetEndpoint(ctx, defaultEndpointName); err == nil {
		fmt.Fprintf(stdout, "endpoint %q already exists; account added to the pool only.\n", defaultEndpointName)
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}

	group, err := st.InsertPolicyGroup(ctx, model.PolicyGroup{
		Name:             defaultGroupName,
		Strategy:         strategy,
		MemberAccountIDs: []string{acct.ID},
	})
	if err != nil {
		return err
	}
	if _, err := st.InsertEndpoint(ctx, model.Endpoint{Name: defaultEndpointName, GroupID: group.ID}); err != nil {
		return err
	}
	skKey, err := randSKKey()
	if err != nil {
		return err
	}
	if _, err := st.InsertApiKey(ctx, model.ApiKey{Key: skKey, Label: "default", Endpoints: []string{defaultEndpointName}}); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "created default %s group %q, endpoint %q\n", strategy, defaultGroupName, defaultEndpointName)
	fmt.Fprintf(stdout, "\nProxy URL:  http://%s:%d/e/%s/v1/responses\n",
		cfg.Server.Proxy.Host, cfg.Server.Proxy.Port, defaultEndpointName)
	fmt.Fprintf(stdout, "API key (shown once — store it now):\n  %s\n", skKey)
	return nil
}

// parseImportArgs extracts the auth.json path and the optional --strategy value
// (order-independent). The strategy defaults to fallback and must be one of the
// three v1 strategies (DESIGN.md §0 D7).
func parseImportArgs(args []string) (path string, strategy model.Strategy, err error) {
	strategy = model.StrategyFallback
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--strategy" || a == "-strategy":
			if i+1 >= len(args) {
				return "", "", errors.New("usage: poolgate import <auth.json> [--strategy fallback|best-quota|load-balance]")
			}
			strategy = model.Strategy(args[i+1])
			i++
		case strings.HasPrefix(a, "--strategy="):
			strategy = model.Strategy(strings.TrimPrefix(a, "--strategy="))
		case strings.HasPrefix(a, "-strategy="):
			strategy = model.Strategy(strings.TrimPrefix(a, "-strategy="))
		default:
			if path == "" {
				path = a
			}
		}
	}
	if path == "" {
		return "", "", errors.New("usage: poolgate import <auth.json> [--strategy fallback|best-quota|load-balance]")
	}
	if !validStrategy(strategy) {
		return "", "", fmt.Errorf("invalid --strategy %q (want fallback, best-quota, or load-balance)", strategy)
	}
	return path, strategy, nil
}

// validStrategy reports whether s is one of the three v1 strategies.
func validStrategy(s model.Strategy) bool {
	switch s {
	case model.StrategyFallback, model.StrategyBestQuota, model.StrategyLoadBalance:
		return true
	default:
		return false
	}
}

// cmdServe starts BOTH listeners — the proxy (translation gateway) and the
// loopback admin API — plus the health scheduler loop. It blocks until ctx is
// cancelled (SIGTERM → graceful shutdown of both) or a listener fails.
func cmdServe(ctx context.Context, _ []string, stdout io.Writer) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	// Single-instance guard (DESIGN.md §21): refuse to start a second server
	// against the same data dir (which would double-bind the listeners and race
	// on the SQLite WAL). openStore has created the data dir by now. The lock is
	// held for the process lifetime and released on exit (or by the kernel on a
	// crash, so it is never left stale).
	lk, err := lock.Acquire(filepath.Join(cfg.DataDir, lockFile))
	if err != nil {
		if errors.Is(err, lock.ErrLocked) {
			return fmt.Errorf("another poolgate serve is already running for data dir %s", cfg.DataDir)
		}
		return fmt.Errorf("acquire single-instance lock: %w", err)
	}
	defer lk.Release()

	logger := slog.New(slog.NewJSONHandler(stdout, nil))

	// Notification engine (DESIGN.md §11): SSRF-guarded egress, holds channel
	// secrets server-side, dispatches secret-free events asynchronously so the
	// hot path is never blocked. Shared by the health engine (account-state
	// transitions), the gateway (no-healthy-member), and the admin "test" action.
	notifier := notify.New(st, notify.WithLogger(logger))

	// Real-time monitor (DESIGN.md §15): records a secret-free per-request log,
	// fans it out to live SSE subscribers, and prunes old rows. Non-blocking
	// Record keeps it off the proxy hot path.
	mon := monitor.New(st, monitor.WithLogger(logger))

	// Health engine: reuse the SAME oauth single-flight refresher the gateway hot
	// path uses (DESIGN.md §19.3), poll usage for zero-spend quota/recovery, and
	// gate the probe cost by the configured mode (usage-poll-only by default).
	refresher := oauth.NewRefresher(st, cfg.Issuer)
	engine := newHealthEngine(st, refresher, cfg.HealthProbeMode, logger, notifier)

	gw := gateway.New(st, cfg, gateway.WithLogger(logger), gateway.WithHealth(engine),
		gateway.WithEventSink(notifier), gateway.WithRecorder(mon))

	// Admin API handler (loopback listener), wired with the same store so the
	// bootstrap token issued by `init` / `admin reset-auth` registers the first
	// passkey through /admin/register/* end-to-end (DESIGN.md §3 / §16 / §17).
	adminHandler, err := buildAdminHandler(cfg, st, logger, notifier, mon)
	if err != nil {
		return err
	}

	// Thin scheduler goroutine: engine.Run ticks with the real clock and returns
	// ctx.Err() on cancellation (graceful shutdown alongside the listeners).
	go func() {
		if err := engine.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Warn("health scheduler stopped", slog.Any("err", err))
		}
	}()

	// Notification dispatcher goroutine: drains the queue and delivers alerts
	// until ctx is cancelled (graceful shutdown alongside the listeners).
	go func() {
		if err := notifier.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Warn("notify dispatcher stopped", slog.Any("err", err))
		}
	}()

	// Monitor recorder goroutine: persists request logs, fans out to SSE
	// subscribers, and prunes old rows until ctx is cancelled.
	go func() {
		if err := mon.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Warn("monitor recorder stopped", slog.Any("err", err))
		}
	}()

	logger.Info("health scheduler started", slog.String("probe_mode", cfg.HealthProbeMode))
	return serveBoth(ctx, cfg, gw, adminHandler, logger, nil, nil)
}

// buildAdminHandler constructs the loopback admin API handler: the admin-auth
// manager (sessions / CSRF / recovery / bootstrap tokens), the WebAuthn service
// (RP resolved once from static admin config, gated by that manager as its
// authorizer), and the admin HTTP server that mounts them. It returns the fully
// middleware-wrapped handler (strict security headers + CSP + same-origin CORS).
func buildAdminHandler(cfg model.Config, st *store.Store, logger *slog.Logger, notifier admin.Notifier, mon admin.MonitorStream) (http.Handler, error) {
	mgr, err := adminauth.New(st)
	if err != nil {
		return nil, fmt.Errorf("admin auth: %w", err)
	}
	wa, err := webauthnsvc.New(cfg, st, webauthnsvc.WithAuthorizer(mgr))
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}
	opts := []admin.Option{admin.WithNotifier(notifier), admin.WithMonitor(mon)}
	// Mount the embedded admin SPA when a bundle is present; otherwise run API-only.
	if spa, serr := webui.Handler(); serr == nil {
		opts = append(opts, admin.WithSPA(spa))
	} else {
		logger.Warn("admin UI bundle unavailable; serving API only", slog.Any("err", serr))
	}
	srv, err := admin.New(cfg, st, mgr, wa, opts...)
	if err != nil {
		return nil, fmt.Errorf("admin api: %w", err)
	}
	logger.Info("admin API configured",
		slog.String("origin", srv.Origin()), slog.String("rp_id", wa.RPID()))
	return srv.Handler(), nil
}

// serveBoth runs the proxy and admin listeners concurrently and blocks until ctx
// is cancelled (both shut down gracefully) or either listener fails to serve
// (the peer is then cancelled too and the first error is returned). onReady
// callbacks, when non-nil, receive each bound address (used by tests to discover
// ephemeral ports).
func serveBoth(ctx context.Context, cfg model.Config, gw *gateway.Gateway, adminHandler http.Handler, logger *slog.Logger, proxyReady, adminReady func(addr string)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	go func() { errCh <- serveGateway(ctx, cfg, gw, logger, proxyReady) }()
	go func() { errCh <- serveAdmin(ctx, cfg, adminHandler, logger, adminReady) }()

	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
			cancel() // a bind/serve failure on one listener brings the peer down too
		}
	}
	return firstErr
}

// serveGateway binds the proxy listener and serves the gateway routes until ctx
// is cancelled. When onReady is non-nil it is invoked with the bound address
// once the listener is open (used by tests to discover the ephemeral port).
func serveGateway(ctx context.Context, cfg model.Config, gw *gateway.Gateway, logger *slog.Logger, onReady func(addr string)) error {
	addr := fmt.Sprintf("%s:%d", cfg.Server.Proxy.Host, cfg.Server.Proxy.Port)
	return serveListener(ctx, addr, gw.Routes(), func(bound string) {
		logger.Info("proxy listening", slog.String("addr", bound))
		if cfg.Server.Proxy.Host != "127.0.0.1" && cfg.Server.Proxy.Host != "localhost" {
			logger.Info("proxy bound to a non-loopback address; front it with a reverse proxy",
				slog.String("host", cfg.Server.Proxy.Host))
		}
		if onReady != nil {
			onReady(bound)
		}
	})
}

// serveAdmin binds the admin listener and serves the admin API handler until ctx
// is cancelled. The admin surface is expected to stay loopback (DESIGN.md §3); a
// non-loopback bind is a warning, not a refusal.
func serveAdmin(ctx context.Context, cfg model.Config, handler http.Handler, logger *slog.Logger, onReady func(addr string)) error {
	addr := fmt.Sprintf("%s:%d", cfg.Server.Admin.Host, cfg.Server.Admin.Port)
	return serveListener(ctx, addr, handler, func(bound string) {
		logger.Info("admin listening (loopback)", slog.String("addr", bound))
		if cfg.Server.Admin.Host != "127.0.0.1" && cfg.Server.Admin.Host != "localhost" {
			logger.Warn("admin bound to a non-loopback address; keep the admin surface private",
				slog.String("host", cfg.Server.Admin.Host))
		}
		if onReady != nil {
			onReady(bound)
		}
	})
}

// serveListener binds addr and serves handler with a bounded read-header timeout
// (no write timeout — SSE streams are long-lived), invoking onReady with the
// bound address once the socket is open, and shutting the server down gracefully
// (5s drain deadline) when ctx is cancelled.
func serveListener(ctx context.Context, addr string, handler http.Handler, onReady func(bound string)) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if onReady != nil {
		onReady(ln.Addr().String())
	}

	// Graceful shutdown on context cancellation.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// newHealthEngine builds the health probe engine. The zero-spend auth-check is
// always wired; small-live-requests are opt-in via probeMode == "allow-live"
// (bounded by the per-account daily budget in the engine). When events is
// non-nil, the engine emits secret-free notification events on state transitions.
func newHealthEngine(st *store.Store, refresher *oauth.Refresher, probeMode string, logger *slog.Logger, events health.EventSink) *health.Engine {
	opts := []health.Option{
		health.WithLogger(logger),
		health.WithAuthProbe(health.NewModelsAuthChecker()),
	}
	if events != nil {
		opts = append(opts, health.WithEventSink(events))
	}
	if probeMode == "allow-live" {
		opts = append(opts, health.WithAllowLive(true), health.WithLiveProbe(health.NewLiveRequester()))
	}
	return health.New(st, usagepkg.New(), refresher, opts...)
}

// randSKKey returns a fresh inbound proxy key in the sk- form.
func randSKKey() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "sk-" + hex.EncodeToString(b[:]), nil
}
