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
	"path/filepath"
	"strings"
	"time"

	"github.com/go2-im/poolgate/internal/authimport"
	"github.com/go2-im/poolgate/internal/config"
	"github.com/go2-im/poolgate/internal/crypto"
	"github.com/go2-im/poolgate/internal/gateway"
	"github.com/go2-im/poolgate/internal/health"
	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/oauth"
	"github.com/go2-im/poolgate/internal/store"
	usagepkg "github.com/go2-im/poolgate/internal/usage"
)

// errUsage is a sentinel returned by run for a usage error (unknown/missing
// command). main maps it to exit code 2; genuine failures map to exit code 1.
var errUsage = errors.New("usage")

const (
	// defaultGroupName / defaultEndpointName are created by `import` when the
	// store has no policy group / endpoint yet.
	defaultGroupName    = "default"
	defaultEndpointName = "default"

	// masterKeyFile is the keyfile name under the data dir (keyfile source).
	masterKeyFile = "master.key"
	// configFile is the YAML config name under the data dir.
	configFile = "config.yaml"
	// envMasterKey is the env var read when master_key_source=env.
	envMasterKey = "POOLGATE_MASTER_KEY"
	// envDataDir overrides the data dir for all subcommands.
	envDataDir = "POOLGATE_DATA_DIR"
)

func main() {
	ctx := context.Background()
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
  poolgate serve                start the proxy listener + health scheduler

environment:
  POOLGATE_DATA_DIR   override the data directory (default: `+config.DefaultDataDir+`)
  POOLGATE_MASTER_KEY base64 master key (when master_key_source=env)
`)
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
	return cfg, nil
}

// openStore loads the master key per cfg.MasterKeySource, builds the cipher, and
// opens the store (running migrations). Used by import and serve.
func openStore(cfg model.Config) (*store.Store, error) {
	var key []byte
	var err error
	switch cfg.MasterKeySource {
	case "env":
		key, err = crypto.LoadKeyFromEnv(envMasterKey)
	default: // keyfile (keychain is a later phase)
		key, err = crypto.LoadOrCreateKeyfile(filepath.Join(cfg.DataDir, masterKeyFile))
	}
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

	token, err := randToken("pgbt")
	if err != nil {
		return err
	}
	const bootstrapTTL = 15 * time.Minute

	fmt.Fprintf(stdout, "poolgate initialized.\n")
	fmt.Fprintf(stdout, "  data dir:       %s\n", cfg.DataDir)
	fmt.Fprintf(stdout, "  schema version: %d\n", ver)
	fmt.Fprintf(stdout, "  proxy bind:     %s:%d\n", cfg.Server.Proxy.Host, cfg.Server.Proxy.Port)
	fmt.Fprintf(stdout, "\nBootstrap token (single-use, expires in %s — not written to logs):\n  %s\n",
		bootstrapTTL, token)
	fmt.Fprintf(stdout, "\nNext: `poolgate import <auth.json>` to add an account, then `poolgate serve`.\n")
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

// cmdServe starts the proxy listener with the translation gateway and the health
// scheduler loop. It blocks until ctx is cancelled (graceful shutdown) or the
// server fails.
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

	logger := slog.New(slog.NewJSONHandler(stdout, nil))

	// Health engine: reuse the SAME oauth single-flight refresher the gateway hot
	// path uses (DESIGN.md §19.3), poll usage for zero-spend quota/recovery, and
	// gate the probe cost by the configured mode (usage-poll-only by default).
	refresher := oauth.NewRefresher(st, cfg.Issuer)
	engine := newHealthEngine(st, refresher, cfg.HealthProbeMode, logger)

	gw := gateway.New(st, cfg, gateway.WithLogger(logger), gateway.WithHealth(engine))

	// Thin scheduler goroutine: engine.Run ticks with the real clock and returns
	// ctx.Err() on cancellation (graceful shutdown alongside the proxy).
	go func() {
		if err := engine.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Warn("health scheduler stopped", slog.Any("err", err))
		}
	}()

	logger.Info("health scheduler started", slog.String("probe_mode", cfg.HealthProbeMode))
	return serveGateway(ctx, cfg, gw, logger, nil)
}

// newHealthEngine builds the health probe engine. The zero-spend auth-check is
// always wired; small-live-requests are opt-in via probeMode == "allow-live"
// (bounded by the per-account daily budget in the engine).
func newHealthEngine(st *store.Store, refresher *oauth.Refresher, probeMode string, logger *slog.Logger) *health.Engine {
	opts := []health.Option{
		health.WithLogger(logger),
		health.WithAuthProbe(health.NewModelsAuthChecker()),
	}
	if probeMode == "allow-live" {
		opts = append(opts, health.WithAllowLive(true), health.WithLiveProbe(health.NewLiveRequester()))
	}
	return health.New(st, usagepkg.New(), refresher, opts...)
}

// serveGateway binds the proxy listener and serves the gateway routes until ctx
// is cancelled. When onReady is non-nil it is invoked with the bound address
// once the listener is open (used by tests to discover the ephemeral port).
func serveGateway(ctx context.Context, cfg model.Config, gw *gateway.Gateway, logger *slog.Logger, onReady func(addr string)) error {
	addr := fmt.Sprintf("%s:%d", cfg.Server.Proxy.Host, cfg.Server.Proxy.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:           gw.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: SSE streams are long-lived.
	}
	logger.Info("proxy listening", slog.String("addr", ln.Addr().String()))
	if cfg.Server.Proxy.Host != "127.0.0.1" && cfg.Server.Proxy.Host != "localhost" {
		logger.Info("proxy bound to a non-loopback address; front it with a reverse proxy",
			slog.String("host", cfg.Server.Proxy.Host))
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

// randToken returns a random token with the given prefix.
func randToken(prefix string) (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(b[:]), nil
}

// randSKKey returns a fresh inbound proxy key in the sk- form.
func randSKKey() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "sk-" + hex.EncodeToString(b[:]), nil
}
