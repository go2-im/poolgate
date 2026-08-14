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
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go2-im/poolgate/internal/authimport"
	"github.com/go2-im/poolgate/internal/config"
	"github.com/go2-im/poolgate/internal/crypto"
	"github.com/go2-im/poolgate/internal/gateway"
	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/store"
)

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
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "import":
		err = cmdImport(args)
	case "serve":
		err = cmdServe(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "poolgate: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "poolgate %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `poolgate — Codex/ChatGPT account pool gateway (Phase 2a)

usage:
  poolgate init                 initialize data dir, master key, and DB
  poolgate import <auth.json>   import a Codex account (explicit, never automatic)
  poolgate serve                start the proxy listener

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
func cmdInit(_ []string) error {
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

	fmt.Printf("poolgate initialized.\n")
	fmt.Printf("  data dir:       %s\n", cfg.DataDir)
	fmt.Printf("  schema version: %d\n", ver)
	fmt.Printf("  proxy bind:     %s:%d\n", cfg.Server.Proxy.Host, cfg.Server.Proxy.Port)
	fmt.Printf("\nBootstrap token (single-use, expires in %s — not written to logs):\n  %s\n",
		bootstrapTTL, token)
	fmt.Printf("\nNext: `poolgate import <auth.json>` to add an account, then `poolgate serve`.\n")
	return nil
}

// cmdImport parses a Codex auth.json and stores the account. If the store has no
// policy group / endpoint / key yet, it creates a default fallback group over
// the imported account, a `default` endpoint, and one sk- key (printed once).
func cmdImport(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: poolgate import <auth.json>")
	}
	path := args[0]

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
	fmt.Printf("imported account %s (label %q, state %s)\n", acct.ID, acct.Label, acct.State)

	// Create default group + endpoint + key if none exists yet.
	if _, err := st.GetEndpoint(ctx, defaultEndpointName); err == nil {
		fmt.Printf("endpoint %q already exists; account added to the pool only.\n", defaultEndpointName)
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}

	group, err := st.InsertPolicyGroup(ctx, model.PolicyGroup{
		Name:             defaultGroupName,
		Strategy:         model.StrategyFallback,
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

	fmt.Printf("created default fallback group %q, endpoint %q\n", defaultGroupName, defaultEndpointName)
	fmt.Printf("\nProxy URL:  http://%s:%d/e/%s/v1/responses\n",
		cfg.Server.Proxy.Host, cfg.Server.Proxy.Port, defaultEndpointName)
	fmt.Printf("API key (shown once — store it now):\n  %s\n", skKey)
	return nil
}

// cmdServe starts the proxy listener with the translation gateway.
func cmdServe(_ []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	gw := gateway.New(st, cfg, gateway.WithLogger(logger))

	addr := fmt.Sprintf("%s:%d", cfg.Server.Proxy.Host, cfg.Server.Proxy.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           gw.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: SSE streams are long-lived.
	}
	logger.Info("proxy listening", slog.String("addr", addr))
	if cfg.Server.Proxy.Host != "127.0.0.1" && cfg.Server.Proxy.Host != "localhost" {
		logger.Info("proxy bound to a non-loopback address; front it with a reverse proxy",
			slog.String("host", cfg.Server.Proxy.Host))
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
