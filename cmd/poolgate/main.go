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
	"github.com/go2-im/poolgate/internal/clientip"
	"github.com/go2-im/poolgate/internal/config"
	"github.com/go2-im/poolgate/internal/crypto"
	"github.com/go2-im/poolgate/internal/gateway"
	"github.com/go2-im/poolgate/internal/health"
	"github.com/go2-im/poolgate/internal/lock"
	"github.com/go2-im/poolgate/internal/memguard"
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
	// maintenanceLockFile serializes credential-touching one-shot commands
	// (import/login/backup/rotate-key/restore) so master-key rotation can never run
	// concurrently with an in-flight import/login (which would seal a new account
	// with the OLD cipher) or backup (which would pair an old key with a new-key DB
	// snapshot). serve deliberately does NOT take it — imports/logins alongside a
	// running server stay allowed (rotate/restore are already gated off serve by the
	// single-instance lock above).
	maintenanceLockFile = ".poolgate.maintenance.lock"
	// restoreMarkerFile marks an in-progress `poolgate restore`. serve refuses to
	// start while it exists (a restore was interrupted mid-commit).
	restoreMarkerFile = ".restore-incomplete"
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
	// envProxyTransport overrides server.transport (both|http-only|ws-only).
	envProxyTransport = "POOLGATE_PROXY_TRANSPORT"
	// envTrustedProxies overrides server.trusted_proxies (comma-separated IPs/CIDRs).
	envTrustedProxies = "POOLGATE_TRUSTED_PROXIES"
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
	case "login":
		if err := cmdLogin(ctx, rest, stdout); err != nil {
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
	case "rotate-key":
		if err := cmdRotateKey(rest, stdout); err != nil {
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
                                [--strategy fallback|best-quota|load-balance|weighted]
  poolgate login                sign in via browser (OAuth + PKCE) to add an account
                                [--strategy fallback|best-quota|load-balance|weighted]
  poolgate serve                start the proxy + admin listeners + health scheduler
  poolgate admin reset-auth     wipe all passkeys/recovery codes/sessions and
                                print a fresh single-use bootstrap token
  poolgate backup               write a passphrase-wrapped backup bundle
                                (master key + DB snapshot) [--out <file>]
                                [--passphrase-file <path>]
  poolgate restore <bundle>     restore a bundle into the data dir
                                [--passphrase-file <path>] [--force]
  poolgate rotate-key           generate a new master key and re-encrypt all
                                secrets (writes a pre-rotation snapshot first)
  poolgate version              print version, commit, and build date

environment:
  POOLGATE_DATA_DIR   override the data directory (default: `+config.DefaultDataDir+`)
  POOLGATE_MASTER_KEY base64 master key (when master_key_source=env)
  POOLGATE_PROXY_HOST / POOLGATE_PROXY_PORT   override the proxy listener bind
  POOLGATE_PROXY_TRANSPORT   both|http-only|ws-only (default http-only)
  POOLGATE_TRUSTED_PROXIES   comma-separated reverse-proxy IPs/CIDRs whose
                             X-Forwarded-For is trusted (default: none)
  POOLGATE_BACKUP_PASSPHRASE  passphrase for backup/restore (or --passphrase-file)

  Any secret env var also accepts a "<NAME>_FILE" variant (Docker/K8s secrets):
  set e.g. POOLGATE_MASTER_KEY_FILE=/run/secrets/key to read it from a file
  instead of the process environment.
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
		p, perr := strconv.Atoi(v)
		if perr != nil || p <= 0 || p > 65535 {
			return model.Config{}, fmt.Errorf("%s must be a port in 1..65535, got %q", envProxyPort, v)
		}
		cfg.Server.Proxy.Port = p
	}
	if v := strings.TrimSpace(os.Getenv(envProxyTransport)); v != "" {
		cfg.Server.Transport = v
	}
	if v := strings.TrimSpace(os.Getenv(envTrustedProxies)); v != "" {
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		cfg.Server.TrustedProxies = out
	}
	// Validate trusted-proxy specs early so a typo fails fast at startup rather
	// than silently disabling forwarded-header handling later.
	if _, err := clientip.ParseCIDRs(cfg.Server.TrustedProxies); err != nil {
		return model.Config{}, err
	}
	// Validate the optional backpressure wait (fail fast on a bad duration).
	if s := strings.TrimSpace(cfg.Server.BackpressureWait); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return model.Config{}, fmt.Errorf("server.backpressure_wait %q is not a valid duration: %w", s, err)
		}
		if d < 0 {
			return model.Config{}, fmt.Errorf("server.backpressure_wait %q must not be negative", s)
		}
	}
	// Validate the optional proactive-token-refresh interval (fail fast on a bad
	// duration; "0" is valid and disables it).
	if s := strings.TrimSpace(cfg.ProactiveTokenRefresh); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return model.Config{}, fmt.Errorf("proactive_token_refresh %q is not a valid duration: %w", s, err)
		}
		if d < 0 {
			return model.Config{}, fmt.Errorf("proactive_token_refresh %q must not be negative", s)
		}
	}
	return cfg, nil
}

// backpressureWait parses the validated server.backpressure_wait duration (0 when
// empty/invalid — loadConfig already rejected invalid values at startup).
func backpressureWait(cfg model.Config) time.Duration {
	s := strings.TrimSpace(cfg.Server.BackpressureWait)
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0
	}
	return d
}

// envValue returns the value of the named env var, honoring the Docker/K8s
// "<NAME>_FILE" secrets convention: if <NAME>_FILE is set, its file contents
// (trailing newline trimmed) are returned instead — so a secret can be mounted
// as a file rather than exposed in the process environment. The _FILE variant
// takes precedence when both are set.
func envValue(name string) (string, error) {
	if p := os.Getenv(name + "_FILE"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("read %s_FILE (%s): %w", name, p, err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return os.Getenv(name), nil
}

// loadMasterKey resolves the raw master key bytes per cfg.MasterKeySource: from
// POOLGATE_MASTER_KEY / POOLGATE_MASTER_KEY_FILE (env) or a keyfile under the
// data dir (default; created if absent). Shared by openStore and the
// backup/restore commands.
func loadMasterKey(cfg model.Config) ([]byte, error) {
	switch cfg.MasterKeySource {
	case "env":
		v, err := envValue(envMasterKey)
		if err != nil {
			return nil, err
		}
		if v == "" {
			return nil, fmt.Errorf("crypto: %s (or %s_FILE) is empty", envMasterKey, envMasterKey)
		}
		return crypto.ParseKey(v)
	default: // keyfile (keychain is a later phase)
		return crypto.LoadOrCreateKeyfile(filepath.Join(cfg.DataDir, masterKeyFile))
	}
}

// loadMasterKeyExisting loads the master key but NEVER creates one. Read-only /
// DR commands (backup) use it: minting a fresh key when the keyfile is missing
// would embed a random key in the bundle that cannot decrypt the snapshotted
// database, producing an unrestorable bundle that still reports success.
func loadMasterKeyExisting(cfg model.Config) ([]byte, error) {
	switch cfg.MasterKeySource {
	case "env":
		v, err := envValue(envMasterKey)
		if err != nil {
			return nil, err
		}
		if v == "" {
			return nil, fmt.Errorf("crypto: %s (or %s_FILE) is empty", envMasterKey, envMasterKey)
		}
		return crypto.ParseKey(v)
	default:
		return crypto.LoadKeyfile(filepath.Join(cfg.DataDir, masterKeyFile))
	}
}

// openStore loads the master key per cfg.MasterKeySource, builds the cipher, and
// opens the store (running migrations). Used by import and serve.
// guardRestoreMarker refuses to proceed while a restore is mid-commit (its marker
// exists), so no command EXCEPT `restore` opens or CREATES the DB / master key over
// a half-committed generation (openStore mints a key + DB when absent). restore does
// its own marker handling and does not route through here.
func guardRestoreMarker(cfg model.Config) error {
	if _, err := os.Stat(filepath.Join(cfg.DataDir, restoreMarkerFile)); err == nil {
		return fmt.Errorf("an interrupted restore is present in %s (%s) — recover it manually (inspect the *.prev files, put the intended DB/master.key/rotations back, delete the marker) before running other commands",
			cfg.DataDir, restoreMarkerFile)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check restore marker: %w", err)
	}
	return nil
}

func openStore(cfg model.Config) (*store.Store, error) {
	if err := guardRestoreMarker(cfg); err != nil {
		return nil, err
	}
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

	// Hold the maintenance lock (concurrent-safe: init coordinates with any running
	// serve via the in-store credential lock) and check the restore marker UNDER it,
	// before openStore mints/opens the key + DB — previously init opened the store with
	// NO lock, so its marker check raced a concurrent restore that set it (P1#5).
	guards, err := acquireCommandGuards(cfg, false)
	if err != nil {
		return err
	}
	defer guards.Release()

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
	// Hold the maintenance lock and check the restore marker UNDER it before opening
	// the store (previously opened with NO lock — a marker-check TOCTOU vs a concurrent
	// restore; P1#5). Concurrent-safe (offline=false): reset-auth may run while serve
	// is up.
	guards, err := acquireCommandGuards(cfg, false)
	if err != nil {
		return err
	}
	defer guards.Release()
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

// acquireMaintenanceLock takes the maintenance lock (non-blocking) for a
// credential-touching one-shot command (import/login/backup/rotate-key/restore).
// It returns a friendly error when another maintenance operation already holds it,
// so master-key rotation can never overlap an in-flight import/login/backup. The
// caller must Release() the returned lock.
func acquireMaintenanceLock(cfg model.Config) (*lock.Lock, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	lk, err := lock.Acquire(filepath.Join(cfg.DataDir, maintenanceLockFile))
	if err != nil {
		if errors.Is(err, lock.ErrLocked) {
			return nil, fmt.Errorf("another maintenance operation (import/login/backup/rotate-key/restore) is in progress for %s — retry once it finishes", cfg.DataDir)
		}
		return nil, fmt.Errorf("acquire maintenance lock: %w", err)
	}
	return lk, nil
}

// commandGuards bundles the standard guards a credential-touching one-shot command
// holds for its duration. Release() unwinds them in reverse acquisition order and is
// safe to call via defer (and on a nil receiver).
type commandGuards struct {
	ilk *lock.Lock // single-instance lock (offline commands only); nil otherwise
	mlk *lock.Lock // maintenance lock (always held)
}

// Release releases the held locks (maintenance first, then single-instance).
func (g *commandGuards) Release() {
	if g == nil {
		return
	}
	if g.mlk != nil {
		_ = g.mlk.Release()
	}
	if g.ilk != nil {
		_ = g.ilk.Release()
	}
}

// acquireCommandGuards takes the canonical guards for a credential-touching one-shot
// command IN A FIXED ORDER, so the restore-marker check is always performed while the
// locks are held. This closes the TOCTOU (audit P1#5) where a concurrent `restore`
// could set the marker between an unlocked check and the lock — or, for `rotate-key`,
// where the marker was not checked at all:
//
//  1. single-instance lock — ONLY when offline is true (backup / rotate-key / restore,
//     which must exclude a live `serve`). Concurrent-safe commands (init / admin /
//     import / login) pass offline=false: they coordinate with a running serve via the
//     in-store credential lock and need only mutual exclusion against each other (the
//     maintenance lock), which ALSO serializes them against restore (restore holds the
//     maintenance lock too).
//  2. maintenance lock — always (serializes credential one-shots, including restore).
//  3. guardRestoreMarker — LAST, under the locks above.
//
// The caller must defer Release().
func acquireCommandGuards(cfg model.Config, offline bool) (*commandGuards, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	g := &commandGuards{}
	if offline {
		ilk, err := lock.Acquire(filepath.Join(cfg.DataDir, lockFile))
		if err != nil {
			g.Release()
			if errors.Is(err, lock.ErrLocked) {
				return nil, fmt.Errorf("a poolgate serve is running for %s — stop it before running this offline command (backup / rotate-key / restore)", cfg.DataDir)
			}
			return nil, fmt.Errorf("acquire single-instance lock: %w", err)
		}
		g.ilk = ilk
	}
	mlk, err := acquireMaintenanceLock(cfg)
	if err != nil {
		g.Release()
		return nil, err
	}
	g.mlk = mlk
	if err := guardRestoreMarker(cfg); err != nil {
		g.Release()
		return nil, err
	}
	return g, nil
}

// cmdImport parses a Codex auth.json and stores the account. If the store has no
// policy group / endpoint / key yet, it creates a default group over the imported
// account (strategy from --strategy, default fallback), a `default` endpoint, and
// one sk- key (printed once).
func cmdImport(args []string, stdout io.Writer) error {
	path, strategy, force, err := parseImportArgs(args)
	if err != nil {
		return err
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	// Hold the maintenance lock so a concurrent rotate-key cannot re-encrypt the DB
	// between opening the store (old cipher) and sealing the imported account.
	mlk, err := acquireMaintenanceLock(cfg)
	if err != nil {
		return err
	}
	defer mlk.Release()
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

	// File import defaults to NON-destructive: if this ChatGPT account is already
	// pooled, refuse rather than overwrite — a stale auth.json would roll the live
	// row back to an older, possibly already-consumed refresh token and revoke the
	// family. `--force` opts into replacing (and clears any pending rotation).
	updated := false
	if force {
		acct, updated, err = st.UpsertAccountByAccountID(ctx, acct)
	} else {
		acct, err = st.InsertAccountUnique(ctx, acct)
		if errors.Is(err, store.ErrAlreadyExists) {
			return fmt.Errorf("an account with this ChatGPT account id is already pooled; use `poolgate login` to refresh its credentials, or `poolgate import %s --force` to overwrite (WARNING: importing an older auth.json can roll the account back to a consumed refresh token)", path)
		}
	}
	if err != nil {
		return err
	}
	if updated {
		fmt.Fprintf(stdout, "replaced existing account %s (--force; credentials overwritten)\n", acct.ID)
	} else {
		fmt.Fprintf(stdout, "imported account %s (label %q, state %s)\n", acct.ID, acct.Label, acct.State)
	}

	return bootstrapDefaults(ctx, st, cfg, acct, strategy, stdout)
}

// bootstrapDefaults creates the default policy group + endpoint + sk- key over
// acct when the store has no endpoint yet (the first account, however it was
// added — CLI import or interactive login). When an endpoint already exists it
// reports that the account joined the pool only. Shared by import and login.
func bootstrapDefaults(ctx context.Context, st *store.Store, cfg model.Config, acct model.Account, strategy model.Strategy, stdout io.Writer) error {
	if _, err := st.GetEndpoint(ctx, defaultEndpointName); err == nil {
		fmt.Fprintf(stdout, "endpoint %q already exists; account added to the pool only.\n", defaultEndpointName)
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}

	group := model.PolicyGroup{
		Name:             defaultGroupName,
		Strategy:         strategy,
		MemberAccountIDs: []string{acct.ID},
	}
	skKey, err := randSKKey()
	if err != nil {
		return err
	}
	// Create the group + endpoint + key atomically so a mid-bootstrap failure can't
	// leave an orphaned group/endpoint that blocks a retry.
	if _, _, err = st.CreateDefaultResources(ctx, group, defaultEndpointName,
		model.ApiKey{Key: skKey, Label: "default", Endpoints: []string{defaultEndpointName}}); err != nil {
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
func parseImportArgs(args []string) (path string, strategy model.Strategy, force bool, err error) {
	strategy = model.StrategyFallback
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--force":
			force = true
		case a == "--strategy" || a == "-strategy":
			if i+1 >= len(args) {
				return "", "", false, errors.New("usage: poolgate import <auth.json> [--strategy fallback|best-quota|load-balance|weighted] [--force]")
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
		return "", "", false, errors.New("usage: poolgate import <auth.json> [--strategy fallback|best-quota|load-balance|weighted] [--force]")
	}
	if !validStrategy(strategy) {
		return "", "", false, fmt.Errorf("invalid --strategy %q (want fallback, best-quota, load-balance, or weighted)", strategy)
	}
	return path, strategy, force, nil
}

// validStrategy reports whether s is one of the three v1 strategies.
func validStrategy(s model.Strategy) bool {
	switch s {
	case model.StrategyFallback, model.StrategyBestQuota, model.StrategyLoadBalance, model.StrategyWeighted:
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

	// Single-instance guard (DESIGN.md §21): acquire BEFORE opening the store, so
	// the lock also gates store open + migrations — two servers starting against
	// the same data dir would otherwise race the migration runner on the shared
	// SQLite WAL. Acquire only needs the data dir to exist. The lock is held for
	// the process lifetime and released on exit (or by the kernel on a crash, so
	// it is never left stale).
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	// Refuse to start if a restore was interrupted mid-commit: the DB and keyfile
	// could belong to different generations. The operator recovers by re-running
	// `poolgate restore` (the previous generation is preserved as *.prev files).
	if _, err := os.Stat(filepath.Join(cfg.DataDir, restoreMarkerFile)); err == nil {
		return fmt.Errorf("an interrupted restore was detected in %s (%s present) — recover it manually: inspect the *.prev files (the previous generation), move the intended DB/master.key/rotations back into place, then delete %s. (`poolgate restore` refuses to run while the marker exists.)",
			cfg.DataDir, restoreMarkerFile, restoreMarkerFile)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check restore marker: %w", err)
	}
	lk, err := lock.Acquire(filepath.Join(cfg.DataDir, lockFile))
	if err != nil {
		if errors.Is(err, lock.ErrLocked) {
			return fmt.Errorf("another poolgate serve is already running for data dir %s", cfg.DataDir)
		}
		return fmt.Errorf("acquire single-instance lock: %w", err)
	}
	defer lk.Release()

	logger := slog.New(slog.NewJSONHandler(stdout, nil))

	// Memory hygiene (DESIGN.md §22): disable core dumps and lock memory against
	// swap BEFORE the master key is read into the process, so for the keyfile and
	// POOLGATE_MASTER_KEY_FILE sources the key never has an in-memory window a
	// crash core file or a swapped page could persist. (A plain POOLGATE_MASTER_KEY
	// env var is already resident in the environment block before Harden runs —
	// use the _FILE variant to avoid that pre-Harden exposure; see docs/DEPLOY.md.)
	// Both mitigations are best-effort — a warning is logged and serve continues if
	// one can't be applied (e.g. memory locking under a tight RLIMIT_MEMLOCK).
	mg := memguard.Harden()
	for _, w := range mg.Warnings {
		logger.Warn("memory hygiene not fully applied", slog.String("detail", w))
	}
	logger.Info("memory hygiene applied",
		slog.Bool("core_dumps_disabled", mg.CoreDumpsDisabled),
		slog.Bool("memory_locked", mg.MemoryLocked))

	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

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
	engine := newHealthEngine(st, refresher, cfg.HealthProbeMode, cfg.ProactiveTokenRefresh, logger, notifier)

	// trusted_proxies were validated in loadConfig; parse is infallible here.
	trusted, _ := clientip.ParseCIDRs(cfg.Server.TrustedProxies)
	gwOpts := []gateway.Option{
		gateway.WithLogger(logger), gateway.WithHealth(engine),
		gateway.WithEventSink(notifier), gateway.WithRecorder(mon),
		gateway.WithTrustedProxies(trusted),
	}
	// Optional bounded-queue backpressure: wait up to backpressure_wait for a slot
	// before 429. Empty/0 = fail fast (the default). Validated in loadConfig.
	if wait := backpressureWait(cfg); wait > 0 {
		gwOpts = append(gwOpts, gateway.WithBackpressure(wait, 0))
	}
	gw := gateway.New(st, cfg, gwOpts...)

	// Admin API handler (loopback listener), wired with the same store so the
	// bootstrap token issued by `init` / `admin reset-auth` registers the first
	// passkey through /admin/register/* end-to-end (DESIGN.md §3 / §16 / §17).
	adminHandler, err := buildAdminHandler(cfg, st, logger, notifier, mon, engine)
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
	// Emit a startup_bind_warning alert for any listener bound to a non-loopback
	// address (DESIGN.md §11) — the notify dispatcher is running by now.
	emitBindWarnings(cfg, notifier)
	return serveBoth(ctx, cfg, gw, adminHandler, logger, nil, nil)
}

// bindEventSink is the minimal notify surface emitBindWarnings needs (satisfied
// by *notify.Engine); it keeps the helper unit-testable with a fake.
type bindEventSink interface {
	Emit(ev model.NotifyEvent)
}

// isLoopbackHost reports whether host is a loopback bind (no alert needed).
func isLoopbackHost(host string) bool {
	switch host {
	case "127.0.0.1", "localhost", "::1", "":
		return true
	}
	return false
}

// emitBindWarnings emits one EventStartupBindWarning per listener bound to a
// non-loopback address. Secret-free; best-effort.
func emitBindWarnings(cfg model.Config, sink bindEventSink) {
	if sink == nil {
		return
	}
	for _, l := range []struct{ name, host string }{
		{"proxy", cfg.Server.Proxy.Host},
		{"admin", cfg.Server.Admin.Host},
	} {
		if isLoopbackHost(l.host) {
			continue
		}
		sink.Emit(model.NotifyEvent{
			Kind: model.EventStartupBindWarning,
			Message: fmt.Sprintf("poolgate: the %s listener is bound to a non-loopback address (%s); "+
				"front it with a reverse proxy and keep access controlled", l.name, l.host),
			At: time.Now().UTC(),
		})
	}
}

// buildAdminHandler constructs the loopback admin API handler: the admin-auth
// manager (sessions / CSRF / recovery / bootstrap tokens), the WebAuthn service
// (RP resolved once from static admin config, gated by that manager as its
// authorizer), and the admin HTTP server that mounts them. It returns the fully
// middleware-wrapped handler (strict security headers + CSP + same-origin CORS).
func buildAdminHandler(cfg model.Config, st *store.Store, logger *slog.Logger, notifier admin.Notifier, mon admin.MonitorStream, skew admin.ClockSkewSource) (http.Handler, error) {
	mgr, err := adminauth.New(st)
	if err != nil {
		return nil, fmt.Errorf("admin auth: %w", err)
	}
	wa, err := webauthnsvc.New(cfg, st, webauthnsvc.WithAuthorizer(mgr))
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}
	opts := []admin.Option{admin.WithNotifier(notifier), admin.WithMonitor(mon), admin.WithLogger(logger)}
	// Interactive "sign in with ChatGPT" account import from the admin UI. Uses the
	// same pinned OAuth flow as the `poolgate login` CLI; the loopback callback
	// (127.0.0.1:1455/1457) requires the operator's browser to be on this host.
	opts = append(opts, admin.WithOAuthLogin(oauth.NewLogin()))
	if skew != nil {
		opts = append(opts, admin.WithClockSkew(skew))
	}
	// trusted_proxies were validated in loadConfig; parse is infallible here.
	if trusted, _ := clientip.ParseCIDRs(cfg.Server.TrustedProxies); len(trusted) > 0 {
		opts = append(opts, admin.WithTrustedProxies(trusted))
	}
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
	addr := net.JoinHostPort(cfg.Server.Proxy.Host, strconv.Itoa(cfg.Server.Proxy.Port))
	// drainStreams=false: proxy relays are FINITE responses whose upstream request
	// is bound to r.Context(); cancelling them at shutdown would truncate a
	// response (losing the terminal usage event) that would otherwise complete
	// within the Shutdown grace. So the proxy relies on Shutdown's timed drain.
	return serveListener(ctx, addr, gw.Routes(), false, func(bound string) {
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
	addr := net.JoinHostPort(cfg.Server.Admin.Host, strconv.Itoa(cfg.Server.Admin.Port))
	// drainStreams=true: the monitor SSE feed is an INFINITE stream that never ends
	// on its own, so cancelling its request context is the only way to drain it
	// without waiting out the Shutdown deadline. Normal admin handlers finish their
	// Write regardless of the context, so this only affects the SSE feed.
	return serveListener(ctx, addr, handler, true, func(bound string) {
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
// (5s drain deadline) when ctx is cancelled. When drainStreams is true, every
// request context is cancelled at the start of shutdown so infinite streaming
// handlers (the monitor SSE feed) drain promptly instead of waiting out the
// deadline; when false, in-flight requests keep running until they finish or the
// deadline elapses (used by the proxy so finite relays complete intact).
func serveListener(ctx context.Context, addr string, handler http.Handler, drainStreams bool, onReady func(bound string)) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	// When draining streams, every request gets a context derived from baseCtx;
	// cancelling baseCtx at shutdown unblocks handlers that select on r.Context()
	// (the monitor SSE feed). Short handlers mid-Write are unaffected (Write does
	// not consult the context). When not draining, leave BaseContext at its
	// default so Shutdown's timed grace applies to in-flight requests.
	baseCtx, baseCancel := context.WithCancel(context.Background())
	defer baseCancel()
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if drainStreams {
		srv.BaseContext = func(net.Listener) context.Context { return baseCtx }
	}
	if onReady != nil {
		onReady(ln.Addr().String())
	}

	// Graceful shutdown on context cancellation. For a draining listener, signal
	// streaming handlers to finish (cancel their request contexts) first; then
	// Shutdown with a bounded deadline as the backstop.
	go func() {
		<-ctx.Done()
		if drainStreams {
			baseCancel()
		}
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
func newHealthEngine(st *store.Store, refresher *oauth.Refresher, probeMode, proactiveRefresh string, logger *slog.Logger, events health.EventSink) *health.Engine {
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
	// proactiveRefresh was validated at config load; empty keeps the engine default,
	// an explicit value (incl. "0" to disable) overrides it.
	if s := strings.TrimSpace(proactiveRefresh); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			opts = append(opts, health.WithProactiveRefresh(d))
		}
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
