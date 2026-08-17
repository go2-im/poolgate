package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/oauth"
)

// TestParseImportArgs covers path/strategy extraction and validation.
func TestParseImportArgs(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantPath     string
		wantStrategy model.Strategy
		wantErr      bool
	}{
		{"path only defaults fallback", []string{"a.json"}, "a.json", model.StrategyFallback, false},
		{"flag before path", []string{"--strategy", "best-quota", "a.json"}, "a.json", model.StrategyBestQuota, false},
		{"flag after path", []string{"a.json", "--strategy", "load-balance"}, "a.json", model.StrategyLoadBalance, false},
		{"equals form", []string{"--strategy=best-quota", "a.json"}, "a.json", model.StrategyBestQuota, false},
		{"single-dash equals form", []string{"-strategy=load-balance", "a.json"}, "a.json", model.StrategyLoadBalance, false},
		{"single-dash flag", []string{"-strategy", "fallback", "a.json"}, "a.json", model.StrategyFallback, false},
		{"missing path", []string{"--strategy", "fallback"}, "", "", true},
		{"missing strategy value", []string{"--strategy"}, "", "", true},
		{"invalid strategy", []string{"--strategy", "round-robin", "a.json"}, "", "", true},
		{"no args", nil, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, strategy, _, err := parseImportArgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseImportArgs(%v) err = %v, wantErr = %v", tt.args, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if path != tt.wantPath || strategy != tt.wantStrategy {
				t.Errorf("parseImportArgs(%v) = (%q,%q), want (%q,%q)",
					tt.args, path, strategy, tt.wantPath, tt.wantStrategy)
			}
		})
	}
}

// TestValidStrategy covers the strategy whitelist.
func TestValidStrategy(t *testing.T) {
	for _, s := range []model.Strategy{model.StrategyFallback, model.StrategyBestQuota, model.StrategyLoadBalance} {
		if !validStrategy(s) {
			t.Errorf("validStrategy(%q) = false, want true", s)
		}
	}
	for _, s := range []model.Strategy{"", "url-test", "bogus"} {
		if validStrategy(s) {
			t.Errorf("validStrategy(%q) = true, want false", s)
		}
	}
}

// TestImportStrategyPersisted drives `import --strategy best-quota` end-to-end and
// asserts the created default group carries that strategy.
func TestImportStrategyPersisted(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(envDataDir, dataDir)
	t.Setenv(envMasterKey, "")
	if err := cmdInit(nil, io.Discard); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}
	authPath := writeAuthJSON(t)
	if err := cmdImport([]string{"--strategy", "best-quota", authPath}, io.Discard); err != nil {
		t.Fatalf("cmdImport: %v", err)
	}

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	st, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer st.Close()
	ctx := context.Background()
	ep, err := st.GetEndpoint(ctx, defaultEndpointName)
	if err != nil {
		t.Fatalf("GetEndpoint: %v", err)
	}
	grp, err := st.GetPolicyGroup(ctx, ep.GroupID)
	if err != nil {
		t.Fatalf("GetPolicyGroup: %v", err)
	}
	if grp.Strategy != model.StrategyBestQuota {
		t.Errorf("group strategy = %q, want best-quota", grp.Strategy)
	}
}

// TestImportInvalidStrategyErrors ensures a bad --strategy is rejected before any
// store mutation.
func TestImportInvalidStrategyErrors(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(envDataDir, dataDir)
	t.Setenv(envMasterKey, "")
	if err := cmdInit(nil, io.Discard); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}
	err := cmdImport([]string{"--strategy", "nonsense", writeAuthJSON(t)}, io.Discard)
	if err == nil {
		t.Fatal("cmdImport with invalid strategy = nil, want error")
	}
}

// TestNewHealthEngineProbeModes covers both probe-mode branches.
func TestNewHealthEngineProbeModes(t *testing.T) {
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
	st, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer st.Close()

	refresher := oauth.NewRefresher(st, cfg.Issuer)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	if e := newHealthEngine(st, refresher, "usage-poll-only", "", logger, nil); e == nil {
		t.Fatal("newHealthEngine(usage-poll-only) = nil")
	}
	if e := newHealthEngine(st, refresher, "allow-live", "", logger, nil); e == nil {
		t.Fatal("newHealthEngine(allow-live) = nil")
	}
}

// TestCmdServeAllowLive drives cmdServe with the allow-live probe mode so the
// live-probe wiring branch executes, then cancels for a clean shutdown.
func TestCmdServeAllowLive(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(envDataDir, dataDir)
	t.Setenv(envMasterKey, "")
	if err := os.WriteFile(filepath.Join(dataDir, configFile),
		[]byte("server:\n  proxy:\n    host: 127.0.0.1\n    port: 0\n  admin:\n    host: 127.0.0.1\n    port: 0\nhealth_probe_mode: allow-live\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := cmdInit(nil, io.Discard); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- cmdServe(ctx, nil, io.Discard) }()
	time.Sleep(150 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("cmdServe(allow-live) = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cmdServe(allow-live) did not return after cancel")
	}
}
