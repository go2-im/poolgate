package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/go2-im/poolgate/internal/model"
)

// TestDefault asserts every field of the pure-default Config.
func TestDefault(t *testing.T) {
	cfg := Default()
	want := model.Config{
		Server: model.ServerConfig{
			Admin:     model.ListenConfig{Host: DefaultAdminHost, Port: DefaultAdminPort},
			Proxy:     model.ListenConfig{Host: DefaultProxyHost, Port: DefaultProxyPort},
			Transport: DefaultTransport,
		},
		DataDir:           DefaultDataDir,
		MasterKeySource:   DefaultMasterKeySource,
		UpstreamAllowlist: DefaultUpstreamAllowlist(),
		Issuer:            DefaultIssuer,
		HealthProbeMode:   DefaultHealthProbeMode,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("Default() = %+v, want %+v", cfg, want)
	}
}

// TestDefaultUpstreamAllowlistFreshSlice ensures callers can't mutate shared
// state: each call must return an independent slice.
func TestDefaultUpstreamAllowlistFreshSlice(t *testing.T) {
	a := DefaultUpstreamAllowlist()
	if len(a) != 2 || a[0] != "chatgpt.com" || a[1] != "api.openai.com" {
		t.Fatalf("allowlist = %v", a)
	}
	a[0] = "evil.example"
	b := DefaultUpstreamAllowlist()
	if b[0] != "chatgpt.com" {
		t.Fatalf("allowlist not fresh per call: %v", b)
	}
}

func TestLoadDefaultsOnEmptyPath(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\"): %v", err)
	}
	if cfg.Server.Admin.Host != DefaultAdminHost || cfg.Server.Admin.Port != DefaultAdminPort {
		t.Fatalf("admin default = %+v", cfg.Server.Admin)
	}
	if cfg.Server.Proxy.Host != DefaultProxyHost || cfg.Server.Proxy.Port != DefaultProxyPort {
		t.Fatalf("proxy default = %+v", cfg.Server.Proxy)
	}
	if cfg.Issuer != DefaultIssuer {
		t.Fatalf("issuer default = %q", cfg.Issuer)
	}
	if len(cfg.UpstreamAllowlist) != 2 {
		t.Fatalf("allowlist default = %v", cfg.UpstreamAllowlist)
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("Load(missing): %v", err)
	}
	if cfg.Issuer != DefaultIssuer {
		t.Fatal("missing file should yield defaults")
	}
}

func TestLoadOverlayKeepsUnsetDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := "server:\n  proxy:\n    port: 9999\ndata_dir: /tmp/pg\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Proxy.Port != 9999 {
		t.Fatalf("proxy port = %d want 9999", cfg.Server.Proxy.Port)
	}
	// Unset by YAML → default retained.
	if cfg.Server.Proxy.Host != DefaultProxyHost {
		t.Fatalf("proxy host = %q want default", cfg.Server.Proxy.Host)
	}
	if cfg.Server.Admin.Port != DefaultAdminPort {
		t.Fatalf("admin port = %d want default", cfg.Server.Admin.Port)
	}
	if cfg.DataDir != "/tmp/pg" {
		t.Fatalf("data_dir = %q", cfg.DataDir)
	}
	if cfg.Issuer != DefaultIssuer {
		t.Fatalf("issuer = %q want default", cfg.Issuer)
	}
}

// TestLoadFullYAMLOverridesEveryField supplies a value for every field so the
// applyDefaults "already set" (false) branches are exercised and no default
// leaks through.
func TestLoadFullYAMLOverridesEveryField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "full.yaml")
	yaml := "" +
		"server:\n" +
		"  admin:\n" +
		"    host: 10.0.0.1\n" +
		"    port: 1111\n" +
		"  proxy:\n" +
		"    host: 10.0.0.2\n" +
		"    port: 2222\n" +
		"  transport: ws-only\n" +
		"data_dir: /var/pg\n" +
		"master_key_source: env\n" +
		"upstream_allowlist:\n" +
		"  - a.example\n" +
		"  - b.example\n" +
		"issuer: https://issuer.example/token\n" +
		"health_probe_mode: allow-live\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := model.Config{
		Server: model.ServerConfig{
			Admin:     model.ListenConfig{Host: "10.0.0.1", Port: 1111},
			Proxy:     model.ListenConfig{Host: "10.0.0.2", Port: 2222},
			Transport: "ws-only",
		},
		DataDir:           "/var/pg",
		MasterKeySource:   "env",
		UpstreamAllowlist: []string{"a.example", "b.example"},
		Issuer:            "https://issuer.example/token",
		HealthProbeMode:   "allow-live",
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("Load(full) = %+v, want %+v", cfg, want)
	}
}

// TestLoadEmptyYAMLAppliesAllDefaults loads a YAML document that sets nothing,
// so every applyDefaults "was empty" (true) branch fires.
func TestLoadEmptyYAMLAppliesAllDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yaml")
	// A lone comment / empty mapping leaves all fields zero-valued.
	if err := os.WriteFile(path, []byte("# nothing here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(cfg, Default()) {
		t.Fatalf("Load(empty yaml) = %+v, want Default() %+v", cfg, Default())
	}
}

// TestLoadBadYAMLReturnsParseError exercises the yaml.Unmarshal error branch.
// On error, Load must return the (defaulted) config and a wrapped error.
func TestLoadBadYAMLReturnsParseError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	// Malformed: a scalar where a mapping is expected + unterminated bracket.
	if err := os.WriteFile(path, []byte("server: [this is not: valid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err == nil {
		t.Fatal("Load(bad yaml): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "config: parse") {
		t.Fatalf("error = %q, want wrapped parse error", err)
	}
	// Even on parse failure, the returned config is the pure default.
	if !reflect.DeepEqual(cfg, Default()) {
		t.Fatalf("cfg on parse error = %+v, want Default()", cfg)
	}
}

// TestLoadReadErrorNonNotExist exercises the read-error branch that is NOT
// os.ErrNotExist: passing a directory as the config path makes os.ReadFile
// fail with a non-"not exist" error.
func TestLoadReadErrorNonNotExist(t *testing.T) {
	dir := t.TempDir() // a directory, not a regular file
	cfg, err := Load(dir)
	if err == nil {
		t.Fatal("Load(dir): expected read error, got nil")
	}
	if !strings.Contains(err.Error(), "config: read") {
		t.Fatalf("error = %q, want wrapped read error", err)
	}
	if !reflect.DeepEqual(cfg, Default()) {
		t.Fatalf("cfg on read error = %+v, want Default()", cfg)
	}
}

// TestApplyDefaultsPerField verifies each field is independently defaulted when
// (and only when) it is zero, driving applyDefaults directly.
func TestApplyDefaultsPerField(t *testing.T) {
	tests := []struct {
		name  string
		in    model.Config
		check func(t *testing.T, c model.Config)
	}{
		{
			name: "all zero fills every default",
			in:   model.Config{},
			check: func(t *testing.T, c model.Config) {
				if !reflect.DeepEqual(c, Default()) {
					t.Fatalf("got %+v want Default()", c)
				}
			},
		},
		{
			name: "set admin host retained, port defaulted",
			in:   model.Config{Server: model.ServerConfig{Admin: model.ListenConfig{Host: "1.2.3.4"}}},
			check: func(t *testing.T, c model.Config) {
				if c.Server.Admin.Host != "1.2.3.4" {
					t.Fatalf("admin host = %q", c.Server.Admin.Host)
				}
				if c.Server.Admin.Port != DefaultAdminPort {
					t.Fatalf("admin port = %d", c.Server.Admin.Port)
				}
			},
		},
		{
			name: "set proxy port retained, host defaulted",
			in:   model.Config{Server: model.ServerConfig{Proxy: model.ListenConfig{Port: 4242}}},
			check: func(t *testing.T, c model.Config) {
				if c.Server.Proxy.Port != 4242 {
					t.Fatalf("proxy port = %d", c.Server.Proxy.Port)
				}
				if c.Server.Proxy.Host != DefaultProxyHost {
					t.Fatalf("proxy host = %q", c.Server.Proxy.Host)
				}
			},
		},
		{
			name: "set data_dir and master_key_source retained",
			in:   model.Config{DataDir: "/d", MasterKeySource: "env"},
			check: func(t *testing.T, c model.Config) {
				if c.DataDir != "/d" || c.MasterKeySource != "env" {
					t.Fatalf("data/mks = %q/%q", c.DataDir, c.MasterKeySource)
				}
			},
		},
		{
			name: "set allowlist retained, issuer defaulted",
			in:   model.Config{UpstreamAllowlist: []string{"only.example"}},
			check: func(t *testing.T, c model.Config) {
				if len(c.UpstreamAllowlist) != 1 || c.UpstreamAllowlist[0] != "only.example" {
					t.Fatalf("allowlist = %v", c.UpstreamAllowlist)
				}
				if c.Issuer != DefaultIssuer {
					t.Fatalf("issuer = %q", c.Issuer)
				}
			},
		},
		{
			name: "set issuer retained, allowlist defaulted",
			in:   model.Config{Issuer: "https://x/token"},
			check: func(t *testing.T, c model.Config) {
				if c.Issuer != "https://x/token" {
					t.Fatalf("issuer = %q", c.Issuer)
				}
				if len(c.UpstreamAllowlist) != 2 {
					t.Fatalf("allowlist = %v", c.UpstreamAllowlist)
				}
			},
		},
		{
			name: "set health_probe_mode retained",
			in:   model.Config{HealthProbeMode: "allow-live"},
			check: func(t *testing.T, c model.Config) {
				if c.HealthProbeMode != "allow-live" {
					t.Fatalf("health_probe_mode = %q, want allow-live", c.HealthProbeMode)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.in
			applyDefaults(&cfg)
			tt.check(t, cfg)
		})
	}
}

func TestSynthesizeAdminOrigin(t *testing.T) {
	// Loopback IP bind maps to localhost (browsers reject bare-IP RP IDs).
	if got := SynthesizeAdminOrigin(model.ListenConfig{Host: "127.0.0.1", Port: 7070}); got != "http://localhost:7070" {
		t.Errorf("loopback origin = %q, want http://localhost:7070", got)
	}
	if got := SynthesizeAdminOrigin(model.ListenConfig{Host: "::1", Port: 7070}); got != "http://localhost:7070" {
		t.Errorf("ipv6 loopback origin = %q, want http://localhost:7070", got)
	}
	// Defaults fill in host+port.
	if got := SynthesizeAdminOrigin(model.ListenConfig{}); got != "http://localhost:7070" {
		t.Errorf("default origin = %q, want http://localhost:7070", got)
	}
	// Explicit external_origin wins verbatim.
	if got := SynthesizeAdminOrigin(model.ListenConfig{ExternalOrigin: "https://admin.example.com"}); got != "https://admin.example.com" {
		t.Errorf("external_origin = %q, want it verbatim", got)
	}
	// Non-loopback host is preserved (operator must set a real domain for WebAuthn).
	if got := SynthesizeAdminOrigin(model.ListenConfig{Host: "192.168.1.5", Port: 7070}); got != "http://192.168.1.5:7070" {
		t.Errorf("non-loopback origin = %q, want preserved", got)
	}
}
