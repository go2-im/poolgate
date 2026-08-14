package config

import (
	"os"
	"path/filepath"
	"testing"
)

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
