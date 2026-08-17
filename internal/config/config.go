// Package config loads poolgate's YAML configuration and applies safe defaults:
// loopback binds, the pinned upstream allowlist, and the pinned OAuth issuer
// (DESIGN.md §6 / §7). The config file is optional; Load returns a fully
// defaulted Config when path is empty or the file is absent.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/go2-im/poolgate/internal/model"
	"gopkg.in/yaml.v3"
)

// SynthesizeAdminOrigin computes the single canonical browser-facing origin for
// the admin listener (scheme://host[:port]). It is the ONE place the origin is
// derived so the admin server's CORS/cookie origin and the WebAuthn RP origin can
// never diverge. An explicit external_origin wins; otherwise the host/port
// defaults apply and a loopback IP bind (127.0.0.1 / ::1) is mapped to
// "localhost" — browsers reject bare-IP WebAuthn RP IDs, and localhost resolves
// to the same loopback bind.
func SynthesizeAdminOrigin(admin model.ListenConfig) string {
	if o := strings.TrimSpace(admin.ExternalOrigin); o != "" {
		return o
	}
	host := strings.TrimSpace(admin.Host)
	if host == "" {
		host = DefaultAdminHost
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		host = "localhost"
	}
	port := admin.Port
	if port == 0 {
		port = DefaultAdminPort
	}
	return fmt.Sprintf("http://%s:%d", host, port)
}

// Defaults for the two listeners and pinned egress values.
const (
	DefaultAdminHost = "127.0.0.1"
	DefaultAdminPort = 7070
	DefaultProxyHost = "127.0.0.1"
	DefaultProxyPort = 8787

	DefaultDataDir         = "poolgate-data"
	DefaultMasterKeySource = "keyfile"

	// DefaultHealthProbeMode is the global health-probe cost policy: usage-poll
	// only (zero token spend). "allow-live" opts into small-live-requests
	// (DESIGN.md §12). It is the safe default so no account is billed by probes.
	DefaultHealthProbeMode = "usage-poll-only"

	// DefaultIssuer is the OAuth token endpoint, pinned regardless of any `iss`
	// claim in imported tokens (DESIGN.md §0 D6 / §6).
	DefaultIssuer = "https://auth.openai.com/oauth/token"

	// DefaultTransport offers both proxy transports (accept the WS upgrade and
	// serve HTTP+SSE). See model.ServerConfig.Transport (DESIGN.md §0 D2).
	DefaultTransport = "both"
)

// DefaultUpstreamAllowlist is the set of hosts poolgate may send
// Authorization-bearing egress to (DESIGN.md §6).
func DefaultUpstreamAllowlist() []string {
	return []string{"chatgpt.com", "api.openai.com"}
}

// Default returns a Config populated entirely with loopback defaults.
func Default() model.Config {
	return model.Config{
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
}

// Load reads YAML from path and overlays it on Default(). An empty path or a
// missing file yields the pure defaults. Any value present in the file wins;
// omitted fields keep their default.
func Load(path string) (model.Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("config: read %q: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("config: parse %q: %w", path, err)
	}
	applyDefaults(&cfg)
	return cfg, nil
}

// applyDefaults fills any zero-valued fields left empty by the YAML overlay.
func applyDefaults(cfg *model.Config) {
	if cfg.Server.Admin.Host == "" {
		cfg.Server.Admin.Host = DefaultAdminHost
	}
	if cfg.Server.Admin.Port == 0 {
		cfg.Server.Admin.Port = DefaultAdminPort
	}
	if cfg.Server.Proxy.Host == "" {
		cfg.Server.Proxy.Host = DefaultProxyHost
	}
	if cfg.Server.Proxy.Port == 0 {
		cfg.Server.Proxy.Port = DefaultProxyPort
	}
	if cfg.DataDir == "" {
		cfg.DataDir = DefaultDataDir
	}
	if cfg.MasterKeySource == "" {
		cfg.MasterKeySource = DefaultMasterKeySource
	}
	if len(cfg.UpstreamAllowlist) == 0 {
		cfg.UpstreamAllowlist = DefaultUpstreamAllowlist()
	}
	if cfg.Issuer == "" {
		cfg.Issuer = DefaultIssuer
	}
	if cfg.HealthProbeMode == "" {
		cfg.HealthProbeMode = DefaultHealthProbeMode
	}
	if cfg.Server.Transport == "" {
		cfg.Server.Transport = DefaultTransport
	}
}
