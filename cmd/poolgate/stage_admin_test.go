package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go2-im/poolgate/internal/adminauth"
	"github.com/go2-im/poolgate/internal/model"
)

// extractBootstrapToken pulls the "pgbt_..." token out of init / reset-auth
// stdout (it is printed on its own indented line).
func extractBootstrapToken(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		f := strings.TrimSpace(line)
		if strings.HasPrefix(f, "pgbt_") {
			return f
		}
	}
	t.Fatalf("no bootstrap token in output:\n%s", out)
	return ""
}

// TestInitIssuesConsumableBootstrapToken verifies `init` persists a real
// bootstrap token (hash only) and that the printed plaintext is consumable via
// the same adminauth path a later passkey-registration flow would use.
func TestInitIssuesConsumableBootstrapToken(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(envDataDir, dataDir)
	t.Setenv(envMasterKey, "")

	var out bytes.Buffer
	if err := cmdInit(nil, &out); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}
	token := extractBootstrapToken(t, out.String())

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

	// Exactly one bootstrap token persisted, and it is a hash (not the plaintext).
	toks, err := st.ListBootstrapTokens(ctx)
	if err != nil {
		t.Fatalf("ListBootstrapTokens: %v", err)
	}
	if len(toks) != 1 {
		t.Fatalf("bootstrap tokens after init = %d, want 1", len(toks))
	}
	if toks[0].TokenHash == token {
		t.Fatal("bootstrap token persisted in plaintext")
	}

	// The printed plaintext consumes successfully exactly once.
	mgr, err := adminauth.New(st)
	if err != nil {
		t.Fatalf("adminauth.New: %v", err)
	}
	if err := mgr.ConsumeBootstrapToken(ctx, token); err != nil {
		t.Fatalf("ConsumeBootstrapToken(init token): %v", err)
	}
	if err := mgr.ConsumeBootstrapToken(ctx, token); err == nil {
		t.Fatal("ConsumeBootstrapToken(reuse) = nil, want single-use failure")
	}
}

// TestAdminResetAuth exercises the full reset: seed a passkey + recovery code +
// session, run `admin reset-auth`, then confirm everything is wiped and the
// fresh printed token is consumable.
func TestAdminResetAuth(t *testing.T) {
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
	ctx := context.Background()

	// Seed auth state: a passkey, some recovery codes, and a session.
	if _, err := st.InsertWebAuthnCredential(ctx, model.WebAuthnCredential{
		CredID: []byte{1, 2, 3}, PublicKey: []byte{4, 5},
	}); err != nil {
		t.Fatalf("seed passkey: %v", err)
	}
	mgr, err := adminauth.New(st)
	if err != nil {
		t.Fatalf("adminauth.New: %v", err)
	}
	if _, err := mgr.GenerateRecoveryCodes(ctx, 4); err != nil {
		t.Fatalf("seed recovery codes: %v", err)
	}
	if _, err := mgr.CreateSession(ctx); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	_ = st.Close()

	// Run reset-auth through the run() dispatcher (covers cmdAdmin routing too).
	var out bytes.Buffer
	if err := run(ctx, []string{"admin", "reset-auth"}, &out, io.Discard); err != nil {
		t.Fatalf("run admin reset-auth: %v", err)
	}
	freshToken := extractBootstrapToken(t, out.String())

	// Reopen and confirm the wipe.
	st2, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore (post-reset): %v", err)
	}
	defer st2.Close()

	if n, _ := st2.CountWebAuthnCredentials(ctx); n != 0 {
		t.Fatalf("passkeys after reset = %d, want 0", n)
	}
	if codes, _ := st2.ListRecoveryCodes(ctx); len(codes) != 0 {
		t.Fatalf("recovery codes after reset = %d, want 0", len(codes))
	}
	sessN, _ := st2.DeleteAllSessions(ctx)
	if sessN != 0 {
		t.Fatalf("sessions after reset = %d, want 0", sessN)
	}
	// Exactly one fresh bootstrap token, and it consumes once.
	toks, _ := st2.ListBootstrapTokens(ctx)
	if len(toks) != 1 {
		t.Fatalf("bootstrap tokens after reset = %d, want 1 fresh", len(toks))
	}
	mgr2, _ := adminauth.New(st2)
	if err := mgr2.ConsumeBootstrapToken(ctx, freshToken); err != nil {
		t.Fatalf("ConsumeBootstrapToken(reset token): %v", err)
	}
}

// TestAdminUsageErrors covers the usage/dispatch error branches of cmdAdmin.
func TestAdminUsageErrors(t *testing.T) {
	// No subcommand.
	if err := run(context.Background(), []string{"admin"}, io.Discard, io.Discard); err != errUsage {
		t.Fatalf("run admin (no sub) = %v, want errUsage", err)
	}
	// Unknown subcommand.
	if err := run(context.Background(), []string{"admin", "bogus"}, io.Discard, io.Discard); err != errUsage {
		t.Fatalf("run admin bogus = %v, want errUsage", err)
	}
}

// TestAdminResetAuthBadConfig covers the config-load error path in
// cmdAdminResetAuth (env master-key source with an empty key).
func TestAdminResetAuthBadConfig(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv(envDataDir, dataDir)
	// Select env master-key source but leave the key empty → openStore fails.
	if err := os.WriteFile(filepath.Join(dataDir, configFile),
		[]byte("master_key_source: env\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(envMasterKey, "")
	if err := cmdAdminResetAuth(nil, io.Discard); err == nil {
		t.Fatal("cmdAdminResetAuth with empty env key = nil, want error")
	}
}
