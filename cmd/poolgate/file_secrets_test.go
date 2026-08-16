package main

import (
	"context"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestEnvValueFileConvention covers the <NAME>_FILE secrets convention: the
// _FILE variant takes precedence, its trailing newline is trimmed, a missing
// file errors, and with neither set the value is empty.
func TestEnvValueFileConvention(t *testing.T) {
	const name = "POOLGATE_TEST_SECRET"

	// Plain env value.
	t.Setenv(name, "plain")
	t.Setenv(name+"_FILE", "")
	if v, err := envValue(name); err != nil || v != "plain" {
		t.Fatalf("plain env: got %q err=%v, want plain", v, err)
	}

	// _FILE takes precedence and trims the trailing newline.
	dir := t.TempDir()
	f := filepath.Join(dir, "secret")
	if err := os.WriteFile(f, []byte("fromfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(name+"_FILE", f)
	if v, err := envValue(name); err != nil || v != "fromfile" {
		t.Fatalf("_FILE precedence: got %q err=%v, want fromfile", v, err)
	}

	// Missing _FILE path errors.
	t.Setenv(name+"_FILE", filepath.Join(dir, "does-not-exist"))
	if _, err := envValue(name); err == nil {
		t.Fatal("expected an error for a missing _FILE path")
	}

	// Neither set → empty.
	t.Setenv(name, "")
	t.Setenv(name+"_FILE", "")
	if v, err := envValue(name); err != nil || v != "" {
		t.Fatalf("unset: got %q err=%v, want empty", v, err)
	}
}

// TestMasterKeyFileConvention exercises loadMasterKey's env source reading the
// key from POOLGATE_MASTER_KEY_FILE end-to-end: init + import succeed and the
// account is decryptable on reopen with the same file-provided key.
func TestMasterKeyFileConvention(t *testing.T) {
	ctx := context.Background()

	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 5)
	}
	keyFile := filepath.Join(t.TempDir(), "master.b64")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(raw)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envMasterKey+"_FILE", keyFile)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, configFile), []byte("master_key_source: env\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envDataDir, dir)

	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init with _FILE key: %v", err)
	}
	if err := run(ctx, []string{"import", writeAuthJSON(t)}, io.Discard, io.Discard); err != nil {
		t.Fatalf("import: %v", err)
	}
	// No plaintext keyfile should have been written (env source).
	if _, err := os.Stat(filepath.Join(dir, masterKeyFile)); !os.IsNotExist(err) {
		t.Fatalf("env-source install unexpectedly wrote a keyfile: %v", err)
	}

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	st, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore with _FILE key: %v", err)
	}
	defer st.Close()
	accts, err := st.ListAccounts(ctx)
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(accts) != 1 {
		t.Fatalf("account count = %d, want 1", len(accts))
	}
}

// TestReadPassphraseFileEnv confirms the backup passphrase honors the
// POOLGATE_BACKUP_PASSPHRASE_FILE convention.
func TestReadPassphraseFileEnv(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "pp")
	if err := os.WriteFile(f, []byte("filepass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envBackupPassphrase, "")
	t.Setenv(envBackupPassphrase+"_FILE", f)

	got, err := readPassphrase("")
	if err != nil || string(got) != "filepass" {
		t.Fatalf("passphrase via _FILE: got %q err=%v, want filepass", got, err)
	}
}
