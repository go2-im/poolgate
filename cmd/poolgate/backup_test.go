package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/store"
)

// TestBackupRestoreRoundTrip provisions a data dir, backs it up, restores into a
// fresh data dir, and verifies the imported account survives — proving the
// master key + DB travel together in the bundle.
func TestBackupRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()

	// Provision dir A: init + import one account.
	dirA := t.TempDir()
	t.Setenv(envDataDir, dirA)
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	authPath := writeAuthJSON(t)
	if err := run(ctx, []string{"import", authPath}, io.Discard, io.Discard); err != nil {
		t.Fatalf("import: %v", err)
	}

	// Back up (passphrase via env).
	t.Setenv(envBackupPassphrase, "correct horse battery staple")
	bundle := filepath.Join(t.TempDir(), "poolgate.pgbak")
	var out bytes.Buffer
	if err := run(ctx, []string{"backup", "--out", bundle}, &out, io.Discard); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if _, err := os.Stat(bundle); err != nil {
		t.Fatalf("bundle not written: %v", err)
	}
	// The bundle must never contain the passphrase in the clear.
	b, _ := os.ReadFile(bundle)
	if bytes.Contains(b, []byte("correct horse battery staple")) {
		t.Fatal("bundle leaked the passphrase in cleartext")
	}

	// Restore into a fresh dir B.
	dirB := t.TempDir()
	t.Setenv(envDataDir, dirB)
	if err := run(ctx, []string{"restore", bundle}, &out, io.Discard); err != nil {
		t.Fatalf("restore: %v", err)
	}
	// The restored keyfile + DB must exist.
	if _, err := os.Stat(filepath.Join(dirB, masterKeyFile)); err != nil {
		t.Fatalf("restored master key missing: %v", err)
	}

	// Open the restored store and confirm the account is readable (decryptable
	// with the restored master key).
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	st, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore(restored): %v", err)
	}
	defer st.Close()
	accts, err := st.ListAccounts(ctx)
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(accts) != 1 {
		t.Fatalf("restored account count = %d, want 1", len(accts))
	}
}

// TestBackupRefusesToMintKeyWhenMissing asserts that backup errors (rather than
// minting a fresh key and producing an unrestorable bundle) when the keyfile is
// absent for a data dir that was never initialized.
func TestBackupRefusesToMintKeyWhenMissing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)
	t.Setenv(envBackupPassphrase, "pw-123456")
	bundle := filepath.Join(t.TempDir(), "b.pgbak")

	err := run(ctx, []string{"backup", "--out", bundle}, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("backup on an uninitialized data dir should error, not mint a key")
	}
	// No stray master.key should have been created as a side effect.
	if _, statErr := os.Stat(filepath.Join(dir, "master.key")); statErr == nil {
		t.Fatal("backup created a stray master.key on a data dir with no database")
	}
	if _, statErr := os.Stat(bundle); statErr == nil {
		t.Fatal("backup wrote a bundle despite failing")
	}
}

// TestRestoreRefusesOverwrite asserts restore won't clobber an existing install
// without --force, and succeeds with it.
func TestRestoreRefusesOverwrite(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Setenv(envBackupPassphrase, "pw-123456")
	bundle := filepath.Join(t.TempDir(), "b.pgbak")
	if err := run(ctx, []string{"backup", "--out", bundle}, io.Discard, io.Discard); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// Restoring over the existing dir must fail without --force.
	if err := run(ctx, []string{"restore", bundle}, io.Discard, io.Discard); err == nil {
		t.Fatal("expected restore to refuse overwriting an existing install")
	}
	// With --force it proceeds.
	if err := run(ctx, []string{"restore", bundle, "--force"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("restore --force: %v", err)
	}
}

// TestRestoreEnvSourceRefusesKeyMismatch asserts that restoring an env-source
// bundle into an environment whose POOLGATE_MASTER_KEY differs from the bundle's
// key is refused up front (rather than "succeeding" and failing at next serve).
func TestRestoreEnvSourceRefusesKeyMismatch(t *testing.T) {
	ctx := context.Background()
	envConfig := []byte("master_key_source: env\n")

	k1 := make([]byte, 32)
	for i := range k1 {
		k1[i] = byte(i + 1)
	}
	t.Setenv(envMasterKey, base64.StdEncoding.EncodeToString(k1))

	dirA := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirA, configFile), envConfig, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(envDataDir, dirA)
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := run(ctx, []string{"import", writeAuthJSON(t)}, io.Discard, io.Discard); err != nil {
		t.Fatalf("import: %v", err)
	}
	t.Setenv(envBackupPassphrase, "mismatch-pass")
	bundle := filepath.Join(t.TempDir(), "m.pgbak")
	if err := run(ctx, []string{"backup", "--out", bundle}, io.Discard, io.Discard); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// Restore into a fresh env-source dir but with a DIFFERENT env key.
	k2 := make([]byte, 32)
	for i := range k2 {
		k2[i] = byte(200 - i)
	}
	t.Setenv(envMasterKey, base64.StdEncoding.EncodeToString(k2))
	dirB := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirB, configFile), envConfig, 0o600); err != nil {
		t.Fatalf("write config B: %v", err)
	}
	t.Setenv(envDataDir, dirB)
	if err := run(ctx, []string{"restore", bundle}, io.Discard, io.Discard); err == nil {
		t.Fatal("restore should refuse when the env key does not match the bundle key")
	}
}

// TestRestoreEnvSourceSkipsKeyfile asserts that under master_key_source=env the
// restore writes the DB but NOT a plaintext master.key (respecting the operator's
// choice to keep the key off disk), and the restored DB decrypts with the env key.
func TestRestoreEnvSourceSkipsKeyfile(t *testing.T) {
	ctx := context.Background()

	// A stable 32-byte master key supplied via the environment.
	rawKey := make([]byte, 32)
	for i := range rawKey {
		rawKey[i] = byte(i * 3)
	}
	t.Setenv(envMasterKey, base64.StdEncoding.EncodeToString(rawKey))

	envConfig := []byte("master_key_source: env\n")

	// Provision dir A (env source) and import an account.
	dirA := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirA, configFile), envConfig, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(envDataDir, dirA)
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := run(ctx, []string{"import", writeAuthJSON(t)}, io.Discard, io.Discard); err != nil {
		t.Fatalf("import: %v", err)
	}
	// An env-source install must not have written a keyfile.
	if _, err := os.Stat(filepath.Join(dirA, masterKeyFile)); !os.IsNotExist(err) {
		t.Fatalf("env-source install unexpectedly has a keyfile: %v", err)
	}

	// Back up.
	t.Setenv(envBackupPassphrase, "env-source-pass")
	bundle := filepath.Join(t.TempDir(), "env.pgbak")
	if err := run(ctx, []string{"backup", "--out", bundle}, io.Discard, io.Discard); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// Restore into a fresh env-source dir B.
	dirB := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirB, configFile), envConfig, 0o600); err != nil {
		t.Fatalf("write config B: %v", err)
	}
	t.Setenv(envDataDir, dirB)
	var out bytes.Buffer
	if err := run(ctx, []string{"restore", bundle}, &out, io.Discard); err != nil {
		t.Fatalf("restore: %v", err)
	}
	// The keyfile must NOT be written; the DB must be.
	if _, err := os.Stat(filepath.Join(dirB, masterKeyFile)); !os.IsNotExist(err) {
		t.Fatalf("restore wrote a keyfile under env source: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("NOT written to disk")) {
		t.Errorf("expected env-source warning in output, got: %q", out.String())
	}

	// The DB decrypts with the env key.
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	st, err := openStore(cfg)
	if err != nil {
		t.Fatalf("openStore(restored env): %v", err)
	}
	defer st.Close()
	accts, err := st.ListAccounts(ctx)
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(accts) != 1 {
		t.Fatalf("restored account count = %d, want 1", len(accts))
	}
}

func TestBackupRestoreErrors(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}

	// No passphrase set → backup errors.
	os.Unsetenv(envBackupPassphrase)
	if err := run(ctx, []string{"backup", "--out", filepath.Join(t.TempDir(), "x.pgbak")}, io.Discard, io.Discard); err == nil {
		t.Fatal("expected backup to fail with no passphrase")
	}

	// Make a real bundle.
	t.Setenv(envBackupPassphrase, "right-passphrase")
	bundle := filepath.Join(t.TempDir(), "b.pgbak")
	if err := run(ctx, []string{"backup", "--out", bundle}, io.Discard, io.Discard); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// Wrong passphrase on restore → error, into a fresh dir.
	t.Setenv(envDataDir, t.TempDir())
	t.Setenv(envBackupPassphrase, "wrong-passphrase")
	if err := run(ctx, []string{"restore", bundle}, io.Discard, io.Discard); err == nil {
		t.Fatal("expected restore to fail with the wrong passphrase")
	}
}

// TestServeRefusesWithRestoreMarker asserts serve won't start if a restore was
// interrupted (marker present), before touching the store.
func TestServeRefusesWithRestoreMarker(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)
	if err := os.WriteFile(filepath.Join(dir, restoreMarkerFile), []byte("x"), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	err := run(ctx, []string{"serve"}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "interrupted restore") {
		t.Fatalf("serve err = %v, want interrupted-restore refusal", err)
	}
}

// TestRestoreLeavesNoResidue asserts a successful restore removes the marker and
// the saved-aside previous generation.
func TestRestoreLeavesNoResidue(t *testing.T) {
	ctx := context.Background()
	dirA := t.TempDir()
	t.Setenv(envDataDir, dirA)
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Setenv(envBackupPassphrase, "residue-pass")
	bundle := filepath.Join(t.TempDir(), "r.pgbak")
	if err := run(ctx, []string{"backup", "--out", bundle}, io.Discard, io.Discard); err != nil {
		t.Fatalf("backup: %v", err)
	}
	// Restore over the same (existing) install with --force so old files are moved
	// aside and then cleaned up.
	if err := run(ctx, []string{"restore", bundle, "--force"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("restore --force: %v", err)
	}
	entries, err := os.ReadDir(dirA)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		n := e.Name()
		if n == restoreMarkerFile || strings.HasSuffix(n, ".prev") || strings.HasSuffix(n, ".tmp") {
			t.Errorf("restore left residue file %q", n)
		}
	}
}

// TestRestoreRollbackRestoresOldGenerationOnFailure forces a failure DURING the
// destructive commit (a saveAside that cannot move the old key aside) and asserts
// the rollback (a) returns an error, (b) restores the original DB + key, and (c)
// clears the restore marker because the old generation was fully recovered.
func TestRestoreRollbackRestoresOldGenerationOnFailure(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)
	if err := run(ctx, []string{"init"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Setenv(envBackupPassphrase, "rollback-pass")
	bundle := filepath.Join(t.TempDir(), "rb.pgbak")
	if err := run(ctx, []string{"backup", "--out", bundle}, io.Discard, io.Discard); err != nil {
		t.Fatalf("backup: %v", err)
	}

	keyPath := filepath.Join(dir, masterKeyFile)
	origKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read original key: %v", err)
	}
	// Block saveAside(keyPath): make "<keyPath>.prev" a NON-EMPTY directory so the
	// rename of the live key aside fails (ENOTEMPTY), triggering the rollback path
	// AFTER the DB was already moved aside.
	blocker := keyPath + ".prev"
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatalf("mkdir blocker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blocker, "x"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}

	err = run(ctx, []string{"restore", bundle, "--force"}, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("restore should fail when the old key cannot be staged aside")
	}
	// Clean the blocker so we can inspect the final state.
	_ = os.RemoveAll(blocker)

	// The original master key is back in place (rollback restored the DB it had
	// moved aside; the key was never moved so it is untouched).
	gotKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("key missing after rollback: %v", err)
	}
	if !bytes.Equal(gotKey, origKey) {
		t.Fatal("master key not preserved across a failed restore")
	}
	if _, err := os.Stat(filepath.Join(dir, store.DBFileName)); err != nil {
		t.Fatalf("database not restored after rollback: %v", err)
	}
	// The rollback fully recovered the old generation, so the marker is cleared.
	if _, err := os.Stat(filepath.Join(dir, restoreMarkerFile)); !os.IsNotExist(err) {
		t.Fatalf("restore marker should be cleared after a clean rollback: %v", err)
	}
	// The recovered install still serves: a fresh backup (which opens the store with
	// the restored key) succeeds.
	if err := run(ctx, []string{"backup", "--out", filepath.Join(t.TempDir(), "after.pgbak")}, io.Discard, io.Discard); err != nil {
		t.Fatalf("recovered install unusable: %v", err)
	}
}

func TestLoadMasterKeyExisting(t *testing.T) {
	// env source: returns the env key and never writes a keyfile.
	dir := t.TempDir()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 5)
	}
	t.Setenv(envMasterKey, base64.StdEncoding.EncodeToString(raw))
	got, err := loadMasterKeyExisting(model.Config{DataDir: dir, MasterKeySource: "env"})
	if err != nil {
		t.Fatalf("loadMasterKeyExisting(env): %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("env key mismatch")
	}
	if _, err := os.Stat(filepath.Join(dir, masterKeyFile)); !os.IsNotExist(err) {
		t.Errorf("env source must not create a keyfile")
	}

	// keyfile source with no keyfile: hard error (never mints).
	if _, err := loadMasterKeyExisting(model.Config{DataDir: t.TempDir()}); err == nil {
		t.Errorf("keyfile source with missing keyfile should error, not mint")
	}
}
