package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	c, err := New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := []string{"", "hello", "sk-abc123", "a longer secret with unicode: 你好 🎉"}
	for _, pt := range cases {
		sealed, err := c.Seal(pt)
		if err != nil {
			t.Fatalf("Seal(%q): %v", pt, err)
		}
		if sealed == pt && pt != "" {
			t.Fatalf("Seal did not transform plaintext %q", pt)
		}
		got, err := c.Open(sealed)
		if err != nil {
			t.Fatalf("Open(%q): %v", pt, err)
		}
		if got != pt {
			t.Fatalf("round-trip mismatch: got %q want %q", got, pt)
		}
	}
}

func TestSealUsesFreshNonce(t *testing.T) {
	key := make([]byte, KeySize)
	c, _ := New(key)
	a, _ := c.Seal("same")
	b, _ := c.Seal("same")
	if a == b {
		t.Fatal("expected distinct ciphertexts for repeated Seal (nonce reuse)")
	}
}

func TestNewRejectsBadKeySize(t *testing.T) {
	if _, err := New([]byte("short")); err != ErrKeySize {
		t.Fatalf("want ErrKeySize, got %v", err)
	}
}

func TestOpenWrongKeyFails(t *testing.T) {
	k1 := make([]byte, KeySize)
	k2 := make([]byte, KeySize)
	k2[0] = 1
	c1, _ := New(k1)
	c2, _ := New(k2)
	sealed, _ := c1.Seal("secret")
	if _, err := c2.Open(sealed); err == nil {
		t.Fatal("expected decryption failure with wrong key")
	}
}

func TestLoadOrCreateKeyfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "master.key")

	key1, err := LoadOrCreateKeyfile(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(key1) != KeySize {
		t.Fatalf("key size %d want %d", len(key1), KeySize)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("keyfile perm %o want 0600", perm)
	}

	key2, err := LoadOrCreateKeyfile(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if string(key1) != string(key2) {
		t.Fatal("keyfile reload returned a different key")
	}
}

func TestLoadKeyFromEnv(t *testing.T) {
	c, _ := New(make([]byte, KeySize))
	_ = c
	const env = "POOLGATE_TEST_KEY"
	t.Setenv(env, "")
	if _, err := LoadKeyFromEnv(env); err == nil {
		t.Fatal("expected error for empty env var")
	}
	// A valid 32-byte base64 key.
	t.Setenv(env, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	key, err := LoadKeyFromEnv(env)
	if err != nil {
		t.Fatalf("LoadKeyFromEnv: %v", err)
	}
	if len(key) != KeySize {
		t.Fatalf("key size %d want %d", len(key), KeySize)
	}
}
