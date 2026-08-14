package crypto

import (
	"encoding/base64"
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

// validKeyB64 is a valid 32-byte key base64 std-encoded.
const validKeyB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestOpenErrors(t *testing.T) {
	c, _ := New(make([]byte, KeySize))
	cases := []struct {
		name string
		in   string
	}{
		{"invalid base64", "!!!not-base64!!!"},
		{"too short", base64.StdEncoding.EncodeToString([]byte("short"))},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.Open(tc.in); err == nil {
				t.Fatalf("Open(%q): expected error", tc.in)
			}
		})
	}
}

func TestLoadKeyFromEnvErrors(t *testing.T) {
	const env = "POOLGATE_TEST_KEY_ERR"
	cases := []struct {
		name string
		set  bool
		val  string
	}{
		{"unset", false, ""},
		{"empty", true, ""},
		{"garbage base64", true, "!!!not base64!!!"},
		{"wrong size decoded", true, base64.StdEncoding.EncodeToString([]byte("too short key"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(env, tc.val)
			} else {
				os.Unsetenv(env)
			}
			if _, err := LoadKeyFromEnv(env); err == nil {
				t.Fatalf("expected error for case %q", tc.name)
			}
		})
	}
}

func TestLoadOrCreateKeyfileErrors(t *testing.T) {
	t.Run("garbage base64 in file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.key")
		if err := os.WriteFile(path, []byte("!!!not base64!!!\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreateKeyfile(path); err == nil {
			t.Fatal("expected decode error")
		}
	})

	t.Run("wrong size key in file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "wrong.key")
		short := base64.StdEncoding.EncodeToString([]byte("too short"))
		if err := os.WriteFile(path, []byte(short+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreateKeyfile(path); err != ErrKeySize {
			t.Fatalf("want ErrKeySize, got %v", err)
		}
	})

	t.Run("read error when path is a directory", func(t *testing.T) {
		dir := t.TempDir()
		// path is an existing directory -> ReadFile returns a non-ErrNotExist error.
		if _, err := LoadOrCreateKeyfile(dir); err == nil {
			t.Fatal("expected read error for directory path")
		}
	})

	t.Run("valid key with trailing whitespace", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "ok.key")
		if err := os.WriteFile(path, []byte("  "+validKeyB64+"\r\n\t "), 0o600); err != nil {
			t.Fatal(err)
		}
		key, err := LoadOrCreateKeyfile(path)
		if err != nil {
			t.Fatalf("LoadOrCreateKeyfile: %v", err)
		}
		if len(key) != KeySize {
			t.Fatalf("key size %d want %d", len(key), KeySize)
		}
	})
}

func TestGenerateKeyfileErrors(t *testing.T) {
	t.Run("mkdir fails when parent is a file", func(t *testing.T) {
		dir := t.TempDir()
		blocker := filepath.Join(dir, "afile")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		// Dir of this path is blocker/sub, but blocker is a regular file -> MkdirAll fails.
		path := filepath.Join(blocker, "sub", "master.key")
		if _, err := generateKeyfile(path); err == nil {
			t.Fatal("expected mkdir error")
		}
	})

	t.Run("write fails when path is a directory", func(t *testing.T) {
		dir := t.TempDir()
		// path itself is an existing directory -> WriteFile fails.
		if _, err := generateKeyfile(dir); err == nil {
			t.Fatal("expected write error")
		}
	})
}

func TestTrimSpace(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"   ", ""},
		{"\t\r\n", ""},
		{"abc", "abc"},
		{"  abc  ", "abc"},
		{"\n\tabc\r\n", "abc"},
		{"a b", "a b"},
	}
	for _, tc := range cases {
		if got := string(trimSpace([]byte(tc.in))); got != tc.want {
			t.Fatalf("trimSpace(%q) = %q want %q", tc.in, got, tc.want)
		}
	}
}
