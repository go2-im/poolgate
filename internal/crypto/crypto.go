// Package crypto provides field-level encryption for secret columns using
// NaCl secretbox (XSalsa20-Poly1305). The master key is loaded from a keyfile
// or an env var; if a keyfile path is given and absent, a fresh key is
// generated and persisted 0600. OS-keychain sourcing is a later phase
// (DESIGN.md §5 / §17).
package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/nacl/secretbox"
)

// KeySize is the secretbox master key length in bytes.
const KeySize = 32

const nonceSize = 24

// ErrKeySize is returned when a supplied master key is not KeySize bytes.
var ErrKeySize = fmt.Errorf("crypto: master key must be %d bytes", KeySize)

// Cipher seals and opens secrets with a fixed 32-byte master key.
type Cipher struct {
	key [KeySize]byte
}

// New builds a Cipher from a raw key. The key must be exactly KeySize bytes.
func New(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	c := &Cipher{}
	copy(c.key[:], key)
	return c, nil
}

// Seal encrypts plaintext and returns a base64 std-encoded string of
// nonce||box. Each call uses a fresh random nonce.
func (c *Cipher) Seal(plaintext string) (string, error) {
	var nonce [nonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", fmt.Errorf("crypto: read nonce: %w", err)
	}
	sealed := secretbox.Seal(nonce[:], []byte(plaintext), &nonce, &c.key)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open reverses Seal: it decodes the base64 string and decrypts it.
func (c *Cipher) Open(ciphertext string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("crypto: decode: %w", err)
	}
	if len(raw) < nonceSize {
		return "", errors.New("crypto: ciphertext too short")
	}
	var nonce [nonceSize]byte
	copy(nonce[:], raw[:nonceSize])
	opened, ok := secretbox.Open(nil, raw[nonceSize:], &nonce, &c.key)
	if !ok {
		return "", errors.New("crypto: decryption failed")
	}
	return string(opened), nil
}

// LoadKeyFromEnv returns the master key decoded from a base64 std-encoded env
// var value. It errors if the var is unset/empty or not KeySize bytes.
func LoadKeyFromEnv(envVar string) ([]byte, error) {
	v := os.Getenv(envVar)
	if v == "" {
		return nil, fmt.Errorf("crypto: env var %q is empty", envVar)
	}
	return ParseKey(v)
}

// GenerateKey returns a fresh cryptographically-random master key (KeySize bytes).
// Used by master-key rotation to mint the new key before re-encrypting.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("crypto: generate key: %w", err)
	}
	return key, nil
}

// EncodeKey base64 std-encodes a raw master key (the on-disk / env representation).
func EncodeKey(key []byte) string { return base64.StdEncoding.EncodeToString(key) }

// ParseKey decodes a base64 std-encoded master key and validates its length.
// It is the shared parser behind LoadKeyFromEnv and any other source (e.g. a
// *_FILE secret) that supplies the key as a base64 string.
func ParseKey(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode key: %w", err)
	}
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	return key, nil
}

// LoadKeyfile reads a base64 std-encoded master key from path WITHOUT creating
// one when it is absent. Read-only / DR commands (e.g. backup) use this so a
// missing keyfile is a hard error rather than silently minting a fresh key that
// cannot decrypt the existing database.
func LoadKeyfile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("crypto: keyfile %q does not exist", path)
		}
		return nil, fmt.Errorf("crypto: read keyfile %q: %w", path, err)
	}
	key, derr := base64.StdEncoding.DecodeString(string(trimSpace(data)))
	if derr != nil {
		return nil, fmt.Errorf("crypto: decode keyfile %q: %w", path, derr)
	}
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	return key, nil
}

// LoadOrCreateKeyfile reads a base64 std-encoded master key from path. If the
// file does not exist, a fresh random key is generated and written 0600
// (creating parent dirs as needed), then returned.
func LoadOrCreateKeyfile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		key, derr := base64.StdEncoding.DecodeString(string(trimSpace(data)))
		if derr != nil {
			return nil, fmt.Errorf("crypto: decode keyfile %q: %w", path, derr)
		}
		if len(key) != KeySize {
			return nil, ErrKeySize
		}
		return key, nil
	case errors.Is(err, os.ErrNotExist):
		return generateKeyfile(path)
	default:
		return nil, fmt.Errorf("crypto: read keyfile %q: %w", path, err)
	}
}

func generateKeyfile(path string) ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("crypto: generate key: %w", err)
	}
	dir := filepath.Dir(path)
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("crypto: mkdir for keyfile: %w", err)
		}
	}
	// Write atomically and durably: a fresh master key that is lost to a crash
	// before the page reaches disk would render every field-encrypted secret
	// permanently unrecoverable. Stage to a temp file, fsync it, rename into
	// place, then fsync the directory (mirrors rekey/backup key writes).
	enc := base64.StdEncoding.EncodeToString(key) + "\n"
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("crypto: create keyfile temp: %w", err)
	}
	if _, err := f.Write([]byte(enc)); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("crypto: write keyfile temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("crypto: fsync keyfile temp: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("crypto: close keyfile temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("crypto: commit keyfile %q: %w", path, err)
	}
	if dir != "" {
		if d, derr := os.Open(dir); derr == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}
	return key, nil
}

// trimSpace strips surrounding ASCII whitespace (keyfiles may have a trailing newline).
func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpace(b[start]) {
		start++
	}
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
