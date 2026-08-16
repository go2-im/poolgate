// Package backup implements poolgate's portable, passphrase-wrapped backup
// bundle (DESIGN.md §20 Ops/DR). A bundle is a single self-contained file that
// carries BOTH the field-encryption master key AND a consistent snapshot of the
// SQLite database, wrapped under a key derived from an operator passphrase — so a
// backup can be restored on a different machine without separately transporting
// the master key, yet a stolen bundle is useless without the passphrase.
//
// Format (all lengths big-endian):
//
//	magic:   "PGBAK1\n"                 (7 bytes)
//	hdrLen:  uint32                      (4 bytes)
//	header:  CBOR(header)                (hdrLen bytes) — KDF params, salt, nonce
//	sealed:  secretbox(payload)          (rest)         — the encrypted payload
//
// The payload (CBOR) holds the master key, the DB snapshot, the schema version,
// and a creation timestamp. The wrap key is argon2id(passphrase, salt) and the
// seal is NaCl secretbox (XSalsa20-Poly1305) — the same primitive the field
// cipher uses. A wrong passphrase or any tampering fails the secretbox open,
// surfaced as ErrPassphrase.
package backup

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
)

// magic identifies a poolgate backup bundle, version 1.
var magic = []byte("PGBAK1\n")

const (
	masterKeyLen = 32 // must match crypto.KeySize
	saltLen      = 16
	nonceLen     = 24 // secretbox nonce

	// argon2id parameters (stored in the header for forward compatibility, so a
	// future bundle can tune them without breaking older readers).
	argonTime    = 3
	argonMemKiB  = 64 * 1024 // 64 MiB
	argonThreads = 4

	// maxHeader / maxSealed bound the sizes read from an untrusted bundle so a
	// corrupt/hostile length prefix cannot trigger a huge allocation.
	maxHeader = 4 << 10  // 4 KiB — the header is tiny
	maxSealed = 2 << 30  // 2 GiB — generous cap for the DB snapshot
)

// ErrPassphrase is returned when the passphrase is wrong or the bundle has been
// tampered with (both fail the authenticated decryption identically, on purpose).
var ErrPassphrase = errors.New("backup: wrong passphrase or corrupt bundle")

// ErrFormat is returned when the input is not a well-formed poolgate bundle.
var ErrFormat = errors.New("backup: not a poolgate backup bundle")

// ErrEmptyPassphrase is returned by Write/Read when the passphrase is empty; an
// empty passphrase would provide no protection for the master key.
var ErrEmptyPassphrase = errors.New("backup: passphrase must not be empty")

// Meta is the non-secret metadata carried in a bundle.
type Meta struct {
	SchemaVersion int
	CreatedAtUnix int64
}

// header is the CBOR-encoded, cleartext framing: KDF parameters + salt + nonce.
// It contains no secrets (the salt/nonce are safe in the clear).
type header struct {
	KDF     string `cbor:"kdf"`
	Salt    []byte `cbor:"salt"`
	Time    uint32 `cbor:"t"`
	MemKiB  uint32 `cbor:"m"`
	Threads uint8  `cbor:"p"`
	Nonce   []byte `cbor:"nonce"`
}

// payload is the CBOR-encoded, encrypted content.
type payload struct {
	MasterKey     []byte `cbor:"mk"`
	DB            []byte `cbor:"db"`
	SchemaVersion int    `cbor:"schema"`
	CreatedAtUnix int64  `cbor:"created"`
}

// Write serializes and encrypts a backup bundle to w. masterKey must be exactly
// 32 bytes; db is the (already consistent) SQLite snapshot. The passphrase must
// be non-empty. meta.CreatedAtUnix should be set by the caller (this package
// avoids reading the clock so it stays deterministic/testable).
func Write(w io.Writer, passphrase, masterKey, db []byte, meta Meta) error {
	if len(passphrase) == 0 {
		return ErrEmptyPassphrase
	}
	if len(masterKey) != masterKeyLen {
		return fmt.Errorf("backup: master key must be %d bytes", masterKeyLen)
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("backup: salt: %w", err)
	}
	var nonce [nonceLen]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return fmt.Errorf("backup: nonce: %w", err)
	}

	var key [32]byte
	deriveKey(&key, passphrase, salt)

	pl, err := cbor.Marshal(payload{
		MasterKey:     masterKey,
		DB:            db,
		SchemaVersion: meta.SchemaVersion,
		CreatedAtUnix: meta.CreatedAtUnix,
	})
	if err != nil {
		return fmt.Errorf("backup: encode payload: %w", err)
	}
	sealed := secretbox.Seal(nil, pl, &nonce, &key)

	hdr, err := cbor.Marshal(header{
		KDF:     "argon2id",
		Salt:    salt,
		Time:    argonTime,
		MemKiB:  argonMemKiB,
		Threads: argonThreads,
		Nonce:   nonce[:],
	})
	if err != nil {
		return fmt.Errorf("backup: encode header: %w", err)
	}

	if _, err := w.Write(magic); err != nil {
		return err
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(hdr)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if _, err := w.Write(sealed); err != nil {
		return err
	}
	return nil
}

// Read decrypts a backup bundle from r and returns the master key, the DB
// snapshot, and the metadata. A wrong passphrase or a tampered bundle returns
// ErrPassphrase; a malformed bundle returns ErrFormat.
func Read(r io.Reader, passphrase []byte) (masterKey, db []byte, meta Meta, err error) {
	if len(passphrase) == 0 {
		return nil, nil, Meta{}, ErrEmptyPassphrase
	}

	gotMagic := make([]byte, len(magic))
	if _, err := io.ReadFull(r, gotMagic); err != nil {
		return nil, nil, Meta{}, ErrFormat
	}
	if !bytesEqual(gotMagic, magic) {
		return nil, nil, Meta{}, ErrFormat
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, nil, Meta{}, ErrFormat
	}
	hdrLen := binary.BigEndian.Uint32(lenBuf[:])
	if hdrLen == 0 || hdrLen > maxHeader {
		return nil, nil, Meta{}, ErrFormat
	}
	hdrBytes := make([]byte, hdrLen)
	if _, err := io.ReadFull(r, hdrBytes); err != nil {
		return nil, nil, Meta{}, ErrFormat
	}
	var hdr header
	if err := cbor.Unmarshal(hdrBytes, &hdr); err != nil {
		return nil, nil, Meta{}, ErrFormat
	}
	if hdr.KDF != "argon2id" || len(hdr.Salt) == 0 || len(hdr.Nonce) != nonceLen ||
		hdr.Time == 0 || hdr.MemKiB == 0 || hdr.Threads == 0 {
		return nil, nil, Meta{}, ErrFormat
	}

	sealed, err := io.ReadAll(io.LimitReader(r, maxSealed))
	if err != nil {
		return nil, nil, Meta{}, ErrFormat
	}

	var key [32]byte
	// Use the header's stored KDF params so a bundle written with different
	// parameters still opens.
	argonKey := argon2.IDKey(passphrase, hdr.Salt, hdr.Time, hdr.MemKiB, hdr.Threads, 32)
	copy(key[:], argonKey)
	var nonce [nonceLen]byte
	copy(nonce[:], hdr.Nonce)

	pl, ok := secretbox.Open(nil, sealed, &nonce, &key)
	if !ok {
		return nil, nil, Meta{}, ErrPassphrase
	}
	var p payload
	if err := cbor.Unmarshal(pl, &p); err != nil {
		// Decryption succeeded but the plaintext is not a valid payload — treat as
		// corruption rather than a passphrase error.
		return nil, nil, Meta{}, ErrFormat
	}
	if len(p.MasterKey) != masterKeyLen {
		return nil, nil, Meta{}, ErrFormat
	}
	return p.MasterKey, p.DB, Meta{SchemaVersion: p.SchemaVersion, CreatedAtUnix: p.CreatedAtUnix}, nil
}

// deriveKey derives the 32-byte wrap key from the passphrase + salt via argon2id
// with the package's default parameters (Write path).
func deriveKey(out *[32]byte, passphrase, salt []byte) {
	k := argon2.IDKey(passphrase, salt, argonTime, argonMemKiB, argonThreads, 32)
	copy(out[:], k)
}

// bytesEqual is a tiny constant-length compare for the magic (not security
// sensitive; the magic is public).
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
