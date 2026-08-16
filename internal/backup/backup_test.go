package backup

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func mustKey() []byte {
	k := make([]byte, masterKeyLen)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// TestRoundTrip writes a bundle and reads it back with the correct passphrase,
// asserting the master key, DB bytes, and metadata all survive intact.
func TestRoundTrip(t *testing.T) {
	pass := []byte("correct horse battery staple")
	key := mustKey()
	db := []byte("SQLite format 3\x00...pretend database bytes...")
	meta := Meta{SchemaVersion: 5, CreatedAtUnix: 1_700_000_000}

	var buf bytes.Buffer
	if err := Write(&buf, pass, key, db, meta); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !bytes.HasPrefix(buf.Bytes(), magic) {
		t.Fatalf("bundle missing magic prefix")
	}

	gotKey, gotDB, gotMeta, err := Read(bytes.NewReader(buf.Bytes()), pass)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(gotKey, key) {
		t.Errorf("master key mismatch")
	}
	if !bytes.Equal(gotDB, db) {
		t.Errorf("db bytes mismatch")
	}
	if gotMeta != meta {
		t.Errorf("meta = %+v, want %+v", gotMeta, meta)
	}
}

// TestWrongPassphrase asserts a different passphrase fails with ErrPassphrase
// (and leaks no plaintext).
func TestWrongPassphrase(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, []byte("right"), mustKey(), []byte("db"), Meta{}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_, _, _, err := Read(bytes.NewReader(buf.Bytes()), []byte("wrong"))
	if err != ErrPassphrase {
		t.Fatalf("err = %v, want ErrPassphrase", err)
	}
}

// TestTamperDetected flips a byte in the sealed region and asserts the open fails.
func TestTamperDetected(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, []byte("pw"), mustKey(), []byte("some database"), Meta{}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	b := buf.Bytes()
	// Flip the last byte (inside the sealed payload).
	b[len(b)-1] ^= 0xff
	if _, _, _, err := Read(bytes.NewReader(b), []byte("pw")); err != ErrPassphrase {
		t.Fatalf("tampered err = %v, want ErrPassphrase", err)
	}
}

// TestBadMagic and truncation cases return ErrFormat, not a panic.
func TestBadMagicAndTruncation(t *testing.T) {
	cases := map[string][]byte{
		"empty":       nil,
		"bad magic":   []byte("NOTPGBAK............"),
		"magic only":  magic,
		"short hdr":   append(append([]byte{}, magic...), 0x00, 0x00, 0x00, 0x10),
		"zero hdrlen": append(append([]byte{}, magic...), 0x00, 0x00, 0x00, 0x00),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := Read(bytes.NewReader(in), []byte("pw"))
			if err == nil {
				t.Fatalf("expected an error for %q", name)
			}
		})
	}
}

// TestEmptyPassphraseRejected covers both Write and Read.
func TestEmptyPassphraseRejected(t *testing.T) {
	if err := Write(&bytes.Buffer{}, nil, mustKey(), []byte("db"), Meta{}); err != ErrEmptyPassphrase {
		t.Errorf("Write empty pass err = %v, want ErrEmptyPassphrase", err)
	}
	if _, _, _, err := Read(bytes.NewReader(magic), nil); err != ErrEmptyPassphrase {
		t.Errorf("Read empty pass err = %v, want ErrEmptyPassphrase", err)
	}
}

// TestRejectsOversizedKDFParams asserts a bundle whose (unauthenticated) header
// carries absurd argon2 cost parameters is rejected as ErrFormat BEFORE argon2
// runs — preventing a pre-auth memory/CPU exhaustion DoS.
func TestRejectsOversizedKDFParams(t *testing.T) {
	// Hand-build a bundle whose header claims a ~4 TiB memory cost.
	var buf bytes.Buffer
	buf.Write(magic)
	hdr, err := cbor.Marshal(header{
		KDF:     "argon2id",
		Salt:    make([]byte, saltLen),
		Time:    1,
		MemKiB:  0xffffffff, // ~4 TiB — must be rejected without allocating
		Threads: 1,
		Nonce:   make([]byte, nonceLen),
	})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(hdr)))
	buf.Write(lenBuf[:])
	buf.Write(hdr)
	buf.Write([]byte("whatever-sealed-bytes"))

	if _, _, _, err := Read(bytes.NewReader(buf.Bytes()), []byte("pw")); err != ErrFormat {
		t.Fatalf("oversized KDF params err = %v, want ErrFormat", err)
	}
}

