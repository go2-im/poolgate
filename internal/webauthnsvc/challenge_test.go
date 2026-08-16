package webauthnsvc

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// fakeClock returns a time it can be advanced.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }

func TestChallengeStoreCapEvictsAndSweeps(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	cs := NewChallengeStore(time.Minute, WithChallengeClock(clk.now), WithChallengeMax(3))

	// Fill to cap.
	for i := 0; i < 3; i++ {
		if _, err := cs.Put(&webauthn.SessionData{Challenge: "c"}); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}
	if cs.Len() != 3 {
		t.Fatalf("Len = %d, want 3", cs.Len())
	}
	// Exceeding the cap evicts the oldest rather than growing unbounded.
	for i := 0; i < 100; i++ {
		if _, err := cs.Put(&webauthn.SessionData{Challenge: "c"}); err != nil {
			t.Fatalf("Put over cap: %v", err)
		}
	}
	if cs.Len() > 3 {
		t.Fatalf("Len = %d, want <= 3 (cap enforced)", cs.Len())
	}

	// Expired entries are swept on Put even below the cap.
	cs2 := NewChallengeStore(time.Minute, WithChallengeClock(clk.now), WithChallengeMax(1000))
	if _, err := cs2.Put(&webauthn.SessionData{Challenge: "old"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	clk.add(2 * time.Minute) // expire it
	if _, err := cs2.Put(&webauthn.SessionData{Challenge: "new"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if cs2.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (expired entry swept)", cs2.Len())
	}
}

func TestChallengeStorePutTake(t *testing.T) {	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	cs := NewChallengeStore(time.Minute, WithChallengeClock(clk.now))

	sess := &webauthn.SessionData{Challenge: "abc"}
	id, err := cs.Put(sess)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if id == "" {
		t.Fatal("Put returned empty id")
	}
	if cs.Len() != 1 {
		t.Fatalf("Len = %d, want 1", cs.Len())
	}

	got, err := cs.Take(id)
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if got.Challenge != "abc" {
		t.Errorf("Challenge = %q, want abc", got.Challenge)
	}
	// Single-use: a second Take fails.
	if _, err := cs.Take(id); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("second Take err = %v, want ErrChallengeNotFound", err)
	}
	if cs.Len() != 0 {
		t.Errorf("Len after Take = %d, want 0", cs.Len())
	}
}

func TestChallengeStoreUnknownID(t *testing.T) {
	cs := NewChallengeStore(0) // defaults TTL
	if cs.ttl != DefaultChallengeTTL {
		t.Errorf("ttl = %v, want default", cs.ttl)
	}
	if _, err := cs.Take("nope"); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("Take(unknown) err = %v, want ErrChallengeNotFound", err)
	}
}

func TestChallengeStoreExpiry(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	cs := NewChallengeStore(time.Minute, WithChallengeClock(clk.now))

	id, err := cs.Put(&webauthn.SessionData{Challenge: "x"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Just before expiry: still live.
	clk.add(time.Minute - time.Nanosecond)
	if _, err := cs.Take(id); err != nil {
		t.Fatalf("Take just before expiry: %v", err)
	}

	// Re-store and cross the expiry boundary.
	id2, _ := cs.Put(&webauthn.SessionData{Challenge: "y"})
	clk.add(time.Minute)
	if _, err := cs.Take(id2); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("Take after expiry err = %v, want ErrChallengeNotFound", err)
	}
}

func TestChallengeStoreSweep(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	cs := NewChallengeStore(time.Minute, WithChallengeClock(clk.now))

	if _, err := cs.Put(&webauthn.SessionData{Challenge: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Put(&webauthn.SessionData{Challenge: "b"}); err != nil {
		t.Fatal(err)
	}
	// Not yet expired: sweep removes nothing.
	if n := cs.Sweep(); n != 0 {
		t.Errorf("Sweep before expiry = %d, want 0", n)
	}
	clk.add(2 * time.Minute)
	if n := cs.Sweep(); n != 2 {
		t.Errorf("Sweep after expiry = %d, want 2", n)
	}
	if cs.Len() != 0 {
		t.Errorf("Len after sweep = %d, want 0", cs.Len())
	}
}

func TestChallengeStorePutNil(t *testing.T) {
	cs := NewChallengeStore(time.Minute)
	if _, err := cs.Put(nil); err == nil {
		t.Fatal("Put(nil) = nil error, want error")
	}
}

func TestChallengeStoreRandFailure(t *testing.T) {
	cs := NewChallengeStore(time.Minute, WithChallengeRand(failReader{}))
	if _, err := cs.Put(&webauthn.SessionData{Challenge: "z"}); err == nil {
		t.Fatal("Put with failing rand = nil error, want error")
	}
}

// deterministic id generation using a fixed reader.
func TestChallengeStoreDeterministicID(t *testing.T) {
	seed := bytes.Repeat([]byte{0xAB}, 64)
	cs := NewChallengeStore(time.Minute, WithChallengeRand(bytes.NewReader(seed)))
	id, err := cs.Put(&webauthn.SessionData{Challenge: "q"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	// 16 bytes of 0xAB → base64 RawURL is deterministic.
	if id != "q6urq6urq6urq6urq6urqw" {
		t.Errorf("id = %q, unexpected", id)
	}
}

// failReader always errors, to exercise entropy-failure paths.
type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
