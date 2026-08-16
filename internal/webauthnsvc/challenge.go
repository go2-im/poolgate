// challenge.go implements the in-memory challenge store for pending WebAuthn
// ceremonies (DESIGN.md §16). Each pending Begin* ceremony stashes its
// go-webauthn *SessionData under a short random id with a TTL; the matching
// Finish* call retrieves and removes it. The clock and randomness source are
// injectable so expiry is deterministic under test.
//
// State is process-local by design: admin ceremonies are short-lived and the
// admin listener is a single loopback process, so there is no need to persist
// challenges across restarts.
package webauthnsvc

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// DefaultChallengeTTL bounds how long a pending ceremony may sit before its
// challenge is considered expired.
const DefaultChallengeTTL = 5 * time.Minute

// DefaultMaxChallenges caps the number of pending challenges held at once. The
// /admin/*/begin endpoints are unauthenticated (they must be, to bootstrap the
// first passkey), so without a cap a flood of begin calls could grow the map
// until the process OOMs. When the cap is reached the oldest entry is evicted to
// admit the new one, so legitimate ceremonies still proceed while memory stays
// bounded at roughly cap * sizeof(entry).
const DefaultMaxChallenges = 4096

// ErrChallengeNotFound is returned by Take when no live (unexpired) challenge
// matches the id. Expired entries are treated as not found.
var ErrChallengeNotFound = errors.New("webauthnsvc: challenge not found")

// pendingChallenge is one stored ceremony session plus its expiry.
type pendingChallenge struct {
	session   *webauthn.SessionData
	expiresAt time.Time
}

// ChallengeStore is a TTL map of pending-ceremony session data keyed by a short
// random id. It is safe for concurrent use.
type ChallengeStore struct {
	mu    sync.Mutex
	items map[string]pendingChallenge
	ttl   time.Duration
	max   int
	now   func() time.Time
	randr io.Reader
}

// ChallengeOption customizes a ChallengeStore.
type ChallengeOption func(*ChallengeStore)

// WithChallengeClock injects the time source (default time.Now, UTC).
func WithChallengeClock(now func() time.Time) ChallengeOption {
	return func(c *ChallengeStore) {
		if now != nil {
			c.now = now
		}
	}
}

// WithChallengeRand injects the id-entropy source (default crypto/rand.Reader).
func WithChallengeRand(r io.Reader) ChallengeOption {
	return func(c *ChallengeStore) {
		if r != nil {
			c.randr = r
		}
	}
}

// WithChallengeMax overrides the maximum number of pending challenges (<= 0 uses
// DefaultMaxChallenges).
func WithChallengeMax(n int) ChallengeOption {
	return func(c *ChallengeStore) {
		if n > 0 {
			c.max = n
		}
	}
}

// NewChallengeStore builds an empty store with the given TTL (ttl <= 0 uses
// DefaultChallengeTTL).
func NewChallengeStore(ttl time.Duration, opts ...ChallengeOption) *ChallengeStore {
	if ttl <= 0 {
		ttl = DefaultChallengeTTL
	}
	c := &ChallengeStore{
		items: make(map[string]pendingChallenge),
		ttl:   ttl,
		max:   DefaultMaxChallenges,
		now:   func() time.Time { return time.Now().UTC() },
		randr: rand.Reader,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Put stores session under a fresh random id with expiry now+ttl and returns the
// id. The caller hands the id back to the browser (opaque) and presents it again
// at Finish time. Put opportunistically sweeps expired entries and enforces the
// size cap (evicting the oldest entry when full) so an unauthenticated flood of
// begin calls cannot grow the map without bound.
func (c *ChallengeStore) Put(session *webauthn.SessionData) (string, error) {
	if session == nil {
		return "", errors.New("webauthnsvc: nil session data")
	}
	id, err := c.newID()
	if err != nil {
		return "", err
	}
	now := c.now().UTC()
	c.mu.Lock()
	c.sweepLocked(now)
	if len(c.items) >= c.max {
		c.evictOldestLocked()
	}
	c.items[id] = pendingChallenge{session: session, expiresAt: now.Add(c.ttl)}
	c.mu.Unlock()
	return id, nil
}

// sweepLocked removes expired entries. The caller must hold c.mu.
func (c *ChallengeStore) sweepLocked(now time.Time) {
	for id, item := range c.items {
		if !now.Before(item.expiresAt) {
			delete(c.items, id)
		}
	}
}

// evictOldestLocked removes the entry with the earliest expiry. The caller must
// hold c.mu and ensure the map is non-empty.
func (c *ChallengeStore) evictOldestLocked() {
	var (
		oldestID string
		oldestAt time.Time
		found    bool
	)
	for id, item := range c.items {
		if !found || item.expiresAt.Before(oldestAt) {
			oldestID, oldestAt, found = id, item.expiresAt, true
		}
	}
	if found {
		delete(c.items, oldestID)
	}
}

// Take retrieves and removes the session for id. It returns ErrChallengeNotFound
// when the id is unknown or its entry has expired (a single-use, self-cleaning
// lookup). Expired entries are always deleted, even though they are not
// returned.
func (c *ChallengeStore) Take(id string) (*webauthn.SessionData, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.items[id]
	if !ok {
		return nil, ErrChallengeNotFound
	}
	delete(c.items, id)
	if !c.now().UTC().Before(item.expiresAt) {
		return nil, ErrChallengeNotFound
	}
	return item.session, nil
}

// Sweep removes every expired entry and returns the number removed. It is not
// required for correctness (Take self-cleans on access) but bounds memory when
// ceremonies are abandoned.
func (c *ChallengeStore) Sweep() int {
	now := c.now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for id, item := range c.items {
		if !now.Before(item.expiresAt) {
			delete(c.items, id)
			removed++
		}
	}
	return removed
}

// Len returns the current number of stored (not-yet-swept) entries.
func (c *ChallengeStore) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// newID returns a 128-bit URL-safe random id.
func (c *ChallengeStore) newID() (string, error) {
	buf := make([]byte, 16)
	if _, err := io.ReadFull(c.randr, buf); err != nil {
		return "", errors.New("webauthnsvc: challenge id entropy: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
