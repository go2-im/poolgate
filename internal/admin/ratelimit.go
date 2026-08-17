// ratelimit.go is the admin API's anti-brute-force limiter (DESIGN.md §22.4):
// per-key failure counting within a sliding window, and a lockout once the
// failure count crosses a threshold. It guards the login, recovery-code, and
// bootstrap-registration paths. The clock is injectable so lockout expiry is
// deterministic under test.
package admin

import (
	"net/http"
	"sync"
	"time"
)

// Default anti-brute-force parameters.
const (
	defaultMaxFailures   = 5
	defaultBruteWindow   = 15 * time.Minute
	defaultLockout       = 15 * time.Minute
	defaultRecoveryCodes = 10
	// defaultMaxBuckets bounds the in-memory bucket map so a flood of DISTINCT keys
	// (e.g. spoofed/rotating source IPs hitting the auth routes) cannot grow it
	// without bound and exhaust memory. When the cap is reached, expired buckets
	// (no active lockout AND window elapsed — they hold no useful state) are pruned;
	// if the map is still full (all buckets active), the soonest-to-expire is evicted
	// to make room. 4096 distinct locked-out keys is far beyond any real single-user
	// deployment, so genuine lockouts are never lost in practice.
	defaultMaxBuckets = 4096
)

// bucket tracks one rate-limit key's recent failures and any active lockout.
type bucket struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

// limiter is a small in-memory failure counter keyed by "route|ip". It is safe
// for concurrent use. The bucket map is bounded by maxBuckets (see Fail).
type limiter struct {
	mu          sync.Mutex
	buckets     map[string]*bucket
	maxFailures int
	maxBuckets  int
	window      time.Duration
	lockout     time.Duration
	now         func() time.Time
}

func newLimiter(maxFailures int, window, lockout time.Duration, now func() time.Time) *limiter {
	if maxFailures <= 0 {
		maxFailures = defaultMaxFailures
	}
	if window <= 0 {
		window = defaultBruteWindow
	}
	if lockout <= 0 {
		lockout = defaultLockout
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &limiter{
		buckets:     make(map[string]*bucket),
		maxFailures: maxFailures,
		maxBuckets:  defaultMaxBuckets,
		window:      window,
		lockout:     lockout,
		now:         now,
	}
}

// Allow reports whether an attempt for key may proceed (i.e. it is not currently
// locked out).
func (l *limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		return true
	}
	return !l.now().Before(b.lockedUntil)
}

// Fail records a failed attempt for key, opening or sliding the window and
// arming a lockout once the failure count reaches the threshold.
func (l *limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.buckets[key]
	if b == nil {
		l.evictIfFullLocked(now) // bound the map before inserting a new key
		b = &bucket{}
		l.buckets[key] = b
	}
	// Reset the window if it has elapsed.
	if b.windowStart.IsZero() || now.Sub(b.windowStart) > l.window {
		b.windowStart = now
		b.failures = 0
	}
	b.failures++
	if b.failures >= l.maxFailures {
		b.lockedUntil = now.Add(l.lockout)
		// Start a fresh window after arming the lockout so a post-lockout
		// attempt gets a clean slate.
		b.failures = 0
		b.windowStart = time.Time{}
	}
}

// Reset clears any failure/lockout state for key after a successful attempt.
func (l *limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, key)
}

// bucketExpiry is the instant after which a bucket holds no useful state: the
// later of its lockout end and its window end. Past this, Allow returns true and
// Fail would reset the window, so the bucket is safe to drop.
func (l *limiter) bucketExpiry(b *bucket) time.Time {
	exp := b.lockedUntil
	if !b.windowStart.IsZero() {
		if we := b.windowStart.Add(l.window); we.After(exp) {
			exp = we
		}
	}
	return exp
}

// evictIfFullLocked bounds the bucket map to maxBuckets (caller holds l.mu). It
// first drops every expired bucket (no useful state); if the map is STILL full
// (all buckets active), it evicts the single soonest-to-expire bucket to make room
// for the incoming key. This guarantees len(buckets) < maxBuckets after it returns
// (so the subsequent insert keeps the map at or below the cap).
func (l *limiter) evictIfFullLocked(now time.Time) {
	if l.maxBuckets <= 0 || len(l.buckets) < l.maxBuckets {
		return
	}
	for k, b := range l.buckets {
		if !now.Before(l.bucketExpiry(b)) { // expired: now >= expiry
			delete(l.buckets, k)
		}
	}
	if len(l.buckets) < l.maxBuckets {
		return
	}
	// All remaining buckets are still active: evict the one that expires soonest.
	var evictKey string
	var soonest time.Time
	for k, b := range l.buckets {
		exp := l.bucketExpiry(b)
		if evictKey == "" || exp.Before(soonest) {
			evictKey, soonest = k, exp
		}
	}
	if evictKey != "" {
		delete(l.buckets, evictKey)
	}
}

// brute wraps an auth handler with the rate-limiter. The handler reports whether
// the attempt failed authentication via *attempt; genuine auth failures are
// counted (and may trigger a lockout), successes reset the counter, and a
// locked-out key is refused up front with 429 + Retry-After.
func (s *Server) brute(route string, h func(w http.ResponseWriter, r *http.Request, at *attempt)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := route + "|" + s.clientIP(r)
		if !s.limiter.Allow(key) {
			w.Header().Set("Retry-After", "900")
			writeErr(w, http.StatusTooManyRequests, errRateLimited, "too many attempts; try again later")
			return
		}
		var at attempt
		h(w, r, &at)
		if at.failed {
			s.limiter.Fail(key)
		} else if at.succeeded {
			s.limiter.Reset(key)
		}
	}
}

// attempt is the outcome an auth handler reports back to the brute wrapper. A
// handler that neither fails auth nor completes a successful login (e.g. a
// begin step, or a malformed request) leaves both flags false so it neither
// counts against nor clears the limiter.
type attempt struct {
	failed    bool
	succeeded bool
}
