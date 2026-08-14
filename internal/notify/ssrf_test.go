package notify

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",       // loopback v4
		"::1",             // loopback v6
		"10.1.2.3",        // private
		"172.16.0.1",      // private
		"192.168.1.1",     // private
		"169.254.169.254", // link-local / cloud metadata
		"fe80::1",         // link-local v6
		"fc00::1",         // ULA (private v6)
		"fd12:3456::1",    // ULA
		"0.0.0.0",         // unspecified
		"::",              // unspecified v6
		"224.0.0.1",       // multicast
		"ff02::1",         // multicast v6
		"::ffff:127.0.0.1", // v4-in-v6 loopback
		"::ffff:10.0.0.1",  // v4-in-v6 private
		"100.64.0.1",       // RFC 6598 CGNAT
		"100.100.100.200",  // Alibaba/Tencent cloud metadata (inside CGNAT)
		"255.255.255.255",  // broadcast (not global-unicast)
	}
	for _, s := range blocked {
		if !blockedIP(netip.MustParseAddr(s)) {
			t.Errorf("blockedIP(%s) = false, want true", s)
		}
	}
	allowed := []string{
		"8.8.8.8",
		"1.1.1.1",
		"203.0.113.10",
		"2606:4700:4700::1111",
	}
	for _, s := range allowed {
		if blockedIP(netip.MustParseAddr(s)) {
			t.Errorf("blockedIP(%s) = true, want false", s)
		}
	}
	// The zero Addr is invalid and must be blocked.
	if !blockedIP(netip.Addr{}) {
		t.Error("blockedIP(zero) = false, want true")
	}
}

func TestGuardControl(t *testing.T) {
	// Blocked resolved address is refused.
	if err := guardControl("tcp", "127.0.0.1:443", nil); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("guardControl(loopback) err = %v, want ErrBlockedAddress", err)
	}
	if err := guardControl("tcp", "169.254.169.254:80", nil); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("guardControl(metadata) err = %v, want ErrBlockedAddress", err)
	}
	// Public address is allowed.
	if err := guardControl("tcp", "8.8.8.8:443", nil); err != nil {
		t.Errorf("guardControl(public) err = %v, want nil", err)
	}
	// Malformed address is refused.
	if err := guardControl("tcp", "not-an-addr", nil); err == nil {
		t.Error("guardControl(malformed) err = nil, want error")
	}
	// A non-numeric host (should never happen post-resolution) is refused.
	if err := guardControl("tcp", "example.com:443", nil); err == nil {
		t.Error("guardControl(hostname) err = nil, want error")
	}
}

func TestRequireHTTPS(t *testing.T) {
	if err := requireHTTPS("https://example.com/hook"); err != nil {
		t.Errorf("requireHTTPS(https) = %v, want nil", err)
	}
	if err := requireHTTPS("http://example.com"); !errors.Is(err, ErrInsecureScheme) {
		t.Errorf("requireHTTPS(http) = %v, want ErrInsecureScheme", err)
	}
	if err := requireHTTPS("https://"); err == nil {
		t.Error("requireHTTPS(no host) = nil, want error")
	}
	if err := requireHTTPS("://:bad:"); err == nil {
		t.Error("requireHTTPS(garbage) = nil, want error")
	}
}

// TestGuardedClientRefusesLoopback verifies the guarded client blocks a request
// to a loopback address at connect time (anti-SSRF), without needing a network.
func TestGuardedClientRefusesLoopback(t *testing.T) {
	client := newGuardedClient(2 * time.Second)
	_, err := client.Get("https://127.0.0.1:9/hook")
	if err == nil {
		t.Fatal("guarded client reached loopback, want blocked")
	}
	if !strings.Contains(err.Error(), "block") {
		t.Errorf("error = %v, want a block error", err)
	}
}

func TestCheckRedirectRefusesDowngrade(t *testing.T) {
	req := func(raw string) *http.Request {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		return &http.Request{URL: u}
	}
	// http downgrade is refused.
	if err := checkRedirect(req("http://example.com"), nil); !errors.Is(err, ErrInsecureScheme) {
		t.Errorf("http redirect err = %v, want ErrInsecureScheme", err)
	}
	// https hop is allowed.
	if err := checkRedirect(req("https://example.com"), nil); err != nil {
		t.Errorf("https redirect err = %v, want nil", err)
	}
	// Too many hops is refused.
	via := make([]*http.Request, 5)
	if err := checkRedirect(req("https://example.com"), via); err == nil {
		t.Error("expected too-many-redirects error")
	}
}
