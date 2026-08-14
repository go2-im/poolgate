// ssrf.go is poolgate's SSRF guard for notification egress (DESIGN.md §22.1 /
// SECURITY.md). Notification webhooks point at arbitrary operator-supplied URLs,
// so — unlike the pinned upstream — we cannot use a host allowlist. Instead we:
//
//   - require HTTPS,
//   - resolve-then-connect to a VETTED IP, refusing any address that is
//     private / loopback / link-local / metadata (169.254.169.254) / ULA / ::1 /
//     unspecified / multicast, and
//   - re-validate at CONNECT time via net.Dialer.Control (anti DNS-rebinding):
//     Control runs on the actual resolved address the dialer is about to connect
//     to, so a DNS record that flips to a blocked IP between resolution and
//     connect is still refused.
package notify

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// ErrBlockedAddress is returned by the guarded dialer when an egress target
// resolves (or connects) to a non-public IP address.
var ErrBlockedAddress = errors.New("notify: egress to a private/loopback/link-local address is blocked")

// ErrInsecureScheme is returned when a channel URL is not HTTPS.
var ErrInsecureScheme = errors.New("notify: webhook URL must use https")

// cgnatV4 is the RFC 6598 carrier-grade-NAT range (100.64.0.0/10). It is NOT
// covered by netip's IsPrivate, yet Alibaba/Tencent cloud expose their instance
// metadata service (which can vend STS credentials) at 100.100.100.200 inside it,
// so egress there must be blocked (DESIGN.md §22.1 "metadata").
var cgnatV4 = netip.MustParsePrefix("100.64.0.0/10")

// blockedIP reports whether ip must be refused as an egress target. It blocks the
// full set required by DESIGN.md §22.1 plus a couple of obviously-unsafe classes.
// netip's predicates already cover the RFC ranges we care about:
//
//   - IsLoopback:          127.0.0.0/8, ::1
//   - IsPrivate:           10/8, 172.16/12, 192.168/16, and ULA fc00::/7
//   - IsLinkLocalUnicast:  169.254.0.0/16 (incl. 169.254.169.254 metadata), fe80::/10
//   - IsUnspecified:       0.0.0.0, ::
//   - multicast classes
//
// plus the CGNAT range (cloud metadata on Alibaba/Tencent) and a final
// global-unicast allowlist backstop that refuses anything not routable on the
// public Internet (broadcast 255.255.255.255, reserved 240.0.0.0/4, etc.).
func blockedIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	// Normalize IPv4-in-IPv6 (e.g. ::ffff:127.0.0.1) to its v4 form so the v4
	// predicates apply.
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	if ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		cgnatV4.Contains(ip) {
		return true
	}
	// Allowlist backstop: only routable public global-unicast addresses may be
	// dialed. This refuses broadcast / reserved ranges that lack a dedicated
	// netip predicate (private/ULA are re-allowed by IsGlobalUnicast, but they
	// were already blocked above).
	return !ip.IsGlobalUnicast()
}

// guardControl is the net.Dialer.Control hook. address is the concrete resolved
// "ip:port" the dialer is about to connect to, so validating it here defeats DNS
// rebinding: even if a hostname resolved to a public IP moments ago, a flip to a
// blocked IP is caught at connect time.
func guardControl(_ string, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("notify: bad dial address %q: %w", address, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		// The dialer always hands Control a numeric address; a non-numeric host
		// means something resolved oddly — refuse rather than risk it.
		return fmt.Errorf("notify: non-numeric dial address %q", host)
	}
	if blockedIP(ip) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, ip)
	}
	return nil
}

// newGuardedClient builds an *http.Client whose dialer refuses non-public IPs at
// connect time and whose transport does not follow redirects into a blocked host
// silently (redirects still pass through the same guarded dialer, and the caller
// caps redirects). timeout bounds the whole request.
func newGuardedClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   guardControl,
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// Every redirect hop dials through guardControl (so a redirect to a
		// blocked IP is refused) and checkRedirect additionally refuses a scheme
		// downgrade and caps the hop count.
		CheckRedirect: checkRedirect,
	}
}

// checkRedirect enforces the HTTPS-only invariant on every redirect hop and caps
// the hop count. A webhook answering 302 Location: http://... cannot force
// cleartext egress (DESIGN.md §22.1 / SECURITY.md).
func checkRedirect(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return ErrInsecureScheme
	}
	if len(via) >= 5 {
		return errors.New("notify: too many redirects")
	}
	return nil
}

// requireHTTPS validates that rawURL is a well-formed https URL. This is the
// cheap first gate; the guarded dialer enforces the IP policy at connect time.
func requireHTTPS(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("notify: invalid url: %w", err)
	}
	if u.Scheme != "https" {
		return ErrInsecureScheme
	}
	if u.Host == "" {
		return errors.New("notify: url has no host")
	}
	return nil
}
