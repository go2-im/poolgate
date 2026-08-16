// Package clientip resolves the real client IP from a request's direct peer and
// X-Forwarded-For chain, honoring a configured set of trusted proxy networks.
//
// The default (no trusted proxies) is to use ONLY the direct peer address and
// ignore X-Forwarded-For entirely — a client-supplied header must never be
// trusted when poolgate is directly exposed. When operators front poolgate with
// a reverse proxy (nginx/Caddy/Cloudflare/Tailscale), they list that proxy's
// address(es)/network(s) as trusted; only then is X-Forwarded-For consulted, and
// only the right-most address that is NOT itself a trusted proxy is returned.
// This makes the IP allowlist and rate-limiter see the true client while
// remaining unspoofable: an untrusted peer's forwarded header is discarded.
package clientip

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// ParseCIDRs parses trusted-proxy specs, each either a CIDR ("10.0.0.0/8",
// "::1/128") or a bare IP ("127.0.0.1", "::1", treated as a single-host network).
// Empty/blank entries are skipped. It returns an error on any malformed spec.
func ParseCIDRs(specs []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, s := range specs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(s); err == nil {
			out = append(out, ipnet)
			continue
		}
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("clientip: invalid trusted proxy %q (want an IP or CIDR)", s)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return out, nil
}

// FromRequest is From applied to an *http.Request (peer + X-Forwarded-For).
func FromRequest(r *http.Request, trusted []*net.IPNet) string {
	return From(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), trusted)
}

// From returns the resolved client IP. remoteAddr is the direct peer (host:port
// or host). xff is the raw X-Forwarded-For header value (may be empty or a
// comma-separated list). trusted is the set of trusted proxy networks.
//
// If the direct peer is not trusted (or there are no trusted networks), the peer
// address is returned and xff is ignored. If the peer is trusted, the chain is
// walked right-to-left and the first address that is not itself a trusted proxy
// is returned; if every hop is trusted (or the header is empty/malformed), the
// peer is returned as a safe fallback.
func From(remoteAddr, xff string, trusted []*net.IPNet) string {
	peer := hostOnly(remoteAddr)
	if len(trusted) == 0 || !contains(trusted, peer) {
		return peer
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ipStr := strings.TrimSpace(parts[i])
		if ipStr == "" {
			continue
		}
		if net.ParseIP(ipStr) == nil {
			// Malformed hop — stop trusting the rest of the (attacker-influenced) chain.
			return peer
		}
		if !contains(trusted, ipStr) {
			return ipStr
		}
	}
	return peer
}

func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func contains(nets []*net.IPNet, ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
