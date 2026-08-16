package clientip

import (
	"net"
	"testing"
)

func mustParse(t *testing.T, specs ...string) []*net.IPNet {
	t.Helper()
	nets, err := ParseCIDRs(specs)
	if err != nil {
		t.Fatalf("ParseCIDRs(%v): %v", specs, err)
	}
	return nets
}

func TestParseCIDRs(t *testing.T) {
	nets, err := ParseCIDRs([]string{"10.0.0.0/8", " 127.0.0.1 ", "::1", ""})
	if err != nil {
		t.Fatalf("ParseCIDRs: %v", err)
	}
	if len(nets) != 3 {
		t.Fatalf("got %d nets, want 3 (blank skipped)", len(nets))
	}
	if _, err := ParseCIDRs([]string{"not-an-ip"}); err == nil {
		t.Fatal("ParseCIDRs(garbage) should error")
	}
}

func TestFrom(t *testing.T) {
	trusted := mustParse(t, "10.0.0.0/8")

	cases := []struct {
		name    string
		peer    string
		xff     string
		trusted []*net.IPNet
		want    string
	}{
		{"no trusted proxies ignores xff", "10.0.0.1:5", "1.2.3.4", nil, "10.0.0.1"},
		{"untrusted peer ignores xff", "203.0.113.9:5", "1.2.3.4", trusted, "203.0.113.9"},
		{"trusted peer takes rightmost untrusted", "10.0.0.1:5", "1.2.3.4, 10.0.0.2", trusted, "1.2.3.4"},
		{"trusted peer, single client", "10.0.0.1:5", "1.2.3.4", trusted, "1.2.3.4"},
		{"all hops trusted falls back to peer", "10.0.0.1:5", "10.0.0.9, 10.0.0.2", trusted, "10.0.0.1"},
		{"malformed hop stops the walk", "10.0.0.1:5", "junk", trusted, "10.0.0.1"},
		{"empty xff with trusted peer", "10.0.0.1:5", "", trusted, "10.0.0.1"},
		{"peer without port", "10.0.0.1", "1.2.3.4", trusted, "1.2.3.4"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := From(c.peer, c.xff, c.trusted); got != c.want {
				t.Errorf("From(%q,%q) = %q, want %q", c.peer, c.xff, got, c.want)
			}
		})
	}
}
