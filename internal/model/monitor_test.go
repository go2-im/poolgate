package model

import (
	"strings"
	"testing"
	"time"
)

func TestSanitizeField(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"plain", "plain"},
		{"a\nb\r\nc", "abc"},   // newlines stripped (SSE-safe)
		{"a\tb", "ab"},         // tab stripped
		{"x\x00\x1f\x7fy", "xy"}, // NUL, C0, DEL stripped
		{"héllo", "héllo"},      // multibyte preserved
	}
	for _, c := range cases {
		if got := SanitizeField(c.in); got != c.want {
			t.Errorf("SanitizeField(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Length cap (in runes).
	long := strings.Repeat("x", MaxMonitorFieldLen+50)
	if got := SanitizeField(long); len([]rune(got)) != MaxMonitorFieldLen {
		t.Errorf("length = %d, want %d", len([]rune(got)), MaxMonitorFieldLen)
	}
	// No newline ever survives (SSE framing safety).
	if strings.ContainsAny(SanitizeField("bad\r\ndata: injected"), "\r\n") {
		t.Error("newline survived sanitization")
	}
}

func TestRequestLogFilterMatches(t *testing.T) {
	base := RequestLog{
		SessionID: "s1", APIKeyID: "k1", Model: "gpt-5", Endpoint: "prod",
		AccountID: "a1", Status: 200, At: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC),
	}
	// Empty filter matches anything.
	if !(RequestLogFilter{}).Matches(base) {
		t.Error("empty filter should match")
	}
	// Each facet, matching + non-matching.
	if !(RequestLogFilter{SessionID: "s1"}).Matches(base) || (RequestLogFilter{SessionID: "s2"}).Matches(base) {
		t.Error("session facet wrong")
	}
	if !(RequestLogFilter{APIKeyID: "k1"}).Matches(base) || (RequestLogFilter{APIKeyID: "k2"}).Matches(base) {
		t.Error("api_key facet wrong")
	}
	if !(RequestLogFilter{Model: "gpt-5"}).Matches(base) || (RequestLogFilter{Model: "gpt-4"}).Matches(base) {
		t.Error("model facet wrong")
	}
	if !(RequestLogFilter{Endpoint: "prod"}).Matches(base) || (RequestLogFilter{Endpoint: "dev"}).Matches(base) {
		t.Error("endpoint facet wrong")
	}
	if !(RequestLogFilter{AccountID: "a1"}).Matches(base) || (RequestLogFilter{AccountID: "a2"}).Matches(base) {
		t.Error("account facet wrong")
	}
	if !(RequestLogFilter{Status: 200}).Matches(base) || (RequestLogFilter{Status: 500}).Matches(base) {
		t.Error("status facet wrong")
	}
	// Time bounds: Since inclusive, Until exclusive.
	if !(RequestLogFilter{Since: base.At}).Matches(base) {
		t.Error("Since == At should match (inclusive)")
	}
	if (RequestLogFilter{Since: base.At.Add(time.Second)}).Matches(base) {
		t.Error("Since after At should not match")
	}
	if (RequestLogFilter{Until: base.At}).Matches(base) {
		t.Error("Until == At should not match (exclusive)")
	}
	if !(RequestLogFilter{Until: base.At.Add(time.Second)}).Matches(base) {
		t.Error("Until after At should match")
	}
	// Composite filter.
	if !(RequestLogFilter{SessionID: "s1", Model: "gpt-5", Status: 200}).Matches(base) {
		t.Error("composite match failed")
	}
}
