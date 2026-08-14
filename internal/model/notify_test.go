package model

import "testing"

func TestNotifyEventKindValid(t *testing.T) {
	valid := []NotifyEventKind{
		EventAccountExpired, EventAccountCooldown, EventAccountQuotaExhausted,
		EventAccountRecovered, EventQuotaLow, EventPolicyNoHealthyMember,
		EventAuthAnomaly, EventStartupBindWarning,
	}
	for _, k := range valid {
		if !k.Valid() {
			t.Errorf("Valid(%q) = false, want true", k)
		}
	}
	for _, k := range []NotifyEventKind{"", "bogus", "account_"} {
		if k.Valid() {
			t.Errorf("Valid(%q) = true, want false", k)
		}
	}
}

func TestNotifyChannelTypeValid(t *testing.T) {
	for _, tp := range []NotifyChannelType{ChannelDingTalk, ChannelWeCom, ChannelWebhook} {
		if !tp.Valid() {
			t.Errorf("Valid(%q) = false, want true", tp)
		}
	}
	for _, tp := range []NotifyChannelType{"", "slack", "email"} {
		if tp.Valid() {
			t.Errorf("Valid(%q) = true, want false", tp)
		}
	}
}

func TestNotifyChannelSubscribes(t *testing.T) {
	// Empty list = subscribe to all.
	all := NotifyChannel{}
	if !all.Subscribes(EventAccountExpired) || !all.Subscribes(EventQuotaLow) {
		t.Error("empty Events should subscribe to all kinds")
	}
	// Specific list.
	ch := NotifyChannel{Events: []NotifyEventKind{EventAccountCooldown, EventAccountRecovered}}
	if !ch.Subscribes(EventAccountCooldown) {
		t.Error("Subscribes(cooldown) = false, want true")
	}
	if ch.Subscribes(EventQuotaLow) {
		t.Error("Subscribes(quota_low) = true, want false")
	}
}

func TestNotifyEventDedupKey(t *testing.T) {
	a := NotifyEvent{Kind: EventAccountCooldown, AccountID: "acct_1", Endpoint: "prod"}
	b := NotifyEvent{Kind: EventAccountCooldown, AccountID: "acct_1", Endpoint: "prod"}
	c := NotifyEvent{Kind: EventAccountCooldown, AccountID: "acct_2", Endpoint: "prod"}
	if a.DedupKey() != b.DedupKey() {
		t.Errorf("identical events differ: %q vs %q", a.DedupKey(), b.DedupKey())
	}
	if a.DedupKey() == c.DedupKey() {
		t.Errorf("different accounts share a key: %q", a.DedupKey())
	}
}
