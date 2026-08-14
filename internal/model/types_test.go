package model

import "testing"

func TestAccountStateValid(t *testing.T) {
	tests := []struct {
		name  string
		state AccountState
		want  bool
	}{
		{"ok", StateOK, true},
		{"cooldown", StateCooldown, true},
		{"quota_exhausted", StateQuotaExhausted, true},
		{"expired", StateExpired, true},
		{"unknown", StateUnknown, true},
		{"revoked", StateRevoked, true},
		{"dead", StateDead, true},
		{"empty", AccountState(""), false},
		{"garbage", AccountState("bogus"), false},
		{"case-sensitive", AccountState("OK"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.Valid(); got != tt.want {
				t.Errorf("AccountState(%q).Valid() = %v, want %v", tt.state, got, tt.want)
			}
		})
	}
}

func TestAccountStateTerminal(t *testing.T) {
	tests := []struct {
		name  string
		state AccountState
		want  bool
	}{
		{"ok", StateOK, false},
		{"cooldown", StateCooldown, false},
		{"quota_exhausted", StateQuotaExhausted, false},
		{"expired", StateExpired, false},
		{"unknown", StateUnknown, false},
		{"revoked", StateRevoked, true},
		{"dead", StateDead, true},
		{"empty", AccountState(""), false},
		{"garbage", AccountState("bogus"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.Terminal(); got != tt.want {
				t.Errorf("AccountState(%q).Terminal() = %v, want %v", tt.state, got, tt.want)
			}
		})
	}
}

// TestTerminalStatesAreValid guards the invariant that every terminal state is
// also a recognized (valid) state.
func TestTerminalStatesAreValid(t *testing.T) {
	for _, s := range []AccountState{StateRevoked, StateDead} {
		if !s.Valid() {
			t.Errorf("terminal state %q should be Valid()", s)
		}
		if !s.Terminal() {
			t.Errorf("state %q should be Terminal()", s)
		}
	}
}

// TestUsageWindowHeadroom covers the (100 - used_percent) computation and its
// clamping to [0,100] (DESIGN.md §4 / §24.2).
func TestUsageWindowHeadroom(t *testing.T) {
	tests := []struct {
		name string
		used float64
		want float64
	}{
		{"unused", 0, 100},
		{"half", 40, 60},
		{"full", 100, 0},
		{"over 100 clamps to 0", 130, 0},
		{"negative used clamps to 100", -20, 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := UsageWindow{Name: "primary", UsedPercent: tt.used}
			if got := w.Headroom(); got != tt.want {
				t.Errorf("UsageWindow{UsedPercent:%v}.Headroom() = %v, want %v", tt.used, got, tt.want)
			}
		})
	}
}
