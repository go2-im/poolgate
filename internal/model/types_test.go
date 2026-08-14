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
