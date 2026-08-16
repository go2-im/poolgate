package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/go2-im/poolgate/internal/model"
)

// fakeLoginFlow is a scriptable loginRunner: it optionally invokes prompt (to
// exercise the printed-URL path) then returns a canned account or error.
type fakeLoginFlow struct {
	acct model.Account
	err  error
}

func (f fakeLoginFlow) Run(_ context.Context, prompt func(string)) (model.Account, error) {
	if prompt != nil {
		prompt("https://auth.example/oauth/authorize?state=x")
	}
	return f.acct, f.err
}

// withFakeLogin swaps newLoginFlow for the duration of a test.
func withFakeLogin(t *testing.T, f loginRunner) {
	t.Helper()
	orig := newLoginFlow
	newLoginFlow = func() loginRunner { return f }
	t.Cleanup(func() { newLoginFlow = orig })
}

func TestCmdLoginFirstAccountBootstraps(t *testing.T) {
	t.Setenv(envDataDir, t.TempDir())
	t.Setenv(envMasterKey, "")
	if err := cmdInit(nil, io.Discard); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}
	withFakeLogin(t, fakeLoginFlow{acct: model.Account{
		AccessToken: "at", RefreshToken: "rt", AccountID: "acc-1", State: model.StateUnknown,
	}})

	var out bytes.Buffer
	if err := cmdLogin(context.Background(), nil, &out); err != nil {
		t.Fatalf("cmdLogin: %v", err)
	}
	s := out.String()
	for _, want := range []string{"signed in", "created default", "API key"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q; got:\n%s", want, s)
		}
	}
	if strings.Contains(s, "warning: the sign-in returned no ChatGPT account id") {
		t.Error("unexpected missing-account-id warning when account id was present")
	}
}

func TestCmdLoginWarnsOnMissingAccountID(t *testing.T) {
	t.Setenv(envDataDir, t.TempDir())
	t.Setenv(envMasterKey, "")
	if err := cmdInit(nil, io.Discard); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}
	withFakeLogin(t, fakeLoginFlow{acct: model.Account{
		AccessToken: "at", RefreshToken: "rt", AccountID: "", State: model.StateUnknown,
	}})

	var out bytes.Buffer
	if err := cmdLogin(context.Background(), nil, &out); err != nil {
		t.Fatalf("cmdLogin: %v", err)
	}
	if !strings.Contains(out.String(), "warning: the sign-in returned no ChatGPT account id") {
		t.Errorf("expected missing-account-id warning; got:\n%s", out.String())
	}
}

func TestCmdLoginFlowError(t *testing.T) {
	t.Setenv(envDataDir, t.TempDir())
	t.Setenv(envMasterKey, "")
	if err := cmdInit(nil, io.Discard); err != nil {
		t.Fatalf("cmdInit: %v", err)
	}
	withFakeLogin(t, fakeLoginFlow{err: errors.New("denied")})
	if err := cmdLogin(context.Background(), nil, io.Discard); err == nil {
		t.Fatal("cmdLogin with flow error = nil, want error")
	}
}

func TestParseLoginArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    model.Strategy
		wantErr bool
	}{
		{"default", nil, model.StrategyFallback, false},
		{"flag spaced", []string{"--strategy", "best-quota"}, model.Strategy("best-quota"), false},
		{"flag equals", []string{"--strategy=load-balance"}, model.Strategy("load-balance"), false},
		{"invalid strategy", []string{"--strategy", "bogus"}, "", true},
		{"missing value", []string{"--strategy"}, "", true},
		{"unexpected positional", []string{"foo.json"}, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseLoginArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("strategy = %q, want %q", got, tc.want)
			}
		})
	}
}
