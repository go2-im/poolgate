// login.go implements `poolgate login`: the interactive OAuth authorization-code
// + PKCE flow (internal/oauth) that adds a pooled account by signing in through
// the browser instead of pasting a Codex auth.json.
//
// The OAuth callback is a loopback listener on this host (127.0.0.1:1455, per the
// Codex client's registered redirect_uri), so the flow is run locally on the
// poolgate host — either at its console or with `ssh -L 1455:127.0.0.1:1455` so a
// remote browser's callback reaches it. This is why login is a CLI command and
// not an admin-UI button: the redirect_uri is fixed to a loopback port that must
// be co-located with whatever completes the sign-in.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/oauth"
)

// loginTimeout bounds how long we wait for the browser redirect before giving up.
const loginTimeout = 5 * time.Minute

// loginRunner is the interactive-login surface cmdLogin drives. *oauth.Login
// satisfies it; tests substitute a fake via newLoginFlow so cmdLogin's store +
// bootstrap logic is exercised without the real OAuth mechanics (those are
// covered in internal/oauth).
type loginRunner interface {
	Run(ctx context.Context, prompt func(authorizeURL string)) (model.Account, error)
}

// newLoginFlow builds the login flow; overridable in tests.
var newLoginFlow = func() loginRunner { return oauth.NewLogin() }

// cmdLogin runs the interactive login and stores the resulting account, creating
// the default group/endpoint/key on the first account (same bootstrap as import).
func cmdLogin(ctx context.Context, args []string, stdout io.Writer) error {
	strategy, err := parseLoginArgs(args)
	if err != nil {
		return err
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	// Hold the maintenance lock for the whole login so a concurrent rotate-key
	// cannot re-encrypt the DB under us. Open the store only AFTER the (up-to-5-min)
	// OAuth flow completes, so the cipher/master key we seal the new account with is
	// the freshest one — never a snapshot captured before a rotation.
	mlk, err := acquireMaintenanceLock(cfg)
	if err != nil {
		return err
	}
	defer mlk.Release()

	ctx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()

	acct, err := newLoginFlow().Run(ctx, func(authorizeURL string) {
		fmt.Fprintf(stdout, "Open this URL in your browser to sign in:\n\n  %s\n\n"+
			"Waiting for the sign-in to complete (Ctrl-C to cancel)...\n", authorizeURL)
	})
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}

	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	acct.Label = "login-" + time.Now().UTC().Format("20060102-150405")
	acct, updated, err := st.UpsertAccountByAccountID(ctx, acct)
	if err != nil {
		return err
	}
	if updated {
		fmt.Fprintf(stdout, "\nsigned in: refreshed existing account %s (state %s)\n", acct.ID, acct.State)
	} else {
		fmt.Fprintf(stdout, "\nsigned in: account %s (label %q, state %s)\n", acct.ID, acct.Label, acct.State)
	}
	if acct.AccountID == "" {
		fmt.Fprintf(stdout, "warning: the sign-in returned no ChatGPT account id; "+
			"proxy requests for this account may be rejected until it is set.\n")
	}

	return bootstrapDefaults(ctx, st, cfg, acct, strategy, stdout)
}

// parseLoginArgs parses the optional --strategy flag for `poolgate login`
// (mirrors import; there is no positional argument).
func parseLoginArgs(args []string) (model.Strategy, error) {
	strategy := model.StrategyFallback
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--strategy" || a == "-strategy":
			if i+1 >= len(args) {
				return "", errors.New("usage: poolgate login [--strategy fallback|best-quota|load-balance]")
			}
			strategy = model.Strategy(args[i+1])
			i++
		case len(a) > len("--strategy=") && a[:len("--strategy=")] == "--strategy=":
			strategy = model.Strategy(a[len("--strategy="):])
		default:
			return "", fmt.Errorf("unexpected argument %q (usage: poolgate login [--strategy ...])", a)
		}
	}
	if !validStrategy(strategy) {
		return "", fmt.Errorf("invalid --strategy %q (want fallback, best-quota, or load-balance)", strategy)
	}
	return strategy, nil
}
