package main

import (
	"context"
	"testing"

	"github.com/go2-im/poolgate/internal/oauth"
)

// TestOAuthLoginAdapter covers the thin adapter that lets *oauth.Login satisfy
// admin.OAuthLogin's headless methods through an opaque handle.
func TestOAuthLoginAdapter(t *testing.T) {
	a := oauthLoginAdapter{oauth.NewLogin()}

	authorizeURL, handle, err := a.BeginManual()
	if err != nil || authorizeURL == "" || handle == nil {
		t.Fatalf("BeginManual: url=%q handle=%v err=%v", authorizeURL, handle, err)
	}

	// A handle of the wrong type is rejected.
	if _, err := a.CompleteManual(context.Background(), "not-a-handle", "x"); err == nil {
		t.Fatal("CompleteManual with wrong-type handle: want error")
	}

	// The real handle with an unparseable paste fails before any network call.
	if _, err := a.CompleteManual(context.Background(), handle, "garbage-no-code"); err == nil {
		t.Fatal("CompleteManual with bad paste: want error")
	}
}
