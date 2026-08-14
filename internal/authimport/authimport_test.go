package authimport

import (
	"errors"
	"testing"

	"github.com/go2-im/poolgate/internal/model"
)

const fixture = `{
  "OPENAI_API_KEY": null,
  "tokens": {
    "id_token": "eyJhbGciOiJ.payload.sig",
    "access_token": "access-abc",
    "refresh_token": "refresh-xyz",
    "account_id": "acct-123"
  },
  "last_refresh": "2026-08-13T00:00:00Z"
}`

func TestParse(t *testing.T) {
	got, err := Parse([]byte(fixture))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.AccessToken != "access-abc" {
		t.Errorf("access = %q", got.AccessToken)
	}
	if got.RefreshToken != "refresh-xyz" {
		t.Errorf("refresh = %q", got.RefreshToken)
	}
	if got.AccountID != "acct-123" {
		t.Errorf("account_id = %q", got.AccountID)
	}
	if got.IDToken != "eyJhbGciOiJ.payload.sig" {
		t.Errorf("id_token = %q", got.IDToken)
	}
	if got.State != model.StateUnknown {
		t.Errorf("state = %q want unknown", got.State)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("timestamps not set")
	}
}

func TestParseNoTokens(t *testing.T) {
	if _, err := Parse([]byte(`{"OPENAI_API_KEY":"sk-x"}`)); !errors.Is(err, ErrNoTokens) {
		t.Fatalf("want ErrNoTokens, got %v", err)
	}
}

func TestParseMissingRequiredToken(t *testing.T) {
	in := `{"tokens":{"access_token":"a","account_id":"x"}}`
	if _, err := Parse([]byte(in)); !errors.Is(err, ErrNoTokens) {
		t.Fatalf("want ErrNoTokens for missing refresh, got %v", err)
	}
}

func TestParseInvalidJSON(t *testing.T) {
	if _, err := Parse([]byte("{not json")); err == nil {
		t.Fatal("expected parse error")
	}
}
