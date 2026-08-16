package authimport

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
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

func TestParseMissingAccessToken(t *testing.T) {
	in := `{"tokens":{"refresh_token":"r","account_id":"x"}}`
	if _, err := Parse([]byte(in)); !errors.Is(err, ErrNoTokens) {
		t.Fatalf("want ErrNoTokens for missing access, got %v", err)
	}
}

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	got, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if got.AccessToken != "access-abc" {
		t.Errorf("access = %q", got.AccessToken)
	}
	if got.RefreshToken != "refresh-xyz" {
		t.Errorf("refresh = %q", got.RefreshToken)
	}
	if got.State != model.StateUnknown {
		t.Errorf("state = %q want unknown", got.State)
	}
}

func TestParseFileMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	if _, err := ParseFile(path); err == nil {
		t.Fatal("expected error for missing file")
	} else if !os.IsNotExist(errors.Unwrap(err)) {
		t.Fatalf("want not-exist error, got %v", err)
	}
}

func TestParseFileMalformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := ParseFile(path); err == nil {
		t.Fatal("expected parse error for malformed file")
	}
}

func TestParseFallsBackToIDTokenAccountID(t *testing.T) {
	// id_token payload carrying the chatgpt_account_id claim, no top-level account_id.
	payload := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"https://api.openai.com/auth":{"chatgpt_account_id":"acc_from_idtoken"}}`))
	idToken := "aGVhZGVy." + payload + ".sig"
	data := `{"tokens":{"access_token":"at","refresh_token":"rt","id_token":"` + idToken + `"}}`

	acct, err := Parse([]byte(data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if acct.AccountID != "acc_from_idtoken" {
		t.Errorf("AccountID = %q, want acc_from_idtoken (from id_token claim)", acct.AccountID)
	}
}

func TestParsePrefersExplicitAccountID(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"https://api.openai.com/auth":{"chatgpt_account_id":"from_idtoken"}}`))
	idToken := "h." + payload + ".s"
	data := `{"tokens":{"access_token":"at","refresh_token":"rt","account_id":"explicit","id_token":"` + idToken + `"}}`
	acct, err := Parse([]byte(data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if acct.AccountID != "explicit" {
		t.Errorf("AccountID = %q, want explicit (top-level wins)", acct.AccountID)
	}
}
