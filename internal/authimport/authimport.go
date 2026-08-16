// Package authimport parses a Codex `auth.json` into a model.Account for
// explicit, manual import (DESIGN.md §17: never auto-imported). It reads the
// nested `tokens` object (access_token, refresh_token, account_id, id_token)
// and ignores everything else in the file.
package authimport

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// authDotJSON mirrors the subset of Codex's auth.json that poolgate needs.
type authDotJSON struct {
	Tokens *tokenData `json:"tokens"`
}

// tokenData mirrors Codex's TokenData (login/src/token_data.rs). id_token is a
// raw JWT string on disk; poolgate stores it verbatim.
type tokenData struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	AccountID    string `json:"account_id"`
}

// ErrNoTokens is returned when the file has no usable `tokens` object.
var ErrNoTokens = errors.New("authimport: auth.json has no tokens")

// ParseFile reads and parses a Codex auth.json at path.
func ParseFile(path string) (model.Account, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return model.Account{}, fmt.Errorf("authimport: read %q: %w", path, err)
	}
	return Parse(data)
}

// Parse decodes Codex auth.json bytes into a model.Account. The account starts
// in StateUnknown with timestamps set to now; the caller assigns ID/Label.
func Parse(data []byte) (model.Account, error) {
	var a authDotJSON
	if err := json.Unmarshal(data, &a); err != nil {
		return model.Account{}, fmt.Errorf("authimport: parse auth.json: %w", err)
	}
	if a.Tokens == nil {
		return model.Account{}, ErrNoTokens
	}
	if a.Tokens.AccessToken == "" || a.Tokens.RefreshToken == "" {
		return model.Account{}, fmt.Errorf("authimport: %w: missing access/refresh token", ErrNoTokens)
	}
	now := time.Now().UTC()
	accountID := a.Tokens.AccountID
	if accountID == "" {
		// Some Codex auth.json variants carry the account id only inside the
		// id_token's `https://api.openai.com/auth`.chatgpt_account_id claim (the
		// login flow reads it the same way). Fall back to it so the imported
		// account has a ChatGPT-Account-ID to send upstream.
		accountID = accountIDFromIDToken(a.Tokens.IDToken)
	}
	return model.Account{
		AccessToken:  a.Tokens.AccessToken,
		RefreshToken: a.Tokens.RefreshToken,
		AccountID:    accountID,
		IDToken:      a.Tokens.IDToken,
		State:        model.StateUnknown,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

// accountIDFromIDToken extracts chatgpt_account_id from the id_token's
// `https://api.openai.com/auth` claim. The token comes from the operator's own
// Codex install (fetched over TLS from the pinned issuer), so the payload is
// decoded without signature verification — same as the login flow. Returns "" on
// any parse failure.
func accountIDFromIDToken(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Auth struct {
			ChatGPTAccountID string `json:"chatgpt_account_id"`
		} `json:"https://api.openai.com/auth"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Auth.ChatGPTAccountID
}
