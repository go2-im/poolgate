// Package authimport parses a Codex `auth.json` into a model.Account for
// explicit, manual import (DESIGN.md §17: never auto-imported). It reads the
// nested `tokens` object (access_token, refresh_token, account_id, id_token)
// and ignores everything else in the file.
package authimport

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	return model.Account{
		AccessToken:  a.Tokens.AccessToken,
		RefreshToken: a.Tokens.RefreshToken,
		AccountID:    a.Tokens.AccountID,
		IDToken:      a.Tokens.IDToken,
		State:        model.StateUnknown,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}
