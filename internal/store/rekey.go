// rekey.go implements master-key rotation at the storage layer (DESIGN.md §22.6):
// re-encrypting every field-encrypted secret column from the store's current
// cipher to a new one, atomically in a single transaction. The encrypted columns
// are accounts.access_token / accounts.refresh_token and notify_channels.config
// (id_token is stored in the clear). If any row fails to decrypt/re-encrypt the
// whole transaction rolls back, leaving the DB entirely on the old key.
package store

import (
	"context"
	"fmt"

	"github.com/go2-im/poolgate/internal/crypto"
)

// RotateSecrets re-encrypts all secret columns from the store's current cipher to
// newCipher in one transaction and reports how many accounts and notify channels
// were rewritten. On any error nothing is committed.
func (s *Store) RotateSecrets(ctx context.Context, newCipher *crypto.Cipher) (accounts, channels int, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("store: begin rotate: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// --- accounts.access_token / refresh_token ---
	type acctRow struct{ id, access, refresh string }
	var accts []acctRow
	rows, err := tx.QueryContext(ctx, `SELECT id, access_token, refresh_token FROM accounts`)
	if err != nil {
		return 0, 0, fmt.Errorf("store: read accounts for rotate: %w", err)
	}
	for rows.Next() {
		var id, sealedA, sealedR string
		if err := rows.Scan(&id, &sealedA, &sealedR); err != nil {
			rows.Close()
			return 0, 0, fmt.Errorf("store: scan account for rotate: %w", err)
		}
		access, err := s.cipher.Open(sealedA)
		if err != nil {
			rows.Close()
			return 0, 0, fmt.Errorf("store: decrypt access token for %s: %w", id, err)
		}
		refresh, err := s.cipher.Open(sealedR)
		if err != nil {
			rows.Close()
			return 0, 0, fmt.Errorf("store: decrypt refresh token for %s: %w", id, err)
		}
		na, err := newCipher.Seal(access)
		if err != nil {
			rows.Close()
			return 0, 0, fmt.Errorf("store: re-seal access token for %s: %w", id, err)
		}
		nr, err := newCipher.Seal(refresh)
		if err != nil {
			rows.Close()
			return 0, 0, fmt.Errorf("store: re-seal refresh token for %s: %w", id, err)
		}
		accts = append(accts, acctRow{id: id, access: na, refresh: nr})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, 0, fmt.Errorf("store: iterate accounts for rotate: %w", err)
	}
	rows.Close()

	// --- notify_channels.config ---
	type chRow struct{ id, config string }
	var chans []chRow
	crows, err := tx.QueryContext(ctx, `SELECT id, config FROM notify_channels`)
	if err != nil {
		return 0, 0, fmt.Errorf("store: read notify channels for rotate: %w", err)
	}
	for crows.Next() {
		var id, sealedCfg string
		if err := crows.Scan(&id, &sealedCfg); err != nil {
			crows.Close()
			return 0, 0, fmt.Errorf("store: scan notify channel for rotate: %w", err)
		}
		cfg, err := s.cipher.Open(sealedCfg)
		if err != nil {
			crows.Close()
			return 0, 0, fmt.Errorf("store: decrypt notify config for %s: %w", id, err)
		}
		nc, err := newCipher.Seal(cfg)
		if err != nil {
			crows.Close()
			return 0, 0, fmt.Errorf("store: re-seal notify config for %s: %w", id, err)
		}
		chans = append(chans, chRow{id: id, config: nc})
	}
	if err := crows.Err(); err != nil {
		crows.Close()
		return 0, 0, fmt.Errorf("store: iterate notify channels for rotate: %w", err)
	}
	crows.Close()

	// All decryption succeeded (the old key was correct) — now write the re-sealed
	// values. Any failure here rolls back the whole rotation.
	for _, a := range accts {
		if _, err := tx.ExecContext(ctx,
			`UPDATE accounts SET access_token = ?, refresh_token = ? WHERE id = ?`,
			a.access, a.refresh, a.id); err != nil {
			return 0, 0, fmt.Errorf("store: rewrite account %s: %w", a.id, err)
		}
	}
	for _, c := range chans {
		if _, err := tx.ExecContext(ctx,
			`UPDATE notify_channels SET config = ? WHERE id = ?`, c.config, c.id); err != nil {
			return 0, 0, fmt.Errorf("store: rewrite notify channel %s: %w", c.id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("store: commit rotate: %w", err)
	}
	return len(accts), len(chans), nil
}
