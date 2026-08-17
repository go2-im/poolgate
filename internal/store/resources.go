// resources.go adds the resource CRUD the admin API (internal/admin, DESIGN.md
// §3 / Phase 3) needs beyond the hot-path reads already in store.go: deleting
// accounts / api keys / endpoints, listing full endpoint and policy-group
// objects, and updating / deleting policy groups. These are plain SQL over the
// tables defined by migrations v1/v2 — no new migration is introduced.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/go2-im/poolgate/internal/model"
)

// ---- accounts -------------------------------------------------------------

// DeleteAccount removes one account by id. ErrNotFound if it does not exist.
// Foreign keys ON DELETE CASCADE clean up usage_snapshots / health_checks; the
// account's group_members rows are removed in the SAME transaction so a deleted
// account never leaves a dangling member id that would break endpoint routing.
func (s *Store) DeleteAccount(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin delete account: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM group_members WHERE member_type = ? AND member_id = ?`,
		memberTypeAccount, id); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("store: clear account group memberships: %w", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM accounts WHERE id = ?`, id)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("store: delete account: %w", err)
	}
	if err := oneRow(res, "delete account"); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit delete account: %w", err)
	}
	// Remove any pending rotation journal for the now-deleted account, fail-closed:
	// a leftover journal (encrypted for a gone account) would otherwise permanently
	// block backup / key rotation, which refuse while any journal is pending.
	if err := s.removeRotationJournal(id); err != nil {
		return fmt.Errorf("store: remove rotation journal for deleted account: %w", err)
	}
	return nil
}

// ---- api keys -------------------------------------------------------------

// GetApiKeyByID loads one inbound key by its id (not its secret value).
func (s *Store) GetApiKeyByID(ctx context.Context, id string) (model.ApiKey, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, key, key_hint, label, endpoints, expires_at, ip_allowlist FROM api_keys WHERE id = ?`, id)
	return scanApiKey(row)
}

// DeleteApiKey removes one inbound key by id. ErrNotFound if it does not exist.
func (s *Store) DeleteApiKey(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_keys WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete api key: %w", err)
	}
	return oneRow(res, "delete api key")
}

// ---- endpoints ------------------------------------------------------------

// ListEndpoints returns all endpoints (name + bound group id) ordered by name.
func (s *Store) ListEndpoints(ctx context.Context) ([]model.Endpoint, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, group_id FROM endpoints ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list endpoints: %w", err)
	}
	defer rows.Close()

	var out []model.Endpoint
	for rows.Next() {
		var e model.Endpoint
		if err := rows.Scan(&e.Name, &e.GroupID); err != nil {
			return nil, fmt.Errorf("store: scan endpoint: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DeleteEndpoint removes one endpoint by name. ErrNotFound if it does not exist.
func (s *Store) DeleteEndpoint(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM endpoints WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("store: delete endpoint: %w", err)
	}
	return oneRow(res, "delete endpoint")
}

// ---- policy groups --------------------------------------------------------

// ListPolicyGroups returns all policy groups (each with its ordered account
// member ids) ordered by name.
func (s *Store) ListPolicyGroups(ctx context.Context) ([]model.PolicyGroup, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id FROM policy_groups ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list policy groups: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: scan policy group id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]model.PolicyGroup, 0, len(ids))
	for _, id := range ids {
		g, err := s.GetPolicyGroup(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

// UpdatePolicyGroup rewrites a group's strategy and its ordered account members
// in a transaction (the members are fully replaced by g.MemberAccountIDs). The
// group name is immutable here (it is the stable handle); ErrNotFound if the id
// does not exist.
func (s *Store) UpdatePolicyGroup(ctx context.Context, g model.PolicyGroup) error {
	if g.ID == "" {
		return errors.New("store: update policy group missing id")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin update group: %w", err)
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE policy_groups SET strategy = ? WHERE id = ?`,
		string(g.Strategy), g.ID)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("store: update group: %w", err)
	}
	if err := oneRow(res, "update group"); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM group_members WHERE group_id = ? AND member_type = ?`,
		g.ID, memberTypeAccount); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("store: clear group members: %w", err)
	}
	for i, accID := range g.MemberAccountIDs {
		if err := assertAccountExistsTx(ctx, tx, accID); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO group_members (group_id, member_type, member_id, position, weight) VALUES (?, ?, ?, ?, ?)`,
			g.ID, memberTypeAccount, accID, i, g.Weight(accID)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: insert group member: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit update group: %w", err)
	}
	return nil
}

// DeletePolicyGroup removes one policy group by id (its group_members rows
// cascade). It fails when an endpoint still references the group (the endpoints
// FK is ON DELETE RESTRICT) — the admin layer maps that to a conflict.
func (s *Store) DeletePolicyGroup(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM policy_groups WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete policy group: %w", err)
	}
	return oneRow(res, "delete policy group")
}
