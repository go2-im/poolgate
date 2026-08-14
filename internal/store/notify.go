// notify.go adds CRUD for notification channels (DESIGN.md §11) over the
// notify_channels table introduced by migration v4. The channel's Config carries
// secrets (webhook URL, signing secret), so — like account tokens — it is
// field-encrypted with the crypto cipher: the Config struct is JSON-marshaled and
// sealed on write, opened and unmarshaled on read. It is never stored in
// plaintext (DESIGN.md §5 / SECURITY.md).
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go2-im/poolgate/internal/model"
)

// InsertNotifyChannel seals the Config and inserts the channel. If ch.ID is empty
// a random id is generated. The stored channel (with its final ID/timestamps) is
// returned.
func (s *Store) InsertNotifyChannel(ctx context.Context, ch model.NotifyChannel) (model.NotifyChannel, error) {
	if !ch.Type.Valid() {
		return model.NotifyChannel{}, fmt.Errorf("store: invalid notify channel type %q", ch.Type)
	}
	if ch.ID == "" {
		ch.ID = newID("ntf")
	}
	now := time.Now().UTC()
	if ch.CreatedAt.IsZero() {
		ch.CreatedAt = now
	}
	if ch.UpdatedAt.IsZero() {
		ch.UpdatedAt = ch.CreatedAt
	}
	sealed, events, err := s.encodeChannel(ch)
	if err != nil {
		return model.NotifyChannel{}, err
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO notify_channels
	(id, type, name, enabled, config, events, min_headroom, dedup_seconds, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ch.ID, string(ch.Type), ch.Name, boolToInt(ch.Enabled), sealed, events,
		ch.MinHeadroom, ch.DedupSeconds, formatTime(ch.CreatedAt), formatTime(ch.UpdatedAt),
	); err != nil {
		return model.NotifyChannel{}, fmt.Errorf("store: insert notify channel: %w", err)
	}
	return ch, nil
}

// GetNotifyChannel loads and decrypts one channel by id.
func (s *Store) GetNotifyChannel(ctx context.Context, id string) (model.NotifyChannel, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, type, name, enabled, config, events, min_headroom, dedup_seconds, created_at, updated_at
FROM notify_channels WHERE id = ?`, id)
	return s.scanNotifyChannel(row)
}

// ListNotifyChannels returns all channels (with decrypted Config) ordered by
// creation time then id. This is the surface the notify.Engine polls.
func (s *Store) ListNotifyChannels(ctx context.Context) ([]model.NotifyChannel, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, type, name, enabled, config, events, min_headroom, dedup_seconds, created_at, updated_at
FROM notify_channels ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list notify channels: %w", err)
	}
	defer rows.Close()

	var out []model.NotifyChannel
	for rows.Next() {
		ch, err := s.scanNotifyChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ch)
	}
	return out, rows.Err()
}

// UpdateNotifyChannel rewrites a channel's mutable fields (type is immutable) and
// reseals its Config, bumping updated_at. ErrNotFound if the id does not exist.
func (s *Store) UpdateNotifyChannel(ctx context.Context, ch model.NotifyChannel) error {
	if ch.ID == "" {
		return errors.New("store: update notify channel missing id")
	}
	if !ch.Type.Valid() {
		return fmt.Errorf("store: invalid notify channel type %q", ch.Type)
	}
	ch.UpdatedAt = time.Now().UTC()
	sealed, events, err := s.encodeChannel(ch)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE notify_channels SET
	type = ?, name = ?, enabled = ?, config = ?, events = ?,
	min_headroom = ?, dedup_seconds = ?, updated_at = ?
WHERE id = ?`,
		string(ch.Type), ch.Name, boolToInt(ch.Enabled), sealed, events,
		ch.MinHeadroom, ch.DedupSeconds, formatTime(ch.UpdatedAt), ch.ID)
	if err != nil {
		return fmt.Errorf("store: update notify channel: %w", err)
	}
	return oneRow(res, "update notify channel")
}

// DeleteNotifyChannel removes one channel by id. ErrNotFound if it does not exist.
func (s *Store) DeleteNotifyChannel(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM notify_channels WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete notify channel: %w", err)
	}
	return oneRow(res, "delete notify channel")
}

// encodeChannel marshals + seals the Config and marshals the events list. It
// returns the sealed config blob and the events JSON, ready for SQL binding.
func (s *Store) encodeChannel(ch model.NotifyChannel) (sealedConfig, eventsJSON string, err error) {
	cfgJSON, err := json.Marshal(ch.Config)
	if err != nil {
		return "", "", fmt.Errorf("store: marshal notify config: %w", err)
	}
	sealed, err := s.cipher.Seal(string(cfgJSON))
	if err != nil {
		return "", "", fmt.Errorf("store: seal notify config: %w", err)
	}
	events := ch.Events
	if events == nil {
		events = []model.NotifyEventKind{}
	}
	ev, err := json.Marshal(events)
	if err != nil {
		return "", "", fmt.Errorf("store: marshal notify events: %w", err)
	}
	return sealed, string(ev), nil
}

func (s *Store) scanNotifyChannel(sc rowScanner) (model.NotifyChannel, error) {
	var (
		ch                 model.NotifyChannel
		typ                string
		enabled            int
		sealedConfig       string
		events             string
		createdAt, updated string
	)
	if err := sc.Scan(&ch.ID, &typ, &ch.Name, &enabled, &sealedConfig, &events,
		&ch.MinHeadroom, &ch.DedupSeconds, &createdAt, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.NotifyChannel{}, ErrNotFound
		}
		return model.NotifyChannel{}, fmt.Errorf("store: scan notify channel: %w", err)
	}
	cfgJSON, err := s.cipher.Open(sealedConfig)
	if err != nil {
		return model.NotifyChannel{}, fmt.Errorf("store: open notify config: %w", err)
	}
	if err := json.Unmarshal([]byte(cfgJSON), &ch.Config); err != nil {
		return model.NotifyChannel{}, fmt.Errorf("store: unmarshal notify config: %w", err)
	}
	if err := json.Unmarshal([]byte(events), &ch.Events); err != nil {
		return model.NotifyChannel{}, fmt.Errorf("store: unmarshal notify events: %w", err)
	}
	ch.Type = model.NotifyChannelType(typ)
	ch.Enabled = enabled != 0
	ch.CreatedAt = parseTime(createdAt)
	ch.UpdatedAt = parseTime(updated)
	return ch, nil
}
