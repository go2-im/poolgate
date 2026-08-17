// rotation_journal.go implements a durable, field-encrypted journal for OAuth
// refresh-token rotation (DESIGN.md §19.3). The hazard it closes: once the issuer
// returns a rotated refresh_token, the OLD one may already be single-use-invalidated
// upstream. If the local DB write of the new token then fails (transient I/O, a
// crash), the new token would be lost and the next refresh would resubmit the OLD
// token — tripping the issuer's reuse detection and revoking the whole token family
// (permanent account breakage).
//
// The journal makes the rotated token durable BEFORE the DB write and only removes
// it once the DB write succeeds, so a failed/interrupted write leaves the new token
// recoverable. It lives OUTSIDE the SQLite database (a file per account under
// <dataDir>/rotations) precisely because the failure mode is the DB write itself —
// an in-DB journal could not survive it. Entries are field-encrypted with the same
// cipher as the token columns, so the journal never holds plaintext secrets.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// rotationJournalDir is the per-account rotation-journal subdirectory of DataDir.
const rotationJournalDir = "rotations"

// rotationJournalEntry is the on-disk journal record. Access/Refresh are SEALED
// (field-encrypted) exactly like the accounts token columns.
type rotationJournalEntry struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
	At      string `json:"at"`
}

func (s *Store) rotationsDir() string { return filepath.Join(s.dataDir, rotationJournalDir) }

// rotationJournalPath maps an account id to its journal file. Account ids are
// store-generated (prefix + hex), never user input, but reject any separator/".."
// defensively so a journal write can never escape the rotations dir.
func (s *Store) rotationJournalPath(id string) (string, error) {
	if id == "" || strings.ContainsRune(id, os.PathSeparator) || strings.Contains(id, "..") {
		return "", fmt.Errorf("store: unsafe rotation journal id %q", id)
	}
	return filepath.Join(s.rotationsDir(), id+".json"), nil
}

// CommitRotatedTokens durably persists a rotated (access, refresh) pair for an
// account: it first writes the fsync'd, encrypted journal entry, then writes the
// tokens to the DB (with bounded retry on transient contention), and only removes
// the journal once the DB write succeeds. If the DB write fails the journal is
// RETAINED so the new token is recoverable (flushed on the next refresh or at the
// next Open) rather than lost — which would force a reuse of the now-stale token.
func (s *Store) CommitRotatedTokens(ctx context.Context, id, accessToken, refreshToken string) error {
	if s.dataDir == "" {
		// No place to journal (in-memory/test store): fall back to a retrying write.
		return s.updateTokensWithRetry(ctx, id, accessToken, refreshToken)
	}
	if err := s.writeRotationJournal(id, accessToken, refreshToken); err != nil {
		return fmt.Errorf("store: write rotation journal: %w", err)
	}
	if err := s.updateTokensWithRetry(ctx, id, accessToken, refreshToken); err != nil {
		// Journal retained on purpose — the rotated token is durable and will be
		// flushed later; do NOT remove it.
		return fmt.Errorf("store: persist rotated tokens (journaled for retry): %w", err)
	}
	_ = s.removeRotationJournal(id)
	return nil
}

// FlushPendingRotation applies any pending journaled rotation for an account to the
// DB and removes the journal on success. It is a no-op when no journal exists. If
// the account no longer exists (deleted) the moot journal is dropped. Callers must
// run this BEFORE using an account's DB refresh_token, so a rotation that failed to
// persist is reconciled instead of resubmitting a stale token.
func (s *Store) FlushPendingRotation(ctx context.Context, id string) error {
	if s.dataDir == "" {
		return nil
	}
	entry, ok, err := s.readRotationJournal(id)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if err := s.updateTokensWithRetry(ctx, id, entry.Access, entry.Refresh); err != nil {
		if errors.Is(err, ErrNotFound) {
			_ = s.removeRotationJournal(id) // account gone; journal is moot
			return nil
		}
		return fmt.Errorf("store: flush pending rotation: %w", err)
	}
	return s.removeRotationJournal(id)
}

// replayTokenRotations flushes every pending rotation journal at startup so a
// rotation that failed to persist before a restart is reconciled before any request
// can trigger a refresh with a stale token. Best-effort: a journal that still cannot
// be applied is left in place for a later retry (never bricks Open).
func (s *Store) replayTokenRotations(ctx context.Context) {
	if s.dataDir == "" {
		return
	}
	matches, err := filepath.Glob(filepath.Join(s.rotationsDir(), "*.json"))
	if err != nil {
		return
	}
	for _, p := range matches {
		id := strings.TrimSuffix(filepath.Base(p), ".json")
		_ = s.FlushPendingRotation(ctx, id)
	}
}

// writeRotationJournal seals the tokens and writes the journal entry atomically:
// temp file (write + fsync) -> rename -> fsync dir, so an interrupted write never
// publishes a partial/plaintext entry.
func (s *Store) writeRotationJournal(id, accessToken, refreshToken string) error {
	path, err := s.rotationJournalPath(id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.rotationsDir(), 0o700); err != nil {
		return err
	}
	sealedAccess, err := s.cipher.Seal(accessToken)
	if err != nil {
		return fmt.Errorf("seal access: %w", err)
	}
	sealedRefresh, err := s.cipher.Seal(refreshToken)
	if err != nil {
		return fmt.Errorf("seal refresh: %w", err)
	}
	data, err := json.Marshal(rotationJournalEntry{
		Access: sealedAccess, Refresh: sealedRefresh, At: formatTime(time.Now().UTC()),
	})
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDirStore(s.rotationsDir())
}

// readRotationJournal loads and decrypts the pending journal for an account, if any.
func (s *Store) readRotationJournal(id string) (rotationJournalEntry, bool, error) {
	path, err := s.rotationJournalPath(id)
	if err != nil {
		return rotationJournalEntry{}, false, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return rotationJournalEntry{}, false, nil
	}
	if err != nil {
		return rotationJournalEntry{}, false, err
	}
	var e rotationJournalEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return rotationJournalEntry{}, false, fmt.Errorf("store: decode rotation journal: %w", err)
	}
	access, err := s.cipher.Open(e.Access)
	if err != nil {
		return rotationJournalEntry{}, false, fmt.Errorf("store: open journaled access: %w", err)
	}
	refresh, err := s.cipher.Open(e.Refresh)
	if err != nil {
		return rotationJournalEntry{}, false, fmt.Errorf("store: open journaled refresh: %w", err)
	}
	return rotationJournalEntry{Access: access, Refresh: refresh, At: e.At}, true, nil
}

// removeRotationJournal deletes an account's journal file and fsyncs the dir so the
// deletion is durable (a resurrected journal would re-apply an already-applied token).
// A missing journal (or rotations dir) is not an error.
func (s *Store) removeRotationJournal(id string) error {
	path, err := s.rotationJournalPath(id)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // nothing to remove (and no dir to sync)
		}
		return err
	}
	return syncDirStore(s.rotationsDir())
}

// PendingRotationIDs returns the account ids that currently have an un-flushed
// rotation journal on disk. Backup and key rotation consult it to REFUSE to proceed
// while any journaled-but-unpersisted rotation exists: the journal is encrypted with
// the CURRENT master key and lives outside the DB snapshot, so backing up (which
// would omit it) or rotating the key (which would leave it undecryptable) past a
// pending journal would strand or lose the rotated token.
func (s *Store) PendingRotationIDs() ([]string, error) {
	return PendingRotationIDsAt(s.dataDir)
}

// PendingRotationIDsAt lists pending rotation-journal account ids under a data dir
// WITHOUT opening the database, so a caller (e.g. `poolgate backup`) can check for
// unresolved rotations without triggering an Open-time replay.
func PendingRotationIDsAt(dataDir string) ([]string, error) {
	if dataDir == "" {
		return nil, nil
	}
	matches, err := filepath.Glob(filepath.Join(dataDir, rotationJournalDir, "*.json"))
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(matches))
	for _, p := range matches {
		ids = append(ids, strings.TrimSuffix(filepath.Base(p), ".json"))
	}
	return ids, nil
}

// updateTokensWithRetry writes rotated tokens with a small bounded backoff on
// transient SQLite contention (busy/locked). ErrNotFound and non-transient errors
// return immediately. The DB already applies busy_timeout, so this only adds a thin
// extra margin for brief I/O contention on the safety-critical rotation write.
func (s *Store) updateTokensWithRetry(ctx context.Context, id, access, refresh string) error {
	const attempts = 4
	var err error
	for i := 0; i < attempts; i++ {
		err = s.UpdateTokens(ctx, id, access, refresh)
		if err == nil || errors.Is(err, ErrNotFound) || !isTransientStoreErr(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(10*(1<<i)) * time.Millisecond):
		}
	}
	return err
}

// isTransientStoreErr reports whether err is a retryable SQLite contention error.
func isTransientStoreErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "sqlite_busy") ||
		strings.Contains(msg, "database table is locked") ||
		strings.Contains(msg, "database is busy")
}

// syncDirStore fsyncs a directory so a rename/remove within it is durable. Errors
// are returned so durability-critical callers can react.
func syncDirStore(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}

// fsyncFile opens a file and fsyncs its contents to stable storage. Used to make a
// just-written recovery artifact (e.g. a pre-migration snapshot) durable before the
// code proceeds to mutate the live database.
func fsyncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
