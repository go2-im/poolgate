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

	"github.com/go2-im/poolgate/internal/lock"
)

// rotationJournalDir is the per-account rotation-journal subdirectory of DataDir.
const rotationJournalDir = "rotations"

// credentialLockFile is a per-data-dir advisory lock serializing ALL account
// credential mutations (online refresh commit, login/import replace, delete)
// ACROSS processes — a live `serve` refresh and a CLI `login` would otherwise
// clobber the same journal file / interleave DB writes (the in-process OAuth
// single-flight cannot span separate processes).
const credentialLockFile = ".credentials.lock"

// rotationJournalEntry is the on-disk journal record. Access/Refresh are SEALED
// (field-encrypted) exactly like the accounts token columns. Seq is a per-account
// monotonic counter so recovery can pick the NEWEST entry when both a committed
// <id>.json and a mid-write <id>.json.tmp survive a crash (an older .json must never
// shadow a newer .tmp — that would restore a stale, already-consumed token).
type rotationJournalEntry struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
	At      string `json:"at"`
	Seq     int64  `json:"seq"`
}

// withCredentialLock runs fn while holding the cross-process credential lock. For an
// in-memory/test store (no data dir) it just runs fn. The lock is BLOCKING so a
// concurrent holder is waited out rather than failing the caller. It is NOT
// reentrant — callers must not nest it (the credential mutators call only lock-free
// internal helpers underneath).
func (s *Store) withCredentialLock(fn func() error) error {
	if s.dataDir == "" {
		return fn()
	}
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		return fmt.Errorf("store: credential lock dir: %w", err)
	}
	lk, err := lock.AcquireBlocking(filepath.Join(s.dataDir, credentialLockFile))
	if err != nil {
		return fmt.Errorf("store: acquire credential lock: %w", err)
	}
	defer func() { _ = lk.Release() }()
	return fn()
}

func (s *Store) rotationsDir() string { return filepath.Join(s.dataDir, rotationJournalDir) }

// RotationsDir returns the rotation-journal directory path under a data dir, so
// out-of-package callers (e.g. `poolgate restore`) can move the whole journal
// generation aside without hardcoding the layout.
func RotationsDir(dataDir string) string { return filepath.Join(dataDir, rotationJournalDir) }

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
// account under the cross-process credential lock. expectedRefresh is the refresh
// token the caller USED for the upstream rotation; before overwriting, it CAS-checks
// that the account's current DB refresh token still equals it — if a concurrent
// login/rotation changed it in the meantime, this commit is SKIPPED (the newer write
// wins and our now-stale rotation is dropped) rather than clobbering fresh creds.
// Otherwise it writes the fsync'd journal, writes the DB (bounded retry), and removes
// the journal only on success; a failed DB write RETAINS the journal for recovery.
func (s *Store) CommitRotatedTokens(ctx context.Context, id, expectedRefresh, accessToken, refreshToken string) error {
	if s.dataDir == "" {
		// No place to journal (in-memory/test store): fall back to a retrying write.
		return s.updateTokensWithRetry(ctx, id, accessToken, refreshToken)
	}
	return s.withCredentialLock(func() error {
		// CAS: only overwrite if the DB still holds the token we rotated from. A
		// concurrent login/import may have replaced it — in that case the fresh creds
		// win and this rotation (derived from a now-superseded token) is discarded.
		cur, err := s.GetAccount(ctx, id)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				_ = s.removeRotationJournal(id)
				return ErrNotFound
			}
			return fmt.Errorf("store: re-read before rotation commit: %w", err)
		}
		if cur.RefreshToken != expectedRefresh {
			// Superseded: drop any journal we may hold and skip the write.
			_ = s.removeRotationJournal(id)
			return nil
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
	})
}

// FlushPendingRotation applies any pending journaled rotation for an account to the
// DB and removes the journal on success, under the cross-process credential lock. It
// is a no-op when no journal exists. If the account no longer exists (deleted) the
// moot journal is dropped. Callers must run this BEFORE using an account's DB
// refresh_token, so a rotation that failed to persist is reconciled instead of
// resubmitting a stale token.
func (s *Store) FlushPendingRotation(ctx context.Context, id string) error {
	if s.dataDir == "" {
		return nil
	}
	return s.withCredentialLock(func() error { return s.flushPendingRotationLocked(ctx, id) })
}

// flushPendingRotationLocked is the body of FlushPendingRotation; the caller holds
// the credential lock.
func (s *Store) flushPendingRotationLocked(ctx context.Context, id string) error {
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
// can trigger a refresh with a stale token. It covers both committed (<id>.json) and
// complete-but-unrenamed (<id>.json.tmp) journals via PendingRotationIDs. Best-effort:
// a journal that still cannot be applied is left in place for a later retry (never
// bricks Open) — and it keeps blocking backup/rotate-key until resolved.
func (s *Store) replayTokenRotations(ctx context.Context) {
	if s.dataDir == "" {
		return
	}
	ids, err := s.PendingRotationIDs()
	if err != nil {
		return
	}
	for _, id := range ids {
		_ = s.FlushPendingRotation(ctx, id)
	}
}

// writeRotationJournal seals the tokens and writes the journal entry atomically:
// temp file (write + fsync) -> rename -> fsync dir, so an interrupted write never
// publishes a partial/plaintext entry. The entry gets a per-account monotonic Seq
// (max of any existing .json/.tmp + 1) so recovery can pick the newest survivor.
// Callers that mutate credentials hold the credential lock, so the read-then-bump of
// Seq is race-free across processes.
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
		Seq: s.nextJournalSeq(path),
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

// nextJournalSeq returns one more than the highest Seq among any existing committed
// (<id>.json) or mid-write (<id>.json.tmp) entry — best-effort: an unreadable/corrupt
// candidate contributes 0, so a fresh entry always outranks it.
func (s *Store) nextJournalSeq(path string) int64 {
	var maxSeq int64
	for _, p := range []string{path, path + ".tmp"} {
		if raw, err := os.ReadFile(p); err == nil {
			var e rotationJournalEntry
			if json.Unmarshal(raw, &e) == nil && e.Seq > maxSeq {
				maxSeq = e.Seq
			}
		}
	}
	return maxSeq + 1
}

// readRotationJournal loads and decrypts the pending journal for an account, if any.
// When both a committed <id>.json and a mid-write <id>.json.tmp survive a crash it
// returns the one with the HIGHER Seq (the newest) — an older .json must never shadow
// a newer .tmp (which would restore a stale, already-consumed token). A candidate
// that cannot be decoded/decrypted is skipped; if the ONLY candidate is corrupt its
// error is surfaced so the caller leaves it in place (keeping the account blocked)
// rather than silently reusing the old DB token.
func (s *Store) readRotationJournal(id string) (rotationJournalEntry, bool, error) {
	path, err := s.rotationJournalPath(id)
	if err != nil {
		return rotationJournalEntry{}, false, err
	}
	var (
		best     rotationJournalEntry
		haveBest bool
		firstErr error
	)
	for _, p := range []string{path, path + ".tmp"} {
		e, ok, rerr := s.readJournalFile(p)
		if rerr != nil {
			if firstErr == nil {
				firstErr = rerr
			}
			continue
		}
		if ok && (!haveBest || e.Seq > best.Seq) {
			best, haveBest = e, true
		}
	}
	if haveBest {
		return best, true, nil
	}
	if firstErr != nil {
		return rotationJournalEntry{}, false, firstErr
	}
	return rotationJournalEntry{}, false, nil
}

// readJournalFile reads, JSON-decodes, and decrypts a single journal file. ok is
// false (nil error) when the file does not exist.
func (s *Store) readJournalFile(path string) (rotationJournalEntry, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return rotationJournalEntry{}, false, nil
	}
	if err != nil {
		return rotationJournalEntry{}, false, err
	}
	var e rotationJournalEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return rotationJournalEntry{}, false, fmt.Errorf("store: decode rotation journal %s: %w", filepath.Base(path), err)
	}
	access, err := s.cipher.Open(e.Access)
	if err != nil {
		return rotationJournalEntry{}, false, fmt.Errorf("store: open journaled access: %w", err)
	}
	refresh, err := s.cipher.Open(e.Refresh)
	if err != nil {
		return rotationJournalEntry{}, false, fmt.Errorf("store: open journaled refresh: %w", err)
	}
	return rotationJournalEntry{Access: access, Refresh: refresh, At: e.At, Seq: e.Seq}, true, nil
}

// removeRotationJournal deletes an account's journal file(s) — both the committed
// <id>.json and any leftover <id>.json.tmp — and fsyncs the dir so the deletion is
// durable (a resurrected journal would re-apply an already-applied token). A missing
// journal (or rotations dir) is not an error.
func (s *Store) removeRotationJournal(id string) error {
	path, err := s.rotationJournalPath(id)
	if err != nil {
		return err
	}
	removed := false
	for _, p := range []string{path, path + ".tmp"} {
		if err := os.Remove(p); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		removed = true
	}
	if removed {
		return syncDirStore(s.rotationsDir())
	}
	return nil
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
// unresolved rotations without triggering an Open-time replay. It uses os.ReadDir so
// a directory-read I/O error is SURFACED (fail-closed) rather than silently treated
// as "no pending journals", and it counts a mid-write <id>.json.tmp as pending too.
func PendingRotationIDsAt(dataDir string) ([]string, error) {
	if dataDir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(filepath.Join(dataDir, rotationJournalDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil // no journals ever written
		}
		return nil, err
	}
	seen := make(map[string]bool)
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if id, ok := journalIDFromName(e.Name()); ok && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// journalIDFromName returns the account id for a rotation-journal filename — the
// committed "<id>.json" or the mid-write "<id>.json.tmp" — and whether name is one.
func journalIDFromName(name string) (string, bool) {
	if strings.HasSuffix(name, ".json.tmp") {
		return strings.TrimSuffix(name, ".json.tmp"), true
	}
	if strings.HasSuffix(name, ".json") {
		return strings.TrimSuffix(name, ".json"), true
	}
	return "", false
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
