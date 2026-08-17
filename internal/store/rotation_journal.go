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
	"github.com/go2-im/poolgate/internal/model"
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
// (field-encrypted) exactly like the accounts token columns.
//
// BaseVersion/TargetVersion tie the entry to the account's credential_version
// (DESIGN.md §19.3a): the entry captures a credential mutation FROM BaseVersion TO
// TargetVersion. Recovery applies it ONLY while the DB is still at BaseVersion, so a
// crash-interrupted rotation is never re-applied over a newer generation a concurrent
// login already wrote. Operation records what wrote it ("refresh"/"login"/"import")
// for diagnostics. A legacy entry written by a pre-v14 binary has no version fields
// (TargetVersion == 0); such entries are applied unconditionally, preserving the old
// flush-on-startup behavior.
//
// Seq is a per-account monotonic counter retained as a TIE-BREAKER when two entries
// carry the SAME TargetVersion (e.g. a committed <id>.json and a mid-write
// <id>.json.tmp of the same generation surviving a crash): the higher Seq is newer.
// Ordering is by TargetVersion first, then Seq.
type rotationJournalEntry struct {
	Access        string `json:"access"`
	Refresh       string `json:"refresh"`
	At            string `json:"at"`
	Seq           int64  `json:"seq"`
	BaseVersion   int64  `json:"base_version"`
	TargetVersion int64  `json:"target_version"`
	Operation     string `json:"operation,omitempty"`
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
// account under the cross-process credential lock, using a credential_version
// compare-and-swap keyed on baseVersion — the version the caller read before the
// upstream rotation. It returns the AUTHORITATIVE account after the attempt and
// whether the rotation was applied:
//
//   - applied == true: the DB version still equalled baseVersion, so the tokens were
//     written and the version bumped to baseVersion+1; the returned account is the new
//     generation.
//   - applied == false, err == nil: SUPERSEDED — a concurrent login/refresh already
//     advanced the version, so this (now-stale) rotation was DROPPED rather than
//     clobbering the fresher credentials; the returned account is the current DB
//     winner. Callers MUST use it instead of the tokens they just fetched, which were
//     never persisted (reusing them risks resubmitting an already-consumed
//     refresh_token and revoking the token family). This fixes the prior behavior
//     where a superseded commit silently returned the caller's non-persisted tokens.
//   - err == ErrNotFound: the account no longer exists (any journal is dropped).
//
// On the applied path it writes the fsync'd journal BEFORE the DB (bounded retry) and
// removes it only on success; a failed DB write RETAINS the journal for recovery.
func (s *Store) CommitRotatedTokens(ctx context.Context, id string, baseVersion int64, accessToken, refreshToken string) (model.Account, bool, error) {
	var (
		result  model.Account
		applied bool
	)
	err := s.withCredentialLock(func() error {
		cur, err := s.GetAccount(ctx, id)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				_ = s.removeRotationJournal(id)
				return ErrNotFound
			}
			return fmt.Errorf("store: re-read before rotation commit: %w", err)
		}
		if cur.CredentialVersion != baseVersion {
			// Superseded: a concurrent mutation advanced the generation. Drop any
			// stale journal we may hold and return the current winner unchanged.
			_ = s.removeRotationJournal(id)
			result = cur
			return nil
		}
		target := baseVersion + 1
		if s.dataDir != "" {
			if err := s.writeRotationJournal(id, accessToken, refreshToken, baseVersion, target, "refresh"); err != nil {
				return fmt.Errorf("store: write rotation journal: %w", err)
			}
		}
		ok, err := s.updateTokensCASWithRetry(ctx, id, baseVersion, target, accessToken, refreshToken)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				_ = s.removeRotationJournal(id)
				return ErrNotFound
			}
			// Journal retained on purpose — the rotated token is durable and will be
			// flushed later; do NOT remove it.
			return fmt.Errorf("store: persist rotated tokens (journaled for retry): %w", err)
		}
		if !ok {
			// Version advanced between our re-read and the CAS (should not happen under
			// the lock, but treat defensively as superseded): drop the journal and
			// return the current winner.
			_ = s.removeRotationJournal(id)
			winner, gerr := s.GetAccount(ctx, id)
			if gerr != nil {
				return fmt.Errorf("store: re-read after superseded commit: %w", gerr)
			}
			result = winner
			return nil
		}
		if s.dataDir != "" {
			if err := s.removeRotationJournal(id); err != nil {
				return fmt.Errorf("store: clear rotation journal: %w", err)
			}
		}
		updated, gerr := s.GetAccount(ctx, id)
		if gerr != nil {
			return fmt.Errorf("store: re-read after rotation commit: %w", gerr)
		}
		result, applied = updated, true
		return nil
	})
	if err != nil {
		return model.Account{}, false, err
	}
	return result, applied, nil
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
// the credential lock. It applies the journaled rotation only when it is coherent
// with the account's current credential_version (DESIGN.md §19.3a):
//
//   - no valid candidate, none corrupt → nothing pending.
//   - no valid candidate but a corrupt one present → FAIL CLOSED (unrecoverable
//     pending rotation; never reuse the DB token blindly).
//   - account gone → drop the moot journal.
//   - legacy entry (no version fields, TargetVersion == 0) → apply unconditionally
//     (pre-v14 behavior); but if a corrupt sibling is also present, FAIL CLOSED (a
//     version-less entry cannot be ordered against an unreadable one).
//   - DB version == entry.BaseVersion → applicable: apply with a version CAS to
//     TargetVersion, then drop BOTH journal files. A corrupt sibling here is provably
//     garbage (a coherent newer generation would require the DB to be past base), so it
//     is cleaned up too.
//   - DB version >= entry.TargetVersion → already applied/superseded → drop it; but if a
//     corrupt sibling is present it could be a LOST newer generation, so FAIL CLOSED.
//   - otherwise (DB version between base and target, or below base) → AMBIGUOUS: fail
//     closed (retain, surface an error) — the account stays blocked until a login
//     rewrites its credentials, never silently reusing a possibly-consumed token.
func (s *Store) flushPendingRotationLocked(ctx context.Context, id string) error {
	entry, haveValid, sawCorrupt, err := s.scanRotationJournals(id)
	if err != nil {
		return err
	}
	if !haveValid {
		if sawCorrupt {
			return fmt.Errorf("store: pending rotation for %s is unreadable (corrupt journal, no valid candidate) — retained, fail-closed", id)
		}
		return nil
	}
	cur, err := s.GetAccount(ctx, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return s.removeRotationJournal(id) // account gone; journal is moot
		}
		return fmt.Errorf("store: flush pending rotation re-read: %w", err)
	}

	// Legacy pre-v14 journal (no version metadata): apply unconditionally, bumping the
	// version. Not a new risk — identical to the recovery behavior this build replaces.
	// A corrupt sibling cannot be ordered against a version-less entry → fail closed.
	if entry.TargetVersion == 0 {
		if sawCorrupt {
			return fmt.Errorf("store: legacy pending rotation for %s sits beside a corrupt candidate — retained, fail-closed", id)
		}
		applied, aerr := s.updateTokensCASWithRetry(ctx, id, cur.CredentialVersion, cur.CredentialVersion+1, entry.Access, entry.Refresh)
		if aerr != nil {
			if errors.Is(aerr, ErrNotFound) {
				return s.removeRotationJournal(id)
			}
			return fmt.Errorf("store: flush legacy rotation: %w", aerr)
		}
		if !applied {
			// The version changed under us (a concurrent mutation) — retry later.
			return fmt.Errorf("store: legacy rotation flush lost the version race for %s", id)
		}
		return s.removeRotationJournal(id)
	}

	dbVer := cur.CredentialVersion
	switch {
	case dbVer == entry.BaseVersion:
		// Applicable. A corrupt sibling here is provably garbage (a coherent newer gen
		// would need the DB past base, which it is not), so apply and clean up both.
		applied, aerr := s.updateTokensCASWithRetry(ctx, id, entry.BaseVersion, entry.TargetVersion, entry.Access, entry.Refresh)
		if aerr != nil {
			if errors.Is(aerr, ErrNotFound) {
				return s.removeRotationJournal(id)
			}
			return fmt.Errorf("store: flush pending rotation: %w", aerr) // journal retained
		}
		if !applied {
			return fmt.Errorf("store: rotation flush lost the version race for %s", id) // retained; retry later
		}
		return s.removeRotationJournal(id)
	case dbVer >= entry.TargetVersion:
		// The valid candidate is already applied/superseded. Normally drop it — but a
		// corrupt sibling could be a LOST newer generation, so fail closed instead.
		if sawCorrupt {
			return fmt.Errorf("store: already-applied rotation for %s sits beside a corrupt (possibly newer) candidate — retained, fail-closed", id)
		}
		return s.removeRotationJournal(id)
	default:
		// dbVer < BaseVersion, or BaseVersion < dbVer < TargetVersion: we cannot prove
		// the journaled generation is the right one to write. FAIL CLOSED.
		return fmt.Errorf("store: pending rotation for %s is ambiguous (db v%d, journal base v%d target v%d) — retained",
			id, dbVer, entry.BaseVersion, entry.TargetVersion)
	}
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
// publishes a partial/plaintext entry. The entry records the credential-version
// transition (base -> target) and operation, plus a per-account monotonic Seq (max of
// any existing .json/.tmp + 1) used only as a same-target tie-breaker. Callers that
// mutate credentials hold the credential lock, so the read-then-bump of Seq is
// race-free across processes.
func (s *Store) writeRotationJournal(id, accessToken, refreshToken string, base, target int64, op string) error {
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
		Seq: s.nextJournalSeq(path), BaseVersion: base, TargetVersion: target, Operation: op,
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
// returns the NEWEST by (TargetVersion, then Seq) — an older generation must never
// shadow a newer one. It is FAIL-CLOSED on corruption: if ANY existing candidate
// cannot be decoded/decrypted, the error is surfaced (and the caller leaves the
// journal in place, keeping the account blocked) EVEN IF another candidate decoded —
// a corrupt candidate could be the newest rotation, and silently applying an older
// valid one could resubmit a token the upstream already superseded, revoking the
// family.
// readRotationJournal is the STRICT reader: it returns the newest VALID candidate,
// but surfaces an error if ANY present candidate is corrupt (even when a valid one
// also exists). Recovery (flushPendingRotationLocked) uses the finer-grained
// scanRotationJournals instead, which can safely apply a coherent valid candidate
// while ignoring a provably-garbage corrupt sibling; this strict reader is kept as a
// conservative oracle for callers/tests that must not proceed past any corruption.
func (s *Store) readRotationJournal(id string) (rotationJournalEntry, bool, error) {
	best, haveValid, sawCorrupt, err := s.scanRotationJournals(id)
	if err != nil {
		return rotationJournalEntry{}, false, err
	}
	if sawCorrupt {
		return rotationJournalEntry{}, false, fmt.Errorf("store: corrupt rotation journal for %q", id)
	}
	return best, haveValid, nil
}

// scanRotationJournals reads both candidate files (<id>.json and <id>.json.tmp) and
// reports: the newest VALID entry by (TargetVersion, Seq); whether any valid entry was
// found; whether any PRESENT candidate failed to decode/decrypt (sawCorrupt); and a
// path-level error. It never fails closed by itself — the caller decides, using the DB
// credential_version, whether a corrupt sibling is safe to ignore (a coherent newer
// generation would require the DB to be past the valid candidate's base, so when the
// valid candidate is applicable the corrupt one is provably garbage).
func (s *Store) scanRotationJournals(id string) (best rotationJournalEntry, haveValid, sawCorrupt bool, err error) {
	if s.dataDir == "" {
		return rotationJournalEntry{}, false, false, nil
	}
	path, perr := s.rotationJournalPath(id)
	if perr != nil {
		return rotationJournalEntry{}, false, false, perr
	}
	for _, p := range []string{path, path + ".tmp"} {
		e, ok, rerr := s.readJournalFile(p)
		if rerr != nil {
			sawCorrupt = true
			continue
		}
		if ok && (!haveValid || journalNewer(e, best)) {
			best, haveValid = e, true
		}
	}
	return best, haveValid, sawCorrupt, nil
}

// journalNewer reports whether a is a newer generation than b: higher TargetVersion,
// or the same TargetVersion with a higher Seq (the same-generation tie-breaker).
func journalNewer(a, b rotationJournalEntry) bool {
	if a.TargetVersion != b.TargetVersion {
		return a.TargetVersion > b.TargetVersion
	}
	return a.Seq > b.Seq
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
	return rotationJournalEntry{
		Access: access, Refresh: refresh, At: e.At, Seq: e.Seq,
		BaseVersion: e.BaseVersion, TargetVersion: e.TargetVersion, Operation: e.Operation,
	}, true, nil
}

// removeRotationJournal deletes an account's journal file(s) — both the committed
// <id>.json and any leftover <id>.json.tmp — and fsyncs the dir so the deletion is
// durable (a resurrected journal would re-apply an already-applied token). A missing
// journal (or rotations dir) is not an error.
func (s *Store) removeRotationJournal(id string) error {
	if s.dataDir == "" {
		return nil
	}
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

// updateTokensCASWithRetry is updateTokensCAS with the same bounded backoff on
// transient SQLite contention. It returns whether the version CAS matched (applied);
// ErrNotFound and non-transient errors return immediately.
func (s *Store) updateTokensCASWithRetry(ctx context.Context, id string, base, target int64, access, refresh string) (bool, error) {
	const attempts = 4
	var (
		applied bool
		err     error
	)
	for i := 0; i < attempts; i++ {
		applied, err = s.updateTokensCAS(ctx, id, base, target, access, refresh)
		if err == nil || errors.Is(err, ErrNotFound) || !isTransientStoreErr(err) {
			return applied, err
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(time.Duration(10*(1<<i)) * time.Millisecond):
		}
	}
	return applied, err
}
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
