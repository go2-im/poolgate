// rekey.go implements `poolgate rotate-key`: master-key rotation (DESIGN.md
// §22.6). It generates a fresh master key, re-encrypts every secret column from
// the old key to the new one atomically (store.RotateSecrets), and only then
// swaps in the new key. A pre-rotation snapshot is written first as a safety net.
//
// It must not run while `serve` is live, so it takes the same single-instance
// lock. The DB re-encryption is one transaction: on failure the DB stays wholly
// on the old key. The one unavoidable window is between the DB commit and the
// key swap:
//   - On a graceful keyfile-write error (or env-source mode) the new key is
//     printed so it can be recorded by hand.
//   - On a HARD crash there (SIGKILL / power loss) the new key is lost from
//     memory; recover by restoring the pre-rotation snapshot — a raw SQLite
//     image, NOT a `poolgate restore` bundle: stop poolgate, copy
//     poolgate-pre-rotate-<ts>.db over <data>/poolgate.db, delete the
//     poolgate.db-wal / poolgate.db-shm sidecars, and keep the OLD key in place.
//     (A best-effort fallback: master.key.tmp, if present, holds the fsync'd new
//     key from the interrupted swap.)
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/go2-im/poolgate/internal/crypto"
	"github.com/go2-im/poolgate/internal/lock"
	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/store"
)

func cmdRotateKey(_ []string, stdout io.Writer) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	// Single-instance guard: rotation must not race a running serve (which holds
	// the old cipher in memory and would write old-key ciphertext mid-rotation).
	lk, err := lock.Acquire(filepath.Join(cfg.DataDir, lockFile))
	if err != nil {
		if err == lock.ErrLocked {
			return fmt.Errorf("another poolgate process holds the lock (is `serve` running?); stop it before rotating the key")
		}
		return fmt.Errorf("acquire single-instance lock: %w", err)
	}
	defer lk.Release()

	// Open the store with the CURRENT (old) key.
	oldKey, err := loadMasterKey(cfg)
	if err != nil {
		return fmt.Errorf("load current master key: %w", err)
	}
	oldCipher, err := crypto.New(oldKey)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg, oldCipher)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()

	// Pre-rotation safety snapshot (consistent VACUUM INTO copy of the live DB).
	snapPath := filepath.Join(cfg.DataDir, "poolgate-pre-rotate-"+time.Now().UTC().Format("20060102-150405")+".db")
	snap, _, err := store.Snapshot(cfg)
	if err != nil {
		return fmt.Errorf("pre-rotation snapshot failed (aborting): %w", err)
	}
	// O_EXCL: never silently clobber an earlier same-second snapshot.
	sf, err := os.OpenFile(snapPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create pre-rotation snapshot: %w", err)
	}
	if _, err := sf.Write(snap); err != nil {
		_ = sf.Close()
		_ = os.Remove(snapPath)
		return fmt.Errorf("write pre-rotation snapshot: %w", err)
	}
	if err := sf.Close(); err != nil {
		return fmt.Errorf("close pre-rotation snapshot: %w", err)
	}
	fmt.Fprintf(stdout, "pre-rotation snapshot written: %s\n", snapPath)

	// Mint the new key and re-encrypt every secret column in one transaction.
	newKey, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	newCipher, err := crypto.New(newKey)
	if err != nil {
		return err
	}
	nAcc, nCh, err := st.RotateSecrets(ctx, newCipher)
	if err != nil {
		return fmt.Errorf("re-encrypt failed (DB unchanged, still on the old key): %w", err)
	}

	// DB is now committed on the NEW key. Persist the new key.
	if cfg.MasterKeySource == "env" {
		fmt.Fprintf(stdout, "\nRe-encrypted %d account(s) and %d notify channel(s).\n"+
			"master_key_source is \"env\": update POOLGATE_MASTER_KEY to the NEW key below — the old key no longer decrypts the DB:\n\n  %s\n\n",
			nAcc, nCh, crypto.EncodeKey(newKey))
		return nil
	}

	keyPath := filepath.Join(cfg.DataDir, masterKeyFile)
	if err := writeKeyfileAtomic(keyPath, newKey); err != nil {
		// The DB is on the new key but the keyfile swap failed. Surface the key so
		// the operator can write it manually. (master.key.tmp may also hold it.)
		fmt.Fprintf(stdout, "\nWARNING: DB re-encrypted but writing %s failed: %v\n"+
			"Write this NEW key (base64) to that file to finish, e.g.:\n  printf '%%s\\n' <KEY> > %s\n"+
			"Or restore the pre-rotation snapshot MANUALLY (it is a raw DB, not a `poolgate restore` bundle):\n"+
			"  stop poolgate; cp %s %s; rm -f %s-wal %s-shm; keep the OLD key.\n\nNEW key: %s\n\n",
			keyPath, err, keyPath, snapPath, dbPathOf(cfg), dbPathOf(cfg), dbPathOf(cfg), crypto.EncodeKey(newKey))
		return fmt.Errorf("rotate: persist new keyfile: %w", err)
	}
	fmt.Fprintf(stdout, "master key rotated: re-encrypted %d account(s), %d notify channel(s); %s updated.\n",
		nAcc, nCh, keyPath)
	pruneOldSnapshots(cfg.DataDir, stdout)
	return nil
}

// dbPathOf returns the main SQLite DB path under the data dir.
func dbPathOf(cfg model.Config) string { return filepath.Join(cfg.DataDir, "poolgate.db") }

// pruneOldSnapshots keeps only the newest keepSnapshots pre-rotation snapshots so
// repeated rotations don't accumulate standing plaintext-metadata DB images.
func pruneOldSnapshots(dataDir string, stdout io.Writer) {
	const keepSnapshots = 3
	matches, err := filepath.Glob(filepath.Join(dataDir, "poolgate-pre-rotate-*.db"))
	if err != nil || len(matches) <= keepSnapshots {
		return
	}
	sort.Strings(matches) // timestamped names sort chronologically
	for _, old := range matches[:len(matches)-keepSnapshots] {
		if err := os.Remove(old); err == nil {
			fmt.Fprintf(stdout, "pruned old pre-rotation snapshot: %s\n", old)
		}
	}
}

// writeKeyfileAtomic writes the base64-encoded key to path via a fsync'd temp
// file + rename, matching the format crypto.LoadOrCreateKeyfile reads.
func writeKeyfileAtomic(path string, key []byte) error {
	tmp := path + ".tmp"
	if err := stageTemp(tmp, []byte(crypto.EncodeKey(key)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}
