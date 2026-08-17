// backup.go implements `poolgate backup` and `poolgate restore` (DESIGN.md §20
// Ops/DR): a portable, passphrase-wrapped bundle carrying the field-encryption
// master key + a consistent DB snapshot, so an operator can move or recover an
// install without separately transporting the master key.
package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go2-im/poolgate/internal/backup"
	"github.com/go2-im/poolgate/internal/lock"
	"github.com/go2-im/poolgate/internal/store"
)

// cmdBackup snapshots the DB, wraps it with the master key under a passphrase,
// and writes a bundle. Flags: --out <file> (default poolgate-backup-<ts>.pgbak),
// --passphrase-file <path> (else POOLGATE_BACKUP_PASSPHRASE).
func cmdBackup(args []string, stdout io.Writer) error {
	out, passFile, err := parseBackupArgs(args)
	if err != nil {
		return err
	}
	pass, err := readPassphrase(passFile)
	if err != nil {
		return err
	}
	if out == "" {
		out = fmt.Sprintf("poolgate-backup-%s.pgbak", time.Now().UTC().Format("20060102-150405"))
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	key, err := loadMasterKeyExisting(cfg)
	if err != nil {
		return fmt.Errorf("load master key: %w", err)
	}
	db, schemaVersion, err := store.Snapshot(cfg)
	if err != nil {
		return err
	}

	// O_EXCL: never silently clobber an existing bundle.
	f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create bundle %q: %w", out, err)
	}
	writeErr := backup.Write(f, pass, key, db, backup.Meta{
		SchemaVersion: schemaVersion,
		CreatedAtUnix: time.Now().UTC().Unix(),
	})
	// Durability: a DR artifact must survive a crash right after it is written.
	// fsync the bundle before reporting success, then fsync the containing dir so
	// the new directory entry is durable too.
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil {
		_ = os.Remove(out) // don't leave a partial/corrupt bundle behind
		return fmt.Errorf("write bundle: %w", writeErr)
	}
	if syncErr != nil {
		_ = os.Remove(out)
		return fmt.Errorf("fsync bundle: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close bundle: %w", closeErr)
	}
	if dir := filepath.Dir(out); dir != "" {
		syncDir(dir)
	}

	fmt.Fprintf(stdout, "backup written: %s\n", out)
	fmt.Fprintf(stdout, "  schema version: %d\n", schemaVersion)
	fmt.Fprintf(stdout, "  db snapshot:    %d bytes (encrypted, passphrase-wrapped)\n", len(db))
	fmt.Fprintf(stdout, "\nStore the passphrase separately — the bundle is useless without it,\nand it cannot be recovered.\n")
	return nil
}

// cmdRestore reads a bundle and writes the master key + DB into the data dir.
// It refuses to overwrite an existing install unless --force. Flags: the bundle
// path (positional), --passphrase-file <path>, --force.
func cmdRestore(args []string, stdout io.Writer) error {
	bundlePath, passFile, force, err := parseRestoreArgs(args)
	if err != nil {
		return err
	}
	pass, err := readPassphrase(passFile)
	if err != nil {
		return err
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	f, err := os.Open(bundlePath)
	if err != nil {
		return fmt.Errorf("open bundle %q: %w", bundlePath, err)
	}
	defer f.Close()
	key, db, meta, err := backup.Read(f, pass)
	if err != nil {
		return err
	}

	// Verify the decrypted bundle BEFORE committing it over a live install:
	// integrity_check, schema-version compatibility, and a sample decrypt proving
	// the embedded key actually matches the database.
	if err := store.VerifyRestoreBundle(db, key); err != nil {
		return err
	}

	// Under master_key_source=env the key is NOT written to disk; the running
	// environment must already carry the matching POOLGATE_MASTER_KEY. If the
	// current env key differs from the bundle's key, the restored DB would be
	// undecryptable on next start — refuse now instead of "succeeding" and failing
	// at the next serve.
	if cfg.MasterKeySource == "env" {
		envKey, kerr := loadMasterKeyExisting(cfg)
		if kerr != nil {
			return fmt.Errorf("master_key_source=env but the current key is unavailable: %w", kerr)
		}
		if !bytes.Equal(envKey, key) {
			return errors.New("POOLGATE_MASTER_KEY does not match this backup's key; set the env to the backup's master key before restoring (master_key_source=env does not write the key to disk)")
		}
	}

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	// Refuse to restore into a data dir that a live `poolgate serve` is using:
	// restore renames the DB and deletes the -wal/-shm sidecars out from under the
	// running server, silently losing its writes / risking corruption. The
	// single-instance lock (held by serve) makes that detectable.
	lk, err := lock.Acquire(filepath.Join(cfg.DataDir, lockFile))
	if err != nil {
		if errors.Is(err, lock.ErrLocked) {
			return fmt.Errorf("a poolgate serve is running for %s — stop it before restoring", cfg.DataDir)
		}
		return fmt.Errorf("acquire lock: %w", err)
	}
	defer lk.Release()

	dbPath := filepath.Join(cfg.DataDir, store.DBFileName)
	keyPath := filepath.Join(cfg.DataDir, masterKeyFile)

	// Refuse to clobber an existing install unless --force.
	if !force {
		for _, p := range []string{dbPath, keyPath} {
			if _, statErr := os.Stat(p); statErr == nil {
				return fmt.Errorf("refusing to overwrite existing %s (pass --force to replace)", p)
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return fmt.Errorf("stat %s: %w", p, statErr)
			}
		}
	}

	// Under master_key_source=env the operator deliberately keeps the key OUT of
	// the filesystem, so restoring only the DB and NOT writing a plaintext keyfile
	// respects that choice (the matching key must already be in POOLGATE_MASTER_KEY).
	writeKey := cfg.MasterKeySource != "env"

	// Stage both artifacts to temp files (write + fsync) BEFORE committing either,
	// then rename into place — never truncate the live DB in-place, and never
	// leave a partially-written database on a mid-write failure.
	dbTmp := dbPath + ".tmp"
	keyTmp := keyPath + ".tmp"
	if err := stageTemp(dbTmp, db, 0o600); err != nil {
		return fmt.Errorf("stage database: %w", err)
	}
	if writeKey {
		// base64, matching crypto.LoadOrCreateKeyfile's format.
		enc := base64.StdEncoding.EncodeToString(key) + "\n"
		if err := stageTemp(keyTmp, []byte(enc), 0o600); err != nil {
			_ = os.Remove(dbTmp)
			return fmt.Errorf("stage master key: %w", err)
		}
	}
	// Commit the DB + key as a pair with rollback. A restore-in-progress marker is
	// written (and fsync'd, with the dir) FIRST so it is durable before any
	// destructive rename; `poolgate serve` refuses to start while it exists, so a
	// crash mid-commit is caught before a mismatched DB/key generation is used.
	// Marker durability is REQUIRED, not best-effort: if the marker (or its
	// directory entry) cannot be fsync'd we abort BEFORE touching the live
	// generation, because a lost marker would let `serve` start on a half-committed
	// restore.
	marker := filepath.Join(cfg.DataDir, restoreMarkerFile)
	cleanupTemps := func() {
		_ = os.Remove(dbTmp)
		if writeKey {
			_ = os.Remove(keyTmp)
		}
	}
	if err := os.WriteFile(marker, []byte("restore in progress\n"), 0o600); err != nil {
		cleanupTemps()
		return fmt.Errorf("write restore marker: %w", err)
	}
	mf, ferr := os.Open(marker)
	if ferr != nil {
		_ = os.Remove(marker)
		cleanupTemps()
		return fmt.Errorf("open restore marker for fsync: %w", ferr)
	}
	syncErr := mf.Sync()
	closeErr := mf.Close()
	if syncErr != nil {
		_ = os.Remove(marker)
		cleanupTemps()
		return fmt.Errorf("fsync restore marker: %w", syncErr)
	}
	if closeErr != nil {
		_ = os.Remove(marker)
		cleanupTemps()
		return fmt.Errorf("close restore marker: %w", closeErr)
	}
	if err := syncDirErr(cfg.DataDir); err != nil {
		_ = os.Remove(marker)
		cleanupTemps()
		return fmt.Errorf("fsync data dir for restore marker: %w", err)
	}

	// Move the current generation aside (DB + key + its WAL/SHM sidecars) so we can
	// roll back on failure AND so a stale sidecar is never applied to the new DB
	// (the restored image has none). Saved copies are removed on success.
	prev := map[string]string{}
	installedDB, installedKey := false, false
	saveAside := func(p string) error {
		if _, err := os.Stat(p); err == nil {
			bak := p + ".prev"
			if err := os.Rename(p, bak); err != nil {
				return err
			}
			prev[p] = bak
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	// rollback undoes a partial commit. It removes ONLY files we actually INSTALLED
	// (renamed from tmp): a path we never installed still holds the ORIGINAL file
	// (e.g. a saveAside failed before it moved the key) and must not be deleted — it
	// isn't in prev, so it could not be restored (this is what previously destroyed
	// the live master key). It returns a combined error if any restore-back step
	// fails and, in that case, KEEPS the restore marker so `serve` refuses to start
	// on a silently-mixed generation and the operator recovers by hand.
	rollback := func() error {
		var errs []error
		if installedDB {
			if e := os.Remove(dbPath); e != nil && !errors.Is(e, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("remove installed db %s: %w", dbPath, e))
			}
		}
		if installedKey {
			if e := os.Remove(keyPath); e != nil && !errors.Is(e, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("remove installed key %s: %w", keyPath, e))
			}
		}
		for orig, bak := range prev {
			if e := os.Rename(bak, orig); e != nil {
				errs = append(errs, fmt.Errorf("restore %s from %s: %w", orig, bak, e))
			}
		}
		_ = os.Remove(dbTmp)
		if writeKey {
			_ = os.Remove(keyTmp)
		}
		if len(errs) == 0 {
			// Old generation fully restored — clear the marker (durably).
			_ = os.Remove(marker)
			syncDir(cfg.DataDir)
			return nil
		}
		// Could not fully restore: KEEP the marker so serve refuses to start.
		syncDir(cfg.DataDir)
		return errors.Join(errs...)
	}
	// fail runs rollback for cause and, if rollback could not fully restore the old
	// generation, reports BOTH errors plus that the marker was kept for manual recovery.
	fail := func(cause error) error {
		if rbErr := rollback(); rbErr != nil {
			return fmt.Errorf("%w; rollback FAILED, restore marker kept at %s — manual recovery required: %v",
				cause, marker, rbErr)
		}
		return cause
	}
	aside := []string{dbPath, dbPath + "-wal", dbPath + "-shm"}
	if writeKey {
		aside = append(aside, keyPath)
	}
	for _, p := range aside {
		if err := saveAside(p); err != nil {
			return fail(fmt.Errorf("stage old %s aside: %w", p, err))
		}
	}

	// Install the new generation.
	if err := os.Rename(dbTmp, dbPath); err != nil {
		return fail(fmt.Errorf("commit database: %w", err))
	}
	installedDB = true
	if writeKey {
		if err := os.Rename(keyTmp, keyPath); err != nil {
			return fail(fmt.Errorf("commit master key: %w", err))
		}
		installedKey = true
	}

	// Success: the new generation is fully installed. Clear the marker and make its
	// REMOVAL durable (fsync the dir) before dropping the saved-aside old generation,
	// so a crash after this point can never resurrect the marker and block a
	// completed restore. If clearing the marker fails, the restore itself still
	// SUCCEEDED — do NOT roll back the good install; report it so the operator
	// removes the marker by hand. The .prev cleanup is best-effort (harmless if left).
	if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		syncDir(cfg.DataDir)
		return fmt.Errorf("restore committed into %s but clearing marker %s failed: %w — remove it manually, then run `poolgate serve`",
			cfg.DataDir, marker, err)
	}
	syncDir(cfg.DataDir)
	for _, bak := range prev {
		_ = os.Remove(bak)
	}

	fmt.Fprintf(stdout, "restore complete into %s\n", cfg.DataDir)
	fmt.Fprintf(stdout, "  schema version: %d\n", meta.SchemaVersion)
	if meta.CreatedAtUnix > 0 {
		fmt.Fprintf(stdout, "  backup taken:   %s\n", time.Unix(meta.CreatedAtUnix, 0).UTC().Format(time.RFC3339))
	}
	if cfg.MasterKeySource == "env" {
		fmt.Fprintf(stdout, "\nNote: master_key_source is \"env\" — the master key was NOT written to disk.\nEnsure POOLGATE_MASTER_KEY is set to the key this backup was made with,\notherwise the restored database cannot be decrypted.\n")
	}
	fmt.Fprintf(stdout, "\nNext: `poolgate serve`.\n")
	return nil
}

// stageTemp writes data to a temp file (0600), fsyncs it, and closes it, WITHOUT
// renaming into place — the caller commits with os.Rename after all temps are
// durable. On any error the temp file is removed.
func stageTemp(tmpPath string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// syncDir best-effort fsyncs a directory so a rename into it is durable across a
// crash. Errors are ignored (not all platforms/filesystems support it); callers
// that MUST know the dir entry is durable use syncDirErr instead.
func syncDir(dir string) {
	_ = syncDirErr(dir)
}

// syncDirErr fsyncs a directory and RETURNS any error, for the durability-critical
// callers (pre-rotation snapshot, restore marker) where a silently-unsynced
// directory entry could forfeit a recovery artifact. A dir that cannot be opened
// or synced surfaces the error so the caller can abort rather than proceed on a
// false durability assumption.
func syncDirErr(dir string) error {
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

// parseBackupArgs parses `backup` flags (order-independent).
func parseBackupArgs(args []string) (out, passFile string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--out" || a == "-out":
			if i+1 >= len(args) {
				return "", "", errors.New("--out requires a path")
			}
			out = args[i+1]
			i++
		case strings.HasPrefix(a, "--out="):
			out = strings.TrimPrefix(a, "--out=")
		case a == "--passphrase-file":
			if i+1 >= len(args) {
				return "", "", errors.New("--passphrase-file requires a path")
			}
			passFile = args[i+1]
			i++
		case strings.HasPrefix(a, "--passphrase-file="):
			passFile = strings.TrimPrefix(a, "--passphrase-file=")
		default:
			return "", "", fmt.Errorf("unexpected argument %q", a)
		}
	}
	return out, passFile, nil
}

// parseRestoreArgs parses the positional bundle path plus flags.
func parseRestoreArgs(args []string) (bundle, passFile string, force bool, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--force":
			force = true
		case a == "--passphrase-file":
			if i+1 >= len(args) {
				return "", "", false, errors.New("--passphrase-file requires a path")
			}
			passFile = args[i+1]
			i++
		case strings.HasPrefix(a, "--passphrase-file="):
			passFile = strings.TrimPrefix(a, "--passphrase-file=")
		default:
			if bundle == "" && !strings.HasPrefix(a, "-") {
				bundle = a
			} else {
				return "", "", false, fmt.Errorf("unexpected argument %q", a)
			}
		}
	}
	if bundle == "" {
		return "", "", false, errors.New("usage: poolgate restore <bundle> [--passphrase-file <path>] [--force]")
	}
	return bundle, passFile, force, nil
}

// readPassphrase reads the backup passphrase from --passphrase-file or
// POOLGATE_BACKUP_PASSPHRASE (or POOLGATE_BACKUP_PASSPHRASE_FILE via the *_FILE
// convention). All sources are trimmed of a trailing newline identically, and a
// non-empty passphrase is required. The value is never echoed.
func readPassphrase(passFile string) ([]byte, error) {
	var raw string
	if passFile != "" {
		b, err := os.ReadFile(passFile)
		if err != nil {
			return nil, fmt.Errorf("read passphrase file: %w", err)
		}
		raw = string(b)
	} else {
		v, err := envValue(envBackupPassphrase)
		if err != nil {
			return nil, err
		}
		raw = v
	}
	pass := []byte(strings.TrimRight(raw, "\r\n"))
	if len(pass) == 0 {
		return nil, errors.New("no passphrase (set POOLGATE_BACKUP_PASSPHRASE[_FILE] or pass --passphrase-file)")
	}
	return pass, nil
}
