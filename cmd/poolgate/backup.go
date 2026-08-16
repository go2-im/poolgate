// backup.go implements `poolgate backup` and `poolgate restore` (DESIGN.md §20
// Ops/DR): a portable, passphrase-wrapped bundle carrying the field-encryption
// master key + a consistent DB snapshot, so an operator can move or recover an
// install without separately transporting the master key.
package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go2-im/poolgate/internal/backup"
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
	key, err := loadMasterKey(cfg)
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
	closeErr := f.Close()
	if writeErr != nil {
		_ = os.Remove(out) // don't leave a partial/corrupt bundle behind
		return fmt.Errorf("write bundle: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close bundle: %w", closeErr)
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

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
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

	// Write the keyfile (base64, matching crypto.LoadOrCreateKeyfile's format).
	enc := base64.StdEncoding.EncodeToString(key)
	if err := os.WriteFile(keyPath, []byte(enc+"\n"), 0o600); err != nil {
		return fmt.Errorf("write master key: %w", err)
	}
	// Write the DB and remove any stale WAL sidecars so the restored file is the
	// single source of truth on next open.
	if err := os.WriteFile(dbPath, db, 0o600); err != nil {
		return fmt.Errorf("write database: %w", err)
	}
	for _, sidecar := range []string{dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Remove(sidecar); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale %s: %w", sidecar, err)
		}
	}

	fmt.Fprintf(stdout, "restore complete into %s\n", cfg.DataDir)
	fmt.Fprintf(stdout, "  schema version: %d\n", meta.SchemaVersion)
	if meta.CreatedAtUnix > 0 {
		fmt.Fprintf(stdout, "  backup taken:   %s\n", time.Unix(meta.CreatedAtUnix, 0).UTC().Format(time.RFC3339))
	}
	if cfg.MasterKeySource == "env" {
		fmt.Fprintf(stdout, "\nNote: master_key_source is \"env\"; the restored keyfile will not be used\nunless you switch back to the keyfile source, or set POOLGATE_MASTER_KEY to\nthe original key.\n")
	}
	fmt.Fprintf(stdout, "\nNext: `poolgate serve`.\n")
	return nil
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

// readPassphrase reads the backup passphrase from --passphrase-file (trailing
// newline trimmed) or POOLGATE_BACKUP_PASSPHRASE. It never echoes the value and
// requires a non-empty passphrase.
func readPassphrase(passFile string) ([]byte, error) {
	var pass []byte
	if passFile != "" {
		b, err := os.ReadFile(passFile)
		if err != nil {
			return nil, fmt.Errorf("read passphrase file: %w", err)
		}
		pass = []byte(strings.TrimRight(string(b), "\r\n"))
	} else {
		pass = []byte(os.Getenv(envBackupPassphrase))
	}
	if len(pass) == 0 {
		return nil, errors.New("no passphrase (set POOLGATE_BACKUP_PASSPHRASE or pass --passphrase-file)")
	}
	return pass, nil
}
