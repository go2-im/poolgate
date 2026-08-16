package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseBackupArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantOut  string
		wantPass string
		wantErr  bool
	}{
		{name: "empty", args: nil},
		{name: "out space", args: []string{"--out", "b.pgbak"}, wantOut: "b.pgbak"},
		{name: "out equals", args: []string{"--out=b.pgbak"}, wantOut: "b.pgbak"},
		{name: "passfile space", args: []string{"--passphrase-file", "p"}, wantPass: "p"},
		{name: "passfile equals", args: []string{"--passphrase-file=p"}, wantPass: "p"},
		{name: "both", args: []string{"--out=b", "--passphrase-file=p"}, wantOut: "b", wantPass: "p"},
		{name: "out missing value", args: []string{"--out"}, wantErr: true},
		{name: "passfile missing value", args: []string{"--passphrase-file"}, wantErr: true},
		{name: "unexpected", args: []string{"junk"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, pass, err := parseBackupArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if out != tc.wantOut || pass != tc.wantPass {
				t.Errorf("got out=%q pass=%q, want out=%q pass=%q", out, pass, tc.wantOut, tc.wantPass)
			}
		})
	}
}

func TestParseRestoreArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantBundle string
		wantPass   string
		wantForce  bool
		wantErr    bool
	}{
		{name: "bundle only", args: []string{"b.pgbak"}, wantBundle: "b.pgbak"},
		{name: "bundle + force", args: []string{"b.pgbak", "--force"}, wantBundle: "b.pgbak", wantForce: true},
		{name: "force + bundle", args: []string{"--force", "b.pgbak"}, wantBundle: "b.pgbak", wantForce: true},
		{name: "passfile space", args: []string{"b", "--passphrase-file", "p"}, wantBundle: "b", wantPass: "p"},
		{name: "passfile equals", args: []string{"b", "--passphrase-file=p"}, wantBundle: "b", wantPass: "p"},
		{name: "missing bundle", args: []string{"--force"}, wantErr: true},
		{name: "passfile missing value", args: []string{"b", "--passphrase-file"}, wantErr: true},
		{name: "second positional", args: []string{"b", "c"}, wantErr: true},
		{name: "unknown flag", args: []string{"b", "--nope"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundle, pass, force, err := parseRestoreArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if bundle != tc.wantBundle || pass != tc.wantPass || force != tc.wantForce {
				t.Errorf("got bundle=%q pass=%q force=%v, want bundle=%q pass=%q force=%v",
					bundle, pass, force, tc.wantBundle, tc.wantPass, tc.wantForce)
			}
		})
	}
}

func TestReadPassphrase(t *testing.T) {
	// From a file, trailing newline trimmed.
	dir := t.TempDir()
	pf := filepath.Join(dir, "pass.txt")
	if err := os.WriteFile(pf, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readPassphrase(pf)
	if err != nil || string(got) != "s3cret" {
		t.Fatalf("file passphrase = %q err=%v, want s3cret", got, err)
	}

	// From env, same trimming so the two intake methods agree.
	t.Setenv(envBackupPassphrase, "s3cret\n")
	got, err = readPassphrase("")
	if err != nil || string(got) != "s3cret" {
		t.Fatalf("env passphrase = %q err=%v, want s3cret", got, err)
	}

	// Empty env → error.
	t.Setenv(envBackupPassphrase, "")
	if _, err := readPassphrase(""); err == nil {
		t.Fatal("expected error for empty passphrase")
	}

	// Missing file → error.
	if _, err := readPassphrase(filepath.Join(dir, "nope")); err == nil {
		t.Fatal("expected error for missing passphrase file")
	}
}

func TestStageTempError(t *testing.T) {
	// A temp path inside a non-existent directory cannot be created.
	badPath := filepath.Join(t.TempDir(), "missing-subdir", "x.tmp")
	if err := stageTemp(badPath, []byte("data"), 0o600); err == nil {
		t.Fatal("expected stageTemp to fail for an uncreatable path")
	}
}

func TestReadPassphrasePreservesInterior(t *testing.T) {
	// readPassphrase trims only trailing newlines, not interior content.
	t.Setenv(envBackupPassphrase, "a b\tc")
	got, err := readPassphrase("")
	if err != nil || string(got) != "a b\tc" {
		t.Fatalf("interior-preserving passphrase = %q err=%v", got, err)
	}
	if strings.TrimSpace(string(got)) != "a b\tc" {
		t.Errorf("unexpected surrounding whitespace")
	}
}
