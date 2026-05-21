package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPassphraseEnvRequiresExplicitOptIn(t *testing.T) {
	t.Cleanup(func() { _ = ConfigurePassphraseSource(PassphraseOptions{}) })
	t.Setenv("MNEMOX_PASSPHRASE", "test-passphrase")
	t.Setenv("MNEMOX_ALLOW_INSECURE_PASSPHRASE_ENV", "")
	if _, err := ReadPassphrase(false); err == nil || !strings.Contains(err.Error(), "MNEMOX_ALLOW_INSECURE_PASSPHRASE_ENV=1") {
		t.Fatalf("expected gated env error, got %v", err)
	}

	t.Setenv("MNEMOX_ALLOW_INSECURE_PASSPHRASE_ENV", "1")
	passphrase, err := ReadPassphrase(false)
	if err != nil {
		t.Fatal(err)
	}
	if passphrase != "test-passphrase" {
		t.Fatalf("unexpected passphrase %q", passphrase)
	}
}

func TestPassphraseFileAndStdinSources(t *testing.T) {
	t.Cleanup(func() { _ = ConfigurePassphraseSource(PassphraseOptions{}) })
	t.Setenv("MNEMOX_PASSPHRASE", "ignored")

	passphrasePath := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(passphrasePath, []byte("file-passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ConfigurePassphraseSource(PassphraseOptions{File: passphrasePath}); err != nil {
		t.Fatal(err)
	}
	passphrase, err := ReadPassphrase(false)
	if err != nil {
		t.Fatal(err)
	}
	if passphrase != "file-passphrase" {
		t.Fatalf("unexpected file passphrase %q", passphrase)
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = writer.WriteString("stdin-passphrase\n")
	_ = writer.Close()
	oldStdin := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() { os.Stdin = oldStdin })
	if err := ConfigurePassphraseSource(PassphraseOptions{FromStdin: true}); err != nil {
		t.Fatal(err)
	}
	passphrase, err = ReadPassphrase(false)
	if err != nil {
		t.Fatal(err)
	}
	if passphrase != "stdin-passphrase" {
		t.Fatalf("unexpected stdin passphrase %q", passphrase)
	}
}
