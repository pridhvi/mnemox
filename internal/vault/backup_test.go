package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupCreateRestoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, ".mnemox")
	v, err := CreateWithPassphrase(root, "ACME", "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	findingID, err := v.AddRecord("finding", map[string]any{
		"title":          "Weak TLS",
		"affected_scope": []string{"app.acme.local"},
	})
	if err != nil {
		t.Fatal(err)
	}
	blobID, err := v.StoreBlobBytes([]byte("evidence data"))
	if err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(dir, "vault.mnemoxbak")
	if err := v.Backup(backupPath); err != nil {
		t.Fatal(err)
	}
	_ = v.Close()

	restoreRoot := filepath.Join(dir, "restore")
	if err := RestoreBackup(backupPath, restoreRoot, "test-passphrase", false); err != nil {
		t.Fatal(err)
	}
	restored, err := OpenWithPassphrase(restoreRoot, "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	rec, err := restored.GetRecord(findingID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Payload["title"] != "Weak TLS" {
		t.Fatalf("unexpected restored record: %#v", rec.Payload)
	}
	blob, err := restored.ReadBlob(blobID)
	if err != nil {
		t.Fatal(err)
	}
	if string(blob) != "evidence data" {
		t.Fatalf("unexpected restored blob %q", blob)
	}
}

func TestBackupRestoreSafetyFailures(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, ".mnemox")
	v, err := CreateWithPassphrase(root, "ACME", "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(dir, "vault.mnemoxbak")
	if err := v.Backup(backupPath); err != nil {
		t.Fatal(err)
	}
	_ = v.Close()

	restoreRoot := filepath.Join(dir, "restore")
	if err := RestoreBackup(backupPath, restoreRoot, "test-passphrase", false); err != nil {
		t.Fatal(err)
	}
	if err := RestoreBackup(backupPath, restoreRoot, "test-passphrase", false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("expected overwrite refusal, got %v", err)
	}
	if err := RestoreBackup(backupPath, filepath.Join(dir, "wrong-pass"), "wrong-passphrase", false); err == nil {
		t.Fatalf("expected wrong passphrase failure")
	}

	corruptPath := filepath.Join(dir, "corrupt.mnemoxbak")
	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(corruptPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RestoreBackup(corruptPath, filepath.Join(dir, "corrupt"), "test-passphrase", false); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("expected checksum failure, got %v", err)
	}
}
