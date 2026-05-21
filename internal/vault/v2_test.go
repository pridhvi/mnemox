package vault

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestMigrateV2BuildsEncryptedBlindIndexes(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, ".mnemox")
	v, err := CreateWithPassphrase(root, "ACME", "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	findingID, err := v.AddRecord("finding", map[string]any{
		"title":          "Weak TLS",
		"status":         "confirmed",
		"affected_scope": []string{"app.acme.local"},
		"summary":        "TLS 1.0 was enabled.",
	})
	if err != nil {
		t.Fatal(err)
	}
	credentialID, err := v.AddRecord("credential", map[string]any{
		"name":     "svc_backup",
		"username": "svc_backup",
		"secret":   "super-secret-value",
		"scope":    "domain",
	})
	if err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(dir, "migration.mnemoxbak")
	writtenBackup, err := v.MigrateV2(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if writtenBackup != backupPath {
		t.Fatalf("unexpected backup path %q", writtenBackup)
	}

	ids, err := v.V2SearchCandidateIDs("weak tls", 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(ids, findingID) {
		t.Fatalf("expected v2 candidate for finding %s, got %#v", findingID, ids)
	}
	ids, err = v.V2SearchCandidateIDs("super-secret-value", 10)
	if err != nil {
		t.Fatal(err)
	}
	if containsString(ids, credentialID) {
		t.Fatalf("credential secret entered v2 search index: %#v", ids)
	}

	rows, err := v.DB.Query(`SELECT value FROM record_fields_v2`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var value []byte
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(value, []byte("Weak TLS")) || bytes.Contains(value, []byte("super-secret-value")) {
			t.Fatalf("v2 field value contains plaintext: %q", value)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	newID, err := v.AddRecord("finding", map[string]any{"title": "SSRF metadata access", "summary": "Instance metadata endpoint was reachable."})
	if err != nil {
		t.Fatal(err)
	}
	ids, err = v.V2SearchCandidateIDs("metadata", 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(ids, newID) {
		t.Fatalf("new record was not added to v2 index: %#v", ids)
	}
	rec, err := v.GetRecord(newID)
	if err != nil {
		t.Fatal(err)
	}
	rec.Payload["title"] = "Open redirect"
	if err := v.UpdateRecord(newID, rec.Payload); err != nil {
		t.Fatal(err)
	}
	ids, err = v.V2SearchCandidateIDs("redirect", 10)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(ids, newID) {
		t.Fatalf("updated record was not added to v2 index: %#v", ids)
	}
	if err := v.DeleteRecord(newID); err != nil {
		t.Fatal(err)
	}
	ids, err = v.V2SearchCandidateIDs("redirect", 10)
	if err != nil {
		t.Fatal(err)
	}
	if containsString(ids, newID) {
		t.Fatalf("deleted record remained in v2 index: %#v", ids)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
