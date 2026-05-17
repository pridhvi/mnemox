package vault

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestSemanticSearchUsesEncryptedCacheAndRedactsCredentialSecrets(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".mnemox")
	v, err := CreateWithPassphrase(root, "ACME", "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	if _, err := v.AddRecord("finding", map[string]any{
		"title":   "Jenkins anonymous read",
		"summary": "Jenkins allowed unauthenticated read access.",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.AddRecord("credential", map[string]any{
		"name":     "svc_backup",
		"username": "svc_backup",
		"secret":   "super-secret-value",
	}); err != nil {
		t.Fatal(err)
	}

	hits, err := v.SemanticSearch("login permission bypass", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) == 0 || hits[0].Title != "Jenkins anonymous read" {
		t.Fatalf("expected semantic finding hit, got %#v", hits)
	}
	secretHits, err := v.SemanticSearch("super-secret-value", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(secretHits) != 0 {
		t.Fatalf("credential secret should not be semantically searchable: %#v", secretHits)
	}

	var token []byte
	if err := v.DB.QueryRow(`SELECT value FROM meta WHERE key = ?`, semanticIndexMetaKey).Scan(&token); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(token, []byte("Jenkins anonymous read")) || bytes.Contains(token, []byte("unauthenticated read access")) || bytes.Contains(token, []byte("super-secret-value")) {
		t.Fatalf("semantic cache contains plaintext: %s", strings.TrimSpace(string(token)))
	}
}
