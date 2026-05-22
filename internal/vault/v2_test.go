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

func TestV2SearchMatchesFullScanAndFilters(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, ".mnemox")
	v, err := CreateWithPassphrase(root, "ACME", "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	asset1, err := v.AddRecord("asset", map[string]any{"name": "ci.acme.local", "type": "host", "value": "10.0.0.10", "tags": []string{"prod"}})
	if err != nil {
		t.Fatal(err)
	}
	asset2, err := v.AddRecord("asset", map[string]any{"name": "app.acme.local", "type": "host", "value": "10.0.0.20", "tags": []string{"dev"}})
	if err != nil {
		t.Fatal(err)
	}
	jenkins, err := v.AddRecord("finding", map[string]any{
		"title":          "Jenkins anonymous read",
		"status":         "confirmed",
		"severity":       "MEDIUM",
		"affected_scope": []string{"ci.acme.local"},
		"summary":        "Jenkins allowed unauthenticated read access.",
		"tags":           []string{"prod", "auth"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tls, err := v.AddRecord("finding", map[string]any{
		"title":          "Weak TLS",
		"status":         "draft",
		"severity":       "LOW",
		"affected_scope": []string{"app.acme.local"},
		"summary":        "TLS 1.0 was enabled.",
		"tags":           []string{"dev"},
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := v.AddRecord("evidence", map[string]any{"caption": "Dashboard proof", "kind": "screenshot", "tags": []string{"prod", "proof"}})
	if err != nil {
		t.Fatal(err)
	}
	note, err := v.AddRecord("note", map[string]any{"text": "Build history was visible", "asset": "ci.acme.local", "tags": []string{"prod"}})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := v.AddRecord("credential", map[string]any{
		"name":     "svc_backup",
		"username": "svc_backup",
		"secret":   "super-secret-value",
		"scope":    "ci.acme.local",
		"tags":     []string{"prod"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range []struct {
		src, dst, rel string
	}{
		{jenkins, asset1, "affects_asset"},
		{tls, asset2, "affects_asset"},
		{evidence, asset1, "evidence_asset"},
		{note, asset1, "note_asset"},
		{credential, asset1, "credential_asset"},
	} {
		if err := v.AddLink(link.src, link.dst, link.rel); err != nil {
			t.Fatal(err)
		}
	}

	baselineJenkins, err := v.SearchWithFilters("jenkins anonymous read", SearchFilters{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	baselineFinding, err := v.SearchWithFilters("jenkins", SearchFilters{Kind: "finding"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	baselineCombo, err := v.SearchWithFilters("jenkins", SearchFilters{Kind: "finding", AssetID: asset1, Tag: "prod", Status: "confirmed"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	baselineProd, err := v.FilteredRecords(SearchFilters{Tag: "prod"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	baselineConfirmed, err := v.FilteredRecords(SearchFilters{Status: "confirmed"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	baselineAsset, err := v.FilteredRecords(SearchFilters{AssetID: asset1}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.MigrateV2(filepath.Join(dir, "migration.mnemoxbak")); err != nil {
		t.Fatal(err)
	}
	if !v.v2TablesReady() {
		t.Fatal("expected v2 index tables")
	}

	jenkinsHits, err := v.SearchWithFilters("jenkins anonymous read", SearchFilters{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hitIDs(jenkinsHits), hitIDs(baselineJenkins); !sameStrings(got, want) {
		t.Fatalf("v2 jenkins search mismatch: got %#v want %#v", got, want)
	}
	findingHits, err := v.SearchWithFilters("jenkins", SearchFilters{Kind: "finding"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hitIDs(findingHits), hitIDs(baselineFinding); !sameStrings(got, want) {
		t.Fatalf("v2 kind search mismatch: got %#v want %#v", got, want)
	}
	comboHits, err := v.SearchWithFilters("jenkins", SearchFilters{Kind: "finding", AssetID: asset1, Tag: "prod", Status: "confirmed"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hitIDs(comboHits), hitIDs(baselineCombo); !sameStrings(got, want) {
		t.Fatalf("v2 combined filter search mismatch: got %#v want %#v", got, want)
	}
	prodRecords, err := v.FilteredRecords(SearchFilters{Tag: "prod"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := recordIDs(prodRecords), recordIDs(baselineProd); !sameStringSet(got, want) {
		t.Fatalf("v2 tag filter mismatch: got %#v want %#v", got, want)
	}
	confirmedRecords, err := v.FilteredRecords(SearchFilters{Status: "confirmed"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := recordIDs(confirmedRecords), recordIDs(baselineConfirmed); !sameStringSet(got, want) {
		t.Fatalf("v2 status filter mismatch: got %#v want %#v", got, want)
	}
	assetRecords, err := v.FilteredRecords(SearchFilters{AssetID: asset1}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := recordIDs(assetRecords), recordIDs(baselineAsset); !sameStringSet(got, want) {
		t.Fatalf("v2 asset filter mismatch: got %#v want %#v", got, want)
	}
	secretHits, err := v.SearchWithFilters("super-secret-value", SearchFilters{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(secretHits) != 0 {
		t.Fatalf("credential secret should not be searchable after v2 migration: %#v", secretHits)
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

func hitIDs(hits []SearchHit) []string {
	ids := make([]string, 0, len(hits))
	for _, hit := range hits {
		ids = append(ids, hit.ID)
	}
	return ids
}

func recordIDs(records []Record) []string {
	ids := make([]string, 0, len(records))
	for _, record := range records {
		ids = append(ids, record.ID)
	}
	return ids
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := map[string]int{}
	for _, value := range a {
		counts[value]++
	}
	for _, value := range b {
		counts[value]--
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}
