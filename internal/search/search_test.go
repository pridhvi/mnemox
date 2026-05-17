package search

import "testing"

func TestRankedWeightsTitlesAndRedactsCredentialSecrets(t *testing.T) {
	records := []Record{
		{ID: "1", Kind: "finding", Payload: map[string]any{"title": "Weak TLS", "summary": "Legacy TLS was enabled"}},
		{ID: "2", Kind: "credential", Payload: map[string]any{"name": "svc_backup", "username": "svc_backup", "secret": "super-secret-value"}},
	}
	hits := Ranked(records, "weak tls", 10)
	if len(hits) == 0 || hits[0].ID != "1" {
		t.Fatalf("expected Weak TLS first, got %#v", hits)
	}
	secretHits := Ranked(records, "super-secret-value", 10)
	if len(secretHits) != 0 {
		t.Fatalf("credential secret should not be searchable: %#v", secretHits)
	}
}

func TestSemanticRankedExpandsLocalSecurityAliases(t *testing.T) {
	records := []Record{
		{ID: "1", Kind: "finding", Payload: map[string]any{"title": "Jenkins anonymous read", "summary": "Jenkins allowed unauthenticated read access."}},
		{ID: "2", Kind: "finding", Payload: map[string]any{"title": "TLS certificate expired", "summary": "The public certificate is no longer valid."}},
		{ID: "3", Kind: "credential", Payload: map[string]any{"name": "svc_backup", "username": "svc_backup", "secret": "super-secret-value"}},
	}
	hits := SemanticRanked(records, "login permission bypass", 10)
	if len(hits) == 0 || hits[0].ID != "1" {
		t.Fatalf("expected semantic auth/access result first, got %#v", hits)
	}
	secretHits := SemanticRanked(records, "super-secret-value", 10)
	if len(secretHits) != 0 {
		t.Fatalf("credential secret should not be semantically searchable: %#v", secretHits)
	}
}
