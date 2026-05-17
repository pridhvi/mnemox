package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"mnemox/internal/vault"
)

func TestWebAPIWorkflowAndCredentialRedaction(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".mnemox")
	v, err := vault.CreateWithPassphrase(root, "ACME", "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	_ = v.Close()

	server := New(Options{VaultPath: root, Addr: "127.0.0.1:0"})
	ts := httptest.NewServer(server.routes())
	defer ts.Close()

	postJSON(t, ts.URL+"/api/unlock", map[string]any{"passphrase": "test-passphrase"}, http.StatusOK)

	finding := postJSON(t, ts.URL+"/api/findings", map[string]any{
		"title":          "Jenkins anonymous read",
		"summary":        "Jenkins allowed unauthenticated read access.",
		"affected_scope": []string{"ci.acme.local"},
	}, http.StatusCreated)
	findingID := finding["id"].(string)
	postJSON(t, ts.URL+"/api/assets", map[string]any{
		"name":  "ci.acme.local",
		"type":  "host",
		"value": "10.0.0.10",
	}, http.StatusCreated)
	assets := getJSON(t, ts.URL+"/api/assets", http.StatusOK)
	if len(assets["items"].([]any)) != 1 {
		t.Fatalf("expected asset list item: %#v", assets)
	}
	assetID := assets["items"].([]any)[0].(map[string]any)["id"].(string)
	postJSON(t, ts.URL+"/api/findings/"+findingID+"/assets", map[string]any{"asset_id": assetID}, http.StatusOK)
	detailWithAsset := getJSON(t, ts.URL+"/api/findings/"+findingID, http.StatusOK)
	if len(detailWithAsset["assets"].([]any)) != 1 {
		t.Fatalf("expected linked finding asset: %#v", detailWithAsset)
	}
	uploadImport(t, ts.URL+"/api/import/nmap", "nmap.xml", `<nmaprun><host><address addr="10.0.0.11"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>`)

	putJSON(t, ts.URL+"/api/findings/"+findingID, map[string]any{
		"title":             "Jenkins anonymous read",
		"status":            "confirmed",
		"severity":          "Unscored",
		"affected_scope":    []string{"ci.acme.local"},
		"summary":           "Jenkins allowed unauthenticated read access.",
		"technical_details": "Anonymous users could view jobs.",
		"impact":            "Build metadata exposure.",
		"remediation":       "Require authentication.",
		"validation":        "Confirm anonymous access is disabled.",
	}, http.StatusOK)

	note := postJSON(t, ts.URL+"/api/findings/"+findingID+"/notes", map[string]any{
		"text":  "Build history was visible",
		"asset": "ci.acme.local",
	}, http.StatusCreated)
	putJSON(t, ts.URL+"/api/notes/"+note["id"].(string), map[string]any{
		"text":  "Build history and job output were visible",
		"asset": "ci.acme.local",
		"tags":  []string{"jenkins"},
	}, http.StatusOK)
	notes := getJSON(t, ts.URL+"/api/notes", http.StatusOK)
	firstNote := notes["items"].([]any)[0].(map[string]any)
	if firstNote["payload"].(map[string]any)["text"] != "Build history and job output were visible" || len(firstNote["assets"].([]any)) != 1 {
		t.Fatalf("expected editable linked note: %#v", notes)
	}
	deleteJSON(t, ts.URL+"/api/notes/"+note["id"].(string)+"/assets/"+assetID, http.StatusOK)
	postJSON(t, ts.URL+"/api/notes/"+note["id"].(string)+"/assets", map[string]any{"asset_id": assetID}, http.StatusOK)

	evidenceRecord := uploadEvidence(t, ts.URL+"/api/findings/"+findingID+"/evidence")
	putJSON(t, ts.URL+"/api/evidence/"+evidenceRecord["id"].(string), map[string]any{
		"kind":    "screenshot",
		"caption": "Updated dashboard proof",
		"tags":    []string{"auth"},
	}, http.StatusOK)
	postJSON(t, ts.URL+"/api/evidence/"+evidenceRecord["id"].(string)+"/assets", map[string]any{"asset_id": assetID}, http.StatusOK)
	evidenceList := getJSON(t, ts.URL+"/api/evidence", http.StatusOK)
	firstEvidence := evidenceList["items"].([]any)[0].(map[string]any)
	if firstEvidence["payload"].(map[string]any)["caption"] != "Updated dashboard proof" || len(firstEvidence["assets"].([]any)) != 1 {
		t.Fatalf("expected editable linked evidence: %#v", evidenceList)
	}
	deleteJSON(t, ts.URL+"/api/evidence/"+evidenceRecord["id"].(string)+"/assets/"+assetID, http.StatusOK)
	postJSON(t, ts.URL+"/api/evidence/"+evidenceRecord["id"].(string)+"/assets", map[string]any{"asset_id": assetID}, http.StatusOK)
	assetDetail := getJSON(t, ts.URL+"/api/assets/"+assetID, http.StatusOK)
	if len(assetDetail["findings"].([]any)) != 1 || len(assetDetail["evidence"].([]any)) != 1 || len(assetDetail["notes"].([]any)) != 1 {
		t.Fatalf("expected asset relation context: %#v", assetDetail)
	}
	filteredFindings := getJSON(t, ts.URL+"/api/findings?asset_id="+assetID, http.StatusOK)
	if len(filteredFindings["items"].([]any)) != 1 {
		t.Fatalf("expected asset-filtered finding: %#v", filteredFindings)
	}
	previewReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/evidence/"+evidenceRecord["id"].(string)+"/preview", nil)
	previewResp, err := http.DefaultClient.Do(previewReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = previewResp.Body.Close()
	if previewResp.StatusCode != http.StatusOK || previewResp.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("unexpected preview response: %d %s", previewResp.StatusCode, previewResp.Header.Get("Content-Type"))
	}

	cvss := postJSON(t, ts.URL+"/api/findings/"+findingID+"/cvss", map[string]any{
		"metrics": map[string]string{"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "L", "VI": "N", "VA": "N", "SC": "N", "SI": "N", "SA": "N"},
		"notes":   "Information disclosure only.",
	}, http.StatusOK)
	if !strings.HasPrefix(cvss["vector"].(string), "CVSS:4.0/") {
		t.Fatalf("expected CVSS vector: %#v", cvss)
	}

	packet := getJSON(t, ts.URL+"/api/findings/"+findingID+"/packet", http.StatusOK)
	if !strings.Contains(packet["markdown"].(string), "Jenkins anonymous read") {
		t.Fatalf("packet missing finding title: %#v", packet)
	}
	bundle := getJSON(t, ts.URL+"/api/findings/"+findingID+"/citation-bundle?asset_id="+assetID, http.StatusOK)
	bundleMarkdown := bundle["markdown"].(string)
	for _, expected := range []string{"Evidence Citation Bundle", "Updated dashboard proof", "Build history and job output were visible", "[evidence:", "[note:"} {
		if !strings.Contains(bundleMarkdown, expected) {
			t.Fatalf("citation bundle missing %q: %s", expected, bundleMarkdown)
		}
	}

	credential := postJSON(t, ts.URL+"/api/credentials", map[string]any{
		"name":     "svc_backup",
		"username": "svc_backup",
		"secret":   "super-secret-value",
		"scope":    "domain",
	}, http.StatusCreated)
	putJSON(t, ts.URL+"/api/credentials/"+credential["id"].(string), map[string]any{
		"name":     "svc_backup_rotated",
		"username": "svc_backup",
		"scope":    "ci.acme.local",
		"tags":     []string{"prod"},
	}, http.StatusOK)
	postJSON(t, ts.URL+"/api/credentials/"+credential["id"].(string)+"/assets", map[string]any{"asset_id": assetID}, http.StatusOK)
	credentialList := getJSON(t, ts.URL+"/api/credentials", http.StatusOK)
	firstCredential := credentialList["items"].([]any)[0].(map[string]any)
	if firstCredential["payload"].(map[string]any)["name"] != "svc_backup_rotated" || len(firstCredential["assets"].([]any)) != 1 {
		t.Fatalf("expected editable linked credential: %#v", credentialList)
	}
	deleteJSON(t, ts.URL+"/api/credentials/"+credential["id"].(string)+"/assets/"+assetID, http.StatusOK)
	postJSON(t, ts.URL+"/api/credentials/"+credential["id"].(string)+"/assets", map[string]any{"asset_id": assetID}, http.StatusOK)
	assetDetail = getJSON(t, ts.URL+"/api/assets/"+assetID, http.StatusOK)
	if len(assetDetail["credentials"].([]any)) != 1 {
		t.Fatalf("expected linked credential in asset detail: %#v", assetDetail)
	}
	credentials := getJSON(t, ts.URL+"/api/credentials", http.StatusOK)
	encoded, _ := json.Marshal(credentials)
	if strings.Contains(string(encoded), "super-secret-value") {
		t.Fatalf("credential list leaked secret: %s", encoded)
	}
	search := getJSON(t, ts.URL+"/api/search?q=super-secret-value", http.StatusOK)
	encoded, _ = json.Marshal(search)
	if strings.Contains(string(encoded), "super-secret-value") || strings.Contains(string(encoded), "svc_backup") {
		t.Fatalf("credential secret was searchable: %s", encoded)
	}
	relatedSearch := getJSON(t, ts.URL+"/api/search?asset_id="+assetID+"&kind=finding", http.StatusOK)
	if len(relatedSearch["items"].([]any)) != 1 {
		t.Fatalf("expected linked finding search result: %#v", relatedSearch)
	}
	relatedCredentialSearch := getJSON(t, ts.URL+"/api/search?asset_id="+assetID+"&kind=credential", http.StatusOK)
	encoded, _ = json.Marshal(relatedCredentialSearch)
	if strings.Contains(string(encoded), "super-secret-value") || !strings.Contains(string(encoded), "svc_backup") {
		t.Fatalf("credential relationship search redaction failed: %s", encoded)
	}
	attackPaths := getJSON(t, ts.URL+"/api/attack-paths", http.StatusOK)
	if len(attackPaths["items"].([]any)) != 1 {
		t.Fatalf("expected attack path chain: %#v", attackPaths)
	}
	firstPath := attackPaths["items"].([]any)[0].(map[string]any)
	if len(firstPath["findings"].([]any)) != 1 || len(firstPath["evidence"].([]any)) != 1 || len(firstPath["notes"].([]any)) != 1 || len(firstPath["credentials"].([]any)) != 1 {
		t.Fatalf("expected complete attack path chain: %#v", firstPath)
	}
}

func TestAssetMergeMovesRelationsAndRedactsCredentialContext(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".mnemox")
	v, err := vault.CreateWithPassphrase(root, "ACME", "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	_ = v.Close()

	server := New(Options{VaultPath: root, Addr: "127.0.0.1:0"})
	ts := httptest.NewServer(server.routes())
	defer ts.Close()

	postJSON(t, ts.URL+"/api/unlock", map[string]any{"passphrase": "test-passphrase"}, http.StatusOK)

	primary := postJSON(t, ts.URL+"/api/assets", map[string]any{
		"name":  "ci.acme.local",
		"type":  "host",
		"value": "ci.acme.local",
		"tags":  []string{"manual"},
		"notes": "Primary operator asset.",
	}, http.StatusCreated)
	primaryID := primary["id"].(string)
	duplicate := postJSON(t, ts.URL+"/api/assets", map[string]any{
		"name":  "ci.acme.local",
		"type":  "host",
		"value": "10.0.0.10",
		"tags":  []string{"import:nmap"},
		"notes": "Imported scan asset.",
	}, http.StatusCreated)
	duplicateID := duplicate["id"].(string)

	duplicates := getJSON(t, ts.URL+"/api/assets/duplicates", http.StatusOK)
	if len(duplicates["items"].([]any)) != 1 {
		t.Fatalf("expected duplicate candidate group: %#v", duplicates)
	}

	finding := postJSON(t, ts.URL+"/api/findings", map[string]any{
		"title":   "Jenkins anonymous read",
		"summary": "Jenkins allowed unauthenticated read access.",
	}, http.StatusCreated)
	findingID := finding["id"].(string)
	postJSON(t, ts.URL+"/api/findings/"+findingID+"/assets", map[string]any{"asset_id": duplicateID}, http.StatusOK)

	note := postJSON(t, ts.URL+"/api/findings/"+findingID+"/notes", map[string]any{
		"text": "Build history was visible",
	}, http.StatusCreated)
	postJSON(t, ts.URL+"/api/notes/"+note["id"].(string)+"/assets", map[string]any{"asset_id": duplicateID}, http.StatusOK)

	evidence := uploadEvidence(t, ts.URL+"/api/findings/"+findingID+"/evidence")
	postJSON(t, ts.URL+"/api/evidence/"+evidence["id"].(string)+"/assets", map[string]any{"asset_id": duplicateID}, http.StatusOK)

	credential := postJSON(t, ts.URL+"/api/credentials", map[string]any{
		"name":     "svc_backup",
		"username": "svc_backup",
		"secret":   "super-secret-value",
		"scope":    "ci.acme.local",
	}, http.StatusCreated)
	postJSON(t, ts.URL+"/api/credentials/"+credential["id"].(string)+"/assets", map[string]any{"asset_id": duplicateID}, http.StatusOK)

	merged := postJSON(t, ts.URL+"/api/assets/"+primaryID+"/merge", map[string]any{"duplicate_id": duplicateID}, http.StatusOK)
	if len(merged["findings"].([]any)) != 1 || len(merged["evidence"].([]any)) != 1 || len(merged["notes"].([]any)) != 1 || len(merged["credentials"].([]any)) != 1 {
		t.Fatalf("expected merged asset relation context: %#v", merged)
	}
	payload := merged["payload"].(map[string]any)
	encoded, _ := json.Marshal(payload)
	if !strings.Contains(string(encoded), "10.0.0.10") || !strings.Contains(string(encoded), "import:nmap") || !strings.Contains(string(encoded), "Imported scan asset.") {
		t.Fatalf("expected merged aliases, tags, and notes: %s", encoded)
	}
	if strings.Contains(string(encoded), "super-secret-value") {
		t.Fatalf("merged asset payload leaked credential secret: %s", encoded)
	}

	getJSON(t, ts.URL+"/api/assets/"+duplicateID, http.StatusNotFound)
	assetList := getJSON(t, ts.URL+"/api/assets", http.StatusOK)
	if len(assetList["items"].([]any)) != 1 {
		t.Fatalf("expected duplicate asset to be removed: %#v", assetList)
	}

	relatedCredentialSearch := getJSON(t, ts.URL+"/api/search?asset_id="+primaryID+"&kind=credential", http.StatusOK)
	encoded, _ = json.Marshal(relatedCredentialSearch)
	if strings.Contains(string(encoded), "super-secret-value") || !strings.Contains(string(encoded), "svc_backup") {
		t.Fatalf("credential relationship search redaction failed after merge: %s", encoded)
	}
}

func TestWebImportEndpointsForBurpNessusAndBloodHound(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".mnemox")
	v, err := vault.CreateWithPassphrase(root, "ACME", "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	_ = v.Close()

	server := New(Options{VaultPath: root, Addr: "127.0.0.1:0"})
	ts := httptest.NewServer(server.routes())
	defer ts.Close()

	postJSON(t, ts.URL+"/api/unlock", map[string]any{"passphrase": "test-passphrase"}, http.StatusOK)

	burp := uploadImport(t, ts.URL+"/api/import/burp", "burp.xml", `<issues><issue><name>Reflected XSS</name><host>https://app.example.test</host><path>/search</path><severity>High</severity><confidence>Certain</confidence><issueBackground>XSS background</issueBackground><issueDetail>q reflected</issueDetail><remediationDetail>Encode output</remediationDetail></issue></issues>`)
	if burp["findings"].(float64) != 1 || burp["assets"].(float64) != 1 {
		t.Fatalf("unexpected burp import: %#v", burp)
	}

	nessus := uploadImport(t, ts.URL+"/api/import/nessus", "scan.nessus", `<NessusClientData_v2><Report name="scan"><ReportHost name="web01"><HostProperties><tag name="host-ip">10.0.0.5</tag></HostProperties><ReportItem port="443" protocol="tcp" severity="3" pluginID="123" pluginName="Weak Cipher"><risk_factor>High</risk_factor><synopsis>Weak cipher enabled.</synopsis><solution>Disable weak ciphers.</solution></ReportItem></ReportHost></Report></NessusClientData_v2>`)
	if nessus["findings"].(float64) != 1 || nessus["assets"].(float64) != 1 {
		t.Fatalf("unexpected nessus import: %#v", nessus)
	}

	bloodhound := uploadImport(t, ts.URL+"/api/import/bloodhound", "bloodhound.json", `{"nodes":[{"id":"u1","label":"alice@ACME.LOCAL","kind":"User"},{"id":"c1","label":"DC01.ACME.LOCAL","kind":"Computer"}],"edges":[{"source":"u1","target":"c1","relationship":"AdminTo"}]}`)
	if bloodhound["assets"].(float64) != 2 || bloodhound["notes"].(float64) != 1 {
		t.Fatalf("unexpected bloodhound import: %#v", bloodhound)
	}
}

func postJSON(t *testing.T, url string, payload any, status int) map[string]any {
	t.Helper()
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return doJSON(t, req, status)
}

func putJSON(t *testing.T, url string, payload any, status int) map[string]any {
	t.Helper()
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return doJSON(t, req, status)
}

func getJSON(t *testing.T, url string, status int) map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return doJSON(t, req, status)
}

func deleteJSON(t *testing.T, url string, status int) map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return doJSON(t, req, status)
}

func doJSON(t *testing.T, req *http.Request, status int) map[string]any {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != status {
		t.Fatalf("%s %s: status %d, body %s", req.Method, req.URL, resp.StatusCode, data)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, data)
	}
	return out
}

func uploadEvidence(t *testing.T, url string) map[string]any {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "jenkins.png")
	if err != nil {
		t.Fatal(err)
	}
	png, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write(png)
	_ = writer.WriteField("caption", "Dashboard visible without authentication")
	_ = writer.WriteField("kind", "screenshot")
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return doJSON(t, req, http.StatusCreated)
}

func uploadImport(t *testing.T, url, filename, content string) map[string]any {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte(content))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	response := doJSON(t, req, http.StatusOK)
	if response["assets"].(float64) < 1 {
		t.Fatalf("expected imported assets: %#v", response)
	}
	return response
}
