package importer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pridhvi/mnemox/internal/vault"
)

func TestNmapXMLImportsAssets(t *testing.T) {
	v := testVault(t)
	xml := `<nmaprun><host><address addr="10.0.0.5"/><hostnames><hostname name="web01.local"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>`
	path := filepath.Join(t.TempDir(), "nmap.xml")
	if err := os.WriteFile(path, []byte(xml), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := NmapXML(v, path)
	if err != nil {
		t.Fatal(err)
	}
	if result.Assets != 1 {
		t.Fatalf("expected 1 asset, got %#v", result)
	}
	records, _ := v.Records("asset")
	if records[0].Payload["name"] != "web01.local" {
		t.Fatalf("unexpected asset: %#v", records[0].Payload)
	}
}

func TestNucleiJSONImportsFindingsAndAssets(t *testing.T) {
	v := testVault(t)
	line := `{"template-id":"exposure","host":"https://example.test","info":{"name":"Example Exposure","severity":"medium"},"template-url":"https://templates.test/exposure"}`
	path := filepath.Join(t.TempDir(), "nuclei.jsonl")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := NucleiJSON(v, path)
	if err != nil {
		t.Fatal(err)
	}
	if result.Findings != 1 || result.Assets != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	findings, _ := v.Records("finding")
	if findings[0].Payload["title"] != "Example Exposure" {
		t.Fatalf("unexpected finding: %#v", findings[0].Payload)
	}
}

func TestBurpXMLImportsFindingsAndAssets(t *testing.T) {
	v := testVault(t)
	xml := `<issues><issue><name>SQL injection</name><host ip="10.0.0.5">https://app.example.test</host><path>/login</path><location>https://app.example.test/login</location><severity>High</severity><confidence>Certain</confidence><issueBackground>SQL injection exists.</issueBackground><issueDetail>Parameter id was injectable.</issueDetail><remediationDetail>Use parameterized queries.</remediationDetail><references>https://portswigger.net/web-security/sql-injection</references></issue></issues>`
	path := filepath.Join(t.TempDir(), "burp.xml")
	if err := os.WriteFile(path, []byte(xml), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := BurpXML(v, path)
	if err != nil {
		t.Fatal(err)
	}
	if result.Findings != 1 || result.Assets != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	findings, _ := v.Records("finding")
	if findings[0].Payload["title"] != "SQL injection" || findings[0].Payload["severity"] != "HIGH" {
		t.Fatalf("unexpected burp finding: %#v", findings[0].Payload)
	}
	assets, _ := v.Linked(findings[0].ID, "affects_asset")
	if len(assets) != 1 || assets[0].Payload["value"] != "https://app.example.test/login" {
		t.Fatalf("expected linked burp asset: %#v", assets)
	}
}

func TestNessusXMLImportsFindingsAndAssets(t *testing.T) {
	v := testVault(t)
	xml := `<NessusClientData_v2><Report name="scan"><ReportHost name="web01"><HostProperties><tag name="host-ip">10.0.0.5</tag><tag name="host-fqdn">web01.local</tag></HostProperties><ReportItem port="443" protocol="tcp" severity="2" pluginID="123" pluginName="TLS 1.0 Enabled"><risk_factor>Medium</risk_factor><synopsis>Legacy TLS is enabled.</synopsis><description>TLS 1.0 accepted.</description><solution>Disable TLS 1.0.</solution><plugin_output>Proof output</plugin_output><see_also>https://example.test/tls</see_also><cve>CVE-TEST</cve></ReportItem></ReportHost></Report></NessusClientData_v2>`
	path := filepath.Join(t.TempDir(), "scan.nessus")
	if err := os.WriteFile(path, []byte(xml), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := NessusXML(v, path)
	if err != nil {
		t.Fatal(err)
	}
	if result.Findings != 1 || result.Assets != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	findings, _ := v.Records("finding")
	if findings[0].Payload["title"] != "TLS 1.0 Enabled" || findings[0].Payload["severity"] != "MEDIUM" {
		t.Fatalf("unexpected nessus finding: %#v", findings[0].Payload)
	}
	assets, _ := v.Linked(findings[0].ID, "affects_asset")
	if len(assets) != 1 || assets[0].Payload["name"] != "web01.local" {
		t.Fatalf("expected linked nessus asset: %#v", assets)
	}
}

func TestBloodHoundJSONImportsAssetsAndRelationshipNotes(t *testing.T) {
	v := testVault(t)
	graph := `{"nodes":[{"id":"u1","label":"alice@ACME.LOCAL","kind":"User"},{"id":"c1","label":"DC01.ACME.LOCAL","kind":"Computer"}],"edges":[{"source":"u1","target":"c1","relationship":"AdminTo"}]}`
	path := filepath.Join(t.TempDir(), "bloodhound.json")
	if err := os.WriteFile(path, []byte(graph), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := BloodHoundJSON(v, path)
	if err != nil {
		t.Fatal(err)
	}
	if result.Assets != 2 || result.Notes != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	notes, _ := v.Records("note")
	if len(notes) != 1 || notes[0].Payload["text"] != "alice@ACME.LOCAL --[AdminTo]--> DC01.ACME.LOCAL" {
		t.Fatalf("unexpected bloodhound note: %#v", notes)
	}
	assets, _ := v.Linked(notes[0].ID, "note_asset")
	if len(assets) != 2 {
		t.Fatalf("expected note linked to path assets: %#v", assets)
	}
}

func TestScreenshotFolderImportsImages(t *testing.T) {
	v := testVault(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "proof.png"), []byte("png"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte("txt"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := ScreenshotFolder(v, dir)
	if err != nil {
		t.Fatal(err)
	}
	if result.Evidence != 1 {
		t.Fatalf("expected 1 evidence item, got %#v", result)
	}
}

func testVault(t *testing.T) *vault.Vault {
	t.Helper()
	v, err := vault.CreateWithPassphrase(filepath.Join(t.TempDir(), ".mnemox"), "test", "passphrase")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}
