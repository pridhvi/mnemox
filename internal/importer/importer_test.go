package importer

import (
	"os"
	"path/filepath"
	"testing"

	"mnemox/internal/vault"
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
