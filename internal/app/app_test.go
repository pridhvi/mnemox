package app_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pridhvi/mnemox/internal/vault"
)

func TestEndToEndFindingPacket(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	evidence := filepath.Join(dir, "jenkins.txt")
	if err := os.WriteFile(evidence, []byte("Jenkins dashboard visible without auth"), 0o600); err != nil {
		t.Fatal(err)
	}

	run(t, bin, dir, "init", "--name", "ACME")
	run(t, bin, dir, "asset", "add", "ci.acme.local", "--type", "host")
	run(t, bin, dir, "finding", "add", "Jenkins anonymous read", "--summary", "Jenkins allowed unauthenticated read access.", "--affected-scope", "ci.acme.local", "--asset", "ci.acme.local")
	run(t, bin, dir, "note", "Build history was visible", "--finding", "Jenkins anonymous read", "--asset", "ci.acme.local")
	run(t, bin, dir, "evidence", "add", evidence, "--finding", "Jenkins anonymous read", "--caption", "Dashboard visible without authentication")
	cvss := run(t, bin, dir, "cvss", "score", "Jenkins anonymous read", "--av", "N", "--ac", "L", "--at", "N", "--pr", "N", "--ui", "N", "--vc", "L", "--vi", "N", "--va", "N", "--sc", "N", "--si", "N", "--sa", "N")
	if !strings.Contains(cvss, "CVSS:4.0/") {
		t.Fatalf("expected CVSS vector, got %s", cvss)
	}

	packet := run(t, bin, dir, "packet", "build", "Jenkins anonymous read")
	for _, want := range []string{"# Jenkins anonymous read", "CVSS v4.0 Base Score", "Dashboard visible without authentication", "[evidence:"} {
		if !strings.Contains(packet, want) {
			t.Fatalf("packet missing %q:\n%s", want, packet)
		}
	}
	bundle := run(t, bin, dir, "packet", "bundle", "Jenkins anonymous read")
	for _, want := range []string{"# Evidence Citation Bundle: Jenkins anonymous read", "## Cited Assets", "ci.acme.local", "Dashboard visible without authentication", "Build history was visible", "[evidence:", "[note:"} {
		if !strings.Contains(bundle, want) {
			t.Fatalf("bundle missing %q:\n%s", want, bundle)
		}
	}
	filteredBundle := run(t, bin, dir, "packet", "bundle", "Jenkins anonymous read", "--asset", "ci.acme.local")
	for _, want := range []string{"## Cited Assets", "Dashboard visible without authentication", "Build history was visible"} {
		if !strings.Contains(filteredBundle, want) {
			t.Fatalf("asset-filtered bundle missing %q:\n%s", want, filteredBundle)
		}
	}

	run(t, bin, dir, "finding", "asset", "unlink", "Jenkins anonymous read", "ci.acme.local")
	unlinkedBundle := run(t, bin, dir, "packet", "bundle", "Jenkins anonymous read")
	if strings.Contains(unlinkedBundle, "## Cited Assets") {
		t.Fatalf("expected unlinked bundle to omit cited assets:\n%s", unlinkedBundle)
	}
	run(t, bin, dir, "finding", "asset", "link", "Jenkins anonymous read", "ci.acme.local")
	relinkedBundle := run(t, bin, dir, "packet", "bundle", "Jenkins anonymous read")
	if !strings.Contains(relinkedBundle, "## Cited Assets") || !strings.Contains(relinkedBundle, "ci.acme.local") {
		t.Fatalf("expected relinked bundle to cite asset:\n%s", relinkedBundle)
	}

	run(t, bin, dir, "cred", "add", "svc_jenkins", "--username", "svc_jenkins", "--secret", "redacted", "--asset", "ci.acme.local")
	t.Setenv("MNEMOX_PASSPHRASE", "test-passphrase")
	t.Setenv("MNEMOX_ALLOW_INSECURE_PASSPHRASE_ENV", "1")
	v, err := vault.Open(filepath.Join(dir, ".mnemox"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	credential, err := v.FindOne("credential", "svc_jenkins")
	if err != nil {
		t.Fatal(err)
	}
	linkedAssets, err := v.Linked(credential.ID, "credential_asset")
	if err != nil {
		t.Fatal(err)
	}
	if len(linkedAssets) != 1 || linkedAssets[0].Payload["name"] != "ci.acme.local" {
		t.Fatalf("expected credential linked to ci.acme.local, got %#v", linkedAssets)
	}
}

func TestSearchFindsEncryptedRecordContents(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	run(t, bin, dir, "init", "--name", "ACME")
	run(t, bin, dir, "finding", "add", "Weak TLS", "--summary", "TLS 1.0 was enabled.")
	run(t, bin, dir, "finding", "add", "Jenkins anonymous read", "--summary", "Jenkins allowed unauthenticated read access.")
	out := run(t, bin, dir, "ask", "TLS enabled")
	if !strings.Contains(out, "Weak TLS") {
		t.Fatalf("expected search result, got %s", out)
	}
	semantic := run(t, bin, dir, "ask", "--semantic", "login permission bypass")
	if !strings.Contains(semantic, "Jenkins anonymous read") {
		t.Fatalf("expected semantic search result, got %s", semantic)
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, executableName("mnemox"))
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/mnemox")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return bin
}

func run(t *testing.T, bin, cwd string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(),
		"MNEMOX_PASSPHRASE=test-passphrase",
		"MNEMOX_ALLOW_INSECURE_PASSPHRASE_ENV=1",
		"MNEMOX_VAULT="+filepath.Join(cwd, ".mnemox"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", bin, args, err, out)
	}
	return string(out)
}

func executableName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		next := filepath.Dir(dir)
		if next == dir {
			t.Fatal("repo root not found")
		}
		dir = next
	}
}
