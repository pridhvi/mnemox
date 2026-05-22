# Mnemox Release Runbook

Mnemox releases are published through GitHub Releases with GoReleaser-built
binary archives. Homebrew is intentionally deferred until demand justifies a
maintained tap.

## Supported Artifacts

- macOS and Linux are supported for `amd64` and `arm64`.
- Windows `amd64` and `arm64` archives are published as preview artifacts.
- Archives are `.tar.gz` for macOS/Linux and `.zip` for Windows.
- `checksums.txt` is signed with cosign as `checksums.txt.sigstore.json`.
- `tesseract` is optional and not bundled; OCR works only when it is installed
  separately and available on `PATH`.

## Pre-Tag Checks

Run from a clean `main` branch:

```bash
git status --short --branch
go test ./...
cd web && npm test && npm run build && npm run e2e
cd ..
go run github.com/securego/gosec/v2/cmd/gosec@latest ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=sign,publish
```

Cross-check the configured release targets:

```bash
tmp="$(mktemp -d)"
for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
  GOOS="${target%/*}" GOARCH="${target#*/}" CGO_ENABLED=0 \
    go build -o "$tmp/mnemox-${target%/*}-${target#*/}" ./cmd/mnemox
done
rm -rf "$tmp"
```

## Tag And Publish

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

The `Release` workflow publishes the GitHub Release. After it completes:

1. Confirm all six binary archives are attached.
2. Confirm `checksums.txt` and `checksums.txt.sigstore.json` are attached.
3. Verify at least one archive checksum locally:

   ```bash
   shasum -a 256 -c checksums.txt --ignore-missing
   ```

4. Verify the signed checksum bundle:

   ```bash
   cosign verify-blob checksums.txt \
     --bundle checksums.txt.sigstore.json \
     --certificate-identity-regexp 'https://github.com/pridhvi/mnemox/.github/workflows/release.yml@refs/tags/v.*' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com
   ```

5. Fill the release body from `.github/release-notes-template.md`.

