# Mnemox

Mnemox is a local-first memory system for pentest engagements. It stores
findings, notes, evidence, credentials, assets, and CVSS v4.0 Base scores in an
encrypted local vault, then renders copy-paste-ready Markdown Finding Packets.
The web UI also includes an Attack Paths workspace for connected asset risk,
context completeness checks, and copy-ready attack path Markdown.

## Install

Download the archive for your OS and CPU from
[GitHub Releases](https://github.com/pridhvi/mnemox/releases):

- `mnemox_<version>_darwin_amd64.tar.gz`: macOS Intel
- `mnemox_<version>_darwin_arm64.tar.gz`: macOS Apple Silicon
- `mnemox_<version>_linux_amd64.tar.gz`: Linux x86_64
- `mnemox_<version>_linux_arm64.tar.gz`: Linux ARM64
- `mnemox_<version>_windows_amd64.zip`: Windows x86_64 preview
- `mnemox_<version>_windows_arm64.zip`: Windows ARM64 preview

Verify the archive checksum before installing:

```bash
shasum -a 256 -c checksums.txt --ignore-missing
tar -xzf mnemox_<version>_<os>_<arch>.tar.gz
install -m 0755 mnemox /usr/local/bin/mnemox
```

On Windows, compare the `Get-FileHash` SHA256 output with `checksums.txt`, then
extract the `.zip` and run `mnemox.exe`.

macOS and Linux are the supported release platforms. Windows binaries are
published as preview artifacts until Windows runtime usage has more mileage.

To build from source:

```bash
make build
```

Go users can install tagged releases directly:

```bash
go install github.com/pridhvi/mnemox/cmd/mnemox@latest
```

Homebrew is intentionally deferred until there is demand for a maintained tap.

## Primary Web Workflow

Build the embedded React UI and Go binary:

```bash
make build
```

Start the local web app:

```bash
./bin/mnemox serve
```

The server binds to `127.0.0.1:8787` by default and prompts for the vault
passphrase in the browser. Use `--port 0` to select a free port. Web sessions
auto-lock after 30 minutes of idle time by default; use
`--lock-after <duration>` to change that or `--lock-after 0` to disable it.

Non-local bind addresses require `--allow-remote` and HTTP Basic Auth:

```bash
./bin/mnemox serve \
  --addr 0.0.0.0 \
  --allow-remote \
  --basic-auth-user operator \
  --basic-auth-password-file ./basic-auth-password
```

The Basic Auth layer protects the SPA and APIs before the vault unlock flow.
The existing API launch token remains required for API mutations and reads.
That token is generated randomly every time `mnemox serve` starts, exposed only
through same-origin `GET /api/status`, kept in the SPA's memory, and sent as
`X-Mnemox-Api-Token` on `/api/*` requests except `/api/status`. It is a
same-origin request guard, not a replacement for Basic Auth or the vault
passphrase. Direct API clients should fetch `/api/status` first, then include
the returned `api_token` header value.

By default, Mnemox uses `.mnemox/` in the current directory. Set
`MNEMOX_VAULT=/path/to/.mnemox` or pass `--vault /path/to/.mnemox`.

## CLI And Console Workflow

Run Mnemox without arguments to enter the console:

```bash
./bin/mnemox
```

Example console session:

```text
mnemox > init --name "ACME External"
mnemox > asset add ci.acme.local --type host
mnemox > finding add "Jenkins anonymous read" --severity Medium --summary "Jenkins allowed unauthenticated read access." --affected-scope ci.acme.local --asset ci.acme.local
mnemox > note "Build history was visible" --finding "Jenkins anonymous read" --asset ci.acme.local
mnemox > evidence add ./jenkins.txt --finding "Jenkins anonymous read" --caption "Dashboard visible without authentication"
mnemox > cred add svc_jenkins --username svc_jenkins --asset ci.acme.local
mnemox > cvss score "Jenkins anonymous read" --av N --ac L --at N --pr N --ui N --vc L --vi N --va N --sc N --si N --sa N
mnemox > packet build "Jenkins anonymous read"
```

The same commands work in batch mode:

```bash
./bin/mnemox --passphrase-file ./vault-passphrase finding add "Weak TLS" --summary "TLS 1.0 was enabled."
```

For automation, prefer `--passphrase-file` or `--passphrase-stdin`. The
`MNEMOX_PASSPHRASE` environment variable is intentionally disabled unless
`MNEMOX_ALLOW_INSECURE_PASSPHRASE_ENV=1` is also set; use it only for CI or
batch jobs where the process environment exposure is understood.

`finding add --affected-scope` stores report-facing scope text. Use
`finding add --asset` or `finding asset link` to create the typed asset
relationship that powers attack paths, asset filters, and cited asset packets.
The asset must already exist; create it with `asset add` first.
`note --asset`, `evidence add --asset`, and `cred add --asset` also create
typed asset relationships when they point at existing assets. Evidence added to
a finding automatically inherits that finding's affected asset links.

## Commands

- `init`: create an encrypted local vault.
- `finding add`: create a finding. Add `--asset <asset>` to link existing affected assets by ID, name, or value.
- `finding asset link/unlink`: manage affected asset relationships for a finding.
- `asset add/list`: create and list assets.
- `note`: add an operator note. Add `--asset <asset>` to link a matching existing asset.
- `evidence add`: encrypt and attach a file as evidence. Add `--asset <asset>` to link existing assets, or attach it to a finding to inherit affected assets.
- `evidence ocr`: manually extract local OCR text from screenshot evidence when `tesseract` is installed.
- `cred add`: add an encrypted credential record. Add `--asset <asset>` to link existing assets.
- `import nmap`: import Nmap XML hosts/services as assets.
- `import nuclei`: import nuclei JSONL findings and assets.
- `import burp`: import Burp Suite XML issues as findings and assets.
- `import nessus`: import Nessus XML report items as findings and assets.
- `import bloodhound`: import BloodHound JSON graph/path exports as assets and relationship notes.
- `import screenshots`: import a folder of screenshots as evidence.
- `ask`: local evidence recall over decrypted vault records. Add `--semantic` to use the encrypted local semantic index.
- `cvss score`: calculate and store a CVSS v4.0 Base score.
- `packet build`: render a cited Markdown Finding Packet.
- `packet bundle`: render a prompt-ready Evidence Citation Bundle.
- `export-blob`: decrypt an evidence blob to a file.
- `backup create <file.mnemoxbak>`: create an encrypted full-vault backup.
- `backup restore <file.mnemoxbak> --vault <path> [--force]`: restore a full-vault backup.
- `vault migrate-v2 [--backup <file.mnemoxbak>]`: create an encrypted backup and build the v2 query index.
- `serve`: start the local web UI.
- `use <vault-path>`: console-only command to switch vault path.

## Security Model

Mnemox prompts for a vault passphrase by default and derives the vault key with
Argon2id. Record payloads and evidence blobs are encrypted with
XChaCha20-Poly1305. Keep the passphrase safe; lost passphrases cannot be
recovered.

The CLI supports `--passphrase-file` and `--passphrase-stdin` for safer
non-interactive use. Environment passphrases are discouraged and require the
explicit `MNEMOX_ALLOW_INSECURE_PASSPHRASE_ENV=1` opt-in because environment
variables can leak through process inspection, shell history, and subprocesses.

Mnemox does not send data to an external AI service. Search supports ranked
keyword/fuzzy matching and an optional deterministic local feature-hashing
semantic mode backed by an encrypted vault cache. Vaults migrated with
`vault migrate-v2` use SQLite blind-index candidate lookup for keyword search
before decrypting and ranking candidate records. It does not download or run a
remote embedding model. Credential secrets are excluded from searchable
material and v2 indexes.

Remote web access is opt-in. `--allow-remote` requires HTTP Basic Auth, and web
sessions auto-lock after an idle timeout unless disabled. The browser never
stores the vault passphrase. The unlocked vault is shared process state: any
lock/logout or idle timeout closes it for all connected browser windows, and a
server restart always drops the unlocked state and generates a new API launch
token. When Basic Auth uses `--basic-auth-password-file`, the password file is
checked per request, so rotating that file invalidates the old Basic Auth
password immediately.

Screenshot OCR is manual and local-only. The optional `tesseract` binary is not
bundled with Mnemox; install it separately for your OS and make sure it is on
`PATH` to enable OCR extraction into encrypted evidence metadata.

## Backlog And Releases

- Project canon: [docs/PROJECT.md](docs/PROJECT.md)
- Backlog: [docs/BACKLOG.md](docs/BACKLOG.md)
- Codex instructions: [AGENTS.md](AGENTS.md)
- CI: `.github/workflows/ci.yml`
- Release config: `.goreleaser.yaml`
- Release runbook: [RELEASE.md](RELEASE.md)
