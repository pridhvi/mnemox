# Mnemox

Mnemox is a Go-only, local-first memory console for pentest engagements. It
stores findings, notes, evidence, credentials, and CVSS v4.0 Base scores in an
encrypted local vault and renders copy-paste-ready Markdown Finding Packets.

## Install

```bash
go build -o bin/mnemox ./cmd/mnemox
```

## Console Workflow

Run Mnemox without arguments to enter the console:

```bash
export MNEMOX_PASSPHRASE='change-me'
./bin/mnemox
```

Example console session:

```text
mnemox > init --name "ACME External"
mnemox > finding add "Jenkins anonymous read" --severity Medium --summary "Jenkins allowed unauthenticated read access."
mnemox > note "Build history was visible" --finding "Jenkins anonymous read" --asset ci.acme.local
mnemox > evidence add ./jenkins.txt --finding "Jenkins anonymous read" --caption "Dashboard visible without authentication"
mnemox > cvss score "Jenkins anonymous read" --av N --ac L --at N --pr N --ui N --vc L --vi N --va N --sc N --si N --sa N
mnemox > packet build "Jenkins anonymous read"
```

The same commands work in batch mode:

```bash
./bin/mnemox finding add "Weak TLS" --summary "TLS 1.0 was enabled."
```

## Web UI

Build the embedded React UI and Go binary:

```bash
cd web
npm install
npm run build
cd ..
go build -o bin/mnemox ./cmd/mnemox
```

Start the local web app:

```bash
export MNEMOX_PASSPHRASE='change-me'
./bin/mnemox serve
```

The server binds to `127.0.0.1:8787` by default. Use `--port 0` to select a
free port. Non-local bind addresses require `--allow-remote`.

By default, Mnemox uses `.mnemox/` in the current directory. Set
`MNEMOX_VAULT=/path/to/.mnemox` or pass `--vault /path/to/.mnemox`.

## Commands

- `init`: create an encrypted local vault.
- `finding add`: create a finding.
- `asset add/list`: create and list assets.
- `note`: add an operator note.
- `evidence add`: encrypt and attach a file as evidence.
- `cred add`: add an encrypted credential record.
- `import nmap`: import Nmap XML hosts/services as assets.
- `import nuclei`: import nuclei JSONL findings and assets.
- `import screenshots`: import a folder of screenshots as evidence.
- `ask`: local evidence recall over decrypted vault records.
- `cvss score`: calculate and store a CVSS v4.0 Base score.
- `packet build`: render a cited Markdown Finding Packet.
- `export-blob`: decrypt an evidence blob to a file.
- `serve`: start the local web UI.
- `use <vault-path>`: console-only command to switch vault path.

## Security Model

Mnemox derives a vault key from `MNEMOX_PASSPHRASE` using Argon2id. Record
payloads and evidence blobs are encrypted with XChaCha20-Poly1305. Keep the
passphrase safe; lost passphrases cannot be recovered.

This MVP performs local keyword-style recall over decrypted records at runtime.
It does not send data to an external AI service. Search uses local ranked
matching over decrypted records at runtime, with credential secrets excluded
from searchable material.

## Backlog And Releases

- Project canon: [docs/PROJECT.md](docs/PROJECT.md)
- Backlog: [docs/BACKLOG.md](docs/BACKLOG.md)
- Codex instructions: [AGENTS.md](AGENTS.md)
- CI: `.github/workflows/ci.yml`
- Release config: `.goreleaser.yaml`
