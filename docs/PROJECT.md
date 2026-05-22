# Mnemox Project Canon

## Product Definition

Mnemox is a local-first engagement memory system for penetration tests. It keeps findings, assets, evidence, notes, credentials, CVSS v4.0 scoring context, and report-ready Markdown packets in an encrypted local vault.

The primary workflow is the local web UI started with `mnemox serve`. The CLI and console remain supported for fast operator workflows and automation.

## Stack

- Backend: Go standard HTTP server.
- Vault: local encrypted records and blobs under `.mnemox/`.
- Frontend: React and TypeScript built as a static SPA.
- Distribution: compiled frontend embedded into GoReleaser-built GitHub Release binaries.
- Search: local ranked keyword/fuzzy search plus deterministic local feature-hashing semantic search with an encrypted vault cache.

## Security Model

- No cloud service, remote sync, telemetry, or external AI/API calls.
- Server binds to `127.0.0.1` by default.
- Vault unlock requires a passphrase. CLI passphrases default to an interactive no-echo prompt, with `--passphrase-file` and `--passphrase-stdin` for non-interactive automation.
- `MNEMOX_PASSPHRASE` is an insecure CI/batch override and is ignored unless `MNEMOX_ALLOW_INSECURE_PASSPHRASE_ENV=1` is also set.
- The browser never stores the passphrase.
- The server keeps an in-memory unlocked vault session until lock/logout or idle timeout. `mnemox serve --lock-after` defaults to `30m`; `0` disables.
- The unlocked vault is shared server process state, not per-browser state. Any lock/logout or idle timeout closes it for all connected browsers. Server restart always drops the unlocked vault and generates a new API launch token.
- Non-local web binding requires `--allow-remote` and HTTP Basic Auth. The API launch token remains required for `/api/*` except `/api/status`.
- The API launch token is a per-process random token returned by same-origin `GET /api/status`, kept in SPA memory, and sent as `X-Mnemox-Api-Token`. It is a request-boundary/CSRF guard, not an authentication substitute.
- Basic Auth is stateless at the HTTP layer. When configured with `--basic-auth-password-file`, the password file is checked per request so file rotation invalidates the old Basic Auth password immediately.
- Credential secrets are excluded from list, search, asset context, attack path, packet, and preview responses.
- Credential secret reveal is an explicit record-specific action.

## Current Module Surface

### Findings

- List, create, and edit findings.
- Link/unlink affected assets.
- Bulk edit affected assets from imported scan data and optionally sync affected scope from selected assets.
- CVSS v4.0 Base calculator with live vector and score.
- Add notes tied to a finding.
- Upload evidence tied to a finding, including drag-and-drop evidence attach.
- Inline Markdown preview for long-form finding fields.
- Render copy-ready Markdown Finding Packets.

### Assets

- List and create assets.
- View linked findings, evidence, notes, and redacted credentials.
- Use asset filters in search and packet workflows.
- Detect likely duplicate assets and merge them while preserving links, tags, notes, and aliases.

### Evidence

- List evidence.
- Preview image evidence.
- Edit evidence metadata.
- Link/unlink evidence to assets.
- Export decrypted evidence blobs through explicit user action.
- Manually extract OCR text from image evidence with optional local Tesseract, storing output as encrypted evidence metadata.

### Credentials

- List credentials without secrets.
- Create and edit credential metadata.
- Link/unlink credentials to assets.
- Reveal secrets through explicit user action only.

### Notes

- Notes can be attached to findings.
- Standalone Notes module supports detail editing.
- Notes can link/unlink assets.

### Search

- User-facing keyword search ranks findings, notes, evidence metadata, asset metadata, and credential metadata in process.
- On v1 vaults, keyword search decrypts matching surfaces at runtime. On v2-migrated vaults, keyword search first uses SQLite blind-index candidate lookup, then decrypts and ranks only candidate records.
- Search includes manually extracted OCR text from screenshot evidence.
- Credential secrets are excluded.
- Filters exist for kind, linked asset, tag, and finding status.
- Optional semantic mode uses deterministic local feature hashing stored only in the encrypted vault metadata cache; it does not download or run a remote embedding model.
- Evidence citation bundles can render prompt-ready, cited Markdown for a finding and optional asset scope.

### Vault v2 Query Direction

- `vault migrate-v2` is an explicit one-way migration command that creates an encrypted backup before adding v2 query structures.
- v2 keeps the pure-Go SQLite distribution and current local-first/no-cloud model.
- The migration derives separate HKDF subkeys from the Argon2id root key for payload, blob, metadata, and blind-index use.
- Full record payloads remain encrypted. Queryable field rows are encrypted in SQLite, and candidate lookup uses HMAC blind-index tokens for kind, status, tag, asset, title, and search terms.
- Credential secrets must never enter semantic caches, encrypted query fields, or blind-index token tables.
- v2 candidate lookup is wired into default keyword search for migrated vaults, including kind, tag, status, and linked-asset filters. Semantic search still uses the encrypted deterministic feature-hash cache.

### Attack Paths

- Relationship data exists through asset links.
- The web UI shows risk hubs, completeness checks, a selected-asset visual map, chain builder controls, and copy-ready attack path Markdown.
- Credential context stays redacted in graph, inspector, and packet output.

### Imports

- Nmap XML import.
- nuclei JSON/JSONL import.
- Burp Suite XML issue import.
- Nessus `.nessus` XML import.
- BloodHound JSON graph/path import as assets and relationship notes.
- Screenshot folder import.
- OCR extraction is manual after upload/import and never calls external services.

## Release Posture

- First release channel is GitHub Releases only, with signed checksum artifacts.
- macOS and Linux are supported for `amd64` and `arm64`.
- Windows `amd64` and `arm64` binaries are published as preview artifacts until Windows runtime usage has more mileage.
- Homebrew is deferred until there is user demand for a maintained tap.
- Optional OCR requires an external `tesseract` binary on `PATH`; Mnemox does not bundle it.

## Near-Term Roadmap Order

1. Exercise the new operational safety surface in real engagement workflows: passphrase files/stdin, remote Basic Auth, idle auto-lock, and encrypted backup/restore.
2. Stabilize v2 query migration with large-vault benchmarks and migrated-vault search usage.
3. Release polish: GitHub binary release notes, docs site, and optional Homebrew tap only after demand.
