# Mnemox Backlog

This is the canonical implementation backlog. Keep it synchronized with code changes.

## Milestone 1: Operator Data Model

- [x] First-class assets for hosts, domains, URLs, users, cloud resources, repos, and generic targets.
- [x] Finding, evidence, and credential records can link to assets through typed links.
- [x] Evidence, notes, credentials, assets, and findings keep typed payload helpers in Go.
- [x] Asset detail view exposes linked findings, evidence, notes, and redacted credentials.
- [x] Notes can link to assets through typed links.
- [x] CLI note, evidence, and credential workflows create typed asset links.
- [x] Asset merge/deduplication workflows.

## Milestone 2: Finding Workspace

- [x] Web finding list and editor.
- [x] CVSS v4.0 Base calculator.
- [x] Finding notes, evidence upload, asset links, and packet preview.
- [x] CLI finding add/link/unlink commands can manage affected asset relationships.
- [x] Web asset module for adding and browsing assets.
- [x] Evidence module metadata edit plus asset link/unlink.
- [x] Credential module metadata edit plus asset link/unlink.
- [x] Loading/error states for primary web modules.
- [x] Notes module detail/edit workflow.
- [x] Bulk edit affected assets from imported scan data.
- [x] Drag-and-drop evidence upload.
- [x] Inline Markdown preview for long-form finding fields.

## Milestone 3: Evidence And Imports

- [x] Nmap XML importer.
- [x] nuclei JSON/JSONL importer.
- [x] Screenshot folder importer.
- [x] Image evidence preview in web UI.
- [x] Explicit decrypted blob export.
- [x] Burp issue import.
- [x] Nessus import.
- [x] BloodHound path import.
- [x] OCR extraction for screenshots.

## Milestone 4: Search, Recall, And Paths

- [x] Ranked local search with phrase, weighted-field, and fuzzy token scoring.
- [x] Credential secrets excluded from search material.
- [x] Search filters by kind and linked asset.
- [x] Packet filtering by linked asset.
- [x] Search filters by tag and finding status.
- [x] Attack Paths linked-chain view.
- [x] Attack Paths workspace with risk hubs, visual map, chain packet, and completeness checks.
- [x] Evidence citation bundles for AI prompts.
- [x] Local embedding index with encrypted cache.

## Milestone 5: Release

- [x] GitHub Actions CI for Go and web checks.
- [x] GoReleaser config for cross-platform binaries.
- [x] Playwright smoke tests for the embedded web workflow.
- [x] CI jobs for Playwright E2E, `govulncheck`, `gosec`, and GoReleaser snapshot validation.
- [x] Signed checksum artifacts for tagged releases through GoReleaser and cosign.
- [x] GitHub Releases binary-only install docs.
- [x] Release runbook and release notes template.
- [x] Native Linux, macOS, and Windows CI smoke checks for Go tests and CLI temp-vault workflow.
- [x] Sample engagement workflow doc covering web-first and CLI automation paths.
- [ ] Optional Homebrew tap after demand validates the maintenance cost.
- [ ] Documentation site.

## Milestone 6: Operational Safety

- [x] Interactive no-echo passphrase remains the default CLI path.
- [x] `MNEMOX_PASSPHRASE` requires `MNEMOX_ALLOW_INSECURE_PASSPHRASE_ENV=1`.
- [x] `--passphrase-stdin` and `--passphrase-file` for non-interactive workflows.
- [x] Web idle auto-lock with `mnemox serve --lock-after`, default `30m`.
- [x] HTTP Basic Auth required when `--allow-remote` is used.
- [x] Full encrypted backup create/restore commands.
- [x] Module path is `github.com/pridhvi/mnemox`.

## Milestone 7: Vault v2 Query Model

- [x] Explicit `vault migrate-v2` command with automatic encrypted backup.
- [x] HKDF-derived payload, blob, metadata, and blind-index subkeys.
- [x] Encrypted v2 query field rows.
- [x] HMAC blind-index token table for kind/status/tag/asset/title/search candidate lookup.
- [x] Credential secrets excluded from v2 indexes.
- [x] Large-vault benchmark comparing current full-scan search and v2 candidate lookup.
- [x] Wire v2 candidate lookup into the default keyword search path after benchmark review.
