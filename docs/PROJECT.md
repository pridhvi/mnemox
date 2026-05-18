# Mnemox Project Canon

## Product Definition

Mnemox is a local-first engagement memory system for penetration tests. It keeps findings, assets, evidence, notes, credentials, CVSS v4.0 scoring context, and report-ready Markdown packets in an encrypted local vault.

The primary workflow is the local web UI started with `mnemox serve`. The CLI and console remain supported for fast operator workflows and automation.

## Stack

- Backend: Go standard HTTP server.
- Vault: local encrypted records and blobs under `.mnemox/`.
- Frontend: React and TypeScript built as a static SPA.
- Distribution: compiled frontend embedded into the Go binary.
- Search: local ranked keyword/fuzzy search plus optional local semantic search with an encrypted vault cache.

## Security Model

- No cloud service, remote sync, telemetry, or external AI/API calls.
- Server binds to `127.0.0.1` by default.
- Vault unlock requires a passphrase or `MNEMOX_PASSPHRASE`.
- The browser never stores the passphrase.
- The server keeps an in-memory unlocked vault session until lock/logout.
- Credential secrets are excluded from list, search, asset context, attack path, packet, and preview responses.
- Credential secret reveal is an explicit record-specific action.

## Current Module Surface

### Findings

- List, create, and edit findings.
- Link/unlink affected assets.
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

- Search findings, notes, evidence metadata, asset metadata, and credential metadata.
- Credential secrets are excluded.
- Filters exist for kind, linked asset, tag, and finding status.
- Optional semantic mode uses deterministic local embeddings stored only in the encrypted vault metadata cache.
- Evidence citation bundles can render prompt-ready, cited Markdown for a finding and optional asset scope.

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

## Near-Term Roadmap Order

1. Release polish: signed artifacts, Homebrew tap, docs site.
