# Mnemox Backlog

This is the canonical implementation backlog. Keep it synchronized with code changes.

## Milestone 1: Operator Data Model

- [x] First-class assets for hosts, domains, URLs, users, cloud resources, repos, and generic targets.
- [x] Finding, evidence, and credential records can link to assets through typed links.
- [x] Evidence, notes, credentials, assets, and findings keep typed payload helpers in Go.
- [x] Asset detail view exposes linked findings, evidence, notes, and redacted credentials.
- [x] Notes can link to assets through typed links.
- [x] Asset merge/deduplication workflows.

## Milestone 2: Finding Workspace

- [x] Web finding list and editor.
- [x] CVSS v4.0 Base calculator.
- [x] Finding notes, evidence upload, asset links, and packet preview.
- [x] Web asset module for adding and browsing assets.
- [x] Evidence module metadata edit plus asset link/unlink.
- [x] Credential module metadata edit plus asset link/unlink.
- [x] Loading/error states for primary web modules.
- [x] Notes module detail/edit workflow.
- [ ] Bulk edit affected assets from imported scan data.
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
- [ ] OCR extraction for screenshots.

## Milestone 4: Search, Recall, And Paths

- [x] Ranked local search with phrase, weighted-field, and fuzzy token scoring.
- [x] Credential secrets excluded from search material.
- [x] Search filters by kind and linked asset.
- [x] Packet filtering by linked asset.
- [ ] Search filters by tag and finding status.
- [x] Attack Paths linked-chain view.
- [ ] Attack Paths graph visualization.
- [ ] Evidence citation bundles for AI prompts.
- [ ] Local embedding index with encrypted cache.

## Milestone 5: Release

- [x] GitHub Actions CI for Go and web checks.
- [x] GoReleaser config for cross-platform binaries.
- [ ] Signed release artifacts.
- [ ] Homebrew tap.
- [ ] Documentation site.
