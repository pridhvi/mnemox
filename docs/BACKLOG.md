# Mnemox Backlog

## Milestone 1: Operator Data Model

- [x] First-class assets for hosts, domains, URLs, users, cloud resources, repos, and generic targets.
- [x] Finding records can link to assets through `affected_scope` names.
- [x] Evidence, notes, credentials, and findings keep typed payload helpers in Go.
- [ ] Add explicit typed link records for `asset -> finding`, `credential -> asset`, and `evidence -> asset`.
- [ ] Add asset merge/deduplication workflows.

## Milestone 2: Finding Workspace

- [x] Web finding list, editor, CVSS v4.0 calculator, notes, evidence, packet preview.
- [x] Web asset module for adding and browsing assets.
- [x] Loading/error states for primary web modules.
- [ ] Bulk edit affected assets from imported scan data.
- [ ] Drag-and-drop evidence upload.
- [ ] Inline Markdown preview for long-form finding fields.

## Milestone 3: Evidence And Imports

- [x] Nmap XML importer.
- [x] nuclei JSON/JSONL importer.
- [x] Screenshot folder importer.
- [ ] Burp issue import.
- [ ] Nessus import.
- [ ] BloodHound path import.
- [ ] OCR extraction for screenshots.

## Milestone 4: Search And Recall

- [x] Ranked local search with phrase, weighted-field, and fuzzy token scoring.
- [x] Credential secrets excluded from search material.
- [ ] Local embedding index with encrypted cache.
- [ ] Evidence citation bundles for AI prompts.
- [ ] Query filters by kind, tag, asset, and finding status.

## Milestone 5: Release

- [x] GitHub Actions CI for Go and web checks.
- [x] GoReleaser config for cross-platform binaries.
- [ ] Signed release artifacts.
- [ ] Homebrew tap.
- [ ] Documentation site.
