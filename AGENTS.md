# Codex Instructions For Mnemox

## Canonical Docs Are Required

Before planning, editing, reviewing, or committing changes in this repository, read these files:

1. `README.md`
2. `docs/PROJECT.md`
3. `docs/BACKLOG.md`

Treat those files as the source of truth for product scope, current status, security defaults, and roadmap order. If implementation and docs disagree, update the docs in the same commit or call out the mismatch before proceeding.

## Product Constraints

- Mnemox is local-first and offline by default.
- The product stack is Go backend plus React/TypeScript frontend embedded into one Go binary.
- Keep secrets local. Do not add cloud sync, telemetry, or external AI/API calls unless a future user explicitly changes the product direction.
- Credential secrets must not appear in list, search, asset context, attack path, packet, or preview responses. Reveal/copy must remain an explicit action.
- `mnemox serve` must bind to `127.0.0.1` by default.
- Browser unlock must never persist the vault passphrase in local storage.

## Engineering Workflow

- Prefer existing packages and patterns before adding dependencies.
- Keep CLI/console behavior working when web features are added.
- Rebuild with `make build` before committing frontend or backend changes so `internal/web/static` and `bin/mnemox` stay current.
- Run these checks before committing when relevant:
  - `go test ./...`
  - `npm test` from `web/`
  - `make build`
- For rendered web changes, run a browser smoke test and capture the flow tested in the final response.

## Documentation Workflow

- Update `docs/BACKLOG.md` whenever a roadmap item changes state.
- Update `docs/PROJECT.md` when the architecture, security model, or module surface changes.
- Keep README focused on install, run, commands, and high-level behavior.
