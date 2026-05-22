# Mnemox vX.Y.Z

## Highlights

- Local-first encrypted engagement memory with embedded web UI.
- GitHub Release binary archives for macOS/Linux `amd64` and `arm64`.
- Windows `amd64` and `arm64` preview archives.

## Install

1. Download the archive for your OS and CPU from this release.
2. Verify the archive against `checksums.txt`.
3. Extract `mnemox` or `mnemox.exe` and place it on your `PATH`.

Go users can also run:

```bash
go install github.com/pridhvi/mnemox/cmd/mnemox@vX.Y.Z
```

## Security Notes

- Vault payloads and blobs are encrypted locally.
- CLI passphrases default to an interactive no-echo prompt.
- `MNEMOX_PASSPHRASE` requires `MNEMOX_ALLOW_INSECURE_PASSPHRASE_ENV=1` and is intended only for CI/batch use.
- Remote web access requires `--allow-remote` plus HTTP Basic Auth.
- Web sessions auto-lock after the configured idle timeout.

## Backup And Migration

- Use `mnemox backup create <file.mnemoxbak>` before major engagement changes.
- `mnemox vault migrate-v2` creates an encrypted migration backup before adding v2 query indexes.
- Existing v1 vaults remain readable without migration.

## Known Limitations

- Windows binaries are preview until Windows runtime usage has more mileage.
- OCR requires an external `tesseract` installation on `PATH`; it is not bundled.
- Homebrew is not published for this release.

