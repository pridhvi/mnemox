# Sample Engagement Workflow

This workflow shows the intended web-first usage pattern and the equivalent CLI
automation path. It keeps all data local and assumes the vault passphrase is
entered interactively or read from a local passphrase file.

## Web-First Flow

1. Build and start Mnemox:

   ```bash
   make build
   ./bin/mnemox serve
   ```

2. Open the printed local URL, create or unlock the vault, and add the core
   engagement assets first. Example assets:

   - `ci.acme.local` as a host asset.
   - `https://ci.acme.local` as a URL asset.
   - `svc_jenkins` as a user or service account asset when it is report-relevant.

3. Create a finding from the Findings workspace. Use `Affected Scope` for
   report-facing text and link the asset records in the Affected Assets control.
   The typed asset links drive asset filters, Attack Paths, and cited packets.

4. Add notes and evidence from the finding detail view. Evidence added to a
   finding inherits the finding's affected asset context, and notes can be
   linked to assets when the note is asset-specific.

5. Score the finding with the CVSS calculator. The score, vector, and severity
   update while metrics are changed; a zero-score vector is displayed as
   Informational in report-facing views.

6. Use Packets to render the Finding Packet or Evidence Citation Bundle. Filter
   by asset when drafting asset-specific report text.

7. Use Attack Paths to review linked chains around assets, evidence, notes, and
   credential context. Credential secrets remain redacted unless explicitly
   revealed from the Credentials workflow.

8. Create a backup before major imports, cleanup, or migration work:

   ```bash
   ./bin/mnemox --passphrase-file ./vault-passphrase backup create acme-external.mnemoxbak
   ```

## CLI Automation Flow

Use `--passphrase-file` or `--passphrase-stdin` for non-interactive runs. Avoid
environment passphrases outside controlled CI/batch contexts.

```bash
vault=".mnemox"
passfile="./vault-passphrase"

./bin/mnemox --vault "$vault" --passphrase-file "$passfile" init --name "ACME External"

./bin/mnemox --vault "$vault" --passphrase-file "$passfile" \
  asset add ci.acme.local --type host --value 10.0.0.10

./bin/mnemox --vault "$vault" --passphrase-file "$passfile" \
  finding add "Jenkins anonymous read" \
  --severity Medium \
  --summary "Jenkins allowed unauthenticated read access." \
  --affected-scope ci.acme.local \
  --asset ci.acme.local

./bin/mnemox --vault "$vault" --passphrase-file "$passfile" \
  note "Build history was visible." \
  --finding "Jenkins anonymous read" \
  --asset ci.acme.local

./bin/mnemox --vault "$vault" --passphrase-file "$passfile" \
  evidence add ./jenkins-dashboard.txt \
  --finding "Jenkins anonymous read" \
  --caption "Dashboard visible without authentication"

./bin/mnemox --vault "$vault" --passphrase-file "$passfile" \
  cvss score "Jenkins anonymous read" \
  --av N --ac L --at N --pr N --ui N \
  --vc L --vi N --va N --sc N --si N --sa N \
  --notes "Anonymous read access exposed build history."

./bin/mnemox --vault "$vault" --passphrase-file "$passfile" \
  packet bundle "Jenkins anonymous read" --asset ci.acme.local \
  --output jenkins-anonymous-read-citations.md

./bin/mnemox --vault "$vault" --passphrase-file "$passfile" \
  backup create acme-external.mnemoxbak
```

Credential creation prompts for the secret when `--secret` is omitted. Run it
as an interactive step, or only pass `--secret` in controlled automation where
command-line exposure is understood:

```bash
./bin/mnemox --vault "$vault" --passphrase-file "$passfile" \
  cred add svc_jenkins --username svc_jenkins --asset ci.acme.local
```

## Import-Heavy Flow

For scan-heavy engagements, import tool output before manual triage:

```bash
./bin/mnemox --vault "$vault" --passphrase-file "$passfile" import nmap ./nmap.xml
./bin/mnemox --vault "$vault" --passphrase-file "$passfile" import nuclei ./nuclei.jsonl
./bin/mnemox --vault "$vault" --passphrase-file "$passfile" import nessus ./scan.nessus
./bin/mnemox --vault "$vault" --passphrase-file "$passfile" import burp ./burp.xml
./bin/mnemox --vault "$vault" --passphrase-file "$passfile" import bloodhound ./path.json
```

After import, use the web UI to merge duplicate assets, bulk edit affected
assets on findings, add operator notes, and build final packets.
