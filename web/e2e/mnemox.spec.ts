import { expect, test, type Page } from '@playwright/test';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const passphrase = 'test-passphrase';

test('embedded primary workflow smoke', async ({ page }) => {
  const app = await startMnemox();
  try {
    await page.goto(app.url);
    await expect(page.getByText('Mnemox').first()).toBeVisible();

    await page.getByRole('button', { name: 'Initialize' }).click();
    await page.getByPlaceholder('Engagement name').fill('E2E Engagement');
    await page.getByPlaceholder('Vault passphrase').fill(passphrase);
    await page.getByRole('button', { name: /Create vault/i }).click();
    await expect(page.getByRole('heading', { name: 'Findings' })).toBeVisible();

    await page.locator('button[title="New finding"]').click();
    await page.getByPlaceholder('Finding title').fill('Jenkins anonymous read');
    await page.getByRole('button', { name: 'Create' }).click();
    await expect(page.locator('.packet-preview').filter({ hasText: 'Jenkins anonymous read' })).toBeVisible();

    const findings = await api<{ items: Array<{ id: string }> }>(page, '/api/findings');
    const findingID = findings.items[0].id;

    const asset = await api<{ id: string }>(page, '/api/assets', {
      method: 'POST',
      body: { name: 'ci.acme.local', type: 'host', value: '10.0.0.10', notes: '', tags: ['prod'] },
    });
    await api(page, `/api/findings/${findingID}/assets`, { method: 'POST', body: { asset_id: asset.id } });

    const cvss = await api<{ score: number; severity: string }>(page, `/api/findings/${findingID}/cvss`, {
      method: 'POST',
      body: {
        metrics: { AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N', VC: 'L', VI: 'N', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
        notes: 'Information disclosure only.',
      },
    });
    expect(cvss.score).toBeGreaterThan(0);
    expect(cvss.severity).toBeTruthy();

    const evidence = await uploadEvidence(page, findingID);
    const preview = await apiBlob(page, `/api/evidence/${evidence.id}/preview`);
    expect(preview.status).toBe(200);
    expect(preview.contentType).toContain('image/png');

    await api(page, `/api/findings/${findingID}/notes`, {
      method: 'POST',
      body: { text: 'Build history was visible', asset: 'ci.acme.local', tags: [] },
    });
    const credential = await api<{ id: string }>(page, '/api/credentials', {
      method: 'POST',
      body: { name: 'svc_backup', username: 'svc_backup', secret: 'super-secret-value', scope: 'ci.acme.local', tags: ['prod'] },
    });
    await api(page, `/api/credentials/${credential.id}/assets`, { method: 'POST', body: { asset_id: asset.id } });
    const credentialList = await api(page, '/api/credentials');
    expect(JSON.stringify(credentialList)).not.toContain('super-secret-value');
    const revealed = await api<{ secret: string }>(page, `/api/credentials/${credential.id}/secret`);
    expect(revealed.secret).toBe('super-secret-value');

    await page.getByRole('button', { name: 'Attack Paths' }).click();
    await expect(page.getByRole('heading', { name: 'Risk Hubs' })).toBeVisible();
    await expect(page.getByText('ci.acme.local').first()).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Attack Path Packet' })).toBeVisible();
    await expect(page.locator('.packet-preview').filter({ hasText: 'Jenkins anonymous read' })).toBeVisible();
  } finally {
    await app.stop();
  }
});

async function api<T = unknown>(page: Page, apiPath: string, options: { method?: string; body?: unknown } = {}): Promise<T> {
  return page.evaluate(async ({ apiPath, options }) => {
    const status = await fetch('/api/status').then((response) => response.json());
    const response = await fetch(apiPath, {
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Mnemox-Api-Token': status.api_token,
      },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || response.statusText);
    return body;
  }, { apiPath, options }) as Promise<T>;
}

async function apiBlob(page: Page, apiPath: string): Promise<{ status: number; contentType: string }> {
  return page.evaluate(async (apiPath) => {
    const status = await fetch('/api/status').then((response) => response.json());
    const response = await fetch(apiPath, { headers: { 'X-Mnemox-Api-Token': status.api_token } });
    await response.arrayBuffer();
    return { status: response.status, contentType: response.headers.get('content-type') || '' };
  }, apiPath);
}

async function uploadEvidence(page: Page, findingID: string): Promise<{ id: string }> {
  return page.evaluate(async (findingID) => {
    const png = Uint8Array.from(atob('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII='), (char) => char.charCodeAt(0));
    const form = new FormData();
    form.append('file', new Blob([png], { type: 'image/png' }), 'jenkins.png');
    form.append('caption', 'Dashboard visible without authentication');
    form.append('kind', 'screenshot');
    const status = await fetch('/api/status').then((response) => response.json());
    const response = await fetch(`/api/findings/${findingID}/evidence`, {
      method: 'POST',
      headers: { 'X-Mnemox-Api-Token': status.api_token },
      body: form,
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || response.statusText);
    return body;
  }, findingID);
}

async function startMnemox(): Promise<{ url: string; stop: () => Promise<void> }> {
  const repoRoot = path.resolve(process.cwd(), '..');
  const tempRoot = mkdtempSync(path.join(tmpdir(), 'mnemox-e2e-'));
  const vaultRoot = path.join(tempRoot, '.mnemox');
  const child = spawn('go', ['run', './cmd/mnemox', '--vault', vaultRoot, 'serve', '--port', '0', '--lock-after', '0'], {
    cwd: repoRoot,
    env: { ...process.env },
  });
  let exited = false;
  child.once('exit', () => {
    exited = true;
  });
  const url = await waitForServerURL(child);
  return {
    url,
    stop: async () => {
      if (!exited) {
        child.kill('SIGTERM');
        await new Promise<void>((resolve) => child.once('exit', () => resolve()));
      }
      rmSync(tempRoot, { recursive: true, force: true });
    },
  };
}

function waitForServerURL(child: ChildProcessWithoutNullStreams): Promise<string> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill('SIGTERM');
        reject(new Error('timed out waiting for Mnemox server'));
      }
    }, 30_000);
    const onData = (data: Buffer) => {
      const text = data.toString();
      const match = text.match(/Mnemox web UI:\s+(http:\/\/\S+)/);
      if (match && !settled) {
        settled = true;
        clearTimeout(timer);
        resolve(match[1]);
      }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.once('exit', (code) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(new Error(`Mnemox server exited before startup with code ${code}`));
      }
    });
  });
}
