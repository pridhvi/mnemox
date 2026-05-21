import type { AssetDetail, AssetDuplicateGroup, AttackPath, CvssState, FindingPayload, FindingRecord, OCRStatus, RecordEnvelope, SearchHit } from './types';

export type ImportResult = { assets: number; findings: number; evidence: number; notes?: number };
export type CvssScorePayload = { vector?: string; metrics?: Record<string, string>; notes?: string };

let apiToken = '';
export const sessionLockedEvent = 'mnemox:session-locked';

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (!(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (apiToken && path !== '/api/status') {
    headers.set('X-Mnemox-Api-Token', apiToken);
  }
  const response = await fetch(path, {
    ...options,
    headers,
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ error: response.statusText }));
    if (response.status === 401 && path !== '/api/status' && path !== '/api/unlock' && path !== '/api/init') {
      apiToken = '';
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent(sessionLockedEvent, { detail: { path } }));
      }
    }
    throw new Error(body.error || response.statusText);
  }
  const payload = await response.json();
  if (path === '/api/status' && typeof payload.api_token === 'string') {
    apiToken = payload.api_token;
  }
  return payload as T;
}

export const api = {
  status: () => request<{ unlocked: boolean; vault_path: string; api_token: string }>('/api/status'),
  init: (name: string, passphrase: string) =>
    request<{ unlocked: boolean }>('/api/init', { method: 'POST', body: JSON.stringify({ name, passphrase }) }),
  unlock: (passphrase: string) =>
    request<{ unlocked: boolean }>('/api/unlock', { method: 'POST', body: JSON.stringify({ passphrase }) }),
  lock: () => request<{ unlocked: boolean }>('/api/lock', { method: 'POST' }),
  listFindings: (assetId = '') =>
    request<{ items: FindingRecord[] }>(`/api/findings${assetId ? `?asset_id=${encodeURIComponent(assetId)}` : ''}`),
  createFinding: (payload: FindingPayload) =>
    request<FindingRecord>('/api/findings', { method: 'POST', body: JSON.stringify(payload) }),
  getFinding: (id: string) => request<FindingRecord>(`/api/findings/${id}`),
  updateFinding: (id: string, payload: FindingPayload) =>
    request<FindingRecord>(`/api/findings/${id}`, { method: 'PUT', body: JSON.stringify(payload) }),
  linkFindingAsset: (id: string, assetId: string) =>
    request<{ items: RecordEnvelope[] }>(`/api/findings/${id}/assets`, { method: 'POST', body: JSON.stringify({ asset_id: assetId }) }),
  setFindingAssets: (id: string, assetIds: string[], syncScope: boolean) =>
    request<FindingRecord>(`/api/findings/${id}/assets`, { method: 'PUT', body: JSON.stringify({ asset_ids: assetIds, sync_scope: syncScope }) }),
  unlinkFindingAsset: (id: string, assetId: string) =>
    request<{ items: RecordEnvelope[] }>(`/api/findings/${id}/assets/${assetId}`, { method: 'DELETE' }),
  addNote: (id: string, payload: { text: string; asset: string; tags: string[] }) =>
    request<RecordEnvelope>(`/api/findings/${id}/notes`, { method: 'POST', body: JSON.stringify(payload) }),
  uploadEvidence: (id: string, form: FormData) =>
    request<RecordEnvelope>(`/api/findings/${id}/evidence`, { method: 'POST', body: form }),
  scoreCvss: (id: string, payload: CvssScorePayload) =>
    request<CvssState>(`/api/findings/${id}/cvss`, { method: 'POST', body: JSON.stringify(payload) }),
  previewCvss: (payload: CvssScorePayload) =>
    request<CvssState>('/api/cvss/preview', { method: 'POST', body: JSON.stringify(payload) }),
  packet: (id: string) => request<{ markdown: string }>(`/api/findings/${id}/packet`),
  citationBundle: (id: string, assetId = '') =>
    request<{ markdown: string }>(`/api/findings/${id}/citation-bundle${assetId ? `?asset_id=${encodeURIComponent(assetId)}` : ''}`),
  assets: () => request<{ items: RecordEnvelope[] }>('/api/assets'),
  asset: (id: string) => request<AssetDetail>(`/api/assets/${id}`),
  assetDuplicates: () => request<{ items: AssetDuplicateGroup[] }>('/api/assets/duplicates'),
  mergeAsset: (id: string, duplicateId: string) =>
    request<AssetDetail>(`/api/assets/${id}/merge`, { method: 'POST', body: JSON.stringify({ duplicate_id: duplicateId }) }),
  createAsset: (payload: { name: string; type: string; value: string; notes: string; tags: string[] }) =>
    request<RecordEnvelope>('/api/assets', { method: 'POST', body: JSON.stringify(payload) }),
  importNmap: (form: FormData) => request<ImportResult>('/api/import/nmap', { method: 'POST', body: form }),
  importNuclei: (form: FormData) => request<ImportResult>('/api/import/nuclei', { method: 'POST', body: form }),
  importBurp: (form: FormData) => request<ImportResult>('/api/import/burp', { method: 'POST', body: form }),
  importNessus: (form: FormData) => request<ImportResult>('/api/import/nessus', { method: 'POST', body: form }),
  importBloodHound: (form: FormData) => request<ImportResult>('/api/import/bloodhound', { method: 'POST', body: form }),
  importScreenshots: (path: string) =>
    request<ImportResult>('/api/import/screenshots', { method: 'POST', body: JSON.stringify({ path }) }),
  ocrStatus: () => request<OCRStatus>('/api/ocr/status'),
  evidence: () => request<{ items: RecordEnvelope[] }>('/api/evidence'),
  updateEvidence: (id: string, payload: { kind: string; caption: string; original_path: string; tags: string[] }) =>
    request<RecordEnvelope>(`/api/evidence/${id}`, { method: 'PUT', body: JSON.stringify(payload) }),
  extractEvidenceOCR: (id: string) =>
    request<RecordEnvelope>(`/api/evidence/${id}/ocr`, { method: 'POST' }),
  linkEvidenceAsset: (id: string, assetId: string) =>
    request<{ items: RecordEnvelope[] }>(`/api/evidence/${id}/assets`, { method: 'POST', body: JSON.stringify({ asset_id: assetId }) }),
  unlinkEvidenceAsset: (id: string, assetId: string) =>
    request<{ items: RecordEnvelope[] }>(`/api/evidence/${id}/assets/${assetId}`, { method: 'DELETE' }),
  notes: () => request<{ items: RecordEnvelope[] }>('/api/notes'),
  updateNote: (id: string, payload: { text: string; asset: string; tags: string[] }) =>
    request<RecordEnvelope>(`/api/notes/${id}`, { method: 'PUT', body: JSON.stringify(payload) }),
  linkNoteAsset: (id: string, assetId: string) =>
    request<{ items: RecordEnvelope[] }>(`/api/notes/${id}/assets`, { method: 'POST', body: JSON.stringify({ asset_id: assetId }) }),
  unlinkNoteAsset: (id: string, assetId: string) =>
    request<{ items: RecordEnvelope[] }>(`/api/notes/${id}/assets/${assetId}`, { method: 'DELETE' }),
  credentials: () => request<{ items: RecordEnvelope[] }>('/api/credentials'),
  createCredential: (payload: { name: string; username: string; secret: string; scope: string; tags: string[] }) =>
    request<RecordEnvelope>('/api/credentials', { method: 'POST', body: JSON.stringify(payload) }),
  updateCredential: (id: string, payload: { name: string; username: string; secret?: string; scope: string; tags: string[] }) =>
    request<RecordEnvelope>(`/api/credentials/${id}`, { method: 'PUT', body: JSON.stringify(payload) }),
  revealCredential: (id: string) => request<{ secret: string }>(`/api/credentials/${id}/secret`),
  linkCredentialAsset: (id: string, assetId: string) =>
    request<{ items: RecordEnvelope[] }>(`/api/credentials/${id}/assets`, { method: 'POST', body: JSON.stringify({ asset_id: assetId }) }),
  unlinkCredentialAsset: (id: string, assetId: string) =>
    request<{ items: RecordEnvelope[] }>(`/api/credentials/${id}/assets/${assetId}`, { method: 'DELETE' }),
  search: (query: string, filters: { kind?: string; assetId?: string; mode?: string; tag?: string; status?: string } = {}) => {
    const params = new URLSearchParams();
    if (query) params.set('q', query);
    if (filters.kind && filters.kind !== 'all') params.set('kind', filters.kind);
    if (filters.assetId) params.set('asset_id', filters.assetId);
    if (filters.mode && filters.mode !== 'keyword') params.set('mode', filters.mode);
    if (filters.tag) params.set('tag', filters.tag);
    if (filters.status && filters.status !== 'all') params.set('status', filters.status);
    return request<{ items: SearchHit[] }>(`/api/search?${params.toString()}`);
  },
  attackPaths: () => request<{ items: AttackPath[] }>('/api/attack-paths'),
  settings: () => request<{ vault_path: string; server: string; unlocked: boolean }>('/api/settings'),
};
