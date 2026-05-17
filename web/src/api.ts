import type { FindingPayload, FindingRecord, RecordEnvelope, SearchHit } from './types';

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...options,
    headers: {
      ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
      ...options.headers,
    },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(body.error || response.statusText);
  }
  return response.json() as Promise<T>;
}

export const api = {
  status: () => request<{ unlocked: boolean; vault_path: string }>('/api/status'),
  init: (name: string, passphrase: string) =>
    request<{ unlocked: boolean }>('/api/init', { method: 'POST', body: JSON.stringify({ name, passphrase }) }),
  unlock: (passphrase: string) =>
    request<{ unlocked: boolean }>('/api/unlock', { method: 'POST', body: JSON.stringify({ passphrase }) }),
  lock: () => request<{ unlocked: boolean }>('/api/lock', { method: 'POST' }),
  listFindings: () => request<{ items: FindingRecord[] }>('/api/findings'),
  createFinding: (payload: FindingPayload) =>
    request<FindingRecord>('/api/findings', { method: 'POST', body: JSON.stringify(payload) }),
  getFinding: (id: string) => request<FindingRecord>(`/api/findings/${id}`),
  updateFinding: (id: string, payload: FindingPayload) =>
    request<FindingRecord>(`/api/findings/${id}`, { method: 'PUT', body: JSON.stringify(payload) }),
  addNote: (id: string, payload: { text: string; asset: string; tags: string[] }) =>
    request<RecordEnvelope>(`/api/findings/${id}/notes`, { method: 'POST', body: JSON.stringify(payload) }),
  uploadEvidence: (id: string, form: FormData) =>
    request<RecordEnvelope>(`/api/findings/${id}/evidence`, { method: 'POST', body: form }),
  scoreCvss: (id: string, payload: { vector?: string; metrics?: Record<string, string>; notes: string }) =>
    request(`/api/findings/${id}/cvss`, { method: 'POST', body: JSON.stringify(payload) }),
  packet: (id: string) => request<{ markdown: string }>(`/api/findings/${id}/packet`),
  evidence: () => request<{ items: RecordEnvelope[] }>('/api/evidence'),
  notes: () => request<{ items: RecordEnvelope[] }>('/api/notes'),
  credentials: () => request<{ items: RecordEnvelope[] }>('/api/credentials'),
  createCredential: (payload: { name: string; username: string; secret: string; scope: string; tags: string[] }) =>
    request<RecordEnvelope>('/api/credentials', { method: 'POST', body: JSON.stringify(payload) }),
  revealCredential: (id: string) => request<{ secret: string }>(`/api/credentials/${id}/secret`),
  search: (query: string) => request<{ items: SearchHit[] }>(`/api/search?q=${encodeURIComponent(query)}`),
  settings: () => request<{ vault_path: string; server: string; unlocked: boolean }>('/api/settings'),
};
