import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, sessionLockedEvent } from './api';

describe('api search', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('sends semantic mode only when requested', async () => {
    const fetchMock = vi.fn(async (path: string) => ({
      ok: true,
      json: async () => ({ items: [], path }),
    })) as unknown as typeof fetch;
    vi.stubGlobal('fetch', fetchMock);

    await api.search('login permission bypass', { kind: 'finding', mode: 'semantic' });

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/search?q=login+permission+bypass&kind=finding&mode=semantic',
      expect.any(Object),
    );
  });

  it('sends tag and status filters', async () => {
    const fetchMock = vi.fn(async (path: string) => ({
      ok: true,
      json: async () => ({ items: [], path }),
    })) as unknown as typeof fetch;
    vi.stubGlobal('fetch', fetchMock);

    await api.search('jenkins', { tag: 'prod', status: 'confirmed' });

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/search?q=jenkins&tag=prod&status=confirmed',
      expect.any(Object),
    );
  });
});

describe('api finding assets', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('replaces affected assets with sync scope option', async () => {
    const fetchMock = vi.fn(async (path: string) => ({
      ok: true,
      json: async () => ({ id: 'finding-1', path }),
    })) as unknown as typeof fetch;
    vi.stubGlobal('fetch', fetchMock);

    await api.setFindingAssets('finding-1', ['asset-1', 'asset-2'], true);

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/findings/finding-1/assets',
      expect.objectContaining({
        method: 'PUT',
        body: JSON.stringify({ asset_ids: ['asset-1', 'asset-2'], sync_scope: true }),
      }),
    );
  });
});

describe('api evidence OCR', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('checks OCR status and extracts OCR for evidence', async () => {
    const fetchMock = vi.fn(async (path: string) => ({
      ok: true,
      json: async () => ({ id: 'evidence-1', path }),
    })) as unknown as typeof fetch;
    vi.stubGlobal('fetch', fetchMock);

    await api.ocrStatus();
    await api.extractEvidenceOCR('evidence-1');

    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/ocr/status', expect.any(Object));
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/evidence/evidence-1/ocr', expect.objectContaining({ method: 'POST' }));
  });
});

describe('api session lock handling', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('dispatches a session event when protected APIs return 401', async () => {
    const fetchMock = vi.fn(async () => ({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
      json: async () => ({ error: 'vault is locked' }),
    })) as unknown as typeof fetch;
    vi.stubGlobal('fetch', fetchMock);
    const listener = vi.fn();
    window.addEventListener(sessionLockedEvent, listener);

    await expect(api.listFindings()).rejects.toThrow('vault is locked');

    expect(listener).toHaveBeenCalledOnce();
    window.removeEventListener(sessionLockedEvent, listener);
  });
});
