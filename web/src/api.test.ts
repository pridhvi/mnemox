import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from './api';

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
});
