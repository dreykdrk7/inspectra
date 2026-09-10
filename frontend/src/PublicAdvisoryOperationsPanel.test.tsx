import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import axe from 'axe-core';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { configureAuthContext } from './api';
import { PublicAdvisoryOperationsPanel } from './PublicAdvisoryOperationsPanel';

const operations = {
  contract_version: '2026-09-09.1',
  egress_enabled: true,
  offline_snapshot_active: false,
  providers: [
    { provider: 'osv', configured: true, cache_entries: 3, fresh_entries: 2, stale_entries: 1, invalid_entries: 0, cache_bytes: 1536, last_updated_at: '2026-09-09T10:00:00Z', truncated: false },
    { provider: 'github_advisories', configured: true, cache_entries: 0, fresh_entries: 0, stale_entries: 0, invalid_entries: 0, cache_bytes: 0, last_updated_at: null, truncated: false },
    { provider: 'nvd', configured: false, cache_entries: 1, fresh_entries: 0, stale_entries: 0, invalid_entries: 1, cache_bytes: 42, last_updated_at: null, truncated: true },
    { provider: 'cisa_kev', configured: true, cache_entries: 0, fresh_entries: 0, stale_entries: 0, invalid_entries: 0, cache_bytes: 0, last_updated_at: null, truncated: false },
  ],
} as const;

function response(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { 'content-type': 'application/json' } });
}

afterEach(() => {
  cleanup();
  configureAuthContext({ csrfRequired: false, csrfToken: null });
  vi.unstubAllGlobals();
});

describe('PublicAdvisoryOperationsPanel', () => {
  it('shows only aggregate provider health and cleans cache after explicit confirmation', async () => {
    configureAuthContext({ csrfRequired: true, csrfToken: 'csrf-value' });
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/cache/purge-expired') && init?.method === 'POST') {
        return Promise.resolve(response({ removed_entries: 2, operations: { ...operations, providers: operations.providers.map((item) => ({ ...item, cache_entries: 0, fresh_entries: 0, stale_entries: 0, invalid_entries: 0, cache_bytes: 0 })) } }));
      }
      return Promise.resolve(response(operations));
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<PublicAdvisoryOperationsPanel />);
    expect(await screen.findByRole('heading', { name: 'Provider and cache health' })).toBeInTheDocument();
    expect(screen.getByText('Egress enabled by operator')).toBeInTheDocument();
    expect(screen.getByRole('list', { name: 'Public advisory provider health' })).toHaveTextContent('Stale cache available');
    expect(screen.getByRole('list', { name: 'Public advisory provider health' })).toHaveTextContent('Attention required');
    expect(document.body).not.toHaveTextContent('private-package-canary');
    expect(document.body).not.toHaveTextContent('response-body-canary');

    fireEvent.click(screen.getByRole('button', { name: 'Review cache cleanup' }));
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Confirm cache cleanup' }));
    expect(await screen.findByText('2 expired or invalid cache entries removed.')).toBeInTheDocument();
    const cleanupCall = fetchMock.mock.calls.find(([, init]) => init?.method === 'POST');
    expect(String(cleanupCall?.[0])).toContain('/operations/public-advisories/cache/purge-expired');
    expect(new Headers(cleanupCall?.[1]?.headers).get('X-CSRF-Token')).toBe('csrf-value');
    expect(cleanupCall?.[1]?.body).toBeUndefined();
    expect((await axe.run(document.body, { rules: { 'color-contrast': { enabled: false } } })).violations).toEqual([]);
  });

  it('fails safely with an actionable retry state', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response({ detail: 'Administrator role required.' }, 403))
      .mockResolvedValueOnce(response({ ...operations, egress_enabled: false }));
    vi.stubGlobal('fetch', fetchMock);

    render(<PublicAdvisoryOperationsPanel />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Administrator access is required.');
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('Egress disabled')).toBeInTheDocument();
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
  });
});
