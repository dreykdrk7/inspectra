import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import axe from 'axe-core';

import { PublicIdentityAttestationPanel } from './PublicIdentityAttestationPanel';
import type { PublicIdentityAttestation } from './types';

const pending = {
  contract_version: '2026-09-09.1',
  id: 'a'.repeat(32),
  ecosystem: 'pypi',
  package_name: 'requests-library',
  status: 'pending',
  revision: 1,
  requested_ttl_days: 30,
  proposed_at: '2026-09-09T10:00:00Z',
  approved_at: null,
  expires_at: null,
  revoked_at: null,
} as const;

function response(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { 'content-type': 'application/json' } });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('PublicIdentityAttestationPanel', () => {
  it('lets a maintainer propose an exact identity but never approve it', async () => {
    let items: unknown[] = [];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === 'POST') {
        items = [pending];
        return Promise.resolve(response(pending, 201));
      }
      return Promise.resolve(response(items));
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<PublicIdentityAttestationPanel role="maintainer" />);
    expect(await screen.findByText(/No package identity is approved/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Ecosystem'), { target: { value: 'pypi' } });
    fireEvent.change(screen.getByLabelText('Exact public package name'), { target: { value: 'Requests_Library' } });
    fireEvent.change(screen.getByLabelText('Approval lifetime'), { target: { value: '30' } });
    fireEvent.click(screen.getByRole('button', { name: 'Propose exact identity' }));

    expect(await screen.findByText('Pending review')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve for OSV' })).not.toBeInTheDocument();
    const proposal = fetchMock.mock.calls.find(([, init]) => init?.method === 'POST');
    expect(JSON.parse(String(proposal?.[1]?.body))).toEqual({
      ecosystem: 'pypi',
      package_name: 'Requests_Library',
      requested_ttl_days: 30,
    });
  });

  it('gives an administrator explicit approve and immediate revoke actions accessibly', async () => {
    let item: PublicIdentityAttestation = { ...pending };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/approve') && init?.method === 'POST') {
        item = { ...pending, status: 'approved', revision: 2, approved_at: '2026-09-09T10:05:00Z', expires_at: '2026-10-09T10:05:00Z' };
        return Promise.resolve(response(item));
      }
      if (init?.method === 'DELETE') {
        item = { ...item, status: 'revoked', revision: 3, revoked_at: '2026-09-09T10:06:00Z' };
        return Promise.resolve(response(item));
      }
      return Promise.resolve(response([item]));
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<PublicIdentityAttestationPanel role="administrator" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Approve for OSV' }));
    expect(await screen.findByText('Approved')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Revoke immediately' }));
    expect(await screen.findByText('Revoked')).toBeInTheDocument();
    await waitFor(async () => expect((await axe.run(document.body, { rules: { 'color-contrast': { enabled: false } } })).violations).toEqual([]));
  });

  it('keeps a reader view-only and explains the empty fail-closed state', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(response([]))));
    render(<PublicIdentityAttestationPanel role="reader" />);

    expect(await screen.findByText(/Eligible components remain local/)).toBeInTheDocument();
    expect(screen.getByText(/Reader access can review approvals/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Propose exact identity' })).not.toBeInTheDocument();
  });
});
