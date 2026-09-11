import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import axe from 'axe-core';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ActiveAssetDeletionPanel } from './ActiveAssetDeletionPanel';

const assetId = 'a'.repeat(32);
const ready = {
  contract_version: '2026-09-10.4', asset_id: assetId, state: 'ready',
  items: [
    { key: 'asset_metadata', disposition: 'delete', item_count: 1, detail: 'The exact target and asset metadata are removed.' },
    { key: 'authorization_revisions', disposition: 'delete', item_count: 2, detail: 'Immutable authorization revisions are removed.' },
    { key: 'verification_challenges', disposition: 'delete', item_count: 1, detail: 'Verification records and challenge digests are removed.' },
    { key: 'execution_jobs', disposition: 'delete', item_count: 3, detail: 'Terminal jobs are removed.' },
    { key: 'execution_results', disposition: 'delete', item_count: 3, detail: 'Observations and triage are removed.' },
    { key: 'report_exports', disposition: 'not_persisted', item_count: 0, detail: 'Reports are rendered on request.' },
    { key: 'product_audit', disposition: 'anonymize', item_count: null, detail: 'Target and job links are detached.' },
  ],
} as const;

function response(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), { status, headers: { 'content-type': 'application/json' } });
}

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe('ActiveAssetDeletionPanel', () => {
  it('shows a target-free preflight and requires explicit confirmation before deletion', async () => {
    const onDeleted = vi.fn();
    const fetchMock = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => Promise.resolve(
      init?.method === 'DELETE'
        ? response({ ...ready, state: 'completed', deletion_receipt_id: 'b'.repeat(32), completed_at: '2026-09-10T12:00:00Z' })
        : response(ready)
    ));
    vi.stubGlobal('fetch', fetchMock);
    const view = render(<ActiveAssetDeletionPanel assetId={assetId} onDeleted={onDeleted} />);

    fireEvent.click(screen.getByRole('button', { name: 'Review deletion scope' }));
    expect(await screen.findByText(/Deletion is ready/)).toBeInTheDocument();
    expect(screen.getByRole('list', { name: 'Active asset deletion scope' })).toHaveTextContent('Product audit');
    expect(view.container).not.toHaveTextContent('private.example.test');
    const remove = screen.getByRole('button', { name: 'Delete asset and retained data' });
    expect(remove).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I understand that the asset/));
    expect(remove).toBeEnabled();
    fireEvent.click(remove);
    await waitFor(() => expect(onDeleted).toHaveBeenCalledOnce());
    const call = fetchMock.mock.calls.find(([, init]) => init?.method === 'DELETE');
    expect(JSON.parse(String(call?.[1]?.body))).toEqual({ confirmation: 'DELETE ACTIVE ASSET' });
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('explains blockers and never offers the destructive action while work is active', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(response({ ...ready, state: 'blocked_active_work' }))));
    const view = render(<ActiveAssetDeletionPanel assetId={assetId} onDeleted={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: 'Review deletion scope' }));
    expect(await screen.findByText(/Deletion is blocked/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Delete asset and retained data' })).not.toBeInTheDocument();
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('keeps a retryable, generic error when the backend retains a recovery journal', async () => {
    let requests = 0;
    vi.stubGlobal('fetch', vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      requests += 1;
      if (init?.method === 'DELETE') return Promise.resolve(response({ detail: 'retry' }, 503));
      return Promise.resolve(response(ready));
    }));
    render(<ActiveAssetDeletionPanel assetId={assetId} onDeleted={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: 'Review deletion scope' }));
    await screen.findByText(/Deletion is ready/);
    fireEvent.click(screen.getByLabelText(/I understand that the asset/));
    fireEvent.click(screen.getByRole('button', { name: 'Delete asset and retained data' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('retained a safe retry record');
    expect(requests).toBeGreaterThanOrEqual(3);
  });
});
