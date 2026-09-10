import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import axe from 'axe-core';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ActiveAssetBatchForm } from './ActiveAssetBatchForm';


function response(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), { status, headers: { 'content-type': 'application/json' } });
}

const readyReview = {
  contract_version: '2026-09-08.1', state: 'ready', format: 'json', input_count: 2, ready_count: 2,
  invalid_count: 0, duplicate_count: 0, conflict_count: 0, can_confirm: true,
  review_digest_sha256: 'a'.repeat(64), preflight_token: 'p'.repeat(43), expires_at: '2026-09-08T15:00:00Z',
  rows: [
    { row: 1, status: 'ready', reason_code: 'ready', asset_type: 'domain', canonical_value: 'one.example.test' },
    { row: 2, status: 'ready', reason_code: 'ready', asset_type: 'host', canonical_value: 'two.example.test' },
  ],
};

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe('ActiveAssetBatchForm', () => {
  it('preflights and commits the exact file only after whole-batch confirmation', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, _init?: RequestInit) => Promise.resolve(
      String(input).endsWith('/preflight')
        ? response(readyReview)
        : response({ contract_version: '2026-09-08.1', batch_id: 'b'.repeat(32), created_count: 2, replayed: false, assets: [] }, 201),
    ));
    vi.stubGlobal('fetch', fetchMock);
    const completed = vi.fn();
    const view = render(<ActiveAssetBatchForm onCompleted={completed} onCancel={vi.fn()} />);
    const source = new File(['[{"authorized":"fixture"}]'], 'authorized-assets.json', { type: 'application/json' });
    fireEvent.change(screen.getByLabelText('Authorized asset inventory'), { target: { files: [source] } });
    fireEvent.click(screen.getByRole('button', { name: 'Review batch' }));

    expect(await screen.findByText('Ready for atomic registration.')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Asset batch row review' })).toHaveTextContent('one.example.test');
    expect(screen.getByRole('region', { name: 'Asset batch row review' })).toHaveTextContent('two.example.test');
    const commit = screen.getByRole('button', { name: 'Register entire batch' });
    expect(commit).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I reviewed every exact asset/));
    fireEvent.click(commit);

    expect(await screen.findByText('Registered 2 authorized assets atomically.')).toBeInTheDocument();
    expect(completed).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const preflightBody = fetchMock.mock.calls[0][1]?.body as FormData;
    const commitBody = fetchMock.mock.calls[1][1]?.body as FormData;
    expect(preflightBody.get('file')).toBeInstanceOf(File);
    expect((preflightBody.get('file') as File).name).toBe(source.name);
    expect(commitBody.get('file')).toBeInstanceOf(File);
    expect((commitBody.get('file') as File).name).toBe(source.name);
    expect(commitBody.get('preflight_token')).toBe(readyReview.preflight_token);
    expect(commitBody.get('batch_confirmed')).toBe('true');
    expect(commitBody.get('idempotency_key')).toMatch(/^[a-f0-9]{32}$/);
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('does not silently skip corrected rows or upload unsupported and oversized files', async () => {
    const correctionReview = {
      ...readyReview,
      state: 'needs_correction', can_confirm: false, ready_count: 0, invalid_count: 1, duplicate_count: 1,
      preflight_token: null, expires_at: null,
      rows: [
        { row: 1, status: 'invalid', reason_code: 'invalid_contract', asset_type: null, canonical_value: null },
        { row: 2, status: 'duplicate_in_batch', reason_code: 'duplicate_identity', asset_type: 'domain', canonical_value: 'duplicate.example.test' },
      ],
    };
    const fetchMock = vi.fn(() => Promise.resolve(response(correctionReview)));
    vi.stubGlobal('fetch', fetchMock);
    render(<ActiveAssetBatchForm onCompleted={vi.fn()} onCancel={vi.fn()} />);
    const input = screen.getByLabelText('Authorized asset inventory');

    fireEvent.change(input, { target: { files: [new File(['x'], 'assets.txt', { type: 'text/plain' })] } });
    expect(screen.getByRole('alert')).toHaveTextContent('Choose a .json or .csv inventory');
    expect(fetchMock).not.toHaveBeenCalled();
    fireEvent.change(input, { target: { files: [new File(['x'.repeat(128 * 1024 + 1)], 'assets.json', { type: 'application/json' })] } });
    expect(screen.getByRole('alert')).toHaveTextContent('exceeds the 128 KiB');
    expect(fetchMock).not.toHaveBeenCalled();

    fireEvent.change(input, { target: { files: [new File(['[]'], 'assets.json', { type: 'application/json' })] } });
    fireEvent.click(screen.getByRole('button', { name: 'Review batch' }));
    expect(await screen.findByText('Corrections required.')).toBeInTheDocument();
    expect(screen.getByText(/will not silently skip rows/)).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Asset batch row review' })).toHaveTextContent('Withheld — invalid contract');
    expect(screen.getByRole('button', { name: 'Register entire batch' })).toBeDisabled();
    await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
  });
});
