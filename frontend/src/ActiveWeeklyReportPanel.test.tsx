import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import axe from 'axe-core';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ActiveWeeklyReportPanel } from './ActiveWeeklyReportPanel';
import type { ActiveWeeklyReportPreflight, ActiveWeeklyReviewReceiptPage } from './types';


const digest = 'a'.repeat(64);
const preflight: ActiveWeeklyReportPreflight = {
  contract_version: '2026-09-09.1',
  state: 'ready',
  period: '7d',
  starts_at: '2026-09-02T12:00:00Z',
  state_at: '2026-09-09T12:00:00Z',
  snapshot_digest: digest,
  assets_total: 4,
  assets_included: 4,
  jobs_total: 12,
  jobs_included: 12,
  actions_total: 3,
  actions_included: 3,
  recurrence_attention_total: 1,
  recurrence_attention_included: 1,
  incomplete: false,
  available_formats: ['markdown', 'json'],
  max_bytes: 1048576,
  privacy: {
    exact_targets_included: true,
    notes_included: false,
    authorization_references_included: false,
    authorization_digests_included: false,
    responsible_accounts_included: false,
    actor_identifiers_included: false,
    challenge_material_included: false,
    raw_results_included: false,
    runner_responses_included: false,
  },
};
const emptyReceipts: ActiveWeeklyReviewReceiptPage = {
  contract_version: '2026-09-10.1',
  revision: 0,
  items: [],
  max_retained: 52,
  retention_days: 400,
};

function jsonResponse(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function routeFetch(
  preflightResult: ActiveWeeklyReportPreflight = preflight,
  mutation?: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>,
) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path.endsWith('/active/operations/weekly-review-receipts') && !init?.method) {
      return Promise.resolve(jsonResponse(emptyReceipts));
    }
    if (path.includes('/active/operations/weekly-report/preflight')) {
      return Promise.resolve(jsonResponse(preflightResult));
    }
    return mutation ? mutation(input, init) : Promise.resolve(jsonResponse({}));
  });
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('ActiveWeeklyReportPanel', () => {
  it('announces preflight loading and keeps a provider-independent retryable error', async () => {
    let rejectRequest: (reason: Error) => void = () => undefined;
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      if (String(input).endsWith('/active/operations/weekly-review-receipts')) {
        return Promise.resolve(jsonResponse(emptyReceipts));
      }
      return new Promise<Response>((_resolve, reject) => { rejectRequest = reject; });
    }));
    render(<ActiveWeeklyReportPanel canExport />);

    await screen.findByText(/No weekly review receipt/);

    fireEvent.click(screen.getByRole('button', { name: 'Prepare report' }));
    expect(screen.getByRole('region', { name: 'Weekly portfolio report' })).toHaveAttribute('aria-busy', 'true');
    expect(screen.getByRole('button', { name: 'Preparing…' })).toBeDisabled();
    rejectRequest(new TypeError('Failed to fetch'));

    expect(await screen.findByRole('alert')).toHaveTextContent(/temporarily unavailable/i);
    expect(screen.getByRole('alert')).toHaveTextContent(/Check the backend connection and try again/i);
    expect(screen.getByRole('alert')).not.toHaveTextContent(/Failed to fetch/i);
    expect(screen.getByRole('region', { name: 'Weekly portfolio report' })).toHaveAttribute('aria-busy', 'false');
    expect(screen.getByRole('button', { name: 'Prepare report' })).toBeEnabled();
  });

  it('preflights sensitive scope and downloads one digest-bound format accessibly', async () => {
    const fetchMock = routeFetch(preflight, async () => new Response('{"state":"ready"}\n', {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'x-inspectra-snapshot-sha256': digest,
        },
      }));
    vi.stubGlobal('fetch', fetchMock);
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn(() => 'blob:weekly-report'),
      revokeObjectURL: vi.fn(),
    });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);

    const view = render(<ActiveWeeklyReportPanel canExport />);
    fireEvent.click(screen.getByRole('button', { name: 'Prepare report' }));
    expect(await screen.findByText(/4 included \/ 4 total/)).toBeInTheDocument();
    expect(screen.getByText(/Exact authorized targets are included/)).toBeInTheDocument();
    expect(screen.queryByText(/weekly-sensitive\.example/)).not.toBeInTheDocument();
    const download = screen.getByRole('button', { name: 'Download JSON' });
    expect(download).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I understand this report may contain exact authorized targets/));
    fireEvent.click(download);
    expect(await screen.findByText(/JSON report downloaded with snapshot aaaaaaaaaaaa/)).toBeInTheDocument();
    const exportCall = fetchMock.mock.calls.find(([, init]) => init?.method === 'POST');
    expect(JSON.parse(String(exportCall?.[1]?.body))).toEqual({
      period: '7d',
      report_format: 'json',
      state_at: preflight.state_at,
      snapshot_digest: digest,
      sensitive_targets_confirmed: true,
    });
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('discloses partial and empty snapshots instead of implying complete coverage', async () => {
    const partial = {
      ...preflight,
      state: 'partial' as const,
      assets_total: 501,
      assets_included: 500,
      incomplete: true,
    };
    vi.stubGlobal('fetch', routeFetch(partial));
    const view = render(<ActiveWeeklyReportPanel canExport />);
    fireEvent.click(screen.getByRole('button', { name: 'Prepare report' }));
    expect(await screen.findByText(/Partial snapshot/)).toBeInTheDocument();
    expect(screen.getByText(/500 included \/ 501 total/)).toBeInTheDocument();
    expect((await axe.run(view.container)).violations).toHaveLength(0);

    cleanup();
    vi.stubGlobal('fetch', routeFetch({
      ...preflight,
      state: 'no_assets',
      assets_total: 0,
      assets_included: 0,
      jobs_total: 0,
      jobs_included: 0,
      actions_total: 0,
      actions_included: 0,
      recurrence_attention_total: 0,
      recurrence_attention_included: 0,
    }));
    render(<ActiveWeeklyReportPanel canExport />);
    fireEvent.click(screen.getByRole('button', { name: 'Prepare report' }));
    expect(await screen.findByText(/No authorized Active assets exist/)).toBeInTheDocument();
  });

  it('keeps the preflight visible and explains a stale export failure', async () => {
    const fetchMock = routeFetch(preflight, async () =>
      jsonResponse({ detail: 'The Active portfolio changed. Generate a new report preflight.' }, 409));
    vi.stubGlobal('fetch', fetchMock);
    render(<ActiveWeeklyReportPanel canExport />);
    fireEvent.click(screen.getByRole('button', { name: 'Prepare report' }));
    await screen.findByText(/4 included \/ 4 total/);
    fireEvent.click(screen.getByLabelText(/I understand this report may contain exact authorized targets/));
    fireEvent.click(screen.getByRole('button', { name: 'Download Markdown' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/portfolio changed/i);
    expect(screen.getByRole('button', { name: 'Refresh preflight' })).toBeInTheDocument();
  });

  it('keeps sensitive exports behind the maintainer role boundary', async () => {
    vi.stubGlobal('fetch', routeFetch());
    const view = render(<ActiveWeeklyReportPanel canExport={false} />);
    fireEvent.click(screen.getByRole('button', { name: 'Prepare report' }));
    expect(await screen.findByText(/A maintainer or administrator must confirm and export/)).toBeInTheDocument();
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Download/ })).not.toBeInTheDocument();
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('records and verifies a bounded target-free receipt with clear history', async () => {
    const receipt = {
      contract_version: '2026-09-10.1' as const,
      id: '1'.repeat(32),
      report_contract_version: '2026-09-09.1' as const,
      period: '7d' as const,
      starts_at: preflight.starts_at,
      state_at: preflight.state_at,
      outcome: 'follow_up_required' as const,
      coverage_state: 'ready' as const,
      coverage_incomplete: false,
      snapshot_hmac_sha256: 'b'.repeat(64),
      reviewed_at: '2026-09-09T12:01:00Z',
      privacy: 'target_free_no_raw_digest_report_actor_notes_or_results' as const,
    };
    const fetchMock = routeFetch(preflight, async (input, init) => {
      const path = String(input);
      if (path.endsWith('/verify')) return jsonResponse({
        contract_version: '2026-09-10.1',
        receipt_id: receipt.id,
        valid: true,
        verification: 'local_hmac_no_external_provider',
      });
      if (path.endsWith('/weekly-review-receipts') && init?.method === 'POST') return jsonResponse({
        contract_version: '2026-09-10.1', revision: 1, receipt, replayed: false,
      }, 201);
      return jsonResponse({});
    });
    vi.stubGlobal('fetch', fetchMock);
    const view = render(<ActiveWeeklyReportPanel canExport />);
    await screen.findByText(/No weekly review receipt/);
    fireEvent.click(screen.getByRole('button', { name: 'Prepare report' }));
    await screen.findByText(/4 included \/ 4 total/);
    fireEvent.click(screen.getByLabelText('Follow-up required'));
    fireEvent.click(screen.getByLabelText(/I reviewed this exact bounded snapshot/));
    fireEvent.click(screen.getByRole('button', { name: 'Record target-free receipt' }));
    expect(await screen.findByText('Target-free weekly review receipt recorded.')).toBeInTheDocument();
    expect(screen.getAllByText('Follow-up required')).toHaveLength(2);
    expect(screen.getByText(/HMAC bbbbbbbbbbbb/)).toBeInTheDocument();
    expect(view.container.textContent).not.toMatch(/target\.example|reviewer@|actor/i);
    fireEvent.change(screen.getByLabelText('Snapshot SHA-256'), { target: { value: digest } });
    fireEvent.click(screen.getByRole('button', { name: 'Verify receipt' }));
    expect(await screen.findByText('Receipt matches this snapshot digest.')).toBeInTheDocument();
    const createCall = fetchMock.mock.calls.find(([input, init]) =>
      String(input).endsWith('/weekly-review-receipts') && init?.method === 'POST');
    const body = JSON.parse(String(createCall?.[1]?.body));
    expect(body).toMatchObject({
      snapshot_digest: digest,
      expected_revision: 0,
      outcome: 'follow_up_required',
      review_confirmed: true,
    });
    expect(body.idempotency_key).toMatch(/^weekly-review-.{16,}$/);
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('keeps history and local verification available to readers while hiding mutation controls', async () => {
    const page: ActiveWeeklyReviewReceiptPage = {
      ...emptyReceipts,
      revision: 1,
      items: [{
        contract_version: '2026-09-10.1',
        id: '1'.repeat(32),
        report_contract_version: '2026-09-09.1',
        period: '7d',
        starts_at: preflight.starts_at,
        state_at: preflight.state_at,
        outcome: 'reviewed',
        coverage_state: 'ready',
        coverage_incomplete: false,
        snapshot_hmac_sha256: 'b'.repeat(64),
        reviewed_at: '2026-09-09T12:01:00Z',
        privacy: 'target_free_no_raw_digest_report_actor_notes_or_results',
      }],
    };
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => Promise.resolve(
      String(input).endsWith('/weekly-review-receipts') ? jsonResponse(page) : jsonResponse(preflight),
    )));
    const view = render(<ActiveWeeklyReportPanel canExport={false} />);
    expect(await screen.findByText('Reviewed')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Verify receipt' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Record target-free receipt' })).not.toBeInTheDocument();
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('announces receipt loading, exposes a safe error and recovers through retry', async () => {
    let resolveInitial: (response: Response) => void = () => undefined;
    let requests = 0;
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      if (!String(input).endsWith('/weekly-review-receipts')) return Promise.resolve(jsonResponse(preflight));
      requests += 1;
      if (requests === 1) return new Promise<Response>((resolve) => { resolveInitial = resolve; });
      return Promise.resolve(jsonResponse(emptyReceipts));
    }));
    render(<ActiveWeeklyReportPanel canExport />);
    expect(screen.getByRole('status', { name: '' })).toHaveTextContent('Loading review receipts…');
    resolveInitial(jsonResponse({ detail: 'Weekly review receipt storage is temporarily unavailable.' }, 503));
    expect(await screen.findByRole('alert')).toHaveTextContent('temporarily unavailable');
    fireEvent.click(screen.getByRole('button', { name: 'Retry receipt history' }));
    expect(await screen.findByText(/No weekly review receipt has been recorded/)).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});
