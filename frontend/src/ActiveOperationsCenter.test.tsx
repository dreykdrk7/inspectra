import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import axe from 'axe-core';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ActiveOperationsCenter } from './ActiveOperationsCenter';
import type { ActiveAsset } from './types';

const asset: ActiveAsset = {
  contract_version: '2026-09-09.1', id: 'a'.repeat(32), organization_id: 'local-admin', owner_id: 'local-admin', responsible_user_ids: [],
  asset_type: 'domain', canonical_value: 'example.test', capabilities: ['active_dns_inventory'], allowed_ports: [], allowed_protocols: ['dns'],
  authorization_method: 'manual_attestation', authorization_reference: 'change-ticket SEC-42', authorized_at: '2026-09-01T10:00:00Z', expires_at: '2099-10-01T10:00:00Z', revoked_at: null, status: 'active', notes: [], created_at: '2026-09-01T10:00:00Z', updated_at: '2026-09-01T10:00:00Z',
  history: [{ id: 'b'.repeat(32), kind: 'registered', occurred_at: '2026-09-01T10:00:00Z', actor_id: 'local-admin', reason_code: null }],
  authorization_revisions: [{ contract_version: '2026-09-10.1', id: 'e'.repeat(32), sequence: 1, source: 'registration', scope_expanded: false, created_at: '2026-09-01T10:00:00Z', authorized_at: '2026-09-01T10:00:00Z', expires_at: '2099-10-01T10:00:00Z', authorization_method: 'manual_attestation', capabilities: ['active_dns_inventory'], allowed_ports: [], allowed_protocols: ['dns'], digest_sha256: 'f'.repeat(64) }],
};
const emptyPosture = { asset, executions: [], baseline_execution: null, history: { returned_count: 0, total_count: 0, has_more: false, next_cursor: null, posture_records_considered: 0, posture_incomplete: false }, posture: { contract_version: '2026-09-09.1', execution_count: 0, counts: { completed: 0, failed: 0, cancelled: 0 }, capabilities: [], baseline_execution_id: null, comparison: null, limitations: ['Observations require manual validation.'] } };
const verificationConfiguration = { contract_version: '2026-09-09.1', enabled: false, remote_runner_ready: false, methods: { manual_attestation: false, dns_txt: false, http_well_known: false, managed_private: false }, challenge_ttl_seconds: 900, max_attempts_per_hour: 5, legal_authorization_established: false as const, target_expansion_allowed: false as const };
const operationsSummary = {
  contract_version: '2026-09-09.4', generated_at: '2026-09-01T10:03:00Z',
  assets: { total: 1, active: 1, expired: 0, revoked: 0, expiring_14_days: 0, duplicate_identity_groups: 0, duplicate_identity_records: 0 },
  verifications: { not_started: 1, pending: 0, verified: 0, failed: 0, expired: 0, revoked: 0 },
  jobs: { total: 3, queued: 0, running: 1, cancelling: 0, cancelled: 0, completed: 1, failed: 1, degraded: 1 },
  changes: { assets_compared: 1, assets_with_changes: 1, observations_changed: 2, inconclusive: 0 },
  actions: { total: 2, authorization_expiring: 0, authorization_expired: 0, failed_jobs: 1, degraded_jobs: 0, verification_attention: 0, observation_changes: 1 },
  action_queue: {
    items: [
      { id: '1'.repeat(32), kind: 'execution_failed', urgency: 'high', action_code: 'retry_execution', asset_id: asset.id, job_id: '9'.repeat(32), reference_at: '2026-08-20T10:03:00Z', due_at: null, occurrence_count: 1 },
      { id: '2'.repeat(32), kind: 'observations_changed', urgency: 'review', action_code: 'triage_changes', asset_id: asset.id, job_id: '8'.repeat(32), reference_at: '2026-08-31T10:03:00Z', due_at: null, occurrence_count: 2 },
    ],
    returned: 2, total: 2, items_truncated: false, source_incomplete: false,
  },
  capabilities: [
    { capability: 'active_dns_inventory', enabled: true, asset_count: 1, execution_count: 3 },
    { capability: 'active_dns_osint', enabled: false, asset_count: 0, execution_count: 0 },
    { capability: 'active_http_basic_header_review', enabled: false, asset_count: 0, execution_count: 0 },
    { capability: 'active_nmap_basic', enabled: false, asset_count: 0, execution_count: 0 },
    { capability: 'active_tls_basic', enabled: false, asset_count: 0, execution_count: 0 },
  ],
  configuration: { verification_enabled: false, recurrence_enabled: true, legacy_free_targets_enabled: false, all_live_capabilities_disabled: false },
  capacity: { admission: 'ready', retry_after_seconds: 5 },
  limits: { assets_considered: 1, assets_total: 1, jobs_considered: 3, jobs_total: 3, incomplete: false, selection_strategy: 'priority_then_recency', priority_candidates: 1 },
  interpretation: 'portfolio_counts_and_bounded_observations_not_vulnerability_findings',
};

function activeGet(input: RequestInfo | URL, records: ActiveAsset[] = [asset], init?: RequestInit) {
  const url = new URL(String(input));
  if (url.pathname.endsWith('/active/operations/weekly-review-receipts')) return response({
    contract_version: '2026-09-10.1', revision: 0, items: [], max_retained: 52, retention_days: 400,
  });
  if (url.pathname.endsWith('/active/verification/configuration')) return response(verificationConfiguration);
  if (url.pathname.endsWith('/active/operations/summary')) return response(operationsSummary);
  if (url.pathname.endsWith('/active/assets/search')) {
    const payload = JSON.parse(String(init?.body ?? '{}')) as Record<string, string>;
    const query = (payload.query ?? '').toLowerCase();
    const queryMode = payload.query_mode ?? 'prefix';
    const status = payload.status;
    const capability = payload.capability;
    const filtered = records.filter((record) =>
      (!query || (queryMode === 'exact' ? record.canonical_value.toLowerCase() === query : record.canonical_value.toLowerCase().startsWith(query)))
      && (!status || record.status === status)
      && (!capability || record.capabilities.includes(capability as ActiveAsset['capabilities'][number]))
    );
    return response({ contract_version: '2026-09-08.1', items: filtered, returned_count: filtered.length, page_size: 24, has_more: false, next_cursor: null });
  }
  if (url.pathname.endsWith('/posture')) return response(emptyPosture);
  if (url.pathname.endsWith('/verification')) return response(null);
  const directAssetId = url.pathname.match(/\/active\/assets\/([a-f0-9]{32})$/)?.[1];
  if (directAssetId) {
    const directAsset = records.find((record) => record.id === directAssetId);
    return directAsset ? response(directAsset) : response({ detail: 'not found' }, 404);
  }
  return response(records);
}

function response(payload: unknown, status = 200) { return new Response(JSON.stringify(payload), { status, headers: { 'content-type': 'application/json' } }); }

function portfolioAsset(index: number): ActiveAsset {
  const suffix = index.toString().padStart(4, '0');
  return {
    ...asset,
    id: index.toString(16).padStart(32, '0'),
    canonical_value: `portfolio-${suffix}-${'internationalized-label-'.repeat(4)}asset.test`,
  };
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.localStorage.clear();
  window.history.replaceState(null, '', '/');
});

describe('ActiveOperationsCenter', () => {
  it('renders searchable authorized assets, detail and accessible empty-safe language', async () => {
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => Promise.resolve(activeGet(input, [asset], init))));
    const view = render(<ActiveOperationsCenter canManage />);
    expect(await screen.findByRole('heading', { name: 'Active operations' })).toBeInTheDocument();
    expect(await screen.findByRole('heading', { name: 'example.test' })).toBeInTheDocument();
    expect(screen.getByText(/Observations are not automatically confirmed vulnerabilities/i)).toBeInTheDocument();
    expect(screen.getByText(/explicit weekly IANA-timezone window/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Details' }));
    const closeDetails = screen.getByRole('button', { name: 'Close details' });
    expect(closeDetails).toHaveAttribute('aria-expanded', 'true');
    expect(closeDetails).toHaveAttribute('aria-controls', `active-asset-detail-${asset.id}`);
    expect(document.getElementById(`active-asset-detail-${asset.id}`)).toBeInTheDocument();
    expect(screen.getByText(/change-ticket SEC-42/)).toBeInTheDocument();
    expect(screen.getAllByText(/Revision 1/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/1 append-only events/)).toBeInTheDocument();
    const evidenceLink = screen.getByRole('link', { name: 'Download verifiable TAR' });
    expect(evidenceLink).toHaveAttribute('href', expect.stringContaining('evidence-bundle?period=90d'));
    expect(screen.getByText(/Exports omit the exact target, authorization reference, notes, accounts, challenges and raw runner output/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Evidence period ending at retained state'), { target: { value: '30d' } });
    expect(evidenceLink).toHaveAttribute('href', expect.stringContaining('evidence-bundle?period=30d'));
    fireEvent.change(screen.getByLabelText('Search authorized asset'), { target: { value: 'example' } });
    await waitFor(() => expect(globalThis.fetch).toHaveBeenCalledWith(expect.stringMatching(/\/active\/assets\/search$/), expect.objectContaining({ body: expect.stringContaining('"query":"example"') })));
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('filters the deterministic action inbox and opens the owner-scoped resolution detail with focus', async () => {
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => Promise.resolve(activeGet(input, [asset], init))));
    const view = render(<ActiveOperationsCenter canManage />);
    expect(await screen.findByRole('heading', { name: 'Action inbox' })).toBeInTheDocument();
    expect(screen.getByText('Bounded execution failed')).toBeInTheDocument();
    expect(screen.getByText('Observed state changed')).toBeInTheDocument();
    expect(screen.getByText('Recorded 12 days ago')).toBeInTheDocument();
    expect(screen.getByText(/does not infer an SLA or a confirmed vulnerability/)).toBeInTheDocument();
    expect(screen.getByRole('list', { name: 'Prioritized Active actions' }).children).toHaveLength(operationsSummary.action_queue.returned);

    fireEvent.change(screen.getByLabelText('Priority'), { target: { value: 'review' } });
    expect(screen.queryByText('Bounded execution failed')).not.toBeInTheDocument();
    expect(screen.getByText('Observed state changed')).toBeInTheDocument();
    expect(JSON.parse(String(window.localStorage.getItem('inspectra.activeActionInbox.v1')))).toEqual({ urgency: 'review', age: 'all' });
    fireEvent.change(screen.getByLabelText('Age of recorded state'), { target: { value: '7' } });
    expect(screen.getByText('No actions match these filters.')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Priority'), { target: { value: 'high' } });
    expect(screen.getByText('Bounded execution failed')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Review safe retry' }));
    const detail = await waitFor(() => {
      const element = document.getElementById(`active-asset-detail-${asset.id}`);
      expect(element).toHaveFocus();
      return element as HTMLElement;
    });
    expect(window.location.hash).toBe(`#active-asset-detail-${asset.id}`);
    expect(detail).toHaveAttribute('tabindex', '-1');
    expect(screen.queryByText(/One action asset is pinned/)).not.toBeInTheDocument();
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('loads a filtered-out action asset through the scoped detail endpoint and reports partial source state', async () => {
    const secondAsset = { ...asset, id: '7'.repeat(32), canonical_value: 'selected-action.test' };
    const partialSummary = {
      ...operationsSummary,
      actions: { ...operationsSummary.actions, total: 1, failed_jobs: 1, observation_changes: 0 },
      action_queue: {
        items: [{ ...operationsSummary.action_queue.items[0], id: '6'.repeat(32), asset_id: secondAsset.id }],
        returned: 1, total: 17, items_truncated: true, source_incomplete: true,
      },
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/active/operations/summary')) return Promise.resolve(response(partialSummary));
      if (String(input).endsWith(`/active/assets/${secondAsset.id}`)) return Promise.resolve(response(secondAsset));
      return Promise.resolve(activeGet(input, [asset], init));
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<ActiveOperationsCenter canManage />);
    expect(await screen.findByText('Partial action inbox.')).toBeInTheDocument();
    expect(screen.getByText(/Showing the first 1 of 17 ordered actions/)).toBeInTheDocument();
    expect(screen.getByText(`Authorized asset ${secondAsset.id.slice(0, 8)}…`)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Review safe retry' }));
    expect(await screen.findByRole('heading', { name: 'selected-action.test' })).toBeInTheDocument();
    await waitFor(() => expect(document.getElementById(`active-asset-detail-${secondAsset.id}`)).toHaveFocus());
    expect(screen.getByText(/One action asset is pinned outside the current portfolio filters/)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(expect.stringMatching(new RegExp(`/active/assets/${secondAsset.id}$`)), expect.anything());
  });

  it('restores an exact action deep link through the scoped asset lookup', async () => {
    const linkedAsset = { ...asset, id: '5'.repeat(32), canonical_value: 'deep-linked-action.test' };
    window.history.replaceState(null, '', `/#active-asset-detail-${linkedAsset.id}`);
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith(`/active/assets/${linkedAsset.id}`)) return Promise.resolve(response(linkedAsset));
      return Promise.resolve(activeGet(input, [asset], init));
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<ActiveOperationsCenter canManage />);
    expect(await screen.findByRole('heading', { name: 'deep-linked-action.test' })).toBeInTheDocument();
    await waitFor(() => expect(document.getElementById(`active-asset-detail-${linkedAsset.id}`)).toHaveFocus());
    expect(fetchMock).toHaveBeenCalledWith(expect.stringMatching(new RegExp(`/active/assets/${linkedAsset.id}$`)), expect.anything());
  });

  it('loads a signed next page without replacing filters, duplicates, or keyboard context', async () => {
    const secondAsset = { ...asset, id: '9'.repeat(32), canonical_value: 'example-two.test' };
    let failNextPage = false;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      if (url.pathname.endsWith('/active/assets/search')) {
        const payload = JSON.parse(String(init?.body ?? '{}')) as Record<string, string>;
        if (payload.cursor) {
          if (failNextPage) return Promise.resolve(response({ detail: 'unavailable' }, 503));
          return Promise.resolve(response({ contract_version: '2026-09-08.1', items: [secondAsset], returned_count: 1, page_size: 24, has_more: false, next_cursor: null }));
        }
        return Promise.resolve(response({ contract_version: '2026-09-08.1', items: [asset], returned_count: 1, page_size: 24, has_more: true, next_cursor: 'signed-cursor' }));
      }
      return Promise.resolve(activeGet(input, [asset], init));
    });
    vi.stubGlobal('fetch', fetchMock);
    const view = render(<ActiveOperationsCenter canManage />);
    const loadMore = await screen.findByRole('button', { name: 'Load next 24 assets' });
    expect(screen.getByText(/Showing 1 matching assets/)).toHaveTextContent('More records are available');
    fireEvent.change(screen.getByLabelText('Search authorized asset'), { target: { value: 'example' } });
    fireEvent.change(screen.getByLabelText('Match'), { target: { value: 'exact' } });
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(expect.stringMatching(/\/active\/assets\/search$/), expect.objectContaining({ body: expect.stringMatching(/"query":"example".*"query_mode":"exact"|"query_mode":"exact".*"query":"example"/) })));

    fireEvent.change(screen.getByLabelText('Match'), { target: { value: 'prefix' } });
    await waitFor(() => expect(screen.getByRole('button', { name: 'Load next 24 assets' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: 'Load next 24 assets' }));
    expect(await screen.findByRole('heading', { name: 'example-two.test' })).toBeInTheDocument();
    expect(screen.getByText(/Showing 2 matching assets/)).toHaveTextContent('All matching records are loaded');
    const completedButton = screen.getByRole('button', { name: 'All matching assets loaded' });
    expect(completedButton).toBeDisabled();
    await waitFor(() => expect(screen.getByText(/Showing 2 matching assets/)).toHaveFocus());
    expect(screen.getByLabelText('Search authorized asset')).toHaveValue('example');
    expect(screen.getByLabelText('Match')).toHaveValue('prefix');
    expect((await axe.run(view.container)).violations).toHaveLength(0);

    failNextPage = true;
    fireEvent.change(screen.getByLabelText('Search authorized asset'), { target: { value: 'recoverable' } });
    await waitFor(() => expect(screen.getByRole('button', { name: 'Load next 24 assets' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: 'Load next 24 assets' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Loaded assets remain visible');
    expect(screen.getByRole('heading', { name: 'example.test' })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Load next 24 assets' })).toHaveFocus());
  });

  it('discards stale filtered responses instead of showing assets from a previous view', async () => {
    const slowAsset = { ...asset, id: '1'.repeat(32), canonical_value: 'slow-view.test' };
    const fastAsset = { ...asset, id: '2'.repeat(32), canonical_value: 'fast-view.test' };
    let resolveSlow: ((value: Response) => void) | undefined;
    let resolveFast: ((value: Response) => void) | undefined;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      if (url.pathname.endsWith('/active/assets/search')) {
        const payload = JSON.parse(String(init?.body ?? '{}')) as Record<string, string>;
        if (payload.query === 'slow') return new Promise<Response>((resolve) => { resolveSlow = resolve; });
        if (payload.query === 'fast') return new Promise<Response>((resolve) => { resolveFast = resolve; });
      }
      return Promise.resolve(activeGet(input, [asset], init));
    });
    vi.stubGlobal('fetch', fetchMock);
    const view = render(<ActiveOperationsCenter canManage />);
    await screen.findByRole('heading', { name: 'example.test' });

    fireEvent.change(screen.getByLabelText('Search authorized asset'), { target: { value: 'slow' } });
    await waitFor(() => expect(resolveSlow).toBeTypeOf('function'));
    fireEvent.change(screen.getByLabelText('Search authorized asset'), { target: { value: 'fast' } });
    await waitFor(() => expect(resolveFast).toBeTypeOf('function'));
    resolveFast?.(response({ contract_version: '2026-09-08.1', items: [fastAsset], returned_count: 1, page_size: 24, has_more: false, next_cursor: null }));
    expect(await screen.findByText('fast-view.test')).toBeInTheDocument();
    resolveSlow?.(response({ contract_version: '2026-09-08.1', items: [slowAsset], returned_count: 1, page_size: 24, has_more: false, next_cursor: null }));

    await waitFor(() => expect(screen.queryByText('slow-view.test')).not.toBeInTheDocument());
    expect(screen.getByText('fast-view.test')).toBeInTheDocument();
    expect(view.container.querySelector('#active-operations')).toHaveAttribute('aria-busy', 'false');
  });

  it('keeps a 2,005-asset portfolio bounded, searchable and accessible', async () => {
    const records = Array.from({ length: 2_005 }, (_, index) => portfolioAsset(index));
    const largeSummary = {
      ...operationsSummary,
      assets: { ...operationsSummary.assets, total: records.length, active: records.length },
      capabilities: operationsSummary.capabilities.map((item) => ({
        ...item,
        asset_count: item.capability === 'active_dns_inventory' ? records.length : 0,
      })),
      limits: { assets_considered: 500, assets_total: records.length, jobs_considered: 3, jobs_total: 3, incomplete: true, selection_strategy: 'priority_then_recency', priority_candidates: 3 },
    };
    const searchBodies: Array<Record<string, string | number>> = [];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      if (url.pathname.endsWith('/active/operations/summary')) return Promise.resolve(response(largeSummary));
      if (url.pathname.endsWith('/active/assets/search')) {
        const payload = JSON.parse(String(init?.body ?? '{}')) as Record<string, string | number>;
        searchBodies.push(payload);
        const query = String(payload.query ?? '').toLowerCase();
        const queryMode = String(payload.query_mode ?? 'prefix');
        const filtered = records.filter((record) => !query || (queryMode === 'exact'
          ? record.canonical_value.toLowerCase() === query
          : record.canonical_value.toLowerCase().startsWith(query)));
        const offset = Number(String(payload.cursor ?? 'offset-0').replace('offset-', ''));
        const pageSize = Number(payload.page_size ?? 24);
        const items = filtered.slice(offset, offset + pageSize);
        const nextOffset = offset + items.length;
        return Promise.resolve(response({
          contract_version: '2026-09-08.1',
          items,
          returned_count: items.length,
          page_size: pageSize,
          has_more: nextOffset < filtered.length,
          next_cursor: nextOffset < filtered.length ? `offset-${nextOffset}` : null,
        }));
      }
      return Promise.resolve(activeGet(input, records, init));
    });
    vi.stubGlobal('fetch', fetchMock);
    const startedAt = performance.now();
    const view = render(<ActiveOperationsCenter canManage />);
    await screen.findByText(records[0].canonical_value);
    expect(view.container.querySelectorAll('.active-asset-card')).toHaveLength(24);
    expect(await screen.findByText(/Partial operational detail/)).toBeInTheDocument();
    expect(screen.getByText(/Asset totals are exact/)).toBeInTheDocument();

    for (const expectedCount of [48, 72, 96]) {
      fireEvent.click(screen.getByRole('button', { name: 'Load next 24 assets' }));
      await waitFor(() => expect(view.container.querySelectorAll('.active-asset-card')).toHaveLength(expectedCount));
    }
    const boundedAt = performance.now();
    expect(boundedAt - startedAt).toBeLessThan(5_000);
    expect(screen.getByRole('button', { name: 'Refine filters to continue' })).toBeDisabled();
    expect(screen.getByText(/safe display limit is reached/)).toHaveFocus();
    expect(view.container.querySelectorAll('.active-asset-card')).toHaveLength(96);
    expect((await axe.run(view.container)).violations).toHaveLength(0);

    fireEvent.change(screen.getByLabelText('Search authorized asset'), { target: { value: records[2_004].canonical_value } });
    fireEvent.change(screen.getByLabelText('Match'), { target: { value: 'exact' } });
    expect(await screen.findByText(records[2_004].canonical_value)).toBeInTheDocument();
    await waitFor(() => expect(view.container.querySelectorAll('.active-asset-card')).toHaveLength(1));
    expect(screen.getByRole('button', { name: 'All matching assets loaded' })).toBeDisabled();
    expect(searchBodies).toHaveLength(5);
    expect(searchBodies[searchBodies.length - 1]).toMatchObject({ query: records[2_004].canonical_value, query_mode: 'exact', page_size: 24 });
    expect(fetchMock.mock.calls.filter(([input]) => new URL(String(input)).pathname.endsWith('/active/assets/search')).every(([input]) => new URL(String(input)).search === '')).toBe(true);
  }, 15_000);

  it('summarizes the current organization and filters the bounded asset view', async () => {
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => Promise.resolve(activeGet(input, [asset], init))));
    render(<ActiveOperationsCenter canManage />);
    const metrics = await screen.findByLabelText('Active asset status summary');
    expect(metrics).toHaveTextContent('Running');
    expect(metrics).toHaveTextContent('Failed or degraded');
    expect(await screen.findByText('0 verified · 0 verification attention')).toBeInTheDocument();
    expect(screen.getByText('1 ready · 0 degraded · 0 unavailable · 4 disabled')).toBeInTheDocument();
    expect(screen.getByText('2 changed signals · 0 inconclusive')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Capability'), { target: { value: 'active_tls_basic' } });
    expect(await screen.findByText(/No authorized assets match this view/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Capability'), { target: { value: 'active_dns_inventory' } });
    expect(await screen.findByRole('heading', { name: 'example.test' })).toBeInTheDocument();
  });

  it('warns about aggregate legacy identity conflicts without inventing an automatic merge', async () => {
    const duplicateSummary = { ...operationsSummary, assets: { ...operationsSummary.assets, total: 2, duplicate_identity_groups: 1, duplicate_identity_records: 2 } };
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/active/operations/summary')) return Promise.resolve(response(duplicateSummary));
      return Promise.resolve(activeGet(input, [asset], init));
    }));
    const view = render(<ActiveOperationsCenter canManage />);
    expect(await screen.findByText('Legacy identity conflicts need review.')).toBeInTheDocument();
    expect(screen.getByText(/2 records share 1 exact identity/)).toBeInTheDocument();
    expect(screen.getByText(/never merges or deletes retained evidence automatically/)).toBeInTheDocument();
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('keeps the asset workflow usable when only the portfolio summary fails', async () => {
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/active/operations/summary')) return Promise.resolve(response({ detail: 'summary unavailable' }, 503));
      return Promise.resolve(activeGet(input, [asset], init));
    }));
    render(<ActiveOperationsCenter canManage />);
    expect(await screen.findByRole('heading', { name: 'example.test' })).toBeInTheDocument();
    expect(await screen.findByRole('alert')).toHaveTextContent('Portfolio summary is temporarily unavailable');
    expect(screen.getByRole('button', { name: 'Details' })).toBeEnabled();
    fireEvent.click(screen.getByRole('button', { name: 'Details' }));
    expect(await screen.findByText(/isolated runner cannot currently attest/i)).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText(/I reconfirm the authorization/));
    expect(screen.getByRole('button', { name: 'Run authorized check' })).toBeDisabled();
  });

  it('explains degraded runner readiness and blocks execution until both gates attest ready', async () => {
    const degraded = {
      ...operationsSummary,
      capabilities: operationsSummary.capabilities.map((item) => ({
        ...item,
        backend_enabled: item.capability === 'active_dns_inventory',
        runner_enabled: false,
        readiness: item.capability === 'active_dns_inventory' ? 'degraded' : 'disabled',
        reason_code: item.capability === 'active_dns_inventory' ? 'runner_gate_disabled' : 'backend_disabled',
        enabled: false,
      })),
    };
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/active/operations/summary')) return Promise.resolve(response(degraded));
      return Promise.resolve(activeGet(input, [asset], init));
    }));
    const view = render(<ActiveOperationsCenter canManage />);
    await screen.findByRole('heading', { name: 'example.test' });
    expect(screen.getByText('0 ready · 1 degraded · 0 unavailable · 4 disabled')).toBeInTheDocument();
    const readiness = screen.getByRole('list', { name: 'Effective runner readiness by capability' });
    expect(readiness).toHaveTextContent('DNS inventory');
    expect(readiness).toHaveTextContent('Degraded');
    expect(readiness).not.toHaveTextContent('active-tools:');
    fireEvent.click(screen.getByRole('button', { name: 'Details' }));
    expect((await screen.findAllByText(/isolated runner gate or health contract is not ready/i))).toHaveLength(2);
    fireEvent.click(screen.getByLabelText(/I reconfirm the authorization/));
    expect(screen.getByRole('button', { name: 'Run authorized check' })).toBeDisabled();
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('reports saturated admission without counts and blocks only new Active work', async () => {
    const saturated = { ...operationsSummary, capacity: { admission: 'saturated' as const, retry_after_seconds: 5 } };
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/active/operations/summary')) return Promise.resolve(response(saturated));
      return Promise.resolve(activeGet(input, [asset], init));
    }));
    const view = render(<ActiveOperationsCenter canManage />);
    expect(await screen.findByText(/Active admission is temporarily full/)).toBeInTheDocument();
    expect(screen.queryByText(/quota|organization limit|asset limit|capability limit/i)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Details' }));
    expect(await screen.findByText(/cannot queue more Active work yet/)).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText(/I reconfirm the authorization/));
    expect(screen.getByRole('button', { name: 'Run authorized check' })).toBeDisabled();
    expect(screen.getByRole('link', { name: 'Export Markdown' })).toBeVisible();
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('registers a canonical scoped asset without accepting a target at execution time', async () => {
    let records: ActiveAsset[] = [];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/active/assets/search')) return Promise.resolve(activeGet(input, records, init));
      if (!init?.method && String(input).endsWith('/active/operations/summary')) return Promise.resolve(response({
        ...operationsSummary,
        assets: { ...operationsSummary.assets, total: records.length, active: records.length },
        verifications: { ...operationsSummary.verifications, not_started: records.length },
      }));
      if (!init?.method) return Promise.resolve(activeGet(input, records, init));
      if (init?.method === 'POST') { records = [asset]; return Promise.resolve(response(asset, 201)); }
      return Promise.resolve(activeGet(input, records, init));
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<ActiveOperationsCenter canManage />);
    await screen.findByText(/No authorized assets match/);
    fireEvent.click(screen.getByRole('button', { name: 'Register asset' }));
    fireEvent.change(screen.getByLabelText('Exact value'), { target: { value: 'Example.Test.' } });
    fireEvent.change(screen.getByLabelText('Authorization reference'), { target: { value: 'change-ticket SEC-42' } });
    fireEvent.click(screen.getByLabelText(/Current operator/));
    fireEvent.click(screen.getByLabelText(/DNS inventory/));
    fireEvent.click(screen.getByLabelText(/I confirm this exact asset/));
    fireEvent.click(screen.getByRole('button', { name: 'Register authorized asset' }));
    expect(await screen.findByRole('heading', { name: 'example.test' })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByLabelText('Active asset status summary')).toHaveTextContent('1Assets'));
    const createCall = fetchMock.mock.calls.find(([input, init]) => init?.method === 'POST' && String(input).endsWith('/active/assets'));
    const body = JSON.parse(String(createCall?.[1]?.body));
    expect(body).toMatchObject({ value: 'Example.Test.', responsible_user_ids: ['local-admin'], capabilities: ['active_dns_inventory'], allowed_protocols: ['dns'] });
    expect(body).not.toHaveProperty('target');
    expect(JSON.stringify(body)).not.toMatch(/password|token|secret/i);
  });

  it('offers only current workspace members as responsible accounts and labels assignment without granting write access', async () => {
    const members = [
      { user_id: '1'.repeat(32), username: 'active.reader', role: 'reader' as const, joined_at: '2026-09-01T10:00:00Z' },
      { user_id: '2'.repeat(32), username: 'active.maintainer', role: 'maintainer' as const, joined_at: '2026-09-01T10:00:00Z' },
    ];
    const assignedAsset: ActiveAsset = { ...asset, responsible_user_ids: [members[0].user_id] };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === 'POST' && String(input).endsWith(`/active/assets/${asset.id}/responsibles`)) {
        return Promise.resolve(response({ ...assignedAsset, responsible_user_ids: [], updated_at: '2026-09-02T11:00:00Z', history: [...assignedAsset.history, { id: '4'.repeat(32), kind: 'responsibles_updated', occurred_at: '2026-09-02T11:00:00Z', actor_id: '3'.repeat(32), reason_code: 'responsibles_unassigned' }] }));
      }
      if (String(input).endsWith('/organization/members')) return Promise.resolve(response(members));
      return Promise.resolve(activeGet(input, [assignedAsset], init));
    });
    vi.stubGlobal('fetch', fetchMock);
    const view = render(<ActiveOperationsCenter canManage teamMode currentUserId={'3'.repeat(32)} />);
    await screen.findByRole('heading', { name: 'example.test' });
    fireEvent.click(screen.getByRole('button', { name: 'Details' }));
    expect(await screen.findByText('active.reader')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Renew authorization' }));
    expect(screen.getByLabelText(/active.reader/)).toBeChecked();
    expect(screen.getByLabelText(/active.maintainer/)).not.toBeChecked();
    fireEvent.click(screen.getByRole('button', { name: 'Close renewal' }));
    fireEvent.click(screen.getByRole('button', { name: 'Manage responsible accounts' }));
    fireEvent.click(screen.getByLabelText(/active.reader/));
    fireEvent.click(screen.getByLabelText(/I confirm this assignment/));
    fireEvent.click(screen.getByRole('button', { name: 'Save responsible accounts' }));
    expect(await screen.findByText('Asset is now unassigned.')).toBeInTheDocument();
    const assignmentCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith(`/active/assets/${asset.id}/responsibles`));
    expect(JSON.parse(String(assignmentCall?.[1]?.body))).toEqual({ responsible_user_ids: [], expected_updated_at: asset.updated_at, assignment_confirmed: true });
    expect(view.container).not.toHaveTextContent('external.member');
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('reloads both assignments and the workspace directory after a membership change', async () => {
    const reader = { user_id: '1'.repeat(32), username: 'departing.reader', role: 'reader' as const, joined_at: '2026-09-01T10:00:00Z' };
    const assignedAsset: ActiveAsset = { ...asset, responsible_user_ids: [reader.user_id] };
    const reconciledAsset: ActiveAsset = {
      ...assignedAsset,
      responsible_user_ids: [],
      updated_at: '2026-09-02T11:00:00Z',
      history: [...assignedAsset.history, { id: '4'.repeat(32), kind: 'responsibles_updated', occurred_at: '2026-09-02T11:00:00Z', actor_id: '3'.repeat(32), reason_code: 'membership_revoked' }],
    };
    let records = [assignedAsset];
    let members = [reader];
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/organization/members')) return Promise.resolve(response(members));
      return Promise.resolve(activeGet(input, records, init));
    }));
    const view = render(<ActiveOperationsCenter canManage teamMode currentUserId={'3'.repeat(32)} refreshToken={0} />);
    await screen.findByRole('heading', { name: 'example.test' });
    fireEvent.click(screen.getByRole('button', { name: 'Details' }));
    expect(await screen.findByText('departing.reader')).toBeInTheDocument();

    records = [reconciledAsset];
    members = [];
    view.rerender(<ActiveOperationsCenter canManage teamMode currentUserId={'3'.repeat(32)} refreshToken={1} />);

    expect(await screen.findByText('Unassigned')).toBeInTheDocument();
    expect(screen.queryByText('departing.reader')).not.toBeInTheDocument();
    expect(screen.getByText('2 append-only events')).toBeInTheDocument();
  });

  it('keeps readers read-only and reports loading failures with retry', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('controlled unavailable'))));
    render(<ActiveOperationsCenter canManage={false} />);
    await waitFor(() => expect(screen.getAllByRole('alert').some((item) => item.textContent?.includes('controlled unavailable'))).toBe(true));
    expect(screen.queryByRole('button', { name: 'Register asset' })).not.toBeInTheDocument();
    expect(screen.getByText('Read only')).toBeInTheDocument();
  });

  it('launches only an asset-bound execution after reconfirmation', async () => {
    const job = { id: 'c'.repeat(32), audit_type: 'active_dns_inventory', active_asset_id: asset.id, active_authorization_contract: '2026-09-09.1', active_authorization_revision_id: 'e'.repeat(32), active_authorization_revision_digest_sha256: 'f'.repeat(64), active_authorization_revision_sequence: 1, target_url: '[REDACTED_DOMAIN]', target_domain: null, status: 'completed', created_at: '2026-09-01T10:01:00Z', updated_at: '2026-09-01T10:01:00Z', source_file_deleted_at: null, result: {}, error: null };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/active/assets/search')) return Promise.resolve(activeGet(input, [asset], init));
      if (!init?.method) return Promise.resolve(activeGet(input, [asset], init));
      return Promise.resolve(response(job, 202));
    });
    const onJobCreated = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    render(<ActiveOperationsCenter canManage onJobCreated={onJobCreated} />);
    await screen.findByRole('heading', { name: 'example.test' });
    fireEvent.click(screen.getByRole('button', { name: 'Details' }));
    expect(screen.getByRole('button', { name: 'Run authorized check' })).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I reconfirm the authorization/));
    fireEvent.click(screen.getByRole('button', { name: 'Run authorized check' }));
    await waitFor(() => expect(onJobCreated).toHaveBeenCalledWith(expect.objectContaining({ active_asset_id: asset.id })));
    expect(onJobCreated).toHaveBeenCalledWith(expect.objectContaining({ active_authorization_revision_sequence: 1, active_authorization_revision_id: 'e'.repeat(32) }));
    const executionCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith(`/active/assets/${asset.id}/executions`));
    expect(JSON.parse(String(executionCall?.[1]?.body))).toEqual({
      capability: 'active_dns_inventory',
      authorization_reconfirmed: true,
      idempotency_key: expect.stringMatching(/^[a-f0-9]{32}$/),
    });
    expect(String(executionCall?.[1]?.body)).not.toContain('example.test');
  });

  it('shows comparable posture, selects a baseline, triages an observation and exports', async () => {
    const executions = [
      { id: 'd'.repeat(32), audit_type: 'active_nmap_basic', active_asset_id: asset.id, active_authorization_contract: '2026-09-09.1', active_authorization_revision_id: 'e'.repeat(32), active_authorization_revision_digest_sha256: 'f'.repeat(64), active_authorization_revision_sequence: 1, target_url: '[REDACTED_TARGET]', target_domain: null, status: 'completed', created_at: '2026-09-01T10:02:00Z', updated_at: '2026-09-01T10:02:00Z', source_file_deleted_at: null, summary: {}, status_detail: { code: 'completed', message: 'Completed', next_action: 'view_results' } },
      { id: 'c'.repeat(32), audit_type: 'active_nmap_basic', active_asset_id: asset.id, active_authorization_contract: '2026-09-09.1', active_authorization_revision_id: 'e'.repeat(32), active_authorization_revision_digest_sha256: 'f'.repeat(64), active_authorization_revision_sequence: 1, target_url: '[REDACTED_TARGET]', target_domain: null, status: 'completed', created_at: '2026-09-01T10:01:00Z', updated_at: '2026-09-01T10:01:00Z', source_file_deleted_at: null, summary: {}, status_detail: { code: 'completed', message: 'Completed', next_action: 'view_results' } },
    ];
    const posture = { ...emptyPosture, executions, posture: { ...emptyPosture.posture, execution_count: 2, counts: { completed: 2, failed: 0, cancelled: 0 }, comparison: { state: 'ready', capability: 'active_nmap_basic', base_execution_id: executions[1].id, target_execution_id: executions[0].id, summary: { new: 1, changed: 0, disappeared: 1, persistent: 0 }, changes: [{ kind: 'new', signal: 'tcp_port:443', before: null, after: 'open', interpretation: 'New TCP port observation; validate service ownership and intended exposure.' }], changes_truncated: false, coverage: {} } } };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/active/verification/configuration')) return Promise.resolve(response(verificationConfiguration));
      if (url.endsWith('/active/operations/summary')) return Promise.resolve(response(operationsSummary));
      if (url.endsWith('/verification')) return Promise.resolve(response(null));
      if (url.endsWith('/posture')) return Promise.resolve(response(posture));
      if (url.endsWith('/baseline') || url.endsWith('/triage')) return Promise.resolve(response({ ...asset, baseline_execution_id: executions[1].id }));
      return Promise.resolve(activeGet(input, [asset], init));
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<ActiveOperationsCenter canManage />);
    await screen.findByRole('heading', { name: 'example.test' });
    fireEvent.click(screen.getByRole('button', { name: 'Details' }));
    expect(await screen.findByText(/New TCP port observation/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Export Markdown' })).toHaveAttribute('href', expect.stringContaining(`/active/assets/${asset.id}/report`));
    fireEvent.click(screen.getAllByRole('button', { name: 'Use baseline' })[0]);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('/baseline'), expect.objectContaining({ method: 'POST' })));
    fireEvent.change(screen.getByLabelText('Triage tcp_port:443'), { target: { value: 'expected_change' } });
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('/triage'), expect.objectContaining({ method: 'POST' })));
    const triageCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith('/triage'));
    expect(JSON.parse(String(triageCall?.[1]?.body))).toEqual({ observation_key: 'tcp_port:443', status: 'expected_change', comment_code: 'planned_change' });
  });

  it('keeps an old baseline visible and pages execution history after a recoverable error', async () => {
    const oldBaseline = { id: '1'.repeat(32), audit_type: 'active_dns_inventory', active_asset_id: asset.id, active_authorization_contract: '2026-09-09.1', active_authorization_revision_id: 'e'.repeat(32), active_authorization_revision_digest_sha256: 'f'.repeat(64), active_authorization_revision_sequence: 1, target_url: '[REDACTED_DOMAIN]', target_domain: null, status: 'completed', created_at: '2026-08-01T10:00:00Z', updated_at: '2026-08-01T10:00:00Z', source_file_deleted_at: null, summary: {}, status_detail: { code: 'completed', message: 'Completed', next_action: 'view_results' } };
    const latest = { ...oldBaseline, id: '3'.repeat(32), created_at: '2026-09-03T10:00:00Z', updated_at: '2026-09-03T10:00:00Z' };
    const middle = { ...oldBaseline, id: '2'.repeat(32), created_at: '2026-09-02T10:00:00Z', updated_at: '2026-09-02T10:00:00Z' };
    const scopedAsset = { ...asset, baseline_execution_id: oldBaseline.id };
    const posture = {
      ...emptyPosture,
      asset: scopedAsset,
      executions: [latest],
      baseline_execution: oldBaseline,
      history: { returned_count: 1, total_count: 3, has_more: true, next_cursor: 'opaque-cursor', posture_records_considered: 3, posture_incomplete: false },
      posture: { ...emptyPosture.posture, execution_count: 3, baseline_execution_id: oldBaseline.id },
    };
    let continuationAttempts = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/active/verification/configuration')) return Promise.resolve(response(verificationConfiguration));
      if (url.endsWith('/active/operations/summary')) return Promise.resolve(response(operationsSummary));
      if (url.endsWith('/verification')) return Promise.resolve(response(null));
      if (url.endsWith('/posture')) return Promise.resolve(response(posture));
      if (url.endsWith('/executions/search')) {
        continuationAttempts += 1;
        return Promise.resolve(continuationAttempts === 1
          ? response({ detail: 'Execution history is temporarily unavailable.' }, 503)
          : response({ contract_version: '2026-09-08.1', items: [middle, oldBaseline], returned_count: 2, total_count: 3, has_more: false, next_cursor: null }));
      }
      return Promise.resolve(activeGet(input, [scopedAsset], init));
    });
    vi.stubGlobal('fetch', fetchMock);
    const view = render(<ActiveOperationsCenter canManage />);
    await screen.findByRole('heading', { name: 'example.test' });
    fireEvent.click(screen.getByRole('button', { name: 'Details' }));
    expect(await screen.findByText(/Showing 1 of 3 retained executions/)).toBeInTheDocument();
    expect(screen.getByText('Selected')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Load older executions (1 of 3)' }));
    await waitFor(() => expect(screen.getAllByRole('alert').some((item) => item.textContent?.includes('Execution history is temporarily unavailable.'))).toBe(true));
    expect(screen.getByText('Selected')).toBeInTheDocument();
    const retry = screen.getByRole('button', { name: 'Load older executions (1 of 3)' });
    fireEvent.click(retry);

    expect(await screen.findByRole('button', { name: 'All retained executions are loaded' })).toHaveAttribute('aria-disabled', 'true');
    expect(screen.getByText(/Showing 3 of 3 retained executions/)).toBeInTheDocument();
    await waitFor(() => expect(retry).toHaveFocus());
    const continuationCalls = fetchMock.mock.calls.filter(([input]) => String(input).endsWith('/executions/search'));
    expect(continuationCalls).toHaveLength(2);
    expect(String(continuationCalls[0][0])).not.toContain('opaque-cursor');
    expect(JSON.parse(String(continuationCalls[0][1]?.body))).toEqual({ page_size: 50, cursor: 'opaque-cursor' });
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('shows durable progress and provides scoped cancel and retry actions', async () => {
    const queued = { id: '1'.repeat(32), audit_type: 'active_dns_inventory', active_asset_id: asset.id, active_execution_phase: 'waiting_for_runner', target_url: '[REDACTED_DOMAIN]', target_domain: null, status: 'queued', created_at: '2026-09-01T10:02:00Z', updated_at: '2026-09-01T10:02:00Z', source_file_deleted_at: null, summary: null };
    const failed = { ...queued, id: '2'.repeat(32), active_execution_phase: 'terminal', status: 'failed', termination_reason: 'runner_unavailable' };
    const posture = { ...emptyPosture, executions: [queued, failed], posture: { ...emptyPosture.posture, execution_count: 2, counts: { completed: 0, failed: 1, cancelled: 0 } } };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/active/verification/configuration')) return Promise.resolve(response(verificationConfiguration));
      if (url.endsWith('/active/operations/summary')) return Promise.resolve(response(operationsSummary));
      if (url.endsWith('/verification')) return Promise.resolve(response(null));
      if (url.endsWith('/posture')) return Promise.resolve(response(posture));
      if (url.endsWith('/cancel')) return Promise.resolve(response({ ...queued, status: 'cancelling' }));
      if (url.endsWith('/retry')) return Promise.resolve(response({ ...queued, id: '3'.repeat(32), retry_of_job_id: failed.id }, 202));
      return Promise.resolve(activeGet(input, [asset], init));
    });
    vi.stubGlobal('fetch', fetchMock);
    vi.stubGlobal('confirm', vi.fn(() => true));
    const view = render(<ActiveOperationsCenter canManage />);
    await screen.findByRole('heading', { name: 'example.test' });
    fireEvent.click(screen.getByRole('button', { name: 'Details' }));
    expect(await screen.findByText('Waiting for isolated runner')).toBeInTheDocument();
    expect(screen.getByText('Stopped with a controlled error')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(expect.stringMatching(/\/cancel$/), expect.objectContaining({ method: 'POST' })));
    fireEvent.click(screen.getByRole('button', { name: 'Retry safely' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(expect.stringMatching(/\/retry$/), expect.objectContaining({ method: 'POST' })));
    const retryCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith('/retry'));
    expect(JSON.parse(String(retryCall?.[1]?.body))).toEqual({ authorization_reconfirmed: true, idempotency_key: expect.stringMatching(/^[a-f0-9]{32}$/) });
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('shows operator policy and completes a one-time manual control verification', async () => {
    const enabledConfiguration = { ...verificationConfiguration, enabled: true, remote_runner_ready: true, methods: { ...verificationConfiguration.methods, manual_attestation: true, dns_txt: true, http_well_known: true } };
    const pending = { contract_version: '2026-09-09.1', id: 'e'.repeat(32), asset_id: asset.id, method: 'manual_attestation', status: 'pending', created_at: '2026-09-01T10:00:00Z', challenge_expires_at: '2099-09-01T10:15:00Z', attempts: 0, last_attempt_at: null, verified_at: null, verification_expires_at: null, revoked_at: null, reason_code: null };
    const verified = { ...pending, status: 'verified', attempts: 1, verified_at: '2026-09-01T10:01:00Z', verification_expires_at: '2099-09-30T10:00:00Z', reason_code: 'matched' };
    const challenge = { verification: pending, challenge_token: `iv1_${'x'.repeat(32)}`, placement: 'Inspectra manual attestation', one_time_display: true, legal_authorization_established: false };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/active/verification/configuration')) return Promise.resolve(response(enabledConfiguration));
      if (url.endsWith('/active/operations/summary')) return Promise.resolve(response(operationsSummary));
      if (url.endsWith('/posture')) return Promise.resolve(response(emptyPosture));
      if (url.endsWith('/verification/challenge')) return Promise.resolve(response(challenge, 201));
      if (url.endsWith('/verification/check')) return Promise.resolve(response(verified));
      if (url.endsWith('/verification')) return Promise.resolve(response(null));
      return Promise.resolve(activeGet(input, [asset], init));
    });
    vi.stubGlobal('fetch', fetchMock);
    const view = render(<ActiveOperationsCenter canManage />);
    expect(await screen.findByText(/Control verification: operator enabled/)).toBeInTheDocument();
    expect(screen.getByText(/Remote DNS\/HTTP verification runner: ready/)).toBeInTheDocument();
    await screen.findByRole('heading', { name: 'example.test' });
    fireEvent.click(screen.getByRole('button', { name: 'Details' }));
    await screen.findByText(/Optional control verification/);
    fireEvent.click(screen.getByRole('button', { name: 'Create bounded challenge' }));
    expect(await screen.findByText(challenge.challenge_token)).toBeInTheDocument();
    expect(screen.getByText(/stores only its SHA-256 digest/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Check exact challenge' })).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I attest again/));
    fireEvent.click(screen.getByRole('button', { name: 'Check exact challenge' }));
    expect((await screen.findAllByText('verified')).length).toBeGreaterThanOrEqual(1);
    const checkCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith('/verification/check'));
    expect(JSON.parse(String(checkCall?.[1]?.body))).toEqual({ verification_id: pending.id, challenge_token: challenge.challenge_token, manual_attestation_confirmed: true });
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('appends a renewal revision and requires a separate expansion confirmation', async () => {
    const renewedAsset: ActiveAsset = {
      ...asset,
      capabilities: ['active_dns_inventory', 'active_dns_osint'],
      updated_at: '2026-09-02T10:00:00Z',
      history: [...asset.history, { id: '6'.repeat(32), kind: 'renewed', occurred_at: '2026-09-02T10:00:00Z', actor_id: 'local-admin', reason_code: 'scope_expanded' }],
      authorization_revisions: [...(asset.authorization_revisions ?? []), { ...asset.authorization_revisions![0], id: '7'.repeat(32), sequence: 2, source: 'renewal', scope_expanded: true, created_at: '2026-09-02T10:00:00Z', authorized_at: '2026-09-02T10:00:00Z', capabilities: ['active_dns_inventory', 'active_dns_osint'], digest_sha256: '8'.repeat(64) }],
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === 'POST' && String(input).endsWith(`/active/assets/${asset.id}/renew`)) return Promise.resolve(response({ asset: renewedAsset, replayed: false, scope_expanded: true }));
      return Promise.resolve(activeGet(input, [asset], init));
    });
    vi.stubGlobal('fetch', fetchMock);
    const view = render(<ActiveOperationsCenter canManage />);
    await screen.findByRole('heading', { name: 'example.test' });
    fireEvent.click(screen.getByRole('button', { name: 'Details' }));
    fireEvent.click(screen.getByRole('button', { name: 'Renew authorization' }));
    expect(screen.getByText('Next revision 2')).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText(/DNS public signals/));
    const submit = screen.getByRole('button', { name: 'Append authorization revision' });
    fireEvent.click(screen.getByLabelText(/I re-attest that this exact asset/));
    expect(submit).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I specifically authorize the newly added capability/));
    expect(submit).toBeEnabled();
    fireEvent.click(submit);
    expect(await screen.findByText(/Authorization revision 2 appended with explicitly confirmed expanded scope/)).toBeInTheDocument();
    const renewalCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith(`/active/assets/${asset.id}/renew`));
    const body = JSON.parse(String(renewalCall?.[1]?.body));
    expect(body).toMatchObject({ expected_revision_id: 'e'.repeat(32), responsible_user_ids: [], capabilities: ['active_dns_inventory', 'active_dns_osint'], scope_expansion_confirmed: true, renewal_confirmed: true });
    expect(body.idempotency_key).toMatch(/^[a-f0-9]{32}$/);
    expect(body).not.toHaveProperty('value');
    expect(JSON.stringify(body)).not.toContain('example.test');
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('labels legacy authorization evidence as unknown and blocks execution controls', async () => {
    const legacyAsset = { ...asset, id: '9'.repeat(32), authorization_revisions: [] };
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => Promise.resolve(activeGet(input, [legacyAsset], init))));
    render(<ActiveOperationsCenter canManage />);
    await screen.findByRole('heading', { name: 'example.test' });
    fireEvent.click(screen.getByRole('button', { name: 'Details' }));
    expect(screen.getByText(/Legacy \/ unknown · re-attestation required/)).toBeInTheDocument();
    expect(screen.getByText(/This legacy authorization has no immutable revision/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Re-attest authorization' })).toBeEnabled();
    expect(screen.queryByRole('button', { name: 'Run authorized check' })).not.toBeInTheDocument();
  });

  it('renders and decides a target-bounded four-eyes review without sensitive fields', async () => {
    const fourEyesSummary = {
      ...operationsSummary,
      configuration: { ...operationsSummary.configuration, four_eyes_enabled: true },
    };
    let approvalStatus = 'pending';
    const approval = () => ({
      contract_version: '2026-09-10.1', id: '4'.repeat(32), asset_id: null,
      kind: 'registration', status: approvalStatus, operation_digest_prefix: '1'.repeat(12),
      requested_at: '2026-09-10T10:00:00Z', expires_at: '2026-09-11T10:00:00Z',
      decided_at: approvalStatus === 'approved' ? '2026-09-10T10:05:00Z' : null,
      consumed_at: null, requested_by_current_user: false,
      can_approve: approvalStatus === 'pending', can_apply: false,
      summary: { asset_type: 'domain', review_target: 'reviewed.example.test', scope_change: 'new_registration', capabilities: ['active_dns_inventory'], allowed_ports: [], allowed_protocols: ['dns'], authorization_expires_at: '2026-10-10T10:00:00Z', reason_code: null },
    });
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/active/operations/summary')) return Promise.resolve(response(fourEyesSummary));
      if (url.endsWith('/active/change-approvals') && !init?.method) return Promise.resolve(response({ contract_version: '2026-09-10.1', enabled: true, items: [approval()], pending_count: approvalStatus === 'pending' ? 1 : 0, privacy: 'no_notes_references_responsible_identities_or_complete_payload' }));
      if (url.endsWith(`/active/change-approvals/${'4'.repeat(32)}/approve`)) { approvalStatus = 'approved'; return Promise.resolve(response(approval())); }
      return Promise.resolve(activeGet(input, [asset], init));
    });
    vi.stubGlobal('fetch', fetchMock);
    const view = render(<ActiveOperationsCenter canManage teamMode currentRole="administrator" currentUserId={'3'.repeat(32)} />);

    expect(await screen.findByRole('heading', { name: 'Four-eyes approvals' })).toBeInTheDocument();
    expect(screen.getByText('reviewed.example.test')).toBeInTheDocument();
    expect(screen.getByText(/Authorization references, notes, responsible account identities/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Approve exact change' }));
    await waitFor(() => expect(screen.getByText('approved')).toBeInTheDocument());
    expect(fetchMock).toHaveBeenCalledWith(expect.stringMatching(/\/approve$/), expect.objectContaining({ method: 'POST' }));
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });
});
