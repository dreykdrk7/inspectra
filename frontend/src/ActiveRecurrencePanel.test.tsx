import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import axe from 'axe-core';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ActiveRecurrencePanel } from './ActiveRecurrencePanel';
import type { ActiveAsset, ActiveAssetVerification, ActiveRecurrence } from './types';

const assetId = 'a'.repeat(32);
const schedule: ActiveRecurrence = {
  contract_version: '2026-09-08.2', id: 'b'.repeat(32), asset_id: assetId,
  capability: 'active_dns_inventory', port: null, interval_days: 7,
  timezone_name: 'Europe/Madrid', window_weekdays: ['monday'], window_start_hour: 9, window_duration_hours: 4,
  authorization_revision_id: 'c'.repeat(32), authorization_revision_sequence: 2,
  authorization_expires_at: '2026-10-08T12:00:00Z',
  verification_id: 'd'.repeat(32), status: 'active', reason_code: 'scheduled',
  next_run_at: '2026-09-15T12:00:00Z', last_scheduled_at: null, last_job_id: null,
  failure_count: 0, next_retry_at: null, last_attempt_at: null, last_outcome: 'never',
  created_at: '2026-09-08T12:00:00Z', updated_at: '2026-09-08T12:00:00Z',
};
const asset = {
  id: assetId, status: 'active', capabilities: ['active_dns_inventory'], allowed_ports: [],
  authorization_revisions: [{ id: 'c'.repeat(32), sequence: 2 }],
} as unknown as ActiveAsset;
const verification = { id: 'd'.repeat(32), status: 'verified' } as ActiveAssetVerification;

function response(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), { status, headers: { 'content-type': 'application/json' } });
}

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe('ActiveRecurrencePanel', () => {
  it('explains the safe default and offers no scheduling action', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(response({ contract_version: '2026-09-08.2', enabled: false, items: [] }))));
    const view = render(<ActiveRecurrencePanel asset={asset} verification={verification} canManage />);
    expect(await screen.findByText(/disabled by default/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Schedule recurring review' })).not.toBeInTheDocument();
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('creates, pauses and deletes a target-free schedule with explicit confirmations', async () => {
    let current: ActiveRecurrence[] = [];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (!init?.method || init.method === 'GET') return Promise.resolve(response({ contract_version: '2026-09-08.2', enabled: true, items: current }));
      if (url.endsWith('/recurrences')) { current = [schedule]; return Promise.resolve(response(schedule, 201)); }
      if (url.endsWith('/pause')) { current = [{ ...schedule, status: 'paused', reason_code: 'operator_paused', updated_at: '2026-09-08T12:01:00Z' }]; return Promise.resolve(response(current[0])); }
      if (init.method === 'DELETE') { current = []; return Promise.resolve(new Response(null, { status: 204 })); }
      return Promise.resolve(response({ detail: 'unexpected request' }, 500));
    });
    vi.stubGlobal('fetch', fetchMock);
    const view = render(<ActiveRecurrencePanel asset={asset} verification={verification} canManage />);
    const create = await screen.findByRole('button', { name: 'Schedule recurring review' });
    expect(create).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I authorize future bounded runs/));
    fireEvent.click(create);
    expect(await screen.findByText(/Recurring review scheduled/)).toBeInTheDocument();
    expect(screen.getByText(/Monday · 09:00–13:00 · Europe\/Madrid/i)).toBeInTheDocument();
    expect(screen.getByText('No deferred retry')).toBeInTheDocument();
    expect(screen.getByText(/already has a schedule/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Schedule recurring review' })).toBeDisabled();
    const createCall = fetchMock.mock.calls.find(([input, init]) => String(input).endsWith('/recurrences') && init?.method === 'POST');
    const payload = JSON.parse(String(createCall?.[1]?.body));
    expect(payload).toMatchObject({ capability: 'active_dns_inventory', interval_days: 7, timezone_name: expect.any(String), window_weekdays: [expect.any(String)], window_start_hour: expect.any(Number), window_duration_hours: expect.any(Number), recurrence_confirmed: true });
    expect(JSON.stringify(payload)).not.toContain('target');

    fireEvent.click(screen.getByRole('button', { name: 'Pause future runs' }));
    expect(await screen.findByRole('button', { name: 'Resume with current authorization' })).toBeInTheDocument();
    expect(screen.getByText('None — resuming recalculates the next window')).toBeInTheDocument();
    const remove = screen.getByRole('button', { name: 'Remove future runs' });
    expect(remove).toBeDisabled();
    fireEvent.click(screen.getByLabelText('Remove this schedule permanently'));
    fireEvent.click(remove);
    await waitFor(() => expect(screen.getByText(/No recurring review is configured/)).toBeInTheDocument());
    const deleteCall = fetchMock.mock.calls.find(([, init]) => init?.method === 'DELETE');
    expect(JSON.parse(String(deleteCall?.[1]?.body))).toEqual({ confirmation: 'DELETE ACTIVE SCHEDULE' });
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });

  it('explains authorization suspension without advertising an executable date', async () => {
    const suspended: ActiveRecurrence = {
      ...schedule,
      status: 'suspended',
      reason_code: 'authorization_unavailable',
      failure_count: 3,
      next_retry_at: null,
      last_outcome: 'runner_unavailable',
    };
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(response({
      contract_version: '2026-09-08.2', enabled: true, items: [suspended],
    }))));
    const view = render(<ActiveRecurrencePanel asset={asset} verification={verification} canManage />);
    expect(await screen.findByText('None — authorization must be re-attested')).toBeInTheDocument();
    expect(screen.getByText(/runner unavailable · attempt 3 · pending/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Resume with current authorization' })).toBeInTheDocument();
    expect((await axe.run(view.container)).violations).toHaveLength(0);
  });
});
