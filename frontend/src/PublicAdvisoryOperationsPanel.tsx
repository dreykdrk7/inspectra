import { useCallback, useEffect, useState } from 'react';

import { ApiError, api } from './api';
import type { PublicAdvisoryOperations, PublicAdvisoryProviderOperations } from './types';

type State = { loading: boolean; error: string | null };

export function PublicAdvisoryOperationsPanel() {
  const [operations, setOperations] = useState<PublicAdvisoryOperations | null>(null);
  const [state, setState] = useState<State>({ loading: true, error: null });
  const [confirmCleanup, setConfirmCleanup] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setState({ loading: true, error: null });
    try {
      setOperations(await api.getPublicAdvisoryOperations());
      setState({ loading: false, error: null });
    } catch (error) {
      setState({ loading: false, error: messageFor(error) });
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  async function cleanup() {
    setState({ loading: true, error: null });
    setResult(null);
    try {
      const response = await api.purgeExpiredPublicAdvisoryCache();
      setOperations(response.operations);
      setResult(`${response.removed_entries} expired or invalid cache entr${response.removed_entries === 1 ? 'y' : 'ies'} removed.`);
      setConfirmCleanup(false);
      setState({ loading: false, error: null });
    } catch (error) {
      setState({ loading: false, error: messageFor(error) });
    }
  }

  return (
    <section className="public-advisory-operations" aria-labelledby="public-advisory-operations-title">
      <div className="section-heading-row">
        <div>
          <p className="eyebrow">Public intelligence operations</p>
          <h3 id="public-advisory-operations-title">Provider and cache health</h3>
          <p className="muted">Aggregate operational facts only. Package identities, queries, payloads, project names and provider response bodies are never shown here.</p>
        </div>
        {operations ? <span className={`status-pill ${operations.egress_enabled ? 'ok' : ''}`}>{operations.egress_enabled ? 'Egress enabled by operator' : 'Egress disabled'}</span> : null}
      </div>

      {state.loading && !operations ? <p role="status" className="muted">Loading public intelligence operations…</p> : null}
      {state.error ? <div role="alert" className="alert">{state.error} <button className="inline-button" onClick={() => void refresh()}>Retry</button></div> : null}

      {operations ? (
        <>
          <p className="muted" role="status">Offline advisory snapshot: {operations.offline_snapshot_active ? 'active' : 'not active'}.</p>
          <ul className="public-advisory-provider-grid" aria-label="Public advisory provider health">
            {operations.providers.map((provider) => <ProviderCard provider={provider} key={provider.provider} />)}
          </ul>
          <div className="public-advisory-maintenance">
            <p className="muted">Cleanup never contacts a provider and does not remove normalized project findings. It removes only cache entries beyond retention or structurally invalid entries.</p>
            {confirmCleanup ? (
              <div className="team-revoke-confirmation" role="group" aria-label="Confirm public advisory cache cleanup">
                <span>Remove expired or invalid public advisory cache entries now?</span>
                <button onClick={() => void cleanup()} disabled={state.loading}>Confirm cache cleanup</button>
                <button className="secondary-button" onClick={() => setConfirmCleanup(false)} disabled={state.loading}>Keep cache</button>
              </div>
            ) : <button className="secondary-button" onClick={() => setConfirmCleanup(true)} disabled={state.loading}>Review cache cleanup</button>}
            {result ? <p role="status" className="success-text">{result}</p> : null}
          </div>
        </>
      ) : null}
    </section>
  );
}

function ProviderCard({ provider }: { provider: PublicAdvisoryProviderOperations }) {
  const state = provider.invalid_entries > 0 ? 'Attention required' : provider.stale_entries > 0 ? 'Stale cache available' : provider.fresh_entries > 0 ? 'Fresh cache available' : 'No cache';
  return (
    <li className="public-advisory-provider-card">
      <div className="section-heading-row"><strong>{label(provider.provider)}</strong><span className={`status-pill ${provider.configured ? 'ok' : ''}`}>{provider.configured ? 'Configured' : 'Disabled'}</span></div>
      <p>{state}{provider.truncated ? '; counts truncated at the operational limit' : ''}.</p>
      <dl>
        <div><dt>Fresh</dt><dd>{provider.fresh_entries}</dd></div>
        <div><dt>Stale</dt><dd>{provider.stale_entries}</dd></div>
        <div><dt>Invalid</dt><dd>{provider.invalid_entries}</dd></div>
        <div><dt>Cache size</dt><dd>{formatBytes(provider.cache_bytes)}</dd></div>
      </dl>
      <p className="muted">Last cache update: {formatTime(provider.last_updated_at)}</p>
    </li>
  );
}

function label(provider: PublicAdvisoryProviderOperations['provider']): string {
  return ({ osv: 'OSV', github_advisories: 'GitHub Security Advisories', nvd: 'NVD', cisa_kev: 'CISA KEV' })[provider];
}
function formatBytes(value: number): string { return value < 1024 ? `${value} B` : `${(value / 1024).toFixed(1)} KiB`; }
function formatTime(value: string | null): string { if (!value) return 'not recorded'; const date = new Date(value); return Number.isNaN(date.getTime()) ? 'invalid timestamp' : date.toLocaleString(); }
function messageFor(error: unknown): string { if (error instanceof ApiError && error.status === 403) return 'Administrator access is required.'; return error instanceof Error && error.message ? error.message : 'Public intelligence operations are unavailable.'; }
