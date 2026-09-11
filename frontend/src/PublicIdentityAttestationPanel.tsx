import { FormEvent, useCallback, useEffect, useState } from 'react';

import { ApiError, api } from './api';
import type { PublicIdentityAttestation, PublicIdentityEcosystem, TeamRole } from './types';

const ecosystems: PublicIdentityEcosystem[] = ['npm', 'pypi', 'go', 'cargo', 'composer', 'maven', 'nuget'];

export function PublicIdentityAttestationPanel({ role }: { role: TeamRole }) {
  const [items, setItems] = useState<PublicIdentityAttestation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [ecosystem, setEcosystem] = useState<PublicIdentityEcosystem>('npm');
  const [packageName, setPackageName] = useState('');
  const [ttlDays, setTtlDays] = useState(30);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setItems(await api.listPublicIdentityAttestations());
    } catch (reason) {
      setError(messageFor(reason));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  async function propose(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusyId('new');
    setError(null);
    try {
      await api.proposePublicIdentityAttestation(ecosystem, packageName, ttlDays);
      setPackageName('');
      await refresh();
    } catch (reason) {
      setError(messageFor(reason));
    } finally {
      setBusyId(null);
    }
  }

  async function mutate(item: PublicIdentityAttestation, action: 'approve' | 'revoke') {
    setBusyId(item.id);
    setError(null);
    try {
      if (action === 'approve') await api.approvePublicIdentityAttestation(item.id);
      else await api.revokePublicIdentityAttestation(item.id);
      await refresh();
    } catch (reason) {
      setError(messageFor(reason));
    } finally {
      setBusyId(null);
    }
  }

  return (
    <section className="public-identity-attestations" aria-labelledby="public-identity-attestations-title">
      <div>
        <h3 id="public-identity-attestations-title">Public package approvals</h3>
        <p className="muted">
          Approval is a second, workspace-specific gate. It never overrides the operator allowlist or source checks;
          only an exact normalized package identity already present in this workspace can become eligible for OSV.
        </p>
      </div>

      {role !== 'reader' ? (
        <form className="public-identity-attestation-form" onSubmit={(event) => void propose(event)}>
          <label>
            Ecosystem
            <select value={ecosystem} onChange={(event) => setEcosystem(event.target.value as PublicIdentityEcosystem)}>
              {ecosystems.map((value) => <option key={value} value={value}>{ecosystemLabel(value)}</option>)}
            </select>
          </label>
          <label>
            Exact public package name
            <input
              value={packageName}
              onChange={(event) => setPackageName(event.target.value)}
              maxLength={321}
              autoComplete="off"
              spellCheck={false}
              required
            />
          </label>
          <label>
            Approval lifetime
            <select value={ttlDays} onChange={(event) => setTtlDays(Number(event.target.value))}>
              <option value={7}>7 days</option>
              <option value={30}>30 days</option>
              <option value={90}>90 days</option>
            </select>
          </label>
          <button type="submit" disabled={busyId !== null || packageName.trim().length === 0}>
            {busyId === 'new' ? 'Proposing…' : 'Propose exact identity'}
          </button>
          <p className="muted">Maintainers may propose. An administrator must approve before egress; approval expires automatically.</p>
        </form>
      ) : <p className="query-warning">Reader access can review approvals but cannot propose, approve or revoke them.</p>}

      {loading ? <p className="muted" role="status">Loading public package approvals…</p> : null}
      {error ? <p className="error-text" role="alert">{error} <button className="inline-button" onClick={() => void refresh()}>Retry</button></p> : null}
      {!loading && !error && items.length === 0 ? (
        <p className="empty-state">No package identity is approved for this workspace. Eligible components remain local.</p>
      ) : null}
      {items.length > 0 ? (
        <ul className="public-identity-attestation-list" aria-label="Public package approvals">
          {items.map((item) => (
            <li key={item.id}>
              <div>
                <strong>{ecosystemLabel(item.ecosystem)} · <code>{item.package_name}</code></strong>
                <span className={`status-pill ${item.status === 'approved' ? 'ok' : ''}`}>{statusLabel(item.status)}</span>
                <p className="muted">Revision {item.revision} · requested {item.requested_ttl_days} days{item.expires_at ? ` · expires ${formatDate(item.expires_at)}` : ''}</p>
              </div>
              {role === 'administrator' && item.status === 'pending' ? (
                <div className="public-identity-attestation-actions">
                  <button disabled={busyId !== null} onClick={() => void mutate(item, 'approve')}>Approve for OSV</button>
                  <button className="danger-button" disabled={busyId !== null} onClick={() => void mutate(item, 'revoke')}>Reject proposal</button>
                </div>
              ) : null}
              {role === 'administrator' && item.status === 'approved' ? (
                <button className="danger-button" disabled={busyId !== null} onClick={() => void mutate(item, 'revoke')}>Revoke immediately</button>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}

function ecosystemLabel(value: PublicIdentityEcosystem): string {
  return ({ npm: 'npm', pypi: 'PyPI', go: 'Go', cargo: 'Cargo', composer: 'Composer', maven: 'Maven', nuget: 'NuGet' })[value];
}

function statusLabel(value: PublicIdentityAttestation['status']): string {
  return ({ pending: 'Pending review', approved: 'Approved', expired: 'Expired', revoked: 'Revoked' })[value];
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'at a recorded time' : date.toLocaleString();
}

function messageFor(reason: unknown): string {
  if (reason instanceof ApiError && reason.status === 401) return 'Your session expired. Sign in again.';
  if (reason instanceof Error && reason.message) return reason.message;
  return 'Public package approvals could not be updated.';
}
