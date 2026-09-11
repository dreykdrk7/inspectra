import { FormEvent, useRef, useState } from 'react';

import { createActiveAssetBatch, createIdempotencyKey, preflightActiveAssetBatch } from './api';
import type { ActiveAssetBatchPreflight } from './types';


const MAX_BATCH_BYTES = 128 * 1024;

type Props = {
  onCompleted: () => void | Promise<void>;
  onCancel: () => void;
};

export function ActiveAssetBatchForm({ onCompleted, onCancel }: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [review, setReview] = useState<ActiveAssetBatchPreflight | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const idempotencyKey = useRef<string | null>(null);

  function selectFile(selected: File | null) {
    setReview(null);
    setConfirmed(false);
    setNotice(null);
    idempotencyKey.current = null;
    if (!selected) {
      setFile(null);
      setError(null);
      return;
    }
    if (!/\.(?:json|csv)$/i.test(selected.name)) {
      setFile(null);
      setError('Choose a .json or .csv inventory. Other formats are not parsed.');
      return;
    }
    if (selected.size > MAX_BATCH_BYTES) {
      setFile(null);
      setError('The inventory exceeds the 128 KiB batch limit. Split it into smaller authorized batches.');
      return;
    }
    setFile(selected);
    setError(null);
  }

  async function preflight(event: FormEvent) {
    event.preventDefault();
    if (!file) return;
    setLoading(true);
    setError(null);
    setNotice(null);
    try {
      setReview(await preflightActiveAssetBatch(file));
      setConfirmed(false);
      idempotencyKey.current = null;
    } catch (caught) {
      setReview(null);
      setError(caught instanceof Error ? caught.message : 'The batch could not be reviewed.');
    } finally {
      setLoading(false);
    }
  }

  async function commit() {
    if (!file || !review?.can_confirm || !review.preflight_token || !confirmed) return;
    setLoading(true);
    setError(null);
    setNotice(null);
    const key = idempotencyKey.current ?? createIdempotencyKey();
    idempotencyKey.current = key;
    try {
      const result = await createActiveAssetBatch(file, review.preflight_token, key);
      setNotice(result.replayed
        ? `Recovered the same ${result.created_count}-asset batch without creating duplicates.`
        : `Registered ${result.created_count} authorized assets atomically.`);
      setConfirmed(false);
      await onCompleted();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'The batch could not be registered.');
    } finally {
      setLoading(false);
    }
  }

  return <section className="active-asset-form active-batch-form" aria-labelledby="active-batch-title" aria-busy={loading}>
    <div className="active-form-heading">
      <div>
        <h3 id="active-batch-title">Import authorized asset batch</h3>
        <p>Review up to 50 exact assets before one all-or-nothing registration. The source is parsed in local Inspectra memory and is never retained.</p>
      </div>
      <span className="status-pill">JSON or CSV · 128 KiB</span>
    </div>
    <form className="active-batch-picker" onSubmit={(event) => void preflight(event)}>
      <label>
        <span>Authorized asset inventory</span>
        <input type="file" accept=".json,.csv,application/json,text/csv" onChange={(event) => selectFile(event.target.files?.[0] ?? null)} />
      </label>
      <button type="submit" disabled={!file || loading}>{loading && !review ? 'Reviewing…' : 'Review batch'}</button>
      <button type="button" className="secondary-button" onClick={onCancel} disabled={loading}>Cancel</button>
    </form>
    <details>
      <summary>Expected file contract</summary>
      <p className="muted">JSON is an array of the same closed objects used by single registration. CSV requires these columns; list values use <code>|</code> and optional notes contain a JSON array.</p>
      <code className="active-batch-header">asset_type,value,responsible_user_ids,capabilities,allowed_ports,allowed_protocols,authorization_method,authorization_reference,authorized_at,expires_at,notes</code>
    </details>
    {review ? <div className="active-batch-review">
      <div className="active-center-metrics" aria-label="Batch preflight summary">
        <Metric label="Input" value={review.input_count} />
        <Metric label="Ready" value={review.ready_count} />
        <Metric label="Invalid" value={review.invalid_count} />
        <Metric label="Duplicates" value={review.duplicate_count} />
        <Metric label="Already registered" value={review.conflict_count} />
      </div>
      <p className={review.can_confirm ? 'success-text' : 'warning-text'} role="status">
        <strong>{review.can_confirm ? 'Ready for atomic registration.' : 'Corrections required.'}</strong>{' '}
        Review digest <code>{review.review_digest_sha256.slice(0, 12)}…</code>. Any file change requires a new preflight.
      </p>
      <div className="table-wrap" role="region" aria-label="Asset batch row review" tabIndex={0}>
        <table><thead><tr><th>Row</th><th>Exact asset</th><th>Type</th><th>State</th></tr></thead><tbody>
          {review.rows.map((row) => <tr key={row.row}>
            <td>{row.row}</td>
            <td>{row.canonical_value ?? 'Withheld — invalid contract'}</td>
            <td>{row.asset_type?.replace('_', ' ') ?? 'Unknown'}</td>
            <td>{batchRowLabel(row.reason_code)}</td>
          </tr>)}
        </tbody></table>
      </div>
      {review.can_confirm ? <label className="checkbox-row">
        <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
        I reviewed every exact asset, capability, port and authorization window and confirm this whole batch is currently authorized.
      </label> : <p className="empty-state">Correct invalid, duplicate or already registered rows and run preflight again. Inspectra will not silently skip rows.</p>}
      <button type="button" onClick={() => void commit()} disabled={!confirmed || loading || !review.can_confirm || !review.preflight_token}>
        {loading && review ? 'Registering batch…' : 'Register entire batch'}
      </button>
    </div> : null}
    {notice ? <p className="success-text" role="status">{notice}</p> : null}
    {error ? <p className="error-text" role="alert">{error}</p> : null}
  </section>;
}

function batchRowLabel(code: ActiveAssetBatchPreflight['rows'][number]['reason_code']): string {
  if (code === 'ready') return 'Ready';
  if (code === 'duplicate_identity') return 'Duplicate in this file';
  if (code === 'identity_already_registered') return 'Already registered';
  return 'Invalid closed contract';
}

function Metric({ label, value }: { label: string; value: number }) {
  return <div><strong>{value}</strong><span>{label}</span></div>;
}
