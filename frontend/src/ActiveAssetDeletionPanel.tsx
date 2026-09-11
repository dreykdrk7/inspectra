import { useState } from 'react';

import { ApiError, deleteActiveAsset, getActiveAssetDeletionPreview } from './api';
import type { ActiveAssetDeletionPreview, ActiveAssetDeletionScopeItem } from './types';

type Props = {
  assetId: string;
  onDeleted: () => void | Promise<void>;
};

export function ActiveAssetDeletionPanel({ assetId, onDeleted }: Props) {
  const [preview, setPreview] = useState<ActiveAssetDeletionPreview | null>(null);
  const [reviewing, setReviewing] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState('');

  const review = async () => {
    setReviewing(true);
    setError('');
    try {
      setPreview(await getActiveAssetDeletionPreview(assetId));
    } catch (caught) {
      setError(deletionMessage(caught, 'preview'));
    } finally {
      setReviewing(false);
    }
  };

  const remove = async () => {
    if (!confirmed || preview?.state !== 'ready') return;
    setDeleting(true);
    setError('');
    try {
      await deleteActiveAsset(assetId);
      await onDeleted();
    } catch (caught) {
      setError(deletionMessage(caught, 'delete'));
      try {
        setPreview(await getActiveAssetDeletionPreview(assetId));
      } catch {
        // The primary actionable error remains visible; refresh is best effort.
      }
    } finally {
      setDeleting(false);
    }
  };

  return (
    <section className="active-deletion-panel" aria-labelledby={`active-delete-${assetId}`}>
      <h5 id={`active-delete-${assetId}`}>Data retention and deletion</h5>
      {!preview ? (
        <>
          <p className="muted">Review the exact owner-scoped cascade before removing this asset. Reports are not stored; retained audit history is detached from the target.</p>
          <button type="button" className="secondary-button" onClick={() => void review()} disabled={reviewing}>
            {reviewing ? 'Reviewing deletion scope…' : 'Review deletion scope'}
          </button>
        </>
      ) : (
        <>
          <div className={`notice ${preview.state === 'ready' ? 'info-notice' : 'warning-notice'}`} role="status">
            {preview.state === 'ready'
              ? 'Deletion is ready. This manifest contains counts and policy only; it does not repeat the target.'
              : 'Deletion is blocked. Cancel active executions and revoke pending verification challenges, then review again.'}
          </div>
          <ul className="active-deletion-scope" aria-label="Active asset deletion scope">
            {preview.items.map((item) => <ScopeItem key={item.key} item={item} />)}
          </ul>
          <div className="action-row">
            <button type="button" className="secondary-button" onClick={() => void review()} disabled={reviewing || deleting}>
              {reviewing ? 'Refreshing…' : 'Refresh preflight'}
            </button>
          </div>
          {preview.state === 'ready' ? (
            <div className="danger-zone">
              <label className="checkbox-row">
                <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
                <span>I understand that the asset, authorization revisions, challenges, jobs, observations, baseline and triage will be removed.</span>
              </label>
              <button type="button" className="danger-button" onClick={() => void remove()} disabled={!confirmed || deleting}>
                {deleting ? 'Deleting safely…' : 'Delete asset and retained data'}
              </button>
            </div>
          ) : null}
        </>
      )}
      {error ? <p className="error-text" role="alert">{error}</p> : null}
    </section>
  );
}

function ScopeItem({ item }: { item: ActiveAssetDeletionScopeItem }) {
  const count = item.item_count === null ? 'Policy' : `${item.item_count} ${item.item_count === 1 ? 'item' : 'items'}`;
  const disposition = item.disposition === 'delete' ? 'Delete' : item.disposition === 'anonymize' ? 'Anonymize' : 'Not stored';
  return <li>
    <div><strong>{scopeLabel(item.key)}</strong><span className="status-pill">{disposition}</span></div>
    <small>{count}</small>
    <p className="muted">{item.detail}</p>
  </li>;
}

function scopeLabel(key: ActiveAssetDeletionScopeItem['key']): string {
  return {
    asset_metadata: 'Asset metadata',
    batch_replay_receipts: 'Batch replay receipts',
    recurrence_policies: 'Recurring review policies',
    change_approvals: 'Change approvals',
    authorization_revisions: 'Authorization revisions',
    verification_challenges: 'Verification records',
    execution_jobs: 'Execution jobs',
    execution_results: 'Results and decisions',
    report_exports: 'Report exports',
    product_audit: 'Product audit',
  }[key];
}

function deletionMessage(error: unknown, phase: 'preview' | 'delete'): string {
  if (error instanceof ApiError && error.status === 409) {
    return 'Deletion is blocked by active work. Cancel executions and revoke pending verification challenges before retrying.';
  }
  if (error instanceof ApiError && error.status === 404) return 'This asset is no longer available.';
  if (error instanceof ApiError && error.status === 503) {
    return phase === 'delete'
      ? 'Deletion did not complete. Inspectra retained a safe retry record; check service health and retry.'
      : 'The deletion preflight is temporarily unavailable. Check service health and try again.';
  }
  return phase === 'delete'
    ? 'Unable to delete this asset safely. Review service health and retry.'
    : 'Unable to review the deletion scope. Refresh and try again.';
}
