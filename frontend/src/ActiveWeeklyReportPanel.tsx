import { useEffect, useRef, useState } from 'react';

import {
  createActiveWeeklyReviewReceipt,
  exportActiveWeeklyReport,
  getActiveWeeklyReportPreflight,
  listActiveWeeklyReviewReceipts,
  verifyActiveWeeklyReviewReceipt,
} from './api';
import type {
  ActiveWeeklyReportFormat,
  ActiveWeeklyReportPeriod,
  ActiveWeeklyReportPreflight,
  ActiveWeeklyReviewOutcome,
  ActiveWeeklyReviewReceiptPage,
} from './types';


function preflightErrorMessage(caught: unknown): string {
  if (caught instanceof TypeError) {
    return 'Weekly report preflight is temporarily unavailable. Check the backend connection and try again.';
  }
  return caught instanceof Error ? caught.message : 'Weekly report preflight is temporarily unavailable.';
}


function exportErrorMessage(caught: unknown): string {
  if (caught instanceof TypeError) {
    return 'Weekly report could not be downloaded. Check the backend connection, prepare a new preflight and retry.';
  }
  return caught instanceof Error ? caught.message : 'Weekly report could not be downloaded. Prepare a new preflight and retry.';
}


function receiptErrorMessage(caught: unknown): string {
  if (caught instanceof TypeError) {
    return 'Weekly review receipts are temporarily unavailable. Check the backend connection and try again.';
  }
  return caught instanceof Error ? caught.message : 'Weekly review receipts are temporarily unavailable.';
}


function newIdempotencyKey(): string {
  if (globalThis.crypto?.randomUUID) return `weekly-review-${globalThis.crypto.randomUUID()}`;
  const bytes = new Uint8Array(16);
  if (globalThis.crypto?.getRandomValues) globalThis.crypto.getRandomValues(bytes);
  else {
    const seed = `${Date.now()}-${Math.random()}-weekly-review`;
    for (let index = 0; index < bytes.length; index += 1) bytes[index] = seed.charCodeAt(index % seed.length) ^ index;
  }
  return `weekly-review-${Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('')}`;
}


export function ActiveWeeklyReportPanel({ canExport }: { canExport: boolean }) {
  const [period, setPeriod] = useState<ActiveWeeklyReportPeriod>('7d');
  const [preflight, setPreflight] = useState<ActiveWeeklyReportPreflight | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState<ActiveWeeklyReportFormat | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [receiptPage, setReceiptPage] = useState<ActiveWeeklyReviewReceiptPage | null>(null);
  const [receiptsLoading, setReceiptsLoading] = useState(true);
  const [receiptsError, setReceiptsError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<ActiveWeeklyReviewOutcome>('reviewed');
  const [receiptConfirmed, setReceiptConfirmed] = useState(false);
  const [receiptSaving, setReceiptSaving] = useState(false);
  const idempotencyKey = useRef(newIdempotencyKey());
  const [verificationReceiptId, setVerificationReceiptId] = useState('');
  const [verificationDigest, setVerificationDigest] = useState('');
  const [verificationBusy, setVerificationBusy] = useState(false);
  const [verificationResult, setVerificationResult] = useState<boolean | null>(null);

  async function loadReceipts() {
    setReceiptsLoading(true);
    setReceiptsError(null);
    try {
      const result = await listActiveWeeklyReviewReceipts();
      if (!result || !Array.isArray(result.items) || typeof result.revision !== 'number') {
        throw new Error('Weekly review receipt response was invalid.');
      }
      setReceiptPage(result);
      setVerificationReceiptId((current) => current || result.items[0]?.id || '');
    } catch (caught) {
      setReceiptsError(receiptErrorMessage(caught));
    } finally {
      setReceiptsLoading(false);
    }
  }

  useEffect(() => {
    void loadReceipts();
  }, []);

  async function prepare() {
    setLoading(true);
    setError(null);
    setNotice(null);
    setConfirmed(false);
    setReceiptConfirmed(false);
    setVerificationResult(null);
    idempotencyKey.current = newIdempotencyKey();
    try {
      const result = await getActiveWeeklyReportPreflight(period);
      setPreflight(result);
    } catch (caught) {
      setPreflight(null);
      setError(preflightErrorMessage(caught));
    } finally {
      setLoading(false);
    }
  }

  async function download(reportFormat: ActiveWeeklyReportFormat) {
    if (!preflight || !confirmed) return;
    setExporting(reportFormat);
    setError(null);
    setNotice(null);
    try {
      const result = await exportActiveWeeklyReport(preflight, reportFormat);
      const url = URL.createObjectURL(result.blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = result.filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
      setNotice(`${reportFormat === 'markdown' ? 'Markdown' : 'JSON'} report downloaded with snapshot ${result.digest.slice(0, 12)}…`);
    } catch (caught) {
      setError(exportErrorMessage(caught));
    } finally {
      setExporting(null);
    }
  }

  async function recordReview() {
    if (!preflight || !receiptPage || !receiptConfirmed) return;
    setReceiptSaving(true);
    setReceiptsError(null);
    setNotice(null);
    try {
      const result = await createActiveWeeklyReviewReceipt(
        preflight,
        outcome,
        receiptPage.revision,
        idempotencyKey.current,
      );
      const remaining = receiptPage.items.filter((item) => item.id !== result.receipt.id);
      setReceiptPage({
        ...receiptPage,
        revision: result.revision,
        items: [result.receipt, ...remaining].slice(0, receiptPage.max_retained),
      });
      setVerificationReceiptId(result.receipt.id);
      setReceiptConfirmed(false);
      setNotice(result.replayed ? 'The existing target-free review receipt was recovered.' : 'Target-free weekly review receipt recorded.');
    } catch (caught) {
      setReceiptsError(receiptErrorMessage(caught));
    } finally {
      setReceiptSaving(false);
    }
  }

  async function verifyReceipt() {
    if (!verificationReceiptId || !/^[a-f0-9]{64}$/.test(verificationDigest)) return;
    setVerificationBusy(true);
    setReceiptsError(null);
    setVerificationResult(null);
    try {
      const result = await verifyActiveWeeklyReviewReceipt(verificationReceiptId, verificationDigest);
      setVerificationResult(result.valid);
    } catch (caught) {
      setReceiptsError(receiptErrorMessage(caught));
    } finally {
      setVerificationBusy(false);
    }
  }

  const busy = loading || exporting !== null || receiptsLoading || receiptSaving || verificationBusy;
  return <section className="active-weekly-report" aria-labelledby="active-weekly-report-title" aria-busy={busy}>
    <div className="active-form-heading">
      <div>
        <span className="eyebrow">Team review</span>
        <h3 id="active-weekly-report-title">Weekly portfolio report</h3>
        <p>Prepare one bounded snapshot of current actions, recent executions, comparable changes and recurrence attention.</p>
      </div>
      {preflight ? <span className={`status-pill ${preflight.state === 'ready' ? 'ok' : ''}`}>{preflight.state.replace('_', ' ')}</span> : null}
    </div>
    <div className="active-weekly-report-controls">
      <label><span>Review window</span><select value={period} onChange={(event) => { setPeriod(event.target.value as ActiveWeeklyReportPeriod); setPreflight(null); setConfirmed(false); setReceiptConfirmed(false); setNotice(null); }}><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option></select></label>
      <button type="button" className="secondary-button" disabled={loading || exporting !== null} onClick={() => void prepare()}>{loading ? 'Preparing…' : preflight ? 'Refresh preflight' : 'Prepare report'}</button>
    </div>
    {!preflight && !loading ? <p className="muted">No report has been generated. Preparing a preflight does not persist or download another copy of portfolio data.</p> : null}
    {preflight ? <div className="active-weekly-report-preflight">
      <dl className="summary-list"><dt>Snapshot</dt><dd><code>{preflight.snapshot_digest.slice(0, 12)}…</code> at {new Date(preflight.state_at).toLocaleString()}</dd><dt>Assets</dt><dd>{preflight.assets_included} included / {preflight.assets_total} total</dd><dt>Executions</dt><dd>{preflight.jobs_included} source records / {preflight.jobs_total} total</dd><dt>Actions</dt><dd>{preflight.actions_included} included / {preflight.actions_total} total</dd><dt>Recurrence attention</dt><dd>{preflight.recurrence_attention_included} included / {preflight.recurrence_attention_total} total</dd></dl>
      {preflight.state === 'no_assets' ? <p className="empty-state">No authorized Active assets exist in this workspace. The report will contain an explicit empty state.</p> : null}
      {preflight.incomplete ? <p className="warning-text" role="status"><strong>Partial snapshot.</strong> The report declares its exact denominators and safe limits. Inspect assets directly before drawing a complete portfolio conclusion.</p> : null}
      <p className="warning-text" role="status"><strong>Sensitive export.</strong> Exact authorized targets are included when present. Notes, authorization references, responsible identities, challenge material and raw runner results remain excluded.</p>
      {canExport ? <label className="checkbox-row"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />I understand this report may contain exact authorized targets and will store and share it accordingly.</label> : null}
      {!canExport ? <p className="warning-text" role="status">A maintainer or administrator must confirm and export this target-bearing report. Read-only users can still review its bounded preflight.</p> : null}
      {canExport ? <div className="row-actions">
        <button type="button" disabled={!confirmed || exporting !== null} onClick={() => void download('markdown')}>{exporting === 'markdown' ? 'Downloading Markdown…' : 'Download Markdown'}</button>
        <button type="button" className="secondary-button" disabled={!confirmed || exporting !== null} onClick={() => void download('json')}>{exporting === 'json' ? 'Downloading JSON…' : 'Download JSON'}</button>
      </div> : null}
      {canExport ? <fieldset className="active-weekly-review-form">
        <legend>Record this review</legend>
        <p className="muted">The receipt stores only period, cutoff, coverage, a keyed digest and a closed outcome. It cannot close actions or prove remediation.</p>
        <label><input type="radio" name="weekly-review-outcome" value="reviewed" checked={outcome === 'reviewed'} onChange={() => setOutcome('reviewed')} />Reviewed</label>
        <label><input type="radio" name="weekly-review-outcome" value="follow_up_required" checked={outcome === 'follow_up_required'} onChange={() => setOutcome('follow_up_required')} />Follow-up required</label>
        <label className="checkbox-row"><input type="checkbox" checked={receiptConfirmed} onChange={(event) => setReceiptConfirmed(event.target.checked)} />I reviewed this exact bounded snapshot and confirm the selected outcome.</label>
        <button type="button" disabled={!receiptConfirmed || !receiptPage || receiptSaving} onClick={() => void recordReview()}>{receiptSaving ? 'Recording review…' : 'Record target-free receipt'}</button>
      </fieldset> : null}
    </div> : null}

    <div className="active-weekly-review-history" aria-labelledby="active-weekly-review-history-title">
      <div className="active-form-heading">
        <div><h4 id="active-weekly-review-history-title">Review receipt history</h4><p>Private, bounded evidence for this workspace. No target or reviewer identity is shown.</p></div>
        {receiptPage ? <span className="status-pill">{receiptPage.items.length} / {receiptPage.max_retained}</span> : null}
      </div>
      {receiptsLoading ? <p role="status">Loading review receipts…</p> : null}
      {!receiptsLoading && receiptPage?.items.length === 0 ? <p className="empty-state">No weekly review receipt has been recorded for this workspace.</p> : null}
      {receiptPage?.items.length ? <ul className="active-weekly-review-list">
        {receiptPage.items.map((item) => <li key={item.id}>
          <div><strong>{item.outcome === 'reviewed' ? 'Reviewed' : 'Follow-up required'}</strong><span>{item.period} · cutoff {new Date(item.state_at).toLocaleString()}</span></div>
          <div><span>Coverage: {item.coverage_state.replace('_', ' ')}</span><code>HMAC {item.snapshot_hmac_sha256.slice(0, 12)}…</code></div>
        </li>)}
      </ul> : null}
      {receiptPage?.items.length ? <form className="active-weekly-review-verify" onSubmit={(event) => { event.preventDefault(); void verifyReceipt(); }}>
        <h5>Verify a downloaded snapshot locally</h5>
        <p className="muted">Paste only the 64-character snapshot SHA-256 from the exported report. Verification contacts no external provider.</p>
        <label><span>Receipt</span><select value={verificationReceiptId} onChange={(event) => { setVerificationReceiptId(event.target.value); setVerificationResult(null); }}>{receiptPage.items.map((item) => <option key={item.id} value={item.id}>{item.outcome.replace(/_/g, ' ')} · {new Date(item.state_at).toLocaleDateString()}</option>)}</select></label>
        <label><span>Snapshot SHA-256</span><input value={verificationDigest} onChange={(event) => { setVerificationDigest(event.target.value.trim().toLowerCase()); setVerificationResult(null); }} minLength={64} maxLength={64} pattern="[a-f0-9]{64}" spellCheck={false} autoComplete="off" placeholder="64 lowercase hexadecimal characters" /></label>
        <button type="submit" className="secondary-button" disabled={!/^[a-f0-9]{64}$/.test(verificationDigest) || verificationBusy}>{verificationBusy ? 'Verifying…' : 'Verify receipt'}</button>
        {verificationResult !== null ? <p className={verificationResult ? 'success-text' : 'warning-text'} role="status">{verificationResult ? 'Receipt matches this snapshot digest.' : 'Receipt does not match this snapshot digest.'}</p> : null}
      </form> : null}
      {receiptsError ? <div><p className="error-text" role="alert">{receiptsError}</p><button type="button" className="secondary-button" disabled={receiptsLoading} onClick={() => void loadReceipts()}>Retry receipt history</button></div> : null}
    </div>
    {notice ? <p className="success-text" role="status">{notice}</p> : null}
    {error ? <p className="error-text" role="alert">{error}</p> : null}
  </section>;
}
