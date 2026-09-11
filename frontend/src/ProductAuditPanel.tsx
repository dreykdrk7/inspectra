import { FormEvent, useCallback, useEffect, useState } from "react";

import { ApiError, api } from "./api";
import type { ActiveAsset, ActiveAuditExportPreflight, ProductAuditEvent, ProductAuditExportPreflight, ProductAuditIntegrityResponse } from "./types";


type LoadState = { loading: boolean; error: string | null };
const idle: LoadState = { loading: false, error: null };

export function ProductAuditPanel() {
  const [events, setEvents] = useState<ProductAuditEvent[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [retentionDays, setRetentionDays] = useState<number | null>(null);
  const [filter, setFilter] = useState("");
  const [appliedFilter, setAppliedFilter] = useState("");
  const [state, setState] = useState<LoadState>({ loading: true, error: null });
  const [activeAssets, setActiveAssets] = useState<ActiveAsset[]>([]);
  const [assetDirectoryError, setAssetDirectoryError] = useState<string | null>(null);
  const [assetDirectoryIncomplete, setAssetDirectoryIncomplete] = useState(false);
  const [exportPeriod, setExportPeriod] = useState<'7d' | '30d' | '90d' | '365d'>('30d');
  const [exportAssetId, setExportAssetId] = useState('');
  const [exportPreflight, setExportPreflight] = useState<ActiveAuditExportPreflight | null>(null);
  const [exportState, setExportState] = useState<LoadState>(idle);
  const [productExportPeriod, setProductExportPeriod] = useState<'7d' | '30d' | '90d' | '365d'>('30d');
  const [productExportAction, setProductExportAction] = useState('');
  const [productExportPreflight, setProductExportPreflight] = useState<ProductAuditExportPreflight | null>(null);
  const [productExportConfirmed, setProductExportConfirmed] = useState(false);
  const [productExportState, setProductExportState] = useState<LoadState>(idle);
  const [productExporting, setProductExporting] = useState<'json' | 'csv' | null>(null);
  const [productExportNotice, setProductExportNotice] = useState<string | null>(null);
  const [integrity, setIntegrity] = useState<ProductAuditIntegrityResponse | null>(null);
  const [integrityState, setIntegrityState] = useState<LoadState>({ loading: true, error: null });

  const load = useCallback(async (options: { append?: boolean; cursor?: string | null; action?: string } = {}) => {
    setState({ loading: true, error: null });
    try {
      const response = await api.listProductAuditEvents({
        limit: 25,
        cursor: options.cursor,
        action: options.action,
      });
      setEvents((current) => options.append ? [...current, ...response.items] : response.items);
      setNextCursor(response.next_cursor);
      setRetentionDays(response.retention_days);
      setState(idle);
    } catch (error) {
      setState({ loading: false, error: messageFor(error) });
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const verifyIntegrity = useCallback(async () => {
    setIntegrityState({ loading: true, error: null });
    try {
      setIntegrity(await api.verifyProductAuditIntegrity());
      setIntegrityState(idle);
    } catch (error) {
      setIntegrity(null);
      setIntegrityState({ loading: false, error: messageForIntegrity(error) });
    }
  }, []);

  useEffect(() => {
    void verifyIntegrity();
  }, [verifyIntegrity]);

  useEffect(() => {
    void api.listActiveAssetPage({ pageSize: 100 })
      .then((page) => { setActiveAssets(page.items); setAssetDirectoryIncomplete(page.has_more); setAssetDirectoryError(null); })
      .catch(() => setAssetDirectoryError('The Active asset selector is unavailable. Organization-wide export remains available.'));
  }, []);

  function applyFilter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const normalized = filter.trim().toLowerCase();
    setAppliedFilter(normalized);
    setEvents([]);
    void load({ action: normalized || undefined });
  }

  function clearFilter() {
    setFilter("");
    setAppliedFilter("");
    setEvents([]);
    void load();
  }

  function changeExportSelection(update: () => void) {
    update();
    setExportPreflight(null);
    setExportState(idle);
  }

  async function reviewActiveExport() {
    setExportState({ loading: true, error: null });
    setExportPreflight(null);
    try {
      setExportPreflight(await api.getActiveAuditExportPreflight(exportPeriod, exportAssetId || undefined));
      setExportState(idle);
    } catch (error) {
      setExportState({ loading: false, error: messageForActiveExport(error) });
    }
  }

  function changeProductExportSelection(update: () => void) {
    update();
    setProductExportPreflight(null);
    setProductExportConfirmed(false);
    setProductExportNotice(null);
    setProductExportState(idle);
  }

  async function reviewProductExport() {
    setProductExportState({ loading: true, error: null });
    setProductExportPreflight(null);
    setProductExportConfirmed(false);
    setProductExportNotice(null);
    try {
      const exactAction = productExportAction.trim().toLowerCase();
      setProductExportPreflight(await api.getProductAuditExportPreflight(productExportPeriod, exactAction || undefined));
      setProductExportState(idle);
    } catch (error) {
      setProductExportState({ loading: false, error: messageForProductExport(error) });
    }
  }

  async function downloadProductExport(exportFormat: 'json' | 'csv') {
    if (!productExportPreflight || !productExportConfirmed) return;
    setProductExporting(exportFormat);
    setProductExportState(idle);
    setProductExportNotice(null);
    try {
      const result = await api.exportProductAudit(productExportPreflight, exportFormat);
      const url = URL.createObjectURL(result.blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = result.filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
      setProductExportNotice(`${exportFormat.toUpperCase()} audit exported from snapshot ${result.digest.slice(0, 12)}…`);
    } catch (error) {
      setProductExportState({ loading: false, error: messageForProductExport(error) });
    } finally {
      setProductExporting(null);
    }
  }

  return (
    <section className="card product-audit-card" aria-labelledby="product-audit-title">
      <div className="section-heading-row">
        <div>
          <p className="eyebrow">Administrative trace</p>
          <h2 id="product-audit-title">Product activity</h2>
          <p className="muted">
            Minimal records of high-value actions in this workspace. Source code, paths, credentials and finding
            evidence are never part of this history.
          </p>
        </div>
        {retentionDays ? <span className="status-pill">Retained {retentionDays} days</span> : null}
      </div>

      <section className={`product-audit-integrity ${integrity?.state || 'unknown'}`} aria-labelledby="product-audit-integrity-title" aria-busy={integrityState.loading}>
        <div>
          <h3 id="product-audit-integrity-title">Audit chain integrity</h3>
          {integrityState.loading ? <p className="muted" role="status">Verifying retained audit chain…</p> : null}
          {integrity?.state === 'valid' ? <p className="success-text" role="status">Valid chain across {integrity.retained_events} retained events in generation {integrity.generation}.</p> : null}
          {integrity?.state === 'empty' ? <p className="muted" role="status">The chain is valid and currently has no retained events.</p> : null}
          {integrity?.state === 'invalid' ? <p className="error-text" role="alert"><strong>Integrity check failed.</strong> Stop relying on this audit history and follow the recovery runbook before exporting it.</p> : null}
          {integrity?.bootstrap_performed ? <p className="warning-text" role="status">Legacy records were chained during this check. Integrity before this first local bootstrap cannot be proven.</p> : null}
          {integrity?.head_digest ? <p className="muted">Head <code>{integrity.head_digest.slice(0, 12)}…</code> · retained sequence {integrity.anchor_sequence} → {integrity.head_sequence}</p> : null}
          {integrityState.error ? <p className="error-text" role="alert">{integrityState.error}</p> : null}
        </div>
        <button type="button" className="secondary-button" onClick={() => void verifyIntegrity()} disabled={integrityState.loading}>{integrityState.loading ? 'Verifying…' : 'Verify chain again'}</button>
      </section>

      <form className="product-audit-filter" onSubmit={applyFilter} role="search">
        <label>
          Exact action
          <input
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            placeholder="project.report_exported"
            pattern="[a-z][a-z0-9_.-]{2,95}"
            maxLength={96}
          />
        </label>
        <button type="submit" disabled={state.loading}>Filter</button>
        {appliedFilter ? <button type="button" className="secondary-button" onClick={clearFilter}>Clear filter</button> : null}
      </form>

      <section className="product-audit-export" aria-labelledby="product-audit-export-title" aria-busy={productExportState.loading || productExporting !== null}>
        <div>
          <h3 id="product-audit-export-title">Export redacted product activity</h3>
          <p className="muted">Prepare an organization-scoped snapshot before downloading. Actor and resource references are pseudonymous; organization identifiers, correlations, metadata, names, paths, targets, source and evidence are excluded.</p>
        </div>
        <div className="product-audit-export-controls">
          <label><span>Activity period</span><select value={productExportPeriod} onChange={(event) => changeProductExportSelection(() => setProductExportPeriod(event.target.value as '7d' | '30d' | '90d' | '365d'))}><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option><option value="90d">Last 90 days</option><option value="365d">Last 365 days</option></select></label>
          <label><span>Exact action (optional)</span><input value={productExportAction} onChange={(event) => changeProductExportSelection(() => setProductExportAction(event.target.value))} placeholder="project.report_exported" pattern="[a-z][a-z0-9_.-]{2,95}" maxLength={96} /></label>
          <button type="button" onClick={() => void reviewProductExport()} disabled={productExportState.loading || productExporting !== null}>{productExportState.loading ? 'Preparing…' : 'Prepare redacted export'}</button>
        </div>
        {productExportState.error ? <p className="error-text" role="alert">{productExportState.error}</p> : null}
        {productExportPreflight ? <div className={`product-audit-export-preview ${productExportPreflight.state}`} role="status">
          <div><strong>{productExportPreflight.state === 'ready' ? 'Redacted snapshot ready' : 'No matching product activity'}</strong><span>{formatDate(productExportPreflight.starts_at)} → {formatDate(productExportPreflight.state_at)}</span></div>
          <dl><div><dt>Matching events</dt><dd>{productExportPreflight.total_events}</dd></div><div><dt>Included</dt><dd>{productExportPreflight.included_events} / {productExportPreflight.max_events}</dd></div><div><dt>Filter</dt><dd>{productExportPreflight.action_filter || 'All actions'}</dd></div><div><dt>Truncated</dt><dd>{productExportPreflight.truncated ? 'Yes — narrow the period or action' : 'No'}</dd></div></dl>
          <p className="muted">Snapshot <code>{productExportPreflight.snapshot_digest.slice(0, 12)}…</code>. It expires at {formatDate(productExportPreflight.expires_at)} and the server rejects a changed scope.</p>
          {productExportPreflight.state === 'ready' ? <>
            <label className="checkbox-row"><input type="checkbox" checked={productExportConfirmed} onChange={(event) => setProductExportConfirmed(event.target.checked)} />I confirm this bounded, redacted audit snapshot may be downloaded for offline review.</label>
            <div className="product-audit-export-actions"><button type="button" disabled={!productExportConfirmed || productExporting !== null} onClick={() => void downloadProductExport('json')}>{productExporting === 'json' ? 'Downloading JSON…' : 'Download JSON'}</button><button type="button" className="secondary-button" disabled={!productExportConfirmed || productExporting !== null} onClick={() => void downloadProductExport('csv')}>{productExporting === 'csv' ? 'Downloading CSV…' : 'Download CSV'}</button></div>
          </> : <p className="muted">Change the period or exact-action filter and prepare the scope again. Empty exports are not offered.</p>}
        </div> : null}
        {productExportNotice ? <p className="success-text" role="status">{productExportNotice}</p> : null}
      </section>

      <section className="product-audit-export" aria-labelledby="active-audit-export-title">
        <div>
          <h3 id="active-audit-export-title">Export Active operational audit</h3>
          <p className="muted">Review a bounded, administrator-only scope before downloading. Exports pseudonymize actors and resources and omit targets, references, notes, client IPs, correlations, raw metadata and evidence.</p>
        </div>
        <div className="product-audit-export-controls">
          <label><span>Audit period</span><select value={exportPeriod} onChange={(event) => changeExportSelection(() => setExportPeriod(event.target.value as '7d' | '30d' | '90d' | '365d'))}><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option><option value="90d">Last 90 days</option><option value="365d">Last 365 days</option></select></label>
          <label><span>Active asset</span><select value={exportAssetId} onChange={(event) => changeExportSelection(() => setExportAssetId(event.target.value))}><option value="">All Active resources in this workspace</option>{activeAssets.map((asset) => <option key={asset.id} value={asset.id}>{asset.canonical_value}</option>)}</select></label>
          <button type="button" onClick={() => void reviewActiveExport()} disabled={exportState.loading}>{exportState.loading ? 'Reviewing…' : 'Review export scope'}</button>
        </div>
        {assetDirectoryError ? <p className="warning-text" role="status">{assetDirectoryError}</p> : null}
        {assetDirectoryIncomplete ? <p className="warning-text" role="status">The selector shows the newest 100 Active assets. Use the organization-wide export or narrow operational work from the Active portfolio.</p> : null}
        {exportState.error ? <p className="error-text" role="alert">{exportState.error}</p> : null}
        {exportPreflight ? <div className={`product-audit-export-preview ${exportPreflight.state}`} role="status">
          <div><strong>{exportPreflight.state === 'ready' ? 'Export ready' : 'No matching Active activity'}</strong><span>{formatDate(exportPreflight.starts_at)} → {formatDate(exportPreflight.ends_at)}</span></div>
          <dl><div><dt>Matching events</dt><dd>{exportPreflight.total_events}</dd></div><div><dt>Included</dt><dd>{exportPreflight.included_events} / {exportPreflight.max_events}</dd></div><div><dt>Scope</dt><dd>{exportPreflight.asset_filter_applied ? 'Selected asset' : 'Current workspace'}</dd></div><div><dt>Truncated</dt><dd>{exportPreflight.truncated ? 'Yes — use a shorter period or asset filter' : 'No'}</dd></div></dl>
          {exportPreflight.state === 'ready' ? <div className="product-audit-export-actions"><a className="secondary-button" href={api.activeAuditExportUrl(exportPeriod, 'json', exportAssetId || undefined)}>Download JSON</a><a className="secondary-button" href={api.activeAuditExportUrl(exportPeriod, 'csv', exportAssetId || undefined)}>Download CSV</a></div> : <p className="muted">Change the period or asset scope and review again. An empty export is not offered.</p>}
        </div> : null}
      </section>

      {state.loading && events.length === 0 ? <p className="muted" role="status">Loading product activity…</p> : null}
      {state.error ? (
        <div className="alert" role="alert">
          {state.error} <button className="inline-button" onClick={() => void load({ action: appliedFilter || undefined })}>Retry</button>
        </div>
      ) : null}
      {!state.loading && !state.error && events.length === 0 ? (
        <div className="compact-empty-state" role="status">
          <strong>{appliedFilter ? "No matching activity" : "No product activity yet"}</strong>
          <span>{appliedFilter ? "Clear the exact-action filter or try another known action." : "High-value actions will appear here after they occur."}</span>
        </div>
      ) : null}

      {events.length > 0 ? (
        <ol className="product-audit-list" aria-label="Product activity events">
          {events.map((event) => (
            <li key={event.id}>
              <div className="product-audit-event-heading">
                <strong>{actionLabel(event.action)}</strong>
                <span className={`status-pill ${event.result === "succeeded" ? "ok" : ""}`}>{resultLabel(event.result)}</span>
              </div>
              <dl>
                <div><dt>When</dt><dd>{formatDate(event.occurred_at)}</dd></div>
                <div><dt>Actor</dt><dd>{event.actor_role} · <code>{shortId(event.actor_id)}</code></dd></div>
                <div><dt>Resource</dt><dd>{event.resource_type} · <code>{shortId(event.resource_id)}</code></dd></div>
                <div><dt>Correlation</dt><dd><code>{shortId(event.correlation_id)}</code></dd></div>
              </dl>
              {Object.keys(event.metadata).length ? (
                <p className="product-audit-metadata">Context: {metadataLabel(event.metadata)}</p>
              ) : null}
            </li>
          ))}
        </ol>
      ) : null}

      {nextCursor && !state.error ? (
        <button
          type="button"
          className="secondary-button product-audit-more"
          disabled={state.loading}
          onClick={() => void load({ append: true, cursor: nextCursor, action: appliedFilter || undefined })}
        >
          {state.loading ? "Loading…" : "Load older activity"}
        </button>
      ) : null}
    </section>
  );
}

function actionLabel(action: string): string {
  return action.split(/[._]/).map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(" ");
}

function resultLabel(result: ProductAuditEvent["result"]): string {
  return result === "succeeded" ? "Succeeded" : result === "denied" ? "Denied" : "Failed";
}

function shortId(value: string): string {
  if (value.length <= 24) return value;
  return `${value.slice(0, 10)}…${value.slice(-8)}`;
}

function metadataLabel(metadata: ProductAuditEvent["metadata"]): string {
  return Object.entries(metadata)
    .map(([key, value]) => `${key.replace(/_/g, " ")} ${String(value)}`)
    .join(" · ");
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Recorded time unavailable" : date.toLocaleString();
}

function messageFor(error: unknown): string {
  if (error instanceof ApiError && error.status === 403) return "Only workspace administrators can view product activity.";
  if (error instanceof ApiError && error.status === 503) return "Product activity is temporarily unavailable. Review storage health and retry.";
  if (error instanceof Error && error.message) return error.message;
  return "Product activity could not be loaded.";
}

function messageForActiveExport(error: unknown): string {
  if (error instanceof ApiError && error.status === 404) return "The selected Active asset is no longer available in this workspace. Refresh the selector and review again.";
  if (error instanceof ApiError && error.status === 403) return "Only workspace administrators can export operational audit evidence.";
  if (error instanceof ApiError && error.status === 503) return "Active audit export is temporarily unavailable. No partial file was created.";
  return "The Active audit export scope could not be reviewed. Retry after checking workspace access.";
}

function messageForProductExport(error: unknown): string {
  if (error instanceof ApiError && error.status === 400) return "The exact-action filter is invalid. Use the lowercase action identifier shown in the activity list.";
  if (error instanceof ApiError && error.status === 403) return "Only workspace administrators can export product activity.";
  if (error instanceof ApiError && error.status === 409) return "The redacted audit snapshot expired or changed. Prepare it again before downloading.";
  if (error instanceof ApiError && error.status === 413) return "The redacted audit export exceeded its safe size. Narrow the period or exact action.";
  if (error instanceof ApiError && error.status === 503) return "Product audit export is temporarily unavailable. No partial file was created.";
  return error instanceof Error && error.message ? error.message : "Product audit export could not be prepared.";
}

function messageForIntegrity(error: unknown): string {
  if (error instanceof ApiError && error.status === 403) return "Only workspace administrators can verify product audit integrity.";
  if (error instanceof ApiError && error.status === 503) return "Audit integrity could not be verified because its storage is unavailable.";
  return "Audit integrity could not be verified. Treat the retained history as unavailable and follow the recovery runbook.";
}
