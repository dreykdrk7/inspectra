import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { activeAssetEvidenceBundleUrl, activeAssetReportUrl, cancelActiveAssetExecution, checkActiveAssetVerification, createActiveAsset, createActiveAssetExecution, createIdempotencyKey, decideActiveChangeApproval, getActiveAsset, getActiveAssetPosture, getActiveAssetVerification, getActiveAssetVerificationConfiguration, getActiveOperationsSummary, listActiveAssetExecutionPage, listActiveAssetPage, listActiveChangeApprovals, listTeamMembers, renewActiveAsset, requestActiveRegistrationApproval, requestActiveRenewalApproval, requestActiveRevocationApproval, retryActiveAssetExecution, revokeActiveAsset, revokeActiveAssetVerification, setActiveAssetBaseline, setActiveAssetTriage, startActiveAssetVerification, updateActiveAssetResponsibles } from './api';
import type { ActiveAsset, ActiveAssetCreateRequest, ActiveAssetPostureResponse, ActiveAssetStatus, ActiveAssetVerification, ActiveAssetVerificationChallenge, ActiveAssetVerificationConfiguration, ActiveAssetVerificationMethod, ActiveCapability, ActiveChangeApproval, ActiveOperationsAction, ActiveOperationsSummary, JobListItem, JobRecord, TeamMember, TeamRole } from './types';
import { ActiveAssetDeletionPanel } from './ActiveAssetDeletionPanel';
import { ActiveAssetBatchForm } from './ActiveAssetBatchForm';
import { ActiveRecurrencePanel } from './ActiveRecurrencePanel';
import { ActiveWeeklyReportPanel } from './ActiveWeeklyReportPanel';

const CAPABILITIES: Array<{ id: ActiveCapability; label: string; detail: string }> = [
  { id: 'active_nmap_basic', label: 'TCP exposure', detail: 'Small TCP connect profile over explicit ports.' },
  { id: 'active_dns_inventory', label: 'DNS inventory', detail: 'Bounded DNS records for the exact name.' },
  { id: 'active_dns_osint', label: 'DNS public signals', detail: 'Certificate Transparency observations; no discovered name is authorized.' },
  { id: 'active_http_basic_header_review', label: 'HTTP headers', detail: 'One bounded HEAD request, no redirect and no body.' },
  { id: 'active_tls_basic', label: 'TLS summary', detail: 'One bounded handshake against an explicit port.' },
];

const ACTIVE_PORTFOLIO_PAGE_SIZE = 24;
const ACTIVE_PORTFOLIO_RENDER_LIMIT = 96;
const ACTIVE_ACTION_PREFERENCES_KEY = 'inspectra.activeActionInbox.v1';

type Props = {
  canManage: boolean;
  teamMode?: boolean;
  currentUserId?: string | null;
  currentRole?: TeamRole | null;
  refreshToken?: number;
  onJobCreated?: (job: JobRecord) => void | Promise<void>;
};

export function ActiveOperationsCenter({ canManage, teamMode = false, currentUserId = null, currentRole = null, refreshToken = 0, onJobCreated }: Props) {
  const [assets, setAssets] = useState<ActiveAsset[]>([]);
  const [status, setStatus] = useState<ActiveAssetStatus | 'all'>('all');
  const [query, setQuery] = useState('');
  const [queryMode, setQueryMode] = useState<'prefix' | 'exact'>('prefix');
  const [capabilityFilter, setCapabilityFilter] = useState<ActiveCapability | 'all'>('all');
  const [recencyFilter, setRecencyFilter] = useState<'all' | '7' | '30'>('all');
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [windowLimited, setWindowLimited] = useState(false);
  const loadMoreButtonRef = useRef<HTMLButtonElement>(null);
  const pageStatusRef = useRef<HTMLParagraphElement>(null);
  const pagingFocusTarget = useRef<'button' | 'status' | null>(null);
  const portfolioGeneration = useRef(0);
  const [showCreate, setShowCreate] = useState(false);
  const [showBatch, setShowBatch] = useState(false);
  const [verificationConfiguration, setVerificationConfiguration] = useState<ActiveAssetVerificationConfiguration | null>(null);
  const [verificationConfigurationError, setVerificationConfigurationError] = useState<string | null>(null);
  const [summary, setSummary] = useState<ActiveOperationsSummary | null>(null);
  const [summaryError, setSummaryError] = useState<string | null>(null);
  const [pinnedActionAsset, setPinnedActionAsset] = useState<ActiveAsset | null>(null);
  const [actionNavigationId, setActionNavigationId] = useState<string | null>(null);
  const [actionNavigationError, setActionNavigationError] = useState<string | null>(null);
  const [focusRequest, setFocusRequest] = useState<{ assetId: string; token: number } | null>(null);
  const deepLinkHandled = useRef(false);
  const focusSequence = useRef(0);
  const [responsibleMembers, setResponsibleMembers] = useState<TeamMember[] | null>(
    teamMode ? null : [localResponsibleMember(currentUserId)],
  );
  const [responsibleMembersError, setResponsibleMembersError] = useState<string | null>(null);
  const [approvals, setApprovals] = useState<ActiveChangeApproval[]>([]);
  const [approvalsLoading, setApprovalsLoading] = useState(false);
  const [approvalsError, setApprovalsError] = useState<string | null>(null);

  const refreshApprovals = useCallback(async () => {
    if (!canManage || !summary?.configuration.four_eyes_enabled) {
      setApprovals([]);
      setApprovalsError(null);
      return;
    }
    setApprovalsLoading(true);
    try {
      const page = await listActiveChangeApprovals();
      setApprovals(page.items);
      setApprovalsError(null);
    } catch {
      setApprovalsError('Four-eyes approval state is temporarily unavailable. Critical changes remain blocked.');
    } finally {
      setApprovalsLoading(false);
    }
  }, [canManage, summary?.configuration.four_eyes_enabled]);

  const refresh = useCallback(async () => {
    const generation = ++portfolioGeneration.current;
    setLoading(true);
    setError(null);
    setPageError(null);
    try {
      const page = await listActiveAssetPage({
        pageSize: ACTIVE_PORTFOLIO_PAGE_SIZE,
        status: status === 'all' ? undefined : status,
        query,
        queryMode,
        capability: capabilityFilter === 'all' ? undefined : capabilityFilter,
        updatedWithinDays: recencyFilter === 'all' ? undefined : Number(recencyFilter) as 7 | 30,
      });
      if (generation !== portfolioGeneration.current) return;
      setAssets(page.items);
      setNextCursor(page.next_cursor);
      setHasMore(page.has_more);
      setWindowLimited(false);
    } catch (caught) {
      if (generation !== portfolioGeneration.current) return;
      setError(caught instanceof Error ? caught.message : 'Active assets could not be loaded.');
    } finally {
      if (generation === portfolioGeneration.current) setLoading(false);
    }
    if (generation !== portfolioGeneration.current) return;
    try {
      const nextSummary = await getActiveOperationsSummary();
      if (generation !== portfolioGeneration.current) return;
      setSummary(nextSummary);
      setSummaryError(null);
    } catch {
      if (generation === portfolioGeneration.current) {
        setSummaryError('Portfolio summary is temporarily unavailable. Asset records remain usable.');
      }
    }
  }, [capabilityFilter, query, queryMode, recencyFilter, status]);

  const loadMore = useCallback(async () => {
    if (!nextCursor || loadingMore) return;
    const generation = portfolioGeneration.current;
    let completedPortfolio = false;
    setLoadingMore(true);
    setPageError(null);
    try {
      const page = await listActiveAssetPage({
        pageSize: ACTIVE_PORTFOLIO_PAGE_SIZE,
        cursor: nextCursor,
        status: status === 'all' ? undefined : status,
        query,
        queryMode,
        capability: capabilityFilter === 'all' ? undefined : capabilityFilter,
        updatedWithinDays: recencyFilter === 'all' ? undefined : Number(recencyFilter) as 7 | 30,
      });
      if (generation !== portfolioGeneration.current) return;
      const known = new Set(assets.map((item) => item.id));
      const nextAssets = [...assets, ...page.items.filter((item) => !known.has(item.id))];
      const reachedWindowLimit = page.has_more && nextAssets.length >= ACTIVE_PORTFOLIO_RENDER_LIMIT;
      setAssets(nextAssets.slice(0, ACTIVE_PORTFOLIO_RENDER_LIMIT));
      setWindowLimited(reachedWindowLimit);
      setHasMore(page.has_more && !reachedWindowLimit);
      completedPortfolio = !page.has_more || reachedWindowLimit;
      setNextCursor(page.next_cursor);
    } catch {
      if (generation === portfolioGeneration.current) {
        setPageError('The next page is unavailable. Loaded assets remain visible; refresh to restart from the newest records.');
      }
    } finally {
      if (generation === portfolioGeneration.current) {
        pagingFocusTarget.current = completedPortfolio ? 'status' : 'button';
      }
      setLoadingMore(false);
    }
  }, [assets, capabilityFilter, loadingMore, nextCursor, query, queryMode, recencyFilter, status]);

  useEffect(() => {
    if (loadingMore || pagingFocusTarget.current === null) return;
    const target = pagingFocusTarget.current;
    pagingFocusTarget.current = null;
    (target === 'status' ? pageStatusRef.current : loadMoreButtonRef.current)?.focus();
  }, [assets.length, hasMore, loadingMore]);

  useEffect(() => {
    const handle = window.setTimeout(() => void refresh(), 150);
    return () => {
      window.clearTimeout(handle);
      portfolioGeneration.current += 1;
    };
  }, [refresh, refreshToken]);

  useEffect(() => {
    void getActiveAssetVerificationConfiguration()
      .then((configuration) => { setVerificationConfiguration(configuration); setVerificationConfigurationError(null); })
      .catch(() => setVerificationConfigurationError('Verification configuration is unavailable. No control check can be started.'));
  }, []);

  useEffect(() => {
    if (!teamMode) {
      setResponsibleMembers([localResponsibleMember(currentUserId)]);
      setResponsibleMembersError(null);
      return;
    }
    setResponsibleMembers(null);
    setResponsibleMembersError(null);
    void listTeamMembers()
      .then((members) => setResponsibleMembers(members))
      .catch(() => setResponsibleMembersError('Responsible accounts are temporarily unavailable. Existing assignments remain unchanged.'));
  }, [currentUserId, refreshToken, teamMode]);

  useEffect(() => {
    if (canManage && summary?.configuration.four_eyes_enabled) void refreshApprovals();
    else setApprovals([]);
  }, [canManage, refreshApprovals, summary?.configuration.four_eyes_enabled]);

  const metrics = useMemo(() => ({
    active: assets.filter((asset) => asset.status === 'active').length,
    expired: assets.filter((asset) => asset.status === 'expired').length,
    revoked: assets.filter((asset) => asset.status === 'revoked').length,
    expiring: assets.filter((asset) => asset.status === 'active' && Date.parse(asset.expires_at) - Date.now() <= 14 * 86_400_000).length,
  }), [assets]);
  const capabilityReadiness = useMemo(
    () => new Map((summary?.capabilities ?? []).map((item) => [item.capability, item])),
    [summary],
  );
  const displayedAssets = useMemo(
    () => pinnedActionAsset && !assets.some((asset) => asset.id === pinnedActionAsset.id) ? [pinnedActionAsset, ...assets] : assets,
    [assets, pinnedActionAsset],
  );

  const openActionAsset = useCallback(async (assetId: string, actionId: string | null = null) => {
    setActionNavigationId(actionId ?? assetId);
    setActionNavigationError(null);
    try {
      let selected = assets.find((asset) => asset.id === assetId);
      if (!selected && pinnedActionAsset?.id === assetId) selected = pinnedActionAsset;
      if (!selected) {
        selected = await getActiveAsset(assetId);
        setPinnedActionAsset(selected);
      }
      window.history.replaceState(null, '', `#active-asset-detail-${assetId}`);
      focusSequence.current += 1;
      setFocusRequest({ assetId, token: focusSequence.current });
    } catch {
      setActionNavigationError('This action asset is unavailable in the current workspace. Refresh the inbox or ask a maintainer to review access.');
    } finally {
      setActionNavigationId(null);
    }
  }, [assets, pinnedActionAsset]);

  useEffect(() => {
    if (loading || deepLinkHandled.current) return;
    const match = window.location.hash.match(/^#active-asset-detail-([a-f0-9]{32})$/);
    deepLinkHandled.current = true;
    if (match) void openActionAsset(match[1]);
  }, [loading, openActionAsset]);

  return (
    <section id="active-operations" className="active-center" aria-labelledby="active-center-title" aria-busy={loading || loadingMore}>
      <header className="active-center-header">
        <div>
          <span className="eyebrow">Authorized observation</span>
          <h2 id="active-center-title">Active operations</h2>
          <p>Register exact authorized assets before running bounded checks. Observations are not automatically confirmed vulnerabilities.</p>
        </div>
        {canManage ? (
          <div className="row-actions">
            <button type="button" onClick={() => { setShowBatch(false); setShowCreate((value) => !value); }} aria-expanded={showCreate} aria-controls="active-asset-create">
              {showCreate ? 'Close registration' : 'Register asset'}
            </button>
            {!summary?.configuration.four_eyes_enabled ? <button type="button" className="secondary-button" onClick={() => { setShowCreate(false); setShowBatch((value) => !value); }} aria-expanded={showBatch} aria-controls="active-asset-batch">
              {showBatch ? 'Close batch import' : 'Import batch'}
            </button> : null}
          </div>
        ) : <span className="status-pill">Read only</span>}
      </header>

      <div className="active-center-metrics" aria-label="Active asset status summary">
        <Metric label="Assets" value={summary?.assets.total ?? assets.length} />
        <Metric label="Active" value={summary?.assets.active ?? metrics.active} />
        <Metric label="Expiring in 14 days" value={summary?.assets.expiring_14_days ?? metrics.expiring} />
        <Metric label="Running" value={(summary?.jobs.running ?? 0) + (summary?.jobs.cancelling ?? 0)} />
        <Metric label="Failed or degraded" value={(summary?.jobs.failed ?? 0) + (summary?.jobs.degraded ?? 0)} />
        <Metric label="Assets changed" value={summary?.changes.assets_with_changes ?? 0} />
        <Metric label="Pending actions" value={summary?.actions.total ?? 0} />
      </div>
      {summary ? <ActiveActionInbox
        summary={summary}
        assets={displayedAssets}
        canManage={canManage}
        openingId={actionNavigationId}
        navigationError={actionNavigationError}
        onOpen={openActionAsset}
      /> : null}
      <ActiveWeeklyReportPanel canExport={canManage} />
      {summaryError ? <p className="error-text" role="alert">{summaryError}</p> : null}
      {summary && summary.assets.duplicate_identity_groups > 0 ? <p className="warning-text" role="status"><strong>Legacy identity conflicts need review.</strong> {summary.assets.duplicate_identity_records} records share {summary.assets.duplicate_identity_groups} exact {summary.assets.duplicate_identity_groups === 1 ? 'identity' : 'identities'} in this workspace. Inspectra blocks another duplicate but never merges or deletes retained evidence automatically.</p> : null}
      {summary?.capacity.admission === 'saturated' ? <p className="warning-text" role="status"><strong>Active admission is temporarily full.</strong> Existing work continues; retry after a bounded execution reaches a terminal state.</p> : null}
      {summary?.limits.incomplete ? <p className="warning-text" role="status"><strong>Partial operational detail.</strong> Asset totals are exact. The review window selects urgent state before recent state, but verification, execution, capability, change and action counts remain bounded. Narrow the portfolio filters or inspect assets directly before drawing conclusions.</p> : null}
      {summary ? <div className="active-center-overview">
        <div><strong>Current organization only</strong><span>{summary.verifications.verified} verified · {summary.verifications.failed + summary.verifications.expired} verification attention</span></div>
        <div><strong>Capability gates</strong><span>{summary.capabilities.filter((item) => effectiveReadiness(item) === 'ready').length} ready · {summary.capabilities.filter((item) => effectiveReadiness(item) === 'degraded').length} degraded · {summary.capabilities.filter((item) => effectiveReadiness(item) === 'unavailable').length} unavailable · {summary.capabilities.filter((item) => effectiveReadiness(item) === 'disabled').length} disabled</span></div>
        <div><strong>Observation boundary</strong><span>{summary.changes.observations_changed} changed signals · {summary.changes.inconclusive} inconclusive</span></div>
      </div> : null}
      {summary ? <div className="active-readiness-grid" role="list" aria-label="Effective runner readiness by capability">
        {summary.capabilities.map((item) => <div role="listitem" key={item.capability}>
          <strong>{CAPABILITIES.find((entry) => entry.id === item.capability)?.label ?? item.capability}</strong>
          <span className={`status-pill ${effectiveReadiness(item) === 'ready' ? 'ok' : ''}`}>{readinessLabel(effectiveReadiness(item))}</span>
          <small>{readinessExplanation(effectiveReadiness(item))}</small>
        </div>)}
      </div> : null}

      {verificationConfiguration ? (
        <div className={`active-verification-banner ${verificationConfiguration.enabled ? 'enabled' : 'disabled'}`} role="status">
          <strong>Control verification: {verificationConfiguration.enabled ? 'operator enabled' : 'disabled by default'}</strong>
          <span>{verificationConfiguration.enabled ? 'Optional challenges are bounded and never replace legal authorization.' : 'Manual authorization remains the only admission boundary; no verification traffic can be sent.'}</span>
          {verificationConfiguration.enabled ? <span>Remote DNS/HTTP verification runner: {verificationConfiguration.remote_runner_ready ? 'ready' : 'unavailable'}. Unavailable methods are not offered.</span> : null}
        </div>
      ) : null}
      {summary ? <div className={`active-verification-banner ${summary.configuration.recurrence_enabled ? 'enabled' : 'disabled'}`} role="status"><strong>Recurring reviews: {summary.configuration.recurrence_enabled ? 'operator enabled' : 'disabled by default'}</strong><span>{summary.configuration.recurrence_enabled ? 'Verified assets may opt in to bounded 7, 14 or 30-day cadences inside an explicit weekly IANA-timezone window.' : 'No recurring Active job can be dispatched by the scheduler.'}</span></div> : null}
      {canManage && summary?.configuration.four_eyes_enabled ? <ActiveChangeApprovalPanel approvals={approvals} loading={approvalsLoading} error={approvalsError} currentRole={currentRole} onChanged={refreshApprovals} /> : null}
      {summary?.configuration.four_eyes_enabled ? <p className="muted">Batch registration is unavailable under four-eyes policy; review each exact asset individually.</p> : null}
      {verificationConfigurationError ? <p className="error-text" role="alert">{verificationConfigurationError}</p> : null}
      {responsibleMembersError ? <p className="error-text" role="alert">{responsibleMembersError}</p> : null}

      {showCreate && canManage ? <ActiveAssetForm members={responsibleMembers} fourEyesEnabled={Boolean(summary?.configuration.four_eyes_enabled)} onApprovalChanged={refreshApprovals} onCreated={(asset) => { setAssets((current) => [asset, ...current]); setShowCreate(false); void refresh(); }} /> : null}
      {showBatch && canManage ? <div id="active-asset-batch"><ActiveAssetBatchForm onCancel={() => setShowBatch(false)} onCompleted={refresh} /></div> : null}

      <div className="active-center-toolbar">
        <label>
          <span>Search authorized asset</span>
          <input className="search-input" type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="example.test" />
        </label>
        <label>
          <span>Match</span>
          <select value={queryMode} onChange={(event) => setQueryMode(event.target.value as 'prefix' | 'exact')}>
            <option value="prefix">Starts with</option><option value="exact">Exact identity</option>
          </select>
        </label>
        <label>
          <span>Status</span>
          <select value={status} onChange={(event) => setStatus(event.target.value as ActiveAssetStatus | 'all')}>
            <option value="all">All</option>
            <option value="active">Active</option>
            <option value="expired">Expired</option>
            <option value="revoked">Revoked</option>
          </select>
        </label>
        <label>
          <span>Capability</span>
          <select value={capabilityFilter} onChange={(event) => setCapabilityFilter(event.target.value as ActiveCapability | 'all')}>
            <option value="all">All capabilities</option>
            {CAPABILITIES.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
          </select>
        </label>
        <label>
          <span>Updated</span>
          <select value={recencyFilter} onChange={(event) => setRecencyFilter(event.target.value as 'all' | '7' | '30')}>
            <option value="all">Any date</option><option value="7">Last 7 days</option><option value="30">Last 30 days</option>
          </select>
        </label>
        <button type="button" className="secondary-button" onClick={() => void refresh()} disabled={loading}>Refresh</button>
      </div>

      {loading ? <p role="status" className="muted">Loading authorized assets…</p> : null}
      {error ? <div className="error-text" role="alert">{error} <button type="button" className="link-button" onClick={() => void refresh()}>Try again</button></div> : null}
      {!loading && !error && assets.length === 0 ? (
        <div className="empty-state">
          <strong>No authorized assets match this view.</strong>
          <p>{canManage ? 'Register one exact asset with a time-bound authorization and explicit capabilities.' : 'Ask a maintainer to register an authorized asset.'}</p>
        </div>
      ) : null}
      <div className="active-asset-grid">
        {displayedAssets.map((asset) => <ActiveAssetCard key={asset.id} asset={asset} members={responsibleMembers} canManage={canManage} currentRole={currentRole} fourEyesEnabled={Boolean(summary?.configuration.four_eyes_enabled)} onApprovalChanged={refreshApprovals} verificationConfiguration={verificationConfiguration} capabilityReadiness={capabilityReadiness} admissionAvailable={summary?.capacity.admission !== 'saturated'} focusToken={focusRequest?.assetId === asset.id ? focusRequest.token : null} onJobCreated={onJobCreated} onPortfolioChanged={refresh} onDeleted={async () => { setAssets((current) => current.filter((item) => item.id !== asset.id)); setPinnedActionAsset((current) => current?.id === asset.id ? null : current); await refresh(); }} onChanged={(updated) => { setAssets((current) => current.map((item) => item.id === updated.id ? updated : item)); setPinnedActionAsset((current) => current?.id === updated.id ? updated : current); void refresh(); }} />)}
      </div>
      {!loading && !error && assets.length > 0 ? <div className="active-page-controls">
        <p ref={pageStatusRef} role="status" tabIndex={-1}>Showing {assets.length} matching assets from the current workspace.{pinnedActionAsset && !assets.some((asset) => asset.id === pinnedActionAsset.id) ? ' One action asset is pinned outside the current portfolio filters.' : ''} {windowLimited ? 'The safe display limit is reached; refine the filters to inspect other records.' : hasMore ? 'More records are available.' : 'All matching records are loaded.'}</p>
        <button ref={loadMoreButtonRef} type="button" className="secondary-button" onClick={() => void loadMore()} disabled={loadingMore || !hasMore}>{loadingMore ? 'Loading next page…' : windowLimited ? 'Refine filters to continue' : hasMore ? `Load next ${ACTIVE_PORTFOLIO_PAGE_SIZE} assets` : 'All matching assets loaded'}</button>
        {pageError ? <p className="error-text" role="alert">{pageError}</p> : null}
      </div> : null}
    </section>
  );
}

type ActionUrgencyFilter = ActiveOperationsAction['urgency'] | 'all';
type ActionAgeFilter = 'all' | '7' | '30';

function ActiveActionInbox({ summary, assets, canManage, openingId, navigationError, onOpen }: {
  summary: ActiveOperationsSummary;
  assets: ActiveAsset[];
  canManage: boolean;
  openingId: string | null;
  navigationError: string | null;
  onOpen: (assetId: string, actionId?: string | null) => Promise<void>;
}) {
  const initialPreferences = useMemo(readActionPreferences, []);
  const [urgency, setUrgency] = useState<ActionUrgencyFilter>(initialPreferences.urgency);
  const [age, setAge] = useState<ActionAgeFilter>(initialPreferences.age);
  const assetNames = useMemo(() => new Map(assets.map((asset) => [asset.id, asset.canonical_value])), [assets]);
  const generatedAt = Date.parse(summary.generated_at);
  const visibleActions = useMemo(() => summary.action_queue.items.filter((action) => {
    if (urgency !== 'all' && action.urgency !== urgency) return false;
    if (age === 'all') return true;
    const referenceAt = Date.parse(action.reference_at);
    return Number.isFinite(generatedAt) && Number.isFinite(referenceAt)
      && generatedAt - referenceAt >= Number(age) * 86_400_000;
  }), [age, generatedAt, summary.action_queue.items, urgency]);

  useEffect(() => {
    try { window.localStorage.setItem(ACTIVE_ACTION_PREFERENCES_KEY, JSON.stringify({ urgency, age })); }
    catch { /* Preference persistence is optional; the inbox remains usable. */ }
  }, [age, urgency]);

  return <section className="active-action-inbox" aria-labelledby="active-action-inbox-title">
    <div className="active-form-heading">
      <div>
        <span className="eyebrow">Weekly review</span>
        <h3 id="active-action-inbox-title">Action inbox</h3>
        <p>Ordered from recorded state and timestamps. Inspectra does not infer an SLA or a confirmed vulnerability.</p>
      </div>
      <span className="status-pill">{summary.action_queue.total} open</span>
    </div>
    <div className="active-action-toolbar">
      <label><span>Priority</span><select value={urgency} onChange={(event) => setUrgency(event.target.value as ActionUrgencyFilter)}>
        <option value="all">All priorities</option><option value="immediate">Immediate</option><option value="high">High</option><option value="scheduled">Scheduled</option><option value="review">Review</option>
      </select></label>
      <label><span>Age of recorded state</span><select value={age} onChange={(event) => setAge(event.target.value as ActionAgeFilter)}>
        <option value="all">Any age</option><option value="7">At least 7 days</option><option value="30">At least 30 days</option>
      </select></label>
    </div>
    {summary.action_queue.source_incomplete || summary.action_queue.items_truncated ? <p className="warning-text" role="status"><strong>Partial action inbox.</strong> {summary.action_queue.source_incomplete ? 'The bounded source window does not include every asset or execution. ' : ''}{summary.action_queue.items_truncated ? `Showing the first ${summary.action_queue.returned} of ${summary.action_queue.total} ordered actions.` : ''} Review portfolio filters before treating this as complete.</p> : null}
    {navigationError ? <p className="error-text" role="alert">{navigationError}</p> : null}
    {summary.action_queue.total === 0 ? <div className="empty-state"><strong>No current actions in the bounded portfolio.</strong><p>Refresh after authorizations, verifications, executions, or observations change.</p></div> : visibleActions.length === 0 ? <div className="empty-state"><strong>No actions match these filters.</strong><p>Change priority or age without altering the underlying action state.</p></div> : <ol className="active-action-list" aria-label="Prioritized Active actions">
      {visibleActions.map((action) => {
        const presentation = actionPresentation(action);
        return <li key={action.id}>
          <div className="active-action-heading"><span className={`status-pill urgency-${action.urgency}`}>{urgencyLabel(action.urgency)}</span><strong>{presentation.title}</strong></div>
          <p>{presentation.explanation}</p>
          <dl><dt>Asset</dt><dd>{assetNames.get(action.asset_id) ?? `Authorized asset ${action.asset_id.slice(0, 8)}…`}</dd><dt>Timing</dt><dd>{actionTiming(action, summary.generated_at)}</dd>{action.occurrence_count > 1 ? <><dt>Signals</dt><dd>{action.occurrence_count} recorded changes</dd></> : null}</dl>
          <button type="button" className="secondary-button" onClick={() => void onOpen(action.asset_id, action.id)} disabled={openingId === action.id}>{openingId === action.id ? 'Opening…' : canManage ? presentation.action : 'Review details'}</button>
        </li>;
      })}
    </ol>}
  </section>;
}

function ActiveChangeApprovalPanel({ approvals, loading, error, currentRole, onChanged }: {
  approvals: ActiveChangeApproval[];
  loading: boolean;
  error: string | null;
  currentRole: TeamRole | null;
  onChanged: () => Promise<void>;
}) {
  const [decidingId, setDecidingId] = useState<string | null>(null);
  const [decisionError, setDecisionError] = useState<string | null>(null);
  const actionable = approvals.filter((item) => ['pending', 'approved', 'interrupted'].includes(item.status));

  async function decide(item: ActiveChangeApproval, decision: 'approve' | 'reject') {
    setDecidingId(item.id);
    setDecisionError(null);
    try {
      await decideActiveChangeApproval(item.id, decision);
      await onChanged();
    } catch (caught) {
      setDecisionError(caught instanceof Error ? caught.message : 'The approval decision could not be recorded.');
    } finally {
      setDecidingId(null);
    }
  }

  return <section className="active-approval-panel" aria-labelledby="active-approval-title" aria-busy={loading}>
    <div className="active-form-heading"><div><span className="eyebrow">Separation of duties</span><h3 id="active-approval-title">Four-eyes approvals</h3><p>Registration, renewal and ordinary revocation require a different current administrator. Reviews expire after 24 hours and bind only the closed critical change.</p></div><span className="status-pill">Operator enabled</span></div>
    <p className="muted">Authorization references, notes, responsible account identities and complete mutation payloads are never retained here. An administrator may apply an immediate security hold without waiting.</p>
    {loading ? <p role="status" className="muted">Loading approval timeline…</p> : null}
    {error ? <p role="alert" className="error-text">{error}</p> : null}
    {decisionError ? <p role="alert" className="error-text">{decisionError}</p> : null}
    {!loading && !error && actionable.length === 0 ? <div className="empty-state"><strong>No actionable critical changes.</strong><p>Submit a registration, renewal or ordinary revocation to create a bounded review.</p></div> : null}
    {actionable.length ? <ol className="active-approval-list" aria-label="Active change approval timeline">{actionable.map((item) => <li key={item.id}>
      <div className="active-action-heading"><span className={`status-pill ${item.status === 'approved' ? 'ok' : ''}`}>{item.status}</span><strong>{item.kind.replace(/_/g, ' ')} · {item.summary.scope_change.replace(/_/g, ' ')}</strong></div>
      <dl><dt>Review</dt><dd><code>{item.operation_digest_prefix}…</code></dd><dt>Asset</dt><dd>{item.summary.review_target ?? (item.asset_id ? `Existing asset ${item.asset_id.slice(0, 8)}…` : 'Target scrubbed')}</dd><dt>Scope</dt><dd>{item.summary.capabilities.length ? `${item.summary.capabilities.length} capabilities · ${item.summary.allowed_protocols.join(', ')}${item.summary.allowed_ports.length ? ` · ports ${item.summary.allowed_ports.join(', ')}` : ''}` : item.summary.reason_code?.replace(/_/g, ' ') ?? 'No executable scope retained'}</dd><dt>Expires</dt><dd>{new Date(item.expires_at).toLocaleString()}</dd></dl>
      {item.status === 'approved' && item.requested_by_current_user ? <p className="success-text" role="status">Approved. Submit the unchanged critical fields again to apply this one-use review.</p> : null}
      {item.status === 'interrupted' ? <p className="warning-text" role="status">Application was interrupted. Request a new review; Inspectra will not replay it.</p> : null}
      {item.can_approve && currentRole === 'administrator' ? <div className="row-actions"><button type="button" onClick={() => void decide(item, 'approve')} disabled={decidingId === item.id}>{decidingId === item.id ? 'Recording…' : 'Approve exact change'}</button><button type="button" className="secondary-button" onClick={() => void decide(item, 'reject')} disabled={decidingId === item.id}>Reject</button></div> : null}
      {item.status === 'pending' && item.requested_by_current_user ? <p className="muted">Waiting for a different current administrator.</p> : null}
    </li>)}</ol> : null}
  </section>;
}

function ActiveAssetForm({ members, fourEyesEnabled, onApprovalChanged, onCreated }: { members: TeamMember[] | null; fourEyesEnabled: boolean; onApprovalChanged: () => Promise<void>; onCreated: (asset: ActiveAsset) => void }) {
  const [assetType, setAssetType] = useState<ActiveAsset['asset_type']>('domain');
  const [value, setValue] = useState('');
  const [reference, setReference] = useState('');
  const [expiry, setExpiry] = useState(() => localDateTime(new Date(Date.now() + 30 * 86_400_000)));
  const [capabilities, setCapabilities] = useState<ActiveCapability[]>([]);
  const [ports, setPorts] = useState('443');
  const [confirmed, setConfirmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [responsibleUserIds, setResponsibleUserIds] = useState<string[]>([]);
  const [approvalNotice, setApprovalNotice] = useState<string | null>(null);

  const protocols = useMemo(() => {
    const result = new Set<ActiveAsset['allowed_protocols'][number]>();
    if (capabilities.some((item) => item.startsWith('active_dns_'))) result.add('dns');
    if (capabilities.includes('active_nmap_basic')) result.add('tcp');
    if (capabilities.includes('active_tls_basic')) result.add('tls');
    if (capabilities.includes('active_http_basic_header_review')) result.add(assetType === 'http_origin' && value.trim().startsWith('http://') ? 'http' : 'https');
    return [...result];
  }, [assetType, capabilities, value]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const allowedPorts = ports.split(',').map((item) => item.trim()).filter(Boolean).map(Number);
      const payload: ActiveAssetCreateRequest = {
        asset_type: assetType,
        value: value.trim(),
        responsible_user_ids: responsibleUserIds,
        capabilities,
        allowed_ports: capabilities.some((item) => ['active_nmap_basic', 'active_tls_basic'].includes(item)) ? allowedPorts : [],
        allowed_protocols: protocols,
        authorization_method: 'manual_attestation',
        authorization_reference: reference.trim(),
        authorized_at: new Date().toISOString(),
        expires_at: new Date(expiry).toISOString(),
        notes: [],
      };
      let approvalId: string | undefined;
      if (fourEyesEnabled) {
        const approval = await requestActiveRegistrationApproval(payload);
        await onApprovalChanged();
        if (approval.status !== 'approved') {
          setApprovalNotice('Review requested. A different administrator must approve it; then submit these unchanged critical fields again.');
          return;
        }
        approvalId = approval.id;
      }
      const asset = await createActiveAsset(payload, approvalId);
      if (fourEyesEnabled) await onApprovalChanged();
      onCreated(asset);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'The asset could not be registered.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form id="active-asset-create" className="active-asset-form" onSubmit={(event) => void submit(event)}>
      <div className="active-form-heading">
        <div><h3>Register an exact asset</h3><p className="muted">Wildcards, CIDR ranges, URL paths, credentials and derived targets are rejected.</p></div>
        <span className="status-pill">Manual attestation</span>
      </div>
      <div className="active-form-grid">
        <label><span>Asset type</span><select value={assetType} onChange={(event) => setAssetType(event.target.value as ActiveAsset['asset_type'])}><option value="domain">Domain</option><option value="host">Host</option><option value="ip">IP address</option><option value="http_origin">HTTP origin</option></select></label>
        <label><span>Exact value</span><input required className="search-input" value={value} onChange={(event) => setValue(event.target.value)} placeholder={assetType === 'http_origin' ? 'https://app.example.test' : 'app.example.test'} /></label>
        <label><span>Authorization reference</span><input required className="search-input" maxLength={96} value={reference} onChange={(event) => setReference(event.target.value)} placeholder="change-ticket SEC-42" /></label>
        <label><span>Authorization expires</span><input required type="datetime-local" value={expiry} min={localDateTime(new Date(Date.now() + 60_000))} onChange={(event) => setExpiry(event.target.value)} /></label>
      </div>
      <ResponsibleMemberSelector members={members} value={responsibleUserIds} onChange={setResponsibleUserIds} />
      <fieldset><legend>Authorized capabilities</legend><div className="capability-choice-grid">{CAPABILITIES.map((capability) => <label key={capability.id} className="capability-choice"><input type="checkbox" checked={capabilities.includes(capability.id)} onChange={(event) => setCapabilities((current) => event.target.checked ? [...current, capability.id] : current.filter((item) => item !== capability.id))} /><span><strong>{capability.label}</strong><small>{capability.detail}</small></span></label>)}</div></fieldset>
      {capabilities.some((item) => ['active_nmap_basic', 'active_tls_basic'].includes(item)) ? <label><span>Explicit TCP/TLS ports (comma-separated, maximum 64)</span><input required className="search-input" value={ports} onChange={(event) => setPorts(event.target.value)} inputMode="numeric" placeholder="443, 8443" /></label> : null}
      <dl className="summary-list"><dt>Protocols derived from scope</dt><dd>{protocols.join(', ') || 'Select a capability'}</dd><dt>Target expansion</dt><dd>Never</dd><dt>Evidence retained</dt><dd>Reference label and structured history only</dd></dl>
      <label className="checkbox-row"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />I confirm this exact asset and selected capabilities are currently authorized.</label>
      {error ? <p className="error-text" role="alert">{error}</p> : null}
      {approvalNotice ? <p className="success-text" role="status">{approvalNotice}</p> : null}
      <button type="submit" disabled={submitting || !confirmed || capabilities.length === 0 || protocols.length === 0}>{submitting ? 'Checking approval…' : fourEyesEnabled ? 'Request or apply reviewed registration' : 'Register authorized asset'}</button>
    </form>
  );
}

function ActiveAssetResponsiblesForm({ asset, members, onSaved, onCancel }: { asset: ActiveAsset; members: TeamMember[] | null; onSaved: (asset: ActiveAsset) => void; onCancel: () => void }) {
  const [responsibleUserIds, setResponsibleUserIds] = useState<string[]>([...asset.responsible_user_ids]);
  const [confirmed, setConfirmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      onSaved(await updateActiveAssetResponsibles(asset.id, {
        responsible_user_ids: responsibleUserIds,
        expected_updated_at: asset.updated_at,
        assignment_confirmed: true,
      }));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Responsible accounts could not be updated safely.');
    } finally {
      setSubmitting(false);
    }
  }

  return <form className="active-asset-form" onSubmit={(event) => void submit(event)}>
    <div className="active-form-heading"><div><h4>Manage responsible accounts</h4><p className="muted">This changes operational assignment only. Authorization scope and its revision remain unchanged.</p></div><span className="status-pill">Current workspace</span></div>
    <ResponsibleMemberSelector members={members} value={responsibleUserIds} onChange={(values) => { setResponsibleUserIds(values); setConfirmed(false); }} preserveUnavailable />
    <label className="checkbox-row"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />I confirm this assignment reflects the current workspace responsibility.</label>
    <div className="row-actions"><button type="submit" disabled={submitting || !confirmed || members === null}>{submitting ? 'Saving…' : 'Save responsible accounts'}</button><button type="button" className="secondary-button" onClick={onCancel} disabled={submitting}>Cancel</button></div>
    {error ? <p className="error-text" role="alert">{error}</p> : null}
  </form>;
}

function ActiveAssetRenewalForm({ asset, members, fourEyesEnabled, onApprovalChanged, onRenewed, onCancel }: { asset: ActiveAsset; members: TeamMember[] | null; fourEyesEnabled: boolean; onApprovalChanged: () => Promise<void>; onRenewed: (asset: ActiveAsset, replayed: boolean, scopeExpanded: boolean) => void; onCancel: () => void }) {
  const [reference, setReference] = useState(asset.authorization_reference);
  const [expiry, setExpiry] = useState(() => localDateTime(new Date(Date.now() + 90 * 86_400_000)));
  const [method, setMethod] = useState<ActiveAsset['authorization_method']>(asset.authorization_method);
  const [capabilities, setCapabilities] = useState<ActiveCapability[]>([...asset.capabilities]);
  const [ports, setPorts] = useState(asset.allowed_ports.join(', ') || '443');
  const [renewalConfirmed, setRenewalConfirmed] = useState(false);
  const [expansionConfirmed, setExpansionConfirmed] = useState(false);
  const [responsibleUserIds, setResponsibleUserIds] = useState<string[]>([...asset.responsible_user_ids]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [approvalNotice, setApprovalNotice] = useState<string | null>(null);
  const idempotencyKey = useRef<string | null>(null);
  const currentRevision = asset.authorization_revisions?.[asset.authorization_revisions.length - 1] ?? null;
  const protocols = useMemo(() => {
    const result = new Set<ActiveAsset['allowed_protocols'][number]>();
    if (capabilities.some((item) => item.startsWith('active_dns_'))) result.add('dns');
    if (capabilities.includes('active_nmap_basic')) result.add('tcp');
    if (capabilities.includes('active_tls_basic')) result.add('tls');
    if (capabilities.includes('active_http_basic_header_review')) {
      if (asset.allowed_protocols.includes('http')) result.add('http');
      if (asset.allowed_protocols.includes('https') || !asset.allowed_protocols.includes('http')) result.add('https');
    }
    return [...result];
  }, [asset.allowed_protocols, capabilities]);
  const parsedPorts = ports.split(',').map((item) => item.trim()).filter(Boolean).map(Number);
  const effectivePorts = capabilities.some((item) => item === 'active_nmap_basic' || item === 'active_tls_basic') ? parsedPorts : [];
  const scopeExpanded = hasExpandedScope(asset, capabilities, effectivePorts, protocols);

  function changed() {
    idempotencyKey.current = null;
    setExpansionConfirmed(false);
    setError(null);
    setApprovalNotice(null);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (effectivePorts.some((item) => !Number.isInteger(item) || item < 1 || item > 65535)) {
      setError('Ports must be explicit integers between 1 and 65535.');
      return;
    }
    setSubmitting(true);
    setError(null);
    idempotencyKey.current ??= createIdempotencyKey();
    try {
      const payload = {
        idempotency_key: idempotencyKey.current,
        expected_revision_id: currentRevision?.id ?? null,
        responsible_user_ids: responsibleUserIds,
        capabilities,
        allowed_ports: effectivePorts,
        allowed_protocols: protocols,
        authorization_method: method,
        authorization_reference: reference.trim(),
        authorized_at: new Date().toISOString(),
        expires_at: new Date(expiry).toISOString(),
        renewal_confirmed: true,
        scope_expansion_confirmed: scopeExpanded && expansionConfirmed,
      } as const;
      let approvalId: string | undefined;
      if (fourEyesEnabled) {
        const approval = await requestActiveRenewalApproval(asset.id, payload);
        await onApprovalChanged();
        if (approval.status !== 'approved') {
          setApprovalNotice('Review requested. Keep this draft unchanged and submit it again after a different administrator approves it.');
          return;
        }
        approvalId = approval.id;
      }
      const response = await renewActiveAsset(asset.id, payload, approvalId);
      if (fourEyesEnabled) await onApprovalChanged();
      idempotencyKey.current = null;
      onRenewed(response.asset, response.replayed, response.scope_expanded);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'The authorization could not be renewed safely.');
    } finally { setSubmitting(false); }
  }

  return <form className="active-asset-form" onSubmit={(event) => void submit(event)}>
    <div className="active-form-heading"><div><h4>Renew authorization</h4><p className="muted">This appends a revision for the same exact asset. It never edits previous revisions or revives a revoked asset.</p></div><span className="status-pill">Next revision {currentRevision ? currentRevision.sequence + 1 : 1}</span></div>
    <div className="active-form-grid">
      <label><span>Authorization method</span><select value={method} onChange={(event) => { changed(); setMethod(event.target.value as ActiveAsset['authorization_method']); }}><option value="manual_attestation">Manual attestation</option><option value="dns_txt">DNS TXT</option><option value="http_well_known">HTTP well-known</option><option value="managed_private">Managed private</option></select></label>
      <label><span>New authorization reference</span><input required maxLength={96} value={reference} onChange={(event) => { changed(); setReference(event.target.value); }} /></label>
      <label><span>New expiry</span><input required type="datetime-local" min={localDateTime(new Date(Date.now() + 60_000))} value={expiry} onChange={(event) => { changed(); setExpiry(event.target.value); }} /></label>
    </div>
    <ResponsibleMemberSelector members={members} value={responsibleUserIds} onChange={(values) => { changed(); setResponsibleUserIds(values); }} preserveUnavailable />
    <fieldset><legend>Scope for the new revision</legend><div className="capability-choice-grid">{CAPABILITIES.map((item) => <label key={item.id} className="capability-choice"><input type="checkbox" checked={capabilities.includes(item.id)} onChange={(event) => { changed(); setCapabilities((current) => event.target.checked ? [...current, item.id] : current.filter((entry) => entry !== item.id)); }} /><span><strong>{item.label}</strong><small>{item.detail}</small></span></label>)}</div></fieldset>
    {capabilities.some((item) => item === 'active_nmap_basic' || item === 'active_tls_basic') ? <label><span>Explicit TCP/TLS ports</span><input required value={ports} onChange={(event) => { changed(); setPorts(event.target.value); }} inputMode="numeric" /></label> : null}
    <dl className="summary-list"><dt>Protocols</dt><dd>{protocols.join(', ') || 'Select a capability'}</dd><dt>Scope change</dt><dd>{scopeExpanded ? 'Expansion — separate confirmation required' : 'Same or reduced scope'}</dd><dt>Previous evidence</dt><dd>Preserved append-only</dd></dl>
    {scopeExpanded ? <label className="checkbox-row"><input type="checkbox" checked={expansionConfirmed} onChange={(event) => setExpansionConfirmed(event.target.checked)} />I specifically authorize the newly added capability, protocol, or port scope.</label> : null}
    <label className="checkbox-row"><input type="checkbox" checked={renewalConfirmed} onChange={(event) => setRenewalConfirmed(event.target.checked)} />I re-attest that this exact asset and the complete scope above are currently authorized.</label>
    {approvalNotice ? <p className="success-text" role="status">{approvalNotice}</p> : null}
    <div className="row-actions"><button type="submit" disabled={submitting || !renewalConfirmed || capabilities.length === 0 || protocols.length === 0 || (scopeExpanded && !expansionConfirmed)}>{submitting ? 'Checking approval…' : fourEyesEnabled ? 'Request or apply reviewed renewal' : 'Append authorization revision'}</button><button type="button" className="secondary-button" onClick={onCancel} disabled={submitting}>Cancel</button></div>
    {error ? <p className="error-text" role="alert">{error}</p> : null}
  </form>;
}

function ActiveAssetCard({ asset, members, canManage, currentRole, fourEyesEnabled, onApprovalChanged, verificationConfiguration, capabilityReadiness, admissionAvailable, focusToken, onChanged, onDeleted, onPortfolioChanged, onJobCreated }: { asset: ActiveAsset; members: TeamMember[] | null; canManage: boolean; currentRole: TeamRole | null; fourEyesEnabled: boolean; onApprovalChanged: () => Promise<void>; verificationConfiguration: ActiveAssetVerificationConfiguration | null; capabilityReadiness: Map<ActiveCapability, ActiveOperationsSummary['capabilities'][number]>; admissionAvailable: boolean; focusToken: number | null; onChanged: (asset: ActiveAsset) => void; onDeleted: () => void | Promise<void>; onPortfolioChanged: () => Promise<void>; onJobCreated?: (job: JobRecord) => void | Promise<void> }) {
  const [expanded, setExpanded] = useState(false);
  const detailId = `active-asset-detail-${asset.id}`;
  const detailRef = useRef<HTMLDivElement>(null);
  const [revoking, setRevoking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [capability, setCapability] = useState<ActiveCapability>(asset.capabilities[0]);
  const [port, setPort] = useState<number | ''>(asset.allowed_ports[0] ?? '');
  const [reconfirmed, setReconfirmed] = useState(false);
  const [running, setRunning] = useState(false);
  const [executionActionId, setExecutionActionId] = useState<string | null>(null);
  const [posture, setPosture] = useState<ActiveAssetPostureResponse | null>(null);
  const [postureLoading, setPostureLoading] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [verification, setVerification] = useState<ActiveAssetVerification | null>(null);
  const [verificationLoading, setVerificationLoading] = useState(false);
  const [verificationMethod, setVerificationMethod] = useState<ActiveAssetVerificationMethod>('manual_attestation');
  const [verificationChallenge, setVerificationChallenge] = useState<ActiveAssetVerificationChallenge | null>(null);
  const [manualVerificationConfirmed, setManualVerificationConfirmed] = useState(false);
  const [showRenewal, setShowRenewal] = useState(false);
  const [showResponsibles, setShowResponsibles] = useState(false);
  const [renewalNotice, setRenewalNotice] = useState<string | null>(null);
  const [revocationNotice, setRevocationNotice] = useState<string | null>(null);
  const [responsibleNotice, setResponsibleNotice] = useState<string | null>(null);
  const [evidencePeriod, setEvidencePeriod] = useState<'30d' | '90d' | '365d' | 'all'>('90d');
  const historyButtonRef = useRef<HTMLButtonElement>(null);
  const authorizationRevision = asset.authorization_revisions?.[asset.authorization_revisions.length - 1] ?? null;
  const responsibleNames = responsibleLabels(asset.responsible_user_ids, members);
  const selectedReadiness = effectiveReadiness(capabilityReadiness.get(capability));
  const availableVerificationMethods = useMemo(() => Object.entries(verificationConfiguration?.methods ?? {})
    .filter(([method, enabled]) => enabled && verificationMethodSupportsAsset(method as ActiveAssetVerificationMethod, asset))
    .map(([method]) => method as ActiveAssetVerificationMethod), [asset, verificationConfiguration]);

  useEffect(() => {
    if (availableVerificationMethods.length > 0 && !availableVerificationMethods.includes(verificationMethod)) {
      setVerificationMethod(availableVerificationMethods[0]);
    }
  }, [availableVerificationMethods, verificationMethod]);

  const refreshPosture = useCallback(async () => {
    setPostureLoading(true);
    try {
      const refreshed = await getActiveAssetPosture(asset.id);
      setPosture((current) => {
        if (!current) return refreshed;
        const executions = mergeActiveExecutions(refreshed.executions, current.executions);
        const hasMore = executions.length < refreshed.history.total_count;
        return {
          ...refreshed,
          executions,
          history: {
            ...refreshed.history,
            returned_count: executions.length,
            next_cursor: hasMore
              ? (current.executions.length > refreshed.executions.length
                ? (current.history.next_cursor ?? refreshed.history.next_cursor)
                : refreshed.history.next_cursor)
              : null,
            has_more: hasMore,
          },
        };
      });
      setHistoryError(null);
    }
    catch (caught) { setError(caught instanceof Error ? caught.message : 'Active history could not be loaded.'); }
    finally { setPostureLoading(false); }
  }, [asset.id]);

  async function loadOlderExecutions() {
    if (!posture?.history.next_cursor || historyLoading) return;
    setHistoryLoading(true); setHistoryError(null);
    try {
      const page = await listActiveAssetExecutionPage(asset.id, posture.history.next_cursor);
      setPosture((current) => current ? {
        ...current,
        executions: mergeActiveExecutions(current.executions, page.items),
        history: {
          ...current.history,
          returned_count: mergeActiveExecutions(current.executions, page.items).length,
          total_count: page.total_count,
          has_more: page.has_more,
          next_cursor: page.next_cursor,
        },
      } : current);
      window.setTimeout(() => historyButtonRef.current?.focus(), 0);
    } catch (caught) {
      setHistoryError(caught instanceof Error ? caught.message : 'Older executions could not be loaded.');
    } finally { setHistoryLoading(false); }
  }

  const refreshVerification = useCallback(async () => {
    setVerificationLoading(true);
    try { setVerification(await getActiveAssetVerification(asset.id)); }
    catch (caught) { setError(caught instanceof Error ? caught.message : 'Control verification state could not be loaded.'); }
    finally { setVerificationLoading(false); }
  }, [asset.id]);

  useEffect(() => { if (expanded) { void refreshPosture(); void refreshVerification(); } }, [expanded, refreshPosture, refreshVerification]);

  useEffect(() => {
    if (focusToken === null) return undefined;
    setExpanded(true);
    const handle = window.setTimeout(() => detailRef.current?.focus(), 0);
    return () => window.clearTimeout(handle);
  }, [focusToken]);

  const hasInFlightExecution = posture?.executions.some((execution) => ['queued', 'running', 'cancelling'].includes(execution.status)) ?? false;
  useEffect(() => {
    if (!expanded || !hasInFlightExecution) return undefined;
    const interval = window.setInterval(() => { void refreshPosture(); }, 1000);
    return () => window.clearInterval(interval);
  }, [expanded, hasInFlightExecution, refreshPosture]);

  async function revoke() {
    if (!window.confirm(`Revoke authorization for ${asset.canonical_value}? Pending work will be blocked.`)) return;
    setRevoking(true); setError(null);
    try {
      let approvalId: string | undefined;
      if (fourEyesEnabled) {
        const approval = await requestActiveRevocationApproval(asset.id, 'authorization_withdrawn');
        await onApprovalChanged();
        if (approval.status !== 'approved') {
          setRevocationNotice('Revocation review requested. Submit again after a different administrator approves it, or use an emergency security hold if delay is unsafe.');
          return;
        }
        approvalId = approval.id;
      }
      onChanged(await revokeActiveAsset(asset.id, 'authorization_withdrawn', approvalId));
      if (fourEyesEnabled) await onApprovalChanged();
    }
    catch (caught) { setError(caught instanceof Error ? caught.message : 'Authorization could not be revoked.'); }
    finally { setRevoking(false); }
  }

  async function emergencySecurityHold() {
    if (!window.confirm(`Apply an immediate security hold to ${asset.canonical_value}? This bypass is audited and stops pending work.`)) return;
    setRevoking(true); setError(null);
    try { onChanged(await revokeActiveAsset(asset.id, 'security_hold')); }
    catch (caught) { setError(caught instanceof Error ? caught.message : 'Emergency security hold could not be applied.'); }
    finally { setRevoking(false); }
  }

  async function execute() {
    setRunning(true); setError(null);
    try {
      const job = await createActiveAssetExecution(asset.id, {
        capability,
        ...(capability === 'active_tls_basic' && typeof port === 'number' ? { port } : {}),
        authorization_reconfirmed: true,
        idempotency_key: createIdempotencyKey(),
      });
      setReconfirmed(false);
      await onJobCreated?.(job);
      await refreshPosture();
      await onPortfolioChanged();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'The bounded execution could not be created.');
    } finally { setRunning(false); }
  }

  async function cancelExecution(jobId: string) {
    setExecutionActionId(jobId); setError(null);
    try { await cancelActiveAssetExecution(asset.id, jobId); await refreshPosture(); await onPortfolioChanged(); }
    catch (caught) { setError(caught instanceof Error ? caught.message : 'The execution could not be cancelled.'); }
    finally { setExecutionActionId(null); }
  }

  async function retryExecution(jobId: string) {
    if (!window.confirm('Retry this bounded capability against the current immutable authorization?')) return;
    setExecutionActionId(jobId); setError(null);
    try {
      const job = await retryActiveAssetExecution(asset.id, jobId);
      await onJobCreated?.(job);
      await refreshPosture();
      await onPortfolioChanged();
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'The execution could not be retried.'); }
    finally { setExecutionActionId(null); }
  }

  async function chooseBaseline(executionId: string) {
    setError(null);
    try { onChanged(await setActiveAssetBaseline(asset.id, executionId)); await refreshPosture(); }
    catch (caught) { setError(caught instanceof Error ? caught.message : 'The baseline could not be selected.'); }
  }

  async function triage(signal: string, status: 'needs_review' | 'acknowledged' | 'expected_change' | 'dismissed') {
    setError(null);
    try {
      onChanged(await setActiveAssetTriage(asset.id, { observation_key: signal, status, comment_code: status === 'needs_review' ? 'needs_owner_review' : status === 'expected_change' ? 'planned_change' : status === 'dismissed' ? 'not_applicable' : 'investigating' }));
      await refreshPosture();
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'The observation triage could not be saved.'); }
  }

  async function startVerification() {
    setVerificationLoading(true); setError(null); setVerificationChallenge(null); setManualVerificationConfirmed(false);
    try {
      const challenge = await startActiveAssetVerification(asset.id, verificationMethod);
      setVerification(challenge.verification);
      setVerificationChallenge(challenge);
      await onPortfolioChanged();
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Control verification could not be started.'); }
    finally { setVerificationLoading(false); }
  }

  async function checkVerification() {
    if (!verificationChallenge) return;
    setVerificationLoading(true); setError(null);
    try {
      const checked = await checkActiveAssetVerification(asset.id, {
        verification_id: verificationChallenge.verification.id,
        challenge_token: verificationChallenge.challenge_token,
        manual_attestation_confirmed: verificationChallenge.verification.method === 'manual_attestation' && manualVerificationConfirmed,
      });
      setVerification(checked);
      setVerificationChallenge(null);
      setManualVerificationConfirmed(false);
      await onPortfolioChanged();
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Control verification could not be checked.'); }
    finally { setVerificationLoading(false); }
  }

  async function revokeVerification() {
    if (!verification) return;
    setVerificationLoading(true); setError(null);
    try { setVerification(await revokeActiveAssetVerification(asset.id, verification.id)); setVerificationChallenge(null); await onPortfolioChanged(); }
    catch (caught) { setError(caught instanceof Error ? caught.message : 'Control verification could not be revoked.'); }
    finally { setVerificationLoading(false); }
  }

  return <article className={`active-asset-card status-${asset.status}${expanded ? ' expanded' : ''}`}>
    <div className="active-asset-card-heading">
      <div><span className={`status-pill ${asset.status === 'active' ? 'ok' : ''}`}>{asset.status}</span><h3>{asset.canonical_value}</h3><p>{asset.asset_type.replace('_', ' ')} · expires {new Date(asset.expires_at).toLocaleString()}</p></div>
      <button type="button" className="secondary-button" onClick={() => setExpanded((value) => !value)} aria-expanded={expanded} aria-controls={detailId}>{expanded ? 'Close details' : 'Details'}</button>
    </div>
    <div className="badge-row">{asset.capabilities.map((item) => <span className="status-pill" key={item}>{CAPABILITIES.find((entry) => entry.id === item)?.label ?? item}</span>)}</div>
    {expanded ? <div ref={detailRef} id={detailId} className="active-asset-detail" tabIndex={-1}>
      <dl className="summary-list"><dt>Ports</dt><dd>{asset.allowed_ports.join(', ') || 'Not applicable'}</dd><dt>Protocols</dt><dd>{asset.allowed_protocols.join(', ')}</dd><dt>Responsible</dt><dd>{responsibleNames.length ? responsibleNames.join(', ') : 'Unassigned'}</dd><dt>Authorization</dt><dd>{asset.authorization_method.replace(/_/g, ' ')} · {asset.authorization_reference}</dd><dt>Authorization revision</dt><dd>{authorizationRevision ? <>Revision {authorizationRevision.sequence} · <code>{authorizationRevision.id.slice(0, 12)}…</code></> : 'Legacy / unknown · re-attestation required'}</dd><dt>History</dt><dd>{asset.history.length} append-only events</dd></dl>
      {asset.authorization_revisions?.length ? <details><summary>Authorization revision history</summary><ol className="active-timeline">{[...asset.authorization_revisions].reverse().map((revision) => <li key={revision.id}><strong>Revision {revision.sequence} · {revision.source}{revision.scope_expanded ? ' · scope expanded' : ''}</strong><span>{new Date(revision.authorized_at).toLocaleString()} → {new Date(revision.expires_at).toLocaleString()}</span><small>{revision.capabilities.length} capabilities · {revision.allowed_protocols.join(', ')}{revision.allowed_ports.length ? ` · ports ${revision.allowed_ports.join(', ')}` : ''} · {revision.id.slice(0, 12)}…</small></li>)}</ol></details> : null}
      {canManage ? <button type="button" className="secondary-button" onClick={() => { setShowResponsibles((value) => !value); setResponsibleNotice(null); }}>{showResponsibles ? 'Close responsibility editor' : 'Manage responsible accounts'}</button> : null}
      {showResponsibles ? <ActiveAssetResponsiblesForm asset={asset} members={members} onCancel={() => setShowResponsibles(false)} onSaved={(updated) => { onChanged(updated); setShowResponsibles(false); setResponsibleNotice(updated.responsible_user_ids.length ? 'Responsible accounts updated.' : 'Asset is now unassigned.'); }} /> : null}
      {responsibleNotice ? <p className="success-text" role="status">{responsibleNotice}</p> : null}
      {canManage && asset.status !== 'revoked' ? <button type="button" className="secondary-button" onClick={() => { setShowRenewal((value) => !value); setRenewalNotice(null); }}>{showRenewal ? 'Close renewal' : asset.status === 'expired' || !authorizationRevision ? 'Re-attest authorization' : 'Renew authorization'}</button> : null}
      {showRenewal ? <ActiveAssetRenewalForm asset={asset} members={members} fourEyesEnabled={fourEyesEnabled} onApprovalChanged={onApprovalChanged} onCancel={() => setShowRenewal(false)} onRenewed={(updated, replayed, expanded) => { onChanged(updated); setShowRenewal(false); setRenewalNotice(replayed ? 'The existing authorization revision was recovered idempotently.' : `Authorization revision ${updated.authorization_revisions?.[updated.authorization_revisions.length - 1]?.sequence ?? 'unknown'} appended${expanded ? ' with explicitly confirmed expanded scope' : ''}.`); }} /> : null}
      {renewalNotice ? <p className="success-text" role="status">{renewalNotice}</p> : null}
      <section className="active-verification" aria-label={`Control verification for ${asset.canonical_value}`}>
        <div className="active-form-heading"><div><h4>Optional control verification</h4><p className="muted">This adds a time-bound control signal. It never establishes legal ownership or expands authorized scope.</p></div>{verification ? <span className={`status-pill ${verification.status === 'verified' ? 'ok' : ''}`}>{verification.status}</span> : null}</div>
        {verificationLoading ? <p role="status" className="muted">Updating verification state…</p> : null}
        {!verificationConfiguration ? <p className="muted">Loading operator policy…</p> : !verificationConfiguration.enabled ? <p className="empty-state">Verification is disabled by the operator. No DNS, HTTP or managed check can leave Inspectra.</p> : null}
        {verification && !verificationChallenge ? <dl className="summary-list"><dt>Method</dt><dd>{verification.method.replace(/_/g, ' ')}</dd><dt>State</dt><dd>{verification.status}</dd><dt>Valid until</dt><dd>{verification.verification_expires_at ? new Date(verification.verification_expires_at).toLocaleString() : 'Not verified'}</dd></dl> : null}
        {verificationConfiguration?.enabled && canManage && asset.status === 'active' && !verificationChallenge && availableVerificationMethods.length > 0 ? <div className="active-verification-controls">
          <label><span>Verification method</span><select value={verificationMethod} onChange={(event) => setVerificationMethod(event.target.value as ActiveAssetVerificationMethod)}>
            {availableVerificationMethods.map((method) => <option key={method} value={method}>{method.replace(/_/g, ' ')}</option>)}
          </select></label>
          <button type="button" className="secondary-button" onClick={() => void startVerification()} disabled={verificationLoading}>Create bounded challenge</button>
        </div> : null}
        {verificationChallenge ? <div className="active-verification-challenge">
          <p><strong>Copy this challenge now; Inspectra stores only its SHA-256 digest.</strong></p>
          <code>{verificationChallenge.challenge_token}</code>
          <p>Placement: <code>{verificationChallenge.placement}</code></p>
          <p className="muted">The challenge expires {new Date(verificationChallenge.verification.challenge_expires_at).toLocaleString()}. Full DNS/HTTP responses are never retained and redirects are never followed.</p>
          {verificationChallenge.verification.method === 'manual_attestation' ? <label className="checkbox-row"><input type="checkbox" checked={manualVerificationConfirmed} onChange={(event) => setManualVerificationConfirmed(event.target.checked)} />I attest again that I control this exact asset; this is not proof of legal ownership.</label> : null}
          <button type="button" onClick={() => void checkVerification()} disabled={verificationLoading || (verificationChallenge.verification.method === 'manual_attestation' && !manualVerificationConfirmed)}>Check exact challenge</button>
        </div> : null}
        {verification && verification.status === 'verified' && canManage ? <button type="button" className="danger-button" onClick={() => void revokeVerification()} disabled={verificationLoading}>Revoke control verification</button> : null}
      </section>
      <ActiveRecurrencePanel asset={asset} verification={verification} canManage={canManage} />
      {asset.status === 'active' && canManage && !authorizationRevision ? <p className="empty-state" role="status">This legacy authorization has no immutable revision. Re-attestation is required before any execution.</p> : null}
      {asset.status === 'active' && canManage && authorizationRevision ? <div className="active-execution-form">
        <h4>Run bounded observation</h4>
        <label><span>Authorized capability</span><select value={capability} onChange={(event) => { setCapability(event.target.value as ActiveCapability); setReconfirmed(false); }}>{asset.capabilities.map((item) => <option value={item} key={item}>{CAPABILITIES.find((entry) => entry.id === item)?.label ?? item}</option>)}</select></label>
        {capability === 'active_tls_basic' ? <label><span>Authorized port</span><select value={port} onChange={(event) => setPort(Number(event.target.value))}>{asset.allowed_ports.map((item) => <option value={item} key={item}>{item}</option>)}</select></label> : null}
        <p className={selectedReadiness === 'ready' ? 'success-text' : 'warning-text'} role="status"><strong>{readinessLabel(selectedReadiness)}.</strong> {readinessExplanation(selectedReadiness)}</p>
        {!admissionAvailable ? <p className="warning-text" role="status">This organization cannot queue more Active work yet. Existing observations remain available.</p> : null}
        <p className="muted">Inspectra derives the exact target and immutable profile from authorization revision {authorizationRevision.sequence} (<code>{authorizationRevision.id.slice(0, 12)}…</code>). Redirects, discovered names and additional ports are never admitted.</p>
        <label className="checkbox-row"><input type="checkbox" checked={reconfirmed} onChange={(event) => setReconfirmed(event.target.checked)} />I reconfirm the authorization is current for this bounded execution.</label>
        <button type="button" onClick={() => void execute()} disabled={!reconfirmed || running || selectedReadiness !== 'ready' || !admissionAvailable}>{running ? 'Queueing bounded check…' : 'Run authorized check'}</button>
      </div> : null}
      <section className="active-posture" aria-label={`Posture history for ${asset.canonical_value}`}>
        <div className="active-form-heading"><div><h4>History and posture</h4><p className="muted">Exports omit the exact target, authorization reference, notes, accounts, challenges and raw runner output.</p></div><a className="secondary-button" href={activeAssetReportUrl(asset.id)}>Export Markdown</a></div>
        <div className="active-evidence-export">
          <label><span>Evidence period ending at retained state</span><select value={evidencePeriod} onChange={(event) => setEvidencePeriod(event.target.value as '30d' | '90d' | '365d' | 'all')}><option value="30d">30 days</option><option value="90d">90 days</option><option value="365d">365 days</option><option value="all">All retained history</option></select></label>
          <div><a className="secondary-button" href={activeAssetEvidenceBundleUrl(asset.id, evidencePeriod)}>Download verifiable TAR</a><small>Includes a versioned manifest and SHA-256 checksums; validate offline before relying on custody.</small></div>
        </div>
        {postureLoading ? <p className="muted" role="status">Loading comparable observations…</p> : null}
        {!postureLoading && posture?.executions.length === 0 ? <p className="empty-state">No bounded executions yet. Run an authorized capability to establish history.</p> : null}
        {posture ? <p className={posture.history.posture_incomplete ? 'warning-text' : 'muted'} role="status">Showing {posture.executions.length} of {posture.history.total_count} retained executions. Posture calculations considered {posture.history.posture_records_considered}{posture.history.posture_incomplete ? ' recent records plus the saved baseline; review older pages before treating history as complete.' : ' records and cover the retained history.'}</p> : null}
        {posture?.executions.length || posture?.baseline_execution ? <div className="table-wrap" role="region" aria-label="Active execution history" tabIndex={0}><table><thead><tr><th>Capability</th><th>Status</th><th>Progress</th><th>Authorization revision</th><th>When</th><th>Actions</th><th>Baseline</th></tr></thead><tbody>{mergeActiveExecutions(posture.executions, posture.baseline_execution ? [posture.baseline_execution] : []).map((execution) => <tr key={execution.id}><td>{CAPABILITIES.find((entry) => entry.id === execution.audit_type)?.label ?? execution.audit_type}</td><td>{execution.status}</td><td>{executionPhaseLabel(execution)}</td><td>{execution.active_authorization_revision_sequence && execution.active_authorization_revision_id ? <>Revision {execution.active_authorization_revision_sequence} · <code>{execution.active_authorization_revision_id.slice(0, 12)}…</code></> : 'Legacy / unknown'}</td><td>{new Date(execution.updated_at).toLocaleString()}</td><td>{canManage && ['queued', 'running', 'cancelling'].includes(execution.status) ? <button type="button" className="link-button" disabled={executionActionId === execution.id || execution.status === 'cancelling'} onClick={() => void cancelExecution(execution.id)}>{execution.status === 'cancelling' ? 'Cancelling…' : 'Cancel'}</button> : canManage && ['failed', 'cancelled'].includes(execution.status) ? <button type="button" className="link-button" disabled={executionActionId === execution.id || selectedReadiness !== 'ready'} onClick={() => void retryExecution(execution.id)}>Retry safely</button> : '—'}</td><td>{asset.baseline_execution_id === execution.id ? 'Selected' : canManage && ['completed', 'failed', 'cancelled'].includes(execution.status) ? <button type="button" className="link-button" onClick={() => void chooseBaseline(execution.id)}>Use baseline</button> : '—'}</td></tr>)}</tbody></table></div> : null}
        {historyError ? <p className="error-text" role="alert">{historyError}</p> : null}
        {posture && posture.history.total_count > 0 ? <button ref={historyButtonRef} type="button" className="secondary-button" disabled={historyLoading} aria-disabled={historyLoading || !posture.history.has_more} onClick={() => void loadOlderExecutions()}>{historyLoading ? 'Loading older executions…' : posture.history.has_more ? `Load older executions (${posture.executions.length} of ${posture.history.total_count})` : 'All retained executions are loaded'}</button> : null}
        {posture?.posture.comparison ? <div className="active-comparison"><p><strong>{posture.posture.comparison.state === 'ready' ? 'Comparable change' : 'Inconclusive change'}</strong> · {posture.posture.comparison.capability}</p>{posture.posture.comparison.authorization ? <p className="muted">Authorization revisions: {posture.posture.comparison.authorization.base.label} → {posture.posture.comparison.authorization.target.label}{posture.posture.comparison.authorization.same_revision === null ? ' · legacy evidence incomplete' : posture.posture.comparison.authorization.same_revision ? ' · same revision' : ' · authorization changed'}.</p> : null}<div className="badge-row"><span className="status-pill">{posture.posture.comparison.summary.new} new</span><span className="status-pill">{posture.posture.comparison.summary.changed} changed</span><span className="status-pill">{posture.posture.comparison.summary.disappeared} disappeared</span><span className="status-pill">{posture.posture.comparison.summary.persistent} persistent</span></div>{posture.posture.comparison.changes.length === 0 ? <p className="muted">No normalized observation changed.</p> : <ul>{posture.posture.comparison.changes.map((change) => <li key={change.signal}><code>{change.signal}</code><span>{change.interpretation}</span>{canManage ? <select aria-label={`Triage ${change.signal}`} defaultValue={asset.triage?.find((entry) => entry.observation_key === change.signal)?.status ?? 'needs_review'} onChange={(event) => void triage(change.signal, event.target.value as 'needs_review' | 'acknowledged' | 'expected_change' | 'dismissed')}><option value="needs_review">Needs review</option><option value="acknowledged">Acknowledged</option><option value="expected_change">Expected change</option><option value="dismissed">Not applicable</option></select> : null}</li>)}</ul>}</div> : null}
        {posture ? <details><summary>Comparison limits</summary><ul>{posture.posture.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul></details> : null}
      </section>
      <ol className="active-timeline">{[...asset.history].reverse().map((event) => <li key={event.id}><strong>{event.kind.replace(/_/g, ' ')}</strong><span>{new Date(event.occurred_at).toLocaleString()}</span>{event.reason_code ? <small>{event.reason_code.replace(/_/g, ' ')}</small> : null}</li>)}</ol>
      {revocationNotice ? <p className="success-text" role="status">{revocationNotice}</p> : null}
      {asset.status === 'active' && canManage ? <div className="row-actions"><button type="button" className="danger-button" onClick={() => void revoke()} disabled={revoking}>{revoking ? 'Updating…' : fourEyesEnabled ? 'Request or apply reviewed revocation' : 'Revoke immediately'}</button>{fourEyesEnabled && currentRole === 'administrator' ? <button type="button" className="danger-button" onClick={() => void emergencySecurityHold()} disabled={revoking}>Emergency security hold</button> : null}</div> : null}
      {canManage ? <ActiveAssetDeletionPanel assetId={asset.id} onDeleted={onDeleted} /> : null}
      {error ? <p className="error-text" role="alert">{error}</p> : null}
    </div> : null}
  </article>;
}

function mergeActiveExecutions(...pages: JobListItem[][]): JobListItem[] {
  const byId = new Map<string, JobListItem>();
  for (const page of pages) for (const execution of page) byId.set(execution.id, execution);
  return [...byId.values()].sort((left, right) => right.created_at.localeCompare(left.created_at) || right.id.localeCompare(left.id));
}

function ResponsibleMemberSelector({ members, value, onChange, preserveUnavailable = false }: { members: TeamMember[] | null; value: string[]; onChange: (value: string[]) => void; preserveUnavailable?: boolean }) {
  return <fieldset>
    <legend>Responsible accounts</legend>
    {members === null ? <p className="muted" role="status">{preserveUnavailable && value.length ? 'Keeping the existing assignment while the current workspace directory loads.' : 'Loading current workspace members…'}</p> : members.length === 0 ? <p className="muted">No current workspace members are available. The asset will remain unassigned.</p> : <div className="capability-choice-grid">{members.map((member) => <label className="capability-choice" key={member.user_id}><input type="checkbox" checked={value.includes(member.user_id)} onChange={(event) => onChange(event.target.checked ? [...value, member.user_id].sort() : value.filter((entry) => entry !== member.user_id))} /><span><strong>{member.username}</strong><small>{member.role} · current workspace</small></span></label>)}</div>}
    <p className="muted">Optional. Only current members of this workspace are accepted; assignment does not grant permission to modify or execute.</p>
  </fieldset>;
}

function localResponsibleMember(currentUserId: string | null): TeamMember {
  return { user_id: currentUserId || 'local-admin', username: 'Current operator', role: 'administrator', joined_at: new Date(0).toISOString() };
}

function responsibleLabels(ids: string[], members: TeamMember[] | null): string[] {
  if (ids.length === 0) return [];
  if (members === null) return ['Assigned (directory unavailable)'];
  const labels = ids.flatMap((id) => {
    const member = members.find((candidate) => candidate.user_id === id);
    return member ? [member.username] : [];
  });
  return labels.length === ids.length ? labels : ['Unassigned — membership changed'];
}

function effectiveReadiness(item: ActiveOperationsSummary['capabilities'][number] | undefined): 'disabled' | 'ready' | 'degraded' | 'unavailable' {
  if (!item) return 'unavailable';
  if (item?.readiness) return item.readiness;
  return item?.enabled ? 'ready' : 'disabled';
}

function readinessLabel(state: 'disabled' | 'ready' | 'degraded' | 'unavailable'): string {
  return state === 'ready' ? 'Ready' : state === 'degraded' ? 'Degraded' : state === 'unavailable' ? 'Unavailable' : 'Disabled';
}

function readinessExplanation(state: 'disabled' | 'ready' | 'degraded' | 'unavailable'): string {
  if (state === 'ready') return 'Backend policy and the isolated runner gate are both enabled.';
  if (state === 'degraded') return 'Backend policy is enabled, but the isolated runner gate or health contract is not ready.';
  if (state === 'unavailable') return 'The isolated runner cannot currently attest this capability.';
  return 'Backend operator policy is disabled; no execution can be admitted.';
}

function executionPhaseLabel(execution: Pick<JobRecord, 'status' | 'termination_reason' | 'active_execution_phase'>): string {
  if (execution.status === 'cancelling') return 'Stopping runner';
  if (execution.status === 'cancelled') return 'Stopped; partial output discarded';
  if (execution.status === 'failed') return execution.termination_reason === 'recovery_rejected' ? 'Rejected before safe recovery' : 'Stopped with a controlled error';
  if (execution.status === 'completed') return 'Results persisted';
  if (execution.active_execution_phase === 'waiting_for_runner') return 'Waiting for isolated runner';
  if (execution.active_execution_phase === 'executing') return 'Bounded capability in progress';
  if (execution.active_execution_phase === 'normalizing') return 'Normalizing safe results';
  return 'Admitted to durable queue';
}

function readActionPreferences(): { urgency: ActionUrgencyFilter; age: ActionAgeFilter } {
  try {
    const value = JSON.parse(window.localStorage.getItem(ACTIVE_ACTION_PREFERENCES_KEY) ?? '{}') as Record<string, unknown>;
    const urgency = ['all', 'immediate', 'high', 'scheduled', 'review'].includes(String(value.urgency)) ? value.urgency as ActionUrgencyFilter : 'all';
    const age = ['all', '7', '30'].includes(String(value.age)) ? value.age as ActionAgeFilter : 'all';
    return { urgency, age };
  } catch { return { urgency: 'all', age: 'all' }; }
}

function urgencyLabel(urgency: ActiveOperationsAction['urgency']): string {
  return urgency === 'immediate' ? 'Immediate' : urgency === 'high' ? 'High' : urgency === 'scheduled' ? 'Scheduled' : 'Review';
}

function actionPresentation(action: ActiveOperationsAction): { title: string; explanation: string; action: string } {
  switch (action.kind) {
    case 'authorization_expired': return { title: 'Authorization expired', explanation: 'The recorded authorization deadline has passed; no further observation is admitted.', action: 'Renew authorization' };
    case 'authorization_expiring': return { title: 'Authorization renewal due', explanation: 'The recorded authorization deadline is within the 14-day review window.', action: 'Review renewal' };
    case 'verification_failed': return { title: 'Control verification failed', explanation: 'The latest optional control check ended without a match; legal authorization is unchanged.', action: 'Review verification' };
    case 'verification_expired': return { title: 'Control verification expired', explanation: 'The latest optional control signal is no longer fresh; legal authorization is unchanged.', action: 'Review verification' };
    case 'execution_failed': return { title: 'Bounded execution failed', explanation: 'The latest execution for one authorized capability stopped with a controlled error.', action: 'Review safe retry' };
    case 'execution_degraded': return { title: 'Execution needs review', explanation: 'The latest execution completed with incomplete or degraded recorded coverage.', action: 'Review execution' };
    case 'observations_changed': return { title: 'Observed state changed', explanation: 'A comparable execution recorded new, changed, or disappeared signals; this is not a vulnerability conclusion.', action: 'Triage changes' };
  }
}

function actionTiming(action: ActiveOperationsAction, generatedAt: string): string {
  const generated = Date.parse(generatedAt);
  const reference = Date.parse(action.due_at ?? action.reference_at);
  if (!Number.isFinite(generated) || !Number.isFinite(reference)) return 'Recorded time unavailable';
  const signedDays = (reference - generated) / 86_400_000;
  if (action.due_at) {
    if (Math.abs(signedDays) < 1) return signedDays < 0 ? 'Deadline passed today' : 'Due within 24 hours';
    return signedDays < 0 ? `Overdue by ${Math.floor(Math.abs(signedDays))} days` : `Due in ${Math.ceil(signedDays)} days`;
  }
  const ageDays = Math.max(0, Math.floor(-signedDays));
  return ageDays === 0 ? 'Recorded today' : `Recorded ${ageDays} ${ageDays === 1 ? 'day' : 'days'} ago`;
}

function Metric({ label, value }: { label: string; value: number }) { return <div><strong>{value}</strong><span>{label}</span></div>; }
function hasExpandedScope(asset: ActiveAsset, capabilities: ActiveCapability[], ports: number[], protocols: ActiveAsset['allowed_protocols']): boolean {
  return capabilities.some((item) => !asset.capabilities.includes(item)) || ports.some((item) => !asset.allowed_ports.includes(item)) || protocols.some((item) => !asset.allowed_protocols.includes(item));
}
function localDateTime(date: Date): string { const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000); return local.toISOString().slice(0, 16); }
function verificationMethodSupportsAsset(method: ActiveAssetVerificationMethod, asset: ActiveAsset): boolean {
  if (method === 'dns_txt') return asset.asset_type === 'domain' || asset.asset_type === 'host';
  if (method === 'http_well_known') return asset.asset_type !== 'ip';
  return true;
}
