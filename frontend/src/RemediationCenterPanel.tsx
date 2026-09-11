import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, CheckSquare, FolderOpen, RefreshCw, Search, Wrench } from "lucide-react";

import { ApiError, api, createIdempotencyKey } from "./api";
import type {
  FindingDecisionStatus,
  ProjectSummary,
  RemediationActionGroup,
  RemediationOccurrence,
  RemediationPage,
  RemediationPlanJob,
  RemediationPlanJobPage,
  RemediationPriority,
  RemediationSearch,
  RemediationSavedView,
  RemediationSavedViewFilters,
  RemediationSavedViewPage,
  RemediationWorkflowState,
  TeamMember,
} from "./types";


type Props = {
  canManage: boolean;
  currentUserId?: string | null;
  members?: TeamMember[];
  onOpenProject: (project: ProjectSummary) => void;
};

type Filters = {
  search: string;
  priority: "all" | RemediationPriority;
  evidenceKind: "all" | "public_vulnerability" | "local_finding";
  ecosystem: "all" | "npm" | "pypi" | "go" | "cargo" | "composer" | "maven" | "nuget";
  dependencyScope: "all" | "direct" | "transitive" | "optional" | "unknown";
  workflowState: "all" | RemediationWorkflowState;
  sort: "priority" | "component" | "projects";
};

const defaults: Filters = {
  search: "",
  priority: "all",
  evidenceKind: "all",
  ecosystem: "all",
  dependencyScope: "all",
  workflowState: "all",
  sort: "priority",
};

const statusLabels: Record<RemediationWorkflowState, string> = {
  open: "Open",
  in_review: "In review",
  accepted: "Risk accepted",
  false_positive: "False positive",
  resolved: "Correction awaiting proof",
  awaiting_reanalysis: "Awaiting reanalysis",
  still_detected: "Still detected",
};

const priorityReasons: Record<RemediationActionGroup["priority_reasons"][number], string> = {
  known_exploited: "Known exploitation (KEV)",
  critical: "Critical CVSS band",
  high: "High CVSS band",
  source_conflict: "Sources disagree",
  new_finding: "New in a comparable analysis",
  direct_dependency: "Direct dependency",
  coverage_incomplete: "Coverage incomplete or lost",
  exception_review_due: "Exception review due",
  awaiting_reanalysis: "Correction needs comparable reanalysis",
};

export function RemediationCenterPanel({ canManage, currentUserId, members: suppliedMembers, onOpenProject }: Props) {
  const [filters, setFilters] = useState<Filters>(defaults);
  const [applied, setApplied] = useState<Filters>(defaults);
  const [page, setPage] = useState<RemediationPage | null>(null);
  const [groups, setGroups] = useState<RemediationActionGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
  const [selectedKeys, setSelectedKeys] = useState<Set<string>>(new Set());
  const [status, setStatus] = useState<FindingDecisionStatus>("in_review");
  const [reason, setReason] = useState("");
  const [comment, setComment] = useState("");
  const [assignee, setAssignee] = useState("");
  const [reviewAt, setReviewAt] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [reportConfirmed, setReportConfirmed] = useState(false);
  const [plans, setPlans] = useState<RemediationPlanJobPage | null>(null);
  const [plansLoading, setPlansLoading] = useState(false);
  const [planBusy, setPlanBusy] = useState<string | null>(null);
  const [planError, setPlanError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [members, setMembers] = useState<TeamMember[]>(suppliedMembers ?? []);
  const [savedViews, setSavedViews] = useState<RemediationSavedViewPage | null>(null);
  const [selectedSavedViewId, setSelectedSavedViewId] = useState("");
  const [savedViewName, setSavedViewName] = useState("");
  const [savedViewVisibility, setSavedViewVisibility] = useState<"private" | "organization">("private");
  const [savedViewDefault, setSavedViewDefault] = useState(false);
  const [savedViewBusy, setSavedViewBusy] = useState(false);
  const [savedViewError, setSavedViewError] = useState<string | null>(null);
  const resultsRef = useRef<HTMLDivElement>(null);
  const pendingAction = useRef<{ signature: string; key: string } | null>(null);
  const pendingPlan = useRef<{ signature: string; key: string } | null>(null);

  useEffect(() => {
    let disposed = false;
    setLoading(true);
    setError(null);
    void api.searchRemediationCenter(toSearch(applied)).then((result) => {
      if (disposed) return;
      setPage(result);
      setGroups(result.items);
      setSelectedGroupId(null);
      setSelectedKeys(new Set());
    }).catch((caught) => {
      if (!disposed) setError(errorMessage(caught));
    }).finally(() => {
      if (!disposed) setLoading(false);
    });
    return () => { disposed = true; };
  }, [applied]);

  useEffect(() => {
    if (suppliedMembers) {
      setMembers(suppliedMembers);
      return;
    }
    if (!canManage) return;
    let disposed = false;
    void api.listTeamMembers().then((items) => {
      if (!disposed) setMembers(items);
    }).catch(() => {
      if (!disposed) setMembers([]);
    });
    return () => { disposed = true; };
  }, [canManage, suppliedMembers]);

  useEffect(() => {
    if (!currentUserId) return;
    let disposed = false;
    setSavedViewBusy(true);
    void api.listRemediationSavedViews().then((result) => {
      if (disposed) return;
      setSavedViews(result);
      const preferred = result.items.find((item) => item.id === result.default_view_id);
      if (preferred) {
        const next = filtersFromSavedView(preferred);
        setSelectedSavedViewId(preferred.id);
        setFilters(next);
        setApplied(next);
      }
    }).catch(() => {
      if (!disposed) setSavedViewError("Saved views are temporarily unavailable. Current filters still work.");
    }).finally(() => {
      if (!disposed) setSavedViewBusy(false);
    });
    return () => { disposed = true; };
  }, [currentUserId]);

  useEffect(() => {
    if (!currentUserId) return;
    let disposed = false;
    setPlansLoading(true);
    void api.listRemediationPlans().then((result) => {
      if (!disposed) setPlans(result);
    }).catch(() => {
      if (!disposed) setPlanError("Durable remediation plans are temporarily unavailable. Current evidence is unchanged.");
    }).finally(() => {
      if (!disposed) setPlansLoading(false);
    });
    return () => { disposed = true; };
  }, [currentUserId]);

  useEffect(() => {
    if (!currentUserId || !plans?.items.some((item) => ["queued", "running", "cancelling"].includes(item.status))) return;
    const timer = window.setInterval(() => {
      void api.listRemediationPlans().then(setPlans).catch(() => {
        setPlanError("Plan progress could not be refreshed. Retry without creating another job.");
      });
    }, 2000);
    return () => window.clearInterval(timer);
  }, [currentUserId, plans]);

  const selectedGroup = groups.find((item) => item.id === selectedGroupId) ?? null;
  const selectedOccurrences = useMemo(
    () => selectedGroup?.occurrences.filter((item) => selectedKeys.has(occurrenceKey(item))) ?? [],
    [selectedGroup, selectedKeys],
  );
  const exception = status === "accepted" || status === "false_positive";
  const reviewDateBounds = useMemo(() => exceptionReviewDateBounds(), []);

  async function loadMore() {
    if (!page?.next_cursor || loadingMore) return;
    setLoadingMore(true);
    setError(null);
    try {
      const next = await api.searchRemediationCenter({ ...toSearch(applied), cursor: page.next_cursor });
      setGroups((current) => [...current, ...next.items.filter((item) => !current.some((known) => known.id === item.id))]);
      setPage(next);
      requestAnimationFrame(() => resultsRef.current?.focus());
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setLoadingMore(false);
    }
  }

  function toggle(group: RemediationActionGroup, occurrence: RemediationOccurrence) {
    const key = occurrenceKey(occurrence);
    setNotice(null);
    setError(null);
    if (selectedGroupId !== group.id) {
      setSelectedGroupId(group.id);
      setSelectedKeys(new Set([key]));
      return;
    }
    setSelectedKeys((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else if (next.size < 25) next.add(key);
      return next;
    });
  }

  async function applyAction(event: FormEvent) {
    event.preventDefault();
    if (!selectedGroup || !selectedOccurrences.length) return;
    setSubmitting(true);
    setError(null);
    setNotice(null);
    try {
      const action = {
        group_id: selectedGroup.id,
        expected_revision: selectedGroup.revision,
        selections: selectedOccurrences.map((item) => ({
          project_id: item.project.id,
          analysis_id: item.analysis.id,
          finding_id: item.finding_id,
        })),
        status,
        reason: reason.trim(),
        comment: comment.trim() || null,
        assignee_user_id: assignee || null,
        review_at: exception && reviewAt ? `${reviewAt}:00Z` : null,
        confirmation: true,
      } as const;
      const signature = JSON.stringify(action);
      if (pendingAction.current?.signature !== signature) {
        pendingAction.current = { signature, key: createIdempotencyKey() };
      }
      const result = await api.applyRemediationAction({
        ...action,
        idempotency_key: pendingAction.current.key,
      });
      const refreshed = await api.searchRemediationCenter(toSearch(applied));
      setPage(refreshed);
      setGroups(refreshed.items);
      setSelectedGroupId(null);
      setSelectedKeys(new Set());
      setReason("");
      setComment("");
      setReviewAt("");
      setConfirmed(false);
      pendingAction.current = null;
      setNotice(`${result.applied_count} append-only decision${result.applied_count === 1 ? "" : "s"} ${result.replayed ? "recovered safely" : "recorded"}. Analyzer evidence was not changed.`);
    } catch (caught) {
      setError(actionErrorMessage(caught));
    } finally {
      setSubmitting(false);
    }
  }

  async function createPlan() {
    if (!reportConfirmed || planBusy) return;
    const request = toSearch(applied);
    const signature = JSON.stringify(request);
    if (pendingPlan.current?.signature !== signature) {
      pendingPlan.current = { signature, key: createIdempotencyKey() };
    }
    setPlanBusy("create");
    setPlanError(null);
    try {
      const created = await api.createRemediationPlan(request, pendingPlan.current.key);
      pendingPlan.current = null;
      setPlans(await api.listRemediationPlans());
      setNotice(`Durable remediation plan ${created.id.slice(0, 12)}… queued from one fixed cutoff.`);
    } catch (caught) {
      setPlanError(caught instanceof ApiError && caught.status === 409 ? "This request key is bound to another plan. Refresh before retrying." : "No durable plan was confirmed. Retry with the same filters; duplicate work is prevented.");
    } finally {
      setPlanBusy(null);
    }
  }

  async function cancelPlan(plan: RemediationPlanJob) {
    setPlanBusy(plan.id);
    setPlanError(null);
    try {
      await api.cancelRemediationPlan(plan.id);
      setPlans(await api.listRemediationPlans());
    } catch {
      setPlanError("The plan could not be cancelled in its current state. Refresh its status.");
    } finally {
      setPlanBusy(null);
    }
  }

  async function retryPlan(plan: RemediationPlanJob) {
    setPlanBusy(plan.id);
    setPlanError(null);
    try {
      await api.retryRemediationPlan(plan.id, createIdempotencyKey());
      setPlans(await api.listRemediationPlans());
    } catch {
      setPlanError("The plan could not be retried safely. Refresh its status before trying again.");
    } finally {
      setPlanBusy(null);
    }
  }

  async function downloadPlan(plan: RemediationPlanJob, format: "json" | "csv") {
    setPlanBusy(`${plan.id}:${format}`);
    setPlanError(null);
    try {
      const result = await api.downloadRemediationPlan(plan.id, format);
      const url = URL.createObjectURL(result.blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = result.filename;
      anchor.click();
      URL.revokeObjectURL(url);
      setNotice(`${format.toUpperCase()} downloaded from immutable snapshot ${result.digest.slice(0, 12)}….`);
    } catch (caught) {
      setPlanError(caught instanceof ApiError && caught.status === 410 ? "This artifact expired. Create a new plan from current evidence." : "The completed plan could not be downloaded; no partial file was retained.");
    } finally {
      setPlanBusy(null);
    }
  }

  function applySavedView(viewId: string) {
    setSelectedSavedViewId(viewId);
    const selected = savedViews?.items.find((item) => item.id === viewId);
    if (!selected) return;
    const next = filtersFromSavedView(selected);
    setFilters(next);
    setApplied(next);
    setNotice(`Saved view “${selected.name}” applied. Free-text search was not stored.`);
  }

  async function saveCurrentView(event: FormEvent) {
    event.preventDefault();
    if (!savedViewName.trim() || savedViewBusy) return;
    setSavedViewBusy(true);
    setSavedViewError(null);
    try {
      const created = await api.createRemediationSavedView({
        name: savedViewName.trim(),
        filters: savedFilters(filters),
        visibility: canManage ? savedViewVisibility : "private",
        make_default: savedViewDefault,
      });
      const refreshed = await api.listRemediationSavedViews();
      setSavedViews(refreshed);
      setSelectedSavedViewId(created.id);
      setSavedViewName("");
      setSavedViewDefault(false);
      setNotice(`Saved ${created.visibility === "organization" ? "workspace" : "private"} view “${created.name}”. Search text was excluded.`);
    } catch (caught) {
      setSavedViewError(savedViewErrorMessage(caught));
    } finally {
      setSavedViewBusy(false);
    }
  }

  async function updateDefaultView(viewId: string | null) {
    if ((viewId !== null && !viewId) || savedViewBusy) return;
    setSavedViewBusy(true);
    setSavedViewError(null);
    try {
      const refreshed = await api.setDefaultRemediationSavedView(viewId);
      setSavedViews(refreshed);
      setNotice(viewId ? "Default remediation view updated for your account." : "Default remediation view cleared for your account.");
    } catch (caught) {
      setSavedViewError(savedViewErrorMessage(caught));
    } finally {
      setSavedViewBusy(false);
    }
  }

  async function deleteSelectedView() {
    const selected = savedViews?.items.find((item) => item.id === selectedSavedViewId);
    if (!selected || selected.owner_user_id !== currentUserId || savedViewBusy) return;
    setSavedViewBusy(true);
    setSavedViewError(null);
    try {
      await api.deleteRemediationSavedView(selected.id);
      const refreshed = await api.listRemediationSavedViews();
      setSavedViews(refreshed);
      setSelectedSavedViewId("");
      setNotice(`Saved view “${selected.name}” deleted.`);
    } catch (caught) {
      setSavedViewError(savedViewErrorMessage(caught));
    } finally {
      setSavedViewBusy(false);
    }
  }

  return (
    <section className="remediation-center" aria-labelledby="remediation-title" aria-busy={loading || loadingMore}>
      <div className="project-portfolio-heading">
        <div>
          <p className="eyebrow">Cross-project action</p>
          <h2 id="remediation-title"><Wrench size={19} aria-hidden="true" /> Remediation center</h2>
          <p className="muted">Group current evidence by a common correction. Inspectra never runs an update command or claims compatibility.</p>
        </div>
        <button className="secondary-button" type="button" onClick={() => setApplied({ ...applied })} disabled={loading}>
          <RefreshCw size={16} aria-hidden="true" /> Refresh
        </button>
      </div>

      {currentUserId ? <div className="remediation-saved-views" aria-busy={savedViewBusy}>
        <div className="remediation-saved-view-picker">
          <label><span>Saved view</span><select value={selectedSavedViewId} disabled={savedViewBusy} onChange={(event) => applySavedView(event.target.value)}><option value="">Current unsaved filters</option>{savedViews?.items.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.visibility === "organization" ? "workspace" : "private"}{item.id === savedViews.default_view_id ? " · default" : ""}</option>)}</select></label>
          <button type="button" className="secondary-button" disabled={!selectedSavedViewId || selectedSavedViewId === savedViews?.default_view_id || savedViewBusy} onClick={() => void updateDefaultView(selectedSavedViewId)}>Make default</button>
          <button type="button" className="secondary-button" disabled={!savedViews?.default_view_id || savedViewBusy} onClick={() => void updateDefaultView(null)}>Clear default</button>
          <button type="button" className="secondary-button" disabled={!savedViews?.items.some((item) => item.id === selectedSavedViewId && item.owner_user_id === currentUserId) || savedViewBusy} onClick={() => void deleteSelectedView()}>Delete my view</button>
        </div>
        <details><summary>Save current closed filters</summary><form className="remediation-save-view-form" onSubmit={(event) => void saveCurrentView(event)}>
          <label><span>View name</span><input value={savedViewName} minLength={3} maxLength={60} pattern="[A-Za-z0-9][A-Za-z0-9 ._-]{2,59}" required onChange={(event) => setSavedViewName(event.target.value)} /></label>
          {canManage ? <label><span>Visibility</span><select value={savedViewVisibility} onChange={(event) => setSavedViewVisibility(event.target.value as "private" | "organization")}><option value="private">Only me</option><option value="organization">Workspace members</option></select></label> : <p className="muted">Reader views are private to your account.</p>}
          <label className="authorization-check"><input type="checkbox" checked={savedViewDefault} onChange={(event) => setSavedViewDefault(event.target.checked)} /><span>Open this view by default on this account.</span></label>
          <p className="muted">Only the closed priority, evidence, ecosystem, dependency, workflow and order filters are saved. Search text, cursors, project IDs and finding IDs are never stored.</p>
          <button type="submit" disabled={savedViewBusy || savedViewName.trim().length < 3}>{savedViewBusy ? "Saving…" : "Save view"}</button>
        </form></details>
        {savedViewError ? <p className="error-text" role="alert">{savedViewError}</p> : null}
      </div> : null}

      <form className="project-portfolio-filters remediation-filters" onSubmit={(event) => {
        event.preventDefault();
        setApplied({ ...filters, search: filters.search.trim() });
      }}>
        <label className="portfolio-search-field"><span>Component, advisory or title</span><input value={filters.search} maxLength={120} onChange={(event) => setFilters((value) => ({ ...value, search: event.target.value }))} /></label>
        <Filter label="Priority" value={filters.priority} setValue={(value) => setFilters((current) => ({ ...current, priority: value as Filters["priority"] }))} options={[["all", "All"], ["urgent", "Urgent"], ["high", "High"], ["review", "Review"]]} />
        <Filter label="Evidence" value={filters.evidenceKind} setValue={(value) => setFilters((current) => ({ ...current, evidenceKind: value as Filters["evidenceKind"] }))} options={[["all", "All"], ["public_vulnerability", "Public vulnerability"], ["local_finding", "Local finding"]]} />
        <Filter label="Ecosystem" value={filters.ecosystem} setValue={(value) => setFilters((current) => ({ ...current, ecosystem: value as Filters["ecosystem"] }))} options={[["all", "All"], ["npm", "npm"], ["pypi", "PyPI"], ["go", "Go"], ["cargo", "Cargo"], ["composer", "Composer"], ["maven", "Maven"], ["nuget", "NuGet"]]} />
        <Filter label="Dependency" value={filters.dependencyScope} setValue={(value) => setFilters((current) => ({ ...current, dependencyScope: value as Filters["dependencyScope"] }))} options={[["all", "All"], ["direct", "Direct"], ["transitive", "Transitive"], ["optional", "Optional"], ["unknown", "Unknown"]]} />
        <Filter label="Workflow" value={filters.workflowState} setValue={(value) => setFilters((current) => ({ ...current, workflowState: value as Filters["workflowState"] }))} options={[["all", "All"], ["open", "Open"], ["in_review", "In review"], ["accepted", "Accepted"], ["false_positive", "False positive"], ["awaiting_reanalysis", "Awaiting reanalysis"], ["still_detected", "Still detected"]]} />
        <Filter label="Order" value={filters.sort} setValue={(value) => setFilters((current) => ({ ...current, sort: value as Filters["sort"] }))} options={[["priority", "Priority"], ["component", "Component"], ["projects", "Affected projects"]]} />
        <div className="project-portfolio-filter-actions"><button type="submit" disabled={loading}><Search size={16} aria-hidden="true" /> Apply</button><button type="button" className="secondary-button" onClick={() => { setFilters(defaults); setApplied(defaults); }}>Reset</button></div>
      </form>

      <p className="sr-only" role="status" aria-live="polite">{loading ? "Loading remediation groups." : page ? `${groups.length} of ${page.total_count} groups loaded.` : "Remediation data unavailable."}</p>
      {error ? <p className="error-text" role="alert">{error}</p> : null}
      {notice ? <p className="success-text" role="status">{notice}</p> : null}
      {loading && !groups.length ? <p className="muted" role="status">Building a current, owner-scoped remediation plan…</p> : null}
      {!loading && page?.summary.total_groups === 0 ? <div className="empty-state"><strong>No current remediation work</strong><p>Run a project analysis and public intelligence query. Corrections disappear only after comparable evidence no longer reports them.</p></div> : null}
      {!loading && page && page.summary.total_groups > 0 && page.total_count === 0 ? <div className="empty-state"><strong>No groups match these filters</strong><p>Broaden or reset the filters; no evidence or workflow state was changed.</p></div> : null}

      {page && page.summary.total_groups > 0 ? <>
        <div className="project-portfolio-summary" aria-label="Remediation summary">
          <Metric label="Action groups" value={page.summary.filtered_groups} />
          <Metric label="Urgent" value={page.summary.urgent_groups} />
          <Metric label="Projects affected" value={page.summary.projects_affected} />
          <Metric label="Known exploited" value={page.summary.known_exploited_groups} detail="KEV, not CVSS" />
          <Metric label="Conflicts" value={page.summary.conflicting_groups} />
          <Metric label="Needs reanalysis" value={page.summary.awaiting_reanalysis} />
        </div>
        {page.limitations.map((item) => <p key={item} className="query-warning">{item}</p>)}
        <div className="remediation-report-controls">
          <label className="authorization-check"><input type="checkbox" checked={reportConfirmed} onChange={(event) => setReportConfirmed(event.target.checked)} /><span>I confirm this owner-scoped export may include project names and security metadata; it excludes source paths, source content, comments and actor identifiers.</span></label>
          <div><button type="button" className="secondary-button" disabled={!reportConfirmed || Boolean(planBusy)} onClick={() => void createPlan()}>{planBusy === "create" ? "Queuing…" : "Create durable plan"}</button></div>
          <p className="muted">The server pages the private project index, fixes one cutoff and publishes no partial download. Completed artifacts expire after seven days.</p>
          {planError ? <p className="error-text" role="alert">{planError}</p> : null}
          {plansLoading ? <p className="muted" role="status">Loading durable plan history…</p> : null}
          {!plansLoading && plans && plans.items.length === 0 ? <div className="empty-state"><strong>No durable plans yet</strong><p>Create one when you need a reproducible cross-project export.</p></div> : null}
          {plans?.items.length ? <ul className="remediation-plan-jobs" aria-label="Durable remediation plans" aria-live="polite">{plans.items.slice(0, 8).map((plan) => <li key={plan.id}>
            <div><strong>{planStatusLabel(plan.status)}</strong><span>Cutoff {formatPlanTime(plan.cutoff_at)} · {planProgressLabel(plan)}</span>{plan.status === "completed" ? <span>{plan.included_groups} groups · {plan.included_occurrences} retained occurrences · expires {formatPlanTime(plan.expires_at)}</span> : null}{plan.status === "expired" ? <span>The seven-day artifact has been removed; create or retry a plan from current evidence.</span> : null}{plan.failure_reason ? <span>{planFailureLabel(plan.failure_reason)}</span> : null}</div>
            <div>{plan.status === "completed" ? <><button type="button" className="secondary-button" disabled={Boolean(planBusy)} onClick={() => void downloadPlan(plan, "json")}>JSON</button><button type="button" className="secondary-button" disabled={Boolean(planBusy)} onClick={() => void downloadPlan(plan, "csv")}>CSV</button></> : null}{canManage && ["queued", "running", "cancelling"].includes(plan.status) ? <button type="button" className="secondary-button" disabled={Boolean(planBusy) || plan.status === "cancelling"} onClick={() => void cancelPlan(plan)}>Cancel</button> : null}{canManage && ["failed", "cancelled", "expired"].includes(plan.status) ? <button type="button" className="secondary-button" disabled={Boolean(planBusy)} onClick={() => void retryPlan(plan)}>Retry</button> : null}</div>
          </li>)}</ul> : null}
        </div>
        <div className="remediation-results" ref={resultsRef} tabIndex={-1} aria-label="Remediation action groups">
          {groups.map((group) => <article className={`remediation-card priority-${group.priority}`} key={group.id}>
            <div className="remediation-card-heading">
              <div><span className={`status-pill portfolio-${group.priority}`}>{group.priority}</span><h3>{group.title}</h3><p className="muted">{group.ecosystem ? `${group.ecosystem} · ` : ""}{group.affected_project_count} project{group.affected_project_count === 1 ? "" : "s"} · {group.occurrence_count} occurrence{group.occurrence_count === 1 ? "" : "s"}</p></div>
              <span className={`severity severity-${group.highest_severity}`}>{group.highest_severity}</span>
            </div>
            <dl className="remediation-facts">
              <Fact label="Observed" value={group.observed_versions.join(", ") || "Not versioned"} />
              <Fact label="Affected range" value={rangeLabel(group)} />
              <Fact label="Fixed" value={group.recommended_fixed_version ?? (group.fixed_versions.join(", ") || "No verified fixed version")} />
              <Fact label="Dependency" value={group.dependency_scopes.join(", ")} />
              <Fact label="Exposure" value="Not assessed" />
              <Fact label="Advisory" value={group.advisory_ids.join(", ") || "Local rule"} />
            </dl>
            {group.known_exploited ? <p className="kev-callout"><AlertTriangle size={16} aria-hidden="true" /> Known exploitation signal from CISA KEV; this does not establish package affectedness.</p> : null}
            <p>{group.recommendation}</p>
            <div className="project-portfolio-reasons"><strong>Why this priority</strong><ul>{group.priority_reasons.map((item) => <li key={item}>{priorityReasons[item]}</li>)}</ul></div>
            {group.source_conflict || group.limitations.length ? <div className="portfolio-limitations" role="note"><AlertTriangle size={16} aria-hidden="true" /><div><strong>Evidence limits</strong><ul>{group.limitations.map((item) => <li key={item}>{item}</li>)}</ul></div></div> : null}
            <details className="remediation-projects"><summary>Affected projects ({group.occurrence_count})</summary>
              <ul>{group.occurrences.map((item) => <li key={occurrenceKey(item)}>
                {canManage ? <label className="remediation-selection"><input type="checkbox" checked={selectedGroupId === group.id && selectedKeys.has(occurrenceKey(item))} disabled={!item.workflow_mutable || (selectedGroupId === group.id && !selectedKeys.has(occurrenceKey(item)) && selectedKeys.size >= 25)} onChange={() => toggle(group, item)} /><span className="sr-only">Select {item.project.name}</span></label> : null}
                <div><strong>{item.project.name}</strong><span>{item.observed_version ?? "Local finding"} · {item.dependency_scope} · {statusLabels[item.workflow_state]}{item.is_new === true ? " · new" : item.is_new === null ? " · comparison unknown" : ""}</span><span>Project owner: {projectResponsibilityLabel(item, members)} · Finding assignee: {item.assignee_username ?? "unassigned"}</span></div>
                <button type="button" className="button-link" onClick={() => onOpenProject({ project: item.project, latest_job: item.analysis })}><FolderOpen size={15} aria-hidden="true" /> Open</button>
              </li>)}</ul>
              {group.occurrences_truncated ? <p className="query-warning">Only the first 100 stable occurrences are shown. Narrow the filters before acting.</p> : null}
            </details>
          </article>)}
          {page.has_more ? <button type="button" className="secondary-button portfolio-load-more" onClick={() => void loadMore()} disabled={loadingMore}>{loadingMore ? "Loading…" : `Load more (${groups.length} of ${page.total_count})`}</button> : null}
        </div>
      </> : null}

      {canManage && selectedGroup && selectedOccurrences.length ? <form className="remediation-bulk-action" onSubmit={(event) => void applyAction(event)}>
        <div><CheckSquare size={18} aria-hidden="true" /><strong>Append a bounded action to {selectedOccurrences.length} selected occurrence{selectedOccurrences.length === 1 ? "" : "s"}</strong><p>Selections must belong to one unchanged group. The server applies at most 25 decisions atomically.</p></div>
        <label><span>Status</span><select value={status} onChange={(event) => { setStatus(event.target.value as FindingDecisionStatus); setConfirmed(false); }}><option value="in_review">In review</option><option value="open">Open</option><option value="accepted">Risk accepted</option><option value="false_positive">False positive</option><option value="resolved">Correction awaiting comparable reanalysis</option></select></label>
        <label><span>Reason</span><input value={reason} minLength={3} maxLength={240} required onChange={(event) => setReason(event.target.value)} /></label>
        {members.length ? <label><span>Assign to</span><select value={assignee} onChange={(event) => setAssignee(event.target.value)}><option value="">Unassigned</option>{members.map((member) => <option key={member.user_id} value={member.user_id}>{member.username}</option>)}</select></label> : null}
        {exception ? <label><span>Review date (UTC)</span><input type="datetime-local" value={reviewAt} min={reviewDateBounds.minimum} max={reviewDateBounds.maximum} required aria-describedby="remediation-review-date-help" onChange={(event) => setReviewAt(event.target.value)} /><small id="remediation-review-date-help">Required; future UTC time no more than 366 days away.</small></label> : null}
        <label className="remediation-comment"><span>Comment (optional; never include secrets)</span><textarea rows={2} maxLength={1000} value={comment} onChange={(event) => setComment(event.target.value)} /></label>
        <label className="authorization-check remediation-confirmation"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>I reviewed the exact projects and understand this records workflow only; it does not change code or prove a correction.</span></label>
        <div className="remediation-action-buttons"><button type="submit" disabled={submitting || !confirmed || reason.trim().length < 3 || (exception && !reviewAt)}>{submitting ? "Recording…" : `Record for ${selectedOccurrences.length}`}</button><button type="button" className="secondary-button" onClick={() => { setSelectedGroupId(null); setSelectedKeys(new Set()); }}>Cancel selection</button></div>
      </form> : !canManage && page?.summary.total_groups ? <p className="muted">Reader access can inspect the remediation plan but cannot change workflow.</p> : null}
    </section>
  );
}

function occurrenceKey(item: RemediationOccurrence) { return `${item.project.id}:${item.analysis.id}:${item.finding_id}`; }
function projectResponsibilityLabel(item: RemediationOccurrence, members: TeamMember[]): string {
  const responsibility = item.project.responsibility;
  if (!responsibility || responsibility.state === "unassigned") return "unassigned";
  if (responsibility.state === "unassigned_attention") return "reassignment required";
  return members.find((member) => member.user_id === responsibility.responsible_user_id)?.username ?? "assigned member unavailable";
}
function Filter({ label, value, options, setValue }: { label: string; value: string; options: Array<[string, string]>; setValue: (value: string) => void }) { return <label><span>{label}</span><select value={value} onChange={(event) => setValue(event.target.value)}>{options.map(([key, text]) => <option key={key} value={key}>{text}</option>)}</select></label>; }
function Metric({ label, value, detail }: { label: string; value: number; detail?: string }) { return <div><span>{label}</span><strong>{value}</strong>{detail ? <small>{detail}</small> : null}</div>; }
function Fact({ label, value }: { label: string; value: string }) { return <div><dt>{label}</dt><dd>{value}</dd></div>; }
function rangeLabel(group: RemediationActionGroup): string { const values = group.affected_ranges.map((item) => item.expression ?? [item.introduced ? `from ${item.introduced}` : null, item.fixed ? `before ${item.fixed}` : null, item.last_affected ? `through ${item.last_affected}` : null].filter(Boolean).join(" ")).filter(Boolean); return values.join("; ") || "See advisory evidence"; }
function toSearch(value: Filters): RemediationSearch { return { search: value.search || undefined, searchMode: "prefix", priority: value.priority === "all" ? undefined : value.priority, evidenceKind: value.evidenceKind === "all" ? undefined : value.evidenceKind, ecosystem: value.ecosystem === "all" ? undefined : value.ecosystem, dependencyScope: value.dependencyScope === "all" ? undefined : value.dependencyScope, workflowState: value.workflowState === "all" ? undefined : value.workflowState, sort: value.sort }; }
function savedFilters(value: Filters): RemediationSavedViewFilters { return { priority: value.priority === "all" ? null : value.priority, evidence_kind: value.evidenceKind === "all" ? null : value.evidenceKind, ecosystem: value.ecosystem === "all" ? null : value.ecosystem, dependency_scope: value.dependencyScope === "all" ? null : value.dependencyScope, workflow_state: value.workflowState === "all" ? null : value.workflowState, sort: value.sort }; }
function filtersFromSavedView(view: RemediationSavedView): Filters { return { search: "", priority: view.filters.priority ?? "all", evidenceKind: view.filters.evidence_kind ?? "all", ecosystem: view.filters.ecosystem ?? "all", dependencyScope: view.filters.dependency_scope ?? "all", workflowState: view.filters.workflow_state ?? "all", sort: view.filters.sort }; }
function savedViewErrorMessage(error: unknown): string { if (error instanceof ApiError && error.status === 403) return "Only maintainers and administrators can share a workspace view. Your private views are unchanged."; if (error instanceof ApiError && error.status === 409) return "Use a unique name or delete one of your 20 saved views."; return "Saved views are temporarily unavailable. Current filters and evidence are unchanged."; }
function errorMessage(error: unknown): string { if (error instanceof ApiError && error.status === 409) return "The remediation view changed while paging. Refresh from the first page."; return "The remediation plan is temporarily unavailable. Existing evidence and workflow decisions were not changed."; }
function actionErrorMessage(error: unknown): string { if (error instanceof ApiError && error.status === 409) return "The selected evidence or workflow changed. Refresh and review the exact selection before retrying."; if (error instanceof ApiError && error.status === 422) return "Review the transition, reason, assignee and future exception date."; return "No complete batch was recorded. Refresh before retrying."; }
function exceptionReviewDateBounds(now = new Date()): { minimum: string; maximum: string } { return { minimum: new Date(now.getTime() + 60_000).toISOString().slice(0, 16), maximum: new Date(now.getTime() + 366 * 24 * 60 * 60 * 1_000).toISOString().slice(0, 16) }; }
function formatPlanTime(value: string | null): string { return value ? new Date(value).toLocaleString() : "not available"; }
function planStatusLabel(status: RemediationPlanJob["status"]): string { return ({ queued: "Queued", running: "Building plan", cancelling: "Cancelling", cancelled: "Cancelled", completed: "Plan ready", failed: "Plan failed", expired: "Artifact expired" })[status]; }
function planProgressLabel(plan: RemediationPlanJob): string { return plan.status === "queued" && plan.total_projects === 0 ? "waiting for a bounded portfolio snapshot" : `${plan.processed_projects} of ${plan.total_projects} projects`; }
function planFailureLabel(reason: NonNullable<RemediationPlanJob["failure_reason"]>): string { return ({ portfolio_changed: "Evidence changed during the snapshot; retry from a new cutoff.", source_unavailable: "Authoritative evidence was temporarily unavailable.", safe_limit_reached: "The configured safe portfolio or group limit was reached.", artifact_too_large: "The bounded artifact size limit was reached.", internal_error: "The worker stopped without publishing a partial artifact." })[reason]; }
