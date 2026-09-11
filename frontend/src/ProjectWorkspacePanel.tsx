import { useEffect, useRef, useState } from "react";
import { Activity, Ban, Eye, RefreshCw, UserRoundCheck } from "lucide-react";

import { ApiError, api } from "./api";
import { ProjectVulnerabilityIntelligencePanel } from "./ProjectVulnerabilityIntelligencePanel";
import { ProjectCiSetupPanel } from "./ProjectCiSetupPanel";
import { SbomRevisionPanel } from "./SbomRevisionPanel";
import { analysisSourceReference, sourceReference } from "./sourcePresentation";
import type { JobListItem, ProjectRecord, ProjectSbomRevisionCreated, ProjectSummary, TeamMember } from "./types";

type LoadState = { loading: boolean; error: string | null };

const initialLoadState: LoadState = { loading: false, error: null };

export function ProjectWorkspacePanel({
  project,
  onOpenAnalysis,
  showVulnerabilityIntelligence = false,
  canManageAutomation = false,
  focusCiSetup = false,
  canImportSbomRevision = false,
  canManageResponsibility = false,
  teamMode = false,
  currentOperator,
  onProjectUpdated,
  onSbomRevisionImported,
}: {
  project: ProjectSummary;
  onOpenAnalysis: (analysisId: string) => void;
  showVulnerabilityIntelligence?: boolean;
  canManageAutomation?: boolean;
  focusCiSetup?: boolean;
  canImportSbomRevision?: boolean;
  canManageResponsibility?: boolean;
  teamMode?: boolean;
  currentOperator?: { user_id: string; username: string };
  onProjectUpdated?: (project: ProjectRecord) => void;
  onSbomRevisionImported?: (created: ProjectSbomRevisionCreated) => void;
}) {
  const [analyses, setAnalyses] = useState<JobListItem[]>([]);
  const [analysisTotal, setAnalysisTotal] = useState(0);
  const [analysisNextCursor, setAnalysisNextCursor] = useState<string | null>(null);
  const [state, setState] = useState<LoadState>(initialLoadState);
  const [cancellingAnalysisId, setCancellingAnalysisId] = useState<string | null>(null);
  const [members, setMembers] = useState<Array<Pick<TeamMember, "user_id" | "username">>>([]);
  const [responsibilityState, setResponsibilityState] = useState<LoadState>(initialLoadState);
  const [responsibilityNotice, setResponsibilityNotice] = useState<string | null>(null);
  const [responsibility, setResponsibility] = useState(project.project.responsibility ?? defaultResponsibility());
  const [responsibilityTarget, setResponsibilityTarget] = useState(project.project.responsibility?.responsible_user_id ?? "");
  const [projectUpdatedAt, setProjectUpdatedAt] = useState(project.project.updated_at);
  const timelineRef = useRef<HTMLOListElement>(null);
  const snapshotCount = project.project.source_snapshots?.length ?? 1;
  const latestAnalysis = project.latest_job;
  const currentSnapshotDeleted = project.project.source_file_deleted_at !== null;
  const sourceType = project.project.source_type === "sbom" || latestAnalysis?.analysis_profile === "sbom_import" ? "sbom" : "archive";
  const snapshots = project.project.source_snapshots ?? [];
  const latestSnapshot = snapshots.length > 0 ? snapshots[snapshots.length - 1] : undefined;

  useEffect(() => {
    const next = project.project.responsibility ?? defaultResponsibility();
    setResponsibility(next);
    setResponsibilityTarget(next.responsible_user_id ?? "");
    setProjectUpdatedAt(project.project.updated_at);
    setResponsibilityNotice(null);
  }, [project.project.id, project.project.responsibility, project.project.updated_at]);

  useEffect(() => {
    let disposed = false;
    if (!teamMode) {
      setMembers(currentOperator ? [currentOperator] : []);
      return () => { disposed = true; };
    }
    setResponsibilityState({ loading: true, error: null });
    void api.listTeamMembers()
      .then((items) => {
        if (!disposed) {
          setMembers(items);
          setResponsibilityState(initialLoadState);
        }
      })
      .catch(() => {
        if (!disposed) setResponsibilityState({ loading: false, error: "Active workspace members could not be loaded. Responsibility changes are blocked." });
      });
    return () => { disposed = true; };
  }, [currentOperator?.user_id, currentOperator?.username, teamMode]);

  useEffect(() => {
    let disposed = false;
    async function load() {
      setState({ loading: true, error: null });
      try {
        const history = await api.listProjectAnalysisPage(project.project.id);
        if (!disposed) {
          setAnalyses(history.items);
          setAnalysisTotal(history.total_count);
          setAnalysisNextCursor(history.next_cursor);
          setState(initialLoadState);
        }
      } catch (error) {
        if (!disposed) {
          setState({ loading: false, error: historyErrorMessage(error) });
        }
      }
    }
    void load();
    return () => {
      disposed = true;
    };
  }, [project.latest_job?.id, project.project.id]);

  async function refresh() {
    setState({ loading: true, error: null });
    try {
      const history = await api.listProjectAnalysisPage(project.project.id);
      setAnalyses(history.items);
      setAnalysisTotal(history.total_count);
      setAnalysisNextCursor(history.next_cursor);
      setState(initialLoadState);
    } catch (error) {
      setState({ loading: false, error: historyErrorMessage(error) });
    }
  }

  async function cancelAnalysis(analysisId: string) {
    setCancellingAnalysisId(analysisId);
    setState({ loading: false, error: null });
    try {
      await api.cancelProjectAnalysis(project.project.id, analysisId);
      const history = await api.listProjectAnalysisPage(project.project.id);
      setAnalyses(history.items);
      setAnalysisTotal(history.total_count);
      setAnalysisNextCursor(history.next_cursor);
    } catch (error) {
      setState({ loading: false, error: cancellationErrorMessage(error) });
    } finally {
      setCancellingAnalysisId(null);
    }
  }

  async function loadMoreAnalyses() {
    if (!analysisNextCursor || state.loading) return;
    setState({ loading: true, error: null });
    try {
      const history = await api.listProjectAnalysisPage(project.project.id, analysisNextCursor);
      setAnalyses((current) => {
        const known = new Set(current.map((analysis) => analysis.id));
        return [...current, ...history.items.filter((analysis) => !known.has(analysis.id))];
      });
      setAnalysisTotal(history.total_count);
      setAnalysisNextCursor(history.next_cursor);
      setState(initialLoadState);
      window.requestAnimationFrame(() => timelineRef.current?.focus());
    } catch (error) {
      setState({ loading: false, error: historyErrorMessage(error) });
      window.requestAnimationFrame(() => timelineRef.current?.focus());
    }
  }

  async function updateResponsibility() {
    if (!canManageResponsibility || responsibilityState.loading || responsibilityState.error) return;
    setResponsibilityState({ loading: true, error: null });
    setResponsibilityNotice(null);
    try {
      const updated = await api.updateProjectResponsibility(
        project.project.id,
        responsibilityTarget || null,
        projectUpdatedAt,
      );
      const next = updated.responsibility ?? defaultResponsibility();
      setResponsibility(next);
      setResponsibilityTarget(next.responsible_user_id ?? "");
      setProjectUpdatedAt(updated.updated_at);
      setResponsibilityNotice(next.state === "assigned" ? "Project responsibility updated." : "Project is explicitly unassigned.");
      onProjectUpdated?.(updated);
      setResponsibilityState(initialLoadState);
    } catch (error) {
      setResponsibilityState({ loading: false, error: responsibilityErrorMessage(error) });
    }
  }

  const responsibleMember = members.find((member) => member.user_id === responsibility.responsible_user_id);
  const responsibilityLabel = responsibility.state === "unassigned_attention"
    ? "Reassignment required after member departure"
    : responsibility.state === "assigned"
      ? responsibleMember?.username ?? "Assigned member unavailable"
      : "No accountable member assigned";

  return (
    <section className="panel project-workspace-panel" aria-label={`Project workspace for ${project.project.name}`}>
      <div className="panel-header">
        <div>
          <h2><Activity size={18} aria-hidden="true" /> Project workspace: {project.project.name}</h2>
          <p className="muted">Review retained {sourceType === "sbom" ? "SBOM revisions" : "archive snapshots"} and decide the next safe action without reopening original source files.</p>
        </div>
        <button className="secondary-button" onClick={() => void refresh()} disabled={state.loading}>
          <RefreshCw size={16} aria-hidden="true" /> {state.loading ? "Loading" : "Refresh history"}
        </button>
      </div>

      <div className="project-workspace-summary" aria-label="Project workspace summary">
        <Metric label="Snapshots" value={snapshotCount} />
        <Metric label="Analyses" value={project.project.analysis_count} />
        <Metric label="Source type" value={sourceType === "sbom" ? "SBOM" : "Archive"} />
        <Metric label="Admission" value={sourceChannelLabel(latestSnapshot?.source_channel)} />
        <Metric label="Current source" value={currentSnapshotDeleted ? "Removed" : sourceReference(project.project.source_reference)} />
      </div>

      <section className={`project-responsibility ${responsibility.state === "unassigned_attention" ? "needs-attention" : ""}`} aria-labelledby={`project-responsibility-${project.project.id}`}>
        <div>
          <h3 id={`project-responsibility-${project.project.id}`}><UserRoundCheck size={17} aria-hidden="true" /> Project responsibility</h3>
          <p><strong>{responsibilityLabel}</strong></p>
          <p className="muted">This accountable owner is separate from assignees on individual findings and does not change triage decisions.</p>
        </div>
        {canManageResponsibility ? (
          <div className="project-responsibility-controls">
            <label>
              <span>Accountable member</span>
              <select
                value={responsibilityTarget}
                disabled={responsibilityState.loading || Boolean(responsibilityState.error)}
                onChange={(event) => { setResponsibilityTarget(event.target.value); setResponsibilityNotice(null); }}
              >
                <option value="">Unassigned</option>
                {members.map((member) => <option key={member.user_id} value={member.user_id}>{member.username}</option>)}
              </select>
            </label>
            <button
              type="button"
              onClick={() => void updateResponsibility()}
              disabled={
                responsibilityState.loading
                || Boolean(responsibilityState.error)
                || responsibilityTarget === (responsibility.responsible_user_id ?? "")
              }
            >
              {responsibilityState.loading ? "Saving…" : "Update responsibility"}
            </button>
          </div>
        ) : <p className="muted">Reader access can inspect project responsibility but cannot change it.</p>}
        {responsibility.state === "unassigned_attention" ? <p className="query-warning" role="status">The previous member left this workspace. Select an active member explicitly; Inspectra never reassigns ownership silently.</p> : null}
        {responsibilityState.error ? <p className="error-text" role="alert">{responsibilityState.error}</p> : null}
        {responsibilityNotice ? <p className="success-text" role="status">{responsibilityNotice}</p> : null}
      </section>

      <div className="project-workspace-next-step" role="status">
        {latestAnalysis ? (
          <>
            <span className={`status-pill ${latestAnalysis.status}`}>{latestAnalysis.status}</span>
            <p>{statusMessage(latestAnalysis)}</p>
          </>
        ) : <p>No retained analysis is linked to this project yet.</p>}
      </div>

      {state.error ? <p className="error-text" role="alert">{state.error}</p> : null}
      {analysisTotal > analyses.length ? (
        <p className="muted" role="status">Showing {analyses.length} of {analysisTotal} retained analyses.</p>
      ) : null}
      {state.loading && analyses.length === 0 ? <p className="muted" role="status">Loading retained analysis history…</p> : null}
      {!state.loading && !state.error && analyses.length === 0 ? <p className="empty-state">No retained analyses are available for this project.</p> : null}

      {analyses.length > 0 ? (
        <ol ref={timelineRef} className="project-workspace-timeline" aria-label="Retained project analysis timeline" tabIndex={-1}>
          {analyses.map((analysis) => {
            const sourceDeleted = analysis.source_file_deleted_at !== null;
            const snapshot = project.project.source_snapshots?.find(
              (candidate) => candidate.source_reference === analysis.source_reference
            );
            return (
              <li key={analysis.id} className="project-workspace-event">
                <div>
                  <div className="project-workspace-event-heading">
                    <span className={`status-pill ${analysis.status}`}>{analysis.status}</span>
                    <strong className="mono">{analysisSourceReference(analysis)}</strong>
                  </div>
                  <p>{statusMessage(analysis)}</p>
                  {analysis.termination_reason ? <p className="muted">{terminationMessage(analysis.termination_reason)}</p> : null}
                  {analysis.status === "completed" ? <p className="muted"><strong>Result integrity:</strong> {analysis.result_integrity_status === "valid" ? "verified" : "unknown (legacy result)"}</p> : null}
                  <p className="muted"><strong>Admission:</strong> {sourceChannelLabel(snapshot?.source_channel)}</p>
                  <span className="subtle-id">{formatDate(analysis.created_at)} · {sourceDeleted ? "Source removed; redacted result retained" : "Source retained"}</span>
                </div>
                <div className="row-actions">
                  {analysis.status === "queued" || analysis.status === "running" || analysis.status === "cancelling" ? (
                    <button
                      className="secondary-button"
                      onClick={() => void cancelAnalysis(analysis.id)}
                      disabled={analysis.status === "cancelling" || cancellingAnalysisId !== null}
                    >
                      <Ban size={15} aria-hidden="true" />
                      {analysis.status === "cancelling" || cancellingAnalysisId === analysis.id ? "Cancelling" : "Cancel analysis"}
                    </button>
                  ) : null}
                  <button className="secondary-button" onClick={() => onOpenAnalysis(analysis.id)}>
                    <Eye size={15} aria-hidden="true" /> Open analysis
                  </button>
                </div>
              </li>
            );
          })}
        </ol>
      ) : null}
      {analysisNextCursor ? (
        <button className="secondary-button" onClick={() => void loadMoreAnalyses()} disabled={state.loading}>
          {state.loading ? "Loading more analyses" : "Load more analyses"}
        </button>
      ) : null}
      {sourceType === "sbom" && onSbomRevisionImported ? (
        <SbomRevisionPanel project={project} canImport={canImportSbomRevision} onImported={onSbomRevisionImported} />
      ) : null}
      {sourceType === "archive" ? <ProjectCiSetupPanel project={project} canManage={canManageAutomation} focusOnMount={focusCiSetup} /> : null}
      {showVulnerabilityIntelligence ? <ProjectVulnerabilityIntelligencePanel project={project} /> : null}
    </section>
  );
}

function Metric({ label, value }: { label: string; value: number | string }) {
  return <div className="project-finding-metric"><span>{label}</span><strong>{value}</strong></div>;
}

function defaultResponsibility(): NonNullable<ProjectRecord["responsibility"]> {
  return { state: "unassigned", responsible_user_id: null, revision: 0, updated_at: null };
}

function sourceChannelLabel(channel: string | undefined): string {
  return ({
    archive_upload: "Archive upload",
    git_cli: "Git / CLI",
    ci: "CI automation",
    sbom: "SBOM import",
    unknown_git_or_ci: "Legacy Git / CI (unverified)",
  } as Record<string, string>)[channel ?? ""] ?? "Legacy source (unverified)";
}

function statusMessage(analysis: JobListItem): string {
  if (analysis.status_detail?.message) {
    return analysis.status_detail.message;
  }
  if (analysis.status === "completed") return "Review findings, inventory, comparison, or the retained report.";
  if (analysis.status === "failed") return "Review the retained record before repeating this source snapshot.";
  if (analysis.status === "cancelled") return "The review was cancelled and can be retried from the retained source.";
  if (analysis.status === "cancelling") return "Cancellation is in progress while the execution workspace is removed.";
  if (analysis.status === "running") return "The review is in progress. Refresh history for its next safe state.";
  return "The review is queued. Refresh history after it begins or completes.";
}

function terminationMessage(reason: string): string {
  return ({
    completed: "Finished under its recorded execution contract.",
    cancelled_by_owner: "Cancelled by the project owner; the execution workspace was removed.",
    application_restart: "Interrupted by an application restart; retry creates a new traceable attempt.",
    application_shutdown: "Interrupted during application shutdown; retry creates a new traceable attempt.",
    recovery_rejected: "The queued work was not resumed because its retained source or execution contract changed.",
    runner_timeout: "Stopped at the configured execution time limit.",
    runner_resource_limit: "Stopped at an isolated-worker resource boundary; reduce the snapshot before retrying.",
    runner_unavailable: "The analysis runner was unavailable; retry is safe from the retained snapshot.",
    runner_contract_invalid: "Stopped because backend and runner limit contracts differed.",
    workspace_error: "Stopped before analysis because the isolated workspace could not be prepared.",
    internal_error: "Stopped with a controlled internal execution error."
  } as Record<string, string>)[reason] ?? "Stopped with an unrecognized legacy reason.";
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown time" : date.toLocaleString();
}

function historyErrorMessage(error: unknown): string {
  if (error instanceof ApiError && error.status === 404) {
    return "This project is no longer available.";
  }
  return "Unable to load project analysis history. Refresh the page and try again.";
}

function cancellationErrorMessage(error: unknown): string {
  if (error instanceof ApiError && error.status === 409) {
    return "This analysis is already in a terminal state and can no longer be cancelled.";
  }
  if (error instanceof ApiError && error.status === 404) {
    return "This project analysis is no longer available.";
  }
  return "Unable to cancel the analysis safely. Refresh its state before trying again.";
}

function responsibilityErrorMessage(error: unknown): string {
  if (error instanceof ApiError && error.status === 409) {
    return "Project or responsibility changed. Refresh the project before assigning an accountable member.";
  }
  if (error instanceof ApiError && error.status === 422) {
    return "Select an active member of this workspace.";
  }
  if (error instanceof ApiError && error.status === 403) {
    return "Your role cannot change project responsibility.";
  }
  return "Project responsibility could not be updated safely. Existing responsibility was not changed.";
}
