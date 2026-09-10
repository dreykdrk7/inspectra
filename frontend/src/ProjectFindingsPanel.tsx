import { useEffect, useMemo, useRef, useState } from "react";
import { FileSearch, RefreshCw } from "lucide-react";

import { ApiError, api } from "./api";
import { ProjectAnalysisAvailabilityNotice } from "./ProjectAnalysisAvailabilityNotice";
import { ProjectAnalysisHistoryStatus, mergeProjectAnalyses } from "./ProjectAnalysisHistoryStatus";
import { analysisSourceReference } from "./sourcePresentation";
import { FindingLifecyclePanel, findingStatusLabel } from "./FindingLifecyclePanel";
import { FindingRemediationActions } from "./NormalizedFindingRemediation";
import type {
  FindingLifecycleState,
  JobListItem,
  NormalizedFinding,
  ProjectFindingsResponse,
  ProjectSummary,
  TeamMember,
  TeamRole,
} from "./types";

type LoadState = {
  loading: boolean;
  error: string | null;
};

type ProjectFindingsPanelProps = {
  project: ProjectSummary;
  onOpenAnalysis: (analysisId: string) => void;
  onRequestNewSnapshot: () => void;
  teamMode?: boolean;
  currentRole?: TeamRole | null;
};

const initialLoadState: LoadState = { loading: false, error: null };
const severityOrder = ["critical", "high", "medium", "low", "info"] as const;

export function ProjectFindingsPanel({
  project,
  onOpenAnalysis,
  onRequestNewSnapshot,
  teamMode = false,
  currentRole = null,
}: ProjectFindingsPanelProps) {
  const [analyses, setAnalyses] = useState<JobListItem[]>([]);
  const [result, setResult] = useState<ProjectFindingsResponse | null>(null);
  const [selectedAnalysisId, setSelectedAnalysisId] = useState<string | null>(project.latest_job?.id ?? null);
  const [state, setState] = useState<LoadState>(initialLoadState);
  const [analysisTotalCount, setAnalysisTotalCount] = useState(0);
  const [analysisNextCursor, setAnalysisNextCursor] = useState<string | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [category, setCategory] = useState("all");
  const [workflowStatus, setWorkflowStatus] = useState("all");
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [members, setMembers] = useState<TeamMember[]>([]);
  const [membersUnavailable, setMembersUnavailable] = useState(false);
  const findingSearchRef = useRef<HTMLInputElement>(null);
  const restoreFindingFilterFocusRef = useRef(false);
  const canManageFindings = !teamMode || currentRole !== "reader";
  const hasActiveFindingFilters = Boolean(query.trim()) || severity !== "all" || category !== "all" || workflowStatus !== "all";

  useEffect(() => {
    if (!hasActiveFindingFilters && restoreFindingFilterFocusRef.current) {
      restoreFindingFilterFocusRef.current = false;
      findingSearchRef.current?.focus();
    }
  }, [hasActiveFindingFilters]);

  const findings = result?.findings ?? [];
  const categories = useMemo(
    () => Array.from(new Set(findings.map((finding) => finding.category))).sort((left, right) => left.localeCompare(right)),
    [findings]
  );
  const filteredFindings = useMemo(() => {
    const normalizedQuery = query.trim().toLocaleLowerCase();
    return findings.filter((finding) => {
      const matchesSeverity = severity === "all" || finding.severity === severity;
      const matchesCategory = category === "all" || finding.category === category;
      const lifecycle = result?.lifecycle?.[finding.id];
      const status = lifecycle?.current_status ?? "open";
      const matchesWorkflow = workflowStatus === "all" || status === workflowStatus;
      const searchable = [
        finding.title,
        finding.rule_id,
        finding.category,
        finding.description,
        finding.evidence,
        finding.location?.path ?? "",
        status,
        lifecycle?.current_decision?.reason ?? "",
        lifecycle?.current_decision?.assignee_username ?? ""
      ]
        .join(" ")
        .toLocaleLowerCase();
      return matchesSeverity && matchesCategory && matchesWorkflow && (!normalizedQuery || searchable.includes(normalizedQuery));
    });
  }, [category, findings, query, result?.lifecycle, severity, workflowStatus]);

  useEffect(() => {
    let disposed = false;
    if (!teamMode) {
      setMembers([]);
      setMembersUnavailable(false);
      return;
    }
    api.listTeamMembers()
      .then((items) => {
        if (!disposed) {
          setMembers(items);
          setMembersUnavailable(false);
        }
      })
      .catch(() => {
        if (!disposed) {
          setMembers([]);
          setMembersUnavailable(true);
        }
      });
    return () => {
      disposed = true;
    };
  }, [project.project.organization_id, teamMode]);

  useEffect(() => {
    let disposed = false;

    async function load() {
      setState({ loading: true, error: null });
      try {
        const history = await api.listProjectAnalysisPage(project.project.id);
        const nextAnalyses = history.items;
        const preferredId =
          nextAnalyses.find((analysis) => analysis.status === "completed")?.id ?? project.latest_job?.id ?? nextAnalyses[0]?.id;
        const nextResult = await api.getProjectFindings(project.project.id, preferredId);
        if (disposed) {
          return;
        }
        setAnalyses(nextAnalyses);
        setAnalysisTotalCount(history.total_count);
        setAnalysisNextCursor(history.next_cursor);
        setHistoryError(null);
        setSelectedAnalysisId(nextResult.analysis?.id ?? preferredId ?? null);
        setResult(nextResult);
        setExpandedFindingId(null);
        setState(initialLoadState);
      } catch (error) {
        if (disposed) {
          return;
        }
        setState({ loading: false, error: projectFindingsErrorMessage(error) });
      }
    }

    void load();
    return () => {
      disposed = true;
    };
  }, [project.latest_job?.id, project.project.id]);

  async function selectAnalysis(analysisId: string) {
    setSelectedAnalysisId(analysisId);
    setState({ loading: true, error: null });
    try {
      const nextResult = await api.getProjectFindings(project.project.id, analysisId);
      setResult(nextResult);
      setExpandedFindingId(null);
      setState(initialLoadState);
    } catch (error) {
      setState({ loading: false, error: projectFindingsErrorMessage(error) });
    }
  }

  async function refresh() {
    setState({ loading: true, error: null });
    try {
      const history = await api.listProjectAnalysisPage(project.project.id);
      const retainedSelection = selectedAnalysisId && !history.items.some((analysis) => analysis.id === selectedAnalysisId)
        ? await api.getProjectAnalysisSummary(project.project.id, selectedAnalysisId)
        : null;
      const nextAnalyses = mergeProjectAnalyses(history.items, retainedSelection ? [retainedSelection] : []);
      const analysisId = selectedAnalysisId ?? nextAnalyses.find((analysis) => analysis.status === "completed")?.id;
      const nextResult = await api.getProjectFindings(project.project.id, analysisId ?? undefined);
      setAnalyses(nextAnalyses);
      setAnalysisTotalCount(history.total_count);
      setAnalysisNextCursor(history.next_cursor);
      setHistoryError(null);
      setSelectedAnalysisId(nextResult.analysis?.id ?? analysisId ?? null);
      setResult(nextResult);
      setState(initialLoadState);
    } catch (error) {
      setState({ loading: false, error: projectFindingsErrorMessage(error) });
    }
  }

  async function loadOlderAnalyses() {
    if (!analysisNextCursor || historyLoading || state.loading) return;
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const history = await api.listProjectAnalysisPage(project.project.id, analysisNextCursor);
      setAnalyses((current) => mergeProjectAnalyses(current, history.items));
      setAnalysisTotalCount(history.total_count);
      setAnalysisNextCursor(history.next_cursor);
    } catch {
      setHistoryError("Unable to load older analyses. The loaded snapshots remain available; try again.");
    } finally {
      setHistoryLoading(false);
    }
  }

  function clearFindingFilters() {
    restoreFindingFilterFocusRef.current = true;
    setQuery("");
    setSeverity("all");
    setCategory("all");
    setWorkflowStatus("all");
  }

  return (
    <section className="panel project-findings-panel" aria-label={`Project findings for ${project.project.name}`} aria-busy={state.loading}>
      <div className="panel-header">
        <div>
          <h2>
            <FileSearch size={18} aria-hidden="true" />
            Findings: {project.project.name}
          </h2>
          <p className="muted">Only redacted, normalized indicators from this project are shown. They are not confirmed exploitation findings.</p>
        </div>
        <button className="secondary-button" onClick={() => void refresh()} disabled={state.loading}>
          <RefreshCw size={16} aria-hidden="true" />
          {state.loading ? "Loading" : "Refresh"}
        </button>
      </div>

      {state.error ? <p className="error-text" role="alert">{state.error}</p> : null}
      {membersUnavailable ? (
        <p className="query-warning" role="status">Member assignments are temporarily unavailable. Existing decisions remain readable.</p>
      ) : null}
      {state.loading && !result ? <p className="muted" role="status">Loading project findings…</p> : null}

      {analyses.length > 0 ? (
        <label className="auth-field project-analysis-picker">
          <span>Analysis snapshot</span>
          <select
            value={selectedAnalysisId ?? ""}
            onChange={(event) => void selectAnalysis(event.target.value)}
            disabled={state.loading}
          >
            {analyses.map((analysis) => (
              <option key={analysis.id} value={analysis.id}>
                {formatAnalysisOption(analysis)}
              </option>
            ))}
          </select>
        </label>
      ) : null}

      <ProjectAnalysisHistoryStatus
        analyses={analyses}
        totalCount={analysisTotalCount}
        hasMore={Boolean(analysisNextCursor)}
        loading={historyLoading || state.loading}
        error={historyError}
        onLoadMore={() => void loadOlderAnalyses()}
      />

      {result?.result_truncated ? (
        <p className="query-warning" role="status">
          This review reached a configured analysis limit. The findings below are partial; review the coverage and source snapshot before
          treating an empty category as absence of risk.
        </p>
      ) : null}

      {result?.coverage ? (
        <p className="query-warning" role="status">
          Coverage {result.coverage.coverage_status}: manifests {result.coverage.supported_manifests_parsed}/{result.coverage.supported_manifests_found}; lockfiles {result.coverage.lockfiles_parsed}/{result.coverage.lockfiles_detected}. {result.coverage.limitations.length ? "Review limitations before trusting an empty result." : "No reported limits."}
        </p>
      ) : null}

      {result?.state === "no_completed_analysis" ? (
        <p className="empty-state">No completed project analysis is available yet. Wait for the queued review or run a retained snapshot.</p>
      ) : null}
      {result && (result.state === "analysis_pending" || result.state === "analysis_failed" || result.state === "analysis_cancelled") ? (
        <ProjectAnalysisAvailabilityNotice state={result.state} />
      ) : null}
      {result?.state === "no_normalized_findings" ? (
        <p className="empty-state">
          This completed analysis has no compatible normalized findings. Open its full report for its analyzer-specific coverage and limits.
        </p>
      ) : null}

      {result?.analysis ? (
        <div className="project-findings-context">
          <span className={`status-pill ${result.analysis.status}`}>{result.analysis.status}</span>
          <span className="mono">{analysisSourceReference(result.analysis)}</span>
          <button className="secondary-button" onClick={() => onOpenAnalysis(result.analysis!.id)}>
            Open full analysis
          </button>
          {result.state === "ready" ? (
            <ProjectReportExports
              projectId={project.project.id}
              analysisId={result.analysis.id}
              canExportTechnical={canManageFindings}
            />
          ) : null}
        </div>
      ) : null}

      {result?.state === "ready" ? (
        <>
          <div className="project-finding-summary" aria-label="Finding summary">
            <SummaryMetric label="Total" value={result.summary.total} />
            {severityOrder.map((level) => <SummaryMetric key={level} label={level} value={result.summary.by_severity[level] ?? 0} />)}
          </div>

          <p className="muted finding-workflow-summary">
            Workflow: {result.summary.by_status?.open ?? result.summary.total} open · {result.summary.by_status?.in_review ?? 0} in review · {result.summary.by_status?.accepted ?? 0} accepted · {result.summary.by_status?.false_positive ?? 0} false positive · {result.summary.by_status?.resolved ?? 0} resolved
            {(result.summary.needs_review ?? 0) > 0 ? ` · ${result.summary.needs_review} need review` : ""}.
          </p>

          <fieldset className="project-finding-filters">
            <legend className="sr-only">Project finding filters</legend>
            <label className="auth-field">
              <span>Search findings</span>
              <input
                className="search-input"
                type="search"
                ref={findingSearchRef}
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Rule, file, evidence, or recommendation"
              />
            </label>
            <label className="auth-field">
              <span>Severity</span>
              <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
                <option value="all">All severities</option>
                {severityOrder.map((level) => <option key={level} value={level}>{capitalize(level)}</option>)}
              </select>
            </label>
            <label className="auth-field">
              <span>Category</span>
              <select value={category} onChange={(event) => setCategory(event.target.value)}>
                <option value="all">All categories</option>
                {categories.map((item) => <option key={item} value={item}>{humanize(item)}</option>)}
              </select>
            </label>
            <label className="auth-field">
              <span>Workflow status</span>
              <select value={workflowStatus} onChange={(event) => setWorkflowStatus(event.target.value)}>
                <option value="all">All workflow statuses</option>
                {(["open", "in_review", "accepted", "false_positive", "resolved"] as const).map((item) => (
                  <option key={item} value={item}>{findingStatusLabel(item)}</option>
                ))}
              </select>
            </label>
          </fieldset>

          {findings.length > 0 ? (
            <div className="project-finding-filter-status">
              <p id="project-finding-filter-status" className="muted" role="status" aria-live="polite">
                Showing {filteredFindings.length} of {findings.length} project {filteredFindings.length === 1 ? "finding" : "findings"}.{hasActiveFindingFilters ? " Filters do not change retained evidence or workflow." : ""}
              </p>
              {hasActiveFindingFilters ? <button type="button" className="link-button" onClick={clearFindingFilters}>Clear finding filters</button> : null}
            </div>
          ) : null}

          {findings.length === 0 ? (
            <p className="empty-state">This completed analysis returned no normalized review indicators within its recorded coverage.</p>
          ) : filteredFindings.length === 0 ? (
            <p className="empty-state">No findings match these filters. Clear or broaden them to review the recorded indicators.</p>
          ) : (
            <ol className="project-finding-list" aria-label="Filtered project findings" aria-describedby="project-finding-filter-status">
              {filteredFindings.map((finding) => {
                const expanded = expandedFindingId === finding.id;
                const lifecycle = result.lifecycle?.[finding.id];
                const currentStatus = lifecycle?.current_status ?? "open";
                return (
                  <li key={finding.id} className="project-finding-card">
                    <button
                      className="project-finding-toggle"
                      aria-expanded={expanded}
                      aria-controls={`finding-${finding.id}`}
                      onClick={() => setExpandedFindingId(expanded ? null : finding.id)}
                    >
                      <span>
                        <strong>{finding.title}</strong>
                        <span className="subtle-id">{finding.rule_id}</span>
                      </span>
                      <span className="badge-row">
                        <span className={`finding-badge ${finding.severity}`}>{finding.severity}</span>
                        <span className={`finding-badge ${finding.confidence}`}>{finding.confidence} confidence</span>
                        <span className={`finding-status-badge ${currentStatus}`}>{findingStatusLabel(currentStatus)}</span>
                      </span>
                    </button>
                    {expanded && result.analysis ? (
                      <FindingDetail
                        finding={finding}
                        lifecycle={lifecycle}
                        projectId={project.project.id}
                        analysisId={result.analysis.id}
                        canManage={canManageFindings}
                        members={members}
                        onLifecycleUpdated={refresh}
                        onRequestNewSnapshot={onRequestNewSnapshot}
                        sourceUpdateLabel={project.project.source_type === "sbom" ? "Review a new SBOM revision" : "Review a new archive snapshot"}
                      />
                    ) : null}
                  </li>
                );
              })}
            </ol>
          )}
        </>
      ) : null}
    </section>
  );
}

function SummaryMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className={`project-finding-metric ${label.toLocaleLowerCase()}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ProjectReportExports({
  projectId,
  analysisId,
  canExportTechnical,
}: {
  projectId: string;
  analysisId: string;
  canExportTechnical: boolean;
}) {
  const [technicalConfirmed, setTechnicalConfirmed] = useState(false);
  const [exporting, setExporting] = useState<"markdown" | "html" | "pdf" | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [exportNotice, setExportNotice] = useState<string | null>(null);

  useEffect(() => {
    setTechnicalConfirmed(false);
    setExportError(null);
    setExportNotice(null);
  }, [analysisId, projectId]);

  async function downloadTechnical(format: "markdown" | "html" | "pdf") {
    if (!technicalConfirmed || !canExportTechnical) return;
    setExporting(format);
    setExportError(null);
    setExportNotice(null);
    try {
      const result = await api.exportProjectAnalysisTechnicalReport(projectId, analysisId, format);
      const url = URL.createObjectURL(result.blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = result.filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
      setExportNotice(`Technical ${format.toUpperCase()} report downloaded.`);
    } catch (caught) {
      setExportError(caught instanceof Error ? caught.message : "Technical report could not be generated.");
    } finally {
      setExporting(null);
    }
  }

  return (
    <div className="project-report-exports" aria-label="Project report exports">
      <div className="project-report-minimal" aria-label="Minimal project report downloads">
        <span className="muted">Minimal report excludes names, paths, evidence and component identities.</span>
        {(["markdown", "html", "pdf"] as const).map((format) => (
          <a key={format} className="export-link" href={api.projectAnalysisReportUrl(projectId, analysisId, format)}>
            Minimal {format.toUpperCase()}
          </a>
        ))}
      </div>
      <details className="project-report-technical">
        <summary>Technical report options</summary>
        <p className="warning-text" role="status">
          Technical reports include project/member names, relative locations, normalized evidence, component identities and workflow decisions. Secrets, unsafe paths and source content remain excluded.
        </p>
        {canExportTechnical ? (
          <>
            <label className="checkbox-row">
              <input
                type="checkbox"
                checked={technicalConfirmed}
                onChange={(event) => setTechnicalConfirmed(event.target.checked)}
              />
              I understand this report contains technical project metadata and will share it only with authorized recipients.
            </label>
            <div className="row-actions">
              {(["markdown", "html", "pdf"] as const).map((format) => (
                <button
                  key={format}
                  type="button"
                  className="secondary-button"
                  disabled={!technicalConfirmed || exporting !== null}
                  onClick={() => void downloadTechnical(format)}
                >
                  {exporting === format ? `Downloading ${format.toUpperCase()}…` : `Technical ${format.toUpperCase()}`}
                </button>
              ))}
            </div>
          </>
        ) : (
          <p className="warning-text" role="status">A maintainer or administrator must confirm this export. Read-only users can download only the minimal profile.</p>
        )}
        {exportNotice ? <p className="success-text" role="status">{exportNotice}</p> : null}
        {exportError ? <p className="error-text" role="alert">{exportError}</p> : null}
      </details>
    </div>
  );
}

function FindingDetail({
  finding,
  lifecycle,
  projectId,
  analysisId,
  canManage,
  members,
  onLifecycleUpdated,
  onRequestNewSnapshot,
  sourceUpdateLabel,
}: {
  finding: NormalizedFinding;
  lifecycle?: FindingLifecycleState;
  projectId: string;
  analysisId: string;
  canManage: boolean;
  members: TeamMember[];
  onLifecycleUpdated: () => Promise<void>;
  onRequestNewSnapshot: () => void;
  sourceUpdateLabel: string;
}) {
  const location = finding.location_status === "withheld_unsafe_path"
    ? "Withheld: unsafe path reported by analyzer"
    : finding.location?.path
      ? `${finding.location.path}${finding.location.line ? `:${finding.location.line}` : ""}`
      : finding.location?.line
        ? `Line ${finding.location.line} (file not reported)`
      : "Not reported by this analyzer";
  return (
    <section id={`finding-${finding.id}`} className="project-finding-detail" aria-label={`Finding detail for ${finding.title}`}>
      <dl className="summary-list">
        <dt>Category</dt>
        <dd>{humanize(finding.category)}</dd>
        <dt>Source</dt>
        <dd className="mono">{finding.source_audit_type}</dd>
        <dt>Location</dt>
        <dd className="mono">{location}</dd>
      </dl>
      {finding.description ? <p>{finding.description}</p> : null}
      {finding.evidence ? <p className="evidence-line"><strong>Redacted evidence:</strong> <code>{finding.evidence}</code></p> : null}
      <FindingRemediationActions
        recommendation={finding.recommendation}
        references={finding.references}
        onRequestNewSnapshot={onRequestNewSnapshot}
        sourceUpdateLabel={sourceUpdateLabel}
      />
      <FindingLifecyclePanel
        projectId={projectId}
        analysisId={analysisId}
        finding={finding}
        lifecycle={lifecycle}
        canManage={canManage}
        members={members}
        onUpdated={onLifecycleUpdated}
      />
    </section>
  );
}

function projectFindingsErrorMessage(error: unknown): string {
  if (error instanceof ApiError && error.status === 404) {
    return "This project analysis is no longer available. Choose another retained analysis.";
  }
  return "Unable to load project findings. Refresh the page and try again.";
}

function formatAnalysisOption(analysis: JobListItem): string {
  return `${formatDate(analysis.updated_at)} · ${analysis.status} · ${analysisSourceReference(analysis)}`;
}

function formatDate(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Unknown time" : parsed.toLocaleString();
}

function capitalize(value: string): string {
  return value ? `${value[0].toLocaleUpperCase()}${value.slice(1)}` : value;
}

function humanize(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (letter: string) => letter.toLocaleUpperCase());
}
