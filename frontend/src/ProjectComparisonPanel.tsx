import { useEffect, useMemo, useState } from "react";
import { GitCompareArrows, RefreshCw } from "lucide-react";

import { ApiError, api } from "./api";
import { analysisSourceReference } from "./sourcePresentation";
import { findingStatusLabel } from "./FindingLifecyclePanel";
import { FindingRemediationActions } from "./NormalizedFindingRemediation";
import { ProjectAnalysisHistoryStatus, mergeProjectAnalyses } from "./ProjectAnalysisHistoryStatus";
import type {
  JobListItem,
  ProjectAnalysisCoverage,
  ProjectAnalysisComparisonResponse,
  ProjectFindingComparison,
  ProjectPublicVulnerabilityComparison,
  ProjectPublicVulnerabilityFindingComparison,
  ProjectSummary,
} from "./types";

type LoadState = {
  loading: boolean;
  error: string | null;
};

type ProjectComparisonPanelProps = {
  project: ProjectSummary;
  onOpenAnalysis: (analysisId: string) => void;
  onRequestNewSnapshot: () => void;
};

const initialLoadState: LoadState = { loading: false, error: null };
const comparisonGroups: Array<{ status: ProjectFindingComparison["status"]; label: string; empty: string }> = [
  { status: "new", label: "New findings", empty: "No new normalized findings in the selected comparison." },
  { status: "resolved", label: "Resolved findings", empty: "No normalized findings were resolved in the selected comparison." },
  { status: "persistent", label: "Persistent findings", empty: "No normalized findings persisted between these analyses." },
];

const publicVulnerabilityComparisonGroups: Array<{
  status: ProjectPublicVulnerabilityFindingComparison["status"];
  label: string;
  empty: string;
}> = [
  { status: "new", label: "New public vulnerability findings", empty: "No new verified public vulnerability findings in the selected comparison." },
  { status: "resolved", label: "Resolved public vulnerability findings", empty: "No verified public vulnerability findings were resolved in the selected comparison." },
  { status: "persistent", label: "Persistent public vulnerability findings", empty: "No verified public vulnerability findings persisted between these analyses." },
];

export function ProjectComparisonPanel({ project, onOpenAnalysis, onRequestNewSnapshot }: ProjectComparisonPanelProps) {
  const [analyses, setAnalyses] = useState<JobListItem[]>([]);
  const [baseAnalysisId, setBaseAnalysisId] = useState<string | null>(null);
  const [targetAnalysisId, setTargetAnalysisId] = useState<string | null>(null);
  const [savedBaselineId, setSavedBaselineId] = useState<string | null>(project.project.baseline_analysis_id ?? null);
  const [savedBaselineVersion, setSavedBaselineVersion] = useState(project.project.baseline_version ?? 0);
  const [baselineNotice, setBaselineNotice] = useState<string | null>(null);
  const [result, setResult] = useState<ProjectAnalysisComparisonResponse | null>(null);
  const [state, setState] = useState<LoadState>(initialLoadState);
  const [analysisTotalCount, setAnalysisTotalCount] = useState(0);
  const [analysisNextCursor, setAnalysisNextCursor] = useState<string | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);

  const completedAnalyses = useMemo(() => analyses.filter((analysis) => analysis.status === "completed"), [analyses]);
  const canCompare = Boolean(baseAnalysisId && targetAnalysisId && baseAnalysisId !== targetAnalysisId);
  const selectedBaseline = completedAnalyses.find((analysis) => analysis.id === baseAnalysisId) ?? null;
  const savedBaseline = completedAnalyses.find((analysis) => analysis.id === savedBaselineId) ?? null;
  const canSaveSelectedBaseline = Boolean(selectedBaseline?.execution_profile && selectedBaseline.id !== savedBaselineId);

  useEffect(() => {
    let disposed = false;

    async function loadInitialComparison() {
      setState({ loading: true, error: null });
      try {
        const history = await api.listProjectAnalysisPage(project.project.id);
        const savedId = project.project.baseline_analysis_id ?? null;
        const nextAnalyses = await includeRetainedAnalyses(project.project.id, history.items, [savedId]);
        const completed = nextAnalyses.filter((analysis) => analysis.status === "completed");
        if (disposed) {
          return;
        }
        setAnalyses(nextAnalyses);
        setAnalysisTotalCount(history.total_count);
        setAnalysisNextCursor(history.next_cursor);
        setHistoryError(null);
        const savedAnalysis = completed.find((analysis) => analysis.id === savedId) ?? null;
        setSavedBaselineId(savedId);
        setSavedBaselineVersion(project.project.baseline_version ?? 0);
        setBaselineNotice(null);
        if (completed.length < 2) {
          setBaseAnalysisId(savedAnalysis?.id ?? completed[0]?.id ?? null);
          setTargetAnalysisId(null);
          setResult(null);
          setState(initialLoadState);
          return;
        }
        const baseId = savedAnalysis?.id ?? completed[1].id;
        const targetId = defaultComparisonTargetId(completed, baseId);
        if (!targetId) {
          setBaseAnalysisId(baseId);
          setTargetAnalysisId(null);
          setResult(null);
          setState(initialLoadState);
          return;
        }
        const comparison = await api.getProjectAnalysisComparison(project.project.id, baseId, targetId);
        if (disposed) {
          return;
        }
        setBaseAnalysisId(baseId);
        setTargetAnalysisId(targetId);
        setResult(comparison);
        setState(initialLoadState);
      } catch (error) {
        if (!disposed) {
          setState({ loading: false, error: comparisonErrorMessage(error) });
        }
      }
    }

    void loadInitialComparison();
    return () => {
      disposed = true;
    };
  }, [project.latest_job?.id, project.project.id]);

  async function compareSelectedAnalyses() {
    if (!baseAnalysisId || !targetAnalysisId || baseAnalysisId === targetAnalysisId) {
      return;
    }
    setState({ loading: true, error: null });
    try {
      const comparison = await api.getProjectAnalysisComparison(project.project.id, baseAnalysisId, targetAnalysisId);
      setResult(comparison);
      setState(initialLoadState);
    } catch (error) {
      setState({ loading: false, error: comparisonErrorMessage(error) });
    }
  }

  async function refresh() {
    setState({ loading: true, error: null });
    try {
      const history = await api.listProjectAnalysisPage(project.project.id);
      const nextAnalyses = await includeRetainedAnalyses(project.project.id, history.items, [
        savedBaselineId,
        baseAnalysisId,
        targetAnalysisId,
      ]);
      const completed = nextAnalyses.filter((analysis) => analysis.status === "completed");
      const savedAnalysis = completed.find((analysis) => analysis.id === savedBaselineId) ?? null;
      const nextBaseId = savedAnalysis?.id ?? (completed.some((analysis) => analysis.id === baseAnalysisId) ? baseAnalysisId : completed[1]?.id ?? completed[0]?.id ?? null);
      const nextTargetId = completed.some((analysis) => analysis.id === targetAnalysisId && analysis.id !== nextBaseId)
        ? targetAnalysisId
        : defaultComparisonTargetId(completed, nextBaseId);
      setAnalyses(nextAnalyses);
      setAnalysisTotalCount(history.total_count);
      setAnalysisNextCursor(history.next_cursor);
      setHistoryError(null);
      setBaseAnalysisId(nextBaseId);
      setTargetAnalysisId(nextTargetId);
      if (!nextBaseId || !nextTargetId || nextBaseId === nextTargetId) {
        setResult(null);
        setState(initialLoadState);
        return;
      }
      const comparison = await api.getProjectAnalysisComparison(project.project.id, nextBaseId, nextTargetId);
      setResult(comparison);
      setState(initialLoadState);
    } catch (error) {
      setState({ loading: false, error: comparisonErrorMessage(error) });
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
      setHistoryError("Unable to load older analyses. The loaded snapshots and current comparison remain available; try again.");
    } finally {
      setHistoryLoading(false);
    }
  }

  async function saveSelectedBaseline() {
    if (!selectedBaseline?.execution_profile) {
      return;
    }
    setState({ loading: true, error: null });
    try {
      const updated = await api.setProjectBaseline(project.project.id, selectedBaseline.id);
      setSavedBaselineId(updated.baseline_analysis_id ?? null);
      setSavedBaselineVersion(updated.baseline_version ?? 0);
      setBaselineNotice(`Saved baseline updated (policy version ${updated.baseline_version ?? 0}).`);
      setResult(null);
      setState(initialLoadState);
    } catch (error) {
      setState({ loading: false, error: comparisonErrorMessage(error) });
    }
  }

  async function clearSavedBaseline() {
    if (!savedBaselineId) {
      return;
    }
    setState({ loading: true, error: null });
    try {
      const updated = await api.clearProjectBaseline(project.project.id);
      setSavedBaselineId(updated.baseline_analysis_id ?? null);
      setSavedBaselineVersion(updated.baseline_version ?? 0);
      setBaselineNotice(`Saved baseline cleared (policy version ${updated.baseline_version ?? 0}).`);
      setResult(null);
      setState(initialLoadState);
    } catch (error) {
      setState({ loading: false, error: comparisonErrorMessage(error) });
    }
  }

  return (
    <section className="panel project-comparison-panel" aria-label={`Project analysis comparison for ${project.project.name}`}>
      <div className="panel-header">
        <div>
          <h2>
            <GitCompareArrows size={18} aria-hidden="true" />
            Analysis comparison
          </h2>
          <p className="muted">
            Compare two completed snapshots of this project. Counts use stable IDs derived from redacted evidence; they are review
            indicators, not proof of exploitation or remediation.
          </p>
        </div>
        <button className="secondary-button" onClick={() => void refresh()} disabled={state.loading}>
          <RefreshCw size={16} aria-hidden="true" />
          {state.loading ? "Loading" : "Refresh history"}
        </button>
      </div>

      {state.error ? <p className="error-text" role="alert">{state.error}</p> : null}
      {state.loading && !result ? <p className="muted" role="status">Loading project analysis history…</p> : null}

      {completedAnalyses.length < 2 && !state.loading ? (
        <p className="empty-state">Complete two retained analyses of this project to compare new, resolved, and persistent findings.</p>
      ) : null}

      {completedAnalyses.length >= 2 ? (
        <>
          <div className="project-baseline-status" role="status">
            {savedBaseline ? (
              <span>Saved project baseline: {formatAnalysisOption(savedBaseline)} (policy version {savedBaselineVersion}).</span>
            ) : savedBaselineId ? (
              <span>Saved project baseline is no longer retained. Clear it before selecting a new baseline.</span>
            ) : (
              <span>No saved project baseline. This comparison is ad hoc until you explicitly save one.</span>
            )}
          </div>
          {baselineNotice ? <p className="success-text" role="status">{baselineNotice}</p> : null}
          <div className="project-comparison-selectors">
            <label className="auth-field">
              <span>Baseline analysis</span>
              <select value={baseAnalysisId ?? ""} onChange={(event) => setBaseAnalysisId(event.target.value)} disabled={state.loading}>
                {completedAnalyses.map((analysis) => <option key={analysis.id} value={analysis.id}>{formatAnalysisOption(analysis)}</option>)}
              </select>
            </label>
            <label className="auth-field">
              <span>Comparison analysis</span>
              <select value={targetAnalysisId ?? ""} onChange={(event) => setTargetAnalysisId(event.target.value)} disabled={state.loading}>
                {completedAnalyses.map((analysis) => <option key={analysis.id} value={analysis.id}>{formatAnalysisOption(analysis)}</option>)}
              </select>
            </label>
            <button className="primary-button" onClick={() => void compareSelectedAnalyses()} disabled={!canCompare || state.loading}>
              Compare selected analyses
            </button>
            <button className="secondary-button" onClick={() => void saveSelectedBaseline()} disabled={!canSaveSelectedBaseline || state.loading}>
              Save selected baseline
            </button>
            {savedBaselineId ? (
              <button className="secondary-button" onClick={() => void clearSavedBaseline()} disabled={state.loading}>
                Clear saved baseline
              </button>
            ) : null}
          </div>
          {!canCompare ? <p className="query-warning">Choose two different completed analyses to start a comparison.</p> : null}
          {selectedBaseline && !selectedBaseline.execution_profile ? (
            <p className="query-warning">A legacy analysis without a recorded execution profile cannot become the saved baseline. Run its retained snapshot again first.</p>
          ) : null}
        </>
      ) : null}

      <ProjectAnalysisHistoryStatus
        analyses={analyses}
        totalCount={analysisTotalCount}
        hasMore={Boolean(analysisNextCursor)}
        loading={historyLoading || state.loading}
        error={historyError}
        onLoadMore={() => void loadOlderAnalyses()}
      />

      {result ? (
        <>
          <div className="project-comparison-context">
            <span className="mono">Baseline {analysisSourceReference(result.base_analysis)}</span>
            {result.uses_saved_baseline ? <span className="comparison-status persistent">Saved project baseline</span> : null}
            <span aria-hidden="true">→</span>
            <span className="mono">Comparison {analysisSourceReference(result.target_analysis)}</span>
            <button className="secondary-button" onClick={() => onOpenAnalysis(result.base_analysis.id)}>Open baseline</button>
            <button className="secondary-button" onClick={() => onOpenAnalysis(result.target_analysis.id)}>Open comparison</button>
          </div>

          {result.limitations.length > 0 ? (
            <ul className="warning-list" aria-label="Comparison limitations">
              {result.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}
            </ul>
          ) : null}

          {result.state === "analysis_pending" ? <p className="empty-state">Both selected analyses must complete before comparing their results.</p> : null}
          {result.state === "not_comparable" ? <p className="empty-state">{notComparableMessage(result)}</p> : null}
          {result.state === "no_normalized_findings" ? <p className="empty-state">One selected analysis has no compatible normalized findings. Open its report for analyzer-specific coverage.</p> : null}

          {result.coverage_comparison ? <CoverageComparison coverage={result.coverage_comparison} /> : null}
          {result.public_vulnerability_comparison ? <PublicVulnerabilityComparison comparison={result.public_vulnerability_comparison} /> : null}
          {result.state === "ready" ? <ComparisonResult
            result={result}
            onRequestNewSnapshot={onRequestNewSnapshot}
            sourceUpdateLabel={project.project.source_type === "sbom" ? "Review a new SBOM revision" : "Review a new archive snapshot"}
          /> : null}
        </>
      ) : null}
    </section>
  );
}

async function includeRetainedAnalyses(
  projectId: string,
  pageItems: JobListItem[],
  requestedIds: Array<string | null>,
): Promise<JobListItem[]> {
  const missingIds = Array.from(new Set(requestedIds.filter((value): value is string => Boolean(value))))
    .filter((analysisId) => !pageItems.some((analysis) => analysis.id === analysisId));
  const resolved: JobListItem[] = [];
  for (const analysisId of missingIds) {
    try {
      resolved.push(await api.getProjectAnalysisSummary(projectId, analysisId));
    } catch (error) {
      if (!(error instanceof ApiError) || error.status !== 404) throw error;
    }
  }
  return mergeProjectAnalyses(pageItems, resolved);
}

function PublicVulnerabilityComparison({ comparison }: { comparison: ProjectPublicVulnerabilityComparison }) {
  return (
    <section className="comparison-public-vulnerabilities" aria-labelledby="comparison-public-vulnerabilities-heading">
      <h3 id="comparison-public-vulnerabilities-heading">Public vulnerability intelligence</h3>
      <p className="muted">
        This is a separate comparison of retained OSV snapshots. A missing, stale, degraded, or legacy snapshot is never treated as
        evidence that a dependency was fixed.
      </p>
      {comparison.limitations.length > 0 ? (
        <ul className="warning-list" aria-label="Public vulnerability comparison limitations">
          {comparison.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}
        </ul>
      ) : null}
      {comparison.state === "not_available" ? <p className="empty-state">Public advisory comparison is not available for these analyses.</p> : null}
      {comparison.state === "not_comparable" ? <p className="empty-state">Public advisory snapshots are not comparable yet. Refresh both analyses when their recorded coverage is equivalent.</p> : null}
      {comparison.state === "ready" ? (
        <>
          <div className="project-comparison-summary" aria-label="Public vulnerability comparison summary">
            <ComparisonMetric label="New public vulnerability findings" value={comparison.summary.new} />
            <ComparisonMetric label="Resolved public vulnerability findings" value={comparison.summary.resolved} />
            <ComparisonMetric label="Persistent public vulnerability findings" value={comparison.summary.persistent} />
          </div>
          {publicVulnerabilityComparisonGroups.map((group) => {
            const findings = comparison.comparisons.filter((item) => item.status === group.status);
            return (
              <section key={group.status} className={`comparison-group ${group.status}`} aria-label={group.label}>
                <h4>{group.label} <span className="subtle-id">{findings.length}</span></h4>
                {findings.length === 0 ? <p className="empty-state">{group.empty}</p> : (
                  <ul className="project-findings-list">
                    {findings.map((item) => <PublicVulnerabilityComparisonFinding key={`${item.status}-${item.finding.id}`} comparison={item} />)}
                  </ul>
                )}
              </section>
            );
          })}
        </>
      ) : null}
    </section>
  );
}

function PublicVulnerabilityComparisonFinding({ comparison }: { comparison: ProjectPublicVulnerabilityFindingComparison }) {
  const { finding, previous_finding: previousFinding } = comparison;
  const knownExploited = finding.kev_signals.some((signal) => signal.status === "known_exploited");
  const nvdEvidence = finding.nvd_evidence ?? [];
  const cpeIdentityCorroborated = nvdEvidence.some((evidence) => evidence.cpe_status === "identity_corroborated");
  return (
    <li className="project-finding-card">
      <article>
        <div className="finding-card-header">
          <span>
            <strong>{finding.advisory_id}</strong>
            <span className="subtle-id">{finding.component_name}@{finding.component_version}</span>
          </span>
          <span className="badge-row">
            <span className={`comparison-status ${comparison.status}`}>{comparison.status}</span>
            <span className={`severity-badge ${finding.cvss_band}`}>CVSS {finding.cvss_band}</span>
            {knownExploited ? <span className="severity-badge critical">Known exploited</span> : null}
          </span>
        </div>
        <p className="muted">{finding.ecosystem} · {finding.dependency_scope} dependency · {humanize(finding.source_consensus)} evidence.</p>
        {previousFinding && comparison.changed_fields.length > 0 ? <p><strong>Evidence updated:</strong> {comparison.changed_fields.map(humanize).join(", ")}</p> : null}
        {nvdEvidence.length > 0 ? (
          <p><strong>NVD CVE evidence:</strong> {nvdEvidence.map((evidence) => evidence.cve_id).join(", ")}. {cpeIdentityCorroborated ? "A reviewed CPE mapping corroborates package identity; OSV still establishes affected versions." : "CPE records remain deliberately unmapped."}</p>
        ) : null}
        {finding.fixed_versions.length > 0 ? <p><strong>Published fixes:</strong> {finding.fixed_versions.join(", ")}</p> : null}
        <p><strong>Recommendation:</strong> {finding.recommendation}</p>
      </article>
    </li>
  );
}

function CoverageComparison({ coverage }: { coverage: NonNullable<ProjectAnalysisComparisonResponse["coverage_comparison"]> }) {
  const status = coverage.status === "equivalent"
    ? "Recorded analysis coverage matches. Source-byte retention is shown separately and does not change what was analyzed."
    : coverage.status === "changed"
      ? "Recorded analysis coverage changed. Inspectra does not classify findings as resolved or new for this pair."
      : "A retained coverage summary is missing. Inspectra does not classify findings as resolved or new for this pair.";

  return (
    <section className="comparison-coverage" aria-labelledby="comparison-coverage-heading">
      <h3 id="comparison-coverage-heading">Recorded analysis coverage</h3>
      <p className="muted" role="status">{status}</p>
      {coverage.changed_metrics.length > 0 ? (
        <p className="query-warning"><strong>Changed:</strong> {coverage.changed_metrics.map(coverageMetricLabel).join(", ")}</p>
      ) : null}
      <div className="comparison-coverage-grid">
        <CoverageSnapshot label="Baseline" coverage={coverage.base} />
        <CoverageSnapshot label="Comparison" coverage={coverage.target} />
      </div>
    </section>
  );
}

function CoverageSnapshot({ label, coverage }: { label: string; coverage: ProjectAnalysisCoverage }) {
  const reachedLimit = coverage.limitations.includes("analysis_limit_reached") ? "Reached" : "Not reported";
  return (
    <section className="comparison-coverage-card" aria-label={`${label} analysis coverage`}>
      <h4>{label}</h4>
      <dl className="summary-list">
        <dt>Manifests parsed</dt>
        <dd>{coverage.supported_manifests_parsed} of {coverage.supported_manifests_found}</dd>
        <dt>Lockfiles parsed</dt>
        <dd>{coverage.lockfiles_parsed} of {coverage.lockfiles_detected}</dd>
        <dt>Dependencies counted</dt>
        <dd>{coverage.total_dependencies}</dd>
        <dt>Analysis limit</dt>
        <dd>{reachedLimit}</dd>
        <dt>Source bytes</dt>
        <dd>{coverage.source_retained ? "Retained" : "No longer retained after analysis"}</dd>
      </dl>
    </section>
  );
}

function ComparisonResult({ result, onRequestNewSnapshot, sourceUpdateLabel }: { result: ProjectAnalysisComparisonResponse; onRequestNewSnapshot: () => void; sourceUpdateLabel: string }) {
  return (
    <>
      <div className="project-comparison-summary" aria-label="Comparison summary">
        <ComparisonMetric label="New" value={result.summary.new} />
        <ComparisonMetric label="Resolved" value={result.summary.resolved} />
        <ComparisonMetric label="Persistent" value={result.summary.persistent} />
      </div>
      {comparisonGroups.map((group) => {
        const findings = result.comparisons.filter((comparison) => comparison.status === group.status);
        return (
          <section key={group.status} className={`comparison-group ${group.status}`} aria-label={group.label}>
            <h3>{group.label} <span className="subtle-id">{findings.length}</span></h3>
            {findings.length === 0 ? <p className="empty-state">{group.empty}</p> : (
              <ol className="project-finding-list">
                {findings.map((comparison) => <ComparisonFinding key={`${comparison.status}:${comparison.finding.id}`} comparison={comparison} onRequestNewSnapshot={onRequestNewSnapshot} sourceUpdateLabel={sourceUpdateLabel} />)}
              </ol>
            )}
          </section>
        );
      })}
    </>
  );
}

function ComparisonMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className={`project-comparison-metric ${label.toLocaleLowerCase()}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ComparisonFinding({ comparison, onRequestNewSnapshot, sourceUpdateLabel }: { comparison: ProjectFindingComparison; onRequestNewSnapshot: () => void; sourceUpdateLabel: string }) {
  const { finding, previous_finding: previousFinding } = comparison;
  const location = formatLocation(finding);
  return (
    <li className="project-finding-card">
      <details>
        <summary className="project-finding-toggle">
          <span>
            <strong>{finding.title}</strong>
            <span className="subtle-id">{finding.rule_id}</span>
          </span>
          <span className="badge-row">
            <span className={`comparison-status ${comparison.status}`}>{comparison.status}</span>
            {previousFinding && previousFinding.severity !== finding.severity ? (
              <span className="severity-change">{previousFinding.severity} → {finding.severity}</span>
            ) : null}
            <span className={`finding-badge ${finding.severity}`}>{finding.severity}</span>
            {comparison.lifecycle ? (
              <span className={`finding-status-badge ${comparison.lifecycle.current_status}`}>
                {findingStatusLabel(comparison.lifecycle.current_status)}
              </span>
            ) : null}
          </span>
        </summary>
        <div className="project-finding-detail">
          <dl className="summary-list">
            <dt>Location</dt>
            <dd className="mono">{location}</dd>
            <dt>Correlation ID</dt>
            <dd className="mono">{finding.id}</dd>
            <dt>Finding workflow</dt>
            <dd>{comparison.lifecycle ? findingStatusLabel(comparison.lifecycle.current_status) : "Open — not yet triaged"}</dd>
            <dt>Assigned to</dt>
            <dd>{comparison.lifecycle?.current_decision?.assignee_username ?? "Unassigned"}</dd>
          </dl>
          {comparison.lifecycle?.current_decision ? (
            <p><strong>Latest decision:</strong> {comparison.lifecycle.current_decision.reason}</p>
          ) : null}
          {comparison.changed_fields.length > 0 ? <p><strong>Changed:</strong> {comparison.changed_fields.map(humanize).join(", ")}</p> : null}
          {previousFinding ? <p className="evidence-line"><strong>Baseline evidence:</strong> <code>{previousFinding.evidence || "Not reported"}</code></p> : null}
          <p className="evidence-line"><strong>{comparison.status === "resolved" ? "Baseline evidence" : "Comparison evidence"}:</strong> <code>{finding.evidence || "Not reported"}</code></p>
          <FindingRemediationActions
            recommendation={finding.recommendation}
            references={finding.references}
            onRequestNewSnapshot={onRequestNewSnapshot}
            sourceUpdateLabel={sourceUpdateLabel}
          />
        </div>
      </details>
    </li>
  );
}

function comparisonErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 404) {
      return "This project analysis is no longer available.";
    }
    if (error.status === 400) {
      return "Choose two different completed analyses from this project.";
    }
    return error.message;
  }
  return "Unable to load this project comparison. Refresh the history and try again.";
}

function notComparableMessage(result: ProjectAnalysisComparisonResponse): string {
  if (result.coverage_comparison?.status === "changed") {
    return "These analyses have different recorded coverage or analysis limits. Review coverage before treating a finding as resolved or new.";
  }
  if (result.coverage_comparison?.status === "unknown") {
    return "One selected analysis has no retained coverage summary, so findings cannot be classified as resolved or new.";
  }
  return "These analyses cannot be compared because their recorded analyzer, profile, or execution limits differ.";
}

function coverageMetricLabel(metric: NonNullable<ProjectAnalysisComparisonResponse["coverage_comparison"]>["changed_metrics"][number]): string {
  const labels: Record<typeof metric, string> = {
    coverage_summary: "coverage summary",
    analysis_limit_reached: "analysis limit",
    total_entries_seen: "archive entries seen",
    supported_manifests_found: "supported manifests found",
    supported_manifests_parsed: "supported manifests parsed",
    unsupported_manifests_detected: "unsupported manifests detected",
    lockfiles_detected: "lockfiles detected",
    lockfiles_parsed: "lockfiles parsed",
    total_dependencies: "dependencies counted",
  };
  return labels[metric];
}

function formatAnalysisOption(analysis: JobListItem): string {
  const updated = new Date(analysis.updated_at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  return `${updated} · ${analysis.status} · ${analysisSourceReference(analysis)}`;
}

function defaultComparisonTargetId(analyses: JobListItem[], baseAnalysisId: string | null): string | null {
  return analyses.find((analysis) => analysis.id !== baseAnalysisId)?.id ?? null;
}

function formatLocation(finding: ProjectFindingComparison["finding"]): string {
  if (finding.location_status === "withheld_unsafe_path") {
    return "Withheld: unsafe path reported by analyzer";
  }
  if (!finding.location?.path) {
    return finding.location?.line ? `Line ${finding.location.line} (file not reported)` : "Not reported by this analyzer";
  }
  return `${finding.location.path}${finding.location.line ? `:${finding.location.line}` : ""}`;
}

function humanize(value: string): string {
  return value.replace(/_/g, " ");
}
