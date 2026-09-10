import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, FolderOpen, RefreshCw, Search, ShieldAlert } from "lucide-react";

import { ApiError, api } from "./api";
import type {
  ProjectPortfolioItem,
  ProjectPortfolioPage,
  ProjectPortfolioPriority,
  ProjectPortfolioPublicState,
  ProjectPortfolioSourceType,
  ProjectSummary,
} from "./types";


type ProjectPortfolioPanelProps = {
  onOpenProject: (project: ProjectSummary) => void;
};

type Filters = {
  search: string;
  priority: "all" | ProjectPortfolioPriority;
  severity: "all" | "critical" | "high" | "medium" | "low";
  sourceType: "all" | ProjectPortfolioSourceType;
  coverage: "all" | "complete" | "partial" | "unknown" | "lost";
  publicIntelligence: "all" | ProjectPortfolioPublicState;
  baseline: "all" | "available" | "missing";
  responsibility: "all" | "assigned" | "multiple" | "unassigned";
  sort: "priority" | "name" | "updated";
};

const defaultFilters: Filters = {
  search: "",
  priority: "all",
  severity: "all",
  sourceType: "all",
  coverage: "all",
  publicIntelligence: "all",
  baseline: "all",
  responsibility: "all",
  sort: "priority",
};

const reasonLabels: Record<ProjectPortfolioItem["priority_reasons"][number], string> = {
  known_exploited: "Known exploitation (KEV)",
  critical_findings: "Critical findings",
  latest_analysis_failed: "Latest analysis failed",
  coverage_lost: "Coverage decreased",
  high_findings: "High findings",
  new_findings: "New findings",
  analysis_incomplete: "Incomplete evidence",
  public_intelligence_stale: "Public data stale",
  public_intelligence_failed: "Public source degraded",
  exception_review_due: "Exception review due",
  pending_triage: "Pending triage",
  no_baseline: "No baseline",
  no_recent_analysis: "No recent analysis",
  no_completed_analysis: "No completed analysis",
};

export function ProjectPortfolioPanel({ onOpenProject }: ProjectPortfolioPanelProps) {
  const [filters, setFilters] = useState<Filters>(defaultFilters);
  const [appliedFilters, setAppliedFilters] = useState<Filters>(defaultFilters);
  const [page, setPage] = useState<ProjectPortfolioPage | null>(null);
  const [items, setItems] = useState<ProjectPortfolioItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const regionRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let disposed = false;
    setLoading(true);
    setError(null);
    void loadPortfolio(appliedFilters)
      .then((result) => {
        if (disposed) return;
        setPage(result);
        setItems(result.items);
      })
      .catch((failure) => {
        if (!disposed) setError(portfolioErrorMessage(failure));
      })
      .finally(() => {
        if (!disposed) setLoading(false);
      });
    return () => {
      disposed = true;
    };
  }, [appliedFilters]);

  const resultDescription = useMemo(() => {
    if (loading) return "Loading the project portfolio.";
    if (error) return error;
    if (!page) return "Portfolio is unavailable.";
    return `${items.length} of ${page.total_count} matching projects loaded. ${page.summary.urgent_projects} urgent and ${page.summary.high_priority_projects} high priority.`;
  }, [error, items.length, loading, page]);

  function submit(event: FormEvent) {
    event.preventDefault();
    setAppliedFilters({ ...filters, search: filters.search.trim() });
  }

  function reset() {
    setFilters(defaultFilters);
    setAppliedFilters(defaultFilters);
  }

  async function loadMore() {
    if (!page?.next_cursor || loadingMore) return;
    setLoadingMore(true);
    setError(null);
    try {
      const next = await loadPortfolio(appliedFilters, page.next_cursor);
      setItems((current) => {
        const known = new Set(current.map((item) => item.project.id));
        return [...current, ...next.items.filter((item) => !known.has(item.project.id))];
      });
      setPage(next);
      window.requestAnimationFrame(() => regionRef.current?.focus());
    } catch (failure) {
      setError(portfolioErrorMessage(failure));
      window.requestAnimationFrame(() => regionRef.current?.focus());
    } finally {
      setLoadingMore(false);
    }
  }

  return (
    <section className="project-portfolio" aria-labelledby="project-portfolio-title" aria-busy={loading || loadingMore}>
      <div className="project-portfolio-heading">
        <div>
          <p className="eyebrow">Continuous risk</p>
          <h2 id="project-portfolio-title"><ShieldAlert size={19} aria-hidden="true" /> Project portfolio</h2>
          <p className="muted">
            Priorities use visible signals, never an opaque score. Partial or incomparable evidence cannot appear improved or clean.
          </p>
        </div>
        <button className="secondary-button" type="button" onClick={() => setAppliedFilters({ ...appliedFilters })} disabled={loading}>
          <RefreshCw size={16} aria-hidden="true" /> Refresh
        </button>
      </div>

      <form className="project-portfolio-filters" onSubmit={submit}>
        <label className="portfolio-search-field">
          <span>Project name prefix</span>
          <input
            value={filters.search}
            maxLength={120}
            onChange={(event) => setFilters((current) => ({ ...current, search: event.target.value }))}
            placeholder="Start of project name"
          />
        </label>
        <PortfolioSelect label="Priority" value={filters.priority} onChange={(value) => setFilters((current) => ({ ...current, priority: value as Filters["priority"] }))} options={[
          ["all", "All priorities"], ["urgent", "Urgent"], ["high", "High"], ["review", "Review"], ["monitor", "Monitor"],
        ]} />
        <PortfolioSelect label="Severity present" value={filters.severity} onChange={(value) => setFilters((current) => ({ ...current, severity: value as Filters["severity"] }))} options={[
          ["all", "Any severity"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"],
        ]} />
        <PortfolioSelect label="Source" value={filters.sourceType} onChange={(value) => setFilters((current) => ({ ...current, sourceType: value as Filters["sourceType"] }))} options={[
          ["all", "All sources"], ["archive", "Uploaded archive"], ["git_or_ci", "Git/CLI or CI"], ["sbom", "SBOM"],
        ]} />
        <PortfolioSelect label="Coverage" value={filters.coverage} onChange={(value) => setFilters((current) => ({ ...current, coverage: value as Filters["coverage"] }))} options={[
          ["all", "Any coverage"], ["complete", "Complete"], ["partial", "Partial"], ["lost", "Coverage lost"], ["unknown", "Unknown"],
        ]} />
        <PortfolioSelect label="Public intelligence" value={filters.publicIntelligence} onChange={(value) => setFilters((current) => ({ ...current, publicIntelligence: value as Filters["publicIntelligence"] }))} options={[
          ["all", "Any source state"], ["fresh", "Fresh"], ["stale", "Stale"], ["partial", "Partial"], ["failed", "Failed"], ["disabled", "Disabled"], ["not_requested", "Not requested"],
        ]} />
        <PortfolioSelect label="Baseline" value={filters.baseline} onChange={(value) => setFilters((current) => ({ ...current, baseline: value as Filters["baseline"] }))} options={[
          ["all", "Any baseline"], ["available", "Baseline available"], ["missing", "No baseline"],
        ]} />
        <PortfolioSelect label="Finding assignment" value={filters.responsibility} onChange={(value) => setFilters((current) => ({ ...current, responsibility: value as Filters["responsibility"] }))} options={[
          ["all", "Any assignment"], ["assigned", "One assignee"], ["multiple", "Multiple assignees"], ["unassigned", "Unassigned"],
        ]} />
        <PortfolioSelect label="Order" value={filters.sort} onChange={(value) => setFilters((current) => ({ ...current, sort: value as Filters["sort"] }))} options={[
          ["priority", "Explainable priority"], ["name", "Project name"], ["updated", "Recently updated"],
        ]} />
        <div className="project-portfolio-filter-actions">
          <button type="submit" disabled={loading}><Search size={16} aria-hidden="true" /> Apply</button>
          <button className="secondary-button" type="button" onClick={reset} disabled={loading}>Reset</button>
        </div>
      </form>

      <p className="sr-only" role="status" aria-live="polite">{resultDescription}</p>
      {error ? <p className="error-text" role="alert">{error}</p> : null}
      {loading && items.length === 0 ? <p className="muted" role="status">Building the owner-scoped portfolio…</p> : null}
      {!loading && page && page.summary.total_projects === 0 ? (
        <div className="empty-state">
          <strong>No projects yet</strong>
          <p>Create an authorized archive or SBOM project to begin continuous risk tracking.</p>
        </div>
      ) : null}
      {!loading && page && page.summary.total_projects > 0 && page.total_count === 0 ? (
        <div className="empty-state">
          <strong>No projects match these filters</strong>
          <p>Reset or broaden the closed filters. Existing projects and evidence were not changed.</p>
        </div>
      ) : null}

      {page && page.summary.total_projects > 0 ? (
        <>
          <div className="project-portfolio-summary" aria-label="Portfolio summary">
            <PortfolioMetric label="Projects" value={page.summary.filtered_projects} detail={`of ${page.summary.total_projects}`} />
            <PortfolioMetric label="Urgent" value={page.summary.urgent_projects} />
            <PortfolioMetric label="High priority" value={page.summary.high_priority_projects} />
            <PortfolioMetric label="KEV" value={page.summary.projects_with_kev} detail="separate from CVSS" />
            <PortfolioMetric label="Partial data" value={page.summary.projects_with_partial_data} />
            <PortfolioMetric label="Pending actions" value={page.summary.pending_actions} />
          </div>
          {page.limitations.map((limitation) => <p className="query-warning" key={limitation}>{limitation}</p>)}
          <div ref={regionRef} className="project-portfolio-results" tabIndex={-1} aria-label="Project portfolio results">
            <ul className="project-portfolio-list">
              {items.map((item) => (
                <li className={`project-portfolio-card priority-${item.priority}`} key={item.project.id}>
                  <div className="project-portfolio-card-heading">
                    <div>
                      <span className={`status-pill portfolio-${item.priority}`}>{priorityLabel(item.priority)}</span>
                      <h3>{item.project.name}</h3>
                      <p className="muted">{sourceLabel(item)} · {operationalLabel(item.operational_state)} · Updated {formatDate(item.project.updated_at)}</p>
                    </div>
                    <button type="button" onClick={() => onOpenProject({ project: item.project, latest_job: item.latest_job })}>
                      <FolderOpen size={16} aria-hidden="true" /> Open project
                    </button>
                  </div>

                  <dl className="project-portfolio-facts">
                    <PortfolioFact label="Risk" value={`${item.finding_counts.critical} critical · ${item.finding_counts.high} high · ${item.finding_counts.medium} medium · ${item.finding_counts.low} low`} />
                    <PortfolioFact label="KEV" value={`${item.finding_counts.kev} known exploited`} />
                    <PortfolioFact label="Changes" value={changeLabel(item)} />
                    <PortfolioFact label="Coverage" value={coverageLabel(item)} />
                    <PortfolioFact label="Public data" value={publicStateLabel(item.public_intelligence_state)} />
                    <PortfolioFact label="Project owner" value={projectResponsibilityLabel(item)} />
                    <PortfolioFact label="Finding assignees" value={responsibilityLabel(item)} />
                    <PortfolioFact label="Actions" value={`${item.pending_actions} pending · ${item.exceptions_due} reviews due · ${item.exceptions_overdue} overdue`} />
                    <PortfolioFact label="Baseline" value={item.project.baseline_analysis_id ? "Available" : "Missing"} />
                  </dl>

                  {item.priority_reasons.length ? (
                    <div className="project-portfolio-reasons">
                      <strong>Why this priority</strong>
                      <ul>{item.priority_reasons.map((reason) => <li key={reason}>{reasonLabels[reason]}</li>)}</ul>
                    </div>
                  ) : <p className="muted">No current priority signal. Continue monitoring after comparable analyses.</p>}
                  {item.limitations.length ? (
                    <div className="portfolio-limitations" role="note">
                      <AlertTriangle size={16} aria-hidden="true" />
                      <div><strong>Evidence limits</strong><ul>{item.limitations.map((value) => <li key={value}>{value}</li>)}</ul></div>
                    </div>
                  ) : null}
                </li>
              ))}
            </ul>
            {page.has_more ? (
              <button type="button" className="secondary-button portfolio-load-more" onClick={() => void loadMore()} disabled={loadingMore}>
                {loadingMore ? "Loading…" : `Load more (${items.length} of ${page.total_count})`}
              </button>
            ) : items.length > 0 ? <p className="muted portfolio-end">All {page.total_count} matching projects are loaded.</p> : null}
          </div>
        </>
      ) : null}
    </section>
  );
}

function PortfolioSelect({ label, value, options, onChange }: { label: string; value: string; options: Array<[string, string]>; onChange: (value: string) => void }) {
  return (
    <label>
      <span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map(([option, text]) => <option value={option} key={option}>{text}</option>)}
      </select>
    </label>
  );
}

function PortfolioMetric({ label, value, detail }: { label: string; value: number; detail?: string }) {
  return <div><span>{label}</span><strong>{value}</strong>{detail ? <small>{detail}</small> : null}</div>;
}

function PortfolioFact({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>;
}

function priorityLabel(priority: ProjectPortfolioPriority): string {
  return ({ urgent: "Urgent", high: "High priority", review: "Review", monitor: "Monitor" })[priority];
}

function operationalLabel(state: ProjectPortfolioItem["operational_state"]): string {
  return state === "no_analysis" ? "No analysis" : state.replace(/_/g, " ");
}

function sourceLabel(item: ProjectPortfolioItem): string {
  if (item.source_type === "sbom") return "Normalized SBOM";
  if (item.source_type_detail === "attested_git_cli") return "Git / CLI (attested)";
  if (item.source_type_detail === "attested_ci") return "CI automation (attested)";
  if (item.source_type === "git_or_ci") return "Legacy Git / CI (unverified channel)";
  return "Uploaded archive";
}

function coverageLabel(item: ProjectPortfolioItem): string {
  const coverage = item.coverage.current;
  const detail = coverage ? `${coverage.supported_manifests_parsed}/${coverage.supported_manifests_found} manifests · ${coverage.lockfiles_parsed}/${coverage.lockfiles_detected} locks` : "no denominator";
  return `${item.coverage.state} · ${detail}`;
}

function changeLabel(item: ProjectPortfolioItem): string {
  if (item.changes.state === "missing_baseline") return "No baseline; changes not classified";
  if (item.changes.state === "baseline_is_latest") return "Baseline is latest; awaiting a new comparable run";
  if (item.changes.state === "not_comparable") return "Not comparable; no improvement inferred";
  return `${item.changes.new + item.changes.public_new} new · ${item.changes.persistent + item.changes.public_persistent} persistent · ${item.changes.resolved + item.changes.public_resolved} resolved`;
}

function responsibilityLabel(item: ProjectPortfolioItem): string {
  const assignment = item.responsibility;
  if (assignment.state === "unassigned") return assignment.inactive_assignment_count ? "Unassigned; previous member unavailable" : "Unassigned";
  const names = assignment.active_assignees.join(", ");
  return assignment.truncated ? `${names} and ${assignment.active_assignee_count - assignment.active_assignees.length} more` : names;
}

function projectResponsibilityLabel(item: ProjectPortfolioItem): string {
  const responsibility = item.project_responsibility;
  if (responsibility.state === "unassigned_attention") return "Reassignment required";
  if (responsibility.state === "assigned") return responsibility.responsible_username ?? "Assigned member";
  return "Unassigned";
}

function publicStateLabel(state: ProjectPortfolioPublicState): string {
  return ({
    fresh: "Fresh",
    stale: "Stale",
    partial: "Partial",
    failed: "Unavailable",
    disabled: "Egress disabled",
    not_requested: "Not requested",
  })[state];
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "unknown" : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

async function loadPortfolio(filters: Filters, cursor?: string | null): Promise<ProjectPortfolioPage> {
  return api.searchProjectPortfolio({
    pageSize: 24,
    cursor,
    search: filters.search || undefined,
    searchMode: "prefix",
    priority: filters.priority === "all" ? undefined : filters.priority,
    severity: filters.severity === "all" ? undefined : filters.severity,
    sourceType: filters.sourceType === "all" ? undefined : filters.sourceType,
    coverage: filters.coverage === "all" ? undefined : filters.coverage,
    publicIntelligence: filters.publicIntelligence === "all" ? undefined : filters.publicIntelligence,
    baseline: filters.baseline === "all" ? undefined : filters.baseline,
    responsibility: filters.responsibility === "all" ? undefined : filters.responsibility,
    sort: filters.sort,
  });
}

function portfolioErrorMessage(error: unknown): string {
  if (error instanceof ApiError && error.status === 409) {
    return "The portfolio changed while you were paging. Refresh to start a coherent snapshot; already loaded projects remain visible.";
  }
  if (error instanceof ApiError && error.status === 400) {
    return "The portfolio page expired or its filters changed. Apply the filters again from the first page.";
  }
  return "Unable to load the project portfolio. Existing project data was not changed; check service health and try again.";
}
