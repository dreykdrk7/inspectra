import { useEffect, useMemo, useState } from "react";
import { BarChart3, Download, RefreshCw } from "lucide-react";

import { ApiError, api } from "./api";
import type { ProjectSummary, RiskTrendMaterialization, RiskTrendProfile, RiskTrendResponse } from "./types";


type Props = {
  onOpenProject: (project: ProjectSummary) => void;
};

const profiles: Array<{ id: RiskTrendProfile; label: string; description: string }> = [
  { id: "developer", label: "Developer", description: "Prioritize actionable changes and verify fixes with comparable analyses." },
  { id: "security", label: "Security", description: "Review KEV, coverage, exceptions and retained risk evidence." },
  { id: "executive", label: "Executive", description: "See portfolio direction, priority projects and evidence gaps without an opaque score." },
];

export function ProjectRiskTrendsPanel({ onOpenProject }: Props) {
  const [result, setResult] = useState<RiskTrendResponse | null>(null);
  const [materialization, setMaterialization] = useState<RiskTrendMaterialization | null>(null);
  const [periodDays, setPeriodDays] = useState<30 | 90 | 180>(90);
  const [bucketDays, setBucketDays] = useState<7 | 30>(7);
  const [profile, setProfile] = useState<RiskTrendProfile>("developer");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exportConfirmed, setExportConfirmed] = useState(false);
  const [exporting, setExporting] = useState<"json" | "csv" | null>(null);
  const [exportNotice, setExportNotice] = useState<string | null>(null);
  const [pollAttempt, setPollAttempt] = useState(0);

  async function load(
    nextPeriod = periodDays,
    nextBucket = bucketDays,
    options: { force?: boolean; silent?: boolean } = {},
  ) {
    if (!options.silent) {
      setLoading(true);
      setPollAttempt(0);
    }
    setError(null);
    try {
      const view = options.force
        ? await api.refreshProjectRiskTrends(nextPeriod, nextBucket)
        : await api.getProjectRiskTrends(nextPeriod, nextBucket);
      setMaterialization(view.materialization);
      setResult(view.trend);
    } catch (cause) {
      setError(cause instanceof ApiError && cause.status === 409
        ? "This portfolio exceeds the current safe trend limit. Narrow retention before retrying."
        : "Risk trends are temporarily unavailable. Existing project evidence remains unchanged; try again.");
    } finally {
      if (!options.silent) setLoading(false);
    }
  }

  useEffect(() => { void load(90, 7); }, []);
  useEffect(() => {
    if (!materialization?.refresh_in_progress || pollAttempt >= 60) return undefined;
    const timer = window.setTimeout(() => {
      void load(periodDays, bucketDays, { silent: true }).finally(() => {
        setPollAttempt((value) => value + 1);
      });
    }, (materialization.retry_after_seconds ?? 1) * 1000);
    return () => window.clearTimeout(timer);
  }, [materialization?.refresh_in_progress, materialization?.requested_at, materialization?.started_at, periodDays, bucketDays, pollAttempt]);

  async function download(format: "json" | "csv") {
    if (!exportConfirmed) return;
    setExporting(format);
    setExportNotice(null);
    try {
      const report = await api.exportProjectRiskTrends(periodDays, bucketDays, profile, format);
      const url = URL.createObjectURL(report.blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = report.filename;
      link.click();
      URL.revokeObjectURL(url);
      setExportNotice(`Downloaded ${format.toUpperCase()} for the ${profile} view. SHA-256 ${report.digest || "not returned"}.`);
    } catch {
      setExportNotice("The report could not be generated. No partial download was kept; try again.");
    } finally {
      setExporting(null);
    }
  }

  const maxChange = useMemo(() => Math.max(1, ...(result?.buckets.map((bucket) =>
    bucket.changes.local_new + bucket.changes.public_new + bucket.changes.local_resolved + bucket.changes.public_resolved
  ) ?? [1])), [result]);

  return (
    <section className="panel risk-trends-panel" aria-labelledby="risk-trends-title">
      <div className="panel-header">
        <div>
          <h2 id="risk-trends-title"><BarChart3 size={18} aria-hidden="true" /> Risk trends</h2>
          <p className="muted">One retained-evidence projection, presented for three team profiles. Every change declares its period, denominator and exclusions.</p>
        </div>
        <button className="secondary-button" onClick={() => void load(periodDays, bucketDays, { force: true })} disabled={loading || materialization?.refresh_in_progress}>
          <RefreshCw size={16} aria-hidden="true" /> {loading ? "Loading" : materialization?.state === "failed" ? "Retry refresh" : "Refresh"}
        </button>
      </div>

      <div className="trend-profile-tabs" role="tablist" aria-label="Risk trend audience">
        {profiles.map((item) => (
          <button key={item.id} type="button" role="tab" aria-selected={profile === item.id} className={profile === item.id ? "active" : ""} onClick={() => setProfile(item.id)}>
            {item.label}
          </button>
        ))}
      </div>
      <p className="trend-profile-copy">{profiles.find((item) => item.id === profile)?.description}</p>

      <form className="trend-controls" onSubmit={(event) => { event.preventDefault(); void load(); }}>
        <label><span>Period</span><select value={periodDays} onChange={(event) => setPeriodDays(Number(event.target.value) as 30 | 90 | 180)}><option value={30}>30 days</option><option value={90}>90 days</option><option value={180}>180 days</option></select></label>
        <label><span>Bucket</span><select value={bucketDays} onChange={(event) => setBucketDays(Number(event.target.value) as 7 | 30)}><option value={7}>7 days</option><option value={30}>30 days</option></select></label>
        <button className="primary-button" type="submit" disabled={loading}>Apply period</button>
      </form>

      {error ? <p className="error-text" role="alert">{error}</p> : null}
      {materialization ? <MaterializationNotice value={materialization} /> : null}
      {materialization?.refresh_in_progress && pollAttempt >= 60 ? <p className="error-text" role="alert">Trend refresh is taking longer than expected. It remains queued safely; refresh this view later.</p> : null}
      {loading && !result ? <p className="muted" role="status">Checking the bounded trend projection…</p> : null}
      {!loading && materialization?.data_state === "unavailable" && !result ? (
        <p className="empty-state">No trend snapshot is available yet. Inspectra is rebuilding it outside this request; this page will check again automatically.</p>
      ) : null}
      {result ? (
        <>
          <p className="trend-period" role="status">
            {formatDate(result.period_starts_at)}–{formatDate(result.period_ends_at)} · {result.summary.projects_in_scope} projects · {result.summary.completed_analyses_in_period} completed analyses · {result.summary.excluded_transitions} excluded transitions
          </p>
          {result.summary.completed_analyses_in_period === 0 ? (
            <p className="empty-state">No completed project analyses fall inside this period. Extend the period or run an authorized project analysis.</p>
          ) : (
            <ProfileMetrics profile={profile} result={result} />
          )}

          <section aria-labelledby="risk-change-history">
            <h3 id="risk-change-history">Comparable change history</h3>
            <p className="muted">Green means findings absent from a later comparable analysis; it does not prove deployment or exposure. Red means newly observed retained evidence.</p>
            <div className="trend-bars" role="list" aria-label="New and resolved findings by period">
              {result.buckets.map((bucket) => {
                const introduced = bucket.changes.local_new + bucket.changes.public_new;
                const resolved = bucket.changes.local_resolved + bucket.changes.public_resolved;
                return (
                  <div className="trend-bar-row" role="listitem" key={bucket.starts_at}>
                    <span>{formatDate(bucket.starts_at)}</span>
                    <div className="trend-bar-track" role="img" aria-label={`${introduced} new and ${resolved} resolved findings; ${bucket.comparable_local_transitions} comparable local transitions and ${bucket.comparable_public_transitions} comparable public transitions`}>
                      <span className="trend-bar-new" style={{ width: `${(introduced / maxChange) * 100}%` }} />
                      <span className="trend-bar-resolved" style={{ width: `${(resolved / maxChange) * 100}%` }} />
                    </div>
                    <strong>{introduced} new · {resolved} resolved</strong>
                  </div>
                );
              })}
            </div>
          </section>

          <div className="trend-breakdowns">
            <TrendDimension title="By ecosystem" items={result.ecosystems} empty="No comparable public-vulnerability ecosystem evidence in this period." />
            <TrendDimension title="By source type" items={result.source_types} empty="No retained analysis source evidence in this period." />
          </div>

          <section aria-labelledby="trend-priority-projects">
            <h3 id="trend-priority-projects">Priority projects now</h3>
            {result.priority_projects.length === 0 ? <p className="empty-state">No projects currently require portfolio prioritization.</p> : (
              <div className="trend-priority-list">
                {result.priority_projects.map((item) => (
                  <article key={item.project.id}>
                    <div><strong>{item.project.name}</strong><span className={`status-pill priority-${item.priority}`}>{item.priority}</span></div>
                    <p>{item.pending_actions} pending actions · {item.reasons.length ? item.reasons.join(", ").replace(/_/g, " ") : "monitor"}</p>
                    <button className="secondary-button" onClick={() => onOpenProject({ project: item.project, latest_job: null })}>Open project</button>
                  </article>
                ))}
              </div>
            )}
          </section>

          <details className="trend-methodology">
            <summary>Denominators, exclusions and limitations</summary>
            <dl>{Object.entries(result.denominators).map(([key, value]) => <div key={key}><dt>{key.replace(/_/g, " ")}</dt><dd>{value}</dd></div>)}</dl>
            {result.exclusions.length ? <ul>{result.exclusions.map((item) => <li key={item.reason}>{item.reason.replace(/_/g, " ")}: {item.count}</li>)}</ul> : <p>No excluded transitions.</p>}
            <ul>{result.limitations.map((item) => <li key={item}>{item}</li>)}</ul>
          </details>

          <div className="trend-export">
            <label className="authorization-check"><input type="checkbox" checked={exportConfirmed} onChange={(event) => setExportConfirmed(event.target.checked)} disabled={materialization?.data_state !== "current"} /><span>I confirm this export may include project names from this organization.</span></label>
            {materialization?.data_state !== "current" ? <p className="muted">Export is available only after the projection is current; stale facts are never exported as fresh.</p> : null}
            <div><button className="secondary-button" disabled={!exportConfirmed || Boolean(exporting) || materialization?.data_state !== "current"} onClick={() => void download("json")}><Download size={16} aria-hidden="true" /> {exporting === "json" ? "Generating" : "JSON"}</button><button className="secondary-button" disabled={!exportConfirmed || Boolean(exporting) || materialization?.data_state !== "current"} onClick={() => void download("csv")}><Download size={16} aria-hidden="true" /> {exporting === "csv" ? "Generating" : "CSV"}</button></div>
            {exportNotice ? <p className={exportNotice.startsWith("Downloaded") ? "success-text" : "error-text"} role="status">{exportNotice}</p> : null}
          </div>
        </>
      ) : null}
    </section>
  );
}

function MaterializationNotice({ value }: { value: RiskTrendMaterialization }) {
  const completed = value.completed_at ? ` Last completed ${formatDateTime(value.completed_at)}.` : "";
  if (value.state === "ready") {
    return <p className="trend-materialization is-ready" role="status"><strong>Trend snapshot current.</strong>{completed}</p>;
  }
  if (value.state === "failed") {
    return <p className="trend-materialization is-failed" role="alert"><strong>Trend refresh failed.</strong> Existing evidence was not changed. Retry the bounded refresh when ready.{completed}</p>;
  }
  if (value.state === "stale") {
    return <p className="trend-materialization is-stale" role="status"><strong>Showing a stale snapshot.</strong> A newer owner-scoped projection is rebuilding; figures below are partial until publication.{completed}</p>;
  }
  return <p className="trend-materialization is-rebuilding" role="status"><strong>Trend snapshot rebuilding.</strong> Work continues outside this request and the page will check again automatically.{completed}</p>;
}

function ProfileMetrics({ profile, result }: { profile: RiskTrendProfile; result: RiskTrendResponse }) {
  const coverageLost = result.buckets.reduce((total, bucket) => total + bucket.coverage_lost, 0);
  const metrics = profile === "developer" ? [
    ["Pending actions", result.summary.pending_actions],
    ["New high/critical", result.changes.critical_or_high_new],
    ["Verified resolved", result.changes.local_resolved + result.changes.public_resolved],
    ["Median to first review", duration(result.time_to_first_review)],
  ] : profile === "security" ? [
    ["Known exploited", result.summary.current_known_exploited_findings],
    ["Overdue exceptions", result.summary.overdue_exceptions],
    ["Coverage losses", coverageLost],
    ["Comparable public changes", result.summary.comparable_public_transitions],
  ] : [
    ["Projects analyzed", `${result.summary.projects_analyzed_in_period}/${result.summary.projects_in_scope}`],
    ["Without recent analysis", result.summary.projects_without_recent_analysis],
    ["Current high/critical", result.summary.current_critical_or_high_findings],
    ["Excluded transitions", result.summary.excluded_transitions],
  ];
  return <div className="trend-metrics">{metrics.map(([label, value]) => <div key={label}><span>{label}</span><strong>{value}</strong></div>)}</div>;
}

function TrendDimension({ title, items, empty }: { title: string; items: RiskTrendResponse["ecosystems"]; empty: string }) {
  return <section><h3>{title}</h3>{items.length === 0 ? <p className="empty-state">{empty}</p> : <ul>{items.map((item) => <li key={item.key}><strong>{item.key.replace(/_/g, " / ")}</strong><span>{item.current_findings} current · {item.new_findings} new · {item.resolved_findings} resolved · {item.comparable_transitions} comparable</span></li>)}</ul>}</section>;
}

function duration(value: RiskTrendResponse["time_to_first_review"]): string {
  return value.sample_count && value.median_hours !== null ? `${value.median_hours} h (${value.sample_count})` : "No sample";
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeZone: "UTC" }).format(new Date(value));
}

function formatDateTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(new Date(value));
}
