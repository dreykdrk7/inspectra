import type { ReactNode } from "react";

import { buildActiveDryRunReport, redactActiveDryRunText, type ActiveDryRunListItem } from "./activeDryRunReport";
import type { MetadataEntry } from "./pdfReport";
import type { JobRecord, JobStatus } from "./types";

export function ActiveDryRunJobReport({ job }: { job: JobRecord }) {
  const report = buildActiveDryRunReport(job);

  if (!report.isActiveDryRun) {
    return (
      <div className="result-layout">
        <p className="muted">No readable report is available for this audit type yet.</p>
        <RawJson rawJson={report.rawJson} />
      </div>
    );
  }

  return (
    <div className="report-layout">
      <section className="report-section">
        <div className="section-title-row">
          <div>
            <h3>Active network dry-run</h3>
            <p className="muted">Dry-run planning for an explicitly authorized target. No network traffic was sent.</p>
          </div>
          <div className="badge-row">
            <span className="status-pill">Active / Network</span>
            <span className="status-pill">Dry-run</span>
            <StatusBadge status={job.status} />
          </div>
        </div>
        <div className="report-summary-grid">
          {report.overview.map((entry) => (
            <div className="report-metric" key={entry.label}>
              <span>{entry.label}</span>
              <strong>{entry.value}</strong>
            </div>
          ))}
        </div>
        <dl className="summary-list">
          <MetadataRow label="Audit type" value={job.audit_type} />
          <MetadataRow label="Category" value="Active / Network" />
          <MetadataRow label="Analyzer" value={report.analyzer ?? "Not available"} />
          <MetadataRow label="Job ID" value={job.id} mono />
          <MetadataRow label="Target" value={job.target_url ? redactActiveDryRunText(job.target_url) : "Not available"} mono />
          <MetadataRow label="Created" value={formatDate(job.created_at)} />
          <MetadataRow label="Updated" value={formatDate(job.updated_at)} />
        </dl>
      </section>

      <div className="alert" role="status">
        No network traffic was sent. Planned checks are preview records only and require human review.
      </div>

      <div className="query-warning" role="status">
        {statusMessage(job.status, report.isSparse, report.allowed)}
      </div>

      <div className="report-grid">
        <ReportSection title="Target Summary">
          <MetadataList entries={report.target} empty="No target summary was returned." monoValues />
        </ReportSection>
        <ReportSection title="Authorization Summary">
          <MetadataList entries={report.authorization} empty="No authorization summary was returned." />
        </ReportSection>
      </div>

      <div className="report-grid">
        <ReportSection title="Policy Decision">
          <MetadataList entries={report.policy} empty="No policy decision was returned." />
        </ReportSection>
        <ReportSection title="Limits">
          <MetadataList entries={report.limits} empty="No dry-run limits were returned." />
        </ReportSection>
      </div>

      <ListSection title="Planned Checks" items={report.plannedChecks} empty="No planned checks were returned." />
      <ListSection title="Blocked Reasons" items={report.blockedReasons} empty="No blocked reasons were returned." />
      <ListSection title="Audit Log" items={report.auditLog} empty="No audit log entries were returned." />

      <ReportSection title="Errors">
        {report.errors.length === 0 ? (
          <p className="empty-state">No controlled errors were reported.</p>
        ) : (
          <ul className="warning-list">
            {report.errors.map((error, index) => (
              <li key={`${error}-${index}`}>{error}</li>
            ))}
          </ul>
        )}
      </ReportSection>

      <RawJson rawJson={report.rawJson} />
    </div>
  );
}

function ReportSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="report-section">
      <h3>{title}</h3>
      {children}
    </section>
  );
}

function MetadataList({
  entries,
  empty,
  monoValues = false
}: {
  entries: MetadataEntry[];
  empty: string;
  monoValues?: boolean;
}) {
  if (entries.length === 0) {
    return <p className="empty-state">{empty}</p>;
  }
  return (
    <dl className="summary-list">
      {entries.map((entry) => (
        <MetadataRow key={entry.label} label={entry.label} value={entry.value} mono={monoValues} />
      ))}
    </dl>
  );
}

function ListSection({ title, items, empty }: { title: string; items: ActiveDryRunListItem[]; empty: string }) {
  return (
    <ReportSection title={title}>
      {items.length === 0 ? (
        <p className="empty-state">{empty}</p>
      ) : (
        <div className="tool-list">
          {items.map((item, index) => (
            <article className="tool-card" key={`${item.title}-${index}`}>
              <div className="tool-card-header">
                <strong>{item.title}</strong>
              </div>
              <MetadataList entries={item.entries} empty="No details returned." />
            </article>
          ))}
        </div>
      )}
    </ReportSection>
  );
}

function MetadataRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <>
      <dt>{label}</dt>
      <dd className={mono ? "mono" : undefined}>{value}</dd>
    </>
  );
}

function StatusBadge({ status }: { status: JobStatus }) {
  return <span className={`status-pill ${status}`}>{status}</span>;
}

function RawJson({ rawJson }: { rawJson: string }) {
  return (
    <section className="report-section">
      <h3>Redacted Raw JSON</h3>
      <p className="muted">Sensitive-looking target values are redacted in results, exports, and raw JSON. Redacted values use [REDACTED].</p>
      <details className="raw-json">
        <summary>Show redacted payload</summary>
        <pre>{rawJson}</pre>
      </details>
    </section>
  );
}

function statusMessage(status: JobStatus, isSparse: boolean, allowed: boolean | null): string {
  if (status === "queued") {
    return "Job queued. The dry-run plan will appear when processing starts.";
  }
  if (status === "running") {
    return "Dry-run planning is running. No network traffic is sent.";
  }
  if (status === "failed") {
    return "The job failed in a controlled state. Review redacted errors below.";
  }
  if (isSparse) {
    return "Some result fields are unavailable; showing available redacted data.";
  }
  if (allowed === false) {
    return "Target blocked by safety policy. Review the blocked reasons below.";
  }
  return "Dry-run plan completed. Planned checks were not executed.";
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}
