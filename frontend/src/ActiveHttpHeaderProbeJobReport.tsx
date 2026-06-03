import type { ReactNode } from "react";

import {
  buildActiveHttpHeaderProbeReport,
  redactActiveHttpHeaderProbeText,
  type ActiveHttpHeaderProbeHeader,
  type ActiveHttpHeaderProbeListItem
} from "./activeHttpHeaderProbeReport";
import type { MetadataEntry } from "./pdfReport";
import type { JobRecord, JobStatus } from "./types";

export function ActiveHttpHeaderProbeJobReport({ job }: { job: JobRecord }) {
  const report = buildActiveHttpHeaderProbeReport(job);

  if (!report.isActiveHttpHeaderProbe) {
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
            <h3>Authorized HTTP header probe</h3>
            <p className="muted">
              One authorized HTTP HEAD request to one explicit URL. Header observations are review indicators, not confirmed vulnerabilities.
            </p>
          </div>
          <div className="badge-row">
            <span className="status-pill">Active / Network</span>
            <span className="status-pill">Live HEAD request</span>
            <span className="status-pill">Body not read</span>
            <span className="status-pill">Redirects not followed</span>
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
          <MetadataRow label="Target" value={job.target_url ? redactActiveHttpHeaderProbeText(job.target_url) : "Not available"} mono />
          <MetadataRow label="Created" value={formatDate(job.created_at)} />
          <MetadataRow label="Updated" value={formatDate(job.updated_at)} />
        </dl>
      </section>

      <div className="alert" role="status">
        {requestStatusCopy(report.networkRequestsSent)}
      </div>

      <div className="query-warning" role="status">
        {statusMessage(job.status, report.isSparse, report.allowed, report.networkRequestsSent)}
      </div>

      <ReportSection title="Live Probe Scope Notice">
        <p className="muted">
          No Nmap, no port checks, no redirects, no custom headers, no auth or cookies, and no response body read. The request may be logged by
          the target.
        </p>
      </ReportSection>

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
        <ReportSection title="DNS Policy Summary">
          <MetadataList entries={report.dns} empty="No DNS policy summary was returned." />
        </ReportSection>
      </div>

      <div className="report-grid">
        <ReportSection title="Request Sent">
          <MetadataList entries={report.request} empty="No request details were returned." />
          <p className="muted">Response body was not read. Redirects were not followed.</p>
        </ReportSection>
        <ReportSection title="Limits">
          <MetadataList entries={report.limits} empty="No live probe limits were returned." />
        </ReportSection>
      </div>

      <ReportSection title="Response Headers">
        <HeaderList headers={report.responseHeaders} />
        <MetadataList entries={report.response} empty="No response metadata was returned." />
      </ReportSection>

      <ListSection title="Observations" items={report.observations} empty="No observations were returned." />
      <ListSection title="Findings" items={report.findings} empty="No findings were returned." />
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

function HeaderList({ headers }: { headers: ActiveHttpHeaderProbeHeader[] }) {
  if (headers.length === 0) {
    return <p className="empty-state">No response headers were returned.</p>;
  }
  return (
    <div className="tool-list">
      {headers.map((header, index) => (
        <article className="tool-card" key={`${header.name}-${index}`}>
          <div className="tool-card-header">
            <strong>{header.name}</strong>
          </div>
          <dl className="summary-list">
            <MetadataRow label="value" value={header.value} mono />
            <MetadataRow label="truncated" value={header.truncated === null ? "Not available" : String(header.truncated)} />
          </dl>
        </article>
      ))}
    </div>
  );
}

function ListSection({ title, items, empty }: { title: string; items: ActiveHttpHeaderProbeListItem[]; empty: string }) {
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
      <p className="muted">Sensitive-looking target and header values are redacted in results, exports, and raw JSON. Redacted values use [REDACTED].</p>
      <details className="raw-json">
        <summary>Show redacted payload</summary>
        <pre>{rawJson}</pre>
      </details>
    </section>
  );
}

function requestStatusCopy(networkRequestsSent: number | null): string {
  if ((networkRequestsSent ?? 0) > 0) {
    return "One authorized HTTP HEAD request was sent. Response body was not read. Redirects were not followed.";
  }
  return "No HTTP request was sent.";
}

function statusMessage(status: JobStatus, isSparse: boolean, allowed: boolean | null, networkRequestsSent: number | null): string {
  if (status === "queued") {
    return "Job queued. The authorized header probe result will appear when processing starts.";
  }
  if (status === "running") {
    return "Authorized HTTP header probe job is running under one-request limits.";
  }
  if (status === "failed") {
    return "The job failed in a controlled state. Review redacted errors below.";
  }
  if (isSparse) {
    return "Some result fields are unavailable; showing available redacted data.";
  }
  if (allowed === false || (networkRequestsSent ?? 0) === 0) {
    return "Target blocked or request not sent. Review policy and blocked reasons below.";
  }
  return "Authorized header probe completed. Header observations require human review.";
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}
