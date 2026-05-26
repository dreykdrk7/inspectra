import type { ReactNode } from "react";

import { buildWebAuditReport, type WebFinding } from "./webReport";
import type { MetadataEntry } from "./pdfReport";
import type { JobRecord, JobStatus } from "./types";

export function WebJobReport({ job }: { job: JobRecord }) {
  const report = buildWebAuditReport(job);

  if (!report.isWebAudit) {
    return (
      <div className="result-layout">
        <p className="muted">No readable report is available for this audit type yet.</p>
        <RawJson job={job} />
      </div>
    );
  }

  return (
    <div className="report-layout">
      <section className="report-section">
        <div className="section-title-row">
          <h3>General Summary</h3>
          <div className="badge-row">
            <StatusBadge status={job.status} />
          </div>
        </div>
        <dl className="summary-list">
          <MetadataRow label="Audit type" value={job.audit_type} />
          <MetadataRow label="Analyzer" value={report.analyzer ?? "Not available"} />
          <MetadataRow label="Job ID" value={job.id} mono />
          <MetadataRow label="Target URL" value={job.target_url ?? "Not available"} mono />
          <MetadataRow label="Created" value={formatDate(job.created_at)} />
          <MetadataRow label="Updated" value={formatDate(job.updated_at)} />
          <MetadataRow label="Completed" value={report.completedAt ? formatDate(report.completedAt) : "Not completed"} />
        </dl>
      </section>

      <div className="report-grid">
        <ReportSection title="Target">
          <MetadataList entries={report.target} empty="No target metadata returned yet." monoValues />
        </ReportSection>
        <ReportSection title="HTTP">
          <MetadataList entries={report.http} empty="No HTTP response returned yet." />
        </ReportSection>
      </div>

      <ReportSection title="Security Headers">
        {report.securityHeaders.length === 0 ? (
          <p className="empty-state">No security header data returned.</p>
        ) : (
          <div className="tool-list">
            {report.securityHeaders.map((header) => (
              <article className="tool-card" key={header.name}>
                <div className="tool-card-header">
                  <strong>{header.name}</strong>
                  <span className={`tool-badge ${header.present ? "ok" : "not_run"}`}>{header.present ? "present" : "missing"}</span>
                </div>
                {header.value ? <p className="mono evidence-line">{header.value}</p> : null}
              </article>
            ))}
          </div>
        )}
      </ReportSection>

      <ReportSection title="Cookies">
        {report.cookies.length === 0 ? (
          <p className="empty-state">No Set-Cookie headers observed.</p>
        ) : (
          <div className="dependency-list">
            {report.cookies.map((cookie, index) => (
              <div className="dependency-row" key={`${cookie.name}-${index}`}>
                <strong>{cookie.name}</strong>
                <span>{cookie.samesite ? `SameSite=${cookie.samesite}` : "SameSite not set"}</span>
                <span className="muted">{[cookie.secure ? "Secure" : "no Secure", cookie.httponly ? "HttpOnly" : "no HttpOnly"].join(", ")}</span>
                {cookie.valueRedacted ? <span className="muted">value redacted{cookie.valueLength !== null ? ` (${cookie.valueLength} chars)` : ""}</span> : null}
              </div>
            ))}
          </div>
        )}
      </ReportSection>

      <div className="report-grid">
        <ReportSection title="TLS">
          <MetadataList entries={report.tls} empty="No TLS data returned." />
        </ReportSection>
        <ReportSection title="robots.txt">
          <MetadataList entries={report.robotsTxt} empty="robots.txt was not checked." />
        </ReportSection>
      </div>

      <ReportSection title="security.txt">
        <MetadataList entries={report.securityTxt} empty="security.txt was not checked." />
      </ReportSection>

      <ReportSection title="Findings">
        {report.findings.length === 0 ? (
          <p className="empty-state">No informational findings reported.</p>
        ) : (
          <div className="finding-list">
            {report.findings.map((finding, index) => (
              <FindingCard finding={finding} key={`${finding.id}-${index}`} />
            ))}
          </div>
        )}
      </ReportSection>

      <ReportSection title="Errors">
        {job.error ? <p className="error-text">{job.error}</p> : null}
        {report.errors.length > 0 ? (
          <ul className="warning-list">
            {report.errors.map((error) => (
              <li key={error}>{error}</li>
            ))}
          </ul>
        ) : job.error ? null : (
          <p className="empty-state">No web audit errors reported.</p>
        )}
      </ReportSection>

      <RawJson job={job} />
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

function FindingCard({ finding }: { finding: WebFinding }) {
  return (
    <article className="tool-card">
      <div className="tool-card-header">
        <strong>{finding.title}</strong>
        <span className={`finding-badge ${finding.level}`}>{finding.level}</span>
      </div>
      {finding.description ? <p>{finding.description}</p> : null}
      {finding.evidence ? <p className="mono evidence-line">{finding.evidence}</p> : null}
      {finding.recommendation ? <p className="muted">{finding.recommendation}</p> : null}
    </article>
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

function RawJson({ job }: { job: JobRecord }) {
  return (
    <details className="raw-json">
      <summary>Raw JSON</summary>
      <pre>{JSON.stringify(job, null, 2)}</pre>
    </details>
  );
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}
