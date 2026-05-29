import type { ReactNode } from "react";

import { buildDjangoConfigAuditReport, redactDjangoConfigValue, type DjangoConfigFinding } from "./djangoConfigReport";
import type { MetadataEntry } from "./pdfReport";
import type { FileRecord, JobRecord, JobStatus } from "./types";

export function DjangoConfigJobReport({ job, file }: { job: JobRecord; file?: FileRecord }) {
  const report = buildDjangoConfigAuditReport(job);

  if (!report.isDjangoConfigAudit) {
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
          <MetadataRow label="Archive type" value={report.archiveType ?? "Not available"} />
          <MetadataRow label="Job ID" value={job.id} mono />
          <MetadataRow label="Source file" value={file?.original_filename ?? job.file_id ?? "Not available"} mono />
          <MetadataRow label="Created" value={formatDate(job.created_at)} />
          <MetadataRow label="Updated" value={formatDate(job.updated_at)} />
        </dl>
      </section>

      {report.truncated ? (
        <div className="alert" role="status">
          Analysis truncated by configured Django config limits. Review skipped files and rerun with a smaller archive if needed.
        </div>
      ) : null}

      {report.secretsRedactedCount > 0 ? (
        <div className="query-warning" role="status">
          Secret-like values were redacted from evidence. Inspectra does not display full SECRET_KEY, password, token, or private key values.
        </div>
      ) : null}

      <div className="report-grid">
        <ReportSection title="Summary">
          <MetadataList entries={report.summary} empty="No Django config summary returned yet." />
        </ReportSection>
        <ReportSection title="Limits">
          <MetadataList entries={report.limits} empty="No Django config limits returned yet." />
        </ReportSection>
      </div>

      <ReportSection title="Detected Files">
        {report.detectedFiles.length === 0 ? (
          <p className="empty-state">No Django-related files detected.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Path</th>
                  <th>Category</th>
                  <th>Read</th>
                  <th>Reason</th>
                  <th>Size</th>
                </tr>
              </thead>
              <tbody>
                {report.detectedFiles.map((item, index) => (
                  <tr key={`${item.path}-${index}`}>
                    <td className="mono">{item.path}</td>
                    <td>{item.category}</td>
                    <td>{item.read ? "yes" : "no"}</td>
                    <td>{item.skipReason ?? "N/A"}</td>
                    <td>{item.sizeBytes === null ? "N/A" : `${item.sizeBytes} B`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </ReportSection>

      <ReportSection title="Django Signals">
        <MetadataList entries={report.signals} empty="No Django signals returned yet." monoValues />
      </ReportSection>

      <div className="report-grid">
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
            <p className="empty-state">No Django config errors reported.</p>
          )}
        </ReportSection>
      </div>

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

function FindingCard({ finding }: { finding: DjangoConfigFinding }) {
  return (
    <article className="tool-card">
      <div className="tool-card-header">
        <strong>{finding.title}</strong>
        <span className={`finding-badge ${finding.level}`}>{finding.level}</span>
      </div>
      {finding.filePath ? <p className="mono evidence-line">{finding.filePath}</p> : null}
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
  const redactedJob = {
    ...job,
    error: typeof job.error === "string" ? redactDjangoConfigValue(job.error) : job.error,
    result: redactDjangoConfigValue(job.result)
  };
  return (
    <details className="raw-json">
      <summary>Raw JSON (redacted)</summary>
      <pre>{JSON.stringify(redactedJob, null, 2)}</pre>
    </details>
  );
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}
