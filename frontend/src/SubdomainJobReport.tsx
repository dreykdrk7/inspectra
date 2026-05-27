import type { ReactNode } from "react";

import { buildSubdomainAuditReport, type SubdomainFinding } from "./subdomainReport";
import type { MetadataEntry } from "./pdfReport";
import type { JobRecord, JobStatus } from "./types";

export function SubdomainJobReport({ job }: { job: JobRecord }) {
  const report = buildSubdomainAuditReport(job);

  if (!report.isSubdomainAudit) {
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
          <MetadataRow label="Root domain" value={job.target_domain ?? "Not available"} mono />
          <MetadataRow label="Created" value={formatDate(job.created_at)} />
          <MetadataRow label="Updated" value={formatDate(job.updated_at)} />
        </dl>
      </section>

      <div className="report-grid">
        <ReportSection title="Target">
          <MetadataList entries={report.target} empty="No subdomain target metadata returned yet." monoValues />
        </ReportSection>
        <ReportSection title="Summary">
          <MetadataList entries={report.summary} empty="No subdomain inventory summary returned yet." />
        </ReportSection>
      </div>

      <ReportSection title="Candidates">
        {report.candidates.length === 0 ? (
          <p className="empty-state">No candidate normalization results returned.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Input</th>
                  <th>FQDN</th>
                  <th>Status</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {report.candidates.map((candidate, index) => (
                  <tr key={`${candidate.input}-${index}`}>
                    <td className="mono">{candidate.input}</td>
                    <td className="mono">{candidate.fqdn ?? "N/A"}</td>
                    <td>
                      <span className={`status-pill ${candidate.status === "accepted" ? "completed" : "failed"}`}>
                        {candidate.status}
                      </span>
                    </td>
                    <td>{candidate.rejectionReason ?? "N/A"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </ReportSection>

      <ReportSection title="DNS Results">
        {report.results.length === 0 ? (
          <p className="empty-state">No DNS result rows returned.</p>
        ) : (
          <div className="finding-list">
            {report.results.map((result) => (
              <article className="tool-card" key={result.fqdn}>
                <div className="tool-card-header">
                  <strong className="mono">{result.fqdn}</strong>
                  <span className={`status-pill ${result.resolves ? "completed" : "queued"}`}>
                    {result.resolves ? "resolves" : "unresolved"}
                  </span>
                </div>
                <dl className="summary-list">
                  <MetadataRow label="A" value={result.a.length ? result.a.join(", ") : "N/A"} mono />
                  <MetadataRow label="AAAA" value={result.aaaa.length ? result.aaaa.join(", ") : "N/A"} mono />
                  <MetadataRow label="CNAME" value={result.cname.length ? result.cname.join(", ") : "N/A"} mono />
                  <MetadataRow label="Private/reserved IP" value={String(result.privateOrReservedIpDetected)} />
                </dl>
                {result.errors.length > 0 ? (
                  <ul className="warning-list">
                    {result.errors.map((error) => (
                      <li key={error}>{error}</li>
                    ))}
                  </ul>
                ) : null}
              </article>
            ))}
          </div>
        )}
      </ReportSection>

      <div className="report-grid">
        <ReportSection title="Wildcard DNS">
          <MetadataList entries={report.wildcardDns} empty="Wildcard DNS was not checked or returned no metadata." monoValues />
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
            <p className="empty-state">No subdomain inventory errors reported.</p>
          )}
        </ReportSection>
      </div>

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

function FindingCard({ finding }: { finding: SubdomainFinding }) {
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
