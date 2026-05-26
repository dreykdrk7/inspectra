import type { ReactNode } from "react";

import { buildManifestAuditReport, type DependencyGroup, type ManifestFinding } from "./manifestReport";
import type { MetadataEntry } from "./pdfReport";
import type { FileRecord, JobRecord, JobStatus } from "./types";

export function ManifestJobReport({ job, file }: { job: JobRecord; file?: FileRecord }) {
  const report = buildManifestAuditReport(job, file);

  if (!report.isManifestAudit) {
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
            {job.source_file_deleted_at ? <span className="status-pill deleted">source deleted</span> : null}
          </div>
        </div>
        <dl className="summary-list">
          <MetadataRow label="Audit type" value={job.audit_type} />
          <MetadataRow label="Analyzer" value={report.analyzer ?? "Not available"} />
          <MetadataRow label="Manifest type" value={formatManifestType(report.manifestType)} />
          <MetadataRow label="Job ID" value={job.id} mono />
          <MetadataRow label="File ID" value={job.file_id ?? "N/A"} mono />
          <MetadataRow label="Created" value={formatDate(job.created_at)} />
          <MetadataRow label="Updated" value={formatDate(job.updated_at)} />
          <MetadataRow label="Completed" value={report.completedAt ? formatDate(report.completedAt) : "Not completed"} />
          <MetadataRow
            label="Source file"
            value={job.source_file_deleted_at ? `Deleted at ${formatDate(job.source_file_deleted_at)}` : "Available"}
          />
        </dl>
      </section>

      <div className="report-grid">
        <ReportSection title="Hashes">
          <MetadataList entries={report.hashes} empty="No hashes returned yet." monoValues />
        </ReportSection>

        <ReportSection title="Manifest File">
          <dl className="summary-list">
            <MetadataRow label="Original name" value={report.fileInfo.originalFilename ?? "Not available"} />
            <MetadataRow label="Size" value={report.fileInfo.sizeBytes === null ? "Not available" : formatBytes(report.fileInfo.sizeBytes)} />
            <MetadataRow label="Dependencies" value={report.summary.totalDependencies === null ? "Not available" : String(report.summary.totalDependencies)} />
            <MetadataRow
              label="Findings"
              value={report.summary.informationalFindingsCount === null ? "Not available" : String(report.summary.informationalFindingsCount)}
            />
          </dl>
        </ReportSection>
      </div>

      <div className="report-grid">
        <ReportSection title="Project Information">
          <MetadataList entries={report.project} empty="No project metadata was found in this manifest." />
        </ReportSection>

        <ReportSection title="Scripts And Engines">
          <MetadataList entries={report.scripts} empty="No scripts were declared." />
          {report.engines.length > 0 ? (
            <>
              <h4 className="compact-heading">Engines</h4>
              <MetadataList entries={report.engines} empty="No engines were declared." />
            </>
          ) : null}
        </ReportSection>
      </div>

      <ReportSection title="Dependencies By Group">
        {report.dependencies.length === 0 ? (
          <p className="empty-state">No dependencies were extracted.</p>
        ) : (
          <div className="dependency-groups">
            {report.dependencies.map((group) => (
              <DependencyGroupCard key={group.name} group={group} />
            ))}
          </div>
        )}
      </ReportSection>

      <ReportSection title="Informational Findings">
        {report.findings.length === 0 ? (
          <p className="empty-state">No informational findings reported.</p>
        ) : (
          <div className="finding-list">
            {report.findings.map((finding, index) => (
              <FindingCard key={`${finding.id}-${index}`} finding={finding} />
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
          <p className="empty-state">No parser errors reported.</p>
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

function DependencyGroupCard({ group }: { group: DependencyGroup }) {
  return (
    <article className="tool-card">
      <div className="tool-card-header">
        <strong>{group.name}</strong>
        <span className="tool-badge not_run">{group.dependencies.length} deps</span>
      </div>
      {group.dependencies.length === 0 ? (
        <p className="empty-state">No dependencies in this group.</p>
      ) : (
        <div className="dependency-list">
          {group.dependencies.map((dependency, index) => (
            <div className="dependency-row" key={`${dependency.name}-${index}`}>
              <strong>{dependency.name}</strong>
              <span className="mono">{dependency.specifier || "no specifier"}</span>
              {dependency.source ? <span className="muted">{dependency.source}</span> : null}
            </div>
          ))}
        </div>
      )}
    </article>
  );
}

function FindingCard({ finding }: { finding: ManifestFinding }) {
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

function formatManifestType(value: string | null): string {
  if (value === "package_json") {
    return "package.json";
  }
  if (value === "requirements_txt") {
    return "requirements.txt";
  }
  if (value === "pyproject_toml") {
    return "pyproject.toml";
  }
  return "Not available";
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
