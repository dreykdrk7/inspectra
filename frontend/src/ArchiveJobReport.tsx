import type { ReactNode } from "react";

import { buildArchiveAuditReport, type ArchiveEntry, type ArchiveFinding } from "./archiveReport";
import type { MetadataEntry } from "./pdfReport";
import type { FileRecord, JobRecord, JobStatus } from "./types";

export function ArchiveJobReport({ job, file }: { job: JobRecord; file?: FileRecord }) {
  const report = buildArchiveAuditReport(job, file);

  if (!report.isArchiveAudit) {
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
          <MetadataRow label="Archive type" value={report.archiveType ?? "Not available"} />
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

        <ReportSection title="Archive File">
          <dl className="summary-list">
            <MetadataRow label="Original name" value={report.fileInfo.originalFilename ?? "Not available"} />
            <MetadataRow label="Size" value={report.fileInfo.sizeBytes === null ? "Not available" : formatBytes(report.fileInfo.sizeBytes)} />
          </dl>
        </ReportSection>
      </div>

      <ReportSection title="Archive Metrics">
        <MetadataList entries={report.summary} empty="No archive metrics returned yet." />
      </ReportSection>

      <ReportSection title="Detected Manifests">
        {report.detectedManifests.length === 0 ? (
          <p className="empty-state">No manifest files detected in the archive sample.</p>
        ) : (
          <div className="dependency-list">
            {report.detectedManifests.map((manifest) => (
              <div className="dependency-row" key={`${manifest.path}-${manifest.manifestType}`}>
                <strong>{manifest.manifestType}</strong>
                <span className="mono">{manifest.path}</span>
                <span className="muted">detected</span>
              </div>
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

      <ReportSection title="Entries Sample">
        {report.entriesSample.length === 0 ? (
          <p className="empty-state">No archive entries were listed.</p>
        ) : (
          <div className="archive-entry-list">
            {report.entriesSample.map((entry, index) => (
              <EntryCard key={`${entry.path}-${index}`} entry={entry} />
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
          <p className="empty-state">No archive parser errors reported.</p>
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
        <MetadataRow key={entry.label} label={entry.label} value={formatMetadataValue(entry)} mono={monoValues} />
      ))}
    </dl>
  );
}

function EntryCard({ entry }: { entry: ArchiveEntry }) {
  return (
    <article className="tool-card">
      <div className="tool-card-header">
        <strong className="mono">{entry.path}</strong>
        <span className="tool-badge not_run">{entry.type}</span>
      </div>
      <dl className="compact-list">
        <MetadataRow label="Size" value={entry.size === null ? "N/A" : formatBytes(entry.size)} />
        <MetadataRow label="Compressed" value={entry.compressedSize === null ? "N/A" : formatBytes(entry.compressedSize)} />
        <MetadataRow label="Mode" value={entry.mode ?? "N/A"} mono />
        <MetadataRow label="Depth" value={entry.depth === null ? "N/A" : String(entry.depth)} />
        {entry.linkTarget ? <MetadataRow label="Link target" value={entry.linkTarget} mono /> : null}
      </dl>
      {entry.flags.length > 0 ? (
        <div className="flag-row">
          {entry.flags.map((flag) => (
            <span className="tool-badge timeout" key={flag.label}>
              {flag.label}
            </span>
          ))}
        </div>
      ) : null}
    </article>
  );
}

function FindingCard({ finding }: { finding: ArchiveFinding }) {
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

function formatMetadataValue(entry: MetadataEntry): string {
  if (entry.label.toLowerCase().includes("bytes")) {
    const parsed = Number(entry.value);
    return Number.isFinite(parsed) ? formatBytes(parsed) : entry.value;
  }
  return entry.value;
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
