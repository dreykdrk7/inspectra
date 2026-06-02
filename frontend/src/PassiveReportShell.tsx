import type { ReactNode } from "react";

import { getAuditTypeMetadata } from "./auditCatalog";
import type { MetadataEntry } from "./pdfReport";
import type { FileRecord, JobRecord, JobStatus } from "./types";

const DEFAULT_ARCHIVE_SCOPE_COPY =
  "Passive static review only. Inspectra reads bounded candidate files from the uploaded archive and reports heuristic review indicators. It does not execute tools, contact live services, validate credentials, query CVEs/advisories, or prove exploitability.";

const HEURISTIC_COPY = "Findings are heuristic review indicators and require human validation.";
const RUNNING_COPY = "Passive analysis is running. No external services are contacted for archive config analyzers.";

export const REDACTION_SCOPE_COPY =
  "Sensitive-looking values are redacted in results, exports, and raw JSON. Redacted values use [REDACTED]. This does not sanitize the original uploaded file.";
export const EMPTY_SECTION_COPY = "No entries reported for this section.";
export const NO_CONTROLLED_ERRORS_COPY = "No controlled errors were reported.";
export const NO_REDACTION_NOTES_COPY = "No redaction notes were reported.";
export const TRUNCATION_COPY = "Limits were reached; results may be partial.";

export function PassiveReportShell({
  job,
  file,
  analyzer,
  archiveType,
  overview,
  findingsCount,
  isSparse = false,
  truncated = false,
  scopeCopy = DEFAULT_ARCHIVE_SCOPE_COPY,
  children,
  rawJson
}: {
  job: JobRecord;
  file?: FileRecord;
  analyzer?: string | null;
  archiveType?: string | null;
  overview: MetadataEntry[];
  findingsCount?: number;
  isSparse?: boolean;
  truncated?: boolean;
  scopeCopy?: string;
  children: ReactNode;
  rawJson?: ReactNode;
}) {
  const metadata = getAuditTypeMetadata(job.audit_type);
  return (
    <div className="report-layout">
      <section className="report-section">
        <div className="section-title-row">
          <div>
            <h3>{metadata.label}</h3>
            <p className="muted">{HEURISTIC_COPY}</p>
          </div>
          <div className="badge-row">
            <span className="status-pill">Passive review</span>
            <StatusBadge status={job.status} />
          </div>
        </div>
        <div className="report-summary-grid">
          {overview.map((entry) => (
            <div className="report-metric" key={entry.label}>
              <span>{entry.label}</span>
              <strong>{entry.value}</strong>
            </div>
          ))}
        </div>
        <dl className="summary-list">
          <MetadataRow label="Audit type" value={job.audit_type} />
          <MetadataRow label="Category" value={metadata.categoryLabel} />
          <MetadataRow label="Analyzer" value={analyzer ?? "Not available"} />
          <MetadataRow label="Archive type" value={archiveType ?? "Not available"} />
          <MetadataRow label="Job ID" value={job.id} mono />
          <MetadataRow label="Source file" value={file?.original_filename ?? job.file_id ?? "Not available"} mono />
          <MetadataRow label="Created" value={formatDate(job.created_at)} />
          <MetadataRow label="Updated" value={formatDate(job.updated_at)} />
        </dl>
      </section>

      <div className="alert" role="status">
        {scopeCopy} {HEURISTIC_COPY}
      </div>

      <div className="query-warning" role="status">
        {statusMessage(job.status, findingsCount, isSparse)}
      </div>

      {truncated ? (
        <div className="alert" role="status">
          {TRUNCATION_COPY}
        </div>
      ) : null}

      {children}

      {rawJson ? (
        <section className="report-section">
          <h3>Redacted Raw JSON</h3>
          <p className="muted">{REDACTION_SCOPE_COPY}</p>
          {rawJson}
        </section>
      ) : null}
    </div>
  );
}

function statusMessage(status: JobStatus, findingsCount?: number, isSparse = false): string {
  if (status === "queued") {
    return "Job queued. Results will appear when processing starts.";
  }
  if (status === "running") {
    return isSparse ? `${RUNNING_COPY} Some result fields are unavailable; showing available redacted data.` : RUNNING_COPY;
  }
  if (status === "failed") {
    return "The job failed in a controlled state. Review errors below; uploaded content was not executed.";
  }
  if (isSparse) {
    return "Some result fields are unavailable; showing available redacted data.";
  }
  if (findingsCount && findingsCount > 0) {
    return "Review indicators were reported. Validate them manually before acting.";
  }
  return "No heuristic findings were reported for this analyzer.";
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

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}
