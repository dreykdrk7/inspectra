import type { ReactNode } from "react";

import type { FileRecord, JobRecord, JobStatus } from "./types";
import { buildPdfAuditReport, type MetadataEntry, type ToolReport, type ToolStatus } from "./pdfReport";

export function PdfJobReport({ job, file }: { job: JobRecord; file?: FileRecord }) {
  const report = buildPdfAuditReport(job, file);

  if (!report.isPdfAudit) {
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
          <MetadataRow label="Job ID" value={job.id} mono />
          <MetadataRow label="File ID" value={job.file_id} mono />
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

        <ReportSection title="File Identification">
          <dl className="summary-list">
            <MetadataRow label="MIME type" value={report.fileInfo.mimeType ?? "Not available"} />
            <MetadataRow label="Size" value={report.fileInfo.sizeBytes === null ? "Not available" : formatBytes(report.fileInfo.sizeBytes)} />
            <MetadataRow label="file output" value={report.fileInfo.fileOutput ?? "Not available"} />
          </dl>
        </ReportSection>
      </div>

      <div className="report-grid">
        <ReportSection title="PDF Metadata">
          <MetadataList entries={report.pdfInfo} empty="pdfinfo did not return structured metadata." />
        </ReportSection>

        <ReportSection title="ExifTool Metadata">
          <MetadataList entries={report.exiftool} empty="exiftool did not return structured metadata." />
        </ReportSection>
      </div>

      <ReportSection title="Validation">
        <div className="validation-row">
          <span className={`tool-badge ${report.validation.qpdfOk === true ? "ok" : report.validation.qpdfOk === false ? "error" : "not_run"}`}>
            qpdf {report.validation.qpdfOk === true ? "ok" : report.validation.qpdfOk === false ? "review" : "unknown"}
          </span>
          <span className="muted">exit code: {report.validation.qpdfExitCode ?? "not available"}</span>
        </div>
        {report.validation.warnings.length > 0 ? (
          <ul className="warning-list">
            {report.validation.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        ) : (
          <p className="empty-state">No validation warnings reported.</p>
        )}
        <ToolOutput title="qpdf stdout" value={report.validation.qpdfStdout} />
        <ToolOutput title="qpdf stderr" value={report.validation.qpdfStderr} />
      </ReportSection>

      <ReportSection title="Tool Status, Errors And Timeouts">
        {report.tools.length === 0 ? (
          <p className="empty-state">No tool output has been recorded yet.</p>
        ) : (
          <div className="tool-list">
            {report.tools.map((tool) => (
              <ToolCard key={tool.name} tool={tool} />
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

function MetadataRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <>
      <dt>{label}</dt>
      <dd className={mono ? "mono" : undefined}>{value}</dd>
    </>
  );
}

function ToolCard({ tool }: { tool: ToolReport }) {
  const hasOutput = tool.stderr.trim() || tool.status === "timeout";

  return (
    <article className="tool-card">
      <div className="tool-card-header">
        <div>
          <strong>{tool.name}</strong>
          <span className="subtle-id">{tool.command}</span>
        </div>
        <ToolBadge status={tool.status} />
      </div>
      <dl className="compact-list">
        <MetadataRow label="Exit code" value={tool.exitCode === null ? "not available" : String(tool.exitCode)} />
        <MetadataRow label="Duration" value={tool.durationMs === null ? "not available" : `${tool.durationMs} ms`} />
        <MetadataRow label="Timeout" value={tool.timeoutSeconds === null ? "not configured" : `${tool.timeoutSeconds} s`} />
      </dl>
      {hasOutput ? <ToolOutput title="stderr" value={tool.stderr || (tool.status === "timeout" ? "Command timed out." : "")} /> : null}
    </article>
  );
}

function StatusBadge({ status }: { status: JobStatus }) {
  return <span className={`status-pill ${status}`}>{status}</span>;
}

function ToolBadge({ status }: { status: ToolStatus }) {
  const label = status === "not_run" ? "not run" : status;
  return <span className={`tool-badge ${status}`}>{label}</span>;
}

function ToolOutput({ title, value }: { title: string; value: string }) {
  if (!value.trim()) {
    return null;
  }
  return (
    <details className="tool-output">
      <summary>{title}</summary>
      <pre>{value}</pre>
    </details>
  );
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

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
