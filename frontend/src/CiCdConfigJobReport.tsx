import type { ReactNode } from "react";

import {
  buildCiCdConfigAuditReport,
  redactCiCdConfigValue,
  type CiCdActionImage,
  type CiCdFile,
  type CiCdFinding,
  type CiCdFindingGroup,
  type CiCdJobStep,
  type CiCdPermission,
  type CiCdPublishDeploySignal,
  type CiCdServiceContainer,
  type CiCdTrigger,
  type CiCdWorkflow
} from "./ciCdConfigReport";
import type { MetadataEntry } from "./pdfReport";
import type { FileRecord, JobRecord, JobStatus } from "./types";

export function CiCdConfigJobReport({ job, file }: { job: JobRecord; file?: FileRecord }) {
  const report = buildCiCdConfigAuditReport(job);

  if (!report.isCiCdConfigAudit) {
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
          Analysis truncated by configured CI/CD config limits. Review skipped files and rerun with a smaller archive if needed.
        </div>
      ) : null}

      {report.redactedValuesCount > 0 ? (
        <div className="query-warning" role="status">
          Secret-like CI/CD values were redacted. Inspectra does not display full tokens, passwords, URL credentials, or private key material.
        </div>
      ) : null}

      <ReportSection title="Summary">
        <MetadataList entries={report.summary} empty="No CI/CD config summary returned yet." />
      </ReportSection>

      <ReportSection title="Workflow Overview">
        {report.workflows.length === 0 ? (
          <p className="empty-state">No workflow overview returned yet.</p>
        ) : (
          <WorkflowTable workflows={report.workflows} />
        )}
      </ReportSection>

      <ReportSection title="Triggers">
        {report.triggers.length === 0 ? <p className="empty-state">No CI/CD triggers returned yet.</p> : <TriggersTable triggers={report.triggers} />}
      </ReportSection>

      <ReportSection title="Permissions">
        {report.permissions.length === 0 ? (
          <p className="empty-state">No CI/CD permissions returned yet.</p>
        ) : (
          <PermissionsTable permissions={report.permissions} />
        )}
      </ReportSection>

      <ReportSection title="Jobs / Steps Overview">
        {report.jobs.length === 0 ? <p className="empty-state">No CI/CD jobs or steps returned yet.</p> : <JobsTable jobs={report.jobs} />}
      </ReportSection>

      <ReportSection title="Actions / Images">
        {report.actions.length === 0 ? (
          <p className="empty-state">No CI/CD actions or images returned yet.</p>
        ) : (
          <ActionsImagesTable actions={report.actions} />
        )}
      </ReportSection>

      <ReportSection title="Service Containers">
        {report.serviceContainers.length === 0 ? (
          <p className="empty-state">No CI/CD service containers returned yet.</p>
        ) : (
          <ServiceContainersTable containers={report.serviceContainers} />
        )}
      </ReportSection>

      <ReportSection title="Publish / Deploy Signals">
        {report.publishDeploySignals.length === 0 ? (
          <p className="empty-state">No CI/CD publish or deploy signals returned yet.</p>
        ) : (
          <PublishDeployTable signals={report.publishDeploySignals} />
        )}
      </ReportSection>

      <ReportSection title="Findings">
        <FindingGroups groups={report.findingGroups} />
      </ReportSection>

      <ReportSection title="Files Detected / Reviewed">
        {report.detectedFiles.length === 0 ? (
          <p className="empty-state">No CI/CD config candidate files detected or returned yet.</p>
        ) : (
          <FilesTable files={report.detectedFiles} />
        )}
        {report.reviewedFiles.length > 0 ? (
          <>
            <h4>Reviewed files</h4>
            <FilesTable files={report.reviewedFiles} />
          </>
        ) : null}
      </ReportSection>

      <ReportSection title="Redaction Notes">
        {report.redactionNotes.length === 0 ? (
          <p className="empty-state">No CI/CD config redaction notes returned.</p>
        ) : (
          <ul className="warning-list">
            {report.redactionNotes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        )}
      </ReportSection>

      <div className="report-grid">
        <ReportSection title="Limits / Truncation">
          <MetadataList entries={report.limits} empty="No CI/CD config limits returned yet." />
        </ReportSection>
        <ReportSection title="Errors">
          {job.error ? <p className="error-text">{String(redactCiCdConfigValue(job.error))}</p> : null}
          {report.errors.length > 0 ? (
            <ul className="warning-list">
              {report.errors.map((error) => (
                <li key={error}>{error}</li>
              ))}
            </ul>
          ) : job.error ? null : (
            <p className="empty-state">No CI/CD config errors reported.</p>
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

function FindingGroups({ groups }: { groups: CiCdFindingGroup[] }) {
  if (groups.length === 0) {
    return <p className="empty-state">No heuristic CI/CD config findings reported.</p>;
  }
  return (
    <div className="finding-list">
      {groups.map((group) => (
        <section className="finding-group" key={group.level}>
          <div className="section-title-row">
            <h4>{group.level}</h4>
            <span className={`finding-badge ${group.level}`}>{group.findings.length}</span>
          </div>
          <div className="finding-list">
            {group.findings.map((finding, index) => (
              <FindingCard finding={finding} key={`${finding.id}-${index}`} />
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}

function FindingCard({ finding }: { finding: CiCdFinding }) {
  return (
    <article className="tool-card">
      <div className="tool-card-header">
        <strong>{finding.title}</strong>
        <div className="badge-row">
          {finding.context ? <ContextBadge context={finding.context} /> : null}
          {finding.provider ? <span className="status-pill">{finding.provider}</span> : null}
          {finding.category ? <span className="status-pill">{finding.category}</span> : null}
          {finding.confidence ? <span className="status-pill">confidence: {finding.confidence}</span> : null}
          <span className={`finding-badge ${finding.level}`}>{finding.level}</span>
        </div>
      </div>
      {finding.filePath ? (
        <p className="mono evidence-line">
          {finding.filePath}
          {finding.line !== null ? `:${finding.line}` : ""}
        </p>
      ) : null}
      {finding.job || finding.step ? (
        <p className="muted">
          {[finding.job ? `job: ${finding.job}` : null, finding.step ? `step: ${finding.step}` : null].filter(Boolean).join(" | ")}
        </p>
      ) : null}
      <p className="subtle-id">{finding.id}</p>
      {finding.description ? <p>{finding.description}</p> : null}
      {finding.evidence ? <p className="mono evidence-line">{finding.evidence}</p> : null}
      {finding.recommendation ? <p className="muted">{finding.recommendation}</p> : null}
    </article>
  );
}

function WorkflowTable({ workflows }: { workflows: CiCdWorkflow[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Path</th>
            <th>Provider</th>
            <th>Name</th>
            <th>Jobs</th>
            <th>Triggers</th>
            <th>Read</th>
            <th>Reason</th>
            <th>Context</th>
          </tr>
        </thead>
        <tbody>
          {workflows.map((workflow, index) => (
            <tr key={`${workflow.path}-${index}`}>
              <td className="mono">{workflow.path}</td>
              <td>{workflow.provider ?? "N/A"}</td>
              <td>{workflow.name ?? "N/A"}</td>
              <td>{workflow.jobsCount ?? "N/A"}</td>
              <td>{workflow.triggers.length > 0 ? workflow.triggers.join(", ") : "N/A"}</td>
              <td>{workflow.read === null ? "N/A" : workflow.read ? "yes" : "no"}</td>
              <td>{workflow.skipReason ?? "N/A"}</td>
              <td>{workflow.context ? <ContextBadge context={workflow.context} /> : "N/A"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TriggersTable({ triggers }: { triggers: CiCdTrigger[] }) {
  return (
    <SimpleTable
      columns={["File", "Provider", "Trigger", "Context", "Evidence"]}
      rows={triggers.map((trigger) => [
        mono(trigger.path),
        trigger.provider ?? "N/A",
        trigger.trigger,
        trigger.context ? <ContextBadge context={trigger.context} /> : "N/A",
        mono(trigger.evidence ?? "N/A")
      ])}
    />
  );
}

function PermissionsTable({ permissions }: { permissions: CiCdPermission[] }) {
  return (
    <SimpleTable
      columns={["File", "Provider", "Permission", "Value", "Context", "Evidence"]}
      rows={permissions.map((permission) => [
        mono(permission.path),
        permission.provider ?? "N/A",
        permission.permission,
        mono(permission.value ?? "N/A"),
        permission.context ? <ContextBadge context={permission.context} /> : "N/A",
        mono(permission.evidence ?? "N/A")
      ])}
    />
  );
}

function JobsTable({ jobs }: { jobs: CiCdJobStep[] }) {
  return (
    <SimpleTable
      columns={["File", "Provider", "Job", "Step", "Steps", "Context", "Excerpt"]}
      rows={jobs.map((job) => [
        mono(job.path),
        job.provider ?? "N/A",
        job.job ?? "N/A",
        job.step ?? "N/A",
        job.stepsDetected ?? "N/A",
        job.context ? <ContextBadge context={job.context} /> : "N/A",
        mono(job.excerpt ?? "N/A")
      ])}
    />
  );
}

function ActionsImagesTable({ actions }: { actions: CiCdActionImage[] }) {
  return (
    <SimpleTable
      columns={["File", "Provider", "Action", "Ref", "Image", "Pinned", "Job", "Step", "Context"]}
      rows={actions.map((action) => [
        mono(action.path),
        action.provider ?? "N/A",
        action.action ?? "N/A",
        action.ref ?? "N/A",
        mono(action.image ?? "N/A"),
        action.pinned === null ? action.signal ?? "N/A" : action.pinned ? "yes" : "no",
        action.job ?? "N/A",
        action.step ?? "N/A",
        action.context ? <ContextBadge context={action.context} /> : "N/A"
      ])}
    />
  );
}

function ServiceContainersTable({ containers }: { containers: CiCdServiceContainer[] }) {
  return (
    <SimpleTable
      columns={["File", "Provider", "Service", "Image", "Privileged", "Default credentials", "Context"]}
      rows={containers.map((container) => [
        mono(container.path),
        container.provider ?? "N/A",
        container.service ?? "N/A",
        mono(container.image ?? "N/A"),
        formatBoolean(container.privileged),
        container.defaultCredentialsHint ?? "N/A",
        container.context ? <ContextBadge context={container.context} /> : "N/A"
      ])}
    />
  );
}

function PublishDeployTable({ signals }: { signals: CiCdPublishDeploySignal[] }) {
  return (
    <SimpleTable
      columns={["File", "Provider", "Signal", "Job", "Step", "Context", "Evidence"]}
      rows={signals.map((signal) => [
        mono(signal.path),
        signal.provider ?? "N/A",
        signal.signal,
        signal.job ?? "N/A",
        signal.step ?? "N/A",
        signal.context ? <ContextBadge context={signal.context} /> : "N/A",
        mono(signal.evidence ?? "N/A")
      ])}
    />
  );
}

function FilesTable({ files }: { files: CiCdFile[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Path</th>
            <th>Category</th>
            <th>Context</th>
            <th>Read</th>
            <th>Reason</th>
            <th>Size</th>
            <th>Bytes read</th>
          </tr>
        </thead>
        <tbody>
          {files.map((item, index) => (
            <tr key={`${item.path}-${index}`}>
              <td className="mono">{item.path}</td>
              <td>{item.category}</td>
              <td>{item.context ? <ContextBadge context={item.context} /> : "N/A"}</td>
              <td>{item.read ? "yes" : "no"}</td>
              <td>{item.skipReason ?? "N/A"}</td>
              <td>{item.sizeBytes === null ? "N/A" : `${item.sizeBytes} B`}</td>
              <td>{item.bytesRead === null ? "N/A" : `${item.bytesRead} B`}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SimpleTable({ columns, rows }: { columns: string[]; rows: ReactNode[][] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column}>{column}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, rowIndex) => (
            <tr key={rowIndex}>
              {row.map((cell, cellIndex) => (
                <td key={`${rowIndex}-${cellIndex}`}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function mono(value: string): ReactNode {
  return <span className="mono">{value}</span>;
}

function ContextBadge({ context }: { context: string }) {
  const contextClass = context.toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
  return <span className={`context-pill ${contextClass}`}>{context}</span>;
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
    error: typeof job.error === "string" ? redactCiCdConfigValue(job.error) : job.error,
    result: redactCiCdConfigValue(job.result)
  };
  return (
    <details className="raw-json">
      <summary>Raw JSON (redacted)</summary>
      <pre>{JSON.stringify(redactedJob, null, 2)}</pre>
    </details>
  );
}

function formatBoolean(value: boolean | null): string {
  return value === null ? "N/A" : value ? "yes" : "no";
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}
