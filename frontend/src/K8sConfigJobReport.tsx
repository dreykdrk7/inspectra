import type { ReactNode } from "react";

import {
  buildK8sConfigAuditReport,
  redactK8sConfigValue,
  type K8sContainer,
  type K8sFile,
  type K8sFinding,
  type K8sFindingGroup,
  type K8sHelmKustomizeSignal,
  type K8sResource,
  type K8sService
} from "./k8sConfigReport";
import type { MetadataEntry } from "./pdfReport";
import type { FileRecord, JobRecord, JobStatus } from "./types";

export function K8sConfigJobReport({ job, file }: { job: JobRecord; file?: FileRecord }) {
  const report = buildK8sConfigAuditReport(job);

  if (!report.isK8sConfigAudit) {
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

      <div className="alert" role="status">
        Passive archive-only Kubernetes manifest review. Inspectra does not run kubectl, access a cluster, render Helm, build Kustomize, download images, query registries/CVEs, or validate exploitability.
      </div>

      {report.truncated ? (
        <div className="alert" role="status">
          Analysis truncated by configured Kubernetes config limits. Review skipped files and rerun with a smaller archive if needed.
        </div>
      ) : null}

      {report.redactedValuesCount > 0 ? (
        <div className="query-warning" role="status">
          Secret-like Kubernetes values were redacted. Inspectra does not display full Secret data/stringData, env/config values, tokens, passwords, URL credentials, or private key material.
        </div>
      ) : null}

      <ReportSection title="Summary">
        <MetadataList entries={report.summary} empty="No Kubernetes config summary returned yet." />
      </ReportSection>

      <ReportSection title="Resources Detected">
        {report.resources.length === 0 ? <p className="empty-state">No Kubernetes resources returned yet.</p> : <ResourcesTable resources={report.resources} />}
      </ReportSection>

      <ReportSection title="Workloads / Containers">
        {report.workloads.length === 0 ? <p className="empty-state">No Kubernetes workloads returned yet.</p> : <ResourcesTable resources={report.workloads} />}
        {report.containers.length > 0 ? (
          <>
            <h4>Containers</h4>
            <ContainersTable containers={report.containers} />
          </>
        ) : (
          <p className="empty-state">No Kubernetes containers returned yet.</p>
        )}
      </ReportSection>

      <ReportSection title="Services / Ingress">
        {report.services.length === 0 ? <p className="empty-state">No Kubernetes services returned yet.</p> : <ServicesTable services={report.services} />}
        {report.ingress.length > 0 ? (
          <>
            <h4>Ingress</h4>
            <ResourcesTable resources={report.ingress} />
          </>
        ) : (
          <p className="empty-state">No Kubernetes ingress resources returned yet.</p>
        )}
      </ReportSection>

      <ReportSection title="RBAC">
        {report.rbac.length === 0 ? <p className="empty-state">No Kubernetes RBAC resources returned yet.</p> : <ResourcesTable resources={report.rbac} />}
      </ReportSection>

      <ReportSection title="Secrets / Config References">
        {report.secrets.length === 0 ? (
          <p className="empty-state">No Kubernetes Secret resources returned yet.</p>
        ) : (
          <ResourcesTable resources={report.secrets} />
        )}
      </ReportSection>

      <ReportSection title="Helm / Kustomize">
        {report.helmKustomizeSignals.length === 0 ? (
          <p className="empty-state">No Helm or Kustomize context returned yet.</p>
        ) : (
          <HelmKustomizeTable signals={report.helmKustomizeSignals} />
        )}
      </ReportSection>

      <ReportSection title="Findings">
        <FindingGroups groups={report.findingGroups} />
      </ReportSection>

      <ReportSection title="Files Detected / Reviewed">
        {report.detectedFiles.length === 0 ? (
          <p className="empty-state">No Kubernetes config candidate files detected or returned yet.</p>
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
          <p className="empty-state">No Kubernetes config redaction notes returned.</p>
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
          <MetadataList entries={report.limits} empty="No Kubernetes config limits returned yet." />
        </ReportSection>
        <ReportSection title="Errors">
          {job.error ? <p className="error-text">{String(redactK8sConfigValue(job.error))}</p> : null}
          {report.errors.length > 0 ? (
            <ul className="warning-list">
              {report.errors.map((error) => (
                <li key={error}>{error}</li>
              ))}
            </ul>
          ) : job.error ? null : (
            <p className="empty-state">No Kubernetes config errors reported.</p>
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

function FindingGroups({ groups }: { groups: K8sFindingGroup[] }) {
  if (groups.length === 0) {
    return <p className="empty-state">No heuristic Kubernetes config findings reported.</p>;
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

function FindingCard({ finding }: { finding: K8sFinding }) {
  return (
    <article className="tool-card">
      <div className="tool-card-header">
        <strong>{finding.title}</strong>
        <div className="badge-row">
          {finding.context ? <ContextBadge context={finding.context} /> : null}
          {finding.kind ? <span className="status-pill">{finding.kind}</span> : null}
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
      {finding.resourceName || finding.namespace || finding.container || finding.fieldPath ? (
        <p className="muted">
          {[
            finding.resourceName ? `resource: ${finding.resourceName}` : null,
            finding.namespace ? `namespace: ${finding.namespace}` : null,
            finding.container ? `container: ${finding.container}` : null,
            finding.fieldPath ? `field: ${finding.fieldPath}` : null
          ].filter(Boolean).join(" | ")}
        </p>
      ) : null}
      <p className="subtle-id">{finding.id}</p>
      {finding.description ? <p>{finding.description}</p> : null}
      {finding.evidence ? <p className="mono evidence-line">{finding.evidence}</p> : null}
      {finding.recommendation ? <p className="muted">{finding.recommendation}</p> : null}
    </article>
  );
}

function ResourcesTable({ resources }: { resources: K8sResource[] }) {
  return (
    <SimpleTable
      columns={["File", "Kind", "Name", "Namespace", "Context"]}
      rows={resources.map((resource) => [
        mono(resource.path),
        resource.kind ?? "N/A",
        resource.name ?? "N/A",
        resource.namespace ?? "N/A",
        resource.context ? <ContextBadge context={resource.context} /> : "N/A"
      ])}
    />
  );
}

function ContainersTable({ containers }: { containers: K8sContainer[] }) {
  return (
    <SimpleTable
      columns={["File", "Workload", "Container", "Image", "Namespace", "Context"]}
      rows={containers.map((container) => [
        mono(container.path),
        [container.kind, container.resourceName].filter(Boolean).join("/") || "N/A",
        container.container ?? "N/A",
        mono(container.image ?? "N/A"),
        container.namespace ?? "N/A",
        container.context ? <ContextBadge context={container.context} /> : "N/A"
      ])}
    />
  );
}

function ServicesTable({ services }: { services: K8sService[] }) {
  return (
    <SimpleTable
      columns={["File", "Kind", "Name", "Type", "Namespace", "Context"]}
      rows={services.map((service) => [
        mono(service.path),
        service.kind ?? "Service",
        service.name ?? "N/A",
        service.type ?? "N/A",
        service.namespace ?? "N/A",
        service.context ? <ContextBadge context={service.context} /> : "N/A"
      ])}
    />
  );
}

function HelmKustomizeTable({ signals }: { signals: K8sHelmKustomizeSignal[] }) {
  return (
    <SimpleTable
      columns={["File", "Category", "Rendered", "Built", "Context", "Evidence"]}
      rows={signals.map((signal) => [
        mono(signal.path),
        signal.category ?? "N/A",
        formatBoolean(signal.rendered),
        formatBoolean(signal.built),
        signal.context ? <ContextBadge context={signal.context} /> : "N/A",
        mono(signal.evidence ?? "N/A")
      ])}
    />
  );
}

function FilesTable({ files }: { files: K8sFile[] }) {
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
    error: typeof job.error === "string" ? redactK8sConfigValue(job.error) : job.error,
    result: redactK8sConfigValue(job.result)
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
