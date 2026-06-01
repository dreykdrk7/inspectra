import type { ReactNode } from "react";

import {
  buildComposeConfigAuditReport,
  redactComposeConfigValue,
  type ComposeBuildContext,
  type ComposeEnvFile,
  type ComposeFile,
  type ComposeFinding,
  type ComposeFindingGroup,
  type ComposeImage,
  type ComposeNetwork,
  type ComposePort,
  type ComposeSecret,
  type ComposeService,
  type ComposeVolume
} from "./composeConfigReport";
import type { MetadataEntry } from "./pdfReport";
import type { FileRecord, JobRecord, JobStatus } from "./types";

export function ComposeConfigJobReport({ job, file }: { job: JobRecord; file?: FileRecord }) {
  const report = buildComposeConfigAuditReport(job);

  if (!report.isComposeConfigAudit) {
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
        Passive archive-only Docker Compose config review. Inspectra does not execute Docker or Docker Compose, run docker compose config,
        start containers, build or pull images, inspect registries, interpolate environment variables, merge multiple Compose files, query
        CVEs, or confirm exploitability. .env, env_file, and Compose secret files are detected as references and are not read by v1.
      </div>

      {report.truncated ? (
        <div className="alert" role="status">
          Analysis truncated by configured Compose config limits. Review skipped files and rerun with a smaller archive if needed.
        </div>
      ) : null}

      {report.redactedValuesCount > 0 ? (
        <div className="query-warning" role="status">
          Secret-like Compose values were redacted. Inspectra does not display environment secret values, env_file or secret file contents,
          credential URLs, registry credentials, database URLs, private keys, or secret-like command and label values.
        </div>
      ) : null}

      <ReportSection title="Summary">
        <MetadataList entries={report.summary} empty="No Compose config summary returned yet." />
      </ReportSection>

      <ReportSection title="Files Detected / Reviewed">
        {report.detectedFiles.length === 0 ? (
          <p className="empty-state">No Compose candidate files detected or returned yet.</p>
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

      <ReportSection title="Services">
        {report.services.length === 0 ? <p className="empty-state">No Compose services returned yet.</p> : <ServicesTable services={report.services} />}
      </ReportSection>

      <ReportSection title="Images and Build Contexts">
        {report.images.length === 0 ? <p className="empty-state">No Compose images returned yet.</p> : <ImagesTable images={report.images} />}
        {report.buildContexts.length > 0 ? (
          <>
            <h4>Build contexts</h4>
            <BuildContextsTable buildContexts={report.buildContexts} />
          </>
        ) : (
          <p className="empty-state">No Compose build contexts returned yet.</p>
        )}
      </ReportSection>

      <ReportSection title="Ports / Exposure">
        {report.ports.length === 0 ? <p className="empty-state">No published Compose ports returned yet.</p> : <PortsTable ports={report.ports} />}
      </ReportSection>

      <ReportSection title="Volumes / Mounts">
        {report.volumes.length === 0 ? <p className="empty-state">No Compose volumes returned yet.</p> : <VolumesTable volumes={report.volumes} />}
      </ReportSection>

      <ReportSection title="Networks">
        {report.networks.length === 0 ? <p className="empty-state">No Compose networks returned yet.</p> : <NetworksTable networks={report.networks} />}
      </ReportSection>

      <ReportSection title="Secrets and Env File References">
        <p className="muted">Compose env_file references, .env files, and secret file references are shown as detected context and are not read by v1.</p>
        {report.envFiles.length === 0 ? <p className="empty-state">No Compose env_file references returned yet.</p> : <EnvFilesTable envFiles={report.envFiles} />}
        {report.secrets.length > 0 ? (
          <>
            <h4>Secrets</h4>
            <SecretsTable secrets={report.secrets} />
          </>
        ) : (
          <p className="empty-state">No Compose secrets returned yet.</p>
        )}
      </ReportSection>

      <ReportSection title="Findings">
        <FindingGroups groups={report.findingGroups} />
      </ReportSection>

      <ReportSection title="Redaction Notes">
        {report.redactionNotes.length === 0 ? (
          <p className="empty-state">No Compose config redaction notes returned.</p>
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
          <MetadataList entries={report.limits} empty="No Compose config limits returned yet." />
        </ReportSection>
        <ReportSection title="Errors">
          {job.error ? <p className="error-text">{String(redactComposeConfigValue(job.error))}</p> : null}
          {report.errors.length > 0 ? (
            <ul className="warning-list">
              {report.errors.map((error) => (
                <li key={error}>{error}</li>
              ))}
            </ul>
          ) : job.error ? null : (
            <p className="empty-state">No Compose config errors reported.</p>
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

function FindingGroups({ groups }: { groups: ComposeFindingGroup[] }) {
  if (groups.length === 0) {
    return <p className="empty-state">No heuristic Compose config findings reported.</p>;
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

function FindingCard({ finding }: { finding: ComposeFinding }) {
  return (
    <article className="tool-card">
      <div className="tool-card-header">
        <strong>{finding.title}</strong>
        <div className="badge-row">
          {finding.context ? <ContextBadge context={finding.context} /> : null}
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
      {finding.service || finding.fieldPath || finding.image || finding.port || finding.hostPath || finding.containerPath || finding.network ? (
        <p className="muted">
          {[
            finding.service ? `service: ${finding.service}` : null,
            finding.fieldPath ? `field: ${finding.fieldPath}` : null,
            finding.image ? `image: ${finding.image}` : null,
            finding.port ? `port: ${finding.port}` : null,
            finding.protocol ? `protocol: ${finding.protocol}` : null,
            finding.hostPath ? `host path: ${finding.hostPath}` : null,
            finding.containerPath ? `container path: ${finding.containerPath}` : null,
            finding.network ? `network: ${finding.network}` : null
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

function FilesTable({ files }: { files: ComposeFile[] }) {
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

function ServicesTable({ services }: { services: ComposeService[] }) {
  return (
    <SimpleTable
      columns={["Service", "Image", "Build", "Restart", "Healthcheck", "Read only", "Privileged", "User", "Network mode", "File", "Context"]}
      rows={services.map((service) => [
        service.name ?? "N/A",
        mono(service.image ?? "N/A"),
        mono(service.build ?? "N/A"),
        service.restart ?? "N/A",
        formatBoolean(service.healthcheck),
        formatBoolean(service.readOnly),
        formatBoolean(service.privileged),
        service.user ?? "N/A",
        service.networkMode ?? "N/A",
        mono(service.filePath || "N/A"),
        service.context ? <ContextBadge context={service.context} /> : "N/A"
      ])}
    />
  );
}

function ImagesTable({ images }: { images: ComposeImage[] }) {
  return (
    <SimpleTable
      columns={["Service", "Image", "Tag", "Digest", "File", "Context"]}
      rows={images.map((image) => [
        image.service ?? "N/A",
        mono(image.image ?? "N/A"),
        image.tag ?? "N/A",
        image.digest ?? "N/A",
        mono(image.filePath || "N/A"),
        image.context ? <ContextBadge context={image.context} /> : "N/A"
      ])}
    />
  );
}

function BuildContextsTable({ buildContexts }: { buildContexts: ComposeBuildContext[] }) {
  return (
    <SimpleTable
      columns={["Service", "Context", "Dockerfile", "File", "Route context"]}
      rows={buildContexts.map((buildContext) => [
        buildContext.service ?? "N/A",
        mono(buildContext.contextPath ?? "N/A"),
        mono(buildContext.dockerfile ?? "N/A"),
        mono(buildContext.filePath || "N/A"),
        buildContext.context ? <ContextBadge context={buildContext.context} /> : "N/A"
      ])}
    />
  );
}

function PortsTable({ ports }: { ports: ComposePort[] }) {
  return (
    <SimpleTable
      columns={["Service", "Host IP", "Published", "Target", "Protocol", "Mode", "File", "Context"]}
      rows={ports.map((port) => [
        port.service ?? "N/A",
        port.hostIp ?? "N/A",
        port.published ?? "N/A",
        port.target ?? "N/A",
        port.protocol ?? "N/A",
        port.mode ?? "N/A",
        mono(port.filePath || "N/A"),
        port.context ? <ContextBadge context={port.context} /> : "N/A"
      ])}
    />
  );
}

function VolumesTable({ volumes }: { volumes: ComposeVolume[] }) {
  return (
    <SimpleTable
      columns={["Service", "Source", "Host path", "Target", "Read only", "Type", "File", "Context"]}
      rows={volumes.map((volume) => [
        volume.service ?? "N/A",
        mono(volume.source ?? "N/A"),
        mono(volume.hostPath ?? "N/A"),
        mono(volume.target ?? "N/A"),
        formatBoolean(volume.readOnly),
        volume.type ?? "N/A",
        mono(volume.filePath || "N/A"),
        volume.context ? <ContextBadge context={volume.context} /> : "N/A"
      ])}
    />
  );
}

function NetworksTable({ networks }: { networks: ComposeNetwork[] }) {
  return (
    <SimpleTable
      columns={["Network", "Service", "External", "Internal", "File", "Context"]}
      rows={networks.map((network) => [
        network.name ?? "N/A",
        network.service ?? "N/A",
        formatBoolean(network.external),
        formatBoolean(network.internal),
        mono(network.filePath || "N/A"),
        network.context ? <ContextBadge context={network.context} /> : "N/A"
      ])}
    />
  );
}

function EnvFilesTable({ envFiles }: { envFiles: ComposeEnvFile[] }) {
  return (
    <SimpleTable
      columns={["Service", "Env file", "Read", "Reason", "Compose file", "Context"]}
      rows={envFiles.map((envFile) => [
        envFile.service ?? "N/A",
        mono(envFile.path ?? "N/A"),
        envFile.read === false ? "no (not read by v1)" : formatBoolean(envFile.read),
        envFile.skipReason ?? "N/A",
        mono(envFile.filePath || "N/A"),
        envFile.context ? <ContextBadge context={envFile.context} /> : "N/A"
      ])}
    />
  );
}

function SecretsTable({ secrets }: { secrets: ComposeSecret[] }) {
  return (
    <SimpleTable
      columns={["Secret", "Service", "File reference", "Field", "Read", "Reason", "Compose file", "Context"]}
      rows={secrets.map((secret) => [
        secret.name ?? "N/A",
        secret.service ?? "N/A",
        mono(secret.file ?? "N/A"),
        secret.fieldPath ?? "N/A",
        secret.read === false ? "no (not read by v1)" : formatBoolean(secret.read),
        secret.skipReason ?? "N/A",
        mono(secret.filePath || "N/A"),
        secret.context ? <ContextBadge context={secret.context} /> : "N/A"
      ])}
    />
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
    error: typeof job.error === "string" ? redactComposeConfigValue(job.error) : job.error,
    result: redactComposeConfigValue(job.result)
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
