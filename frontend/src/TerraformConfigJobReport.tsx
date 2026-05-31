import type { ReactNode } from "react";

import {
  buildTerraformConfigAuditReport,
  redactTerraformConfigValue,
  type TerraformBackend,
  type TerraformFile,
  type TerraformFinding,
  type TerraformFindingGroup,
  type TerraformModule,
  type TerraformProvider,
  type TerraformResource,
  type TerraformStateFile,
  type TerraformVariable
} from "./terraformConfigReport";
import type { MetadataEntry } from "./pdfReport";
import type { FileRecord, JobRecord, JobStatus } from "./types";

export function TerraformConfigJobReport({ job, file }: { job: JobRecord; file?: FileRecord }) {
  const report = buildTerraformConfigAuditReport(job);

  if (!report.isTerraformConfigAudit) {
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
        Passive archive-only Terraform/OpenTofu/Terragrunt IaC review. Inspectra does not execute Terraform, run init/validate/plan/apply, download providers or modules, call cloud APIs, access remote state, analyze drift, query CVEs, or confirm exploitability. State files are detected but not read.
      </div>

      {report.truncated ? (
        <div className="alert" role="status">
          Analysis truncated by configured Terraform config limits. Review skipped files and rerun with a smaller archive if needed.
        </div>
      ) : null}

      {report.redactedValuesCount > 0 ? (
        <div className="query-warning" role="status">
          Secret-like Terraform values were redacted. Inspectra does not display tfvars/default/output values, provider/backend credentials, state contents, user_data secrets, URL credentials, tokens, passwords, access keys, or private key material.
        </div>
      ) : null}

      <ReportSection title="Summary">
        <MetadataList entries={report.summary} empty="No Terraform config summary returned yet." />
      </ReportSection>

      <ReportSection title="Files Detected / Reviewed">
        {report.detectedFiles.length === 0 ? (
          <p className="empty-state">No Terraform config candidate files detected or returned yet.</p>
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

      <ReportSection title="Providers / Backends">
        {report.providers.length === 0 ? (
          <p className="empty-state">No Terraform providers returned yet.</p>
        ) : (
          <ProvidersTable providers={report.providers} />
        )}
        {report.backends.length > 0 ? (
          <>
            <h4>Backends</h4>
            <BackendsTable backends={report.backends} />
          </>
        ) : (
          <p className="empty-state">No Terraform backends returned yet.</p>
        )}
      </ReportSection>

      <ReportSection title="Modules">
        {report.modules.length === 0 ? <p className="empty-state">No Terraform modules returned yet.</p> : <ModulesTable modules={report.modules} />}
      </ReportSection>

      <ReportSection title="Resources">
        {report.resources.length === 0 ? (
          <p className="empty-state">No Terraform resources returned yet.</p>
        ) : (
          <ResourcesTable resources={report.resources} />
        )}
      </ReportSection>

      <ReportSection title="Variables / Outputs">
        {report.variables.length === 0 ? (
          <p className="empty-state">No Terraform variables returned yet.</p>
        ) : (
          <VariablesTable variables={report.variables} />
        )}
        {report.outputs.length > 0 ? (
          <>
            <h4>Outputs</h4>
            <VariablesTable variables={report.outputs} />
          </>
        ) : (
          <p className="empty-state">No Terraform outputs returned yet.</p>
        )}
      </ReportSection>

      <ReportSection title="State Files">
        <p className="muted">Terraform state files are detected but not read.</p>
        {report.stateFiles.length === 0 ? (
          <p className="empty-state">No Terraform state files returned yet.</p>
        ) : (
          <StateFilesTable stateFiles={report.stateFiles} />
        )}
      </ReportSection>

      <ReportSection title="Findings">
        <FindingGroups groups={report.findingGroups} />
      </ReportSection>

      <ReportSection title="Redaction Notes">
        {report.redactionNotes.length === 0 ? (
          <p className="empty-state">No Terraform config redaction notes returned.</p>
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
          <MetadataList entries={report.limits} empty="No Terraform config limits returned yet." />
        </ReportSection>
        <ReportSection title="Errors">
          {job.error ? <p className="error-text">{String(redactTerraformConfigValue(job.error))}</p> : null}
          {report.errors.length > 0 ? (
            <ul className="warning-list">
              {report.errors.map((error) => (
                <li key={error}>{error}</li>
              ))}
            </ul>
          ) : job.error ? null : (
            <p className="empty-state">No Terraform config errors reported.</p>
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

function FindingGroups({ groups }: { groups: TerraformFindingGroup[] }) {
  if (groups.length === 0) {
    return <p className="empty-state">No heuristic Terraform config findings reported.</p>;
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

function FindingCard({ finding }: { finding: TerraformFinding }) {
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
      {finding.resourceType || finding.resourceName || finding.blockType || finding.fieldPath ? (
        <p className="muted">
          {[
            finding.resourceType ? `resource type: ${finding.resourceType}` : null,
            finding.resourceName ? `resource: ${finding.resourceName}` : null,
            finding.blockType ? `block: ${finding.blockType}` : null,
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

function ProvidersTable({ providers }: { providers: TerraformProvider[] }) {
  return (
    <SimpleTable
      columns={["File", "Provider", "Source", "Version", "Context"]}
      rows={providers.map((provider) => [
        mono(provider.filePath),
        provider.name ?? "N/A",
        mono(provider.source ?? "N/A"),
        provider.version ?? "N/A",
        provider.context ? <ContextBadge context={provider.context} /> : "N/A"
      ])}
    />
  );
}

function BackendsTable({ backends }: { backends: TerraformBackend[] }) {
  return (
    <SimpleTable
      columns={["File", "Type", "Config keys", "Context"]}
      rows={backends.map((backend) => [
        mono(backend.filePath),
        backend.type ?? "N/A",
        backend.configKeys.length > 0 ? backend.configKeys.join(", ") : "N/A",
        backend.context ? <ContextBadge context={backend.context} /> : "N/A"
      ])}
    />
  );
}

function ModulesTable({ modules }: { modules: TerraformModule[] }) {
  return (
    <SimpleTable
      columns={["File", "Module", "Source", "Version", "Ref", "Context"]}
      rows={modules.map((module) => [
        mono(module.filePath),
        module.name ?? "N/A",
        mono(module.source ?? "N/A"),
        module.version ?? "N/A",
        module.ref ?? "N/A",
        module.context ? <ContextBadge context={module.context} /> : "N/A"
      ])}
    />
  );
}

function ResourcesTable({ resources }: { resources: TerraformResource[] }) {
  return (
    <SimpleTable
      columns={["File", "Provider", "Type", "Name", "Context"]}
      rows={resources.map((resource) => [
        mono(resource.filePath),
        resource.provider ?? "N/A",
        resource.resourceType ?? "N/A",
        resource.resourceName ?? "N/A",
        resource.context ? <ContextBadge context={resource.context} /> : "N/A"
      ])}
    />
  );
}

function VariablesTable({ variables }: { variables: TerraformVariable[] }) {
  return (
    <SimpleTable
      columns={["File", "Kind", "Name", "Sensitive", "Default present", "Context"]}
      rows={variables.map((variable) => [
        mono(variable.filePath),
        variable.kind,
        variable.name ?? "N/A",
        formatBoolean(variable.sensitive),
        formatBoolean(variable.defaultPresent),
        variable.context ? <ContextBadge context={variable.context} /> : "N/A"
      ])}
    />
  );
}

function StateFilesTable({ stateFiles }: { stateFiles: TerraformStateFile[] }) {
  return (
    <SimpleTable
      columns={["Path", "Category", "Read", "Reason", "Context"]}
      rows={stateFiles.map((stateFile) => [
        mono(stateFile.path),
        stateFile.category,
        stateFile.read ? "yes" : "no",
        stateFile.skipReason ?? "state_file_not_read",
        stateFile.context ? <ContextBadge context={stateFile.context} /> : "N/A"
      ])}
    />
  );
}

function FilesTable({ files }: { files: TerraformFile[] }) {
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
    error: typeof job.error === "string" ? redactTerraformConfigValue(job.error) : job.error,
    result: redactTerraformConfigValue(job.result)
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
