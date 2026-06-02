import type { ReactNode } from "react";

import {
  buildDatabaseConfigAuditReport,
  redactDatabaseConfigValue,
  type DatabaseDumpOrBackupFile,
  type DatabaseEngine,
  type DatabaseFile,
  type DatabaseFinding,
  type DatabaseFindingGroup,
  type DatabaseInclude,
  type DatabasePgHbaRule,
  type DatabaseSetting
} from "./databaseConfigReport";
import type { MetadataEntry } from "./pdfReport";
import type { FileRecord, JobRecord, JobStatus } from "./types";

export function DatabaseConfigJobReport({ job, file }: { job: JobRecord; file?: FileRecord }) {
  const report = buildDatabaseConfigAuditReport(job);

  if (!report.isDatabaseConfigAudit) {
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
        Passive archive-only database config review. Inspectra does not start PostgreSQL, MySQL, or MariaDB, execute DB clients, connect
        to databases, validate credentials, run queries, parse dumps, read .env/.pgpass/.my.cnf/.mylogin.cnf contents, resolve includes,
        or claim runtime truth. Findings are heuristic review indicators requiring human review.
      </div>

      {report.truncated ? (
        <div className="alert" role="status">
          Analysis truncated by configured Database config limits. Review skipped files and rerun with a smaller archive if needed.
        </div>
      ) : null}

      {report.redactedValuesCount > 0 ? (
        <div className="query-warning" role="status">
          Secret-like database values were redacted. Inspectra does not display passwords, DSNs, connection strings, PGPASSWORD or
          MYSQL_PWD values, private keys, credential-file contents, env file contents, or dump contents.
        </div>
      ) : null}

      <ReportSection title="Summary">
        <MetadataList entries={report.summary} empty="No Database config summary returned yet." />
      </ReportSection>

      <ReportSection title="Files Detected / Reviewed">
        {report.detectedFiles.length === 0 ? (
          <p className="empty-state">No Database candidate files detected or returned yet.</p>
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

      <ReportSection title="Engines Detected">
        {report.engines.length === 0 ? <p className="empty-state">No database engines returned yet.</p> : <EnginesTable engines={report.engines} />}
      </ReportSection>

      <ReportSection title="PostgreSQL Settings">
        {report.postgresSettings.length === 0 ? (
          <p className="empty-state">No PostgreSQL settings returned yet.</p>
        ) : (
          <SettingsTable settings={report.postgresSettings} />
        )}
      </ReportSection>

      <ReportSection title="pg_hba.conf Rules">
        {report.pgHbaRules.length === 0 ? <p className="empty-state">No pg_hba.conf rules returned yet.</p> : <PgHbaRulesTable rules={report.pgHbaRules} />}
      </ReportSection>

      <ReportSection title="MySQL / MariaDB Settings">
        {report.mysqlSettings.length === 0 ? (
          <p className="empty-state">No MySQL or MariaDB settings returned yet.</p>
        ) : (
          <SettingsTable settings={report.mysqlSettings} />
        )}
      </ReportSection>

      <ReportSection title="Includes">
        <p className="muted">Database include directives are shown as detected context. v1 does not resolve includes or read host paths.</p>
        {report.includes.length === 0 ? <p className="empty-state">No database include directives returned yet.</p> : <IncludesTable includes={report.includes} />}
      </ReportSection>

      <ReportSection title="Dumps / Backups and Credential Files">
        <p className="muted">.env, .pgpass, .my.cnf, .mylogin.cnf, SQL dumps, and backup files are shown as detected context and are not read by v1.</p>
        {report.dumpOrBackupFiles.length === 0 ? (
          <p className="empty-state">No database dumps, backups, or credential files returned yet.</p>
        ) : (
          <DumpOrBackupFilesTable files={report.dumpOrBackupFiles} />
        )}
      </ReportSection>

      <ReportSection title="Findings">
        <FindingGroups groups={report.findingGroups} />
      </ReportSection>

      <ReportSection title="Redaction Notes">
        {report.redactionNotes.length === 0 ? (
          <p className="empty-state">No Database config redaction notes returned.</p>
        ) : (
          <ul className="warning-list">
            {report.redactionNotes.map((note, index) => (
              <li key={`${index}-${note}`}>{note}</li>
            ))}
          </ul>
        )}
      </ReportSection>

      <div className="report-grid">
        <ReportSection title="Limits / Truncation">
          <MetadataList entries={report.limits} empty="No Database config limits returned yet." />
        </ReportSection>
        <ReportSection title="Errors">
          {job.error ? <p className="error-text">{String(redactDatabaseConfigValue(job.error))}</p> : null}
          {report.errors.length > 0 ? (
            <ul className="warning-list">
              {report.errors.map((error, index) => (
                <li key={`${index}-${error}`}>{error}</li>
              ))}
            </ul>
          ) : job.error ? null : (
            <p className="empty-state">No Database config errors reported.</p>
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

function FindingGroups({ groups }: { groups: DatabaseFindingGroup[] }) {
  if (groups.length === 0) {
    return <p className="empty-state">No heuristic Database config findings reported.</p>;
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

function FindingCard({ finding }: { finding: DatabaseFinding }) {
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
      {finding.engine || finding.section || finding.setting || finding.authMethod || finding.address ? (
        <p className="muted">
          {[
            finding.engine ? `engine: ${finding.engine}` : null,
            finding.section ? `section: ${finding.section}` : null,
            finding.setting ? `setting: ${finding.setting}` : null,
            finding.authMethod ? `auth: ${finding.authMethod}` : null,
            finding.address ? `address: ${finding.address}` : null
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

function FilesTable({ files }: { files: DatabaseFile[] }) {
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

function EnginesTable({ engines }: { engines: DatabaseEngine[] }) {
  return (
    <SimpleTable
      columns={["Engine", "File", "Context", "Files"]}
      rows={engines.map((engine) => [
        engine.engine,
        mono(engine.filePath || "N/A"),
        engine.context ? <ContextBadge context={engine.context} /> : "N/A",
        engine.filesCount === null ? "N/A" : String(engine.filesCount)
      ])}
    />
  );
}

function SettingsTable({ settings }: { settings: DatabaseSetting[] }) {
  return (
    <SimpleTable
      columns={["Engine", "Section", "Setting", "Safe value", "File", "Line", "Context"]}
      rows={settings.map((setting) => [
        setting.engine ?? "N/A",
        setting.section ?? "N/A",
        setting.setting ?? "N/A",
        mono(setting.value ?? "N/A"),
        mono(setting.filePath || "N/A"),
        setting.line === null ? "N/A" : String(setting.line),
        setting.context ? <ContextBadge context={setting.context} /> : "N/A"
      ])}
    />
  );
}

function PgHbaRulesTable({ rules }: { rules: DatabasePgHbaRule[] }) {
  return (
    <SimpleTable
      columns={["Type", "Database", "User", "Address", "Auth method", "File", "Line", "Context"]}
      rows={rules.map((rule) => [
        rule.type ?? "N/A",
        rule.database ?? "N/A",
        rule.user ?? "N/A",
        mono(rule.address ?? "N/A"),
        rule.authMethod ?? "N/A",
        mono(rule.filePath || "N/A"),
        rule.line === null ? "N/A" : String(rule.line),
        rule.context ? <ContextBadge context={rule.context} /> : "N/A"
      ])}
    />
  );
}

function IncludesTable({ includes }: { includes: DatabaseInclude[] }) {
  return (
    <SimpleTable
      columns={["Directive", "Target", "Resolved", "Engine", "File", "Line", "Context"]}
      rows={includes.map((include) => [
        include.directive ?? "N/A",
        mono(include.target ?? "N/A"),
        include.resolved === false ? "no (not resolved by v1)" : formatBoolean(include.resolved),
        include.engine ?? "N/A",
        mono(include.filePath || "N/A"),
        include.line === null ? "N/A" : String(include.line),
        include.context ? <ContextBadge context={include.context} /> : "N/A"
      ])}
    />
  );
}

function DumpOrBackupFilesTable({ files }: { files: DatabaseDumpOrBackupFile[] }) {
  return (
    <SimpleTable
      columns={["Path", "Category", "Read", "Reason", "Size", "Context"]}
      rows={files.map((file) => [
        mono(file.path || "N/A"),
        file.category,
        file.read === false ? "no (not read by v1)" : formatBoolean(file.read),
        file.skipReason ?? "N/A",
        file.sizeBytes === null ? "N/A" : `${file.sizeBytes} B`,
        file.context ? <ContextBadge context={file.context} /> : "N/A"
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
    error: typeof job.error === "string" ? redactDatabaseConfigValue(job.error) : job.error,
    result: redactDatabaseConfigValue(job.result)
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
