import type { ReactNode } from "react";

import type { MetadataEntry } from "./pdfReport";
import { PassiveReportShell } from "./PassiveReportShell";
import {
  buildSqlDatabaseConfigAuditReport,
  redactSqlDatabaseConfigValue,
  type SqlDatabaseConfigFile,
  type SqlDatabaseFile,
  type SqlDatabaseFinding,
  type SqlDatabaseFindingGroup,
  type SqlDatabaseInclude,
  type SqlDatabaseNoReadFile,
  type SqlDatabasePgHbaRule,
  type SqlDatabaseSetting
} from "./sqlDatabaseConfigReport";
import type { FileRecord, JobRecord } from "./types";

export function SqlDatabaseConfigJobReport({ job, file }: { job: JobRecord; file?: FileRecord }) {
  const report = buildSqlDatabaseConfigAuditReport(job);

  if (!report.isSqlDatabaseConfigAudit) {
    return (
      <div className="result-layout">
        <p className="muted">No readable report is available for this audit type yet.</p>
        <RawJson job={job} />
      </div>
    );
  }

  return (
    <PassiveReportShell
      job={job}
      file={file}
      analyzer={report.analyzer}
      archiveType={report.archiveType}
      overview={report.overview}
      findingsCount={report.findingsCount}
      isSparse={report.summary.length === 0}
      rawJson={<RawJson job={job} />}
    >
      {report.truncated ? (
        <div className="alert" role="status">
          Analysis truncated by configured SQL database config limits. Review skipped files and rerun with a smaller archive if needed.
        </div>
      ) : null}

      {report.redactedValuesCount > 0 ? (
        <div className="query-warning" role="status">
          Secret-like SQL database values were redacted. Inspectra does not display passwords, connection strings, PGPASSWORD or
          MYSQL_PWD values, replication passwords, private keys, credential-file contents, env file contents, dump rows, or data files.
        </div>
      ) : null}

      <ReportSection title="Summary">
        <MetadataList entries={report.summary} empty="No SQL database config summary returned yet." />
      </ReportSection>

      <ReportSection title="Files Detected / Reviewed">
        {report.detectedFiles.length === 0 ? (
          <p className="empty-state">No SQL database candidate files detected or returned yet.</p>
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

      <ReportSection title="Engine / Config Overview">
        {report.postgresConfigs.length === 0 && report.mysqlConfigs.length === 0 ? (
          <p className="empty-state">No SQL database config overview returned yet.</p>
        ) : (
          <>
            {report.postgresConfigs.length > 0 ? (
              <>
                <h4>PostgreSQL config files</h4>
                <ConfigFilesTable files={report.postgresConfigs} />
              </>
            ) : null}
            {report.mysqlConfigs.length > 0 ? (
              <>
                <h4>MySQL / MariaDB config files</h4>
                <ConfigFilesTable files={report.mysqlConfigs} />
              </>
            ) : null}
          </>
        )}
      </ReportSection>

      <ReportSection title="PostgreSQL Configs">
        {report.postgresConfigs.length === 0 ? <p className="empty-state">No PostgreSQL configs returned yet.</p> : <ConfigFilesTable files={report.postgresConfigs} />}
      </ReportSection>

      <ReportSection title="PostgreSQL pg_hba.conf Rules">
        {report.postgresHbaRules.length === 0 ? <p className="empty-state">No pg_hba.conf rules returned yet.</p> : <PgHbaRulesTable rules={report.postgresHbaRules} />}
      </ReportSection>

      <ReportSection title="MySQL / MariaDB Configs">
        {report.mysqlConfigs.length === 0 ? <p className="empty-state">No MySQL or MariaDB configs returned yet.</p> : <ConfigFilesTable files={report.mysqlConfigs} />}
      </ReportSection>

      <ReportSection title="Database Settings">
        {report.databaseSettings.length === 0 ? (
          <p className="empty-state">No SQL database settings returned yet.</p>
        ) : (
          <SettingsTable settings={report.databaseSettings} />
        )}
      </ReportSection>

      <ReportSection title="Includes Detected / Not Resolved">
        <p className="muted">SQL database include directives are shown as detected context. v1 does not resolve includes or read host paths.</p>
        {report.includes.length === 0 ? <p className="empty-state">No SQL database include directives returned yet.</p> : <IncludesTable includes={report.includes} />}
      </ReportSection>

      <ReportSection title="Sensitive Files Detected / Not Read">
        <p className="muted">.env, .pgpass, .my.cnf, .mylogin.cnf, private key, certificate, and credential-adjacent files are detected but not read by v1.</p>
        {report.sensitiveFiles.length === 0 ? <p className="empty-state">No sensitive SQL database adjacent files returned yet.</p> : <NoReadFilesTable files={report.sensitiveFiles} />}
      </ReportSection>

      <ReportSection title="Dumps / Backups Detected / Not Read">
        <p className="muted">SQL dumps and backup files are detected as review context and are not read by v1.</p>
        {report.dumpOrBackupFiles.length === 0 ? (
          <p className="empty-state">No SQL database dumps or backups returned yet.</p>
        ) : (
          <NoReadFilesTable files={report.dumpOrBackupFiles} />
        )}
      </ReportSection>

      <ReportSection title="Data / WAL / Binlog / InnoDB Files Detected / Not Read">
        <p className="muted">Database data, WAL, binlog, and InnoDB files are detected as sensitive adjacent files and are not read by v1.</p>
        {report.dataFiles.length === 0 ? <p className="empty-state">No SQL database data files returned yet.</p> : <NoReadFilesTable files={report.dataFiles} />}
      </ReportSection>

      <ReportSection title="Findings">
        <FindingGroups groups={report.findingGroups} />
      </ReportSection>

      <ReportSection title="Redaction Notes">
        {report.redactionNotes.length === 0 ? (
          <p className="empty-state">No SQL database config redaction notes returned.</p>
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
          <MetadataList entries={report.limits} empty="No SQL database config limits returned yet." />
        </ReportSection>
        <ReportSection title="Errors">
          {job.error ? <p className="error-text">{String(redactSqlDatabaseConfigValue(job.error))}</p> : null}
          {report.errors.length > 0 ? (
            <ul className="warning-list">
              {report.errors.map((error, index) => (
                <li key={`${index}-${error}`}>{error}</li>
              ))}
            </ul>
          ) : job.error ? null : (
            <p className="empty-state">No SQL database config errors reported.</p>
          )}
        </ReportSection>
      </div>
    </PassiveReportShell>
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

function MetadataList({ entries, empty }: { entries: MetadataEntry[]; empty: string }) {
  if (entries.length === 0) {
    return <p className="empty-state">{empty}</p>;
  }
  return (
    <dl className="summary-list">
      {entries.map((entry) => (
        <MetadataRow key={entry.label} label={entry.label} value={entry.value} />
      ))}
    </dl>
  );
}

function FindingGroups({ groups }: { groups: SqlDatabaseFindingGroup[] }) {
  if (groups.length === 0) {
    return <p className="empty-state">No heuristic SQL database config findings reported.</p>;
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

function FindingCard({ finding }: { finding: SqlDatabaseFinding }) {
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

function FilesTable({ files }: { files: SqlDatabaseFile[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Path</th>
            <th>Category</th>
            <th>Engine</th>
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
              <td>{item.engine ?? "N/A"}</td>
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

function ConfigFilesTable({ files }: { files: SqlDatabaseConfigFile[] }) {
  return (
    <SimpleTable
      columns={["File", "Category", "Engine", "Context", "Read", "Bytes read", "Settings"]}
      rows={files.map((file) => [
        mono(file.filePath || "N/A"),
        file.category ?? "N/A",
        file.engine ?? "N/A",
        file.context ? <ContextBadge context={file.context} /> : "N/A",
        file.read === null ? "N/A" : file.read ? "yes" : "no",
        file.bytesRead === null ? "N/A" : `${file.bytesRead} B`,
        file.settingsCount === null ? "N/A" : String(file.settingsCount)
      ])}
    />
  );
}

function SettingsTable({ settings }: { settings: SqlDatabaseSetting[] }) {
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

function PgHbaRulesTable({ rules }: { rules: SqlDatabasePgHbaRule[] }) {
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

function IncludesTable({ includes }: { includes: SqlDatabaseInclude[] }) {
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

function NoReadFilesTable({ files }: { files: SqlDatabaseNoReadFile[] }) {
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

function RawJson({ job }: { job: JobRecord }) {
  const redactedJob = {
    ...job,
    error: typeof job.error === "string" ? redactSqlDatabaseConfigValue(job.error) : job.error,
    result: redactSqlDatabaseConfigValue(job.result)
  };
  return (
    <details className="raw-json">
      <summary>Show redacted payload</summary>
      <pre>{JSON.stringify(redactedJob, null, 2)}</pre>
    </details>
  );
}

function formatBoolean(value: boolean | null): string {
  return value === null ? "N/A" : value ? "yes" : "no";
}
