import type { ReactNode } from "react";

import {
  buildRedisConfigAuditReport,
  redactRedisConfigValue,
  type RedisConfigFile,
  type RedisFile,
  type RedisFinding,
  type RedisFindingGroup,
  type RedisInclude,
  type RedisSensitiveFile,
  type RedisSetting
} from "./redisConfigReport";
import type { MetadataEntry } from "./pdfReport";
import { PassiveReportShell } from "./PassiveReportShell";
import type { FileRecord, JobRecord } from "./types";

export function RedisConfigJobReport({ job, file }: { job: JobRecord; file?: FileRecord }) {
  const report = buildRedisConfigAuditReport(job);

  if (!report.isRedisConfigAudit) {
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
          Analysis truncated by configured Redis config limits. Review skipped files and rerun with a smaller archive if needed.
        </div>
      ) : null}

      {report.redactedValuesCount > 0 ? (
        <div className="query-warning" role="status">
          Secret-like Redis values were redacted. Inspectra does not display requirepass, masterauth, Sentinel auth-pass, Redis URL
          passwords, ACL material, dump/AOF-like values, private keys, tokens, or sensitive adjacent file contents.
        </div>
      ) : null}

      <ReportSection title="Summary">
        <MetadataList entries={report.summary} empty="No Redis config summary returned yet." />
      </ReportSection>

      <ReportSection title="Files / Configs Detected">
        {report.detectedFiles.length === 0 ? (
          <p className="empty-state">No Redis config candidate files detected or returned yet.</p>
        ) : (
          <FilesTable files={report.detectedFiles} />
        )}
        {report.reviewedFiles.length > 0 ? (
          <>
            <h4>Reviewed files</h4>
            <FilesTable files={report.reviewedFiles} />
          </>
        ) : null}
        {report.configs.length > 0 ? (
          <>
            <h4>Configs</h4>
            <ConfigsTable configs={report.configs} />
          </>
        ) : null}
      </ReportSection>

      <ReportSection title="Redis Settings">
        {report.redisSettings.length === 0 ? <p className="empty-state">No Redis settings returned yet.</p> : <SettingsTable settings={report.redisSettings} />}
      </ReportSection>

      <ReportSection title="Sentinel Settings">
        {report.sentinelSettings.length === 0 ? (
          <p className="empty-state">No Redis Sentinel settings returned yet.</p>
        ) : (
          <SettingsTable settings={report.sentinelSettings} />
        )}
      </ReportSection>

      <ReportSection title="Includes">
        <p className="muted">Redis include directives are shown as detected context. v1 does not resolve includes or read host paths.</p>
        {report.includes.length === 0 ? <p className="empty-state">No Redis include directives returned yet.</p> : <IncludesTable includes={report.includes} />}
      </ReportSection>

      <ReportSection title="ACL / Dumps / AOF / Backups">
        <p className="muted">Sensitive adjacent files are detected but not read by v1. This includes ACL files, .env files, RDB dumps, AOF files, appendonly directories, and backups.</p>
        {report.aclFiles.length === 0 ? <p className="empty-state">No Redis ACL files returned yet.</p> : <SensitiveFilesTable files={report.aclFiles} />}
        {report.dumpOrAofFiles.length > 0 ? (
          <>
            <h4>Dumps, AOF, appendonly, and backups</h4>
            <SensitiveFilesTable files={report.dumpOrAofFiles} />
          </>
        ) : (
          <p className="empty-state">No Redis dumps, AOF files, appendonly entries, or backups returned yet.</p>
        )}
      </ReportSection>

      <ReportSection title="Findings">
        <FindingGroups groups={report.findingGroups} />
      </ReportSection>

      <ReportSection title="Redaction Notes">
        {report.redactionNotes.length === 0 ? (
          <p className="empty-state">No Redis config redaction notes returned.</p>
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
          <MetadataList entries={report.limits} empty="No Redis config limits returned yet." />
        </ReportSection>
        <ReportSection title="Errors">
          {job.error ? <p className="error-text">{String(redactRedisConfigValue(job.error))}</p> : null}
          {report.errors.length > 0 ? (
            <ul className="warning-list">
              {report.errors.map((error, index) => (
                <li key={`${index}-${error}`}>{error}</li>
              ))}
            </ul>
          ) : job.error ? null : (
            <p className="empty-state">No Redis config errors reported.</p>
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

function FindingGroups({ groups }: { groups: RedisFindingGroup[] }) {
  if (groups.length === 0) {
    return <p className="empty-state">No heuristic Redis config findings reported.</p>;
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

function FindingCard({ finding }: { finding: RedisFinding }) {
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
      {finding.configType || finding.directive || finding.setting || finding.address || finding.port || finding.path ? (
        <p className="muted">
          {[
            finding.configType ? `config: ${finding.configType}` : null,
            finding.directive ? `directive: ${finding.directive}` : null,
            finding.setting ? `setting: ${finding.setting}` : null,
            finding.address ? `address: ${finding.address}` : null,
            finding.port ? `port: ${finding.port}` : null,
            finding.path ? `path: ${finding.path}` : null
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

function FilesTable({ files }: { files: RedisFile[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Path</th>
            <th>Category</th>
            <th>Config</th>
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
              <td>{item.configType ?? "N/A"}</td>
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

function ConfigsTable({ configs }: { configs: RedisConfigFile[] }) {
  return (
    <SimpleTable
      columns={["Path", "Config type", "Context"]}
      rows={configs.map((config) => [
        mono(config.path || "N/A"),
        config.configType ?? "N/A",
        config.context ? <ContextBadge context={config.context} /> : "N/A"
      ])}
    />
  );
}

function SettingsTable({ settings }: { settings: RedisSetting[] }) {
  return (
    <SimpleTable
      columns={["Config", "Directive", "Setting", "Safe value", "File", "Line", "Context"]}
      rows={settings.map((setting) => [
        setting.configType ?? "N/A",
        setting.directive ?? "N/A",
        setting.setting ?? "N/A",
        mono(setting.value ?? "N/A"),
        mono(setting.filePath || "N/A"),
        setting.line === null ? "N/A" : String(setting.line),
        setting.context ? <ContextBadge context={setting.context} /> : "N/A"
      ])}
    />
  );
}

function IncludesTable({ includes }: { includes: RedisInclude[] }) {
  return (
    <SimpleTable
      columns={["Directive", "Target", "Resolved", "Config", "File", "Line", "Context"]}
      rows={includes.map((include) => [
        include.directive ?? "N/A",
        mono(include.target ?? "N/A"),
        include.resolved === false ? "no (not resolved by v1)" : formatBoolean(include.resolved),
        include.configType ?? "N/A",
        mono(include.filePath || "N/A"),
        include.line === null ? "N/A" : String(include.line),
        include.context ? <ContextBadge context={include.context} /> : "N/A"
      ])}
    />
  );
}

function SensitiveFilesTable({ files }: { files: RedisSensitiveFile[] }) {
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
    error: typeof job.error === "string" ? redactRedisConfigValue(job.error) : job.error,
    result: redactRedisConfigValue(job.result)
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
