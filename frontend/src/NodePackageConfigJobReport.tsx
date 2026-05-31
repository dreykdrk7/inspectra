import type { ReactNode } from "react";

import {
  buildNodePackageConfigAuditReport,
  redactNodePackageConfigValue,
  type NodeDependencyGroup,
  type NodeFindingGroup,
  type NodeLockfileSignal,
  type NodePackageFile,
  type NodePackageFinding,
  type NodePackageManagerSignal,
  type NodePackageOverview,
  type NodePackageScript
} from "./nodePackageConfigReport";
import type { MetadataEntry } from "./pdfReport";
import type { FileRecord, JobRecord, JobStatus } from "./types";

export function NodePackageConfigJobReport({ job, file }: { job: JobRecord; file?: FileRecord }) {
  const report = buildNodePackageConfigAuditReport(job);

  if (!report.isNodePackageConfigAudit) {
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
          Analysis truncated by configured Node package config limits. Review skipped files and rerun with a smaller archive if needed.
        </div>
      ) : null}

      {report.redactedValuesCount > 0 ? (
        <div className="query-warning" role="status">
          Secret-like package-manager values were redacted. Inspectra does not display full npm tokens, passwords, URL credentials, or script secret assignments.
        </div>
      ) : null}

      <ReportSection title="Summary">
        <MetadataList entries={report.summary} empty="No Node package config summary returned yet." />
      </ReportSection>

      <ReportSection title="Package / Workspace Overview">
        {report.packages.length === 0 ? (
          <p className="empty-state">No package overview returned yet.</p>
        ) : (
          <PackageOverviewTable packages={report.packages} />
        )}
      </ReportSection>

      <ReportSection title="Scripts">
        {report.scripts.length === 0 ? (
          <p className="empty-state">No package scripts returned yet.</p>
        ) : (
          <ScriptsTable scripts={report.scripts} />
        )}
      </ReportSection>

      <ReportSection title="Dependency Groups">
        {report.dependencyGroups.length === 0 ? (
          <p className="empty-state">No dependency groups returned yet.</p>
        ) : (
          <DependencyGroups groups={report.dependencyGroups} />
        )}
      </ReportSection>

      <ReportSection title="Package Manager Config Signals">
        {report.packageManagerConfigSignals.length === 0 ? (
          <p className="empty-state">No package manager config signals returned yet.</p>
        ) : (
          <PackageManagerSignalsTable signals={report.packageManagerConfigSignals} />
        )}
      </ReportSection>

      <ReportSection title="Lockfile Signals">
        {report.lockfileSignals.length === 0 ? (
          <p className="empty-state">No lockfile signals returned yet.</p>
        ) : (
          <LockfileSignalsTable signals={report.lockfileSignals} />
        )}
      </ReportSection>

      <ReportSection title="Findings">
        <FindingGroups groups={report.findingGroups} />
      </ReportSection>

      <ReportSection title="Files Detected / Reviewed">
        {report.detectedFiles.length === 0 ? (
          <p className="empty-state">No Node package config candidate files detected or returned yet.</p>
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
          <p className="empty-state">No Node package config redaction notes returned.</p>
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
          <MetadataList entries={report.limits} empty="No Node package config limits returned yet." />
        </ReportSection>
        <ReportSection title="Errors">
          {job.error ? <p className="error-text">{String(redactNodePackageConfigValue(job.error))}</p> : null}
          {report.errors.length > 0 ? (
            <ul className="warning-list">
              {report.errors.map((error) => (
                <li key={error}>{error}</li>
              ))}
            </ul>
          ) : job.error ? null : (
            <p className="empty-state">No Node package config errors reported.</p>
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

function FindingGroups({ groups }: { groups: NodeFindingGroup[] }) {
  if (groups.length === 0) {
    return <p className="empty-state">No heuristic Node package config findings reported.</p>;
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

function FindingCard({ finding }: { finding: NodePackageFinding }) {
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
      <p className="subtle-id">{finding.id}</p>
      {finding.description ? <p>{finding.description}</p> : null}
      {finding.evidence ? <p className="mono evidence-line">{finding.evidence}</p> : null}
      {finding.recommendation ? <p className="muted">{finding.recommendation}</p> : null}
    </article>
  );
}

function PackageOverviewTable({ packages }: { packages: NodePackageOverview[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Manifest</th>
            <th>Name</th>
            <th>Version</th>
            <th>Private</th>
            <th>Package manager</th>
            <th>Workspace</th>
            <th>Context</th>
          </tr>
        </thead>
        <tbody>
          {packages.map((item, index) => (
            <tr key={`${item.path}-${index}`}>
              <td className="mono">{item.path}</td>
              <td>{item.name ?? "N/A"}</td>
              <td>{item.version ?? "N/A"}</td>
              <td>{formatBoolean(item.privateFlag)}</td>
              <td className="mono">{item.packageManager ?? "N/A"}</td>
              <td>{item.workspace ?? "N/A"}</td>
              <td>{item.context ? <ContextBadge context={item.context} /> : "N/A"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ScriptsTable({ scripts }: { scripts: NodePackageScript[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>File</th>
            <th>Script</th>
            <th>Category</th>
            <th>Context</th>
            <th>Excerpt</th>
          </tr>
        </thead>
        <tbody>
          {scripts.map((script, index) => (
            <tr key={`${script.path}-${script.name}-${index}`}>
              <td className="mono">{script.path}</td>
              <td>{script.name}</td>
              <td>{script.category ?? "N/A"}</td>
              <td>{script.context ? <ContextBadge context={script.context} /> : "N/A"}</td>
              <td className="mono">{script.excerpt || "N/A"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DependencyGroups({ groups }: { groups: NodeDependencyGroup[] }) {
  return (
    <div className="finding-list">
      {groups.map((group, index) => (
        <article className="tool-card" key={`${group.path}-${group.group}-${index}`}>
          <div className="tool-card-header">
            <strong>{group.group}</strong>
            <div className="badge-row">
              {group.context ? <ContextBadge context={group.context} /> : null}
              <span className="status-pill">{group.dependencies.length} deps</span>
            </div>
          </div>
          <p className="mono evidence-line">{group.path}</p>
          {group.dependencies.length === 0 ? (
            <p className="empty-state">No dependencies returned in this group.</p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Specifier</th>
                    <th>Source</th>
                    <th>Indicators</th>
                  </tr>
                </thead>
                <tbody>
                  {group.dependencies.map((dependency, dependencyIndex) => (
                    <tr key={`${dependency.name}-${dependencyIndex}`}>
                      <td>{dependency.name}</td>
                      <td className="mono">{dependency.specifier || "N/A"}</td>
                      <td>{dependency.sourceType ?? "N/A"}</td>
                      <td>{dependency.indicators.length > 0 ? dependency.indicators.join(", ") : "N/A"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </article>
      ))}
    </div>
  );
}

function PackageManagerSignalsTable({ signals }: { signals: NodePackageManagerSignal[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>File</th>
            <th>Key</th>
            <th>Value</th>
            <th>Signal</th>
            <th>Context</th>
            <th>Line</th>
          </tr>
        </thead>
        <tbody>
          {signals.map((signal, index) => (
            <tr key={`${signal.path}-${signal.key ?? signal.signal ?? index}`}>
              <td className="mono">{signal.path}</td>
              <td className="mono">{signal.key ?? "N/A"}</td>
              <td className="mono">{signal.value ?? "N/A"}</td>
              <td>{signal.signal ?? "N/A"}</td>
              <td>{signal.context ? <ContextBadge context={signal.context} /> : "N/A"}</td>
              <td>{signal.line ?? "N/A"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function LockfileSignalsTable({ signals }: { signals: NodeLockfileSignal[] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Path</th>
            <th>Lockfile</th>
            <th>Manager</th>
            <th>Read</th>
            <th>Reason</th>
            <th>Size</th>
            <th>Context</th>
          </tr>
        </thead>
        <tbody>
          {signals.map((signal, index) => (
            <tr key={`${signal.path}-${index}`}>
              <td className="mono">{signal.path}</td>
              <td>{signal.lockfile ?? "N/A"}</td>
              <td>{signal.manager ?? "N/A"}</td>
              <td>{signal.read === null ? "N/A" : signal.read ? "yes" : "no"}</td>
              <td>{signal.skipReason ?? "N/A"}</td>
              <td>{signal.sizeBytes === null ? "N/A" : `${signal.sizeBytes} B`}</td>
              <td>{signal.context ? <ContextBadge context={signal.context} /> : "N/A"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FilesTable({ files }: { files: NodePackageFile[] }) {
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
    error: typeof job.error === "string" ? redactNodePackageConfigValue(job.error) : job.error,
    result: redactNodePackageConfigValue(job.result)
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
