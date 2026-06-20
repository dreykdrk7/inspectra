import type { ReactNode } from "react";

import {
  buildProjectArchiveAuditReport,
  type ProjectArchiveEcosystemSummary,
  type ParsedProjectManifest,
  type ProjectArchiveFinding,
  type ProjectArchiveManifest
} from "./projectArchiveReport";
import type { MetadataEntry } from "./pdfReport";
import type { FileRecord, JobRecord, JobStatus } from "./types";

export function ProjectArchiveJobReport({ job, file }: { job: JobRecord; file?: FileRecord }) {
  const report = buildProjectArchiveAuditReport(job, file);

  if (!report.isProjectArchiveAudit) {
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
          <MetadataRow label="Archive type" value={report.archiveType ?? "Not available"} />
          <MetadataRow label="Job ID" value={job.id} mono />
          <MetadataRow label="File ID" value={job.file_id ?? "N/A"} mono />
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
        <ReportSection title="Archive File">
          <dl className="summary-list">
            <MetadataRow label="Original name" value={report.fileInfo.originalFilename ?? "Not available"} />
            <MetadataRow label="Size" value={report.fileInfo.sizeBytes === null ? "Not available" : formatBytes(report.fileInfo.sizeBytes)} />
          </dl>
        </ReportSection>
      </div>

      <div className="report-grid">
        <ReportSection title="Project Archive Metrics">
          <MetadataList entries={report.summary} empty="No project archive metrics returned yet." />
        </ReportSection>
        <ReportSection title="Limits">
          <MetadataList entries={report.limits} empty="No limits returned." />
        </ReportSection>
      </div>

      <ReportSection title="Ecosystem Summary">
        <EcosystemSummaryList entries={report.ecosystemSummary} />
      </ReportSection>

      <ReportSection title="Supported Manifests">
        <ManifestList manifests={report.supportedManifests} empty="No supported manifests detected." />
      </ReportSection>

      <ReportSection title="Unsupported Manifests Detected">
        <ManifestList manifests={report.unsupportedManifests} empty="No unsupported manifest filenames detected." />
      </ReportSection>

      <ReportSection title="Parsed Manifests">
        {report.parsedManifests.length === 0 ? (
          <p className="empty-state">No manifests were parsed.</p>
        ) : (
          <div className="dependency-groups">
            {report.parsedManifests.map((manifest) => (
              <ParsedManifestCard manifest={manifest} key={`${manifest.path}-${manifest.manifestType}`} />
            ))}
          </div>
        )}
      </ReportSection>

      <ReportSection title="Informational Findings">
        {report.findings.length === 0 ? (
          <p className="empty-state">No informational findings reported.</p>
        ) : (
          <div className="dependency-groups">
            {groupFindingsByEcosystem(report.findings).map((group) => (
              <div className="finding-group" key={group.ecosystem}>
                <div className="tool-card-header">
                  <h4>{group.ecosystemLabel}</h4>
                  <span className="tool-badge not_run">{group.findings.length} findings</span>
                </div>
                <div className="finding-list">
                  {group.findings.map((finding, index) => (
                    <FindingCard key={`${finding.id}-${index}`} finding={finding} />
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </ReportSection>

      <ReportSection title="Errors">
        {job.error ? <p className="error-text">{job.error}</p> : null}
        {report.errors.length > 0 ? (
          <ul className="warning-list">
            {report.errors.map((error) => (
              <li key={error}>{error}</li>
            ))}
          </ul>
        ) : job.error ? null : (
          <p className="empty-state">No project archive parser errors reported.</p>
        )}
      </ReportSection>

      <RawJson job={job} />
    </div>
  );
}

function EcosystemSummaryList({ entries }: { entries: ProjectArchiveEcosystemSummary[] }) {
  if (entries.length === 0) {
    return <p className="empty-state">No ecosystem finding summary returned.</p>;
  }
  return (
    <dl className="summary-list">
      {entries.map((entry) => (
        <MetadataRow key={entry.ecosystem} label={entry.ecosystemLabel} value={`${entry.findingsCount} findings`} />
      ))}
    </dl>
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
        <MetadataRow key={entry.label} label={entry.label} value={formatMetadataValue(entry)} mono={monoValues} />
      ))}
    </dl>
  );
}

function ManifestList({ manifests, empty }: { manifests: ProjectArchiveManifest[]; empty: string }) {
  if (manifests.length === 0) {
    return <p className="empty-state">{empty}</p>;
  }
  return (
    <div className="dependency-list">
      {manifests.map((manifest) => (
        <div className="dependency-row" key={`${manifest.path}-${manifest.manifestType}-${manifest.reason ?? ""}`}>
          <strong>{manifest.manifestType}</strong>
          <span className="mono">{manifest.path}</span>
          <span className="muted">{manifest.status ?? manifest.reason ?? "detected"}</span>
        </div>
      ))}
    </div>
  );
}

function ParsedManifestCard({ manifest }: { manifest: ParsedProjectManifest }) {
  return (
    <article className="tool-card">
      <div className="tool-card-header">
        <strong className="mono">{manifest.path}</strong>
        <span className="tool-badge ok">{manifest.manifestType}</span>
      </div>
      <dl className="compact-list">
        <MetadataRow label="Size" value={manifest.sizeBytes === null ? "N/A" : formatBytes(manifest.sizeBytes)} />
      </dl>
      <MetadataList entries={manifest.project} empty="No project metadata extracted." />
      {manifest.scripts.length > 0 ? (
        <>
          <h4 className="compact-heading">Scripts</h4>
          <MetadataList entries={manifest.scripts} empty="No scripts detected." />
        </>
      ) : null}
      {manifest.dependencies.length > 0 ? (
        <div className="dependency-groups">
          {manifest.dependencies.map((group) => (
            <div className="dependency-group-inline" key={`${manifest.path}-${group.name}`}>
              <div className="tool-card-header">
                <strong>{group.name}</strong>
                <span className="tool-badge not_run">{group.dependencies.length} deps</span>
              </div>
              <div className="dependency-list">
                {group.dependencies.map((dependency, index) => (
                  <div className="dependency-row" key={`${dependency.name}-${index}`}>
                    <strong>{dependency.name}</strong>
                    <span className="mono">{dependency.specifier || "no specifier"}</span>
                    <span className="muted">{dependency.source ?? ""}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      ) : null}
      {manifest.errors.length > 0 ? (
        <ul className="warning-list">
          {manifest.errors.map((error) => (
            <li key={error}>{error}</li>
          ))}
        </ul>
      ) : null}
    </article>
  );
}

function FindingCard({ finding }: { finding: ProjectArchiveFinding }) {
  return (
    <article className="tool-card">
      <div className="tool-card-header">
        <strong>{finding.title}</strong>
        <div className="badge-row">
          <span className="status-pill">{finding.ecosystemLabel}</span>
          <span className="status-pill">{finding.categoryLabel}</span>
          <span className={`finding-badge ${finding.level}`}>{finding.level}</span>
        </div>
      </div>
      {finding.description ? <p>{finding.description}</p> : null}
      {finding.evidence ? <p className="mono evidence-line">{finding.evidence}</p> : null}
      {finding.recommendation ? <p className="muted">{finding.recommendation}</p> : null}
    </article>
  );
}

function groupFindingsByEcosystem(findings: ProjectArchiveFinding[]) {
  const groups = new Map<string, { ecosystem: string; ecosystemLabel: string; findings: ProjectArchiveFinding[] }>();
  findings.forEach((finding) => {
    const group = groups.get(finding.ecosystem) ?? {
      ecosystem: finding.ecosystem,
      ecosystemLabel: finding.ecosystemLabel,
      findings: []
    };
    group.findings.push(finding);
    groups.set(finding.ecosystem, group);
  });
  return Array.from(groups.values()).sort((a, b) => {
    if (a.ecosystem === "unknown_ecosystem" && b.ecosystem !== "unknown_ecosystem") {
      return 1;
    }
    if (a.ecosystem !== "unknown_ecosystem" && b.ecosystem === "unknown_ecosystem") {
      return -1;
    }
    return a.ecosystemLabel.localeCompare(b.ecosystemLabel);
  });
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
  return (
    <details className="raw-json">
      <summary>Raw JSON</summary>
      <pre>{JSON.stringify(job, null, 2)}</pre>
    </details>
  );
}

function formatMetadataValue(entry: MetadataEntry): string {
  if (entry.label.toLowerCase().includes("bytes")) {
    const parsed = Number(entry.value);
    return Number.isFinite(parsed) ? formatBytes(parsed) : entry.value;
  }
  return entry.value;
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
