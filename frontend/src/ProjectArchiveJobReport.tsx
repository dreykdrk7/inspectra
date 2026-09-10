import type { ReactNode } from "react";

import {
  buildProjectArchiveAuditReport,
  type ProjectArchiveDependencyPinningSummary,
  type ProjectArchiveEcosystemSummary,
  type ParsedProjectManifest,
  type ProjectArchiveFinding,
  type ProjectArchiveManifest
} from "./projectArchiveReport";
import type { MetadataEntry } from "./pdfReport";
import type { FileRecord, JobRecord, JobStatus } from "./types";
import { sourceReference } from "./sourcePresentation";

export function ProjectArchiveJobReport({ job, file }: { job: JobRecord; file?: FileRecord }) {
  const report = buildProjectArchiveAuditReport(job, file);
  const isProjectAnalysis = Boolean(job.project_id);

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
          <MetadataRow label="Execution profile" value={formatExecutionProfile(job)} />
          <MetadataRow label="Job ID" value={job.id} mono />
          <MetadataRow
            label={isProjectAnalysis ? "Source reference" : "File ID"}
            value={isProjectAnalysis ? sourceReference(job.source_reference) : job.file_id ?? "N/A"}
            mono
          />
          {job.retry_of_job_id ? <MetadataRow label="Retry of analysis" value={job.retry_of_job_id} mono /> : null}
          <MetadataRow label="Restart recoveries" value={String(job.recovery_count ?? 0)} />
          <MetadataRow label="Last recovered" value={job.last_recovered_at ? formatDate(job.last_recovered_at) : "Never"} />
          <MetadataRow label="Created" value={formatDate(job.created_at)} />
          <MetadataRow label="Started" value={job.started_at ? formatDate(job.started_at) : "Not recorded"} />
          <MetadataRow label="Updated" value={formatDate(job.updated_at)} />
          <MetadataRow label="Finished" value={job.finished_at ? formatDate(job.finished_at) : "Not finished"} />
          <MetadataRow label="Termination" value={formatTerminationReason(job.termination_reason)} />
          <MetadataRow label="Completed" value={report.completedAt ? formatDate(report.completedAt) : "Not completed"} />
          <MetadataRow
            label="Source file"
            value={job.source_file_deleted_at ? `Deleted at ${formatDate(job.source_file_deleted_at)}` : "Available"}
          />
        </dl>
      </section>

      <div className="report-grid">
        <ReportSection title={isProjectAnalysis ? "Source identity" : "Hashes"}>
          {isProjectAnalysis ? (
            <p className="muted">Content digests are retained server-side for reproducibility and withheld from project views.</p>
          ) : <MetadataList entries={report.hashes} empty="No hashes returned yet." monoValues />}
        </ReportSection>
        <ReportSection title="Archive File">
          <dl className="summary-list">
            <MetadataRow
              label="Original name"
              value={isProjectAnalysis ? "Withheld in project views; available only in Files" : report.fileInfo.originalFilename ?? "Not available"}
            />
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

      <ReportSection title="Dependency Pinning Summary">
        <DependencyPinningSummaryList entries={report.dependencyPinningSummary} />
      </ReportSection>

      <ReportSection title="Declared License Review">
        {report.licenseReview ? (
          <div className="dependency-groups">
            <p className="muted">
              Contract {report.licenseReview.contractVersion ?? "not recorded"}; policy {report.licenseReview.policyMode}.
              This inventory is not legal advice and does not infer dependency-license compatibility.
            </p>
            {report.licenseReview.declarations.length > 0 ? (
              <div className="dependency-list">
                {report.licenseReview.declarations.map((declaration) => (
                  <div className="dependency-row" key={`${declaration.manifestPath}-${declaration.status}-${declaration.expression ?? ""}`}>
                    <strong>{declaration.expression ?? "No supported declaration"}</strong>
                    <span className="mono">{declaration.manifestPath}</span>
                    <span className={`status-pill ${declaration.status === "not_permitted" ? "failed" : declaration.status === "declared" ? "completed" : "partial"}`}>
                      {declaration.status.replace(/_/g, " ")}
                    </span>
                  </div>
                ))}
              </div>
            ) : <p className="empty-state">No supported root-project license declarations were observed.</p>}
            {report.licenseReview.limitations.length > 0 ? (
              <ul className="warning-list">
                {report.licenseReview.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}
              </ul>
            ) : null}
          </div>
        ) : <p className="empty-state">License review was not recorded for this legacy analysis.</p>}
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

function DependencyPinningSummaryList({ entries }: { entries: ProjectArchiveDependencyPinningSummary[] }) {
  if (entries.length === 0) {
    return <p className="empty-state">No dependency pinning summary returned.</p>;
  }
  return (
    <div className="dependency-list">
      {entries.map((entry) => (
        <div className="dependency-row" key={`${entry.ecosystem}-${entry.theme}`}>
          <strong>{entry.ecosystemLabel}</strong>
          <span>{entry.summary}</span>
          <span className="muted">{entry.manifestPaths.length > 0 ? entry.manifestPaths.join(", ") : entry.themeLabel}</span>
        </div>
      ))}
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
      {manifest.integrity.length > 0 ? (
        <>
          <h4 className="compact-heading">Requirements integrity</h4>
          <p className="muted">Aggregate evidence only. Inspectra discards digest values and does not treat an exact pin as artifact integrity.</p>
          <MetadataList entries={manifest.integrity} empty="No integrity evidence reported." />
        </>
      ) : null}
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
      {finding.manifestPath ? (
        <p className="mono evidence-line">{finding.manifestPath}{finding.line ? `:${finding.line}` : ""}</p>
      ) : null}
      {finding.confidence ? <p className="muted">Confidence: {finding.confidence}</p> : null}
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
      <dt className="metadata-key">{label}</dt>
      <dd className={mono ? "mono" : undefined}>{value}</dd>
    </>
  );
}

function StatusBadge({ status }: { status: JobStatus }) {
  return <span className={`status-pill ${status}`}>{status}</span>;
}

function RawJson({ job }: { job: JobRecord }) {
  const visibleJob = job.project_id ? projectJobWithoutSourceMetadata(job) : job;
  return (
    <details className="raw-json">
      <summary>Raw JSON</summary>
      <pre>{JSON.stringify(visibleJob, null, 2)}</pre>
    </details>
  );
}

function projectJobWithoutSourceMetadata(job: JobRecord): Record<string, unknown> {
  const visibleJob: Record<string, unknown> = { ...job };
  delete visibleJob.file_id;
  delete visibleJob.source_sha256;
  const result = job.result ? { ...job.result } : null;
  if (result) {
    delete result.hashes;
    const fileIdentification = result.file_identification;
    if (fileIdentification && typeof fileIdentification === "object" && !Array.isArray(fileIdentification)) {
      const safeIdentification = { ...(fileIdentification as Record<string, unknown>) };
      delete safeIdentification.original_filename;
      result.file_identification = safeIdentification;
    }
  }
  return { ...visibleJob, result };
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

function formatExecutionProfile(job: JobRecord): string {
  const profile = job.execution_profile;
  if (!profile) {
    return "Not recorded (legacy analysis)";
  }
  const timeout = typeof profile.timeout_seconds === "number" ? `${profile.timeout_seconds}s` : "not recorded";
  const limits = [
    ["workspace copy", profile.workspace_max_bytes, true],
    ["expanded", profile.max_total_uncompressed_bytes, true],
    ["entries", profile.max_archive_entries, false],
    ["manifests", profile.max_manifests, false],
    ["manifest item", profile.max_manifest_bytes, true],
    ["manifest total", profile.max_total_manifest_bytes, true],
    ["lockfiles", profile.max_lockfiles, false],
    ["lock packages", profile.max_lockfile_packages, false],
    ["lock edges", profile.max_lockfile_edges, false]
  ] as const;
  const recordedLimits = limits.flatMap(([label, value, bytes]) => (
    typeof value === "number" ? [`${label} ${bytes ? formatBytes(value) : value}`] : []
  )).join("; ");
  const queueLimits = typeof profile.audit_max_inflight_jobs === "number" && typeof profile.audit_max_inflight_jobs_per_owner === "number"
    ? `; in-flight global ${profile.audit_max_inflight_jobs}; in-flight per owner ${profile.audit_max_inflight_jobs_per_owner}`
    : "; in-flight limits not recorded";
  const worker = profile.worker_contract_version
    ? `; isolated worker ${profile.worker_contract_version}, ${profile.worker_lifecycle ?? "lifecycle not recorded"}, concurrency ${profile.worker_max_concurrency ?? "not recorded"}, CPU ${profile.worker_cpu_seconds ?? "not recorded"} s, memory ${profile.worker_memory_bytes ? formatBytes(profile.worker_memory_bytes) : "not recorded"}`
    : "";
  const licensePolicy = profile.license_policy_contract_version
    ? `; license review ${profile.license_policy_contract_version}, exact deny entries ${profile.license_policy_denied_identifiers?.length ?? 0}`
    : "";
  return `${profile.profile_name}; contract ${profile.contract_version}; rules ${profile.ruleset_version}; admission ${formatBytes(profile.max_upload_bytes)}; timeout ${timeout}; concurrency ${profile.audit_max_concurrency}${queueLimits}; workspace ${profile.workspace_policy ?? "legacy shared source"}${worker}${licensePolicy}${recordedLimits ? `; ${recordedLimits}` : ""}`;
}

function formatTerminationReason(reason: string | null | undefined): string {
  return ({
    completed: "Completed under the recorded contract",
    cancelled_by_owner: "Cancelled by the project owner after workspace cleanup",
    application_restart: "Interrupted by application restart; safe retry required",
    application_shutdown: "Interrupted during application shutdown; safe retry required",
    recovery_rejected: "Queued work rejected because its retained source or execution contract changed",
    runner_timeout: "Stopped at the recorded time limit",
    runner_resource_limit: "Stopped at the recorded isolated-worker resource boundary",
    runner_unavailable: "Runner unavailable; safe retry required",
    runner_contract_invalid: "Runner limit contract did not match",
    workspace_error: "Workspace could not be prepared within limits",
    internal_error: "Controlled internal execution error"
  } as Record<string, string>)[reason ?? ""] ?? (reason ? "Unrecognized terminal reason" : "Not recorded");
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
