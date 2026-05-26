import { ChangeEvent, FormEvent, ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import { Activity, Download, Eye, FilePlus2, Play, RefreshCw, Trash2, UploadCloud } from "lucide-react";

import { api } from "./api";
import {
  auditTypeLabel,
  buildDashboardMetrics,
  fileKindLabel,
  filterFiles,
  filterJobs,
  statusLabel,
  type FileKindFilter,
  type JobStatusFilter,
  type JobTypeFilter
} from "./dashboardFilters";
import { ArchiveJobReport } from "./ArchiveJobReport";
import { ImageJobReport } from "./ImageJobReport";
import { ManifestJobReport } from "./ManifestJobReport";
import { PdfJobReport } from "./PdfJobReport";
import { ProjectArchiveJobReport } from "./ProjectArchiveJobReport";
import type { FileRecord, HealthResponse, JobListItem, JobRecord, ReportFormat } from "./types";

type LoadState = {
  loading: boolean;
  error: string | null;
};

const initialLoadState: LoadState = { loading: false, error: null };

export function App() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [files, setFiles] = useState<FileRecord[]>([]);
  const [jobs, setJobs] = useState<JobListItem[]>([]);
  const [selectedJob, setSelectedJob] = useState<JobRecord | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadKind, setUploadKind] = useState<FileRecord["kind"]>("pdf");
  const [healthState, setHealthState] = useState<LoadState>(initialLoadState);
  const [filesState, setFilesState] = useState<LoadState>(initialLoadState);
  const [jobsState, setJobsState] = useState<LoadState>(initialLoadState);
  const [uploadState, setUploadState] = useState<LoadState>(initialLoadState);
  const [actionError, setActionError] = useState<string | null>(null);
  const [fileKindFilter, setFileKindFilter] = useState<FileKindFilter>("all");
  const [fileSearch, setFileSearch] = useState("");
  const [jobStatusFilter, setJobStatusFilter] = useState<JobStatusFilter>("all");
  const [jobTypeFilter, setJobTypeFilter] = useState<JobTypeFilter>("all");
  const [jobSearch, setJobSearch] = useState("");

  const refreshHealth = useCallback(async () => {
    setHealthState({ loading: true, error: null });
    try {
      setHealth(await api.health());
      setHealthState({ loading: false, error: null });
    } catch (error) {
      setHealth(null);
      setHealthState({ loading: false, error: toErrorMessage(error) });
    }
  }, []);

  const refreshFiles = useCallback(async () => {
    setFilesState({ loading: true, error: null });
    try {
      setFiles(await api.listFiles());
      setFilesState({ loading: false, error: null });
    } catch (error) {
      setFilesState({ loading: false, error: toErrorMessage(error) });
    }
  }, []);

  const refreshJobs = useCallback(async (options: { quiet?: boolean } = {}) => {
    if (!options.quiet) {
      setJobsState({ loading: true, error: null });
    }
    try {
      setJobs(await api.listJobs());
      setJobsState({ loading: false, error: null });
    } catch (error) {
      setJobsState({ loading: false, error: toErrorMessage(error) });
    }
  }, []);

  const refreshAll = useCallback(async () => {
    setActionError(null);
    await Promise.all([refreshHealth(), refreshFiles(), refreshJobs()]);
  }, [refreshFiles, refreshHealth, refreshJobs]);

  useEffect(() => {
    void refreshAll();
  }, [refreshAll]);

  const hasActiveJobs = useMemo(() => jobs.some((job) => job.status === "queued" || job.status === "running"), [jobs]);
  const isRefreshing = healthState.loading || filesState.loading || jobsState.loading;
  const metrics = useMemo(() => buildDashboardMetrics(files, jobs), [files, jobs]);
  const filteredFiles = useMemo(
    () => filterFiles(files, fileKindFilter, fileSearch),
    [fileKindFilter, fileSearch, files]
  );
  const filteredJobs = useMemo(
    () => filterJobs(jobs, jobStatusFilter, jobTypeFilter, jobSearch),
    [jobSearch, jobStatusFilter, jobTypeFilter, jobs]
  );
  const selectedJobFile = useMemo(
    () => (selectedJob ? files.find((file) => file.id === selectedJob.file_id) : undefined),
    [files, selectedJob]
  );

  useEffect(() => {
    if (!hasActiveJobs) {
      return;
    }
    const interval = window.setInterval(() => {
      void refreshJobs({ quiet: true });
    }, 3000);
    return () => window.clearInterval(interval);
  }, [hasActiveJobs, refreshJobs]);

  async function handleUpload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedFile) {
      setUploadState({ loading: false, error: uploadErrorForKind(uploadKind) });
      return;
    }

    setUploadState({ loading: true, error: null });
    setActionError(null);
    try {
      if (uploadKind === "pdf") {
        await api.uploadPdf(selectedFile);
      } else if (uploadKind === "image") {
        await api.uploadImage(selectedFile);
      } else if (uploadKind === "manifest") {
        await api.uploadManifest(selectedFile);
      } else {
        await api.uploadArchive(selectedFile);
      }
      setSelectedFile(null);
      event.currentTarget.reset();
      await refreshFiles();
      setUploadState({ loading: false, error: null });
    } catch (error) {
      setUploadState({ loading: false, error: toErrorMessage(error) });
    }
  }

  function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    setSelectedFile(event.target.files?.[0] ?? null);
    setUploadState(initialLoadState);
  }

  async function launchAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job =
        file.kind === "pdf"
          ? await api.launchPdfAudit(file.id)
          : file.kind === "image"
            ? await api.launchImageAudit(file.id)
            : file.kind === "manifest"
              ? await api.launchManifestAudit(file.id)
              : await api.launchArchiveAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchProjectArchiveAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchProjectArchiveAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function deleteFile(fileId: string) {
    setActionError(null);
    try {
      await api.deleteFile(fileId);
      await Promise.all([refreshFiles(), refreshJobs()]);
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function viewJob(jobId: string) {
    setActionError(null);
    try {
      setSelectedJob(await api.getJob(jobId));
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  return (
    <main className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">Defensive local audits</p>
          <h1>Inspectra</h1>
        </div>
        <button className="secondary-button" onClick={() => void refreshAll()} disabled={isRefreshing}>
          <RefreshCw size={16} aria-hidden="true" />
          {isRefreshing ? "Refreshing" : "Refresh data"}
        </button>
      </header>

      {actionError ? <div className="alert">{actionError}</div> : null}

      <section className="metrics-grid" aria-label="Dashboard summary">
        <MetricCard label="Total files" value={metrics.totalFiles} />
        <MetricCard label="PDFs" value={metrics.pdfs} />
        <MetricCard label="Images" value={metrics.images} />
        <MetricCard label="Manifests" value={metrics.manifests} />
        <MetricCard label="Archives" value={metrics.archives} />
        <MetricCard label="Total jobs" value={metrics.totalJobs} />
        <MetricCard label="Completed" value={metrics.completedJobs} />
        <MetricCard label="Failed" value={metrics.failedJobs} />
        <MetricCard label="Active" value={metrics.activeJobs} />
      </section>

      <section className="dashboard-grid">
        <Panel
          title="Backend"
          icon={<Activity size={18} aria-hidden="true" />}
          action={healthState.loading ? <span className="muted">Checking</span> : null}
        >
          <div className="health-row">
            <span className={health?.status === "ok" ? "status-pill ok" : "status-pill"}>{health?.status ?? "offline"}</span>
            <span className="muted">{health?.service ?? healthState.error ?? "No response yet"}</span>
            <span className="mono">{api.baseUrl()}</span>
          </div>
        </Panel>

        <Panel title="Upload File" icon={<FilePlus2 size={18} aria-hidden="true" />}>
          <form className="upload-form" onSubmit={(event) => void handleUpload(event)}>
            <div className="segmented-control" aria-label="Upload type">
              <button type="button" className={uploadKind === "pdf" ? "active" : ""} onClick={() => setUploadKind("pdf")}>
                PDF
              </button>
              <button type="button" className={uploadKind === "image" ? "active" : ""} onClick={() => setUploadKind("image")}>
                Image
              </button>
              <button type="button" className={uploadKind === "manifest" ? "active" : ""} onClick={() => setUploadKind("manifest")}>
                Manifest
              </button>
              <button type="button" className={uploadKind === "archive" ? "active" : ""} onClick={() => setUploadKind("archive")}>
                Archive
              </button>
            </div>
            <input
              type="file"
              accept={acceptForKind(uploadKind)}
              onChange={handleFileChange}
            />
            <button type="submit" disabled={uploadState.loading}>
              <UploadCloud size={16} aria-hidden="true" />
              {uploadState.loading ? "Uploading" : "Upload"}
            </button>
          </form>
          {uploadState.error ? <p className="error-text">{uploadState.error}</p> : null}
        </Panel>
      </section>

      <section className="content-grid">
        <Panel title="Files" action={filesState.loading ? <span className="muted">Loading</span> : null}>
          <div className="filter-bar">
            <div className="segmented-control" aria-label="File kind filter">
              {(["all", "pdf", "image", "manifest", "archive"] as FileKindFilter[]).map((kind) => (
                <button
                  type="button"
                  key={kind}
                  className={fileKindFilter === kind ? "active" : ""}
                  onClick={() => setFileKindFilter(kind)}
                >
                  {fileKindLabel(kind)}
                </button>
              ))}
            </div>
            <input
              className="search-input"
              type="search"
              placeholder="Search files"
              value={fileSearch}
              onChange={(event) => setFileSearch(event.target.value)}
            />
          </div>
          {filesState.error ? <p className="error-text">{filesState.error}</p> : null}
          {files.length === 0 ? (
            <EmptyState text="No files registered." />
          ) : filteredFiles.length === 0 ? (
            <EmptyState text="No files match the current filters." />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Kind</th>
                    <th>Size</th>
                    <th>SHA-256</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFiles.map((file) => (
                    <tr key={file.id}>
                      <td>
                        <strong>{file.original_filename}</strong>
                        <span className="subtle-id">{file.id}</span>
                      </td>
                      <td>
                        <span className={`status-pill ${kindClass(file.kind)}`}>{file.kind}</span>
                      </td>
                      <td>{formatBytes(file.size_bytes)}</td>
                      <td className="mono">{shortHash(file.sha256)}</td>
                      <td>{formatDate(file.created_at)}</td>
                      <td>
                        <div className="row-actions">
                          <button onClick={() => void launchAudit(file)}>
                            <Play size={15} aria-hidden="true" />
                            {auditLabel(file.kind)}
                          </button>
                          {file.kind === "archive" ? (
                            <button onClick={() => void launchProjectArchiveAudit(file)}>
                              <Play size={15} aria-hidden="true" />
                              Analyze project manifests
                            </button>
                          ) : null}
                          <button className="danger-button" onClick={() => void deleteFile(file.id)}>
                            <Trash2 size={15} aria-hidden="true" />
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel
          title="Jobs"
          action={jobsState.loading ? <span className="muted">Loading</span> : hasActiveJobs ? <span className="muted">Auto-refresh on</span> : null}
        >
          <div className="filter-stack">
            <div className="filter-bar">
              <div className="segmented-control" aria-label="Job status filter">
                {(["all", "queued", "running", "completed", "failed"] as JobStatusFilter[]).map((status) => (
                  <button
                    type="button"
                    key={status}
                    className={jobStatusFilter === status ? "active" : ""}
                    onClick={() => setJobStatusFilter(status)}
                  >
                    {statusLabel(status)}
                  </button>
                ))}
              </div>
              <input
                className="search-input"
                type="search"
                placeholder="Search jobs"
                value={jobSearch}
                onChange={(event) => setJobSearch(event.target.value)}
              />
            </div>
            <div className="segmented-control wide-control" aria-label="Job audit type filter">
              {(["all", "pdf_basic", "image_basic", "manifest_basic", "archive_basic", "project_archive_basic"] as JobTypeFilter[]).map((auditType) => (
                <button
                  type="button"
                  key={auditType}
                  className={jobTypeFilter === auditType ? "active" : ""}
                  onClick={() => setJobTypeFilter(auditType)}
                >
                  {auditTypeLabel(auditType)}
                </button>
              ))}
            </div>
          </div>
          {jobsState.error ? <p className="error-text">{jobsState.error}</p> : null}
          {jobs.length === 0 ? (
            <EmptyState text="No jobs yet." />
          ) : filteredJobs.length === 0 ? (
            <EmptyState text="No jobs match the current filters." />
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>Type</th>
                    <th>File</th>
                    <th>Updated</th>
                    <th>Summary</th>
                    <th>Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredJobs.map((job) => (
                    <tr key={job.id}>
                      <td>
                        <span className={`status-pill ${job.status}`}>{job.status}</span>
                      </td>
                      <td>{job.audit_type}</td>
                      <td className="mono">{shortId(job.file_id)}</td>
                      <td>{formatDate(job.updated_at)}</td>
                      <td>{summarizeJob(job)}</td>
                      <td>
                        <button className="icon-button" title="View job" onClick={() => void viewJob(job.id)}>
                          <Eye size={16} aria-hidden="true" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </section>

      <Panel title="Job Result">
        {selectedJob ? (
          <>
            <ExportActions job={selectedJob} />
            {selectedJob.audit_type === "pdf_basic" ? (
              <PdfJobReport job={selectedJob} file={selectedJobFile} />
            ) : selectedJob.audit_type === "image_basic" ? (
              <ImageJobReport job={selectedJob} file={selectedJobFile} />
            ) : selectedJob.audit_type === "manifest_basic" ? (
              <ManifestJobReport job={selectedJob} file={selectedJobFile} />
            ) : selectedJob.audit_type === "archive_basic" ? (
              <ArchiveJobReport job={selectedJob} file={selectedJobFile} />
            ) : (
              <ProjectArchiveJobReport job={selectedJob} file={selectedJobFile} />
            )}
          </>
        ) : (
          <EmptyState text="Select a job to view its result." />
        )}
      </Panel>
    </main>
  );
}

function Panel({
  title,
  icon,
  action,
  children
}: {
  title: string;
  icon?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>
          {icon}
          {title}
        </h2>
        {action}
      </div>
      {children}
    </section>
  );
}

function EmptyState({ text }: { text: string }) {
  return <p className="empty-state">{text}</p>;
}

function MetricCard({ label, value }: { label: string; value: number }) {
  return (
    <article className="metric-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

function ExportActions({ job }: { job: JobRecord }) {
  const formats: Array<{ format: ReportFormat; label: string }> = [
    { format: "markdown", label: "Export Markdown" },
    { format: "html", label: "Export HTML" },
    { format: "xml", label: "Export XML" },
    { format: "pdf", label: "Export PDF" }
  ];

  return (
    <div className="export-actions" aria-label="Job export actions">
      {formats.map((item) => (
        <a key={item.format} className="export-link" href={api.jobExportUrl(job.id, item.format)}>
          <Download size={15} aria-hidden="true" />
          {item.label}
        </a>
      ))}
    </div>
  );
}

function toErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unexpected error";
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

function shortHash(value: string): string {
  return `${value.slice(0, 12)}...${value.slice(-8)}`;
}

function shortId(value: string): string {
  return value.slice(0, 10);
}

function acceptForKind(kind: FileRecord["kind"]): string {
  if (kind === "pdf") {
    return "application/pdf,.pdf";
  }
  if (kind === "image") {
    return "image/jpeg,image/png,image/webp,.jpg,.jpeg,.png,.webp";
  }
  if (kind === "manifest") {
    return "application/json,text/plain,application/toml,.json,.txt,.toml";
  }
  return "application/zip,application/x-tar,application/gzip,.zip,.tar,.tar.gz,.tgz";
}

function uploadErrorForKind(kind: FileRecord["kind"]): string {
  if (kind === "pdf") {
    return "Selecciona un PDF.";
  }
  if (kind === "image") {
    return "Selecciona una imagen.";
  }
  if (kind === "manifest") {
    return "Selecciona un manifiesto.";
  }
  return "Selecciona un archivo comprimido.";
}

function kindClass(kind: FileRecord["kind"]): string {
  if (kind === "pdf") {
    return "pdf-kind";
  }
  if (kind === "image") {
    return "image-kind";
  }
  if (kind === "manifest") {
    return "manifest-kind";
  }
  return "archive-kind";
}

function auditLabel(kind: FileRecord["kind"]): string {
  if (kind === "archive") {
    return "Analyze archive";
  }
  if (kind === "manifest") {
    return "Analyze manifest";
  }
  if (kind === "image") {
    return "Analyze image";
  }
  return "Analyze PDF";
}

function summarizeJob(job: JobListItem): string {
  if (!job.summary) {
    return job.source_file_deleted_at ? "Source deleted" : "Pending";
  }
  const error = typeof job.summary.error === "string" ? job.summary.error : null;
  if (error) {
    return error;
  }
  const warnings = Array.isArray(job.summary.warnings) ? job.summary.warnings.length : 0;
  const timedOut = Array.isArray(job.summary.timed_out_tools) ? job.summary.timed_out_tools.length : 0;
  const qpdfOk = typeof job.summary.qpdf_ok === "boolean" ? job.summary.qpdf_ok : undefined;
  const mimeType = typeof job.summary.mime_type === "string" ? job.summary.mime_type : null;
  const manifestType = typeof job.summary.manifest_type === "string" ? job.summary.manifest_type : null;
  const archiveType = typeof job.summary.archive_type === "string" ? job.summary.archive_type : null;
  const totalEntries = typeof job.summary.total_entries === "number" ? job.summary.total_entries : null;
  const totalDependencies = typeof job.summary.total_dependencies === "number" ? job.summary.total_dependencies : null;
  const findingsCount =
    typeof job.summary.informational_findings_count === "number"
      ? job.summary.informational_findings_count
      : typeof job.summary.findings_count === "number"
        ? job.summary.findings_count
        : null;
  if (job.audit_type === "image_basic") {
    return `${mimeType ?? "image"}, ${warnings} warnings, ${timedOut} timeouts`;
  }
  if (job.audit_type === "manifest_basic") {
    return `${manifestType ?? "manifest"}, ${totalDependencies ?? 0} deps, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "archive_basic") {
    return `${archiveType ?? "archive"}, ${totalEntries ?? 0} entries, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "project_archive_basic") {
    return `${archiveType ?? "archive"}, ${totalDependencies ?? 0} deps, ${findingsCount ?? 0} findings`;
  }
  const validation = qpdfOk === undefined ? "unknown" : qpdfOk ? "valid" : "review";
  return `${validation}, ${warnings} warnings, ${timedOut} timeouts`;
}

export default App;
