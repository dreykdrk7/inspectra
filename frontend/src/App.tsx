import { ChangeEvent, FormEvent, ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import { Activity, Download, Eye, FilePlus2, Globe2, Network, Play, RefreshCw, Trash2, UploadCloud } from "lucide-react";

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
import { CiCdConfigJobReport } from "./CiCdConfigJobReport";
import { ComposeConfigJobReport } from "./ComposeConfigJobReport";
import { DjangoConfigJobReport } from "./DjangoConfigJobReport";
import { DomainJobReport } from "./DomainJobReport";
import { DockerConfigJobReport } from "./DockerConfigJobReport";
import { ImageJobReport } from "./ImageJobReport";
import { K8sConfigJobReport } from "./K8sConfigJobReport";
import { ManifestJobReport } from "./ManifestJobReport";
import { NginxConfigJobReport } from "./NginxConfigJobReport";
import { NodePackageConfigJobReport } from "./NodePackageConfigJobReport";
import { PdfJobReport } from "./PdfJobReport";
import { ProjectArchiveJobReport } from "./ProjectArchiveJobReport";
import { SecretsReviewJobReport } from "./SecretsReviewJobReport";
import { SubdomainJobReport } from "./SubdomainJobReport";
import { TerraformConfigJobReport } from "./TerraformConfigJobReport";
import { WebJobReport } from "./WebJobReport";
import type { FileRecord, HealthResponse, JobListItem, JobRecord, ReportFormat, SbomFormat } from "./types";
import { inspectWebUrlQuery } from "./webUrl";

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
  const [webUrl, setWebUrl] = useState("");
  const [webAuthorizationConfirmed, setWebAuthorizationConfirmed] = useState(false);
  const [webAuditState, setWebAuditState] = useState<LoadState>(initialLoadState);
  const [domainName, setDomainName] = useState("");
  const [domainAuthorizationConfirmed, setDomainAuthorizationConfirmed] = useState(false);
  const [domainAuditState, setDomainAuditState] = useState<LoadState>(initialLoadState);
  const [subdomainRootDomain, setSubdomainRootDomain] = useState("");
  const [subdomainCandidates, setSubdomainCandidates] = useState("");
  const [subdomainAuthorizationConfirmed, setSubdomainAuthorizationConfirmed] = useState(false);
  const [subdomainAuditState, setSubdomainAuditState] = useState<LoadState>(initialLoadState);

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
    () => (selectedJob?.file_id ? files.find((file) => file.id === selectedJob.file_id) : undefined),
    [files, selectedJob]
  );
  const webQueryInspection = useMemo(() => inspectWebUrlQuery(webUrl), [webUrl]);

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

  async function launchDjangoConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchDjangoConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchDockerConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchDockerConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchSecretsReviewAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchSecretsReviewAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchNodePackageConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchNodePackageConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchCiCdConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchCiCdConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchK8sConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchK8sConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchTerraformConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchTerraformConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchNginxConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchNginxConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchComposeConfigAudit(file: FileRecord) {
    setActionError(null);
    try {
      const job = await api.launchComposeConfigAudit(file.id);
      setSelectedJob(job);
      await refreshJobs();
    } catch (error) {
      setActionError(toErrorMessage(error));
    }
  }

  async function launchWebAudit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setActionError(null);
    setWebAuditState({ loading: true, error: null });
    try {
      const job = await api.launchWebBasicAudit(webUrl, webAuthorizationConfirmed);
      setSelectedJob(job);
      setWebUrl("");
      setWebAuthorizationConfirmed(false);
      await refreshJobs();
      setWebAuditState({ loading: false, error: null });
    } catch (error) {
      setWebAuditState({ loading: false, error: toErrorMessage(error) });
    }
  }

  async function launchDomainAudit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setActionError(null);
    setDomainAuditState({ loading: true, error: null });
    try {
      const job = await api.launchDomainBasicAudit(domainName, domainAuthorizationConfirmed);
      setSelectedJob(job);
      setDomainName("");
      setDomainAuthorizationConfirmed(false);
      await refreshJobs();
      setDomainAuditState({ loading: false, error: null });
    } catch (error) {
      setDomainAuditState({ loading: false, error: toErrorMessage(error) });
    }
  }

  async function launchSubdomainAudit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setActionError(null);
    setSubdomainAuditState({ loading: true, error: null });
    try {
      const candidates = parseSubdomainCandidates(subdomainCandidates);
      const job = await api.launchSubdomainInventoryAudit(subdomainRootDomain, candidates, subdomainAuthorizationConfirmed);
      setSelectedJob(job);
      setSubdomainRootDomain("");
      setSubdomainCandidates("");
      setSubdomainAuthorizationConfirmed(false);
      await refreshJobs();
      setSubdomainAuditState({ loading: false, error: null });
    } catch (error) {
      setSubdomainAuditState({ loading: false, error: toErrorMessage(error) });
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
          <p className="eyebrow">Defensive audits</p>
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

        <Panel title="Web Audit" icon={<Globe2 size={18} aria-hidden="true" />}>
          <form className="web-audit-form" onSubmit={(event) => void launchWebAudit(event)}>
            <input
              className="search-input"
              type="url"
              placeholder="https://example.com"
              value={webUrl}
              onChange={(event) => setWebUrl(event.target.value)}
              required
            />
            {webQueryInspection.hasQueryString ? (
              <div className="query-warning" role="status">
                {webQueryInspection.sensitiveParams.length > 0 ? (
                  <>
                    Se detectan posibles parametros sensibles que seran redactados en resultados y exports:{" "}
                    <span className="mono">{webQueryInspection.sensitiveParams.join(", ")}</span>
                  </>
                ) : (
                  "La URL contiene query string. Inspectra usara la URL para la request autorizada, pero redactara parametros sensibles en resultados y exports. Evita introducir secretos reales."
                )}
              </div>
            ) : null}
            <label className="checkbox-row">
              <input
                type="checkbox"
                checked={webAuthorizationConfirmed}
                onChange={(event) => setWebAuthorizationConfirmed(event.target.checked)}
              />
              Confirmo que tengo autorización para auditar este objetivo
            </label>
            <button type="submit" disabled={webAuditState.loading || !webAuthorizationConfirmed}>
              <Play size={16} aria-hidden="true" />
              {webAuditState.loading ? "Starting" : "Analyze URL"}
            </button>
          </form>
          {webAuditState.error ? <p className="error-text">{webAuditState.error}</p> : null}
        </Panel>

        <Panel title="Domain Baseline" icon={<Network size={18} aria-hidden="true" />}>
          <form className="web-audit-form" onSubmit={(event) => void launchDomainAudit(event)}>
            <input
              className="search-input"
              type="text"
              placeholder="example.com"
              value={domainName}
              onChange={(event) => setDomainName(event.target.value)}
              required
            />
            <label className="checkbox-row">
              <input
                type="checkbox"
                checked={domainAuthorizationConfirmed}
                onChange={(event) => setDomainAuthorizationConfirmed(event.target.checked)}
              />
              Confirmo que tengo autorización para auditar este dominio
            </label>
            <button type="submit" disabled={domainAuditState.loading || !domainAuthorizationConfirmed}>
              <Play size={16} aria-hidden="true" />
              {domainAuditState.loading ? "Starting" : "Analyze domain"}
            </button>
          </form>
          {domainAuditState.error ? <p className="error-text">{domainAuditState.error}</p> : null}
        </Panel>

        <Panel title="Subdomain Inventory" icon={<Network size={18} aria-hidden="true" />}>
          <form className="web-audit-form" onSubmit={(event) => void launchSubdomainAudit(event)}>
            <input
              className="search-input"
              type="text"
              placeholder="example.com"
              value={subdomainRootDomain}
              onChange={(event) => setSubdomainRootDomain(event.target.value)}
              required
            />
            <textarea
              className="search-input multiline-input"
              placeholder={"www\napi.example.com\nadmin"}
              value={subdomainCandidates}
              onChange={(event) => setSubdomainCandidates(event.target.value)}
              rows={4}
              required
            />
            <label className="checkbox-row">
              <input
                type="checkbox"
                checked={subdomainAuthorizationConfirmed}
                onChange={(event) => setSubdomainAuthorizationConfirmed(event.target.checked)}
              />
              Confirmo que tengo autorización para auditar estos subdominios
            </label>
            <button type="submit" disabled={subdomainAuditState.loading || !subdomainAuthorizationConfirmed}>
              <Play size={16} aria-hidden="true" />
              {subdomainAuditState.loading ? "Starting" : "Analyze subdomains"}
            </button>
          </form>
          {subdomainAuditState.error ? <p className="error-text">{subdomainAuditState.error}</p> : null}
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
                          {file.kind === "archive" ? (
                            <button onClick={() => void launchDjangoConfigAudit(file)}>
                              <Play size={15} aria-hidden="true" />
                              Analyze Django config
                            </button>
                          ) : null}
                          {file.kind === "archive" ? (
                            <button onClick={() => void launchDockerConfigAudit(file)}>
                              <Play size={15} aria-hidden="true" />
                              Analyze Docker config
                            </button>
                          ) : null}
                          {file.kind === "archive" ? (
                            <button onClick={() => void launchSecretsReviewAudit(file)}>
                              <Play size={15} aria-hidden="true" />
                              Analyze secrets review
                            </button>
                          ) : null}
                          {file.kind === "archive" ? (
                            <button onClick={() => void launchNodePackageConfigAudit(file)}>
                              <Play size={15} aria-hidden="true" />
                              Analyze Node package config
                            </button>
                          ) : null}
                          {file.kind === "archive" ? (
                            <button onClick={() => void launchCiCdConfigAudit(file)}>
                              <Play size={15} aria-hidden="true" />
                              Analyze CI/CD config
                            </button>
                          ) : null}
                          {file.kind === "archive" ? (
                            <button onClick={() => void launchK8sConfigAudit(file)}>
                              <Play size={15} aria-hidden="true" />
                              Analyze Kubernetes config
                            </button>
                          ) : null}
                          {file.kind === "archive" ? (
                            <button onClick={() => void launchTerraformConfigAudit(file)}>
                              <Play size={15} aria-hidden="true" />
                              Analyze Terraform config
                            </button>
                          ) : null}
                          {file.kind === "archive" ? (
                            <button onClick={() => void launchNginxConfigAudit(file)}>
                              <Play size={15} aria-hidden="true" />
                              Analyze Nginx config
                            </button>
                          ) : null}
                          {file.kind === "archive" ? (
                            <button onClick={() => void launchComposeConfigAudit(file)}>
                              <Play size={15} aria-hidden="true" />
                              Analyze Compose config
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
              {(["all", "pdf_basic", "image_basic", "manifest_basic", "archive_basic", "project_archive_basic", "web_basic", "domain_basic", "subdomain_inventory_basic", "django_config_basic", "docker_config_basic", "secrets_review_basic", "node_package_config_basic", "ci_cd_config_basic", "k8s_config_basic", "terraform_config_basic", "nginx_config_basic", "compose_config_basic"] as JobTypeFilter[]).map((auditType) => (
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
                    <th>Target</th>
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
                      <td className="mono">{job.file_id ? shortId(job.file_id) : job.target_url ?? job.target_domain ?? "N/A"}</td>
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
            ) : selectedJob.audit_type === "project_archive_basic" ? (
              <ProjectArchiveJobReport job={selectedJob} file={selectedJobFile} />
            ) : selectedJob.audit_type === "domain_basic" ? (
              <DomainJobReport job={selectedJob} />
            ) : selectedJob.audit_type === "subdomain_inventory_basic" ? (
              <SubdomainJobReport job={selectedJob} />
            ) : selectedJob.audit_type === "django_config_basic" ? (
              <DjangoConfigJobReport job={selectedJob} file={selectedJobFile} />
            ) : selectedJob.audit_type === "docker_config_basic" ? (
              <DockerConfigJobReport job={selectedJob} file={selectedJobFile} />
            ) : selectedJob.audit_type === "secrets_review_basic" ? (
              <SecretsReviewJobReport job={selectedJob} file={selectedJobFile} />
            ) : selectedJob.audit_type === "node_package_config_basic" ? (
              <NodePackageConfigJobReport job={selectedJob} file={selectedJobFile} />
            ) : selectedJob.audit_type === "ci_cd_config_basic" ? (
              <CiCdConfigJobReport job={selectedJob} file={selectedJobFile} />
            ) : selectedJob.audit_type === "k8s_config_basic" ? (
              <K8sConfigJobReport job={selectedJob} file={selectedJobFile} />
            ) : selectedJob.audit_type === "terraform_config_basic" ? (
              <TerraformConfigJobReport job={selectedJob} file={selectedJobFile} />
            ) : selectedJob.audit_type === "nginx_config_basic" ? (
              <NginxConfigJobReport job={selectedJob} file={selectedJobFile} />
            ) : selectedJob.audit_type === "compose_config_basic" ? (
              <ComposeConfigJobReport job={selectedJob} file={selectedJobFile} />
            ) : (
              <WebJobReport job={selectedJob} />
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
  const sbomFormats: Array<{ format: SbomFormat; label: string }> = [
    { format: "cyclonedx-json", label: "Export CycloneDX JSON" },
    { format: "spdx-json", label: "Export SPDX JSON" }
  ];

  return (
    <div className="export-actions" aria-label="Job export actions">
      {formats.map((item) => (
        <a key={item.format} className="export-link" href={api.jobExportUrl(job.id, item.format)}>
          <Download size={15} aria-hidden="true" />
          {item.label}
        </a>
      ))}
      {supportsSbomExport(job)
        ? sbomFormats.map((item) => (
            <a key={item.format} className="export-link" href={api.jobSbomUrl(job.id, item.format)}>
              <Download size={15} aria-hidden="true" />
              {item.label}
            </a>
          ))
        : null}
    </div>
  );
}

function supportsSbomExport(job: JobRecord): boolean {
  return job.status === "completed" && (job.audit_type === "manifest_basic" || job.audit_type === "project_archive_basic");
}

function toErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unexpected error";
}

function parseSubdomainCandidates(value: string): string[] {
  return value
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
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
  const statusCode = typeof job.summary.status_code === "number" ? job.summary.status_code : null;
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
  if (job.audit_type === "web_basic") {
    return `HTTP ${statusCode ?? "pending"}, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "domain_basic") {
    const recordsFound = typeof job.summary.records_found_count === "number" ? job.summary.records_found_count : 0;
    return `${recordsFound} records, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "subdomain_inventory_basic") {
    const resolvedCount = typeof job.summary.resolved_count === "number" ? job.summary.resolved_count : 0;
    const acceptedCount = typeof job.summary.candidates_accepted === "number" ? job.summary.candidates_accepted : 0;
    return `${resolvedCount}/${acceptedCount} resolved, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "django_config_basic") {
    const filesRead = typeof job.summary.files_read === "number" ? job.summary.files_read : 0;
    return `${filesRead} files read, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "docker_config_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    return `${filesReviewed} files reviewed, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "secrets_review_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    const sensitiveFiles = typeof job.summary.sensitive_files_detected === "number" ? job.summary.sensitive_files_detected : 0;
    return `${filesReviewed} files reviewed, ${sensitiveFiles} sensitive files, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "node_package_config_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    const packagesDetected = typeof job.summary.packages_detected === "number" ? job.summary.packages_detected : 0;
    const scriptsDetected = typeof job.summary.scripts_detected === "number" ? job.summary.scripts_detected : 0;
    return `${filesReviewed} files reviewed, ${packagesDetected} packages, ${scriptsDetected} scripts, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "ci_cd_config_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    const workflowsDetected = typeof job.summary.workflow_files_detected === "number" ? job.summary.workflow_files_detected : 0;
    const jobsDetected = typeof job.summary.jobs_detected === "number" ? job.summary.jobs_detected : 0;
    return `${filesReviewed} files reviewed, ${workflowsDetected} workflows, ${jobsDetected} jobs, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "k8s_config_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    const resourcesDetected = typeof job.summary.resources_detected === "number" ? job.summary.resources_detected : 0;
    const workloadsDetected = typeof job.summary.workloads_detected === "number" ? job.summary.workloads_detected : 0;
    return `${filesReviewed} files reviewed, ${resourcesDetected} resources, ${workloadsDetected} workloads, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "terraform_config_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    const resourcesDetected = typeof job.summary.resources_detected === "number" ? job.summary.resources_detected : 0;
    const stateFilesDetected = typeof job.summary.state_files_detected === "number" ? job.summary.state_files_detected : 0;
    return `${filesReviewed} files reviewed, ${resourcesDetected} resources, ${stateFilesDetected} state files, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "nginx_config_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    const serverBlocksDetected = typeof job.summary.server_blocks_detected === "number" ? job.summary.server_blocks_detected : 0;
    const includesDetected = typeof job.summary.includes_detected === "number" ? job.summary.includes_detected : 0;
    return `${filesReviewed} files reviewed, ${serverBlocksDetected} servers, ${includesDetected} includes, ${findingsCount ?? 0} findings`;
  }
  if (job.audit_type === "compose_config_basic") {
    const filesReviewed = typeof job.summary.files_reviewed === "number" ? job.summary.files_reviewed : 0;
    const servicesDetected = typeof job.summary.services_detected === "number" ? job.summary.services_detected : 0;
    const publishedPortsDetected = typeof job.summary.published_ports_detected === "number" ? job.summary.published_ports_detected : 0;
    return `${filesReviewed} files reviewed, ${servicesDetected} services, ${publishedPortsDetected} ports, ${findingsCount ?? 0} findings`;
  }
  const validation = qpdfOk === undefined ? "unknown" : qpdfOk ? "valid" : "review";
  return `${validation}, ${warnings} warnings, ${timedOut} timeouts`;
}

export default App;
