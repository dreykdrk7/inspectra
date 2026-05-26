import type { AuditType, FileRecord, JobListItem, JobStatus } from "./types";

export type FileKindFilter = "all" | FileRecord["kind"];
export type JobStatusFilter = "all" | JobStatus;
export type JobTypeFilter = "all" | AuditType;

export function buildDashboardMetrics(files: FileRecord[], jobs: JobListItem[]) {
  return {
    totalFiles: files.length,
    pdfs: files.filter((file) => file.kind === "pdf").length,
    images: files.filter((file) => file.kind === "image").length,
    manifests: files.filter((file) => file.kind === "manifest").length,
    archives: files.filter((file) => file.kind === "archive").length,
    totalJobs: jobs.length,
    completedJobs: jobs.filter((job) => job.status === "completed").length,
    failedJobs: jobs.filter((job) => job.status === "failed").length,
    activeJobs: jobs.filter((job) => job.status === "queued" || job.status === "running").length
  };
}

export function filterFiles(files: FileRecord[], kindFilter: FileKindFilter, search: string): FileRecord[] {
  const query = search.trim().toLowerCase();
  return files.filter((file) => {
    const matchesKind = kindFilter === "all" || file.kind === kindFilter;
    const matchesSearch =
      !query ||
      file.original_filename.toLowerCase().includes(query) ||
      file.id.toLowerCase().includes(query) ||
      file.kind.toLowerCase().includes(query);
    return matchesKind && matchesSearch;
  });
}

export function filterJobs(
  jobs: JobListItem[],
  statusFilter: JobStatusFilter,
  typeFilter: JobTypeFilter,
  search: string
): JobListItem[] {
  const query = search.trim().toLowerCase();
  return jobs.filter((job) => {
    const matchesStatus = statusFilter === "all" || job.status === statusFilter;
    const matchesType = typeFilter === "all" || job.audit_type === typeFilter;
    const matchesSearch =
      !query ||
      job.id.toLowerCase().includes(query) ||
      (job.file_id ?? "").toLowerCase().includes(query) ||
      (job.target_url ?? "").toLowerCase().includes(query) ||
      (job.target_domain ?? "").toLowerCase().includes(query) ||
      job.audit_type.toLowerCase().includes(query) ||
      job.status.toLowerCase().includes(query);
    return matchesStatus && matchesType && matchesSearch;
  });
}

export function fileKindLabel(kind: FileKindFilter): string {
  if (kind === "all") {
    return "All";
  }
  if (kind === "image") {
    return "Images";
  }
  if (kind === "manifest") {
    return "Manifest";
  }
  if (kind === "archive") {
    return "Archives";
  }
  return "PDF";
}

export function statusLabel(status: JobStatusFilter): string {
  return status === "all" ? "All" : status;
}

export function auditTypeLabel(auditType: JobTypeFilter): string {
  if (auditType === "all") {
    return "All";
  }
  if (auditType === "web_basic") {
    return "web_basic";
  }
  if (auditType === "domain_basic") {
    return "domain_basic";
  }
  return auditType;
}
