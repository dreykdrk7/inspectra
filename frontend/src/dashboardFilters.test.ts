import { describe, expect, it } from "vitest";

import { buildDashboardMetrics, filterFiles, filterJobs } from "./dashboardFilters";
import type { FileRecord, JobListItem } from "./types";

const files: FileRecord[] = [
  {
    id: "pdf-file-1",
    kind: "pdf",
    original_filename: "Report.PDF",
    stored_filename: "1.pdf",
    content_type: "application/pdf",
    size_bytes: 120,
    sha256: "abc",
    created_at: "2026-05-26T10:00:00Z"
  },
  {
    id: "image-file-2",
    kind: "image",
    original_filename: "Evidence.PNG",
    stored_filename: "2.png",
    content_type: "image/png",
    size_bytes: 240,
    sha256: "def",
    created_at: "2026-05-26T10:01:00Z"
  },
  {
    id: "manifest-file-3",
    kind: "manifest",
    original_filename: "package.json",
    stored_filename: "3-package.json",
    content_type: "application/json",
    size_bytes: 360,
    sha256: "ghi",
    created_at: "2026-05-26T10:02:00Z"
  },
  {
    id: "archive-file-4",
    kind: "archive",
    original_filename: "project.zip",
    stored_filename: "4.zip",
    content_type: "application/zip",
    size_bytes: 480,
    sha256: "jkl",
    created_at: "2026-05-26T10:03:00Z"
  }
];

const jobs: JobListItem[] = [
  {
    id: "job-pdf-completed",
    audit_type: "pdf_basic",
    file_id: "pdf-file-1",
    target_url: null,
    target_domain: null,
    status: "completed",
    created_at: "2026-05-26T10:03:00Z",
    updated_at: "2026-05-26T10:04:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-image-running",
    audit_type: "image_basic",
    file_id: "image-file-2",
    target_url: null,
    target_domain: null,
    status: "running",
    created_at: "2026-05-26T10:05:00Z",
    updated_at: "2026-05-26T10:06:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-manifest-failed",
    audit_type: "manifest_basic",
    file_id: "manifest-file-3",
    target_url: null,
    target_domain: null,
    status: "failed",
    created_at: "2026-05-26T10:07:00Z",
    updated_at: "2026-05-26T10:08:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-archive-queued",
    audit_type: "archive_basic",
    file_id: "archive-file-4",
    target_url: null,
    target_domain: null,
    status: "queued",
    created_at: "2026-05-26T10:09:00Z",
    updated_at: "2026-05-26T10:10:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-project-archive-completed",
    audit_type: "project_archive_basic",
    file_id: "archive-file-4",
    target_url: null,
    target_domain: null,
    status: "completed",
    created_at: "2026-05-26T10:11:00Z",
    updated_at: "2026-05-26T10:12:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-web-completed",
    audit_type: "web_basic",
    file_id: null,
    target_url: "https://example.test/",
    target_domain: null,
    status: "completed",
    created_at: "2026-05-26T10:13:00Z",
    updated_at: "2026-05-26T10:14:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-domain-completed",
    audit_type: "domain_basic",
    file_id: null,
    target_url: null,
    target_domain: "example.com",
    status: "completed",
    created_at: "2026-05-26T10:15:00Z",
    updated_at: "2026-05-26T10:16:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-subdomains-completed",
    audit_type: "subdomain_inventory_basic",
    file_id: null,
    target_url: null,
    target_domain: "example.com",
    status: "completed",
    created_at: "2026-05-26T10:17:00Z",
    updated_at: "2026-05-26T10:18:00Z",
    source_file_deleted_at: null,
    summary: null
  }
];

describe("dashboard filters", () => {
  it("filters files by kind", () => {
    expect(filterFiles(files, "image", "")).toEqual([files[1]]);
    expect(filterFiles(files, "manifest", "")).toEqual([files[2]]);
    expect(filterFiles(files, "archive", "")).toEqual([files[3]]);
  });

  it("searches files case-insensitively by filename, id, and kind", () => {
    expect(filterFiles(files, "all", "report")).toEqual([files[0]]);
    expect(filterFiles(files, "all", "IMAGE-FILE")).toEqual([files[1]]);
    expect(filterFiles(files, "all", "MANIFEST")).toEqual([files[2]]);
    expect(filterFiles(files, "all", "ZIP")).toEqual([files[3]]);
  });

  it("filters jobs by status and audit type", () => {
    expect(filterJobs(jobs, "running", "all", "")).toEqual([jobs[1]]);
    expect(filterJobs(jobs, "all", "manifest_basic", "")).toEqual([jobs[2]]);
    expect(filterJobs(jobs, "all", "archive_basic", "")).toEqual([jobs[3]]);
    expect(filterJobs(jobs, "all", "project_archive_basic", "")).toEqual([jobs[4]]);
    expect(filterJobs(jobs, "all", "web_basic", "")).toEqual([jobs[5]]);
    expect(filterJobs(jobs, "all", "domain_basic", "")).toEqual([jobs[6]]);
    expect(filterJobs(jobs, "all", "subdomain_inventory_basic", "")).toEqual([jobs[7]]);
  });

  it("searches jobs case-insensitively by job id, file id, audit type, and status", () => {
    expect(filterJobs(jobs, "all", "all", "JOB-PDF")).toEqual([jobs[0]]);
    expect(filterJobs(jobs, "all", "all", "image-file")).toEqual([jobs[1]]);
    expect(filterJobs(jobs, "all", "all", "MANIFEST_BASIC")).toEqual([jobs[2]]);
    expect(filterJobs(jobs, "all", "all", "ARCHIVE_BASIC")).toEqual([jobs[3], jobs[4]]);
    expect(filterJobs(jobs, "all", "all", "PROJECT_ARCHIVE")).toEqual([jobs[4]]);
    expect(filterJobs(jobs, "all", "all", "FAILED")).toEqual([jobs[2]]);
    expect(filterJobs(jobs, "all", "all", "EXAMPLE.TEST")).toEqual([jobs[5]]);
    expect(filterJobs(jobs, "all", "all", "EXAMPLE.COM")).toEqual([jobs[6], jobs[7]]);
    expect(filterJobs(jobs, "all", "all", "SUBDOMAIN_INVENTORY")).toEqual([jobs[7]]);
  });

  it("builds dashboard metrics from current files and jobs", () => {
    expect(buildDashboardMetrics(files, jobs)).toEqual({
      totalFiles: 4,
      pdfs: 1,
      images: 1,
      manifests: 1,
      archives: 1,
      totalJobs: 8,
      completedJobs: 5,
      failedJobs: 1,
      activeJobs: 2
    });
  });
});
