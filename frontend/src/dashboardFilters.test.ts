import { describe, expect, it } from "vitest";

import { AUDIT_TYPE_CATALOG, AUDIT_TYPE_ORDER, getAuditTypeMetadata } from "./auditCatalog";
import { auditTypeCategoryLabel, auditTypeLabel, buildDashboardMetrics, filterFiles, filterJobs, JOB_TYPE_FILTERS } from "./dashboardFilters";
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
  },
  {
    id: "job-django-completed",
    audit_type: "django_config_basic",
    file_id: "archive-file-4",
    target_url: null,
    target_domain: null,
    status: "completed",
    created_at: "2026-05-26T10:19:00Z",
    updated_at: "2026-05-26T10:20:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-docker-completed",
    audit_type: "docker_config_basic",
    file_id: "archive-file-4",
    target_url: null,
    target_domain: null,
    status: "completed",
    created_at: "2026-05-26T10:21:00Z",
    updated_at: "2026-05-26T10:22:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-secrets-completed",
    audit_type: "secrets_review_basic",
    file_id: "archive-file-4",
    target_url: null,
    target_domain: null,
    status: "completed",
    created_at: "2026-05-26T10:23:00Z",
    updated_at: "2026-05-26T10:24:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-node-completed",
    audit_type: "node_package_config_basic",
    file_id: "archive-file-4",
    target_url: null,
    target_domain: null,
    status: "completed",
    created_at: "2026-05-26T10:25:00Z",
    updated_at: "2026-05-26T10:26:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-ci-completed",
    audit_type: "ci_cd_config_basic",
    file_id: "archive-file-4",
    target_url: null,
    target_domain: null,
    status: "completed",
    created_at: "2026-05-26T10:27:00Z",
    updated_at: "2026-05-26T10:28:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-k8s-completed",
    audit_type: "k8s_config_basic",
    file_id: "archive-file-4",
    target_url: null,
    target_domain: null,
    status: "completed",
    created_at: "2026-05-26T10:29:00Z",
    updated_at: "2026-05-26T10:30:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-terraform-completed",
    audit_type: "terraform_config_basic",
    file_id: "archive-file-4",
    target_url: null,
    target_domain: null,
    status: "completed",
    created_at: "2026-05-26T10:31:00Z",
    updated_at: "2026-05-26T10:32:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-nginx-completed",
    audit_type: "nginx_config_basic",
    file_id: "archive-file-4",
    target_url: null,
    target_domain: null,
    status: "completed",
    created_at: "2026-05-26T10:33:00Z",
    updated_at: "2026-05-26T10:34:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-compose-completed",
    audit_type: "compose_config_basic",
    file_id: "archive-file-4",
    target_url: null,
    target_domain: null,
    status: "completed",
    created_at: "2026-05-26T10:35:00Z",
    updated_at: "2026-05-26T10:36:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-database-completed",
    audit_type: "database_config_basic",
    file_id: "archive-file-4",
    target_url: null,
    target_domain: null,
    status: "completed",
    created_at: "2026-05-26T10:37:00Z",
    updated_at: "2026-05-26T10:38:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-redis-completed",
    audit_type: "redis_config_basic",
    file_id: "archive-file-4",
    target_url: null,
    target_domain: null,
    status: "completed",
    created_at: "2026-05-26T10:39:00Z",
    updated_at: "2026-05-26T10:40:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-sql-database-completed",
    audit_type: "sql_database_config_basic",
    file_id: "archive-file-4",
    target_url: null,
    target_domain: null,
    status: "completed",
    created_at: "2026-05-26T10:41:00Z",
    updated_at: "2026-05-26T10:42:00Z",
    source_file_deleted_at: null,
    summary: null
  },
  {
    id: "job-active-dry-run-completed",
    audit_type: "active_network_dry_run",
    file_id: null,
    target_url: "https://active-dry-run.test/",
    target_domain: null,
    status: "completed",
    created_at: "2026-05-26T10:43:00Z",
    updated_at: "2026-05-26T10:44:00Z",
    source_file_deleted_at: null,
    summary: { allowed: true, planned_checks_count: 1, blocked_reasons_count: 0, network_requests_sent: 0 }
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
    expect(filterJobs(jobs, "all", "django_config_basic", "")).toEqual([jobs[8]]);
    expect(filterJobs(jobs, "all", "docker_config_basic", "")).toEqual([jobs[9]]);
    expect(filterJobs(jobs, "all", "secrets_review_basic", "")).toEqual([jobs[10]]);
    expect(filterJobs(jobs, "all", "node_package_config_basic", "")).toEqual([jobs[11]]);
    expect(filterJobs(jobs, "all", "ci_cd_config_basic", "")).toEqual([jobs[12]]);
    expect(filterJobs(jobs, "all", "k8s_config_basic", "")).toEqual([jobs[13]]);
    expect(filterJobs(jobs, "all", "terraform_config_basic", "")).toEqual([jobs[14]]);
    expect(filterJobs(jobs, "all", "nginx_config_basic", "")).toEqual([jobs[15]]);
    expect(filterJobs(jobs, "all", "compose_config_basic", "")).toEqual([jobs[16]]);
    expect(filterJobs(jobs, "all", "database_config_basic", "")).toEqual([jobs[17]]);
    expect(filterJobs(jobs, "all", "redis_config_basic", "")).toEqual([jobs[18]]);
    expect(filterJobs(jobs, "all", "sql_database_config_basic", "")).toEqual([jobs[19]]);
    expect(filterJobs(jobs, "all", "active_network_dry_run", "")).toEqual([jobs[20]]);
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
    expect(filterJobs(jobs, "all", "all", "DJANGO_CONFIG")).toEqual([jobs[8]]);
    expect(filterJobs(jobs, "all", "all", "SQL_DATABASE_CONFIG")).toEqual([jobs[19]]);
    expect(filterJobs(jobs, "all", "all", "DOCKER_CONFIG")).toEqual([jobs[9]]);
    expect(filterJobs(jobs, "all", "all", "SECRETS_REVIEW")).toEqual([jobs[10]]);
    expect(filterJobs(jobs, "all", "all", "NODE_PACKAGE")).toEqual([jobs[11]]);
    expect(filterJobs(jobs, "all", "all", "CI_CD_CONFIG")).toEqual([jobs[12]]);
    expect(filterJobs(jobs, "all", "all", "K8S_CONFIG")).toEqual([jobs[13]]);
    expect(filterJobs(jobs, "all", "all", "TERRAFORM_CONFIG")).toEqual([jobs[14]]);
    expect(filterJobs(jobs, "all", "all", "NGINX_CONFIG")).toEqual([jobs[15]]);
    expect(filterJobs(jobs, "all", "all", "COMPOSE_CONFIG")).toEqual([jobs[16]]);
    expect(filterJobs(jobs, "all", "all", "DATABASE_CONFIG")).toEqual([jobs[17], jobs[19]]);
    expect(filterJobs(jobs, "all", "all", "REDIS_CONFIG")).toEqual([jobs[18]]);
    expect(filterJobs(jobs, "all", "all", "ACTIVE_NETWORK")).toEqual([jobs[20]]);
  });

  it("searches jobs by human audit label and category", () => {
    expect(filterJobs(jobs, "all", "all", "SQL DB config")).toEqual([jobs[19]]);
    expect(filterJobs(jobs, "all", "all", "Data layer")).toEqual([jobs[17], jobs[18], jobs[19]]);
    expect(filterJobs(jobs, "all", "all", "Active network dry-run")).toEqual([jobs[20]]);
    expect(filterJobs(jobs, "all", "all", "Active / Network")).toEqual([jobs[20]]);
    expect(filterJobs(jobs, "all", "all", "Infrastructure & deployment")).toEqual([jobs[12], jobs[13], jobs[14]]);
  });

  it("builds dashboard metrics from current files and jobs", () => {
    expect(buildDashboardMetrics(files, jobs)).toEqual({
      totalFiles: 4,
      pdfs: 1,
      images: 1,
      manifests: 1,
      archives: 1,
      totalJobs: 21,
      completedJobs: 18,
      failedJobs: 1,
      activeJobs: 2
    });
  });

  it("labels all visible alpha audit types with catalog metadata", () => {
    expect(JOB_TYPE_FILTERS).toEqual(["all", ...AUDIT_TYPE_ORDER]);
    for (const auditType of AUDIT_TYPE_ORDER) {
      const metadata = AUDIT_TYPE_CATALOG[auditType];
      expect(metadata.label).not.toEqual(auditType);
      expect(metadata.categoryLabel).not.toBe("Unknown");
      expect(metadata.sourceFamily).not.toBe("unknown");
    }
  });

  it("keeps audit catalog descriptions passive and avoids critical claim wording", () => {
    const forbiddenCopy = [
      "compromised",
      "breached",
      "exploitable",
      "confirmed vulnerability",
      "credentials valid",
      "hacked",
      "live exposure confirmed",
      "database exposed",
      "redis exposed"
    ];

    for (const auditType of AUDIT_TYPE_ORDER) {
      const metadata = AUDIT_TYPE_CATALOG[auditType];
      const description = metadata.shortDescription.toLowerCase();
      for (const phrase of forbiddenCopy) {
        expect(description).not.toContain(phrase);
      }
      if (metadata.sourceFamily === "archive") {
        expect(description).toMatch(/passive|review|indicator/);
      }
    }
  });

  it("labels Redis and SQL database config jobs for the dashboard filter", () => {
    expect(auditTypeLabel("redis_config_basic")).toBe("Redis config");
    expect(auditTypeLabel("sql_database_config_basic")).toBe("SQL DB config");
    expect(auditTypeLabel("active_network_dry_run")).toBe("Active network dry-run");
    expect(auditTypeCategoryLabel("redis_config_basic")).toBe("Data layer");
    expect(auditTypeCategoryLabel("sql_database_config_basic")).toBe("Data layer");
    expect(auditTypeCategoryLabel("active_network_dry_run")).toBe("Active / Network");
  });

  it("keeps a stable fallback for unknown audit types", () => {
    expect(auditTypeLabel("custom_future_basic")).toBe("custom_future_basic");
    expect(getAuditTypeMetadata("custom_future_basic")).toMatchObject({
      auditType: "custom_future_basic",
      categoryLabel: "Unknown",
      sourceFamily: "unknown"
    });
  });
});
