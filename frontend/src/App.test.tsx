import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App, toErrorMessage } from "./App";
import { ApiError } from "./api";

// App exercises several independently loaded panels. Keep transition assertions
// tolerant of CI worker contention without relaxing the timeout for every test.
const APP_TRANSITION_TIMEOUT = { timeout: 5_000 } as const;
const APP_TRANSITION_TEST_TIMEOUT_MS = 10_000;
const APP_URL_RESTORE_TIMEOUT = { timeout: 10_000 } as const;
const APP_URL_RESTORE_TEST_TIMEOUT_MS = 15_000;

function jsonResponse(payload: unknown, status = 200, headers: HeadersInit = {}): Response {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("content-type", "application/json");
  return new Response(JSON.stringify(payload), {
    status,
    headers: responseHeaders
  });
}

function jobListResponse(url: string, items: unknown[]): Response {
  return jsonResponse(
    url.endsWith("/jobs/search")
      ? {
          contract_version: "2026-09-08.1",
          items,
          returned_count: items.length,
          total_count: items.length,
          has_more: false,
          next_cursor: null,
        }
      : items,
  );
}

const trustedLocalAuthStatus = {
  auth_mode: "trusted_local_no_auth",
  auth_required: false,
  configured: false,
  trusted_local: true,
  default_operator_id: "local-admin",
  login_available: false,
  authenticated: false,
  operator_id: null,
  csrf_required: false,
  csrf_token: null
};

const selfHostedLoginStatus = {
  auth_mode: "self_hosted_single_admin",
  auth_required: true,
  configured: true,
  trusted_local: false,
  default_operator_id: "local-admin",
  login_available: true,
  authenticated: false,
  operator_id: null,
  csrf_required: true,
  csrf_token: null
};

const selfHostedAuthenticatedStatus = {
  ...selfHostedLoginStatus,
  authenticated: true,
  operator_id: "local-admin",
  csrf_token: "csrf-token-123"
};

const privateTeamLoginStatus = {
  ...selfHostedLoginStatus,
  auth_mode: "private_team_lightweight_users",
};

const privateTeamAuthenticatedStatus = {
  ...privateTeamLoginStatus,
  authenticated: true,
  operator_id: "team-admin",
  username: "admin",
  organization_id: "local-admin",
  organization_name: "Acme security",
  role: "administrator",
  csrf_token: "team-csrf-token",
};

const projectArchivePreflight = {
  contract_version: "2026-09-06.2",
  status: "available",
  accepted_archive_formats: [".zip", ".tar", ".tar.gz", ".tgz"],
  upload_limit_bytes: 20 * 1024 * 1024,
  supported_manifests: [
    { name: "package.json", ecosystem: "npm", coverage: "dependency declarations" },
    { name: "requirements.txt", ecosystem: "PyPI", coverage: "dependency declarations" },
  ],
  exact_resolution: [
    { name: "package-lock.json", ecosystem: "npm", coverage: "exact registry versions only when roots match" },
    { name: "pnpm-lock.yaml", ecosystem: "npm", coverage: "exact local versions only when roots match; never public-advisory egress" },
    { name: "yarn.lock (Classic v1)", ecosystem: "npm", coverage: "exact local versions only when selector matches; Berry remains detected but not resolved; never public-advisory egress" },
  ],
  detected_not_resolved: ["poetry.lock", "Pipfile.lock"],
  limitations: ["The preview does not open, upload, hash, or inspect a selected archive."],
  boundaries: ["Inspectra does not execute project code or install dependencies."],
};

const retentionPolicy = {
  contract_version: "2026-09-10.6",
  cleanup_scope: "active_organization_plus_shared_public_cache",
  cleanup_runs_at_startup: true,
  manual_cleanup_allowed: true,
  application_encryption_at_rest: "operator_managed",
  backups: "offline_bundle_operator_encrypted_not_automatically_purged",
  data_classification_complete: true,
  backup_contract_version: "2026-09-06.1",
  source_metadata_contract_version: "2026-09-06.1",
  source_metadata: [
    { key: "original_filename", label: "Original source filename", retained_in: ["source_upload"], sensitivity: "private_source_label", project_view_disclosure: "withheld", report_disclosure: "withheld", integration_disclosure: "withheld", retention_relation: "follows_each_parent_record", description: "Available only in file management." },
    { key: "content_sha256", label: "Source content SHA-256", retained_in: ["analysis_record"], sensitivity: "correlatable_content_digest", project_view_disclosure: "withheld", report_disclosure: "withheld", integration_disclosure: "withheld", retention_relation: "follows_each_parent_record", description: "Retained server-side." },
    { key: "source_file_id", label: "Internal source identifier", retained_in: ["project_record"], sensitivity: "opaque_internal_identifier", project_view_disclosure: "withheld", report_disclosure: "withheld", integration_disclosure: "withheld", retention_relation: "follows_each_parent_record", description: "Used for authorized Files actions." },
    { key: "source_reference", label: "Safe source reference", retained_in: ["derived_projection"], sensitivity: "safe_presentation_reference", project_view_disclosure: "shown", report_disclosure: "shown", integration_disclosure: "shown", retention_relation: "derived_not_stored", description: "Used in project views and reports." },
  ],
  classes: [
    {
      key: "source_uploads",
      label: "Uploaded source archives",
      category: "project_data",
      scope: "organization",
      storage: "durable_upload_store",
      sensitivity: "project_content",
      retention_mode: "bounded",
      retention_days: 30,
      freshness_seconds: null,
      retention_seconds: null,
      automatic_cleanup: true,
      manual_cleanup: true,
      follows_class: null,
      deletion_triggers: ["retention_expiry", "explicit_source_deletion"],
      backup_disposition: "included_sensitive",
      restore_behavior: "restored",
      description: "Expired source bytes are removed unless an active analysis still needs them.",
    },
  ],
};

let projectCreated = false;
let projectLatestJobStatus: "queued" | "running" | "cancelling" | "cancelled" | "completed" | "failed" = "queued";
let paginatedJobHistory = false;
let paginatedProjectHistory = false;

function projectSummaryFixture() {
  return {
    project: {
      source_metadata_contract_version: "2026-09-06.1",
      source_name_disclosure: "withheld_use_files_view",
      source_digest_disclosure: "retained_server_side",
      id: "project-archive-1",
      name: "django",
      source_reference: "snapshot-0123456789abcdef",
      source_file_deleted_at: null,
      latest_job_id: "job-project-1",
      analysis_count: 1,
      created_at: "2026-05-26T10:06:00Z",
      updated_at: "2026-05-26T10:06:00Z"
    },
    latest_job: {
      id: "job-project-1",
      project_id: "project-archive-1",
      source_reference: "snapshot-0123456789abcdef",
      audit_type: "project_archive_basic",
      target_url: null,
      target_domain: null,
      status: projectLatestJobStatus,
      created_at: "2026-05-26T10:06:00Z",
      updated_at: "2026-05-26T10:06:00Z",
      source_file_deleted_at: null,
      summary: null
    }
  };
}

function secondProjectSummaryFixture() {
  return {
    ...projectSummaryFixture(),
    project: {
      ...projectSummaryFixture().project,
      id: "22222222222222222222222222222222",
      name: "second-project",
    },
    latest_job: null,
  };
}

function headerValue(init: RequestInit | undefined, name: string): string | null {
  return new Headers(init?.headers).get(name);
}

describe("App", () => {
  beforeEach(() => {
    projectCreated = false;
    projectLatestJobStatus = "queued";
    paginatedJobHistory = false;
    paginatedProjectHistory = false;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/project-analysis-preflight")) {
          return Promise.resolve(jsonResponse(projectArchivePreflight));
        }
        if (url.endsWith("/privacy/retention")) {
          return Promise.resolve(jsonResponse(retentionPolicy));
        }
        if (url.endsWith("/projects/portfolio/search")) {
          return Promise.resolve(jsonResponse({
            contract_version: "2026-09-09.1",
            snapshot_at: "2026-09-09T10:00:00Z",
            items: [],
            returned_count: 0,
            total_count: 0,
            has_more: false,
            next_cursor: null,
            summary: {
              total_projects: 0,
              filtered_projects: 0,
              urgent_projects: 0,
              high_priority_projects: 0,
              projects_with_kev: 0,
              projects_without_baseline: 0,
              projects_with_partial_data: 0,
              stale_or_failed_intelligence: 0,
              pending_actions: 0,
            },
            priority_model: "closed_signals_no_opaque_score",
            portfolio_complete: true,
            limitations: [],
          }));
        }
        if (url.includes("/projects/actions?")) {
          return Promise.resolve(jsonResponse({
            contract_version: "2026-09-10.1",
            items: [],
            total: 0,
            unread: 0,
            source_complete: true,
            retained_limit: 2000,
            state_revision: 0,
            privacy: "closed_reasons_opaque_ids_no_evidence_or_free_text",
          }));
        }
        if (url.endsWith("/remediation/views")) {
          return Promise.resolve(jsonResponse({
            contract_version: "2026-09-09.1",
            items: [],
            default_view_id: null,
            owned_count: 0,
            organization_count: 0,
            privacy: "closed_filters_only_no_search_cursor_or_resource_ids",
          }));
        }
        if (url.endsWith("/remediation/plans")) {
          return Promise.resolve(jsonResponse({
            contract_version: "2026-09-09.1",
            items: [],
            max_retained_jobs: 100,
            artifact_ttl_days: 7,
          }));
        }
        if (url.endsWith("/remediation/search")) {
          return Promise.resolve(jsonResponse({
            contract_version: "2026-09-09.1",
            snapshot_at: "2026-09-09T10:00:00Z",
            items: [],
            returned_count: 0,
            total_count: 0,
            has_more: false,
            next_cursor: null,
            summary: {
              total_groups: 0,
              filtered_groups: 0,
              urgent_groups: 0,
              high_groups: 0,
              projects_affected: 0,
              known_exploited_groups: 0,
              conflicting_groups: 0,
              awaiting_reanalysis: 0,
            },
            resolution_policy: "comparable_reanalysis_required",
            portfolio_complete: true,
            limitations: [],
          }));
        }
        if (url.endsWith("/projects/trends")) {
          return Promise.resolve(jsonResponse({
            contract_version: "2026-09-10.2",
            materialization: {
              state: "ready", data_state: "current", refresh_in_progress: false,
              retryable: false, requested_at: "2026-09-09T09:59:00Z",
              started_at: null, completed_at: "2026-09-09T10:00:00Z",
              failure_code: null, retry_after_seconds: null,
            },
            trend: {
              contract_version: "2026-09-10.1",
              generated_at: "2026-09-09T10:00:00Z",
              period_starts_at: "2026-06-11T10:00:00Z",
              period_ends_at: "2026-09-09T10:00:00Z",
              bucket_days: 7,
              summary: {
              projects_in_scope: 0, projects_analyzed_in_period: 0, projects_without_recent_analysis: 0,
              retained_completed_analyses: 0, completed_analyses_in_period: 0,
              comparable_local_transitions: 0, comparable_public_transitions: 0,
              excluded_transitions: 0, pending_actions: 0, overdue_exceptions: 0,
              current_known_exploited_findings: 0, current_critical_or_high_findings: 0,
              },
              changes: { local_new: 0, local_persistent: 0, local_resolved: 0, public_new: 0, public_persistent: 0, public_resolved: 0, critical_or_high_new: 0 },
              buckets: [], ecosystems: [], source_types: [],
              time_to_first_review: { cohort: "first_retained_observation_in_period", sample_count: 0, median_hours: null, p90_hours: null },
              time_to_verified_resolution: { cohort: "first_retained_observation_in_period", sample_count: 0, median_hours: null, p90_hours: null },
              priority_projects: [], exclusions: [],
              denominators: { projects: 0, retained_completed_analyses: 0, analyses_in_period: 0, local_comparable_transitions: 0, public_comparable_transitions: 0, first_review_samples: 0, verified_resolution_samples: 0 },
              limitations: [],
            },
          }));
        }
        if (url.endsWith("/projects/search")) {
          if (paginatedProjectHistory) {
            const request = JSON.parse(String(init?.body || "{}")) as { cursor?: string };
            const first = projectSummaryFixture();
            const second = secondProjectSummaryFixture();
            const items = request.cursor ? [second] : [first];
            return Promise.resolve(jsonResponse({
              contract_version: "2026-09-09.1",
              items,
              returned_count: 1,
              total_count: 2,
              has_more: !request.cursor,
              next_cursor: request.cursor ? null : "opaque.project.cursor",
            }));
          }
          const items = projectCreated ? [projectSummaryFixture()] : [];
          return Promise.resolve(jsonResponse({
            contract_version: "2026-09-09.1",
            items,
            returned_count: items.length,
            total_count: items.length,
            has_more: false,
            next_cursor: null,
          }));
        }
        if (url.endsWith("/projects")) {
          if ((init?.method || "GET").toUpperCase() === "POST") {
            projectCreated = true;
            return Promise.resolve(
              jsonResponse(
                {
                  project: {
                    source_metadata_contract_version: "2026-09-06.1",
                    source_name_disclosure: "withheld_use_files_view",
                    source_digest_disclosure: "retained_server_side",
                    id: "project-archive-1",
                    name: "django",
                    source_reference: "snapshot-0123456789abcdef",
                    source_file_deleted_at: null,
                    latest_job_id: "job-project-1",
                    analysis_count: 1,
                    created_at: "2026-05-26T10:06:00Z",
                    updated_at: "2026-05-26T10:06:00Z"
                  },
                  job: {
                    id: "job-project-1",
                    project_id: "project-archive-1",
                    source_reference: "snapshot-0123456789abcdef",
                    audit_type: "project_archive_basic",
                    target_url: null,
                    target_domain: null,
                    status: projectLatestJobStatus,
                    created_at: "2026-05-26T10:06:00Z",
                    updated_at: "2026-05-26T10:06:00Z",
                    source_file_deleted_at: null,
                    result: null,
                    error: null
                  }
                },
                201
              )
            );
          }
          if (projectCreated) {
            return Promise.resolve(jsonResponse([projectSummaryFixture()]));
          }
          return Promise.resolve(jsonResponse([]));
        }
        if (url.endsWith("/projects/22222222222222222222222222222222")) {
          return Promise.resolve(jsonResponse(secondProjectSummaryFixture()));
        }
        if (url.startsWith("http://localhost:8000/projects/project-archive-1/findings")) {
          return Promise.resolve(
            jsonResponse({
              project: {
                source_metadata_contract_version: "2026-09-06.1",
                source_name_disclosure: "withheld_use_files_view",
                source_digest_disclosure: "retained_server_side",
                id: "project-archive-1",
                name: "django",
                source_reference: "snapshot-0123456789abcdef",
                source_file_deleted_at: null,
                latest_job_id: "job-project-1",
                analysis_count: 1,
                created_at: "2026-05-26T10:06:00Z",
                updated_at: "2026-05-26T10:06:00Z"
              },
              analysis: {
                id: "job-project-1",
                project_id: "project-archive-1",
                source_reference: "snapshot-0123456789abcdef",
                analysis_profile: "project_archive_basic",
                audit_type: "project_archive_basic",
                target_url: null,
                target_domain: null,
                status: "completed",
                created_at: "2026-05-26T10:06:00Z",
                updated_at: "2026-05-26T10:06:00Z",
                source_file_deleted_at: null,
                summary: null
              },
              state: "ready",
              summary: {
                total: 1,
                by_severity: { critical: 0, high: 0, medium: 1, low: 0, info: 0 },
                by_category: { dependency_hygiene: 1 }
              },
              result_truncated: false,
              findings: [
                {
                  id: "project-finding-1",
                  rule_id: "dependency_not_exactly_pinned",
                  source_audit_type: "project_archive_basic",
                  title: "Dependency is not exactly pinned",
                  category: "dependency_hygiene",
                  severity: "medium",
                  confidence: "medium",
                  description: "Version coverage is broad.",
                  evidence: "requirements.txt: package>=1",
                  location: { path: "requirements.txt", line: null },
                  recommendation: "Use a reviewed exact version.",
                  references: []
                }
              ]
            })
          );
        }
        if (url.endsWith("/projects/project-archive-1/analyses")) {
          if ((init?.method || "GET").toUpperCase() === "POST") {
            projectLatestJobStatus = "queued";
            return Promise.resolve(
              jsonResponse(
                {
                  id: "job-project-rerun-1",
                  project_id: "project-archive-1",
                  source_reference: "snapshot-0123456789abcdef",
                  analysis_profile: "project_archive_basic",
                  audit_type: "project_archive_basic",
                  file_id: "file-archive-1",
                  target_url: null,
                  target_domain: null,
                  status: "queued",
                  created_at: "2026-05-26T10:10:00Z",
                  updated_at: "2026-05-26T10:10:00Z",
                  source_file_deleted_at: null,
                  result: null,
                  error: null
                },
                202
              )
            );
          }
          return Promise.resolve(
            jsonResponse([
              {
                id: "job-project-1",
                project_id: "project-archive-1",
                source_reference: "snapshot-0123456789abcdef",
                analysis_profile: "project_archive_basic",
                audit_type: "project_archive_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: projectLatestJobStatus,
                created_at: "2026-05-26T10:06:00Z",
                updated_at: "2026-05-26T10:06:00Z",
                source_file_deleted_at: null,
                summary: null
              }
            ])
          );
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(
            jsonResponse([
              {
                id: "file-pdf-1",
                kind: "pdf",
                original_filename: "sample.pdf",
                stored_filename: "file-pdf-1.pdf",
                content_type: "application/pdf",
                size_bytes: 100,
                sha256: "abc1234567890abc",
                created_at: "2026-05-26T10:00:00Z"
              },
              {
                id: "file-manifest-1",
                kind: "manifest",
                original_filename: "package.json",
                stored_filename: "file-manifest-1-package.json",
                content_type: "application/json",
                size_bytes: 200,
                sha256: "def1234567890def",
                created_at: "2026-05-26T10:03:00Z"
              },
              {
                id: "file-archive-1",
                source_reference: "snapshot-0123456789abcdef",
                kind: "archive",
                original_filename: "django.zip",
                stored_filename: "file-archive-1.zip",
                content_type: "application/zip",
                size_bytes: 300,
                sha256: "fed1234567890fed",
                created_at: "2026-05-26T10:06:00Z"
              }
            ])
          );
        }
        if (url.endsWith("/jobs/job-pdf-1")) {
          return Promise.resolve(
            jsonResponse({
              id: "job-pdf-1",
              audit_type: "pdf_basic",
              file_id: "file-pdf-1",
              target_url: null,
              target_domain: null,
              status: "completed",
              created_at: "2026-05-26T10:01:00Z",
              updated_at: "2026-05-26T10:02:00Z",
              source_file_deleted_at: null,
              result: { analyzer: "pdf_basic", hashes: { sha256: "abc" }, validation: { qpdf_ok: true } },
              error: null
            })
          );
        }
        if (url.endsWith("/jobs/job-manifest-1")) {
          return Promise.resolve(
            jsonResponse({
              id: "job-manifest-1",
              audit_type: "manifest_basic",
              file_id: "file-manifest-1",
              target_url: null,
              target_domain: null,
              status: "completed",
              created_at: "2026-05-26T10:04:00Z",
              updated_at: "2026-05-26T10:05:00Z",
              source_file_deleted_at: null,
              result: {
                analyzer: "manifest_basic",
                manifest_type: "package_json",
                hashes: { sha256: "def" },
                parsed: {
                  project: { name: "demo" },
                  dependencies: { dependencies: [{ name: "react", specifier: "^18.3.1" }] },
                  scripts: {},
                  engines: {}
                },
                summary: { total_dependencies: 1, dependency_groups: ["dependencies"], informational_findings_count: 0 },
                findings: [],
                errors: []
              },
              error: null
            })
          );
        }
        if (url.endsWith("/audits/web/basic")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-web-1",
                audit_type: "web_basic",
                file_id: null,
                target_url: "https://example.test/",
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:06:00Z",
                updated_at: "2026-05-26T10:06:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/domain/basic")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-domain-1",
                audit_type: "domain_basic",
                file_id: null,
                target_url: null,
                target_domain: "example.com",
                status: "queued",
                created_at: "2026-05-26T10:07:00Z",
                updated_at: "2026-05-26T10:07:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/subdomains/basic")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-subdomains-1",
                audit_type: "subdomain_inventory_basic",
                file_id: null,
                target_url: null,
                target_domain: "example.com",
                status: "queued",
                created_at: "2026-05-26T10:08:00Z",
                updated_at: "2026-05-26T10:08:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/active/network/dry-run")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-active-dry-run-1",
                audit_type: "active_network_dry_run",
                file_id: null,
                target_url: "https://example.test/",
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:08:30Z",
                updated_at: "2026-05-26T10:08:30Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/active/network/http-header-probe")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-active-http-header-1",
                audit_type: "active_http_header_probe",
                file_id: null,
                target_url: "https://example.test/",
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:08:45Z",
                updated_at: "2026-05-26T10:08:45Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/active/web/http-basic-header-review")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-active-http-basic-header-review-1",
                audit_type: "active_http_basic_header_review",
                file_id: null,
                target_url: "[REDACTED_TARGET]",
                target_domain: null,
                status: "completed",
                created_at: "2026-05-26T10:08:50Z",
                updated_at: "2026-05-26T10:08:50Z",
                source_file_deleted_at: null,
                result: { capability: "active_http_basic_header_review", result_status: "not_executed" },
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/django-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-django-1",
                audit_type: "django_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:09:00Z",
                updated_at: "2026-05-26T10:09:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/docker-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-docker-1",
                audit_type: "docker_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:10:00Z",
                updated_at: "2026-05-26T10:10:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/secrets-review/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-secrets-1",
                audit_type: "secrets_review_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:11:00Z",
                updated_at: "2026-05-26T10:11:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/node-package-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-node-1",
                audit_type: "node_package_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:12:00Z",
                updated_at: "2026-05-26T10:12:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/ci-cd-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-ci-1",
                audit_type: "ci_cd_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:13:00Z",
                updated_at: "2026-05-26T10:13:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/k8s-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-k8s-1",
                audit_type: "k8s_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:14:00Z",
                updated_at: "2026-05-26T10:14:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/terraform-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-terraform-1",
                audit_type: "terraform_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:15:00Z",
                updated_at: "2026-05-26T10:15:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/nginx-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-nginx-1",
                audit_type: "nginx_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:16:00Z",
                updated_at: "2026-05-26T10:16:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/compose-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-compose-1",
                audit_type: "compose_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:17:00Z",
                updated_at: "2026-05-26T10:17:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/database-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-database-1",
                audit_type: "database_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:18:00Z",
                updated_at: "2026-05-26T10:18:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/redis-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-redis-1",
                audit_type: "redis_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:19:00Z",
                updated_at: "2026-05-26T10:19:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/audits/sql-database-config/file-archive-1")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-sql-database-1",
                audit_type: "sql_database_config_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: "queued",
                created_at: "2026-05-26T10:20:00Z",
                updated_at: "2026-05-26T10:20:00Z",
                source_file_deleted_at: null,
                result: null,
                error: null
              },
              202
            )
          );
        }
        if (url.endsWith("/jobs/search") && paginatedJobHistory) {
          const request = JSON.parse(String(init?.body || "{}")) as { cursor?: string };
          const indexes = request.cursor ? [50] : Array.from({ length: 50 }, (_value, index) => index);
          const items = indexes.map((index) => ({
            id: `job-page-${index}`,
            audit_type: "pdf_basic",
            file_id: null,
            target_url: null,
            target_domain: null,
            status: "completed",
            created_at: `2026-05-26T10:${String(index).padStart(2, "0")}:00Z`,
            updated_at: `2026-05-26T10:${String(index).padStart(2, "0")}:00Z`,
            source_file_deleted_at: null,
            summary: null,
          }));
          return Promise.resolve(jsonResponse({
            contract_version: "2026-09-08.1",
            items,
            returned_count: items.length,
            total_count: 51,
            has_more: !request.cursor,
            next_cursor: request.cursor ? null : "opaque.cursor",
          }));
        }
        if ((url.endsWith("/jobs") || url.endsWith("/jobs/search")) && projectCreated) {
          return Promise.resolve(
            jobListResponse(url, [
              {
                id: "job-project-1",
                project_id: "project-archive-1",
                audit_type: "project_archive_basic",
                file_id: "file-archive-1",
                target_url: null,
                target_domain: null,
                status: projectLatestJobStatus,
                created_at: "2026-05-26T10:06:00Z",
                updated_at: "2026-05-26T10:06:00Z",
                source_file_deleted_at: null,
                summary: null
              }
            ])
          );
        }
        if (url.endsWith("/jobs") || url.endsWith("/jobs/search")) {
          return Promise.resolve(
            jobListResponse(url, [
              {
                id: "job-pdf-1",
                audit_type: "pdf_basic",
                file_id: "file-pdf-1",
                target_url: null,
                target_domain: null,
                status: "completed",
                created_at: "2026-05-26T10:01:00Z",
                updated_at: "2026-05-26T10:02:00Z",
                source_file_deleted_at: null,
                summary: { qpdf_ok: true, warnings: [], timed_out_tools: [] }
              },
              {
                id: "job-manifest-1",
                audit_type: "manifest_basic",
                file_id: "file-manifest-1",
                target_url: null,
                target_domain: null,
                status: "completed",
                created_at: "2026-05-26T10:04:00Z",
                updated_at: "2026-05-26T10:05:00Z",
                source_file_deleted_at: null,
                summary: { manifest_type: "package_json", total_dependencies: 1, informational_findings_count: 0 }
              }
            ])
          );
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
    vi.unstubAllGlobals();
    window.history.replaceState({}, "", "/");
  });

  it("keeps controlled API errors and replaces unexpected client errors with a recoverable message", () => {
    expect(toErrorMessage(new ApiError("Invalid credentials.", 401))).toBe("Invalid credentials.");
    expect(toErrorMessage(new Error("raw client stack detail"))).toBe(
      "Unable to complete the request. Refresh the page and try again."
    );
  });

  it("renders the main dashboard sections with mocked API data", async () => {
    render(<App />);

    expect(screen.getByRole("heading", { name: "Inspectra" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Backend" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Upload File" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Web Audit" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Domain Baseline" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Subdomain Inventory" })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Active operations" }, { timeout: 5_000 })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Active / Network dry-run" })).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Files" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Jobs" })).toBeInTheDocument();
    fireEvent.click(screen.getByText("Workspace administration and data controls"));
    expect(await screen.findByRole("heading", { name: "Data lifecycle" })).toBeInTheDocument();
    const demoNote = screen.getByRole("note", { name: "Local alpha demo fixture note" });
    expect(demoNote.textContent).toContain("Optional local demo");
    expect(demoNote.textContent).toContain("synthetic fixtures");
    expect(demoNote.textContent).toContain("tests/fixtures/demo/passive-alpha/");
    expect(demoNote.textContent).toContain("Do not upload real secrets or production archives");
    expect(demoNote.textContent).toContain("never reads or uploads a fixture automatically");
    expect(demoNote.textContent).toContain("delete the uploaded fixture from Files");
    expect(demoNote.textContent).toContain("not a CVE or exploitability claim");
    expect(demoNote.textContent).toContain("[REDACTED]");
    expect(demoNote.textContent).toContain("original upload unchanged");
    expect(demoNote.textContent).not.toContain("Run all recommended passive checks");
    for (const phrase of [
      "compromised",
      "breached",
      "exploitable",
      "confirmed vulnerability",
      "credentials valid",
      "hacked",
      "safe",
      "secure",
      "live exposure",
      "clean"
    ]) {
      expect(demoNote.textContent?.toLowerCase() ?? "").not.toContain(phrase);
    }

    expect(await screen.findByText("inspectra-backend")).toBeInTheDocument();
    expect(screen.getByText("sample.pdf")).toBeInTheDocument();
    expect(screen.getByText("django.zip")).toBeInTheDocument();
    expect(screen.getAllByText("PDF basic").length).toBeGreaterThan(0);
    expect(screen.getAllByText("File basics").length).toBeGreaterThan(0);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledTimes(16);
    });
    const requestedUrls = vi.mocked(globalThis.fetch).mock.calls.map(([input]) => String(input));
    expect(requestedUrls).toEqual(expect.arrayContaining([
      expect.stringMatching(/\/active\/assets\/search$/),
      expect.stringMatching(/\/active\/operations\/summary$/),
      expect.stringMatching(/\/active\/operations\/weekly-review-receipts$/),
      expect.stringMatching(/\/active\/verification\/configuration$/),
      expect.stringMatching(/\/jobs\/search$/),
      expect.stringMatching(/\/remediation\/search$/),
      expect.stringMatching(/\/remediation\/views$/),
      expect.stringMatching(/\/remediation\/plans$/),
      expect.stringMatching(/\/projects\/actions\?/),
    ]));
  });

  it("keeps free-target Active flows out of the application shell", async () => {
    render(<App />);

    await screen.findByText("inspectra-backend");
    expect(await screen.findByRole("heading", { name: "Active operations" })).toBeInTheDocument();
    expect(screen.getByText(/Live Active checks are no longer started from free-form targets here/)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Authorized HTTP Header Probe" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Authorized HTTP HEAD target URL")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Active Nmap basic target")).not.toBeInTheDocument();
  });

  it("loads bounded job history pages without putting the cursor in the URL", async () => {
    paginatedJobHistory = true;
    render(<App />);

    expect(await screen.findByText("Showing 50 of 51 jobs. Filters and search apply to loaded jobs; load more to expand the history.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Load more jobs" }));

    await waitFor(() => {
      expect(screen.queryByRole("button", { name: "Load more jobs" })).not.toBeInTheDocument();
    });
    expect(screen.getAllByTitle("View job")).toHaveLength(51);
    await waitFor(() => {
      expect(screen.getByRole("region", { name: "Jobs table. Scroll horizontally to view all fields." })).toHaveFocus();
    });
    const historyCalls = vi.mocked(globalThis.fetch).mock.calls.filter(([input]) => String(input).endsWith("/jobs/search"));
    expect(historyCalls).toHaveLength(2);
    expect(String(historyCalls[1][0])).not.toContain("opaque.cursor");
    expect(JSON.parse(String(historyCalls[1][1]?.body))).toMatchObject({ cursor: "opaque.cursor", page_size: 50 });
  });

  it("loads bounded project pages without putting the cursor in the URL", async () => {
    paginatedProjectHistory = true;
    render(<App />);

    expect(await screen.findByText("Showing 1 of 2 projects.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Load more projects" }));

    expect(await screen.findByText("Showing 2 of 2 projects.")).toBeInTheDocument();
    expect(
      within(screen.getByRole("region", { name: "Projects table. Scroll horizontally to view all fields." }))
        .getByText("second-project")
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Load more projects" })).not.toBeInTheDocument();
    const projectCalls = vi.mocked(globalThis.fetch).mock.calls.filter(([input]) => String(input).endsWith("/projects/search"));
    expect(projectCalls).toHaveLength(2);
    expect(String(projectCalls[1][0])).not.toContain("opaque.project.cursor");
    expect(JSON.parse(String(projectCalls[1][1]?.body))).toMatchObject({ cursor: "opaque.project.cursor", page_size: 50 });
  });

  it("restores a deep project link without loading intervening pages", async () => {
    paginatedProjectHistory = true;
    window.history.replaceState({}, "", "/#project=22222222222222222222222222222222");
    render(<App />);

    expect(
      await screen.findByRole(
        "heading",
        { name: "Project workspace: second-project" },
        { timeout: 5_000 },
      )
    ).toBeInTheDocument();
    const projectCalls = vi.mocked(globalThis.fetch).mock.calls.map(([input]) => String(input));
    expect(projectCalls.filter((url) => url.endsWith("/projects/search"))).toHaveLength(1);
    expect(projectCalls).toContain("http://localhost:8000/projects/22222222222222222222222222222222");
  });

  it("does not send a non-canonical project fragment to the backend", async () => {
    paginatedProjectHistory = true;
    window.history.replaceState({}, "", "/#project=private%2Fcustomer%3Ftoken%3Dcanary");
    render(<App />);

    await screen.findByText("Showing 1 of 2 projects.");
    await waitFor(() => expect(window.location.hash).toBe(""));
    const requested = vi.mocked(globalThis.fetch).mock.calls.map(([input]) => String(input));
    expect(requested.some((url) => url.includes("private") || url.includes("canary"))).toBe(false);
  });

  it("gives essential fields accessible names and exposes selected filter states", async () => {
    render(<App />);

    await screen.findByText("inspectra-backend");
    expect(screen.getByLabelText("File to upload")).toHaveAttribute("type", "file");
    expect(screen.getByLabelText("URL to audit")).toHaveAttribute("type", "url");
    expect(screen.getByLabelText("Domain to audit")).toBeInTheDocument();
    expect(screen.getByLabelText("Root domain")).toBeInTheDocument();
    expect(screen.getByLabelText("Explicit subdomain candidates")).toBeInTheDocument();
    expect(await screen.findByLabelText("Search authorized asset")).toHaveAttribute("type", "search");
    expect(screen.queryByLabelText("Dry-run target URL")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Authorized HTTP HEAD target URL")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Search files")).toHaveAttribute("type", "search");
    expect(screen.getByLabelText("Search jobs")).toHaveAttribute("type", "search");

    const uploadType = within(screen.getByLabelText("Upload type"));
    expect(uploadType.getByRole("button", { name: "PDF" })).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(uploadType.getByRole("button", { name: "Archive" }));
    expect(uploadType.getByRole("button", { name: "PDF" })).toHaveAttribute("aria-pressed", "false");
    expect(uploadType.getByRole("button", { name: "Archive" })).toHaveAttribute("aria-pressed", "true");

    const fileKindFilter = within(screen.getByLabelText("File kind filter"));
    expect(fileKindFilter.getByRole("button", { name: "All" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "View PDF basic job" })).toHaveAccessibleName("View PDF basic job");
  });

  it("guides a new user into the authorized archive-backed project flow", async () => {
    render(<App />);

    await screen.findByText("inspectra-backend");
    expect(screen.getByRole("heading", { name: "Start a professional security review" })).toBeInTheDocument();
    expect(screen.getByText(/does not execute project code, install dependencies, clone repositories/i)).toBeInTheDocument();
    expect(screen.getByLabelText("Project onboarding paths")).toHaveTextContent("Local repository");
    expect(screen.getByLabelText("Project onboarding paths")).toHaveTextContent("Continuous delivery");
    expect(screen.getByLabelText("Project onboarding paths")).toHaveTextContent("Repository-free");
    expect(screen.getByRole("button", { name: "Open CI setup" })).toBeDisabled();

    fireEvent.click(screen.getByRole("button", { name: "Use archive workflow" }));

    await waitFor(() => {
      expect(within(screen.getByLabelText("Upload type")).getByRole("button", { name: "Archive" })).toHaveAttribute("aria-pressed", "true");
    });
    expect(screen.getByRole("heading", { name: "Upload project archive" })).toBeInTheDocument();
    expect(screen.getByText(/Project source: upload an authorized ZIP or TAR snapshot/i)).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Coverage preview" })).toBeInTheDocument();
    expect(screen.getByText("20 MiB")).toBeInTheDocument();
    expect(globalThis.fetch).toHaveBeenCalledWith(
      "http://localhost:8000/project-analysis-preflight",
      expect.objectContaining({ credentials: "include" }),
    );
    const upload = screen.getByLabelText("File to upload");
    expect(upload).toHaveAttribute("aria-describedby", "project-upload-boundary");
    expect(upload).toHaveFocus();
  });

  it("moves focus into the private SBOM preflight from the repository-free path", async () => {
    render(<App />);

    await screen.findByText("inspectra-backend");
    fireEvent.click(screen.getByRole("button", { name: "Preflight SBOM" }));

    const sbomFile = screen.getByLabelText("SBOM JSON");
    await waitFor(() => expect(sbomFile).toHaveFocus());
    expect(screen.getByRole("heading", { name: "Import an immutable SBOM" })).toBeInTheDocument();
    expect(screen.getByText(/private, no-egress preflight/i)).toBeInTheDocument();
  });

  it("continues a recent archive project into its CI setup without exposing CI for first-time users", async () => {
    projectCreated = true;
    projectLatestJobStatus = "completed";
    render(<App />);

    expect(await screen.findByRole("button", { name: /django Archive/i })).toBeInTheDocument();
    const ciButton = screen.getByRole("button", { name: "Open CI setup" });
    expect(ciButton).toBeEnabled();
    fireEvent.click(ciButton);

    expect(await screen.findByRole("heading", { name: "Project workspace: django" })).toBeInTheDocument();
    const ciSetup = await screen.findByRole("region", { name: "Connect this project to CI" });
    await waitFor(() => expect(ciSetup).toHaveFocus());
    expect(window.location.hash).toContain("project=project-archive-1");
  });

  it("makes dense file and job tables keyboard-reachable with a responsive scroll hint", async () => {
    render(<App />);

    await screen.findByText("inspectra-backend");
    const filesTable = screen.getByRole("region", { name: "Files table. Scroll horizontally to view all fields." });
    const jobsTable = screen.getByRole("region", { name: "Jobs table. Scroll horizontally to view all fields." });

    expect(filesTable).toHaveAttribute("tabindex", "0");
    expect(jobsTable).toHaveAttribute("tabindex", "0");
    expect(within(filesTable).getByRole("table", { name: "Files" })).toBeInTheDocument();
    expect(within(jobsTable).getByRole("table", { name: "Jobs" })).toBeInTheDocument();
    expect(within(filesTable).getByText("Scroll horizontally to view all file fields.")).toHaveAttribute("aria-hidden", "true");
    expect(within(jobsTable).getByText("Scroll horizontally to view all job fields.")).toHaveAttribute("aria-hidden", "true");
  });

  it("has no critical accessibility violations in the initial dashboard", async () => {
    const view = render(<App />);

    await screen.findByText("inspectra-backend");
    const results = await axe.run(view.container, {
      rules: {
        "color-contrast": { enabled: false }
      }
    });
    const criticalViolations = results.violations.filter((violation) => violation.impact === "critical");

    expect(criticalViolations).toEqual([]);
  });

  it("shows the self-hosted login gate when auth is required and unauthenticated", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(selfHostedLoginStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);

    expect(await screen.findByText("Authentication required for this self-hosted instance.")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Upload File" })).not.toBeInTheDocument();
    const rendered = view.container.textContent ?? "";
    expect(rendered).not.toContain(".env");
    expect(rendered).not.toContain("bypass");
    expect(rendered).not.toContain("csrf-token-123");
    expect(vi.mocked(globalThis.fetch).mock.calls.some(([input]) => String(input).endsWith("/files"))).toBe(false);
  });

  it("shows team username and invitation activation without loading private data", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) return Promise.resolve(jsonResponse(privateTeamLoginStatus));
        if (url.endsWith("/health")) return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      }),
    );

    render(<App />);

    expect(await screen.findByText("Sign in to your private team workspace. Access is limited by membership and role.")).toBeInTheDocument();
    expect(screen.getByLabelText("Username")).toHaveAttribute("autocomplete", "username");
    expect(screen.getByLabelText("Password")).toHaveAttribute("autocomplete", "current-password");
    expect(await screen.findByRole("button", { name: "I have a one-time invitation" })).toBeInTheDocument();
    expect(vi.mocked(globalThis.fetch).mock.calls.some(([input]) => String(input).endsWith("/files"))).toBe(false);
  });

  it("offers fixed federated sign-in without collecting identity-provider input", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse({
            ...privateTeamLoginStatus,
            federated_login_available: true,
            federated_login_path: "/auth/oidc/start",
          }));
        }
        if (url.endsWith("/health")) return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      }),
    );

    render(<App />);

    const link = await screen.findByRole("link", { name: "Continue with SSO" });
    expect(link).toHaveAttribute("href", "http://localhost:8000/auth/oidc/start");
    expect(screen.getByText("Your account must be provisioned in this workspace before sign-in.")).toBeInTheDocument();
    expect(screen.queryByLabelText(/issuer|tenant|redirect|provider/i)).not.toBeInTheDocument();
  });

  it("loads the scoped team workspace after authenticated status", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) return Promise.resolve(jsonResponse(privateTeamAuthenticatedStatus));
        if (url.endsWith("/organization/members")) {
          return Promise.resolve(jsonResponse([{ user_id: "team-admin", username: "admin", role: "administrator", joined_at: "2026-09-06T10:00:00Z" }]));
        }
        if (url.endsWith("/organizations")) {
          return Promise.resolve(jsonResponse([{ id: "local-admin", name: "Acme security", role: "administrator", created_at: "2026-09-06T10:00:00Z" }]));
        }
        if (url.endsWith("/organization")) {
          return Promise.resolve(jsonResponse({ id: "local-admin", name: "Acme security", current_user_id: "team-admin", current_username: "admin", current_role: "administrator" }));
        }
        if (url.endsWith("/health")) return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        if (url.endsWith("/project-analysis-preflight")) return Promise.resolve(jsonResponse(projectArchivePreflight));
        if (url.endsWith("/files") || url.endsWith("/projects") || url.endsWith("/jobs")) return Promise.resolve(jsonResponse([]));
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      }),
    );

    render(<App />);

    expect(await screen.findByRole("heading", { name: "Acme security" }, APP_TRANSITION_TIMEOUT)).toBeInTheDocument();
    expect(screen.getByText("Acme security · administrator")).toBeInTheDocument();
    expect(screen.getByText("Projects, analyses and exports use this workspace as their isolation boundary. Roles never bypass authorization, redaction or analysis limits.")).toBeInTheDocument();
  }, APP_TRANSITION_TEST_TIMEOUT_MS);

  it("shows controlled unavailable auth state without configuration guidance", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse({ ...selfHostedLoginStatus, configured: false, login_available: false }));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);

    expect(await screen.findByText("Authentication is not available for this deployment.")).toBeInTheDocument();
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();
    const rendered = view.container.textContent ?? "";
    expect(rendered).not.toContain(".env");
    expect(rendered).not.toContain("INSPECTRA_ADMIN_PASSWORD_HASH");
    expect(rendered).not.toContain("bypass");
  });

  it("logs in, refreshes auth status, clears the password, and hides the login gate", async () => {
    let authStatusCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          authStatusCalls += 1;
          return Promise.resolve(jsonResponse(authStatusCalls === 1 ? selfHostedLoginStatus : selfHostedAuthenticatedStatus));
        }
        if (url.endsWith("/auth/login")) {
          expect(JSON.parse(String(init?.body))).toEqual({ password: "correct-admin-password" });
          return Promise.resolve(jsonResponse({ authenticated: true, operator_id: "local-admin", auth_mode: "self_hosted_single_admin" }));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files") || url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);

    const passwordInput = await screen.findByLabelText("Password");
    fireEvent.change(passwordInput, { target: { value: "correct-admin-password" } });
    fireEvent.click(screen.getByRole("button", { name: /Sign in/i }));

    expect(await screen.findByText("Signed in as local-admin")).toBeInTheDocument();
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Upload File" })).toBeInTheDocument();
    fireEvent.click(screen.getByText("Workspace administration and data controls"));
    expect(await screen.findByRole("heading", { name: "Product activity" })).toBeInTheDocument();
    const rendered = view.container.textContent ?? "";
    expect(rendered).not.toContain("correct-admin-password");
    expect(rendered).not.toContain("csrf-token-123");
    expect(rendered).not.toContain("inspectra_session");
  });

  it("shows generic login failure and clears the password", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(selfHostedLoginStatus));
        }
        if (url.endsWith("/auth/login")) {
          return Promise.resolve(jsonResponse({ detail: "Invalid credentials." }, 401));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<App />);

    const passwordInput = await screen.findByLabelText("Password");
    fireEvent.change(passwordInput, { target: { value: "wrong-admin-password" } });
    fireEvent.click(screen.getByRole("button", { name: /Sign in/i }));

    expect(await screen.findByText("Invalid credentials.")).toBeInTheDocument();
    expect((screen.getByLabelText("Password") as HTMLInputElement).value).toBe("");
    expect(document.body.textContent ?? "").not.toContain("wrong-admin-password");
  });

  it("shows controlled login rate-limit copy and clears the password", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(selfHostedLoginStatus));
        }
        if (url.endsWith("/auth/login")) {
          return Promise.resolve(
            jsonResponse({ detail: "Too many attempts. Try again later." }, 429, { "Retry-After": "60" })
          );
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<App />);

    const passwordInput = await screen.findByLabelText("Password");
    fireEvent.change(passwordInput, { target: { value: "super-secret-password" } });
    fireEvent.click(screen.getByRole("button", { name: /Sign in/i }));

    expect(await screen.findByText("Too many attempts. Try again later.")).toBeInTheDocument();
    expect((screen.getByLabelText("Password") as HTMLInputElement).value).toBe("");
    const rendered = document.body.textContent ?? "";
    expect(rendered).not.toContain("super-secret-password");
    expect(rendered).not.toContain("Retry-After");
    expect(rendered).not.toContain("60");
    expect(rendered).not.toContain("client key");
    expect(rendered).not.toContain("threshold");
    expect(rendered).not.toContain("recovery");
    expect(rendered).not.toContain("bypass");
    expect(rendered).not.toContain(".env");
  });

  it("sends CSRF only on mutating requests and keeps it out of the DOM", async () => {
    const manifestRecord = {
      id: "file-manifest-uploaded",
      kind: "manifest",
      original_filename: "package.json",
      stored_filename: "file-manifest-uploaded-package.json",
      content_type: "application/json",
      size_bytes: 48,
      sha256: "1234567890abcdef1234567890abcdef",
      created_at: "2026-05-26T10:20:00Z"
    };
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(selfHostedAuthenticatedStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files/manifest")) {
          return Promise.resolve(jsonResponse(manifestRecord, 201));
        }
        if (url.endsWith("/files") || url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);

    expect(await screen.findByText("Signed in as local-admin")).toBeInTheDocument();
    await waitFor(() => {
      const filesGetCall = vi.mocked(globalThis.fetch).mock.calls.find(([input]) => String(input).endsWith("/files"));
      expect(headerValue(filesGetCall?.[1] as RequestInit | undefined, "X-CSRF-Token")).toBeNull();
    });
    fireEvent.click(screen.getAllByRole("button", { name: "Manifest" })[0]);
    const input = screen.getByLabelText("File to upload");
    fireEvent.change(input, {
      target: {
        files: [new File(['{"name":"demo","version":"1.0.0"}'], "package.json", { type: "application/json" })]
      }
    });
    fireEvent.click(screen.getByRole("button", { name: /Upload/i }));

    await waitFor(() => {
      const uploadCall = vi.mocked(globalThis.fetch).mock.calls.find(([input]) => String(input).endsWith("/files/manifest"));
      expect(headerValue(uploadCall?.[1] as RequestInit | undefined, "X-CSRF-Token")).toBe("csrf-token-123");
    });
    expect(view.container.textContent ?? "").not.toContain("csrf-token-123");
  });

  it("logs out with the CSRF header and returns to login state", async () => {
    let authStatusCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          authStatusCalls += 1;
          return Promise.resolve(jsonResponse(authStatusCalls === 1 ? selfHostedAuthenticatedStatus : selfHostedLoginStatus));
        }
        if (url.endsWith("/auth/logout")) {
          return Promise.resolve(jsonResponse({ authenticated: false, operator_id: null, auth_mode: "self_hosted_single_admin" }));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files") || url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<App />);

    expect(await screen.findByText("Signed in as local-admin")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Sign out/i }));

    await waitFor(() => {
      const logoutCall = vi.mocked(globalThis.fetch).mock.calls.find(([input]) => String(input).endsWith("/auth/logout"));
      expect(headerValue(logoutCall?.[1] as RequestInit | undefined, "X-CSRF-Token")).toBe("csrf-token-123");
    });
    expect(await screen.findByLabelText("Password")).toBeInTheDocument();
  });

  it("refreshes auth and returns to login state after a global 401", async () => {
    let authStatusCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          authStatusCalls += 1;
          return Promise.resolve(jsonResponse(authStatusCalls === 1 ? selfHostedAuthenticatedStatus : selfHostedLoginStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(jsonResponse({ detail: "Authentication required." }, 401));
        }
        if (url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<App />);

    expect(await screen.findByText("Session expired. Sign in again.")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
  });

  it("renders clear empty dashboard states for files and jobs", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(jsonResponse([]));
        }
        if (url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<App />);

    expect(await screen.findByText("Upload a file or archive to start a passive review.")).toBeInTheDocument();
    expect(screen.getByText("Choose a passive archive review to create a job.")).toBeInTheDocument();
  });

  it("uploads a manifest and keeps archive-only actions off the non-archive row", async () => {
    const manifestRecord = {
      id: "file-manifest-uploaded",
      kind: "manifest",
      original_filename: "package.json",
      stored_filename: "file-manifest-uploaded-package.json",
      content_type: "application/json",
      size_bytes: 48,
      sha256: "1234567890abcdef1234567890abcdef",
      created_at: "2026-05-26T10:20:00Z"
    };
    let uploaded = false;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(jsonResponse(uploaded ? [manifestRecord] : []));
        }
        if (url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([]));
        }
        if (url.endsWith("/files/manifest")) {
          uploaded = true;
          return Promise.resolve(jsonResponse(manifestRecord, 201));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);
    const scoped = within(view.container);

    expect(await scoped.findByText("Upload a file or archive to start a passive review.")).toBeInTheDocument();
    fireEvent.click(scoped.getAllByRole("button", { name: "Manifest" })[0]);
    const input = scoped.getByLabelText("File to upload");
    fireEvent.change(input, {
      target: {
        files: [new File(['{"name":"demo","version":"1.0.0"}'], "package.json", { type: "application/json" })]
      }
    });
    fireEvent.click(scoped.getByRole("button", { name: /Upload/i }));

    expect(await scoped.findByText("package.json")).toBeInTheDocument();
    expect(view.container.textContent).not.toContain("Cannot read properties of null");
    expect(globalThis.fetch).toHaveBeenCalledWith("http://localhost:8000/files/manifest", expect.objectContaining({ method: "POST" }));

    const rows = Array.from(view.container.querySelectorAll("tr"));
    const manifestRow = rows.find((row) => row.textContent?.includes("package.json"));
    expect(manifestRow).toBeDefined();
    expect(manifestRow?.textContent).toContain("Analyze manifest");
    for (const archiveOnlyAction of [
      "Analyze Redis config",
      "Analyze SQL DB config",
      "Analyze secrets review",
      "Analyze CI/CD config",
      "Analyze Nginx config",
      "Analyze Docker config",
      "Analyze Kubernetes config",
      "Analyze Terraform config"
    ]) {
      expect(manifestRow?.textContent).not.toContain(archiveOnlyAction);
    }
    expect(manifestRow?.textContent).not.toContain("Run all recommended passive checks");
  });

  it("shows SBOM export buttons only for completed manifest jobs", async () => {
    render(<App />);

    const viewButtons = await screen.findAllByTitle("View job");
    fireEvent.click(viewButtons[0]);

    expect(await screen.findByText("Export PDF")).toBeInTheDocument();
    expect(screen.queryByText("Export CycloneDX JSON")).not.toBeInTheDocument();

    fireEvent.click(viewButtons[1]);

    const cyclonedxLink = await screen.findByRole("link", { name: /Export CycloneDX JSON/i });
    const spdxLink = screen.getByRole("link", { name: /Export SPDX JSON/i });
    expect(cyclonedxLink).toHaveAttribute("href", "http://localhost:8000/jobs/job-manifest-1/sbom/cyclonedx-json");
    expect(spdxLink).toHaveAttribute("href", "http://localhost:8000/jobs/job-manifest-1/sbom/spdx-json");
  });

  it("restores a selected job from the URL and marks the result step as current", async () => {
    window.history.replaceState({}, "", "/#job=job-pdf-1");

    render(<App />);

    expect(await screen.findByRole("heading", { name: "General Summary" }, APP_URL_RESTORE_TIMEOUT)).toBeInTheDocument();
    expect(screen.getByText("PDF basic is completed. Its result is now selected below.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "4. Review result" })).toHaveAttribute("aria-current", "step");
    expect(document.activeElement).toHaveAttribute("id", "results");
    expect(window.location.hash).toBe("#job=job-pdf-1");
  }, APP_URL_RESTORE_TEST_TIMEOUT_MS);

  it("clears an unavailable job link and gives a recoverable next step", async () => {
    window.history.replaceState({}, "", "/#job=missing-job");

    render(<App />);

    expect(await screen.findByText("The job selected in the link is no longer available. Choose another job from the list.")).toBeInTheDocument();
    expect(window.location.hash).toBe("");
  });

  it("starts a web audit from the URL form", async () => {
    render(<App />);

    const inputs = await screen.findAllByPlaceholderText("https://example.com");
    const input = inputs[inputs.length - 1];
    fireEvent.change(input, { target: { value: "https://example.test/" } });
    const checkboxes = screen.getAllByLabelText("I confirm I am authorized to audit this target.");
    fireEvent.click(checkboxes[checkboxes.length - 1]);
    const buttons = screen.getAllByRole("button", { name: /Analyze URL/i });
    fireEvent.click(buttons[buttons.length - 1]);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/web/basic",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ url: "https://example.test/", authorization_confirmed: true })
        })
      );
    });
    expect(await screen.findByText("Web basic is queued. Its result is now selected below.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "4. Review result" })).toHaveAttribute("aria-current", "step");
    expect(window.location.hash).toBe("#job=job-web-1");
  });

  it("warns when the web audit URL contains sensitive query parameters", async () => {
    render(<App />);

    const inputs = await screen.findAllByPlaceholderText("https://example.com");
    const input = inputs[inputs.length - 1];
    fireEvent.change(input, { target: { value: "https://example.test/callback?token=supersecret&page=1" } });

    expect(screen.getByText(/Possible sensitive parameters will be redacted/i)).toBeInTheDocument();
    expect(screen.getByText("token")).toBeInTheDocument();
  });

  it("does not start a web audit without authorization confirmation", async () => {
    render(<App />);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalled();
    });
    vi.mocked(globalThis.fetch).mockClear();

    const inputs = screen.getAllByPlaceholderText("https://example.com");
    const input = inputs[inputs.length - 1];
    fireEvent.change(input, { target: { value: "https://example.test/" } });
    const buttons = screen.getAllByRole("button", { name: /Analyze URL/i });
    const button = buttons[buttons.length - 1];

    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("starts a domain audit from the domain form", async () => {
    render(<App />);

    const inputs = await screen.findAllByPlaceholderText("example.com");
    const input = inputs[inputs.length - 2];
    fireEvent.change(input, { target: { value: "example.com" } });
    const checkboxes = screen.getAllByLabelText("I confirm I am authorized to audit this domain.");
    fireEvent.click(checkboxes[checkboxes.length - 1]);
    const buttons = screen.getAllByRole("button", { name: /Analyze domain/i });
    fireEvent.click(buttons[buttons.length - 1]);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/domain/basic",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ domain: "example.com", authorization_confirmed: true })
        })
      );
    });
  });

  it("starts a subdomain inventory audit from explicit candidates", async () => {
    render(<App />);

    const rootInputs = await screen.findAllByPlaceholderText("example.com");
    const rootInput = rootInputs[rootInputs.length - 1];
    fireEvent.change(rootInput, { target: { value: "example.com" } });
    const candidateInputs = screen.getAllByPlaceholderText(/api\.example\.com/);
    const candidatesInput = candidateInputs[candidateInputs.length - 1];
    fireEvent.change(candidatesInput, { target: { value: "www\napi.example.com" } });
    const checkboxes = screen.getAllByLabelText("I confirm I am authorized to audit these subdomains.");
    fireEvent.click(checkboxes[checkboxes.length - 1]);
    const buttons = screen.getAllByRole("button", { name: /Analyze subdomains/i });
    fireEvent.click(buttons[buttons.length - 1]);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/subdomains/basic",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            root_domain: "example.com",
            subdomains: ["www", "api.example.com"],
            authorization_confirmed: true
          })
        })
      );
    });
  });

  it("does not start a subdomain inventory audit without authorization confirmation", async () => {
    render(<App />);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalled();
    });
    vi.mocked(globalThis.fetch).mockClear();

    const rootInputs = screen.getAllByPlaceholderText("example.com");
    const rootInput = rootInputs[rootInputs.length - 1];
    fireEvent.change(rootInput, { target: { value: "example.com" } });
    const candidateInputs = screen.getAllByPlaceholderText(/api\.example\.com/);
    const candidatesInput = candidateInputs[candidateInputs.length - 1];
    fireEvent.change(candidatesInput, { target: { value: "www\napi.example.com" } });
    const buttons = screen.getAllByRole("button", { name: /Analyze subdomains/i });
    const button = buttons[buttons.length - 1];

    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("renders Active dry-run jobs with redacted target table and report payload", async () => {
    const activeJob = {
      id: "job-active-legacy-1",
      audit_type: "active_network_dry_run",
      file_id: null,
      target_url: "http://user:pass@example.com/?token=token_should_never_render",
      target_domain: null,
      status: "completed",
      created_at: "2026-05-26T10:21:00Z",
      updated_at: "2026-05-26T10:22:00Z",
      source_file_deleted_at: null,
      summary: {
        target_display: "http://user:pass@example.com/?token=token_should_never_render",
        allowed: false,
        planned_checks_count: 0,
        blocked_reasons_count: 1,
        network_requests_sent: 0
      }
    };
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(jsonResponse([]));
        }
        if (url.endsWith("/jobs/job-active-legacy-1")) {
          return Promise.resolve(
            jsonResponse({
              ...activeJob,
              summary: undefined,
              result: {
                analyzer: "active_network_dry_run",
                mode: "dry_run",
                profile: "http_header_probe_preview",
                target: {
                  raw: "http://user:pass@example.com/?token=token_should_never_render",
                  password: "super-secret-password"
                },
                authorization: {
                  confirmed: true,
                  authorization_header: "Authorization: Bearer token_should_never_render"
                },
                policy: {
                  allowed: false,
                  reason: "url_credentials_rejected"
                },
                limits: {
                  max_requests: 0,
                  timeout_seconds: 0,
                  max_redirects: 0,
                  response_size_bytes: 0
                },
                planned_checks: [{ url: "http://user:pass@example.com/?password=super-secret-password" }],
                blocked_reasons: [{ code: "url_credentials_rejected", message: "Authorization: Bearer token_should_never_render" }],
                audit_log: [{ event: "dry_run_blocked", raw: "-----BEGIN PRIVATE KEY----- fixture -----END PRIVATE KEY-----" }],
                errors: ["PRIVATE KEY token_should_never_render"],
                summary: {
                  allowed: false,
                  planned_checks_count: 0,
                  blocked_reasons_count: 1,
                  network_requests_sent: 0
                }
              },
              error: "Authorization: Bearer token_should_never_render"
            })
          );
        }
        if (url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([activeJob]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);

    expect(await screen.findByText("Active network dry-run")).toBeInTheDocument();
    let rendered = view.container.textContent ?? "";
    for (const secret of [
      "http://user:pass@example.com",
      "user:pass",
      "token_should_never_render",
      "super-secret-password",
      "Authorization: Bearer token_should_never_render",
      "PRIVATE KEY"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("[REDACTED]");

    fireEvent.click(screen.getByTitle("View job"));
    expect(await screen.findByRole("heading", { name: "Active network dry-run" }, APP_TRANSITION_TIMEOUT)).toBeInTheDocument();
    rendered = view.container.textContent ?? "";
    expect(rendered).toContain("url_credentials_rejected");
    expect(rendered).toContain("network requests");
    for (const secret of [
      "http://user:pass@example.com",
      "user:pass",
      "token_should_never_render",
      "super-secret-password",
      "Authorization: Bearer token_should_never_render",
      "PRIVATE KEY"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("[REDACTED]");
  }, APP_TRANSITION_TEST_TIMEOUT_MS);

  it("renders Active HTTP header probe jobs with redacted target table and report payload", async () => {
    const activeJob = {
      id: "job-active-http-legacy-1",
      audit_type: "active_http_header_probe",
      file_id: null,
      target_url: "http://user:pass@example.com/?token=token_should_never_render",
      target_domain: null,
      status: "completed",
      created_at: "2026-05-26T10:23:00Z",
      updated_at: "2026-05-26T10:24:00Z",
      source_file_deleted_at: null,
      summary: {
        target_display: "http://user:pass@example.com/?token=token_should_never_render",
        allowed: true,
        network_requests_sent: 1,
        body_bytes_read: 0,
        redirects_followed: 0
      }
    };
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(jsonResponse([]));
        }
        if (url.endsWith("/jobs/job-active-http-legacy-1")) {
          return Promise.resolve(
            jsonResponse({
              ...activeJob,
              summary: undefined,
              result: {
                analyzer: "active_http_header_probe",
                mode: "live_header_probe",
                profile: "http_header_probe",
                target: {
                  raw: "http://user:pass@example.com/?token=token_should_never_render",
                  password: "super-secret-password"
                },
                authorization: {
                  confirmed: true,
                  live_traffic_confirmed: true,
                  authorization_header: "Authorization: Bearer token_should_never_render"
                },
                policy: {
                  allowed: true,
                  reason: "policy_allowed"
                },
                dns: {
                  answers_count: 1,
                  blocked_answers_count: 0
                },
                request: {
                  method: "HEAD",
                  network_requests_sent: 1
                },
                response: {
                  body_read: false,
                  body_bytes_read: 0,
                  redirects_followed: 0,
                  headers: [
                    { name: "Set-Cookie", value: "session_should_not_render=cookie_should_not_render" },
                    { name: "Authorization", value: "Authorization: Bearer token_should_never_render" },
                    { name: "X-Api-Key", value: "raw-api-key-123456" },
                    { name: "Location", value: "http://user:pass@example.com/?token=token_should_never_render" },
                    { name: "X-Key", value: "-----BEGIN PRIVATE KEY----- fixture -----END PRIVATE KEY-----" }
                  ]
                },
                observations: [{ code: "legacy_observation", evidence: "raw-api-key-123456" }],
                findings: [{ id: "legacy_finding", evidence: "PRIVATE KEY token_should_never_render" }],
                blocked_reasons: [],
                limits: { max_requests: 1, max_redirects: 0, response_body_bytes: 0 },
                audit_log: [{ event: "head_request_completed", raw: "raw-api-key-123456" }],
                errors: ["PASSWORD=super-secret-password"],
                summary: {
                  allowed: true,
                  network_requests_sent: 1,
                  body_bytes_read: 0,
                  redirects_followed: 0
                }
              },
              error: "Authorization: Bearer token_should_never_render"
            })
          );
        }
        if (url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([activeJob]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);

    expect(await screen.findByText("Authorized HTTP header probe")).toBeInTheDocument();
    let rendered = view.container.textContent ?? "";
    for (const secret of [
      "http://user:pass@example.com",
      "user:pass",
      "token_should_never_render",
      "super-secret-password",
      "Authorization: Bearer token_should_never_render",
      "raw-api-key-123456",
      "session_should_not_render",
      "cookie_should_not_render",
      "PRIVATE KEY"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("[REDACTED]");

    fireEvent.click(screen.getByTitle("View job"));
    expect(await screen.findByRole("heading", { name: "Authorized HTTP header probe" }, APP_TRANSITION_TIMEOUT)).toBeInTheDocument();
    rendered = view.container.textContent ?? "";
    expect(rendered).toContain("One authorized HTTP HEAD request was sent.");
    expect(rendered).toContain("Response body was not read.");
    expect(rendered).toContain("Redirects were not followed.");
    for (const secret of [
      "http://user:pass@example.com",
      "user:pass",
      "token_should_never_render",
      "super-secret-password",
      "Authorization: Bearer token_should_never_render",
      "raw-api-key-123456",
      "session_should_not_render",
      "cookie_should_not_render",
      "PRIVATE KEY"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("[REDACTED]");
  }, APP_TRANSITION_TEST_TIMEOUT_MS);

  it("renders Active Nmap basic jobs with redacted target table, report payload, and no archive action", async () => {
    const activeJob = {
      id: "job-active-nmap-legacy-1",
      audit_type: "active_nmap_basic",
      file_id: null,
      target_url: "192.168.56.10",
      target_domain: null,
      status: "completed",
      created_at: "2026-05-26T10:25:00Z",
      updated_at: "2026-05-26T10:26:00Z",
      source_file_deleted_at: null,
      summary: {
        target_display: "192.168.56.10",
        capability: "active_nmap_basic",
        result_status: "completed",
        observation_count: 1,
        open_tcp_observations_count: 1
      }
    };
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/auth/status")) {
          return Promise.resolve(jsonResponse(trustedLocalAuthStatus));
        }
        if (url.endsWith("/health")) {
          return Promise.resolve(jsonResponse({ status: "ok", service: "inspectra-backend" }));
        }
        if (url.endsWith("/files")) {
          return Promise.resolve(jsonResponse([]));
        }
        if (url.endsWith("/jobs/job-active-nmap-legacy-1")) {
          return Promise.resolve(
            jsonResponse({
              ...activeJob,
              summary: undefined,
              result: {
                audit_type: "active_nmap_basic",
                capability: "active_nmap_basic",
                mode: "live_nmap_basic",
                profile: "tcp_connect_small",
                status: "completed",
                target: { raw: "192.168.56.10", hostname: "secret-lab.internal" },
                command: "nmap -sT -Pn -n -oX - -p 22,443 -- 192.168.56.10",
                stdout: "stdout with 192.168.56.10 and <nmaprun><host><address addr='192.168.56.10'/></host></nmaprun>",
                stderr: "stderr for secret-lab.internal Authorization: Bearer token_should_never_render",
                raw_xml: "<nmaprun args='nmap -sT 192.168.56.10'><host><ports /></host></nmaprun>",
                port_observations: [{ port: 443, protocol: "tcp", state: "open", reason: "syn-ack" }],
                limits: { output_truncated: false, stderr_truncated: true, timed_out: false },
                legacy: {
                  service_banner: "OpenSSH_9.9 secret-service-banner",
                  notes: "confirmed vulnerability exploitable target is safe all ports found full network scan",
                  headers: { Cookie: "sessionid=secret-session-cookie", Authorization: "Bearer token_should_never_render" },
                  cookies: "sessionid=secret-session-cookie",
                  tokens: ["token_should_never_render"],
                  credentials: { api_key: "raw-api-key-123456" }
                },
                errors: ["nmap -sT 192.168.56.10 failed with token_should_never_render"]
              },
              error: "nmap -sT 192.168.56.10 PRIVATE KEY token_should_never_render"
            })
          );
        }
        if (url.endsWith("/jobs")) {
          return Promise.resolve(jsonResponse([activeJob]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<App />);

    expect(await screen.findByText("Active Nmap basic")).toBeInTheDocument();
    let rendered = view.container.textContent ?? "";
    for (const secret of [
      "192.168.56.10",
      "secret-lab.internal",
      "nmap -sT",
      "<nmaprun",
      "stdout with",
      "stderr for",
      "OpenSSH_9.9",
      "secret-service-banner",
      "token_should_never_render",
      "sessionid=secret-session-cookie",
      "raw-api-key-123456",
      "PRIVATE KEY"
    ]) {
      expect(rendered).not.toContain(secret);
    }

    fireEvent.click(screen.getByTitle("View job"));
    expect(await screen.findByRole("heading", { name: "Active / Nmap basic report" })).toBeInTheDocument();
    rendered = view.container.textContent ?? "";
    expect(rendered).toContain("Observed TCP exposure");
    expect(rendered).toContain("Review indicator");
    expect(rendered).toContain("Manual validation required");
    expect(rendered).toContain("No security finding is asserted");
    expect(rendered).toContain("Authorization is user asserted, not proof of ownership");
    expect(rendered).toContain("Raw JSON (redacted)");
    expect(rendered).toContain("443");
    expect(rendered).toContain("syn-ack");
    expect(rendered).not.toContain("exploitable");
    expect(rendered).not.toContain("target is safe");
    expect(rendered).not.toContain("all ports found");
    expect(rendered).not.toContain("full network scan");
    expect(rendered).not.toContain("Analyze archive");
    expect(rendered).not.toContain("Run all recommended passive checks");
    for (const secret of [
      "192.168.56.10",
      "secret-lab.internal",
      "nmap -sT",
      "<nmaprun",
      "stdout with",
      "stderr for",
      "OpenSSH_9.9",
      "secret-service-banner",
      "token_should_never_render",
      "sessionid=secret-session-cookie",
      "raw-api-key-123456",
      "PRIVATE KEY"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("[REDACTED");
    expect(
      vi
        .mocked(globalThis.fetch)
        .mock.calls.some(([input]) => String(input).endsWith("/active/network/nmap-basic"))
    ).toBe(false);
  });

  it("groups archive passive actions by category without adding a run-all action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf"));
    expect(archiveRow).toBeDefined();
    expect(archiveRow?.textContent).toContain("Passive review");
    expect(archiveRow?.textContent).toContain("credential checks");
    expect(archiveRow?.textContent).toContain("CVE query");
    expect(archiveRow?.textContent).toContain("Start here");
    expect(archiveRow?.textContent).toContain("Secrets");
    expect(archiveRow?.textContent).toContain("Application");
    expect(archiveRow?.textContent).toContain("Container & service wiring");
    expect(archiveRow?.textContent).toContain("Deployment & IaC");
    expect(archiveRow?.textContent).toContain("Web edge");
    expect(archiveRow?.textContent).toContain("Data layer");
    expect(archiveRow?.textContent).not.toContain("Run all recommended passive checks");
    expect(archiveRow?.textContent).not.toContain("Active network dry-run");
    expect(archiveRow?.textContent).not.toContain("Create dry-run plan");
    expect(archiveRow?.textContent).not.toContain("Authorized HTTP Header Probe");
    expect(archiveRow?.textContent).not.toContain("Create authorized header probe job");
    expect(archiveRow?.textContent).not.toContain("Active / Nmap basic");
    expect(archiveRow?.textContent).not.toContain("Create bounded no-live record");
    expect(pdfRow?.textContent).not.toContain("Start here");
    expect(pdfRow?.textContent).not.toContain("Data layer");

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
    const archiveText = archiveRow?.textContent?.toLowerCase() ?? "";
    for (const phrase of forbiddenCopy) {
      expect(archiveText).not.toContain(phrase);
    }
  });

  it("creates an archive-backed project and exposes its queued initial analysis", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const authorization = screen.getAllByRole("checkbox", {
      name: "I confirm I own or am authorized to analyze this archive as a project."
    });
    const buttons = screen.getAllByRole("button", { name: "Create project & analyze" });
    expect(buttons[buttons.length - 1]).toBeDisabled();
    fireEvent.click(authorization[authorization.length - 1]);
    expect(buttons[buttons.length - 1]).toBeEnabled();
    fireEvent.click(buttons[buttons.length - 1]);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/projects",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ source_file_id: "file-archive-1", authorization_confirmed: true })
        })
      );
    });

    expect(await screen.findByText("Project django was created and its initial review is queued.")).toBeInTheDocument();
    const projectsTable = screen.getByRole("region", { name: "Projects table. Scroll horizontally to view all fields." });
    expect(within(projectsTable).getByRole("table", { name: "Projects" })).toBeInTheDocument();
    expect(within(projectsTable).getByText("django")).toBeInTheDocument();
    expect(within(projectsTable).getByText("snapshot-0123456789abcdef")).toBeInTheDocument();
    expect(within(projectsTable).getByText("Archive retained; filename withheld")).toBeInTheDocument();
    expect(projectsTable).not.toHaveTextContent("django.zip");
    expect(projectsTable).not.toHaveTextContent("fed1234567890fed");
    expect(within(projectsTable).getByText("queued")).toBeInTheDocument();
    expect(within(projectsTable).getByRole("button", { name: "View latest analysis for django" })).toBeInTheDocument();
  });

  it("reruns a retained project snapshot only after its previous analysis is terminal", async () => {
    projectCreated = true;
    projectLatestJobStatus = "completed";
    render(<App />);

    const runAgain = await screen.findByRole("button", { name: "Run recorded snapshot for django again" });
    expect(runAgain).toBeEnabled();
    fireEvent.click(runAgain);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/projects/project-archive-1/analyses",
        expect.objectContaining({ method: "POST" })
      );
    });

    expect(await screen.findByText("A new analysis of django is queued for its recorded source snapshot.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run recorded snapshot for django again" })).toBeDisabled();
  });

  it("opens the next-snapshot flow without offering the source already retained by the project", async () => {
    projectCreated = true;
    projectLatestJobStatus = "completed";
    render(<App />);

    fireEvent.click(await screen.findByRole("button", { name: "Add a new archive snapshot to django" }));

    expect(await screen.findByRole("heading", { name: "Add project snapshot" })).toBeInTheDocument();
    expect(screen.getByText(/Upload a different ZIP or TAR archive/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add snapshot & analyze" })).not.toBeInTheDocument();
  });

  it("opens a focused project workspace from the project table", async () => {
    projectCreated = true;
    projectLatestJobStatus = "completed";
    render(<App />);

    fireEvent.click(await screen.findByRole("button", { name: "Open workspace for django" }));

    expect(await screen.findByRole("heading", { name: "Project workspace: django" })).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Retained project analysis timeline" })).toBeInTheDocument();
    expect(window.location.hash).toContain("project=project-archive-1");
  });

  it("opens a project finding explorer with a restorable project link", async () => {
    projectCreated = true;
    projectLatestJobStatus = "completed";
    render(<App />);

    fireEvent.click(await screen.findByRole("button", { name: "Explore findings for django" }));

    expect(await screen.findByRole("heading", { name: "Findings: django" })).toBeInTheDocument();
    expect(await screen.findByText("Dependency is not exactly pinned")).toBeInTheDocument();
    expect(window.location.hash).toContain("project=project-archive-1");
  });

  it("refreshes project status while an active project job is being monitored", async () => {
    projectCreated = true;
    projectLatestJobStatus = "queued";
    vi.useFakeTimers();
    render(<App />);

    await act(async () => {});
    const projectsTable = screen.getByRole("region", { name: "Projects table. Scroll horizontally to view all fields." });
    expect(within(projectsTable).getByText("queued")).toBeInTheDocument();
    projectLatestJobStatus = "completed";
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });

    expect(screen.getByRole("button", { name: "Run recorded snapshot for django again" })).toBeEnabled();
  });

  it("starts a Django config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const buttons = screen.getAllByRole("button", { name: /Analyze Django config/i });
    fireEvent.click(buttons[buttons.length - 1]);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/django-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a Docker config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const labels = screen.getAllByText("Analyze Docker config");
    const button = labels[labels.length - 1].closest("button");
    expect(button).not.toBeNull();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/docker-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a secrets review audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze secrets review"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze secrets review");
    expect(pdfRow?.textContent).not.toContain("Analyze secrets review");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze secrets review")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/secrets-review/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a Node package config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze Node package config"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze Node package config");
    expect(pdfRow?.textContent).not.toContain("Analyze Node package config");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze Node package config")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/node-package-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a CI/CD config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze CI/CD config"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze CI/CD config");
    expect(pdfRow?.textContent).not.toContain("Analyze CI/CD config");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze CI/CD config")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/ci-cd-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a Kubernetes config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze Kubernetes config"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze Kubernetes config");
    expect(pdfRow?.textContent).not.toContain("Analyze Kubernetes config");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze Kubernetes config")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/k8s-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a Terraform config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze Terraform config"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze Terraform config");
    expect(pdfRow?.textContent).not.toContain("Analyze Terraform config");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze Terraform config")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/terraform-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a Nginx config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze Nginx config"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze Nginx config");
    expect(pdfRow?.textContent).not.toContain("Analyze Nginx config");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze Nginx config")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/nginx-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a Compose config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze Compose config"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze Compose config");
    expect(pdfRow?.textContent).not.toContain("Analyze Compose config");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze Compose config")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/compose-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a Database config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze database config"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze database config");
    expect(pdfRow?.textContent).not.toContain("Analyze database config");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze database config")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/database-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a Redis config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze Redis config"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze Redis config");
    expect(pdfRow?.textContent).not.toContain("Analyze Redis config");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze Redis config")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/redis-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });

  it("starts a SQL DB config audit from an archive action", async () => {
    render(<App />);

    await screen.findAllByText("django.zip");
    const rows = Array.from(document.querySelectorAll("tr"));
    const archiveRow = rows.find((row) => row.textContent?.includes("django.zip") && row.textContent.includes("Analyze SQL DB config"));
    const pdfRow = rows.find((row) => row.textContent?.includes("sample.pdf") && row.textContent.includes("Analyze PDF"));
    expect(archiveRow?.textContent).toContain("Analyze SQL DB config");
    expect(pdfRow?.textContent).not.toContain("Analyze SQL DB config");
    const button = Array.from(archiveRow?.querySelectorAll("button") ?? []).find((item) =>
      item.textContent?.includes("Analyze SQL DB config")
    );
    expect(button).toBeDefined();
    fireEvent.click(button as HTMLButtonElement);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/audits/sql-database-config/file-archive-1",
        expect.objectContaining({ method: "POST" })
      );
    });
  });
});
