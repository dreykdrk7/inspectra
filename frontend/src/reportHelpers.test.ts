import { describe, expect, it } from "vitest";

import { buildArchiveAuditReport } from "./archiveReport";
import { buildDjangoConfigAuditReport, redactDjangoConfigValue } from "./djangoConfigReport";
import { buildDomainAuditReport } from "./domainReport";
import { buildDockerConfigAuditReport, redactDockerConfigValue } from "./dockerConfigReport";
import { buildImageAuditReport } from "./imageReport";
import { buildManifestAuditReport } from "./manifestReport";
import { buildPdfAuditReport } from "./pdfReport";
import { buildProjectArchiveAuditReport } from "./projectArchiveReport";
import { buildSubdomainAuditReport } from "./subdomainReport";
import { buildWebAuditReport } from "./webReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-1",
  file_id: "file-1",
  target_url: null,
  target_domain: null,
  status: "completed",
  created_at: "2026-05-26T10:00:00Z",
  updated_at: "2026-05-26T10:01:00Z",
  source_file_deleted_at: null,
  error: null
} satisfies Omit<JobRecord, "audit_type" | "result">;

describe("report helpers", () => {
  it("builds a PDF report with missing optional fields", () => {
    const report = buildPdfAuditReport({ ...baseJob, audit_type: "pdf_basic", result: null });

    expect(report.isPdfAudit).toBe(true);
    expect(report.hashes).toEqual([]);
    expect(report.validation.qpdfOk).toBeNull();
    expect(report.tools).toEqual([]);
  });

  it("extracts image privacy indicators when present", () => {
    const report = buildImageAuditReport({
      ...baseJob,
      audit_type: "image_basic",
      result: {
        analyzer: "inspectra-image-basic",
        privacy_indicators: {
          gps_present: true,
          fields: { gps: ["GPSLatitude"] }
        }
      }
    });

    expect(report.isImageAudit).toBe(true);
    expect(report.privacyIndicators.find((indicator) => indicator.key === "gps")).toMatchObject({
      present: true,
      fields: ["GPSLatitude"]
    });
  });

  it("normalizes manifest dependencies and findings", () => {
    const report = buildManifestAuditReport({
      ...baseJob,
      audit_type: "manifest_basic",
      result: {
        manifest_type: "package_json",
        parsed: {
          project: { name: "demo" },
          dependencies: {
            dependencies: [{ name: "react", specifier: "^18.3.1" }]
          }
        },
        summary: {
          total_dependencies: 1,
          dependency_groups: ["dependencies"],
          informational_findings_count: 1
        },
        findings: [{ id: "dependency_not_exactly_pinned", title: "Review range", level: "info" }]
      }
    });

    expect(report.isManifestAudit).toBe(true);
    expect(report.manifestType).toBe("package_json");
    expect(report.project).toContainEqual({ label: "name", value: "demo" });
    expect(report.dependencies[0].dependencies[0]).toMatchObject({ name: "react", specifier: "^18.3.1" });
    expect(report.findings[0]).toMatchObject({ id: "dependency_not_exactly_pinned", title: "Review range" });
  });

  it("normalizes archive summaries, findings, and entry flags", () => {
    const report = buildArchiveAuditReport({
      ...baseJob,
      audit_type: "archive_basic",
      result: {
        archive_type: "zip",
        hashes: { sha256: "abc" },
        summary: { total_entries: 2, findings_count: 1 },
        detected_manifests: [{ path: "package.json", manifest_type: "package.json" }],
        findings: [{ id: "archive_sensitive_name_entry", title: "Sensitive name", level: "medium" }],
        entries_sample: [
          {
            path: ".env",
            type: "file",
            size: 10,
            compressed_size: 8,
            mode: "0o644",
            depth: 1,
            flags: { sensitive_name: true, manifest_file: false }
          }
        ]
      }
    });

    expect(report.isArchiveAudit).toBe(true);
    expect(report.archiveType).toBe("zip");
    expect(report.detectedManifests[0]).toMatchObject({ path: "package.json" });
    expect(report.findings[0]).toMatchObject({ id: "archive_sensitive_name_entry", level: "medium" });
    expect(report.entriesSample[0].flags).toContainEqual({ label: "sensitive_name", value: "true" });
  });

  it("normalizes project archive parsed manifests and findings", () => {
    const report = buildProjectArchiveAuditReport({
      ...baseJob,
      audit_type: "project_archive_basic",
      result: {
        archive_type: "zip",
        summary: { supported_manifests_parsed: 1, total_dependencies: 1, findings_count: 1 },
        supported_manifests: [{ path: "package.json", manifest_type: "package_json", status: "parsed" }],
        unsupported_manifests: [{ path: "package-lock.json", manifest_type: "package-lock.json" }],
        parsed_manifests: [
          {
            path: "package.json",
            manifest_type: "package_json",
            size_bytes: 64,
            parsed: {
              project: { name: "demo" },
              dependencies: { dependencies: [{ name: "react", specifier: "^18.3.1" }] },
              scripts: { postinstall: "node setup.js" }
            },
            findings: [{ id: "package_sensitive_lifecycle_script", title: "Lifecycle script", level: "medium" }],
            errors: []
          }
        ],
        findings: [{ id: "package_sensitive_lifecycle_script", title: "Lifecycle script", level: "medium" }]
      }
    });

    expect(report.isProjectArchiveAudit).toBe(true);
    expect(report.supportedManifests[0]).toMatchObject({ path: "package.json", status: "parsed" });
    expect(report.unsupportedManifests[0]).toMatchObject({ path: "package-lock.json" });
    expect(report.parsedManifests[0].project).toContainEqual({ label: "name", value: "demo" });
    expect(report.parsedManifests[0].dependencies[0].dependencies[0]).toMatchObject({ name: "react" });
    expect(report.findings[0]).toMatchObject({ id: "package_sensitive_lifecycle_script" });
  });

  it("normalizes web audit headers, cookies, and findings", () => {
    const report = buildWebAuditReport({
      ...baseJob,
      audit_type: "web_basic",
      file_id: null,
      target_url: "http://example.test/",
      result: {
        analyzer: "web_basic",
        target: {
          final_url: "http://example.test/?token=REDACTED&page=1",
          query_string_present: true,
          query_params_redacted: true,
          redacted_query_params: ["token"]
        },
        http: { status_code: 200 },
        security_headers: {
          "Content-Security-Policy": { present: false, value: null },
          "X-Content-Type-Options": { present: true, value: "nosniff" }
        },
        cookies: [{ name: "sid", value_redacted: true, value_length: 11, secure: false, httponly: true, samesite: "Lax" }],
        findings: [{ id: "web_csp_missing", title: "CSP missing", level: "info" }]
      }
    });

    expect(report.isWebAudit).toBe(true);
    expect(report.securityHeaders).toContainEqual({ name: "Content-Security-Policy", present: false, value: null });
    expect(report.cookies[0]).toMatchObject({ name: "sid", httponly: true, valueRedacted: true, valueLength: 11 });
    expect(report.findings[0]).toMatchObject({ id: "web_csp_missing" });
    expect(report.queryStringPresent).toBe(true);
    expect(report.queryParamsRedacted).toBe(true);
    expect(report.redactedQueryParams).toEqual(["token"]);
  });

  it("normalizes domain audit DNS, email security, and findings", () => {
    const report = buildDomainAuditReport({
      ...baseJob,
      audit_type: "domain_basic",
      file_id: null,
      target_domain: "example.com",
      result: {
        analyzer: "domain_basic",
        target: { normalized_domain: "example.com" },
        dns: {
          A: ["93.184.216.34"],
          MX: [{ preference: 10, exchange: "mail.example.com" }],
          www: { checked: true, domain: "www.example.com", CNAME: ["example.com"] }
        },
        email_security: {
          spf: { present: true, all_mechanism: "-all" },
          dmarc: { present: true, policy: "reject" },
          dkim: { checked: false, status: "not_checked" }
        },
        findings: [{ id: "domain_caa_absent", title: "CAA absent", level: "info" }],
        errors: []
      }
    });

    expect(report.isDomainAudit).toBe(true);
    expect(report.target).toContainEqual({ label: "normalized_domain", value: "example.com" });
    expect(report.spf).toContainEqual({ label: "present", value: "true" });
    expect(report.dmarc).toContainEqual({ label: "policy", value: "reject" });
    expect(report.www[0]).toMatchObject({ label: "checked" });
    expect(report.findings[0]).toMatchObject({ id: "domain_caa_absent" });
  });

  it("normalizes subdomain inventory candidates, DNS results, and findings", () => {
    const report = buildSubdomainAuditReport({
      ...baseJob,
      audit_type: "subdomain_inventory_basic",
      file_id: null,
      target_domain: "example.com",
      result: {
        analyzer: "subdomain_inventory_basic",
        target: { normalized_root_domain: "example.com" },
        summary: {
          candidates_accepted: 2,
          resolved_count: 1,
          findings_count: 1,
          truncated: true,
          deadline_reached: true
        },
        limits: { global_deadline_seconds: 30, max_candidates: 100 },
        candidates: [
          { input: "www", fqdn: "www.example.com", status: "accepted" },
          { input: "api.evil.com", status: "rejected", rejection_reason: "outside root" }
        ],
        results: [
          {
            fqdn: "www.example.com",
            resolves: true,
            status: "processed",
            A: ["93.184.216.34"],
            AAAA: [],
            CNAME: ["example.net"],
            private_or_reserved_ip_detected: false,
            errors: []
          },
          {
            fqdn: "api.example.com",
            resolves: false,
            status: "skipped",
            skip_reason: "global_deadline_reached",
            deadline_reached: true,
            A: [],
            AAAA: [],
            CNAME: [],
            private_or_reserved_ip_detected: false,
            errors: ["Skipped because the global subdomain inventory deadline was reached."]
          }
        ],
        wildcard_dns: { checked: true, possible: false, probes_count: 2 },
        findings: [{ id: "subdomain_external_cname", title: "External CNAME", level: "info" }],
        errors: []
      }
    });

    expect(report.isSubdomainAudit).toBe(true);
    expect(report.target).toContainEqual({ label: "normalized_root_domain", value: "example.com" });
    expect(report.candidates[0]).toMatchObject({ input: "www", fqdn: "www.example.com", status: "accepted" });
    expect(report.candidates[1]).toMatchObject({ status: "rejected", rejectionReason: "outside root" });
    expect(report.results[0]).toMatchObject({ fqdn: "www.example.com", resolves: true, cname: ["example.net"] });
    expect(report.results[1]).toMatchObject({ status: "skipped", skipReason: "global_deadline_reached", deadlineReached: true });
    expect(report.truncated).toBe(true);
    expect(report.deadlineReached).toBe(true);
    expect(report.limits).toContainEqual({ label: "global_deadline_seconds", value: "30" });
    expect(report.findings[0]).toMatchObject({ id: "subdomain_external_cname" });
  });

  it("tolerates sparse subdomain inventory results", () => {
    const report = buildSubdomainAuditReport({
      ...baseJob,
      audit_type: "subdomain_inventory_basic",
      file_id: null,
      target_domain: "example.com",
      result: {
        analyzer: "subdomain_inventory_basic",
        target: { normalized_root_domain: "example.com" },
        summary: {}
      }
    });

    expect(report.isSubdomainAudit).toBe(true);
    expect(report.target).toContainEqual({ label: "normalized_root_domain", value: "example.com" });
    expect(report.candidates).toEqual([]);
    expect(report.results).toEqual([]);
    expect(report.findings).toEqual([]);
  });

  it("normalizes Django config detected files, signals, and redacted findings", () => {
    const report = buildDjangoConfigAuditReport({
      ...baseJob,
      audit_type: "django_config_basic",
      result: {
        analyzer: "django_config_basic",
        archive_type: "zip",
        summary: {
          files_read: 1,
          findings_count: 2,
          secrets_redacted_count: 1,
          truncated: false
        },
        limits: { max_files: 100 },
        detected_files: [
          { path: "project/settings.py", category: "django_config", read: true, size_bytes: 128 },
          { path: ".env", category: "env_sensitive", read: false, skip_reason: "sensitive_env_not_read" }
        ],
        django_signals: {
          debug: { status: "enabled_or_default_true", files: ["project/settings.py"] },
          secret_key: { status: "hardcoded", files: ["project/settings.py"] }
        },
        findings: [
          {
            id: "django_secret_key_hardcoded",
            title: "Django SECRET_KEY appears hardcoded",
            level: "medium",
            evidence: "SECRET_KEY = [REDACTED]",
            file_path: "project/settings.py",
            context: "shared"
          },
          {
            id: "django_csrf_cookie_secure_not_true",
            title: "CSRF_COOKIE_SECURE was not observed as true",
            level: "low",
            evidence: "CSRF_COOKIE_SECURE = not observed as True; files: project/settings.py; contexts: shared",
            context: "grouped"
          }
        ],
        errors: []
      }
    });

    expect(report.isDjangoConfigAudit).toBe(true);
    expect(report.archiveType).toBe("zip");
    expect(report.overview).toContainEqual({ label: "Files reviewed", value: "1" });
    expect(report.overview).toContainEqual({ label: "Sensitive env files", value: "1" });
    expect(report.filesReadCount).toBe(1);
    expect(report.findingsCount).toBe(2);
    expect(report.envSensitiveCount).toBe(1);
    expect(report.detectedFiles[0]).toMatchObject({ path: "project/settings.py", read: true });
    expect(report.detectedFiles[1]).toMatchObject({ path: ".env", read: false, skipReason: "sensitive_env_not_read" });
    expect(report.reviewedFiles[0]).toMatchObject({ path: "project/settings.py" });
    expect(report.sensitiveEnvFiles[0]).toMatchObject({ path: ".env", category: "env_sensitive" });
    expect(report.signals).toContainEqual({ label: "debug.status", value: "enabled_or_default_true" });
    expect(report.findings[0]).toMatchObject({ id: "django_secret_key_hardcoded", evidence: "SECRET_KEY = [REDACTED]", context: "shared" });
    expect(report.findings[1]).toMatchObject({ id: "django_csrf_cookie_secure_not_true", filePath: null, context: "grouped" });
    expect(report.findingGroups.map((group) => group.level)).toEqual(["medium", "low"]);
  });

  it("tolerates sparse Django config results", () => {
    const report = buildDjangoConfigAuditReport({
      ...baseJob,
      audit_type: "django_config_basic",
      result: {
        analyzer: "django_config_basic",
        summary: {}
      }
    });

    expect(report.isDjangoConfigAudit).toBe(true);
    expect(report.detectedFiles).toEqual([]);
    expect(report.findings).toEqual([]);
    expect(report.errors).toEqual([]);
  });

  it("redacts legacy Django config secret-like values", () => {
    const report = buildDjangoConfigAuditReport({
      ...baseJob,
      audit_type: "django_config_basic",
      error: "TOKEN=super-secret-value-123",
      result: {
        analyzer: "django_config_basic",
        summary: { secrets_redacted_count: 0 },
        detected_files: [
          { path: "project/settings.py", category: "django_config", read: false, skip_reason: "DATABASE_URL=postgres://user:rawpass@db/app" }
        ],
        django_signals: {
          secret_key: { status: "SECRET_KEY = 'django-insecure-test-secret'", files: ["project/settings.py"] }
        },
        findings: [
          {
            id: "legacy_secret",
            title: "Legacy secret",
            level: "medium",
            evidence: "SECRET_KEY = 'super-secret-value-123'",
            description: "DATABASE_URL=postgres://user:rawpass@db/app",
            recommendation: "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----"
          }
        ],
        errors: ["PASSWORD=super-secret-value-123"]
      }
    });
    const serializedReport = JSON.stringify(report);
    const redactedRaw = JSON.stringify(redactDjangoConfigValue({
      error: "TOKEN=super-secret-value-123",
      result: report
    }));

    for (const secret of ["super-secret-value-123", "django-insecure-test-secret", "rawpass", "abc123", "BEGIN PRIVATE KEY"]) {
      expect(serializedReport).not.toContain(secret);
      expect(redactedRaw).not.toContain(secret);
    }
    expect(serializedReport).toContain("REDACTED");
    expect(report.findings[0].evidence).toContain("[REDACTED]");
    expect(report.detectedFiles[0].skipReason).toContain("[REDACTED]");
  });

  it("normalizes Docker config files, stages, services, and findings", () => {
    const report = buildDockerConfigAuditReport({
      ...baseJob,
      audit_type: "docker_config_basic",
      result: {
        analyzer: "docker_config_basic",
        archive_type: "zip",
        summary: {
          files_reviewed: 2,
          dockerfiles_detected: 1,
          compose_files_detected: 1,
          services_detected: 1,
          findings_count: 2,
          secrets_redacted_count: 1,
          truncated: false
        },
        limits: { max_files: 100 },
        files_detected: [
          { path: "Dockerfile", category: "dockerfile", read: true, size_bytes: 128, context: "shared" },
          { path: "docker-compose.yml", category: "compose", read: true, size_bytes: 256, context: "production" }
        ],
        dockerfile_stages: [
          {
            file_path: "Dockerfile",
            context: "shared",
            stage: "runtime",
            base_image: "python:latest",
            user_observed: false,
            healthcheck_observed: true
          }
        ],
        compose_services: [
          {
            file_path: "docker-compose.yml",
            service: "web",
            context: "production",
            image: "example/web:latest",
            ports: ["8000:8000"],
            privileged: false,
            read_only: true,
            network_mode: "bridge"
          }
        ],
        findings: [
          {
            id: "docker_latest_tag",
            title: "Docker base image uses latest tag",
            level: "low",
            category: "image",
            context: "shared",
            file_path: "Dockerfile",
            stage: "runtime",
            evidence: "FROM python:latest"
          },
          {
            id: "docker_missing_healthcheck",
            title: "Healthcheck not observed",
            category: "compose",
            context: "production",
            service: "web",
            evidence: "healthcheck not observed"
          }
        ],
        redaction_notes: ["Sensitive environment values were redacted."],
        errors: []
      }
    });

    expect(report.isDockerConfigAudit).toBe(true);
    expect(report.archiveType).toBe("zip");
    expect(report.overview).toContainEqual({ label: "Files reviewed", value: "2" });
    expect(report.overview).toContainEqual({ label: "Dockerfiles", value: "1" });
    expect(report.detectedFiles[0]).toMatchObject({ path: "Dockerfile", context: "shared", read: true });
    expect(report.stages[0]).toMatchObject({ filePath: "Dockerfile", baseImage: "python:latest", userObserved: false });
    expect(report.composeServices[0]).toMatchObject({ filePath: "docker-compose.yml", name: "web", ports: ["8000:8000"] });
    expect(report.findings[0]).toMatchObject({ id: "docker_latest_tag", level: "low", filePath: "Dockerfile" });
    expect(report.findings[1]).toMatchObject({ id: "docker_missing_healthcheck", level: "unknown", filePath: null, service: "web" });
    expect(report.findingGroups.map((group) => group.level)).toEqual(["low", "unknown"]);
    expect(report.redactionNotes).toEqual(["Sensitive environment values were redacted."]);
  });

  it("tolerates sparse Docker config results", () => {
    const report = buildDockerConfigAuditReport({
      ...baseJob,
      audit_type: "docker_config_basic",
      result: {
        analyzer: "docker_config_basic",
        summary: {}
      }
    });

    expect(report.isDockerConfigAudit).toBe(true);
    expect(report.detectedFiles).toEqual([]);
    expect(report.stages).toEqual([]);
    expect(report.composeServices).toEqual([]);
    expect(report.findings).toEqual([]);
    expect(report.errors).toEqual([]);
  });

  it("redacts legacy Docker config secret-like values", () => {
    const report = buildDockerConfigAuditReport({
      ...baseJob,
      audit_type: "docker_config_basic",
      error: "TOKEN=super-secret-value-123",
      result: {
        analyzer: "docker_config_basic",
        summary: { secrets_redacted_count: 0 },
        files_detected: [
          { path: "docker-compose.yml", category: "compose", read: false, skip_reason: "DATABASE_URL=postgres://user:rawpass@db/app" }
        ],
        findings: [
          {
            id: "legacy_secret",
            title: "Legacy secret",
            level: "medium",
            evidence: "SECRET_KEY = 'super-secret-value-123'",
            description: "DATABASE_URL=postgres://user:rawpass@db/app",
            recommendation: "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----"
          }
        ],
        errors: ["PASSWORD=super-secret-value-123"]
      }
    });
    const serializedReport = JSON.stringify(report);
    const redactedRaw = JSON.stringify(redactDockerConfigValue({
      error: "TOKEN=super-secret-value-123",
      result: report
    }));

    for (const secret of ["super-secret-value-123", "rawpass", "abc123", "BEGIN PRIVATE KEY"]) {
      expect(serializedReport).not.toContain(secret);
      expect(redactedRaw).not.toContain(secret);
    }
    expect(serializedReport).toContain("REDACTED");
    expect(report.findings[0].evidence).toContain("[REDACTED]");
    expect(report.detectedFiles[0].skipReason).toContain("[REDACTED]");
  });
});
