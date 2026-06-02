import { describe, expect, it } from "vitest";

import { buildArchiveAuditReport } from "./archiveReport";
import { buildCiCdConfigAuditReport, redactCiCdConfigValue } from "./ciCdConfigReport";
import { buildComposeConfigAuditReport, redactComposeConfigValue } from "./composeConfigReport";
import { buildDatabaseConfigAuditReport, redactDatabaseConfigValue } from "./databaseConfigReport";
import { buildDjangoConfigAuditReport, redactDjangoConfigValue } from "./djangoConfigReport";
import { buildDomainAuditReport } from "./domainReport";
import { buildDockerConfigAuditReport, redactDockerConfigValue } from "./dockerConfigReport";
import { buildImageAuditReport } from "./imageReport";
import { buildK8sConfigAuditReport, redactK8sConfigValue } from "./k8sConfigReport";
import { buildManifestAuditReport } from "./manifestReport";
import { buildNginxConfigAuditReport, redactNginxConfigValue } from "./nginxConfigReport";
import { buildNodePackageConfigAuditReport, redactNodePackageConfigValue } from "./nodePackageConfigReport";
import { buildPdfAuditReport } from "./pdfReport";
import { buildProjectArchiveAuditReport } from "./projectArchiveReport";
import { buildRedisConfigAuditReport, redactRedisConfigValue } from "./redisConfigReport";
import { buildSecretsReviewAuditReport, redactSecretsReviewValue } from "./secretsReviewReport";
import { buildSubdomainAuditReport } from "./subdomainReport";
import { buildTerraformConfigAuditReport, redactTerraformConfigValue } from "./terraformConfigReport";
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

  it("normalizes secrets review files, findings, confidence, and redacted values", () => {
    const report = buildSecretsReviewAuditReport({
      ...baseJob,
      audit_type: "secrets_review_basic",
      result: {
        analyzer: "secrets_review_basic",
        archive_type: "zip",
        summary: {
          files_considered: 3,
          files_reviewed: 2,
          sensitive_files_detected: 1,
          findings_count: 2,
          high_confidence_count: 1,
          redacted_values_count: 2,
          truncated: false
        },
        limits: { max_files: 100 },
        files_detected: [
          { path: ".env.production", category: "env_sensitive", read: false, skip_reason: "real_env_file_not_read", context: "production" },
          { path: ".env.example", category: "env_template", read: true, bytes_read: 64, context: "example" }
        ],
        files_reviewed: [{ path: ".env.example", category: "env_template", read: true, bytes_read: 64, context: "example" }],
        sensitive_files: [{ path: ".env.production", category: "env_sensitive", read: false, skip_reason: "real_env_file_not_read", context: "production" }],
        findings: [
          {
            id: "secret_like_assignment",
            title: "Secret-like assignment observed",
            level: "medium",
            confidence: "high",
            category: "assignment",
            context: "production",
            file_path: "settings.py",
            line: "12",
            evidence: "SECRET_KEY=[REDACTED]"
          },
          {
            code: "weak_placeholder_secret",
            message: "Placeholder secret",
            severity: "info",
            confidence: "low",
            category: "placeholder"
          }
        ],
        redaction_notes: ["Values were redacted."],
        errors: []
      }
    });

    expect(report.isSecretsReviewAudit).toBe(true);
    expect(report.archiveType).toBe("zip");
    expect(report.overview).toContainEqual({ label: "Sensitive files", value: "1" });
    expect(report.sensitiveFiles[0]).toMatchObject({ path: ".env.production", read: false, context: "production" });
    expect(report.reviewedFiles[0]).toMatchObject({ path: ".env.example", bytesRead: 64 });
    expect(report.findings[0]).toMatchObject({
      id: "secret_like_assignment",
      level: "medium",
      confidence: "high",
      category: "assignment",
      line: 12,
      filePath: "settings.py"
    });
    expect(report.findings[1]).toMatchObject({ id: "weak_placeholder_secret", title: "Placeholder secret", level: "info" });
    expect(report.findingGroups.map((group) => group.level)).toEqual(["medium", "info"]);
    expect(report.redactionNotes).toEqual(["Values were redacted."]);
  });

  it("redacts legacy secrets review payloads defensively", () => {
    const report = buildSecretsReviewAuditReport({
      ...baseJob,
      audit_type: "secrets_review_basic",
      error: "TOKEN=fixture-secret-key-value",
      result: {
        analyzer: "secrets_review_basic",
        summary: { redacted_values_count: 0 },
        raw_secret: "fixture-secret-key-value",
        secret_value: { nested: "fixture-secret-key-value" },
        sensitive_files: [
          { path: ".env.production", category: "env_sensitive", read: false, skip_reason: "SECRET_KEY=fixture-secret-key-value" }
        ],
        findings: [
          {
            id: "legacy_secret",
            title: "Legacy secret",
            level: "medium",
            evidence: "SECRET_KEY=fixture-secret-key-value",
            description: "DATABASE_URL=postgres://user:fixture-db-password@db/app",
            recommendation: "REDIS_URL=redis://:fixture-redis-password@redis:6379/0"
          },
          {
            id: "legacy_private_key",
            title: "Legacy private key",
            evidence: "-----BEGIN PRIVATE KEY----- fixture material -----END PRIVATE KEY-----"
          },
          {
            id: "legacy_jwt",
            title: "Legacy JWT",
            evidence: "eyJhbGciOiJIUzI1NiJ9.fixture.fixture"
          }
        ],
        errors: ["https://user:fixture-db-password@example.com/path?token=fixture-secret-key-value"]
      }
    });
    const serializedReport = JSON.stringify(report);
    const redactedRaw = JSON.stringify(redactSecretsReviewValue({
      error: "TOKEN=fixture-secret-key-value",
      result: report
    }));

    for (const secret of [
      "fixture-secret-key-value",
      "fixture-db-password",
      "fixture-redis-password",
      "fixture material",
      "eyJhbGciOiJIUzI1NiJ9.fixture.fixture"
    ]) {
      expect(serializedReport).not.toContain(secret);
      expect(redactedRaw).not.toContain(secret);
    }
    expect(serializedReport).toContain("REDACTED");
    expect(report.findings[0].evidence).toContain("[REDACTED]");
    expect(report.sensitiveFiles[0].skipReason).toContain("[REDACTED]");
  });

  it("normalizes Node package config package, script, dependency, signal, lockfile, and finding data", () => {
    const report = buildNodePackageConfigAuditReport({
      ...baseJob,
      audit_type: "node_package_config_basic",
      result: {
        analyzer: "node_package_config_basic",
        archive_type: "zip",
        summary: {
          files_considered: 5,
          files_reviewed: 4,
          package_manifests_detected: 1,
          lockfiles_detected: 1,
          package_manager_configs_detected: 1,
          packages_detected: 1,
          scripts_detected: 2,
          findings_count: 2,
          redacted_values_count: 1,
          truncated: false
        },
        limits: { max_files: 100 },
        files_detected: [
          { path: "package.json", category: "package_manifest", read: true, bytes_read: 256, context: "shared" },
          { path: ".npmrc", category: "package_manager_config", read: true, bytes_read: 64, context: "production" }
        ],
        files_reviewed: [{ path: "package.json", category: "package_manifest", read: true, bytes_read: 256, context: "shared" }],
        packages: [
          {
            path: "package.json",
            name: "demo",
            version: "1.0.0",
            private: false,
            package_manager: "pnpm@9.0.0",
            workspace: "packages/*",
            context: "shared"
          }
        ],
        scripts: [{ path: "package.json", name: "postinstall", excerpt: "node scripts/setup.js", context: "shared" }],
        dependency_groups: [
          {
            path: "package.json",
            group: "dependencies",
            context: "shared",
            dependencies: [{ name: "react", specifier: "^18.3.1", source_type: "registry", indicators: ["range"] }]
          }
        ],
        package_manager_config_signals: [{ path: ".npmrc", key: "_authToken", value: "[REDACTED]", line: "2", context: "production" }],
        lockfile_signals: [{ path: "pnpm-lock.yaml", lockfile: "pnpm-lock.yaml", manager: "pnpm", read: true, context: "shared" }],
        findings: [
          {
            id: "postinstall_script_present",
            title: "postinstall script is present",
            level: "low",
            confidence: "medium",
            category: "script",
            context: "shared",
            file_path: "package.json",
            line: "8",
            evidence: "postinstall: node scripts/setup.js"
          },
          {
            code: "npmrc_token_reference_detected",
            message: "npm token",
            severity: "medium",
            confidence: "high",
            category: "package_manager_config"
          }
        ],
        redaction_notes: ["Values were redacted."],
        errors: []
      }
    });

    expect(report.isNodePackageConfigAudit).toBe(true);
    expect(report.archiveType).toBe("zip");
    expect(report.overview).toContainEqual({ label: "Packages", value: "1" });
    expect(report.detectedFiles[0]).toMatchObject({ path: "package.json", read: true, context: "shared" });
    expect(report.packages[0]).toMatchObject({ path: "package.json", name: "demo", packageManager: "pnpm@9.0.0" });
    expect(report.scripts[0]).toMatchObject({ name: "postinstall", category: "lifecycle" });
    expect(report.dependencyGroups[0].dependencies[0]).toMatchObject({ name: "react", sourceType: "registry" });
    expect(report.packageManagerConfigSignals[0]).toMatchObject({ key: "_authToken", value: "[REDACTED]", line: 2 });
    expect(report.lockfileSignals[0]).toMatchObject({ lockfile: "pnpm-lock.yaml", manager: "pnpm", read: true });
    expect(report.findings[0]).toMatchObject({ id: "postinstall_script_present", level: "low", confidence: "medium", line: 8 });
    expect(report.findings[1]).toMatchObject({ id: "npmrc_token_reference_detected", title: "npm token", level: "medium" });
    expect(report.findingGroups.map((group) => group.level)).toEqual(["medium", "low"]);
    expect(report.redactionNotes).toEqual(["Values were redacted."]);
  });

  it("redacts legacy Node package config payloads defensively", () => {
    const report = buildNodePackageConfigAuditReport({
      ...baseJob,
      audit_type: "node_package_config_basic",
      error: "_authToken=fixture-token",
      result: {
        analyzer: "node_package_config_basic",
        summary: { redacted_values_count: 0 },
        scripts: [{ path: "package.json", name: "build", excerpt: "API_KEY=fixture-key npm run build" }],
        package_manager_config_signals: [
          {
            path: ".npmrc",
            key: "_authToken",
            value: "fixture-token",
            registry: "https://user:fixture-password@registry.example.test/pkg"
          }
        ],
        findings: [
          {
            id: "legacy_node_secret",
            title: "Legacy node secret",
            evidence: "_auth=fixture-auth",
            description: "https://example.test/hook?token=fixture-token&key=fixture-key",
            recommendation: "secret=fixture-secret"
          }
        ],
        errors: ["password=fixture-password"]
      }
    });
    const serializedReport = JSON.stringify(report);
    const redactedRaw = JSON.stringify(
      redactNodePackageConfigValue({
        error: "_authToken=fixture-token",
        result: report
      })
    );

    for (const secret of [
      "fixture-token",
      "fixture-auth",
      "fixture-password",
      "fixture-key",
      "fixture-secret",
      "https://user:fixture-password@registry.example.test/pkg",
      "https://example.test/hook?token=fixture-token&key=fixture-key",
      "API_KEY=fixture-key npm run build"
    ]) {
      expect(serializedReport).not.toContain(secret);
      expect(redactedRaw).not.toContain(secret);
    }
    expect(serializedReport).toContain("REDACTED");
    expect(report.scripts[0].excerpt).toContain("[REDACTED]");
    expect(report.packageManagerConfigSignals[0].value).toBe("[REDACTED]");
  });

  it("normalizes CI/CD config workflows, jobs, signals, and findings", () => {
    const report = buildCiCdConfigAuditReport({
      ...baseJob,
      audit_type: "ci_cd_config_basic",
      result: {
        analyzer: "ci_cd_config_basic",
        archive_type: "zip",
        summary: {
          files_considered: 4,
          files_reviewed: 3,
          workflow_files_detected: 2,
          jobs_detected: 1,
          steps_detected: 2,
          triggers_detected: 1,
          findings_count: 2,
          redacted_values_count: 1,
          truncated: false
        },
        limits: { max_files: 100 },
        files_detected: [
          { path: ".github/workflows/release.yml", category: "github_actions", read: true, bytes_read: 1024, context: "production" },
          { path: ".env.production", category: "env_sensitive", read: false, skip_reason: "real_env_file_not_read", context: "production" }
        ],
        files_reviewed: [
          { path: ".github/workflows/release.yml", category: "github_actions", read: true, bytes_read: 1024, context: "production" }
        ],
        workflows: [
          {
            file_path: ".github/workflows/release.yml",
            provider: "github_actions",
            name: "release",
            jobs_count: 1,
            triggers: ["pull_request_target"],
            context: "production"
          }
        ],
        jobs: [
          {
            file_path: ".github/workflows/release.yml",
            provider: "github_actions",
            job: "publish",
            step: "npm publish",
            steps_detected: 2,
            evidence: "npm publish",
            context: "production"
          }
        ],
        triggers: [{ file_path: ".github/workflows/release.yml", provider: "github_actions", trigger: "pull_request_target", context: "production" }],
        permissions: [
          { file_path: ".github/workflows/release.yml", provider: "github_actions", permission: "contents", value: "write", context: "production" }
        ],
        actions: [
          {
            file_path: ".github/workflows/release.yml",
            provider: "github_actions",
            action: "actions/checkout",
            ref: "main",
            job: "publish",
            context: "production"
          },
          { file_path: ".gitlab-ci.yml", provider: "gitlab_ci", image: "node:latest", context: "shared" }
        ],
        service_containers: [
          { file_path: ".gitlab-ci.yml", provider: "gitlab_ci", service: "postgres", image: "postgres:latest", privileged: false, context: "shared" }
        ],
        publish_deploy_signals: [
          { file_path: ".github/workflows/release.yml", provider: "github_actions", job: "publish", signal: "npm publish", context: "production" }
        ],
        findings: [
          {
            id: "pull_request_target_used",
            title: "pull_request_target trigger requires review",
            level: "medium",
            confidence: "medium",
            category: "triggers",
            provider: "github_actions",
            context: "production",
            file_path: ".github/workflows/release.yml",
            job: "publish",
            step: "checkout",
            line: "4",
            evidence: "on: pull_request_target"
          },
          {
            code: "github_permissions_missing",
            message: "permissions block not observed",
            severity: "low",
            confidence: "medium"
          }
        ],
        redaction_notes: ["CI values were redacted."],
        errors: []
      }
    });

    expect(report.isCiCdConfigAudit).toBe(true);
    expect(report.archiveType).toBe("zip");
    expect(report.overview).toContainEqual({ label: "Workflows", value: "2" });
    expect(report.detectedFiles[0]).toMatchObject({ path: ".github/workflows/release.yml", read: true, context: "production" });
    expect(report.workflows[0]).toMatchObject({ provider: "github_actions", name: "release", jobsCount: 1 });
    expect(report.jobs[0]).toMatchObject({ job: "publish", step: "npm publish", stepsDetected: 2 });
    expect(report.triggers[0]).toMatchObject({ trigger: "pull_request_target" });
    expect(report.permissions[0]).toMatchObject({ permission: "contents", value: "write" });
    expect(report.actions[0]).toMatchObject({ action: "actions/checkout", ref: "main" });
    expect(report.serviceContainers[0]).toMatchObject({ service: "postgres", image: "postgres:latest" });
    expect(report.publishDeploySignals[0]).toMatchObject({ signal: "npm publish" });
    expect(report.findings[0]).toMatchObject({ id: "pull_request_target_used", provider: "github_actions", job: "publish", step: "checkout", line: 4 });
    expect(report.findings[1]).toMatchObject({ id: "github_permissions_missing", level: "low" });
    expect(report.findingGroups.map((group) => group.level)).toEqual(["medium", "low"]);
    expect(report.redactionNotes).toEqual(["CI values were redacted."]);
  });

  it("redacts legacy CI/CD config payloads defensively", () => {
    const report = buildCiCdConfigAuditReport({
      ...baseJob,
      audit_type: "ci_cd_config_basic",
      error: "TOKEN=fixture-token",
      result: {
        analyzer: "ci_cd_config_basic",
        summary: { redacted_values_count: 0 },
        jobs: [{ file_path: ".github/workflows/release.yml", job: "deploy", command: "API_KEY=fixture-key npm run build" }],
        actions: [{ file_path: ".github/workflows/release.yml", action: "deploy", image: "https://user:fixture-password@ci.example.test/hook" }],
        publish_deploy_signals: [
          { file_path: ".github/workflows/release.yml", signal: "deploy", evidence: "https://example.test/deploy?token=fixture-token&key=fixture-key" }
        ],
        findings: [
          {
            id: "legacy_ci_secret",
            title: "Legacy CI secret",
            evidence: "SECRET_KEY=fixture-secret",
            description: "PASSWORD=fixture-password",
            recommendation: "-----BEGIN PRIVATE KEY----- fixture material -----END PRIVATE KEY-----"
          }
        ],
        errors: ["CLIENT_SECRET=fixture-secret"]
      }
    });
    const serializedReport = JSON.stringify(report);
    const redactedRaw = JSON.stringify(
      redactCiCdConfigValue({
        error: "TOKEN=fixture-token",
        result: report
      })
    );

    for (const secret of [
      "fixture-token",
      "fixture-password",
      "fixture-key",
      "fixture-secret",
      "fixture material",
      "https://user:fixture-password@ci.example.test/hook",
      "https://example.test/deploy?token=fixture-token&key=fixture-key",
      "API_KEY=fixture-key npm run build"
    ]) {
      expect(serializedReport).not.toContain(secret);
      expect(redactedRaw).not.toContain(secret);
    }
    expect(serializedReport).toContain("REDACTED");
    expect(report.jobs[0].excerpt).toContain("[REDACTED]");
    expect(report.actions[0].image).toContain("[REDACTED]");
  });

  it("keeps CI/CD config sparse summaries aligned with runner field names", () => {
    const report = buildCiCdConfigAuditReport({
      ...baseJob,
      audit_type: "ci_cd_config_basic",
      result: {
        analyzer: "ci_cd_config_basic",
        files_detected: [
          { path: ".github/workflows/ci.yml", category: "github_workflow", read: true, context: "shared" },
          { path: ".github/actions/setup/action.yml", category: "github_action", read: true, context: "shared" },
          { path: ".env.production", category: "env_sensitive", read: false, skip_reason: "real_env_file_not_read", context: "production" }
        ],
        actions: [{ path: ".github/workflows/ci.yml", provider: "github_actions", action: "actions/checkout@main", context: "shared" }],
        findings: [{ id: "github_permissions_missing", title: "permissions missing" }],
        errors: []
      }
    });

    expect(report.workflowFilesDetectedCount).toBe(2);
    expect(report.overview).toContainEqual({ label: "Workflows", value: "2" });
    expect(report.actions[0]).toMatchObject({ action: "actions/checkout", ref: "main" });
    expect(report.findings[0]).toMatchObject({ id: "github_permissions_missing", level: "unknown", confidence: null });
  });

  it("normalizes Kubernetes config resources, findings, context, and runner field names", () => {
    const report = buildK8sConfigAuditReport({
      ...baseJob,
      audit_type: "k8s_config_basic",
      result: {
        analyzer: "k8s_config_basic",
        archive_type: "zip",
        summary: {
          files_considered: 5,
          files_reviewed: 4,
          manifest_files_detected: 4,
          resources_detected: 4,
          workloads_detected: 1,
          services_detected: 1,
          secrets_detected: 1,
          rbac_resources_detected: 1,
          findings_count: 2,
          redacted_values_count: 1,
          truncated: false
        },
        files_detected: [
          { path: "deploy/production/app.yaml", category: "k8s_manifest", read: true, context: "production" },
          { path: ".env.production", category: "env_sensitive", read: false, skip_reason: "real_env_file_not_read", context: "production" }
        ],
        resources: [{ path: "deploy/production/app.yaml", kind: "Deployment", name: "web", namespace: "prod", context: "production" }],
        workloads: [{ path: "deploy/production/app.yaml", kind: "Deployment", name: "web", namespace: "prod", context: "production" }],
        containers: [{ path: "deploy/production/app.yaml", kind: "Deployment", resource_name: "web", container: "app", image: "nginx:latest", context: "production" }],
        services: [{ path: "deploy/production/app.yaml", kind: "Service", name: "web", type: "LoadBalancer", context: "production" }],
        ingress: [{ path: "deploy/production/app.yaml", kind: "Ingress", name: "web", context: "production" }],
        rbac: [{ path: "deploy/production/app.yaml", kind: "ClusterRole", name: "broad", context: "production" }],
        secrets: [{ path: "deploy/production/app.yaml", kind: "Secret", name: "app-secret", namespace: "prod", context: "production" }],
        helm_kustomize_signals: [{ path: "charts/app/templates/deployment.yaml", category: "helm_template", rendered: false, context: "example" }],
        findings: [
          {
            id: "privileged_container",
            title: "Container is configured as privileged",
            level: "medium",
            confidence: "high",
            category: "pod_security",
            kind: "Deployment",
            resource_name: "web",
            namespace: "prod",
            container: "app",
            field_path: "securityContext.privileged",
            file_path: "deploy/production/app.yaml",
            context: "production",
            line: "22",
            evidence: "kind=Deployment; metadata.name=web; field=securityContext.privileged"
          },
          { code: "image_latest_tag", message: "image latest", severity: "low" }
        ],
        redaction_notes: ["Kubernetes values were redacted."],
        errors: []
      }
    });

    expect(report.isK8sConfigAudit).toBe(true);
    expect(report.overview).toContainEqual({ label: "Resources", value: "4" });
    expect(report.detectedFiles[0]).toMatchObject({ path: "deploy/production/app.yaml", context: "production" });
    expect(report.resources[0]).toMatchObject({ kind: "Deployment", name: "web", namespace: "prod" });
    expect(report.containers[0]).toMatchObject({ resourceName: "web", container: "app", image: "nginx:latest" });
    expect(report.services[0]).toMatchObject({ type: "LoadBalancer" });
    expect(report.helmKustomizeSignals[0]).toMatchObject({ category: "helm_template", rendered: false });
    expect(report.findings[0]).toMatchObject({ id: "privileged_container", fieldPath: "securityContext.privileged", line: 22 });
    expect(report.findingGroups.map((group) => group.level)).toEqual(["medium", "low"]);
    expect(report.redactionNotes).toEqual(["Kubernetes values were redacted."]);
  });

  it("redacts legacy Kubernetes config payloads defensively", () => {
    const report = buildK8sConfigAuditReport({
      ...baseJob,
      audit_type: "k8s_config_basic",
      error: "PASSWORD=super-secret-password",
      result: {
        analyzer: "k8s_config_basic",
        summary: { redacted_values_count: 0 },
        resources: [
          {
            kind: "Secret",
            name: "app-secret",
            stringData: { password: "super-secret-password", privateKey: "-----BEGIN PRIVATE KEY----- db_password_plaintext -----END PRIVATE KEY-----" },
            data: { token: "token_should_never_render" }
          }
        ],
        containers: [
          {
            container: "app",
            env: [{ name: "API_KEY", value: "raw-api-key-123456" }],
            image: "registry-user:registry-pass/k8s-app:latest"
          }
        ],
        secrets: [{ kind: "Secret", name: "app-secret", stringData: "TOKEN=token_should_never_render", data: "password=db_password_plaintext" }],
        findings: [
          {
            id: "legacy_k8s_secret",
            title: "Legacy Kubernetes secret",
            evidence: "PASSWORD=super-secret-password",
            description: "CLIENT_SECRET=token_should_never_render",
            recommendation: "-----BEGIN PRIVATE KEY----- db_password_plaintext -----END PRIVATE KEY-----"
          }
        ],
        errors: ["API_KEY=raw-api-key-123456"]
      }
    });
    const serializedReport = JSON.stringify(report);
    const redactedRaw = JSON.stringify(
      redactK8sConfigValue({
        error: "SECRET_KEY=fixture-secret",
        result: report
      })
    );

    for (const secret of [
      "super-secret-password",
      "raw-api-key-123456",
      "token_should_never_render",
      "PRIVATE KEY",
      "db_password_plaintext",
      "registry-user:registry-pass"
    ]) {
      expect(serializedReport).not.toContain(secret);
      expect(redactedRaw).not.toContain(secret);
    }
    expect(serializedReport).toContain("REDACTED");
    expect(report.findings[0].evidence).toContain("[REDACTED]");
    expect(report.containers[0].image).toContain("[REDACTED]");
  });

  it("normalizes Terraform config providers, resources, state files, findings, and runner field names", () => {
    const report = buildTerraformConfigAuditReport({
      ...baseJob,
      audit_type: "terraform_config_basic",
      result: {
        analyzer: "terraform_config_basic",
        archive_type: "zip",
        summary: {
          files_considered: 5,
          files_reviewed: 4,
          terraform_files_detected: 3,
          tfvars_files_detected: 1,
          state_files_detected: 1,
          providers_detected: 1,
          backends_detected: 1,
          modules_detected: 1,
          resources_detected: 2,
          findings_count: 2,
          redacted_values_count: 1,
          truncated: false
        },
        files_detected: [
          { path: "infra/production/main.tf", category: "terraform", read: true, context: "production" },
          { path: "infra/production/terraform.tfstate", category: "terraform_state", read: false, skip_reason: "state_file_not_read", context: "production" }
        ],
        providers: [{ file_path: "infra/production/providers.tf", name: "aws", source: "hashicorp/aws", version: "~> 5.0", context: "production" }],
        backends: [{ file_path: "infra/production/backend.tf", type: "s3", config_keys: ["bucket", "region"], context: "production" }],
        modules: [{ file_path: "infra/production/main.tf", name: "vpc", source: "terraform-aws-modules/vpc/aws", version: "5.0.0", context: "production" }],
        resources: [{ file_path: "infra/production/main.tf", provider: "aws", resource_type: "aws_security_group", resource_name: "web", context: "production" }],
        variables: [{ file_path: "infra/production/variables.tf", name: "db_password", sensitive: true, default_present: true, context: "production" }],
        outputs: [{ file_path: "infra/production/outputs.tf", name: "api_key", sensitive: false, context: "production" }],
        state_files: [{ path: "infra/production/terraform.tfstate", category: "terraform_state", read: false, skip_reason: "state_file_not_read", context: "production" }],
        findings: [
          {
            id: "aws_security_group_ssh_open_world",
            title: "Security group allows SSH from any IPv4 address",
            level: "medium",
            confidence: "high",
            category: "aws_network",
            provider: "aws",
            resource_type: "aws_security_group",
            resource_name: "web",
            field_path: "ingress.cidr_blocks",
            file_path: "infra/production/main.tf",
            context: "production",
            line: "22",
            evidence: "resource=aws_security_group.web; field=ingress.cidr_blocks"
          },
          { code: "terraform_lockfile_missing", message: "lockfile missing", severity: "low" }
        ],
        redaction_notes: ["Terraform values were redacted."],
        errors: []
      }
    });

    expect(report.isTerraformConfigAudit).toBe(true);
    expect(report.overview).toContainEqual({ label: "Resources", value: "2" });
    expect(report.detectedFiles[0]).toMatchObject({ path: "infra/production/main.tf", context: "production" });
    expect(report.providers[0]).toMatchObject({ name: "aws", source: "hashicorp/aws" });
    expect(report.backends[0]).toMatchObject({ type: "s3", configKeys: ["bucket", "region"] });
    expect(report.modules[0]).toMatchObject({ name: "vpc" });
    expect(report.resources[0]).toMatchObject({ resourceType: "aws_security_group", resourceName: "web" });
    expect(report.variables[0]).toMatchObject({ name: "db_password", defaultPresent: true });
    expect(report.outputs[0]).toMatchObject({ kind: "output", name: "api_key" });
    expect(report.stateFiles[0]).toMatchObject({ path: "infra/production/terraform.tfstate", read: false });
    expect(report.findings[0]).toMatchObject({ id: "aws_security_group_ssh_open_world", fieldPath: "ingress.cidr_blocks", line: 22 });
    expect(report.findingGroups.map((group) => group.level)).toEqual(["medium", "low"]);
    expect(report.redactionNotes).toEqual(["Terraform values were redacted."]);
  });

  it("redacts legacy Terraform config payloads defensively", () => {
    const report = buildTerraformConfigAuditReport({
      ...baseJob,
      audit_type: "terraform_config_basic",
      error: "PASSWORD=super-secret-password",
      result: {
        analyzer: "terraform_config_basic",
        summary: { redacted_values_count: 0 },
        providers: [{ name: "aws", access_key: "AKIAIOSFODNN7EXAMPLE", secret_key: "aws_secret_access_key_should_not_render" }],
        backends: [{ type: "s3", config: { secret_key: "aws_secret_access_key_should_not_render", password: "super-secret-password" } }],
        modules: [{ name: "db", source: "postgres://user:pass@example.com/db" }],
        resources: [{ resource_type: "aws_instance", resource_name: "web", user_data: "TOKEN=token_should_never_render\nregistry-user:registry-pass" }],
        variables: [{ name: "db_password", default: "db_password_plaintext" }],
        outputs: [{ name: "api_key", value: "raw-api-key-123456", sensitive: false }],
        state_files: [{ path: "terraform.tfstate", read: false, content: "super-secret-password raw-api-key-123456" }],
        findings: [
          {
            id: "legacy_terraform_secret",
            title: "Legacy Terraform secret",
            evidence: "PASSWORD=super-secret-password",
            description: "CLIENT_SECRET=token_should_never_render",
            recommendation: "-----BEGIN PRIVATE KEY----- PRIVATE KEY db_password_plaintext -----END PRIVATE KEY-----"
          }
        ],
        errors: ["API_KEY=raw-api-key-123456", "AWS_SECRET_ACCESS_KEY=aws_secret_access_key_should_not_render", "postgres://user:pass@example.com/db", "registry-user:registry-pass"]
      }
    });
    const serializedReport = JSON.stringify(report);
    const redactedRaw = JSON.stringify(
      redactTerraformConfigValue({
        error: "SECRET_KEY=fixture-secret",
        result: report
      })
    );

    for (const secret of [
      "super-secret-password",
      "raw-api-key-123456",
      "token_should_never_render",
      "PRIVATE KEY",
      "db_password_plaintext",
      "AKIAIOSFODNN7EXAMPLE",
      "aws_secret_access_key_should_not_render",
      "postgres://user:pass@example.com/db",
      "registry-user:registry-pass"
    ]) {
      expect(serializedReport).not.toContain(secret);
      expect(redactedRaw).not.toContain(secret);
    }
    expect(serializedReport).toContain("REDACTED");
    expect(report.findings[0].evidence).toContain("[REDACTED]");
    expect(report.stateFiles[0]).toMatchObject({ read: false });
  });

  it("normalizes Nginx config servers, locations, includes, directives, and findings", () => {
    const report = buildNginxConfigAuditReport({
      ...baseJob,
      audit_type: "nginx_config_basic",
      result: {
        analyzer: "nginx_config_basic",
        archive_type: "zip",
        summary: {
          files_considered: 3,
          files_reviewed: 2,
          nginx_files_detected: 2,
          server_blocks_detected: 1,
          location_blocks_detected: 1,
          upstream_blocks_detected: 1,
          includes_detected: 2,
          tls_servers_detected: 1,
          findings_count: 2,
          redacted_values_count: 1,
          truncated: false
        },
        files_detected: [{ path: "deploy/nginx/default.conf", category: "nginx_config", read: true, context: "production" }],
        servers: [{ path: "deploy/nginx/default.conf", context: "production", line: "1", server_name: "example.com", listen: ["443 ssl"], tls: true }],
        locations: [{ path: "deploy/nginx/default.conf", context: "production", line: "20", location: "/api", server_name: "example.com" }],
        upstreams: [{ path: "deploy/nginx/default.conf", context: "production", line: "40", name: "backend" }],
        includes: [{ path: "deploy/nginx/default.conf", context: "production", line: "8", target: "conf.d/*.conf", absolute: false, glob: true, resolved: false }],
        directives: [{ path: "deploy/nginx/default.conf", context: "production", line: "22", directive: "proxy_pass", arguments: "http://internal:8080", block_type: "location", location: "/api" }],
        findings: [
          {
            id: "nginx_proxy_pass_http_upstream",
            title: "Nginx proxies to an HTTP upstream",
            level: "low",
            confidence: "high",
            category: "proxy",
            context: "production",
            block_type: "location",
            location: "/api",
            directive: "proxy_pass",
            file_path: "deploy/nginx/default.conf",
            line: "22",
            evidence: "proxy_pass=http://internal:8080"
          },
          { code: "nginx_include_not_resolved", message: "include not resolved", severity: "info" }
        ],
        redaction_notes: ["Nginx values were redacted."],
        errors: []
      }
    });

    expect(report.isNginxConfigAudit).toBe(true);
    expect(report.overview).toContainEqual({ label: "Servers", value: "1" });
    expect(report.detectedFiles[0]).toMatchObject({ path: "deploy/nginx/default.conf", context: "production" });
    expect(report.servers[0]).toMatchObject({ serverName: "example.com", listen: ["443 ssl"], tls: true, line: 1 });
    expect(report.locations[0]).toMatchObject({ location: "/api", serverName: "example.com" });
    expect(report.upstreams[0]).toMatchObject({ name: "backend" });
    expect(report.includes[0]).toMatchObject({ target: "conf.d/*.conf", glob: true, resolved: false });
    expect(report.directives[0]).toMatchObject({ directive: "proxy_pass", arguments: "http://internal:8080" });
    expect(report.findings[0]).toMatchObject({ id: "nginx_proxy_pass_http_upstream", directive: "proxy_pass", line: 22 });
    expect(report.findingGroups.map((group) => group.level)).toEqual(["low", "info"]);
    expect(report.redactionNotes).toEqual(["Nginx values were redacted."]);
  });

  it("redacts legacy Nginx config payloads defensively", () => {
    const report = buildNginxConfigAuditReport({
      ...baseJob,
      audit_type: "nginx_config_basic",
      error: "Authorization: Bearer token_should_never_render",
      result: {
        analyzer: "nginx_config_basic",
        summary: { redacted_values_count: 0 },
        servers: [{ server_name: "example.com", password: "super-secret-password" }],
        locations: [{ location: "/api", proxy_pass: "http://user:pass@example.com" }],
        upstreams: [{ name: "backend", url: "http://registry-user:registry-pass@upstream.example.test" }],
        includes: [{ target: "/etc/nginx/secrets.conf", content: "raw-api-key-123456", resolved: false }],
        directives: [
          { directive: "proxy_pass", arguments: "http://user:pass@example.com" },
          { directive: "proxy_set_header", arguments: "Authorization: Bearer token_should_never_render" },
          { directive: "set", arguments: "$api_key raw-api-key-123456" },
          { directive: "set", arguments: "$proxy_password proxy_password_should_not_render" }
        ],
        findings: [
          {
            id: "legacy_nginx_secret",
            title: "Legacy Nginx secret",
            evidence: "proxy_pass http://user:pass@example.com",
            description: "Authorization: Bearer token_should_never_render",
            recommendation: "-----BEGIN PRIVATE KEY----- PRIVATE KEY raw-api-key-123456 -----END PRIVATE KEY-----"
          }
        ],
        errors: ["PASSWORD=super-secret-password", "registry-user:registry-pass", "sessionid=secret-session-cookie"]
      }
    });
    const serializedReport = JSON.stringify(report);
    const redactedRaw = JSON.stringify(
      redactNginxConfigValue({
        error: "Authorization: Bearer token_should_never_render",
        result: report
      })
    );

    for (const secret of [
      "super-secret-password",
      "raw-api-key-123456",
      "token_should_never_render",
      "Authorization: Bearer token_should_never_render",
      "http://user:pass@example.com",
      "registry-user:registry-pass",
      "sessionid=secret-session-cookie",
      "proxy_password_should_not_render",
      "PRIVATE KEY"
    ]) {
      expect(serializedReport).not.toContain(secret);
      expect(redactedRaw).not.toContain(secret);
    }
    expect(serializedReport).toContain("REDACTED");
    expect(report.findings[0].evidence).toContain("[REDACTED]");
    expect(report.includes[0]).toMatchObject({ resolved: false });
  });

  it("normalizes Compose config services, ports, volumes, env files, and findings", () => {
    const report = buildComposeConfigAuditReport({
      ...baseJob,
      audit_type: "compose_config_basic",
      result: {
        analyzer: "compose_config_basic",
        archive_type: "zip",
        summary: {
          files_considered: 4,
          files_reviewed: 2,
          compose_files_detected: 2,
          services_detected: 1,
          networks_detected: 1,
          volumes_detected: 1,
          secrets_detected: 1,
          published_ports_detected: 1,
          env_files_detected: 1,
          findings_count: 2,
          redacted_values_count: 1,
          truncated: false
        },
        files_detected: [{ path: "deploy/compose/docker-compose.yml", category: "compose", read: true, context: "production" }],
        services: [
          {
            name: "web",
            file_path: "deploy/compose/docker-compose.yml",
            context: "production",
            image: "nginx:latest",
            build: "./web",
            restart: "always",
            healthcheck: false,
            read_only: false,
            privileged: false,
            user: "root",
            network_mode: "bridge"
          }
        ],
        images: [{ service: "web", image: "nginx:latest", tag: "latest", file_path: "deploy/compose/docker-compose.yml", context: "production" }],
        build_contexts: [{ service: "web", context_path: "./web", dockerfile: "Dockerfile", file_path: "deploy/compose/docker-compose.yml" }],
        ports: [{ service: "web", host_ip: "0.0.0.0", published: "8080", target: "80", protocol: "tcp", file_path: "deploy/compose/docker-compose.yml" }],
        volumes: [{ service: "web", host_path: "/var/run/docker.sock", target: "/var/run/docker.sock", read_only: false, type: "bind" }],
        networks: [{ name: "edge", service: "web", external: true, internal: false }],
        secrets: [{ name: "db_password", service: "web", file: "./secrets/db_password.txt", read: false, skip_reason: "not_read" }],
        env_files: [{ service: "web", path: ".env.production", read: false, skip_reason: "sensitive_file_not_read" }],
        findings: [
          {
            id: "compose_docker_socket_mounted",
            title: "Docker socket mounted",
            level: "medium",
            confidence: "high",
            category: "volumes",
            context: "production",
            service: "web",
            host_path: "/var/run/docker.sock",
            container_path: "/var/run/docker.sock",
            file_path: "deploy/compose/docker-compose.yml",
            evidence: "service=web host_path=/var/run/docker.sock",
            recommendation: "Review whether this mount is needed."
          },
          { code: "compose_env_file_reference", message: "env_file reference detected", severity: "low" }
        ],
        redaction_notes: ["Compose values were redacted."],
        errors: []
      }
    });

    expect(report.isComposeConfigAudit).toBe(true);
    expect(report.overview).toContainEqual({ label: "Services", value: "1" });
    expect(report.detectedFiles[0]).toMatchObject({ path: "deploy/compose/docker-compose.yml", context: "production" });
    expect(report.services[0]).toMatchObject({ name: "web", image: "nginx:latest", user: "root" });
    expect(report.images[0]).toMatchObject({ service: "web", tag: "latest" });
    expect(report.buildContexts[0]).toMatchObject({ contextPath: "./web", dockerfile: "Dockerfile" });
    expect(report.ports[0]).toMatchObject({ hostIp: "0.0.0.0", published: "8080", target: "80" });
    expect(report.volumes[0]).toMatchObject({ hostPath: "/var/run/docker.sock", target: "/var/run/docker.sock" });
    expect(report.networks[0]).toMatchObject({ name: "edge", external: true });
    expect(report.secrets[0]).toMatchObject({ name: "db_password", read: false });
    expect(report.envFiles[0]).toMatchObject({ path: ".env.production", read: false });
    expect(report.findings[0]).toMatchObject({ id: "compose_docker_socket_mounted", service: "web" });
    expect(report.findingGroups.map((group) => group.level)).toEqual(["medium", "low"]);
    expect(report.redactionNotes).toEqual(["Compose values were redacted."]);
  });

  it("redacts legacy Compose config payloads defensively", () => {
    const report = buildComposeConfigAuditReport({
      ...baseJob,
      audit_type: "compose_config_basic",
      error: "POSTGRES_PASSWORD=super-secret-password",
      result: {
        analyzer: "compose_config_basic",
        summary: { redacted_values_count: 0 },
        services: [{ name: "db", environment: "POSTGRES_PASSWORD=super-secret-password", command: "token_should_never_render" }],
        images: [{ service: "app", image: "registry.example.test/app:latest", registry_auth: "registry-user:registry-pass" }],
        build_contexts: [{ service: "app", content: "raw-api-key-123456" }],
        ports: [{ service: "db", published: "5432", password: "super-secret-password" }],
        volumes: [{ service: "app", source: "/root/.ssh", content: "-----BEGIN PRIVATE KEY----- PRIVATE KEY -----END PRIVATE KEY-----" }],
        networks: [{ name: "edge", token: "token_should_never_render" }],
        secrets: [{ name: "db_password", file: "./secret.txt", content: "super-secret-password compose_secret_file_should_not_render", read: false }],
        env_files: [{ service: "app", path: ".env", content: "DATABASE_URL=postgres://user:pass@example.com/db compose_secret_file_should_not_render", read: false }],
        findings: [
          {
            id: "legacy_compose_secret",
            title: "Legacy Compose secret",
            evidence: "DATABASE_URL=postgres://user:pass@example.com/db",
            description: "redis://:super-secret-password@redis:6379/0",
            recommendation: "raw-api-key-123456 token_should_never_render"
          }
        ],
        errors: ["POSTGRES_PASSWORD=super-secret-password", "registry-user:registry-pass", "compose_secret_file_should_not_render", "-----BEGIN PRIVATE KEY-----"]
      }
    });
    const serializedReport = JSON.stringify(report);
    const redactedRaw = JSON.stringify(
      redactComposeConfigValue({
        error: "POSTGRES_PASSWORD=super-secret-password",
        result: report
      })
    );

    for (const secret of [
      "super-secret-password",
      "raw-api-key-123456",
      "token_should_never_render",
      "POSTGRES_PASSWORD=super-secret-password",
      "DATABASE_URL=postgres://user:pass@example.com/db",
      "redis://:super-secret-password@redis:6379/0",
      "registry-user:registry-pass",
      "compose_secret_file_should_not_render",
      "PRIVATE KEY"
    ]) {
      expect(serializedReport).not.toContain(secret);
      expect(redactedRaw).not.toContain(secret);
    }
    expect(serializedReport).toContain("REDACTED");
    expect(report.findings[0].evidence).toContain("[REDACTED]");
    expect(report.secrets[0]).toMatchObject({ read: false });
    expect(report.envFiles[0]).toMatchObject({ read: false });
  });

  it("normalizes Database config engines, settings, includes, dumps, and findings", () => {
    const report = buildDatabaseConfigAuditReport({
      ...baseJob,
      audit_type: "database_config_basic",
      result: {
        analyzer: "database_config_basic",
        archive_type: "zip",
        summary: {
          files_considered: 7,
          files_reviewed: 3,
          database_files_detected: 4,
          postgres_files_detected: 2,
          mysql_files_detected: 1,
          mariadb_files_detected: 1,
          pg_hba_files_detected: 1,
          dump_or_backup_files_detected: 2,
          engines_detected: 2,
          findings_count: 2,
          redacted_values_count: 1,
          truncated: false
        },
        files_detected: [{ path: "db/postgres/postgresql.conf", category: "postgres_config", read: true, context: "production" }],
        engines: [{ engine: "postgresql", file_path: "db/postgres/postgresql.conf", context: "production", files_count: 2 }],
        postgres_settings: [{ engine: "postgresql", setting: "listen_addresses", value: "*", file_path: "db/postgres/postgresql.conf", line: 3, context: "production" }],
        pg_hba_rules: [{ type: "host", database: "all", user: "all", address: "0.0.0.0/0", auth_method: "trust", file_path: "db/postgres/pg_hba.conf", line: 5, context: "production" }],
        mysql_settings: [{ engine: "mysql", section: "mysqld", setting: "bind-address", value: "0.0.0.0", file_path: "db/mysql/my.cnf", line: 8 }],
        includes: [{ directive: "include", target: "/etc/postgresql/secret.conf", resolved: false, file_path: "db/postgres/postgresql.conf", engine: "postgresql", line: 10 }],
        dump_or_backup_files: [{ path: "backups/prod.sql", category: "database_dump", read: false, skip_reason: "dump_not_read", size_bytes: 4096, context: "production" }],
        findings: [
          {
            id: "postgres_pg_hba_trust_auth",
            title: "pg_hba.conf allows trust authentication",
            level: "medium",
            confidence: "high",
            category: "auth",
            context: "production",
            engine: "postgresql",
            auth_method: "trust",
            address: "0.0.0.0/0",
            file_path: "db/postgres/pg_hba.conf",
            line: 5,
            evidence: "host all all 0.0.0.0/0 trust",
            recommendation: "Review whether trust authentication is appropriate."
          },
          { code: "database_dump_or_backup_file_present", message: "dump detected but not read", severity: "info" }
        ],
        redaction_notes: ["Database values were redacted."],
        errors: []
      }
    });

    expect(report.isDatabaseConfigAudit).toBe(true);
    expect(report.overview).toContainEqual({ label: "Engines", value: "2" });
    expect(report.detectedFiles[0]).toMatchObject({ path: "db/postgres/postgresql.conf", context: "production" });
    expect(report.engines[0]).toMatchObject({ engine: "postgresql", filesCount: 2 });
    expect(report.postgresSettings[0]).toMatchObject({ setting: "listen_addresses", value: "*" });
    expect(report.pgHbaRules[0]).toMatchObject({ authMethod: "trust", address: "0.0.0.0/0" });
    expect(report.mysqlSettings[0]).toMatchObject({ setting: "bind-address", value: "0.0.0.0" });
    expect(report.includes[0]).toMatchObject({ target: "/etc/postgresql/secret.conf", resolved: false });
    expect(report.dumpOrBackupFiles[0]).toMatchObject({ path: "backups/prod.sql", read: false });
    expect(report.findings[0]).toMatchObject({ id: "postgres_pg_hba_trust_auth", engine: "postgresql" });
    expect(report.findingGroups.map((group) => group.level)).toEqual(["medium", "info"]);
    expect(report.redactionNotes).toEqual(["Database values were redacted."]);
  });

  it("redacts legacy Database config payloads defensively", () => {
    const report = buildDatabaseConfigAuditReport({
      ...baseJob,
      audit_type: "database_config_basic",
      error: "PGPASSWORD=super-secret-password",
      result: {
        analyzer: "database_config_basic",
        summary: { redacted_values_count: 0 },
        engines: [{ engine: "postgresql", content: "raw-db-password-123456 pgpass_secret_should_not_render" }],
        postgres_settings: [{ setting: "password_encryption", value: "super-secret-password" }],
        pg_hba_rules: [{ content: "postgres://user:pass@example.com/db", auth_method: "trust" }],
        mysql_settings: [{ setting: "MYSQL_PWD", value: "super-secret-password" }],
        includes: [{ target: "/etc/postgresql/secret.conf", content: "replication_password_should_not_render" }],
        dump_or_backup_files: [{ path: "backup.sql", read: false, content: "db_password_plaintext dump_row_secret_should_not_render" }],
        findings: [
          {
            id: "legacy_database_secret",
            title: "Legacy Database secret",
            evidence: "postgres://user:pass@example.com/db",
            description: "MYSQL_PWD=super-secret-password",
            recommendation: "raw-db-password-123456 replication_password_should_not_render"
          }
        ],
        errors: [
          "PGPASSWORD=super-secret-password",
          "mysql://user:pass@example.com/db",
          "-----BEGIN PRIVATE KEY-----",
          "db_password_plaintext",
          "dump_row_secret_should_not_render",
          "pgpass_secret_should_not_render",
          "mycnf_secret_should_not_render"
        ]
      }
    });
    const serializedReport = JSON.stringify(report);
    const redactedRaw = JSON.stringify(
      redactDatabaseConfigValue({
        error: "PGPASSWORD=super-secret-password",
        result: report
      })
    );

    for (const secret of [
      "super-secret-password",
      "raw-db-password-123456",
      "postgres://user:pass@example.com/db",
      "mysql://user:pass@example.com/db",
      "replication_password_should_not_render",
      "PGPASSWORD=super-secret-password",
      "MYSQL_PWD=super-secret-password",
      "db_password_plaintext",
      "dump_row_secret_should_not_render",
      "pgpass_secret_should_not_render",
      "mycnf_secret_should_not_render",
      "PRIVATE KEY"
    ]) {
      expect(serializedReport).not.toContain(secret);
      expect(redactedRaw).not.toContain(secret);
    }
    expect(serializedReport).toContain("REDACTED");
    expect(report.findings[0].evidence).toContain("[REDACTED]");
    expect(report.dumpOrBackupFiles[0]).toMatchObject({ read: false });
  });

  it("normalizes Redis config settings, includes, no-read files, and findings", () => {
    const report = buildRedisConfigAuditReport({
      ...baseJob,
      audit_type: "redis_config_basic",
      result: {
        analyzer: "redis_config_basic",
        archive_type: "zip",
        summary: {
          files_considered: 6,
          files_reviewed: 2,
          redis_files_detected: 1,
          sentinel_files_detected: 1,
          acl_files_detected: 1,
          dump_or_aof_files_detected: 2,
          configs_detected: 2,
          findings_count: 2,
          redacted_values_count: 1,
          truncated: false
        },
        files_detected: [{ path: "deploy/redis/redis.conf", category: "redis", config_type: "redis", read: true, context: "production" }],
        configs: [
          { path: "deploy/redis/redis.conf", config_type: "redis", context: "production" },
          { path: "deploy/redis/sentinel.conf", config_type: "sentinel", context: "production" }
        ],
        redis_settings: [{ config_type: "redis", directive: "bind", setting: "bind", value: "0.0.0.0", file_path: "deploy/redis/redis.conf", line: 2 }],
        sentinel_settings: [{ config_type: "sentinel", directive: "sentinel", setting: "sentinel monitor", value: "mymaster 10.0.0.2 6379 2", file_path: "deploy/redis/sentinel.conf", line: 2 }],
        includes: [{ directive: "include", target: "/etc/redis/secrets.conf", resolved: false, file_path: "deploy/redis/redis.conf", config_type: "redis", line: 8 }],
        acl_files: [{ path: "deploy/redis/users.acl", category: "acl", read: false, skip_reason: "acl_file_not_read", size_bytes: 128 }],
        dump_or_aof_files: [{ path: "deploy/redis/dump.rdb", category: "dump_or_aof", read: false, skip_reason: "dump_or_aof_not_read", size_bytes: 4096 }],
        findings: [
          {
            id: "redis_bind_public_interface",
            title: "Redis bind allows public interface",
            level: "medium",
            confidence: "high",
            category: "network",
            context: "production",
            config_type: "redis",
            directive: "bind",
            address: "0.0.0.0",
            file_path: "deploy/redis/redis.conf",
            line: 2,
            evidence: "bind 0.0.0.0"
          },
          { code: "redis_acl_file_not_read", message: "ACL file detected but not read", severity: "info" }
        ],
        redaction_notes: ["Redis values were redacted."],
        errors: []
      }
    });

    expect(report.isRedisConfigAudit).toBe(true);
    expect(report.overview).toContainEqual({ label: "Redis configs", value: "1" });
    expect(report.overview).toContainEqual({ label: "Sentinel configs", value: "1" });
    expect(report.detectedFiles[0]).toMatchObject({ path: "deploy/redis/redis.conf", configType: "redis" });
    expect(report.configs[0]).toMatchObject({ path: "deploy/redis/redis.conf", configType: "redis" });
    expect(report.redisSettings[0]).toMatchObject({ setting: "bind", value: "0.0.0.0" });
    expect(report.sentinelSettings[0]).toMatchObject({ setting: "sentinel monitor" });
    expect(report.includes[0]).toMatchObject({ target: "/etc/redis/secrets.conf", resolved: false });
    expect(report.aclFiles[0]).toMatchObject({ path: "deploy/redis/users.acl", read: false });
    expect(report.dumpOrAofFiles[0]).toMatchObject({ path: "deploy/redis/dump.rdb", read: false });
    expect(report.findings[0]).toMatchObject({ id: "redis_bind_public_interface", configType: "redis" });
    expect(report.findingGroups.map((group) => group.level)).toEqual(["medium", "info"]);
    expect(report.redactionNotes).toEqual(["Redis values were redacted."]);
  });

  it("redacts legacy Redis config payloads defensively", () => {
    const report = buildRedisConfigAuditReport({
      ...baseJob,
      audit_type: "redis_config_basic",
      error: "requirepass super-secret-password",
      result: {
        analyzer: "redis_config_basic",
        summary: { redacted_values_count: 0 },
        configs: [{ path: "deploy/redis/redis.conf", content: "requirepass super-secret-password" }],
        redis_settings: [{ setting: "requirepass", value: "super-secret-password" }],
        sentinel_settings: [{ setting: "sentinel auth-pass", value: "token_should_never_render" }],
        includes: [{ target: "/etc/redis/secrets.conf", content: "raw-api-key-123456", resolved: false }],
        acl_files: [{ path: "users.acl", read: false, content: "acl_password_hash_should_not_render" }],
        dump_or_aof_files: [{ path: "dump.rdb", read: false, content: "dump_value_should_not_render" }],
        findings: [
          {
            id: "legacy_redis_secret",
            title: "Legacy Redis secret",
            evidence: "requirepass super-secret-password redis://:super-secret-password@redis:6379/0",
            description: "Authorization: Bearer token_should_never_render",
            recommendation: "-----BEGIN PRIVATE KEY----- fixture -----END PRIVATE KEY-----"
          }
        ],
        errors: ["requirepass super-secret-password", "raw-api-key-123456", "token_should_never_render", "acl_password_hash_should_not_render", "dump_value_should_not_render"]
      }
    });
    const serializedReport = JSON.stringify(report);
    const redactedRaw = JSON.stringify(
      redactRedisConfigValue({
        error: "requirepass super-secret-password",
        result: report
      })
    );

    for (const secret of [
      "super-secret-password",
      "raw-api-key-123456",
      "token_should_never_render",
      "acl_password_hash_should_not_render",
      "dump_value_should_not_render",
      "redis://:super-secret-password@redis:6379/0",
      "PRIVATE KEY"
    ]) {
      expect(serializedReport).not.toContain(secret);
      expect(redactedRaw).not.toContain(secret);
    }
    expect(serializedReport).toContain("REDACTED");
    expect(report.findings[0].evidence).toContain("[REDACTED]");
    expect(report.aclFiles[0]).toMatchObject({ read: false });
  });
});
