import { describe, expect, it } from "vitest";

import { buildArchiveAuditReport } from "./archiveReport";
import { buildCiCdConfigAuditReport, redactCiCdConfigValue } from "./ciCdConfigReport";
import { buildDjangoConfigAuditReport, redactDjangoConfigValue } from "./djangoConfigReport";
import { buildDomainAuditReport } from "./domainReport";
import { buildDockerConfigAuditReport, redactDockerConfigValue } from "./dockerConfigReport";
import { buildImageAuditReport } from "./imageReport";
import { buildManifestAuditReport } from "./manifestReport";
import { buildNodePackageConfigAuditReport, redactNodePackageConfigValue } from "./nodePackageConfigReport";
import { buildPdfAuditReport } from "./pdfReport";
import { buildProjectArchiveAuditReport } from "./projectArchiveReport";
import { buildSecretsReviewAuditReport, redactSecretsReviewValue } from "./secretsReviewReport";
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
});
