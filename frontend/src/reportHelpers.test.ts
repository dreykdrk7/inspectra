import { describe, expect, it } from "vitest";

import { buildArchiveAuditReport } from "./archiveReport";
import { buildImageAuditReport } from "./imageReport";
import { buildManifestAuditReport } from "./manifestReport";
import { buildPdfAuditReport } from "./pdfReport";
import { buildProjectArchiveAuditReport } from "./projectArchiveReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-1",
  file_id: "file-1",
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
});
