import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { ProjectArchiveJobReport } from "./ProjectArchiveJobReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-project-archive-1",
  audit_type: "project_archive_basic",
  file_id: "file-archive-1",
  target_url: null,
  target_domain: null,
  status: "completed",
  created_at: "2026-05-26T10:00:00Z",
  updated_at: "2026-05-26T10:01:00Z",
  source_file_deleted_at: null,
  error: null
} satisfies Omit<JobRecord, "result">;

afterEach(() => {
  cleanup();
});

describe("ProjectArchiveJobReport", () => {
  it("withholds project source names and content digests from the technical view and raw JSON", () => {
    const privateFilename = "customer-secret-branch.zip";
    const privateDigest = "f".repeat(64);
    render(
      <ProjectArchiveJobReport
        job={{
          ...baseJob,
          project_id: "project-private",
          source_reference: "snapshot-0123456789abcdef",
          source_sha256: privateDigest,
          result: {
            analyzer: "project_archive_basic",
            hashes: { sha256: privateDigest },
            file_identification: { original_filename: privateFilename, size_bytes: 256 },
            findings: []
          }
        }}
      />
    );

    expect(screen.getByText("snapshot-0123456789abcdef")).toBeInTheDocument();
    expect(screen.getByText(/content digests are retained server-side/i)).toBeInTheDocument();
    expect(screen.getByText(/withheld in project views/i)).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(privateFilename);
    expect(document.body).not.toHaveTextContent(privateDigest);
    expect(document.body).not.toHaveTextContent("file-archive-1");
  });

  it("renders category labels for known and unknown project archive findings", () => {
    render(
      <ProjectArchiveJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "project_archive_basic",
            archive_type: "zip",
            summary: { findings_count: 2 },
            limits: { max_total_manifest_bytes: 1048576 },
            supported_manifests: [{ path: "package.json", manifest_type: "package_json", status: "parsed" }],
            unsupported_manifests: [],
            parsed_manifests: [],
            findings: [
              {
                id: "package_sensitive_lifecycle_script",
                title: "Lifecycle script should be reviewed",
                level: "medium",
                description: "Review before running package manager commands.",
                evidence: "package.json: postinstall: node setup.js",
                recommendation: "Confirm the script is expected."
              },
              {
                id: "requirements_dependency_not_exactly_pinned",
                title: "Dependency is not exactly pinned",
                level: "low",
                description: "Review repeatability.",
                evidence: "requirements.txt: line 1: fastapi>=0.110",
                recommendation: "Consider exact pins where deterministic installs matter."
              },
              {
                id: "future_project_archive_signal",
                title: "Future project archive signal",
                level: "info",
                description: "Future signal description.",
                evidence: "future evidence",
                recommendation: "Review manually."
              },
              {
                id: "secret_like_assignment",
                title: "Secret-like assignment observed",
                level: "medium",
                confidence: "medium",
                category: "sensitive_data_review",
                category_label: "Sensitive data review",
                ecosystem: "framework_config",
                ecosystem_label: "Framework/config",
                file_path: "config/settings.py",
                line: 7,
                description: "A value was redacted.",
                evidence: "API_KEY=[REDACTED]",
                recommendation: "Use an approved runtime mechanism."
              }
            ],
            errors: []
          }
        }}
      />
    );

    expect(screen.getByRole("heading", { name: "Informational Findings" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Ecosystem Summary" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Dependency Pinning Summary" })).toBeInTheDocument();
    expect(screen.getByText("max_total_manifest_bytes")).toHaveClass("metadata-key");
    expect(screen.getByText("1.0 MB")).toBeInTheDocument();
    expect(screen.getByText("Execution profile")).toBeInTheDocument();
    expect(screen.getByText("Not recorded (legacy analysis)")).toBeInTheDocument();
    expect(
      screen.getByText("Python / requirements: 1 dependency pinning review indicator across 1 manifest.")
    ).toBeInTheDocument();
    expect(screen.getAllByText("Node / package.json").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Python / requirements").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Unknown ecosystem").length).toBeGreaterThan(0);
    expect(screen.getByText("Package script review")).toBeInTheDocument();
    expect(screen.getByText("Dependency hygiene")).toBeInTheDocument();
    expect(screen.getByText("Uncategorized review indicator")).toBeInTheDocument();
    expect(screen.getByText("Lifecycle script should be reviewed")).toBeInTheDocument();
    expect(screen.getByText("Dependency is not exactly pinned")).toBeInTheDocument();
    expect(screen.getByText("Future project archive signal")).toBeInTheDocument();
    expect(screen.getByText("Sensitive data review")).toBeInTheDocument();
    expect(screen.getByText("config/settings.py:7")).toBeInTheDocument();
    expect(screen.getByText("Confidence: medium")).toBeInTheDocument();
    expect(screen.getByText("API_KEY=[REDACTED]")).toBeInTheDocument();
    expect(screen.getAllByText("1 findings").length).toBeGreaterThanOrEqual(3);
    expect(screen.getAllByText("medium").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText("package.json: postinstall: node setup.js")).toBeInTheDocument();
    expect(screen.getByText("Confirm the script is expected.")).toBeInTheDocument();
  });

  it("renders the saved non-sensitive execution profile instead of configuration details", () => {
    render(
      <ProjectArchiveJobReport
        job={{
          ...baseJob,
          execution_profile: {
            contract_version: "2026-09-06.3",
            profile_name: "project_archive_basic",
            ruleset_version: "2026-09-06.1",
            max_upload_bytes: 1048576,
            audit_max_concurrency: 2,
            audit_max_inflight_jobs: 20,
            audit_max_inflight_jobs_per_owner: 5,
            timeout_seconds: 45,
            workspace_policy: "isolated_copy_stream_worker_v1",
            workspace_max_bytes: 1048576,
            worker_contract_version: "2026-09-06.1",
            worker_source_transport: "inline_base64_sha256_v1",
            worker_lifecycle: "ephemeral_subprocess",
            worker_max_concurrency: 1,
            worker_cpu_seconds: 45,
            worker_memory_bytes: 402653184,
            worker_max_result_bytes: 4194304,
            worker_max_file_bytes: 33554432,
            worker_max_open_files: 64,
            worker_max_processes: 32,
            max_total_uncompressed_bytes: 10485760,
            max_archive_entries: 500,
            max_manifests: 25,
            max_manifest_bytes: 524288,
            max_total_manifest_bytes: 2097152,
            max_lockfiles: 5,
            max_lockfile_packages: 2000,
            max_lockfile_edges: 4000,
            license_policy_contract_version: "2026-09-09.1",
            license_policy_denied_identifiers: ["AGPL-3.0-only"]
          },
          started_at: "2026-05-26T10:00:01Z",
          finished_at: "2026-05-26T10:01:00Z",
          termination_reason: "completed",
          retry_of_job_id: "job-project-archive-0",
          recovery_count: 2,
          last_recovered_at: "2026-05-26T09:59:00Z",
          result: { analyzer: "project_archive_basic", archive_type: "zip", findings: [] }
        }}
      />
    );

    expect(
      screen.getByText(
        "project_archive_basic; contract 2026-09-06.3; rules 2026-09-06.1; admission 1.0 MB; timeout 45s; concurrency 2; in-flight global 20; in-flight per owner 5; workspace isolated_copy_stream_worker_v1; isolated worker 2026-09-06.1, ephemeral_subprocess, concurrency 1, CPU 45 s, memory 384.0 MB; license review 2026-09-09.1, exact deny entries 1; workspace copy 1.0 MB; expanded 10.0 MB; entries 500; manifests 25; manifest item 512.0 KB; manifest total 2.0 MB; lockfiles 5; lock packages 2000; lock edges 4000",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("Completed under the recorded contract")).toBeInTheDocument();
    expect(screen.getByText("job-project-archive-0")).toBeInTheDocument();
    expect(screen.getByText("Restart recoveries")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
    expect(screen.getByText("Last recovered").nextElementSibling).not.toHaveTextContent("Never");
    expect(screen.queryByText(/INSPECTRA_MAX_UPLOAD_BYTES|token|secret|http/i)).not.toBeInTheDocument();
  });

  it("renders declared, unknown, and policy-blocked license states without legal claims", () => {
    render(
      <ProjectArchiveJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "project_archive_basic",
            license_review: {
              contract_version: "2026-09-09.1",
              policy_mode: "exact_deny_identifiers",
              declarations: [
                { manifest_path: "package.json", status: "declared", expression: "MIT" },
                { manifest_path: "services/api/pyproject.toml", status: "unknown_unrecognized_withheld" },
                { manifest_path: "legacy/package.json", status: "not_permitted", expression: "AGPL-3.0-only" }
              ],
              limitations: ["Dependency licenses are not inferred."]
            },
            findings: []
          }
        }}
      />
    );

    expect(screen.getByRole("heading", { name: "Declared License Review" })).toBeInTheDocument();
    expect(screen.getByText("MIT")).toBeInTheDocument();
    expect(screen.getByText("No supported declaration")).toBeInTheDocument();
    expect(screen.getByText("not permitted")).toBeInTheDocument();
    expect(screen.getByText(/not legal advice/i)).toBeInTheDocument();
    expect(screen.getByText("Dependency licenses are not inferred.")).toBeInTheDocument();
  });

  it("shows aggregate requirements hash evidence without rendering digests or private sources", () => {
    const privateDigest = "a".repeat(64);
    render(
      <ProjectArchiveJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "project_archive_basic",
            parsed_manifests: [{
              path: "services/api/requirements.txt",
              manifest_type: "requirements_txt",
              parsed: {
                project: {},
                dependencies: { dependencies: [{ name: "requests", specifier: "==2.32.3", source: "line 1" }] },
                integrity_summary: {
                  contract_version: "requirements-hash-summary-v1",
                  status: "missing",
                  exact_pins: 2,
                  exact_pins_with_hashes: 1,
                  exact_pins_missing_hashes: 1,
                  hash_entries_for_exact_pins: 2,
                  non_registry_entries_excluded: 1
                },
                scripts: {}
              },
              findings: [{
                id: "requirements_exact_pins_missing_hashes",
                title: "Some exact Python requirements have no retained hash evidence",
                level: "info",
                description: "Exact pins are not artifact-integrity evidence.",
                evidence: "1 of 2 exact requirement entries had no supported hash option.",
                recommendation: "Review a fully hashed workflow."
              }],
              errors: []
            }],
            findings: []
          }
        }}
      />
    );

    expect(screen.getByRole("heading", { name: "Requirements integrity" })).toBeInTheDocument();
    expect(screen.getByText(/discards digest values/i)).toBeInTheDocument();
    expect(screen.getByText("missing")).toBeInTheDocument();
    expect(screen.getByText("exact_pins_with_hashes")).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(privateDigest);
    expect(document.body).not.toHaveTextContent("private.example");
  });
});
