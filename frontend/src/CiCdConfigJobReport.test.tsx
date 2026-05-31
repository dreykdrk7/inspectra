import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { CiCdConfigJobReport } from "./CiCdConfigJobReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-ci-1",
  audit_type: "ci_cd_config_basic",
  file_id: "archive-1",
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

describe("CiCdConfigJobReport", () => {
  it("renders summary, workflow sections, findings, context, limits, errors, and raw JSON", () => {
    render(
      <CiCdConfigJobReport
        job={{
          ...baseJob,
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
              truncated: true
            },
            limits: { max_files: 100, max_file_bytes: 524288, max_total_bytes: 2097152 },
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
            triggers: [
              { file_path: ".github/workflows/release.yml", provider: "github_actions", trigger: "pull_request_target", context: "production" }
            ],
            permissions: [
              {
                file_path: ".github/workflows/release.yml",
                provider: "github_actions",
                permission: "contents",
                value: "write",
                context: "production"
              }
            ],
            jobs: [
              {
                file_path: ".github/workflows/release.yml",
                provider: "github_actions",
                job: "publish",
                step: "checkout",
                steps_detected: 2,
                evidence: "npm publish",
                context: "production"
              }
            ],
            actions: [
              {
                file_path: ".github/workflows/release.yml",
                provider: "github_actions",
                action: "actions/checkout",
                ref: "main",
                job: "publish",
                step: "checkout",
                context: "production"
              }
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
                file_path: ".github/workflows/release.yml",
                job: "publish",
                step: "checkout",
                context: "production",
                line: "4",
                evidence: "on: pull_request_target",
                recommendation: "Review privileged pull request trigger behavior."
              },
              {
                id: "workflow_dispatch_with_inputs",
                title: "Manual workflow inputs require review",
                evidence: "workflow_dispatch inputs",
                context: "development"
              }
            ],
            redaction_notes: ["CI/CD secret-like values were redacted."],
            errors: ["controlled error"]
          }
        }}
        file={{ id: "archive-1", kind: "archive", original_filename: "ci.zip", stored_filename: "ci.zip", content_type: "application/zip", size_bytes: 100, sha256: "abc", created_at: "2026-05-26T10:00:00Z" }}
      />
    );

    expect(screen.getByRole("heading", { name: "General Summary" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Workflow Overview" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Triggers" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Permissions" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Jobs / Steps Overview" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Actions / Images" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Service Containers" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Publish / Deploy Signals" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Findings" })).toBeInTheDocument();
    expect(screen.getByText("pull_request_target trigger requires review")).toBeInTheDocument();
    expect(screen.getAllByText("production").length).toBeGreaterThan(0);
    expect(screen.getAllByText("github_actions").length).toBeGreaterThan(0);
    expect(screen.getByText("confidence: medium")).toBeInTheDocument();
    expect(screen.getByText(".env.production")).toBeInTheDocument();
    expect(screen.getByText("real_env_file_not_read")).toBeInTheDocument();
    expect(screen.getByText("Analysis truncated by configured CI/CD config limits. Review skipped files and rerun with a smaller archive if needed.")).toBeInTheDocument();
    expect(screen.getByText("controlled error")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });

  it("tolerates sparse CI/CD config results", () => {
    render(
      <CiCdConfigJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "ci_cd_config_basic",
            summary: {}
          }
        }}
      />
    );

    expect(screen.getByText("No heuristic CI/CD config findings reported.")).toBeInTheDocument();
    expect(screen.getByText("No workflow overview returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No CI/CD triggers returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No CI/CD actions or images returned yet.")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });

  it("redacts legacy secret-like values in report sections and raw JSON", () => {
    const { container } = render(
      <CiCdConfigJobReport
        job={{
          ...baseJob,
          error: "TOKEN=fixture-token",
          result: {
            analyzer: "ci_cd_config_basic",
            summary: { redacted_values_count: 0 },
            jobs: [
              {
                file_path: ".github/workflows/release.yml",
                provider: "github_actions",
                job: "deploy",
                command: "API_KEY=fixture-key npm run build"
              }
            ],
            actions: [
              {
                file_path: ".github/workflows/release.yml",
                provider: "github_actions",
                action: "deploy",
                image: "https://user:fixture-password@ci.example.test/hook"
              }
            ],
            publish_deploy_signals: [
              {
                file_path: ".github/workflows/release.yml",
                signal: "deploy",
                evidence: "https://example.test/deploy?token=fixture-token&key=fixture-key"
              }
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
        }}
      />
    );

    const rendered = container.textContent ?? "";
    for (const secret of [
      "fixture-token",
      "fixture-password",
      "fixture-key",
      "fixture-secret",
      "fixture material",
      "https://user:fixture-password@ci.example.test/hook",
      "https://example.test/deploy?token=fixture-token&key=fixture-key"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("REDACTED");
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });
});
