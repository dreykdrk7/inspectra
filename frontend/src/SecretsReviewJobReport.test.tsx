import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { SecretsReviewJobReport } from "./SecretsReviewJobReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-secrets-1",
  audit_type: "secrets_review_basic",
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

describe("SecretsReviewJobReport", () => {
  it("renders summary, sensitive files, grouped findings, metadata, limits, errors, and raw JSON", () => {
    render(
      <SecretsReviewJobReport
        job={{
          ...baseJob,
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
              truncated: true
            },
            limits: { max_files: 100, max_file_bytes: 524288 },
            sensitive_files: [
              {
                path: ".env.production",
                category: "env_sensitive",
                read: false,
                skip_reason: "real_env_file_not_read",
                size_bytes: 64,
                context: "production"
              }
            ],
            files_detected: [
              {
                path: ".env.production",
                category: "env_sensitive",
                read: false,
                skip_reason: "real_env_file_not_read",
                size_bytes: 64,
                context: "production"
              },
              { path: ".env.example", category: "env_template", read: true, bytes_read: 48, context: "example" }
            ],
            files_reviewed: [{ path: ".env.example", category: "env_template", read: true, bytes_read: 48, context: "example" }],
            findings: [
              {
                id: "secret_like_assignment",
                title: "Secret-like assignment observed",
                level: "medium",
                confidence: "high",
                category: "assignment",
                context: "production",
                file_path: "settings.py",
                line: 12,
                description: "Review this secret-like setting.",
                evidence: "SECRET_KEY=[REDACTED]",
                recommendation: "Move secrets to an approved secret manager or environment source."
              },
              {
                id: "grouped_secret_hint",
                title: "Grouped secret hint",
                category: "template",
                confidence: "low",
                evidence: "TOKEN=[REDACTED]"
              }
            ],
            redaction_notes: ["Secret-like values were redacted."],
            errors: ["controlled parser warning"]
          }
        }}
      />
    );

    expect(screen.getByRole("heading", { name: "General Summary" })).toBeInTheDocument();
    expect(screen.getByText("Sensitive files")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Sensitive Files Detected But Not Read" })).toBeInTheDocument();
    expect(screen.getAllByText(".env.production").length).toBeGreaterThan(0);
    expect(screen.getAllByText("production").length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Findings" })).toBeInTheDocument();
    expect(screen.getByText("secret_like_assignment")).toBeInTheDocument();
    expect(screen.getByText("grouped_secret_hint")).toBeInTheDocument();
    expect(screen.getByText("confidence: high")).toBeInTheDocument();
    expect(screen.getByText("confidence: low")).toBeInTheDocument();
    expect(screen.getByText("assignment")).toBeInTheDocument();
    expect(screen.getByText("settings.py:12")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Files Detected / Reviewed" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Redaction Notes" })).toBeInTheDocument();
    expect(screen.getByText("Secret-like values were redacted.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Limits / Truncation" })).toBeInTheDocument();
    expect(screen.getByText("controlled parser warning")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });

  it("tolerates sparse secrets review results with clear empty states", () => {
    render(
      <SecretsReviewJobReport
        job={{
          ...baseJob,
          status: "running",
          result: {
            analyzer: "secrets_review_basic",
            summary: {}
          }
        }}
      />
    );

    expect(screen.getByText("No sensitive files reported as skipped.")).toBeInTheDocument();
    expect(screen.getByText("No heuristic secret findings reported.")).toBeInTheDocument();
    expect(screen.getByText("No secrets-review candidate files detected or returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No secrets review errors reported.")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });

  it("redacts legacy raw secrets from rendered content and raw JSON", () => {
    const { container } = render(
      <SecretsReviewJobReport
        job={{
          ...baseJob,
          error: "TOKEN=fixture-secret-key-value",
          result: {
            analyzer: "secrets_review_basic",
            summary: { redacted_values_count: 0 },
            raw_secret: "fixture-secret-key-value",
            sensitive_files: [
              {
                path: ".env.production",
                category: "env_sensitive",
                read: false,
                skip_reason: "SECRET_KEY=fixture-secret-key-value"
              }
            ],
            findings: [
              {
                id: "legacy_assignment",
                title: "Legacy assignment",
                evidence: "SECRET_KEY=fixture-secret-key-value",
                description: "DATABASE_URL=postgres://user:fixture-db-password@db/app",
                recommendation: "REDIS_URL=redis://:fixture-redis-password@redis:6379/0"
              },
              {
                id: "legacy_jwt",
                title: "Legacy JWT",
                evidence: "eyJhbGciOiJIUzI1NiJ9.fixture.fixture"
              },
              {
                id: "legacy_private_key",
                title: "Legacy private key",
                evidence: "-----BEGIN PRIVATE KEY----- fixture material -----END PRIVATE KEY-----"
              }
            ],
            errors: ["https://user:fixture-db-password@example.com/path?token=fixture-secret-key-value"]
          }
        }}
      />
    );

    const text = container.textContent ?? "";
    for (const secret of [
      "fixture-secret-key-value",
      "fixture-db-password",
      "fixture-redis-password",
      "fixture material",
      "eyJhbGciOiJIUzI1NiJ9.fixture.fixture"
    ]) {
      expect(text).not.toContain(secret);
    }
    expect(text).toContain("REDACTED");
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });
});
