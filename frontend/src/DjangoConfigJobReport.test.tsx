import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { DjangoConfigJobReport } from "./DjangoConfigJobReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-django-1",
  audit_type: "django_config_basic",
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

describe("DjangoConfigJobReport", () => {
  it("renders grouped findings, context, env-sensitive files, and redacted raw JSON", () => {
    render(
      <DjangoConfigJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "django_config_basic",
            archive_type: "zip",
            summary: {
              files_read: 2,
              findings_count: 2,
              secrets_redacted_count: 1,
              truncated: true
            },
            limits: { max_files: 100 },
            detected_files: [
              { path: "project/settings/production.py", category: "django_config", read: true, size_bytes: 128, context: "production" },
              { path: ".env.production", category: "env_sensitive", read: false, skip_reason: "sensitive_env_not_read", size_bytes: 64 }
            ],
            django_signals: {
              debug: { status: "enabled_or_default_true", files: ["project/settings/production.py"] }
            },
            findings: [
              {
                id: "django_debug_enabled",
                title: "Django DEBUG appears enabled",
                level: "medium",
                context: "production",
                evidence: "DEBUG = True/default=True (context: production)",
                description: "Review production DEBUG handling.",
                recommendation: "Set DEBUG=False in production.",
                file_path: "project/settings/production.py"
              },
              {
                id: "django_csrf_cookie_secure_not_true",
                title: "CSRF_COOKIE_SECURE was not observed as true",
                level: "low",
                context: "grouped",
                evidence: "CSRF_COOKIE_SECURE = not observed as True; files: project/settings.py; contexts: shared",
                description: "Grouped missing setting.",
                recommendation: "Review production settings."
              }
            ],
            errors: ["PASSWORD=super-secret-value-123"]
          }
        }}
      />
    );

    expect(screen.getByRole("heading", { name: "General Summary" })).toBeInTheDocument();
    expect(screen.getByText("Files reviewed")).toBeInTheDocument();
    expect(screen.getByText("Sensitive env files")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Findings" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Files Reviewed / Detected Files" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Sensitive Env Files Detected But Not Read" })).toBeInTheDocument();
    expect(screen.getByText("django_debug_enabled")).toBeInTheDocument();
    expect(screen.getByText("django_csrf_cookie_secure_not_true")).toBeInTheDocument();
    expect(screen.getAllByText("production").length).toBeGreaterThan(0);
    expect(screen.getByText("grouped")).toBeInTheDocument();
    expect(screen.getAllByText(".env.production").length).toBeGreaterThan(0);
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
    expect(screen.queryByText("super-secret-value-123")).not.toBeInTheDocument();
  });

  it("tolerates sparse Django config results with clear empty states", () => {
    render(
      <DjangoConfigJobReport
        job={{
          ...baseJob,
          status: "running",
          result: {
            analyzer: "django_config_basic",
            summary: {}
          }
        }}
      />
    );

    expect(screen.getByText("No heuristic findings reported.")).toBeInTheDocument();
    expect(screen.getByText("No Django-related files detected or returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No real .env files were reported as present.")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });
});
