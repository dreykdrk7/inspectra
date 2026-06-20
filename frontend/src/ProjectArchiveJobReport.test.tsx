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
  it("renders category labels for known and unknown project archive findings", () => {
    render(
      <ProjectArchiveJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "project_archive_basic",
            archive_type: "zip",
            summary: { findings_count: 2 },
            limits: { max_manifests: 50 },
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
    expect(screen.getAllByText("1 findings").length).toBeGreaterThanOrEqual(3);
    expect(screen.getByText("medium")).toBeInTheDocument();
    expect(screen.getByText("package.json: postinstall: node setup.js")).toBeInTheDocument();
    expect(screen.getByText("Confirm the script is expected.")).toBeInTheDocument();
  });
});
