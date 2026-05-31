import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { NodePackageConfigJobReport } from "./NodePackageConfigJobReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-node-1",
  audit_type: "node_package_config_basic",
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

describe("NodePackageConfigJobReport", () => {
  it("renders package overview, scripts, dependencies, signals, findings, limits, errors, and redacted raw JSON", () => {
    const { container } = render(
      <NodePackageConfigJobReport
        job={{
          ...baseJob,
          error: "token=fixture-token",
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
              redacted_values_count: 2,
              truncated: true
            },
            limits: { max_files: 100, max_file_bytes: 524288 },
            files_detected: [
              { path: "project/package.json", category: "package_manifest", read: true, bytes_read: 512, context: "shared" },
              { path: "project/.npmrc", category: "package_manager_config", read: true, bytes_read: 64, context: "production" }
            ],
            files_reviewed: [{ path: "project/package.json", category: "package_manifest", read: true, bytes_read: 512, context: "shared" }],
            packages: [
              {
                path: "project/package.json",
                name: "demo",
                version: "1.0.0",
                private: false,
                package_manager: "pnpm@9.0.0",
                workspace: "packages/*",
                context: "shared"
              }
            ],
            scripts: [
              {
                path: "project/package.json",
                name: "postinstall",
                excerpt: "node scripts/setup.js",
                context: "shared"
              },
              {
                path: "project/package.json",
                name: "build",
                excerpt: "API_KEY=fixture-key npm run build",
                context: "shared"
              }
            ],
            dependency_groups: [
              {
                path: "project/package.json",
                group: "dependencies",
                context: "shared",
                dependencies: [{ name: "react", specifier: "^18.3.1", source_type: "registry", indicators: ["range"] }]
              }
            ],
            package_manager_config_signals: [
              {
                path: "project/.npmrc",
                key: "_authToken",
                value: "fixture-token",
                line: "2",
                context: "production"
              },
              {
                path: "project/.npmrc",
                key: "registry",
                value: "https://user:fixture-password@registry.example.test/pkg",
                line: 3,
                context: "production"
              }
            ],
            lockfile_signals: [
              { path: "project/pnpm-lock.yaml", lockfile: "pnpm-lock.yaml", manager: "pnpm", read: true, context: "shared" }
            ],
            findings: [
              {
                id: "postinstall_script_present",
                title: "postinstall script is present",
                level: "low",
                confidence: "medium",
                category: "script",
                context: "shared",
                file_path: "project/package.json",
                line: "8",
                description: "Review lifecycle script behavior.",
                evidence: "postinstall: node scripts/setup.js",
                recommendation: "Review scripts before installing dependencies."
              },
              {
                id: "npmrc_token_reference_detected",
                title: "npm auth value observed",
                confidence: "high",
                category: "package_manager_config",
                evidence: "_auth=fixture-auth"
              }
            ],
            redaction_notes: ["Package-manager credentials were redacted."],
            errors: ["https://example.test/hook?token=fixture-token&key=fixture-key"]
          }
        }}
      />
    );

    expect(screen.getByRole("heading", { name: "General Summary" })).toBeInTheDocument();
    expect(screen.getByText("Packages")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Package / Workspace Overview" })).toBeInTheDocument();
    expect(screen.getByText("demo")).toBeInTheDocument();
    expect(screen.getByText("pnpm@9.0.0")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Scripts" })).toBeInTheDocument();
    expect(screen.getByText("postinstall")).toBeInTheDocument();
    expect(screen.getByText("lifecycle")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Dependency Groups" })).toBeInTheDocument();
    expect(screen.getByText("react")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Package Manager Config Signals" })).toBeInTheDocument();
    expect(screen.getByText("_authToken")).toBeInTheDocument();
    expect(screen.getAllByText("registry").length).toBeGreaterThan(0);
    expect(screen.getAllByText("[REDACTED]").length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Lockfile Signals" })).toBeInTheDocument();
    expect(screen.getByText("pnpm-lock.yaml")).toBeInTheDocument();
    expect(screen.getByText("postinstall_script_present")).toBeInTheDocument();
    expect(screen.getByText("npmrc_token_reference_detected")).toBeInTheDocument();
    expect(screen.getByText("confidence: high")).toBeInTheDocument();
    expect(screen.getAllByText("shared").length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Files Detected / Reviewed" })).toBeInTheDocument();
    expect(screen.getByText("Package-manager credentials were redacted.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Limits / Truncation" })).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();

    const text = container.textContent ?? "";
    for (const secret of [
      "fixture-token",
      "fixture-auth",
      "fixture-password",
      "fixture-key",
      "https://user:fixture-password@registry.example.test/pkg",
      "https://example.test/hook?token=fixture-token&key=fixture-key",
      "API_KEY=fixture-key npm run build"
    ]) {
      expect(text).not.toContain(secret);
    }
  });

  it("tolerates sparse Node package config results with clear empty states", () => {
    render(
      <NodePackageConfigJobReport
        job={{
          ...baseJob,
          status: "running",
          result: {
            analyzer: "node_package_config_basic",
            summary: {}
          }
        }}
      />
    );

    expect(screen.getByText("No package overview returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No package scripts returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No dependency groups returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No package manager config signals returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No lockfile signals returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No heuristic Node package config findings reported.")).toBeInTheDocument();
    expect(screen.getByText("No Node package config candidate files detected or returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No Node package config errors reported.")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });
});
