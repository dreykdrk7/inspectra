import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { DockerConfigJobReport } from "./DockerConfigJobReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-docker-1",
  audit_type: "docker_config_basic",
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

describe("DockerConfigJobReport", () => {
  it("renders grouped findings, context, files, stages, services, and redacted raw JSON", () => {
    render(
      <DockerConfigJobReport
        job={{
          ...baseJob,
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
              truncated: true
            },
            limits: { max_files: 100 },
            files_detected: [
              { path: "Dockerfile", category: "dockerfile", read: true, size_bytes: 128, context: "shared" },
              { path: "compose.prod.yml", category: "compose", read: true, size_bytes: 256, context: "production" }
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
                file_path: "compose.prod.yml",
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
                evidence: "FROM python:latest",
                description: "Review whether this tag is intentional.",
                recommendation: "Pin images in controlled deployments.",
                file_path: "Dockerfile",
                stage: "runtime"
              },
              {
                id: "docker_sensitive_env_name",
                title: "Sensitive environment name observed",
                level: "info",
                category: "compose",
                context: "production",
                evidence: "SECRET_KEY=[REDACTED]",
                description: "A sensitive environment variable name was present.",
                recommendation: "Keep secret values out of compose files.",
                service: "web"
              }
            ],
            redaction_notes: ["Sensitive environment values were redacted."],
            errors: ["TOKEN=super-secret-value-123"]
          }
        }}
      />
    );

    expect(screen.getByRole("heading", { name: "General Summary" })).toBeInTheDocument();
    expect(screen.getByText("Dockerfiles")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Findings" })).toBeInTheDocument();
    expect(screen.getByText("docker_latest_tag")).toBeInTheDocument();
    expect(screen.getByText("docker_sensitive_env_name")).toBeInTheDocument();
    expect(screen.getAllByText("production").length).toBeGreaterThan(0);
    expect(screen.getAllByText("shared").length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Files Detected / Reviewed" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Dockerfile Stages" })).toBeInTheDocument();
    expect(screen.getAllByText("python:latest").length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Compose Services" })).toBeInTheDocument();
    expect(screen.getAllByText("web").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Sensitive environment values were redacted.").length).toBeGreaterThan(0);
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
    expect(screen.queryByText("super-secret-value-123")).not.toBeInTheDocument();
  });

  it("tolerates sparse Docker config results with clear empty states", () => {
    render(
      <DockerConfigJobReport
        job={{
          ...baseJob,
          status: "running",
          result: {
            analyzer: "docker_config_basic",
            summary: {}
          }
        }}
      />
    );

    expect(screen.getByText("No heuristic findings reported.")).toBeInTheDocument();
    expect(screen.getByText("No Docker-related files detected or returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No Dockerfile stages returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No Compose services returned yet.")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });
});
