import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { ComposeConfigJobReport } from "./ComposeConfigJobReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-compose-1",
  audit_type: "compose_config_basic",
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

describe("ComposeConfigJobReport", () => {
  it("renders summary, Compose sections, findings, limits, errors, and raw JSON", () => {
    render(
      <ComposeConfigJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "compose_config_basic",
            archive_type: "zip",
            summary: {
              files_considered: 5,
              files_reviewed: 2,
              compose_files_detected: 2,
              services_detected: 2,
              networks_detected: 1,
              volumes_detected: 1,
              secrets_detected: 1,
              published_ports_detected: 2,
              env_files_detected: 1,
              findings_count: 2,
              redacted_values_count: 1,
              truncated: true
            },
            limits: { max_files: 100, max_file_bytes: 524288, max_total_bytes: 2097152 },
            files_detected: [
              { path: "deploy/compose/docker-compose.yml", category: "compose", read: true, bytes_read: 2048, context: "production" },
              { path: ".env.production", category: "sensitive_env", read: false, skip_reason: "sensitive_file_not_read", context: "production" }
            ],
            files_reviewed: [
              { path: "deploy/compose/docker-compose.yml", category: "compose", read: true, bytes_read: 2048, context: "production" }
            ],
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
                privileged: true,
                user: "root",
                network_mode: "host"
              }
            ],
            images: [{ service: "web", image: "nginx:latest", tag: "latest", file_path: "deploy/compose/docker-compose.yml", context: "production" }],
            build_contexts: [{ service: "web", context_path: "./web", dockerfile: "Dockerfile", file_path: "deploy/compose/docker-compose.yml" }],
            ports: [
              { service: "db", host_ip: "0.0.0.0", published: "5432", target: "5432", protocol: "tcp", file_path: "deploy/compose/docker-compose.yml", context: "production" }
            ],
            volumes: [{ service: "web", host_path: "/var/run/docker.sock", target: "/var/run/docker.sock", read_only: false, type: "bind" }],
            networks: [{ name: "edge", service: "web", external: true, internal: false, file_path: "deploy/compose/docker-compose.yml" }],
            secrets: [{ name: "db_password", service: "web", file: "./secrets/db_password.txt", read: false, skip_reason: "not_read", file_path: "deploy/compose/docker-compose.yml" }],
            env_files: [{ service: "web", path: ".env.production", read: false, skip_reason: "sensitive_file_not_read", file_path: "deploy/compose/docker-compose.yml" }],
            findings: [
              {
                id: "compose_privileged_true",
                title: "Compose service runs privileged",
                level: "medium",
                confidence: "high",
                category: "hardening",
                context: "production",
                service: "web",
                field_path: "services.web.privileged",
                file_path: "deploy/compose/docker-compose.yml",
                evidence: "services.web.privileged=true",
                recommendation: "Review whether privileged mode is required."
              },
              {
                id: "compose_env_file_reference",
                title: "Compose env_file reference detected",
                level: "low",
                confidence: "high",
                category: "secrets",
                service: "web",
                file_path: "deploy/compose/docker-compose.yml",
                evidence: "env_file=.env.production"
              }
            ],
            redaction_notes: ["Compose env files are detected but not read."],
            errors: ["controlled parser warning"]
          }
        }}
        file={{ id: "archive-1", kind: "archive", original_filename: "compose.zip", stored_filename: "compose.zip", content_type: "application/zip", size_bytes: 100, sha256: "abc", created_at: "2026-05-26T10:00:00Z" }}
      />
    );

    expect(screen.getByRole("heading", { name: "General Summary" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Services" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Images and Build Contexts" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Ports / Exposure" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Volumes / Mounts" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Networks" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Secrets and Env File References" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Findings" })).toBeInTheDocument();
    expect(screen.getByText(/Passive archive-only Docker Compose config review/)).toBeInTheDocument();
    expect(screen.getAllByText(/not read by v1/).length).toBeGreaterThan(0);
    expect(screen.getByText("Compose service runs privileged")).toBeInTheDocument();
    expect(screen.getAllByText("nginx:latest").length).toBeGreaterThan(0);
    expect(screen.getAllByText(".env.production").length).toBeGreaterThan(0);
    expect(screen.getByText("Analysis truncated by configured Compose config limits. Review skipped files and rerun with a smaller archive if needed.")).toBeInTheDocument();
    expect(screen.getByText("controlled parser warning")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });

  it("tolerates sparse, malformed, and running style Compose config payloads", () => {
    render(
      <ComposeConfigJobReport
        job={{
          ...baseJob,
          status: "running",
          result: {
            analyzer: "compose_config_basic",
            summary: {},
            findings: [{ id: "sparse" }]
          }
        }}
      />
    );

    expect(screen.getByText("No Compose services returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No Compose images returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No published Compose ports returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No Compose volumes returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No Compose networks returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No Compose config limits returned yet.")).toBeInTheDocument();
    expect(screen.getByText("sparse")).toBeInTheDocument();

    cleanup();

    render(<ComposeConfigJobReport job={{ ...baseJob, status: "failed", result: null, error: "controlled failure" }} />);
    expect(screen.getByText("controlled failure")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });

  it("redacts legacy Compose secret-like values in report sections and raw JSON", () => {
    const { container } = render(
      <ComposeConfigJobReport
        job={{
          ...baseJob,
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
            secrets: [{ name: "db_password", file: "./secret.txt", content: "super-secret-password", read: false }],
            env_files: [{ service: "app", path: ".env", content: "DATABASE_URL=postgres://user:pass@example.com/db", read: false }],
            findings: [
              {
                id: "legacy_compose_secret",
                title: "Legacy Compose secret",
                evidence: "DATABASE_URL=postgres://user:pass@example.com/db",
                description: "redis://:super-secret-password@redis:6379/0",
                recommendation: "raw-api-key-123456 token_should_never_render"
              }
            ],
            errors: ["POSTGRES_PASSWORD=super-secret-password", "registry-user:registry-pass", "-----BEGIN PRIVATE KEY-----"]
          }
        }}
      />
    );

    const rendered = container.textContent ?? "";
    for (const secret of [
      "super-secret-password",
      "raw-api-key-123456",
      "token_should_never_render",
      "POSTGRES_PASSWORD=super-secret-password",
      "DATABASE_URL=postgres://user:pass@example.com/db",
      "redis://:super-secret-password@redis:6379/0",
      "registry-user:registry-pass",
      "PRIVATE KEY"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("REDACTED");
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });
});
