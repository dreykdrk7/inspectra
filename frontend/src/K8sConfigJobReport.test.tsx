import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { K8sConfigJobReport } from "./K8sConfigJobReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-k8s-1",
  audit_type: "k8s_config_basic",
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

describe("K8sConfigJobReport", () => {
  it("renders summary, Kubernetes sections, findings, scope copy, limits, errors, and raw JSON", () => {
    render(
      <K8sConfigJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "k8s_config_basic",
            archive_type: "zip",
            summary: {
              files_considered: 5,
              files_reviewed: 4,
              manifest_files_detected: 4,
              resources_detected: 5,
              workloads_detected: 1,
              services_detected: 1,
              secrets_detected: 1,
              rbac_resources_detected: 1,
              findings_count: 2,
              redacted_values_count: 1,
              truncated: true
            },
            limits: { max_files: 100, max_file_bytes: 524288, max_total_bytes: 2097152 },
            files_detected: [
              { path: "deploy/production/app.yaml", category: "k8s_manifest", read: true, bytes_read: 1024, context: "production" },
              { path: ".env.production", category: "env_sensitive", read: false, skip_reason: "real_env_file_not_read", context: "production" }
            ],
            files_reviewed: [
              { path: "deploy/production/app.yaml", category: "k8s_manifest", read: true, bytes_read: 1024, context: "production" }
            ],
            resources: [
              { path: "deploy/production/app.yaml", kind: "Deployment", name: "web", namespace: "prod", context: "production" },
              { path: "deploy/production/app.yaml", kind: "Secret", name: "app-secret", namespace: "prod", context: "production" }
            ],
            workloads: [{ path: "deploy/production/app.yaml", kind: "Deployment", name: "web", namespace: "prod", context: "production" }],
            containers: [
              { path: "deploy/production/app.yaml", kind: "Deployment", resource_name: "web", container: "app", image: "nginx:latest", namespace: "prod", context: "production" }
            ],
            services: [{ path: "deploy/production/app.yaml", kind: "Service", name: "web", type: "LoadBalancer", context: "production" }],
            ingress: [{ path: "deploy/production/app.yaml", kind: "Ingress", name: "web", context: "production" }],
            rbac: [{ path: "deploy/production/app.yaml", kind: "ClusterRole", name: "broad", context: "production" }],
            secrets: [{ path: "deploy/production/app.yaml", kind: "Secret", name: "app-secret", namespace: "prod", context: "production" }],
            helm_kustomize_signals: [
              { path: "charts/app/templates/deployment.yaml", category: "helm_template", rendered: false, context: "example" },
              { path: "kustomization.yaml", category: "kustomize_config", built: false, context: "shared" }
            ],
            findings: [
              {
                id: "privileged_container",
                title: "Container is configured as privileged",
                level: "medium",
                confidence: "high",
                category: "pod_security",
                kind: "Deployment",
                resource_name: "web",
                namespace: "prod",
                container: "app",
                field_path: "securityContext.privileged",
                file_path: "deploy/production/app.yaml",
                context: "production",
                line: "22",
                evidence: "kind=Deployment; metadata.name=web; field=securityContext.privileged",
                recommendation: "Review least privilege posture."
              },
              {
                id: "helm_template_detected_not_rendered",
                title: "Helm template detected but not rendered",
                level: "info",
                category: "helm",
                context: "example"
              }
            ],
            redaction_notes: ["Secret-like Kubernetes manifest values are redacted."],
            errors: ["controlled error"]
          }
        }}
        file={{ id: "archive-1", kind: "archive", original_filename: "k8s.zip", stored_filename: "k8s.zip", content_type: "application/zip", size_bytes: 100, sha256: "abc", created_at: "2026-05-26T10:00:00Z" }}
      />
    );

    expect(screen.getByRole("heading", { name: "General Summary" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Resources Detected" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Workloads / Containers" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Services / Ingress" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "RBAC" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Secrets / Config References" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Helm / Kustomize" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Findings" })).toBeInTheDocument();
    expect(screen.getByText("Passive archive-only Kubernetes manifest review. Inspectra does not run kubectl, access a cluster, render Helm, build Kustomize, download images, query registries/CVEs, or validate exploitability.")).toBeInTheDocument();
    expect(screen.getByText("Container is configured as privileged")).toBeInTheDocument();
    expect(screen.getAllByText("production").length).toBeGreaterThan(0);
    expect(screen.getByText("confidence: high")).toBeInTheDocument();
    expect(screen.getByText(".env.production")).toBeInTheDocument();
    expect(screen.getByText("real_env_file_not_read")).toBeInTheDocument();
    expect(screen.getByText("Analysis truncated by configured Kubernetes config limits. Review skipped files and rerun with a smaller archive if needed.")).toBeInTheDocument();
    expect(screen.getByText("controlled error")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });

  it("tolerates sparse Kubernetes config results and queued/running style payloads", () => {
    render(
      <K8sConfigJobReport
        job={{
          ...baseJob,
          status: "running",
          result: {
            analyzer: "k8s_config_basic",
            summary: {},
            findings: [{ id: "sparse" }]
          }
        }}
      />
    );

    expect(screen.getByText("No Kubernetes resources returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No Kubernetes workloads returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No Kubernetes services returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No Kubernetes config limits returned yet.")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
    expect(screen.getByText("sparse")).toBeInTheDocument();
  });

  it("redacts legacy Kubernetes secret-like values in report sections and raw JSON", () => {
    const { container } = render(
      <K8sConfigJobReport
        job={{
          ...baseJob,
          error: "SECRET_KEY=fixture-secret",
          result: {
            analyzer: "k8s_config_basic",
            summary: { redacted_values_count: 0 },
            resources: [
              {
                kind: "Secret",
                name: "app-secret",
                stringData: { password: "fixture-password" },
                data: { token: "fixture-token" }
              }
            ],
            containers: [
              {
                container: "app",
                env: [{ name: "API_KEY", value: "fixture-key" }],
                image: "https://user:fixture-password@registry.example.test/app"
              }
            ],
            secrets: [{ kind: "Secret", name: "app-secret", stringData: "TOKEN=fixture-token", data: "password=fixture-password" }],
            findings: [
              {
                id: "legacy_k8s_secret",
                title: "Legacy Kubernetes secret",
                evidence: "PASSWORD=fixture-password",
                description: "CLIENT_SECRET=fixture-secret",
                recommendation: "-----BEGIN PRIVATE KEY----- fixture material -----END PRIVATE KEY-----"
              }
            ],
            errors: ["API_KEY=fixture-key"]
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
      "https://user:fixture-password@registry.example.test/app"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("REDACTED");
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });
});
