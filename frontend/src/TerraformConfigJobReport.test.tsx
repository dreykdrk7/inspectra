import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { TerraformConfigJobReport } from "./TerraformConfigJobReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-terraform-1",
  audit_type: "terraform_config_basic",
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

describe("TerraformConfigJobReport", () => {
  it("renders summary, Terraform sections, findings, scope copy, limits, errors, and raw JSON", () => {
    render(
      <TerraformConfigJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "terraform_config_basic",
            archive_type: "zip",
            summary: {
              files_considered: 7,
              files_reviewed: 5,
              terraform_files_detected: 3,
              tfvars_files_detected: 1,
              state_files_detected: 1,
              providers_detected: 1,
              backends_detected: 1,
              modules_detected: 1,
              resources_detected: 3,
              findings_count: 2,
              redacted_values_count: 1,
              truncated: true
            },
            limits: { max_files: 100, max_file_bytes: 524288, max_total_bytes: 2097152 },
            files_detected: [
              { path: "infra/prod/main.tf", category: "terraform", read: true, bytes_read: 2048, context: "production" },
              { path: "infra/prod/terraform.tfstate", category: "terraform_state", read: false, skip_reason: "state_file_not_read", context: "production" }
            ],
            files_reviewed: [
              { path: "infra/prod/main.tf", category: "terraform", read: true, bytes_read: 2048, context: "production" }
            ],
            providers: [{ file_path: "infra/prod/providers.tf", name: "aws", source: "hashicorp/aws", version: "~> 5.0", context: "production" }],
            backends: [{ file_path: "infra/prod/backend.tf", type: "s3", config_keys: ["bucket", "region"], context: "production" }],
            modules: [{ file_path: "infra/prod/main.tf", name: "vpc", source: "terraform-aws-modules/vpc/aws", version: "5.0.0", context: "production" }],
            resources: [
              { file_path: "infra/prod/main.tf", provider: "aws", resource_type: "aws_security_group", resource_name: "web", context: "production" },
              { file_path: "infra/prod/main.tf", provider: "aws", resource_type: "aws_s3_bucket", resource_name: "logs", context: "production" }
            ],
            variables: [{ file_path: "infra/prod/variables.tf", name: "db_password", sensitive: true, default_present: true, context: "production" }],
            outputs: [{ file_path: "infra/prod/outputs.tf", name: "api_key", sensitive: false, context: "production" }],
            state_files: [{ path: "infra/prod/terraform.tfstate", category: "terraform_state", read: false, skip_reason: "state_file_not_read", context: "production" }],
            findings: [
              {
                id: "aws_security_group_ssh_open_world",
                title: "Security group allows SSH from any IPv4 address",
                level: "medium",
                confidence: "high",
                category: "aws_network",
                provider: "aws",
                resource_type: "aws_security_group",
                resource_name: "web",
                field_path: "ingress.cidr_blocks",
                file_path: "infra/prod/main.tf",
                context: "production",
                line: "22",
                evidence: "resource=aws_security_group.web; field=ingress.cidr_blocks",
                recommendation: "Review network exposure before applying changes."
              },
              {
                id: "terraform_state_file_present",
                title: "Terraform state file detected",
                level: "medium",
                category: "state",
                context: "production"
              }
            ],
            redaction_notes: ["Terraform secret-like values are redacted."],
            errors: ["controlled error"]
          }
        }}
        file={{ id: "archive-1", kind: "archive", original_filename: "terraform.zip", stored_filename: "terraform.zip", content_type: "application/zip", size_bytes: 100, sha256: "abc", created_at: "2026-05-26T10:00:00Z" }}
      />
    );

    expect(screen.getByRole("heading", { name: "General Summary" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Providers / Backends" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Modules" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Resources" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Variables / Outputs" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "State Files" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Findings" })).toBeInTheDocument();
    expect(screen.getByText(/Passive archive-only Terraform\/OpenTofu\/Terragrunt IaC review/)).toBeInTheDocument();
    expect(screen.getByText(/State files are detected but not read/)).toBeInTheDocument();
    expect(screen.getByText("Security group allows SSH from any IPv4 address")).toBeInTheDocument();
    expect(screen.getAllByText("production").length).toBeGreaterThan(0);
    expect(screen.getByText("confidence: high")).toBeInTheDocument();
    expect(screen.getAllByText("infra/prod/terraform.tfstate").length).toBeGreaterThan(0);
    expect(screen.getAllByText("state_file_not_read").length).toBeGreaterThan(0);
    expect(screen.getByText("Analysis truncated by configured Terraform config limits. Review skipped files and rerun with a smaller archive if needed.")).toBeInTheDocument();
    expect(screen.getByText("controlled error")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });

  it("tolerates sparse Terraform config results and queued/running style payloads", () => {
    render(
      <TerraformConfigJobReport
        job={{
          ...baseJob,
          status: "running",
          result: {
            analyzer: "terraform_config_basic",
            summary: {},
            findings: [{ id: "sparse" }]
          }
        }}
      />
    );

    expect(screen.getByText("No Terraform providers returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No Terraform resources returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No Terraform state files returned yet.")).toBeInTheDocument();
    expect(screen.getByText("No Terraform config limits returned yet.")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
    expect(screen.getByText("sparse")).toBeInTheDocument();
  });

  it("redacts legacy Terraform secret-like values in report sections and raw JSON", () => {
    const { container } = render(
      <TerraformConfigJobReport
        job={{
          ...baseJob,
          error: "PASSWORD=super-secret-password",
          result: {
            analyzer: "terraform_config_basic",
            summary: { redacted_values_count: 0 },
            providers: [{ name: "aws", access_key: "AKIAIOSFODNN7EXAMPLE", secret_key: "aws_secret_access_key_should_not_render" }],
            backends: [{ type: "s3", config: { secret_key: "aws_secret_access_key_should_not_render", password: "super-secret-password" } }],
            modules: [{ name: "db", source: "postgres://user:pass@example.com/db" }],
            resources: [{ resource_type: "aws_instance", resource_name: "web", user_data: "TOKEN=token_should_never_render" }],
            variables: [{ name: "db_password", default: "db_password_plaintext" }],
            outputs: [{ name: "api_key", value: "raw-api-key-123456", sensitive: false }],
            state_files: [{ path: "terraform.tfstate", read: false, content: "super-secret-password raw-api-key-123456" }],
            findings: [
              {
                id: "legacy_terraform_secret",
                title: "Legacy Terraform secret",
                evidence: "PASSWORD=super-secret-password",
                description: "CLIENT_SECRET=token_should_never_render",
                recommendation: "-----BEGIN PRIVATE KEY----- PRIVATE KEY db_password_plaintext -----END PRIVATE KEY-----"
              }
            ],
            errors: ["API_KEY=raw-api-key-123456", "AWS_SECRET_ACCESS_KEY=aws_secret_access_key_should_not_render", "postgres://user:pass@example.com/db"]
          }
        }}
      />
    );

    const rendered = container.textContent ?? "";
    for (const secret of [
      "super-secret-password",
      "raw-api-key-123456",
      "token_should_never_render",
      "PRIVATE KEY",
      "db_password_plaintext",
      "AKIAIOSFODNN7EXAMPLE",
      "aws_secret_access_key_should_not_render",
      "postgres://user:pass@example.com/db"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("REDACTED");
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
  });
});
