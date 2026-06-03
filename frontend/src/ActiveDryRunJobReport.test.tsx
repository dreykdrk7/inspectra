import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { ActiveDryRunJobReport } from "./ActiveDryRunJobReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-active-1",
  audit_type: "active_network_dry_run",
  file_id: null,
  target_url: "https://example.test/",
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

describe("ActiveDryRunJobReport", () => {
  it("renders summary, policy, planned checks, blocked reasons, audit log, limits, errors, and raw JSON", () => {
    render(
      <ActiveDryRunJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "active_network_dry_run",
            mode: "dry_run",
            profile: "http_header_probe_preview",
            summary: {
              allowed: true,
              planned_checks_count: 1,
              blocked_reasons_count: 1,
              network_requests_sent: 0
            },
            target: {
              input: "https://example.test/",
              normalized: "https://example.test/",
              scope: "single-target"
            },
            authorization: {
              confirmed: true,
              statement: "I confirm I own or am authorized to test this target.",
              scope: "single-target"
            },
            policy: {
              allowed: true,
              reason: "dry_run_allowed",
              no_network: true
            },
            limits: {
              max_requests: 0,
              timeout_seconds: 0,
              max_redirects: 0,
              response_size_bytes: 0
            },
            planned_checks: [
              {
                id: "http_header_probe_preview",
                method: "HEAD",
                target: "https://example.test/",
                network_request: false
              }
            ],
            blocked_reasons: [{ code: "external_network_disabled", reason: "No network traffic is allowed in dry-run mode." }],
            audit_log: [{ event: "dry_run_created", network_requests_sent: 0 }],
            errors: ["controlled warning"]
          }
        }}
      />
    );

    expect(screen.getByRole("heading", { name: "Active network dry-run" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Target Summary" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Authorization Summary" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Policy Decision" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Planned Checks" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Blocked Reasons" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Audit Log" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Redacted Raw JSON" })).toBeInTheDocument();
    expect(screen.getByText("No network traffic was sent. Planned checks are preview records only and require human review.")).toBeInTheDocument();
    expect(screen.getAllByText("http_header_probe_preview").length).toBeGreaterThan(0);
    expect(screen.getAllByText("external_network_disabled").length).toBeGreaterThan(0);
    expect(screen.getAllByText("dry_run_created").length).toBeGreaterThan(0);
    expect(screen.getByText("controlled warning")).toBeInTheDocument();
    expect(screen.getAllByText("0").length).toBeGreaterThan(0);
  });

  it("shows blocked, sparse, running, and failed states without breaking", () => {
    render(
      <ActiveDryRunJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "active_network_dry_run",
            summary: { allowed: false, blocked_reasons_count: 1, network_requests_sent: 0 },
            policy: { allowed: false, reason: "target_not_allowed" },
            blocked_reasons: [{ code: "target_not_allowed", reason: "Target is outside the allowed dry-run scope." }]
          }
        }}
      />
    );

    expect(screen.getByText("Target blocked by safety policy. Review the blocked reasons below.")).toBeInTheDocument();
    expect(screen.getAllByText("target_not_allowed").length).toBeGreaterThan(0);

    cleanup();

    render(<ActiveDryRunJobReport job={{ ...baseJob, status: "running", result: { analyzer: "active_network_dry_run", summary: {} } }} />);
    expect(screen.getByText("Dry-run planning is running. No network traffic is sent.")).toBeInTheDocument();
    expect(screen.getByText("No planned checks were returned.")).toBeInTheDocument();

    cleanup();

    render(<ActiveDryRunJobReport job={{ ...baseJob, status: "failed", result: null, error: "controlled failure" }} />);
    expect(screen.getByText("The job failed in a controlled state. Review redacted errors below.")).toBeInTheDocument();
    expect(screen.getByText("controlled failure")).toBeInTheDocument();
    expect(screen.getByText("Show redacted payload")).toBeInTheDocument();
  });

  it("redacts legacy Active dry-run secret-like values in sections and raw JSON", () => {
    const { container } = render(
      <ActiveDryRunJobReport
        job={{
          ...baseJob,
          error: "Authorization: Bearer token_should_never_render",
          result: {
            analyzer: "active_network_dry_run",
            target: {
              input: "http://user:pass@example.com/?token=token_should_never_render",
              password: "super-secret-password"
            },
            authorization: {
              confirmed: true,
              authorization_header: "Authorization: Bearer token_should_never_render"
            },
            policy: {
              allowed: false,
              reason: "token_should_never_render"
            },
            planned_checks: [
              {
                id: "legacy_check",
                target: "http://user:pass@example.com",
                header_value: "Authorization: Bearer token_should_never_render"
              }
            ],
            blocked_reasons: [{ code: "blocked", reason: "PRIVATE KEY token_should_never_render" }],
            audit_log: [{ event: "legacy", raw: "raw-api-key-123456" }],
            errors: [
              "PASSWORD=super-secret-password",
              "Authorization: Bearer token_should_never_render",
              "-----BEGIN PRIVATE KEY----- fixture -----END PRIVATE KEY-----"
            ]
          }
        }}
      />
    );

    const rendered = container.textContent ?? "";
    for (const secret of [
      "super-secret-password",
      "raw-api-key-123456",
      "token_should_never_render",
      "Authorization: Bearer token_should_never_render",
      "http://user:pass@example.com",
      "PRIVATE KEY"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("REDACTED");
    expect(screen.getByText("Redacted Raw JSON")).toBeInTheDocument();
  });
});
