import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { ActiveHttpHeaderProbeJobReport } from "./ActiveHttpHeaderProbeJobReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-active-http-1",
  audit_type: "active_http_header_probe",
  file_id: null,
  target_url: "https://example.test/",
  target_domain: null,
  status: "completed",
  created_at: "2026-05-26T10:00:00Z",
  updated_at: "2026-05-26T10:01:00Z",
  source_file_deleted_at: null,
  error: null
} satisfies Omit<JobRecord, "result">;

const fixtureSecrets = [
  "super-secret-password",
  "token_should_never_render",
  "raw-api-key-123456",
  "Authorization: Bearer token_should_never_render",
  "http://user:pass@example.com",
  "session_should_not_render",
  "cookie_should_not_render",
  "-----BEGIN PRIVATE KEY-----",
  "PRIVATE KEY"
];

afterEach(() => {
  cleanup();
});

describe("ActiveHttpHeaderProbeJobReport", () => {
  it("renders live HEAD sections, response headers, limits, errors, and raw JSON", () => {
    render(
      <ActiveHttpHeaderProbeJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "active_http_header_probe",
            mode: "live_header_probe",
            profile: "http_header_probe",
            summary: {
              allowed: true,
              network_requests_sent: 1,
              body_bytes_read: 0,
              redirects_followed: 0,
              redacted_headers_count: 2
            },
            target: {
              input: "https://example.test/",
              normalized: "https://example.test/",
              scope: "single-target"
            },
            authorization: {
              confirmed: true,
              live_traffic_confirmed: true,
              scope: "single-target"
            },
            policy: {
              allowed: true,
              reason: "policy_allowed"
            },
            dns: {
              resolution_attempted: true,
              answers_count: 1,
              blocked_answers_count: 0,
              policy: "allowed"
            },
            request: {
              method: "HEAD",
              network_requests_sent: 1,
              custom_headers: "none"
            },
            response: {
              status_code: 200,
              body_read: false,
              body_bytes_read: 0,
              redirects_followed: 0,
              headers: [
                { name: "Server", value: "nginx", truncated: false },
                { name: "Set-Cookie", value: "session_should_not_render=cookie_should_not_render", truncated: false },
                { name: "Location", value: "https://example.test/callback?token=token_should_never_render", truncated: true }
              ]
            },
            observations: [{ code: "redirect_present_not_followed_info", evidence: "Location token=token_should_never_render" }],
            findings: [{ id: "header_review_indicator", title: "Header review indicator", level: "info", evidence: "raw-api-key-123456" }],
            blocked_reasons: [],
            limits: {
              max_targets: 1,
              max_requests: 1,
              timeout_seconds: 3,
              max_redirects: 0,
              response_body_bytes: 0
            },
            audit_log: [{ event: "head_request_completed", network_requests_sent: 1 }],
            errors: ["controlled warning"]
          }
        }}
      />
    );

    expect(screen.getByRole("heading", { name: "Authorized HTTP header probe" })).toBeInTheDocument();
    expect(screen.getByText("Live HEAD request")).toBeInTheDocument();
    expect(screen.getByText("Body not read")).toBeInTheDocument();
    expect(screen.getByText("Redirects not followed")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Live Probe Scope Notice" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "DNS Policy Summary" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Request Sent" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Response Headers" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Observations" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Findings" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Redacted Raw JSON" })).toBeInTheDocument();
    expect(screen.getByText("One authorized HTTP HEAD request was sent. Response body was not read. Redirects were not followed.")).toBeInTheDocument();
    expect(screen.getByText(/Header observations are review indicators, not confirmed vulnerabilities\./)).toBeInTheDocument();
    expect(screen.getAllByText("HEAD").length).toBeGreaterThan(0);
    expect(screen.getAllByText("body_read").length).toBeGreaterThan(0);
    expect(screen.getAllByText("body_bytes_read").length).toBeGreaterThan(0);
    expect(screen.getAllByText("redirects_followed").length).toBeGreaterThan(0);
    expect(screen.getByText("Server")).toBeInTheDocument();
    expect(screen.getByText("Set-Cookie")).toBeInTheDocument();
    expect(screen.getAllByText("[REDACTED]").length).toBeGreaterThan(0);
    expect(screen.getByText("controlled warning")).toBeInTheDocument();
    expect(screen.getByText("Show redacted payload")).toBeInTheDocument();
  });

  it("shows blocked, sparse, running, and failed states without breaking", () => {
    render(
      <ActiveHttpHeaderProbeJobReport
        job={{
          ...baseJob,
          result: {
            analyzer: "active_http_header_probe",
            summary: { allowed: false, network_requests_sent: 0, body_bytes_read: 0, redirects_followed: 0 },
            policy: { allowed: false, reason: "resolved_ip_blocked" },
            blocked_reasons: [{ code: "resolved_ip_blocked", reason: "A resolved IP address was blocked." }]
          }
        }}
      />
    );

    expect(screen.getByText("No HTTP request was sent.")).toBeInTheDocument();
    expect(screen.getByText("Target blocked or request not sent. Review policy and blocked reasons below.")).toBeInTheDocument();
    expect(screen.getAllByText("resolved_ip_blocked").length).toBeGreaterThan(0);

    cleanup();

    render(<ActiveHttpHeaderProbeJobReport job={{ ...baseJob, status: "running", result: { analyzer: "active_http_header_probe", summary: {} } }} />);
    expect(screen.getByText("Authorized HTTP header probe job is running under one-request limits.")).toBeInTheDocument();
    expect(screen.getByText("No response headers were returned.")).toBeInTheDocument();

    cleanup();

    render(<ActiveHttpHeaderProbeJobReport job={{ ...baseJob, status: "failed", result: null, error: "controlled failure" }} />);
    expect(screen.getByText("The job failed in a controlled state. Review redacted errors below.")).toBeInTheDocument();
    expect(screen.getByText("controlled failure")).toBeInTheDocument();
    expect(screen.getByText("Show redacted payload")).toBeInTheDocument();
  });

  it("redacts legacy Active HTTP header probe secrets in sections and raw JSON", () => {
    const { container } = render(
      <ActiveHttpHeaderProbeJobReport
        job={{
          ...baseJob,
          target_url: "http://user:pass@example.com/?token=token_should_never_render",
          error: "Authorization: Bearer token_should_never_render",
          result: {
            analyzer: "active_http_header_probe",
            target: {
              input: "http://user:pass@example.com/?token=token_should_never_render",
              password: "super-secret-password"
            },
            authorization: {
              confirmed: true,
              live_traffic_confirmed: true,
              authorization_header: "Authorization: Bearer token_should_never_render"
            },
            policy: {
              allowed: false,
              reason: "token_should_never_render"
            },
            response: {
              headers: [
                { name: "Set-Cookie", value: "session_should_not_render=cookie_should_not_render" },
                { name: "Authorization", value: "Authorization: Bearer token_should_never_render" },
                { name: "X-Api-Key", value: "raw-api-key-123456" },
                { name: "Location", value: "http://user:pass@example.com/?token=token_should_never_render" },
                { name: "X-Key", value: "-----BEGIN PRIVATE KEY----- fixture -----END PRIVATE KEY-----" }
              ]
            },
            observations: [{ code: "legacy_observation", evidence: "raw-api-key-123456" }],
            findings: [{ id: "legacy_finding", evidence: "PRIVATE KEY token_should_never_render" }],
            blocked_reasons: [{ code: "blocked", reason: "PASSWORD=super-secret-password" }],
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
    for (const secret of fixtureSecrets) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("REDACTED");
  });
});
