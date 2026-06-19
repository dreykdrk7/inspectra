import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { ActiveHttpBasicHeaderReviewJobReport } from "./ActiveHttpBasicHeaderReviewJobReport";
import { buildActiveHttpBasicHeaderReviewReport, redactActiveHttpBasicHeaderReviewText } from "./activeHttpBasicHeaderReviewReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-active-http-basic-header-review-1",
  audit_type: "active_http_basic_header_review",
  file_id: null,
  target_url: "[REDACTED_TARGET]",
  target_domain: null,
  status: "completed",
  created_at: "2026-06-19T10:00:00Z",
  updated_at: "2026-06-19T10:01:00Z",
  source_file_deleted_at: null,
  error: null
} satisfies Omit<JobRecord, "result">;

const noisyValues = [
  "https://authorized.example/",
  "authorized.example",
  "token_should_never_render",
  "session_should_not_render",
  "cookie_should_not_render",
  "Authorization: Bearer token_should_never_render",
  "raw-api-key-123456",
  "response_body_should_not_render",
  "redirect-location-should-not-render",
  "raw_exception_should_not_render"
];

afterEach(() => {
  cleanup();
});

describe("ActiveHttpBasicHeaderReviewJobReport", () => {
  it("renders the no-live HTTP header review fields without treating completed as request success", () => {
    render(
      <ActiveHttpBasicHeaderReviewJobReport
        job={{
          ...baseJob,
          result: {
            audit_type: "active_http_basic_header_review",
            capability: "active_http_basic_header_review",
            mode: "live_http_basic_header_review",
            profile: "http_headers_single_request",
            status: "not_executed",
            result_status: "not_executed",
            lifecycle_state: "not_executed",
            target: "[REDACTED_TARGET]",
            target_display: "[REDACTED_TARGET]",
            method: "HEAD",
            manual_validation_required: true,
            review_wording: "HTTP header review indicator",
            result_interpretation: "HTTP header review indicator",
            job_status_meaning: "Completed job status means the no-live record was stored; no HTTP request was performed.",
            execution: {
              live_request_performed: false,
              network_requests_sent: 0,
              requests_sent: 0,
              http_requests_sent: 0,
              redirect_followed: false,
              body_read: false,
              job_created: true,
              storage_persisted: true
            },
            summary: {
              result_status: "not_executed",
              manual_validation_required: true,
              review_wording: "HTTP header review indicator",
              result_interpretation: "HTTP header review indicator",
              job_status_meaning: "Completed job status means the no-live record was stored; no HTTP request was performed.",
              live_request_performed: false,
              redirect_followed: false,
              body_read: false,
              requests_sent: 0,
              http_requests_sent: 0,
              job_created: true,
              storage_persisted: true
            },
            limits: {
              max_targets: 1,
              method: "HEAD",
              max_redirects: 0,
              response_body_bytes: 0,
              raw_target_persisted: false,
              headers_persisted: false,
              cookies_persisted: false,
              response_body_persisted: false
            },
            surface_caveats: [
              "No live HTTP request was performed",
              "No redirect was followed",
              "No response body was read",
              "Manual validation required",
              "HTTP header review indicator wording only"
            ]
          }
        }}
      />
    );

    expect(screen.getByRole("heading", { name: "Active / HTTP header review report" })).toBeInTheDocument();
    expect(screen.getByText("No-live review record")).toBeInTheDocument();
    expect(screen.getAllByText("not_executed").length).toBeGreaterThan(0);
    expect(screen.getAllByText("[REDACTED_TARGET]").length).toBeGreaterThan(0);
    expect(screen.getAllByText("HEAD").length).toBeGreaterThan(0);
    expect(screen.getAllByText("HTTP header review indicator").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Manual validation required").length).toBeGreaterThan(0);
    expect(screen.getAllByText("false").length).toBeGreaterThan(0);
    expect(screen.getAllByText("0").length).toBeGreaterThan(0);
    expect(screen.getByText("Completed job status means the no-live record was stored; no HTTP request was performed.")).toBeInTheDocument();
    expect(screen.getByText("No live HTTP request was performed. Completed job status only means the no-live review record was stored.")).toBeInTheDocument();
    expect(screen.getByText("Raw JSON (redacted)")).toBeInTheDocument();
    expect(document.body.textContent ?? "").not.toMatch(/request\s+success/i);
  });

  it("keeps report and raw JSON display on the no-live allowlist", () => {
    const { container } = render(
      <ActiveHttpBasicHeaderReviewJobReport
        job={{
          ...baseJob,
          target_url: "https://authorized.example/?token=token_should_never_render",
          error: "raw_exception_should_not_render token_should_never_render",
          result: {
            audit_type: "active_http_basic_header_review",
            capability: "active_http_basic_header_review",
            status: "not_executed",
            result_status: "not_executed",
            target: "https://authorized.example/",
            raw_target: "https://authorized.example/private?token=token_should_never_render",
            method: "HEAD",
            headers: [{ name: "Authorization", value: "Bearer token_should_never_render" }],
            cookies: ["session_should_not_render=cookie_should_not_render"],
            redirect_chain: ["redirect-location-should-not-render"],
            response_body: "response_body_should_not_render",
            exception: "raw_exception_should_not_render",
            credentials: { api_key: "raw-api-key-123456" },
            execution: {
              live_request_performed: true,
              network_requests_sent: 99,
              requests_sent: 99,
              redirect_followed: true,
              body_read: true,
              job_created: true,
              storage_persisted: true
            },
            summary: {
              requests_sent: 99,
              live_request_performed: true,
              redirect_followed: true,
              body_read: true,
              job_created: true,
              storage_persisted: true
            },
            limits: {
              max_url_length: 2048
            },
            surface_caveats: ["No live HTTP request was performed"]
          }
        }}
      />
    );

    const rendered = container.textContent ?? "";
    for (const value of noisyValues) {
      expect(rendered).not.toContain(value);
    }
    expect(rendered).toContain("[REDACTED_TARGET]");
    expect(rendered).toContain('"requests_sent": 0');
    expect(rendered).toContain('"live_request_performed": false');
    expect(rendered).toContain('"redirect_followed": false');
    expect(rendered).toContain('"body_read": false');
  });

  it("renders live observed HEAD result indicators without raw target, header, cookie, or Location values", () => {
    const { container } = render(
      <ActiveHttpBasicHeaderReviewJobReport
        job={{
          ...baseJob,
          result: {
            audit_type: "active_http_basic_header_review",
            capability: "active_http_basic_header_review",
            status: "observed",
            result_status: "observed",
            lifecycle_state: "observed",
            target: "https://authorized.example/private?token=token_should_never_render#fragment",
            target_display: "https://authorized.example/",
            raw_target: "https://authorized.example/private?token=token_should_never_render#fragment",
            method: "HEAD",
            headers: [
              { name: "Server", value: "server_should_not_render" },
              { name: "Set-Cookie", value: "session_should_not_render=cookie_should_not_render" },
              { name: "Location", value: "https://authorized.example/next?token=token_should_never_render" }
            ],
            cookies: [{ name: "session_should_not_render", value: "cookie_should_not_render" }],
            response: {
              status_code: 302,
              status_class: "3xx",
              redirect_present: true,
              location_header_present: true,
              redirect_followed: false,
              body_read: false,
              body_bytes_read: 0,
              location: "https://authorized.example/next?token=token_should_never_render",
              headers: [{ name: "Server", value: "server_should_not_render" }],
              body: "response_body_should_not_render"
            },
            resolver_guard: {
              checked: true,
              resolved: true,
              answers_count: 1,
              blocked_answers_count: 0,
              resolved_ips: ["93.184.216.34"],
              exception: "raw_exception_should_not_render"
            },
            header_indicators: {
              hsts_present: true,
              csp_present: true,
              x_content_type_options_present: true,
              x_frame_options_present: true,
              referrer_policy_present: true,
              permissions_policy_present: true,
              server_header_present: true,
              server_header_value_redacted: true,
              set_cookie_present: true,
              set_cookie_count: 12,
              set_cookie_count_truncated: true,
              set_cookie_secure_attribute_present: true,
              set_cookie_httponly_attribute_present: true,
              set_cookie_samesite_attribute_present: true,
              location_header_present: true,
              raw_server_value: "server_should_not_render"
            },
            execution: {
              live_request_performed: true,
              network_requests_sent: 1,
              requests_sent: 1,
              http_requests_sent: 1,
              dns_queries_sent: 1,
              redirect_followed: false,
              body_read: false,
              job_created: true,
              storage_persisted: true
            },
            summary: {
              result_status: "observed",
              status_code: 302,
              status_class: "3xx",
              redirect_present: true,
              location_header_present: true,
              live_request_performed: true,
              redirect_followed: false,
              body_read: false,
              requests_sent: 1,
              http_requests_sent: 1,
              headers_received_count: 10,
              headers_processed_count: 8,
              redacted_headers_count: 2,
              truncated_headers_count: 1
            },
            errors: [{ code: "raw_exception_should_not_render" }],
            exception: "raw_exception_should_not_render",
            response_body: "response_body_should_not_render",
            surface_caveats: [
              "One authorized HTTP HEAD request was attempted",
              "No redirect was followed",
              "No response body was read",
              "Manual validation required",
              "HTTP header review indicator wording only"
            ]
          }
        }}
      />
    );

    const rendered = container.textContent ?? "";
    expect(screen.getByText("Backend live HEAD result")).toBeInTheDocument();
    expect(screen.getAllByText("observed").length).toBeGreaterThan(0);
    expect(screen.getAllByText("302").length).toBeGreaterThan(0);
    expect(screen.getAllByText("3xx").length).toBeGreaterThan(0);
    expect(screen.getAllByText("true").length).toBeGreaterThan(0);
    expect(screen.getByText("A backend-gated live HEAD attempt reached a controlled terminal state. Job status is not a target pass or security success.")).toBeInTheDocument();
    expect(screen.getByText("Header Presence Indicators")).toBeInTheDocument();
    expect(screen.getByText("set_cookie_count")).toBeInTheDocument();
    expect(rendered).toContain("8");
    for (const value of [...noisyValues, "server_should_not_render", "93.184.216.34", "fragment"]) {
      expect(rendered).not.toContain(value);
    }
    expect(rendered).toContain("[REDACTED_TARGET]");
    expect(rendered).toContain('"headers": []');
    expect(rendered).toContain('"cookies": []');
    expect(rendered).toContain('"redirect_chain": []');
    expect(rendered).toContain('"body_read": false');
    expect(rendered).toContain('"redirect_followed": false');
  });

  it("renders live timeout and controlled error statuses as redacted review context", () => {
    for (const status of ["timed_out", "request_failed"]) {
      cleanup();
      const { container } = render(
        <ActiveHttpBasicHeaderReviewJobReport
          job={{
            ...baseJob,
            status: "failed",
            result: {
              capability: "active_http_basic_header_review",
              status,
              result_status: status,
              target: "https://authorized.example/?token=token_should_never_render",
              method: "HEAD",
              errors: [{ code: status === "timed_out" ? "request_timed_out" : "controlled_network_error", message: "raw_exception_should_not_render" }],
              execution: {
                live_request_performed: true,
                requests_sent: 1,
                network_requests_sent: 1,
                http_requests_sent: 1,
                redirect_followed: false,
                body_read: false
              },
              summary: {
                live_request_performed: true,
                requests_sent: 1,
                redirect_followed: false,
                body_read: false
              },
              exception: "raw_exception_should_not_render"
            }
          }}
        />
      );

      const rendered = container.textContent ?? "";
      expect(rendered).toContain(status);
      expect(rendered).toContain(status === "timed_out" ? "request_timed_out" : "controlled_network_error");
      expect(rendered).toContain("HTTP header review indicator");
      expect(rendered).toContain("Manual validation required");
      expect(rendered).not.toContain("authorized.example");
      expect(rendered).not.toContain("token_should_never_render");
      expect(rendered).not.toContain("raw_exception_should_not_render");
    }
  });

  it("exposes a helper that redacts target display values defensively", () => {
    const report = buildActiveHttpBasicHeaderReviewReport({
      ...baseJob,
      target_url: "https://authorized.example/?token=token_should_never_render",
      result: {
        capability: "active_http_basic_header_review",
        status: "not_executed",
        result_status: "not_executed",
        reason_codes: ["query_not_allowed", "not_live"]
      }
    });

    expect(report.isActiveHttpBasicHeaderReview).toBe(true);
    expect(report.target).toBe("[REDACTED_TARGET]");
    expect(report.method).toBe("HEAD");
    expect(report.reasonCodes).toEqual(["query_not_allowed", "controlled_no_live"]);
    expect(report.rawJson).not.toContain("authorized.example");
    expect(report.rawJson).not.toContain("token_should_never_render");
    expect(redactActiveHttpBasicHeaderReviewText("https://authorized.example/")).toBe("[REDACTED_TARGET]");
  });
});
