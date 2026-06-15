import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { ActiveDnsOsintJobReport } from "./ActiveDnsOsintJobReport";
import { buildActiveDnsOsintReport, redactActiveDnsOsintValue } from "./activeDnsOsintReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-active-dns-osint-1",
  audit_type: "active_dns_osint",
  file_id: null,
  target_url: "[REDACTED_DOMAIN]",
  target_domain: null,
  status: "completed",
  created_at: "2026-06-15T10:00:00Z",
  updated_at: "2026-06-15T10:01:00Z",
  source_file_deleted_at: null,
  error: null
} satisfies Omit<JobRecord, "result">;

const forbiddenClaimPatterns = [
  new RegExp(["all", "\\s+", "subdomains", "\\s+", "found"].join(""), "i"),
  new RegExp(["all", "\\s+", "records", "\\s+", "found"].join(""), "i"),
  new RegExp(["complete", "\\s+", "coverage"].join(""), "i"),
  new RegExp(["confirmed", "\\s+", "vulnerability"].join(""), "i"),
  new RegExp(["exploit", "able"].join(""), "i"),
  new RegExp(["target", "\\s+", "is", "\\s+", "safe"].join(""), "i"),
  new RegExp(["public", "\\s+", "scanner"].join(""), "i")
];

afterEach(() => {
  cleanup();
});

describe("ActiveDnsOsintJobReport", () => {
  it("renders CT OSINT counts, passive DNS boundary, and redacted observed samples", () => {
    render(
      <ActiveDnsOsintJobReport
        job={{
          ...baseJob,
          result: {
            audit_type: "active_dns_osint",
            capability: "active_dns_osint",
            mode: "live_dns_osint",
            profile: "ct_subdomain_discovery_bounded",
            status: "osint_best_effort",
            result_status: "osint_best_effort",
            coverage_level: "osint_best_effort",
            domain: "[REDACTED_DOMAIN]",
            sources: {
              certificate_transparency: {
                attempted: true,
                status: "completed",
                names_observed_count: 7,
                names_retained_count: 5,
                names_discarded_count: 2,
                truncated: false
              },
              passive_dns: { attempted: false, status: "not_attempted" }
            },
            observed_names: {
              count: 5,
              max_names: 100,
              sample: ["[REDACTED_DNS_NAME]", "[REDACTED_DNS_NAME]", "[REDACTED_DNS_NAME]"],
              truncated: false
            },
            execution: {
              external_requests_sent: 1,
              ct_queries_sent: 1,
              passive_dns_queries_sent: 0,
              dns_queries_sent: 0,
              http_requests_sent: 0,
              provider_api_used: false,
              crawling_performed: false,
              observed_name_auto_scan_performed: false
            },
            limits: { max_names: 100, source_error_details_persisted: false },
            surface_caveats: ["Manual validation required.", "Observed names are not auto-scanned."]
          }
        }}
      />
    );

    expect(screen.getByRole("heading", { name: "Active / DNS OSINT report" })).toBeInTheDocument();
    expect(screen.getAllByText("osint_best_effort").length).toBeGreaterThan(0);
    expect(screen.getAllByText("DNS OSINT review indicator").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/OSINT best-effort/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Manual validation required/).length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Certificate Transparency Source" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Observed Names" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Passive DNS" })).toBeInTheDocument();
    expect(screen.getByText("CT source completed within configured bounds.")).toBeInTheDocument();
    expect(screen.getAllByText("[REDACTED_DOMAIN]").length).toBeGreaterThan(0);
    expect(screen.getAllByText("[REDACTED_DNS_NAME]").length).toBeGreaterThan(0);
    expect(screen.getByText("Passive DNS is not part of this product flow.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Raw JSON (redacted)" })).toBeInTheDocument();
  });

  it("renders controlled CT source states conservatively", () => {
    const statuses = ["partial", "timed_out", "rate_limited", "source_unavailable", "invalid_source_response"] as const;
    for (const status of statuses) {
      const { unmount } = render(
        <ActiveDnsOsintJobReport
          job={{
            ...baseJob,
            result: {
              capability: "active_dns_osint",
              result_status: "osint_best_effort",
              coverage_level: "osint_best_effort",
              domain: "[REDACTED_DOMAIN]",
              sources: {
                certificate_transparency: {
                  attempted: true,
                  status,
                  names_observed_count: 1,
                  names_retained_count: 1,
                  names_discarded_count: 0,
                  truncated: status === "partial"
                },
                passive_dns: { attempted: false, status: "not_attempted" }
              },
              observed_names: { count: 1, max_names: 10, sample: ["[REDACTED_DNS_NAME]"], truncated: status === "partial" }
            }
          }}
        />
      );
      expect(screen.getAllByText(status).length).toBeGreaterThan(0);
      expect(document.body.textContent ?? "").toContain("controlled");
      unmount();
    }
  });

  it("redacts raw CT payloads, names, certificate material, source errors, and forbidden claims", () => {
    const { container } = render(
      <ActiveDnsOsintJobReport
        job={{
          ...baseJob,
          target_url: "secret.example.internal",
          result: {
            capability: "active_dns_osint",
            status: "osint_best_effort",
            coverage_level: "osint_best_effort",
            domain: "secret.example.internal",
            sources: {
              certificate_transparency: {
                attempted: true,
                status: "completed",
                names_observed_count: 3,
                names_retained_count: 2,
                names_discarded_count: 1,
                truncated: false,
                raw_ct_payload: "admin.secret.example.internal raw-ct-token",
                certificate_body: "-----BEGIN CERTIFICATE-----\nraw cert body\n-----END CERTIFICATE-----"
              },
              passive_dns: { attempted: true, status: "provider_api_used" }
            },
            observed_names: {
              count: 2,
              max_names: 100,
              sample: ["admin.secret.example.internal", "mail.secret.example.internal"],
              truncated: false
            },
            raw_ct_payload: "admin.secret.example.internal raw-ct-token",
            certificate_body: "-----BEGIN CERTIFICATE-----\nraw cert body\n-----END CERTIFICATE-----",
            raw_source_error: "secret.example.internal source traceback raw-ct-token",
            provider_api_token: "provider-token-123",
            headers: { Authorization: "Bearer raw-ct-token" },
            errors: [{ source: "certificate_transparency", code: "timed_out", detail: "admin.secret.example.internal raw-ct-token" }],
            legacy: {
              notes: [
                "all " + "subdomains " + "found",
                "complete " + "coverage",
                "confirmed " + "vulnerability",
                "exploit" + "able",
                "target is " + "safe",
                "public " + "scanner"
              ].join(" ")
            }
          },
          error: "secret.example.internal raw-ct-token"
        }}
      />
    );

    const rendered = container.textContent ?? "";
    for (const secret of [
      "secret.example.internal",
      "admin.secret.example.internal",
      "mail.secret.example.internal",
      "raw-ct-token",
      "provider-token-123",
      "raw cert body",
      "source traceback"
    ]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("[REDACTED");
    expect(rendered).toContain("not_attempted");
    for (const pattern of forbiddenClaimPatterns) {
      expect(rendered).not.toMatch(pattern);
    }
  });

  it("exposes a pure report helper with defensive Raw JSON redaction", () => {
    const report = buildActiveDnsOsintReport({
      ...baseJob,
      target_url: "secret.example.internal",
      result: {
        capability: "active_dns_osint",
        status: "osint_best_effort",
        coverage_level: "osint_best_effort",
        domain: "secret.example.internal",
        sources: {
          certificate_transparency: {
            attempted: true,
            status: "completed",
            names_observed_count: 1,
            names_retained_count: 1,
            names_discarded_count: 0,
            truncated: false
          }
        },
        observed_names: {
          count: 1,
          max_names: 10,
          sample: ["admin.secret.example.internal"],
          truncated: false
        }
      }
    });
    const redacted = JSON.stringify(redactActiveDnsOsintValue(report), null, 2);

    expect(report.isActiveDnsOsint).toBe(true);
    expect(report.coverageLevel).toBe("osint_best_effort");
    expect(report.observedNames.sample).toEqual(["[REDACTED_DNS_NAME]"]);
    expect(report.rawJson).not.toContain("secret.example.internal");
    expect(report.rawJson).not.toContain("admin.secret.example.internal");
    expect(redacted).not.toContain("secret.example.internal");
  });
});
