import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { ActiveDnsInventoryJobReport } from "./ActiveDnsInventoryJobReport";
import { buildActiveDnsInventoryReport, redactActiveDnsInventoryValue } from "./activeDnsInventoryReport";
import type { JobRecord } from "./types";

const baseJob = {
  id: "job-active-dns-1",
  audit_type: "active_dns_inventory",
  file_id: null,
  target_url: "secret.example.internal",
  target_domain: null,
  status: "completed",
  created_at: "2026-06-14T10:00:00Z",
  updated_at: "2026-06-14T10:01:00Z",
  source_file_deleted_at: null,
  error: null
} satisfies Omit<JobRecord, "result">;

const fixtureSecrets = [
  "secret.example.internal",
  "admin.secret.example.internal",
  "mail.secret.example.internal",
  "192.0.2.55",
  "2001:db8::55",
  "_spf.example.net",
  "ca.example.net",
  "token_should_never_render",
  "Authorization: Bearer token_should_never_render",
  "sessionid=secret-session-cookie",
  "raw-api-key-123456",
  "raw_dns_packet",
  "raw_dns_message",
  "raw_resolver_log",
  "raw_zone",
  "zone_file",
  "provider_api_token",
  "provider-zone-123"
];

afterEach(() => {
  cleanup();
});

describe("ActiveDnsInventoryJobReport", () => {
  it("renders grouped standard records, security indicators, and bounded subdomain summary", () => {
    render(
      <ActiveDnsInventoryJobReport
        job={{
          ...baseJob,
          target_url: "[REDACTED_DOMAIN]",
          result: {
            audit_type: "active_dns_inventory",
            capability: "active_dns_inventory",
            mode: "live_dns_inventory",
            profile: "dns_inventory_authorized",
            status: "best_effort_inventory",
            result_status: "best_effort_inventory",
            coverage_level: "best_effort_inventory",
            domain: "[REDACTED_DOMAIN]",
            record_types: ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"],
            records: {
              A: { count: 1, sample: [{ name: "[REDACTED_DOMAIN]", type: "A", value: "[REDACTED_DNS_VALUE]", ttl: 300 }] },
              MX: {
                count: 1,
                sample: [{ name: "[REDACTED_DOMAIN]", type: "MX", value: "[REDACTED_DNS_VALUE]", ttl: 300, priority: 10 }]
              },
              TXT: {
                count: 2,
                sample: [{ name: "[REDACTED_DOMAIN]", type: "TXT", value: "[REDACTED_DNS_VALUE]", ttl: 300 }]
              }
            },
            security_records: {
              spf: { checked: true, present: true, record_value: "[REDACTED_DNS_VALUE]" },
              dmarc: { checked: true, present: true, record_value: "[REDACTED_DNS_VALUE]" },
              caa: { checked: true, present: true, record_count: 1 },
              dkim: { checked: false, status: "not_attempted" }
            },
            subdomains: {
              enabled: true,
              strategy: "fixed_candidate_allowlist",
              candidates_checked: 12,
              query_record_types: ["A", "AAAA", "CNAME"],
              count: 2,
              sample: [
                { name: "[REDACTED_DNS_NAME]", record_types: ["A"], record_count: 1 },
                { name: "[REDACTED_DNS_NAME]", record_types: ["CNAME"], record_count: 1 }
              ],
              sample_truncated: false
            },
            zone_transfer: { attempted: false, status: "not_attempted" },
            provider_import: { attempted: false, status: "not_attempted" },
            execution: { dns_queries_sent: 45, subdomain_queries_sent: 36 },
            limits: { domain_value_persisted: false, dns_packets_persisted: false, resolver_logs_persisted: false },
            surface_caveats: ["Manual validation required."]
          }
        }}
      />
    );

    expect(screen.getByRole("heading", { name: "Active / DNS inventory report" })).toBeInTheDocument();
    expect(screen.getAllByText(/DNS configuration review indicator/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/best-effort DNS inventory/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Manual validation required/).length).toBeGreaterThan(0);
    expect(screen.getByText(/unless authorized AXFR is accepted by an authoritative server/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Grouped DNS Records" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Security Record Indicators" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Bounded Subdomain Summary" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Authorized Zone Transfer (AXFR)" })).toBeInTheDocument();
    expect(screen.getAllByText("[REDACTED_DOMAIN]").length).toBeGreaterThan(0);
    expect(screen.getAllByText("[REDACTED_DNS_VALUE]").length).toBeGreaterThan(0);
    expect(screen.getAllByText("[REDACTED_DNS_NAME]").length).toBeGreaterThan(0);
    expect(screen.getAllByText("present / review indicator").length).toBeGreaterThanOrEqual(3);
    expect(screen.getAllByText("not_attempted").length).toBeGreaterThan(0);
    expect(screen.getByText("fixed_candidate_allowlist")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Raw JSON (redacted)" })).toBeInTheDocument();
  });

  it("renders partial inventory and controlled errors without raw resolver details", () => {
    const { container } = render(
      <ActiveDnsInventoryJobReport
        job={{
          ...baseJob,
          status: "completed",
          result: {
            audit_type: "active_dns_inventory",
            capability: "active_dns_inventory",
            status: "partial_inventory",
            result_status: "partial_inventory",
            coverage_level: "partial_inventory",
            domain: "secret.example.internal",
            records: {
              A: { count: 1, sample: [{ name: "secret.example.internal", type: "A", value: "192.0.2.55", ttl: 300 }] }
            },
            security_records: {
              spf: { checked: true, present: true, record_value: "v=spf1 include:_spf.example.net -all" },
              dmarc: { checked: true, present: true, record_value: "v=DMARC1; p=reject" },
              caa: { checked: true, present: true, record_count: 1, raw_value: "issue ca.example.net" },
              dkim: { checked: false, status: "not_attempted" }
            },
            subdomains: {
              enabled: true,
              strategy: "fixed_candidate_allowlist",
              candidates_checked: 12,
              query_record_types: ["A", "AAAA", "CNAME"],
              count: 1,
              sample: [{ name: "admin.secret.example.internal", record_types: ["A"], record_count: 1 }]
            },
            raw_dns_packet: "raw_dns_packet token_should_never_render",
            raw_dns_message: "raw_dns_message secret.example.internal",
            raw_zone: "secret.example.internal 300 IN A 192.0.2.55",
            zone_file: "$ORIGIN secret.example.internal.",
            raw_resolver_log: "raw_resolver_log secret.example.internal 192.0.2.55",
            provider_api_token: "provider_api_token token_should_never_render",
            provider_zone_id: "provider-zone-123",
            credentials: { api_key: "raw-api-key-123456" },
            headers: { Authorization: "Bearer token_should_never_render" },
            cookies: "sessionid=secret-session-cookie",
            errors: [{ code: "dns_query_timeout", detail: "secret.example.internal token_should_never_render" }],
            legacy: {
              notes: "confirmed vulnerability exploitable target is safe all records found full DNS inventory public scanner"
            }
          },
          error: "secret.example.internal raw_resolver_log token_should_never_render"
        }}
      />
    );

    const rendered = container.textContent ?? "";
    expect(rendered).toContain("partial_inventory");
    expect(rendered).toContain("partial inventory review indicator");
    for (const secret of fixtureSecrets) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).toContain("[REDACTED");
    expect(rendered).not.toMatch(/confirmed\s+vulnerability/i);
    expect(rendered).not.toMatch(/exploitable/i);
    expect(rendered).not.toMatch(/target\s+is\s+safe/i);
    expect(rendered).not.toMatch(/all\s+records\s+found/i);
    expect(rendered).not.toMatch(/full\s+DNS\s+inventory/i);
    expect(rendered).not.toMatch(/public\s+scanner/i);
  });

  it("exposes a pure report helper with defensive Raw JSON redaction", () => {
    const report = buildActiveDnsInventoryReport({
      ...baseJob,
      result: {
        capability: "active_dns_inventory",
        status: "best_effort_inventory",
        coverage_level: "best_effort_inventory",
        domain: "secret.example.internal",
        records: {
          A: { count: 1, sample: [{ name: "secret.example.internal", type: "A", value: "192.0.2.55", ttl: 300 }] }
        },
        security_records: {
          spf: { checked: true, present: true, record_value: "v=spf1 include:_spf.example.net -all" },
          dmarc: { checked: true, present: false },
          caa: { checked: true, present: false, record_count: 0 },
          dkim: { checked: false, status: "not_attempted" }
        }
      }
    });
    const redacted = JSON.stringify(redactActiveDnsInventoryValue(report), null, 2);

    expect(report.isActiveDnsInventory).toBe(true);
    expect(report.coverageLevel).toBe("best_effort_inventory");
    expect(report.recordGroups[0]?.type).toBe("A");
    expect(report.rawJson).not.toContain("secret.example.internal");
    expect(report.rawJson).not.toContain("192.0.2.55");
    expect(report.rawJson).not.toContain("_spf.example.net");
    expect(redacted).not.toContain("secret.example.internal");
  });

  it("renders authorized AXFR completion as high-risk review indicator without raw zone material", () => {
    const { container } = render(
      <ActiveDnsInventoryJobReport
        job={{
          ...baseJob,
          target_url: "[REDACTED_DOMAIN]",
          result: {
            capability: "active_dns_inventory",
            status: "zone_transfer_complete",
            result_status: "zone_transfer_complete",
            coverage_level: "zone_transfer_complete",
            domain: "secret.example.internal",
            zone_transfer: {
              attempted: true,
              status: "zone_transfer_complete",
              nameservers_considered: 2,
              nameservers_attempted: 1,
              records_received_count: 40,
              records_retained_count: 25,
              truncated: true,
              reason_code: "terminal_soa_observed",
              interpretation: "zone transfer accepted by authoritative server"
            },
            provider_import: { attempted: false, status: "not_attempted" },
            records: {
              A: { count: 1, sample: [{ name: "secret.example.internal", type: "A", value: "192.0.2.55", ttl: 300 }] }
            },
            raw_nameserver: "ns1.secret.example.internal",
            authoritative_nameserver: "ns1.secret.example.internal",
            raw_zone: "secret.example.internal 300 IN A 192.0.2.55",
            zone_file: "$ORIGIN secret.example.internal.",
            raw_dns_packet: "raw_dns_packet secret.example.internal",
            surface_caveats: ["Manual validation required."]
          }
        }}
      />
    );

    const rendered = container.textContent ?? "";
    expect(rendered).toContain("zone_transfer_complete");
    expect(rendered).toContain("zone transfer accepted by authoritative server");
    expect(rendered).toContain("high-risk configuration review indicator");
    expect(rendered).toContain("Manual validation required");
    expect(rendered).toContain("Nameservers considered");
    expect(rendered).toContain("2");
    expect(rendered).toContain("Records retained");
    expect(rendered).toContain("25");
    for (const secret of ["secret.example.internal", "ns1.secret.example.internal", "192.0.2.55", "$ORIGIN"]) {
      expect(rendered).not.toContain(secret);
    }
    expect(rendered).not.toMatch(/confirmed\s+vulnerability/i);
    expect(rendered).not.toMatch(/exploitable/i);
    expect(rendered).not.toMatch(/target\s+is\s+safe/i);
    expect(rendered).not.toMatch(/all\s+records\s+found/i);
    expect(rendered).not.toMatch(/public\s+scanner/i);
  });

  it.each(["refused", "timed_out", "malformed_response", "record_limit_exceeded"] as const)(
    "renders AXFR %s as a controlled state",
    (status) => {
      const { container } = render(
        <ActiveDnsInventoryJobReport
          job={{
            ...baseJob,
            result: {
              capability: "active_dns_inventory",
              status: "partial_inventory",
              coverage_level: "partial_inventory",
              domain: "secret.example.internal",
              zone_transfer: {
                attempted: true,
                status,
                nameservers_considered: 1,
                nameservers_attempted: 1,
                records_received_count: 0,
                records_retained_count: 0,
                truncated: false
              }
            }
          }}
        />
      );

      const rendered = container.textContent ?? "";
      expect(rendered).toContain(status);
      expect(rendered).toContain("partial inventory");
      expect(rendered).not.toContain("secret.example.internal");
      expect(rendered).not.toMatch(/confirmed\s+vulnerability/i);
      expect(rendered).not.toMatch(/exploitable/i);
      expect(rendered).not.toMatch(/target\s+is\s+safe/i);
      expect(rendered).not.toMatch(/all\s+records\s+found/i);
      expect(rendered).not.toMatch(/public\s+scanner/i);
    }
  );
});
