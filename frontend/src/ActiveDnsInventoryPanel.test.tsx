import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ActiveDnsInventoryPanel, validateActiveDnsInventoryDomain } from "./ActiveDnsInventoryPanel";

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" }
  });
}

describe("ActiveDnsInventoryPanel", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("renders a bounded DNS inventory form without dangerous inputs", () => {
    render(<ActiveDnsInventoryPanel />);

    const panel = screen.getByLabelText("Active / DNS inventory");
    expect(screen.getByRole("heading", { name: "Active / DNS inventory" })).toBeInTheDocument();
    expect(screen.getByText("Backend gated")).toBeInTheDocument();
    expect(screen.getByLabelText("Domain")).toBeInTheDocument();
    expect(panel.textContent).toContain("Local/private/owned");
    expect(panel.textContent).toContain("Authorized domain only");
    expect(panel.textContent).toContain("Best-effort inventory");
    expect(panel.textContent).toContain("DNS configuration review indicator");
    expect(panel.textContent).toContain("best-effort or partial inventory");
    expect(panel.textContent).toContain("not complete-zone coverage");
    expect(panel.textContent).toContain("Zone transfer");
    expect(panel.textContent).toContain("Not available in this phase");
    expect(panel.textContent).toContain("Provider import");
    expect(panel.textContent).toContain("Domain redacted");
    for (const recordType of ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"]) {
      expect(screen.getByLabelText(recordType)).toBeChecked();
    }
    expect(screen.getByLabelText("Include SPF, DMARC, and CAA review indicators.")).toBeChecked();
    expect(screen.getByLabelText("Include bounded fixed-candidate subdomain summary.")).toBeChecked();
    expect(screen.getByLabelText("Zone transfer is not available and will not be attempted.")).toBeDisabled();
    expect(screen.getByRole("button", { name: /Create DNS inventory job/i })).toBeDisabled();
    expect(panel.querySelector('input[type="file"]')).toBeNull();
    expect(panel.querySelector("textarea")).toBeNull();
    expect(screen.queryByLabelText(/provider/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/headers/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/cookies/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/tokens/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/credentials/i)).not.toBeInTheDocument();
    expect(panel.textContent ?? "").not.toMatch(/confirmed\s+vulnerability/i);
    expect(panel.textContent ?? "").not.toMatch(/exploitable/i);
    expect(panel.textContent ?? "").not.toMatch(/target\s+is\s+safe/i);
    expect(panel.textContent ?? "").not.toMatch(/all\s+records\s+found/i);
    expect(panel.textContent ?? "").not.toMatch(/public\s+scanner/i);
  });

  it("keeps submit disabled until domain, record type, and confirmations are present", () => {
    vi.stubGlobal("fetch", vi.fn());
    render(<ActiveDnsInventoryPanel />);

    const submit = screen.getByRole("button", { name: /Create DNS inventory job/i });
    expect(submit).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Domain"), { target: { value: "example.internal" } });
    expect(submit).toBeDisabled();

    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to query this domain."));
    expect(submit).toBeDisabled();

    fireEvent.click(screen.getByLabelText("I confirm this domain is local, private, self-hosted, or owned scope."));
    expect(submit).toBeDisabled();

    fireEvent.click(screen.getByLabelText("I understand this capability sends bounded live DNS queries if backend policy accepts it."));
    expect(submit).not.toBeDisabled();

    for (const recordType of ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"]) {
      fireEvent.click(screen.getByLabelText(recordType));
    }
    expect(screen.getByText("Select at least one allowlisted DNS record type.")).toBeInTheDocument();
    expect(submit).toBeDisabled();
  });

  it("sends the exact backend contract body and renders a redacted JobRecord", async () => {
    const onJobCreated = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        if (String(input).endsWith("/active/network/dns-inventory")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-active-dns-inventory-05",
                audit_type: "active_dns_inventory",
                file_id: null,
                target_url: "[REDACTED_DOMAIN]",
                target_domain: null,
                status: "completed",
                created_at: "2026-06-14T00:00:00Z",
                updated_at: "2026-06-14T00:00:00Z",
                source_file_deleted_at: null,
                result: {
                  audit_type: "active_dns_inventory",
                  capability: "active_dns_inventory",
                  mode: "live_dns_inventory",
                  profile: "dns_inventory_authorized",
                  status: "best_effort_inventory",
                  result_status: "best_effort_inventory",
                  coverage_level: "best_effort_inventory",
                  domain: "[REDACTED_DOMAIN]",
                  records: {
                    A: { count: 1, sample: [{ name: "[REDACTED_DOMAIN]", type: "A", value: "[REDACTED_DNS_VALUE]", ttl: 300 }] },
                    MX: {
                      count: 1,
                      sample: [{ name: "[REDACTED_DOMAIN]", type: "MX", value: "[REDACTED_DNS_VALUE]", ttl: 300, priority: 10 }]
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
                    sample: [{ name: "[REDACTED_DNS_NAME]", record_types: ["A"], record_count: 1 }]
                  },
                  zone_transfer: { attempted: false, status: "not_attempted" },
                  provider_import: { attempted: false, status: "not_attempted" },
                  execution: { dns_queries_sent: 45, subdomain_queries_sent: 36 }
                },
                error: null
              },
              202
            )
          );
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );
    render(<ActiveDnsInventoryPanel onJobCreated={onJobCreated} />);

    fireEvent.change(screen.getByLabelText("Domain"), { target: { value: " Example.Internal " } });
    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to query this domain."));
    fireEvent.click(screen.getByLabelText("I confirm this domain is local, private, self-hosted, or owned scope."));
    fireEvent.click(screen.getByLabelText("I understand this capability sends bounded live DNS queries if backend policy accepts it."));
    fireEvent.click(screen.getByRole("button", { name: /Create DNS inventory job/i }));

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/active/network/dns-inventory",
        expect.objectContaining({ method: "POST" })
      );
    });
    const request = vi.mocked(globalThis.fetch).mock.calls[0]?.[1] as RequestInit | undefined;
    expect(JSON.parse(String(request?.body))).toEqual({
      mode: "live_dns_inventory",
      profile: "dns_inventory_authorized",
      domain: "example.internal",
      record_types: ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"],
      include_security_records: true,
      include_subdomain_discovery: true,
      attempt_zone_transfer: false,
      authorization_confirmed: true,
      local_private_or_owned_scope_confirmed: true,
      live_dns_queries_confirmed: true
    });
    expect(await screen.findByText(/DNS configuration review indicator job created/i)).toBeInTheDocument();
    expect(screen.getByText("job-active-dns-inventory-05")).toBeInTheDocument();
    expect(screen.getAllByText("best_effort_inventory").length).toBeGreaterThan(0);
    expect(screen.getByText("[REDACTED_DOMAIN]")).toBeInTheDocument();
    expect(screen.getByText("2 redacted DNS record indicators.")).toBeInTheDocument();
    expect(screen.getByText(/SPF present, DMARC present, CAA present/)).toBeInTheDocument();
    expect(screen.getByText("2 bounded redacted subdomain candidates observed.")).toBeInTheDocument();
    expect(onJobCreated).toHaveBeenCalledWith(expect.objectContaining({ id: "job-active-dns-inventory-05" }));
    expect(document.body.textContent ?? "").not.toContain("example.internal");
  });

  it("renders disabled backend errors without reflecting domain values", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        if (String(input).endsWith("/active/network/dns-inventory")) {
          return Promise.resolve(jsonResponse({ detail: "active_dns_inventory is disabled in this environment." }, 403));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );
    render(<ActiveDnsInventoryPanel />);

    fireEvent.change(screen.getByLabelText("Domain"), { target: { value: "secret.example.internal" } });
    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to query this domain."));
    fireEvent.click(screen.getByLabelText("I confirm this domain is local, private, self-hosted, or owned scope."));
    fireEvent.click(screen.getByLabelText("I understand this capability sends bounded live DNS queries if backend policy accepts it."));
    fireEvent.click(screen.getByRole("button", { name: /Create DNS inventory job/i }));

    expect(await screen.findByText("Active / DNS inventory is disabled or unavailable in this environment.")).toBeInTheDocument();
    expect(document.body.textContent ?? "").not.toContain("secret.example.internal");
  });

  it("validates a single explicit domain", () => {
    expect(validateActiveDnsInventoryDomain("Example.Internal")).toEqual({ ok: true, domain: "example.internal", error: null });
    expect(validateActiveDnsInventoryDomain("https://example.internal")).toMatchObject({ ok: false });
    expect(validateActiveDnsInventoryDomain("example.internal/path")).toMatchObject({ ok: false });
    expect(validateActiveDnsInventoryDomain("*.example.internal")).toMatchObject({ ok: false });
    expect(validateActiveDnsInventoryDomain("example.internal example.test")).toMatchObject({ ok: false });
    expect(validateActiveDnsInventoryDomain("192.0.2.10")).toMatchObject({ ok: false });
  });
});
