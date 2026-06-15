import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ActiveDnsOsintPanel, parseActiveDnsOsintMaxNames, validateActiveDnsOsintDomain } from "./ActiveDnsOsintPanel";

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" }
  });
}

describe("ActiveDnsOsintPanel", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("renders a separate DNS OSINT form without unsupported source inputs", () => {
    render(<ActiveDnsOsintPanel />);

    const panel = screen.getByLabelText("Active / DNS OSINT");
    expect(screen.getByRole("heading", { name: "Active / DNS OSINT" })).toBeInTheDocument();
    expect(screen.getByText("Backend gated")).toBeInTheDocument();
    expect(screen.getByText("Certificate Transparency bounded")).toBeInTheDocument();
    expect(screen.getAllByText("Passive DNS unavailable").length).toBeGreaterThan(0);
    expect(screen.getByText("Best-effort review")).toBeInTheDocument();
    expect(screen.getByLabelText("Domain")).toBeInTheDocument();
    expect(screen.getByLabelText("Max observed names")).toBeInTheDocument();
    expect(screen.getByText("ct_subdomain_discovery_bounded")).toBeInTheDocument();
    expect(panel.textContent).toContain("DNS OSINT review indicator");
    expect(panel.textContent).toContain("Manual validation required");
    expect(panel.textContent).toMatch(/observed names are not queued for scanning/i);
    expect(screen.getByRole("button", { name: /Create DNS OSINT job/i })).toBeDisabled();
    expect(panel.querySelector('input[type="file"]')).toBeNull();
    expect(panel.querySelector("textarea")).toBeNull();
    expect(screen.queryByLabelText(/provider/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/passive dns source/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/headers/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/cookies/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/tokens/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/credentials/i)).not.toBeInTheDocument();
    const rendered = panel.textContent ?? "";
    expect(rendered).not.toMatch(new RegExp(["all", "\\s+", "subdomains", "\\s+", "found"].join(""), "i"));
    expect(rendered).not.toMatch(new RegExp(["complete", "\\s+", "coverage"].join(""), "i"));
    expect(rendered).not.toMatch(new RegExp(["confirmed", "\\s+", "vulnerability"].join(""), "i"));
    expect(rendered).not.toMatch(new RegExp(["exploit", "able"].join(""), "i"));
    expect(rendered).not.toMatch(new RegExp(["target", "\\s+", "is", "\\s+", "safe"].join(""), "i"));
    expect(rendered).not.toMatch(new RegExp(["public", "\\s+", "scanner"].join(""), "i"));
  });

  it("requires a domain, bounded max_names, and all confirmations", () => {
    vi.stubGlobal("fetch", vi.fn());
    render(<ActiveDnsOsintPanel />);

    const submit = screen.getByRole("button", { name: /Create DNS OSINT job/i });
    expect(submit).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Domain"), { target: { value: "example.internal" } });
    expect(submit).toBeDisabled();

    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to query this domain."));
    expect(submit).toBeDisabled();

    fireEvent.click(screen.getByLabelText("I confirm this is my domain or an explicitly authorized domain."));
    expect(submit).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Max observed names"), { target: { value: "101" } });
    fireEvent.click(screen.getByLabelText("I understand this may send bounded public OSINT queries if backend policy accepts it."));
    expect(screen.getByText("Max observed names must be between 1 and 100.")).toBeInTheDocument();
    expect(submit).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Max observed names"), { target: { value: "25" } });
    expect(submit).not.toBeDisabled();
  });

  it("sends the exact backend contract and renders a redacted JobRecord", async () => {
    const onJobCreated = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        if (String(input).endsWith("/active/network/dns-osint")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-active-dns-osint-07",
                audit_type: "active_dns_osint",
                file_id: null,
                target_url: "[REDACTED_DOMAIN]",
                target_domain: null,
                status: "completed",
                created_at: "2026-06-15T00:00:00Z",
                updated_at: "2026-06-15T00:00:00Z",
                source_file_deleted_at: null,
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
                      names_observed_count: 5,
                      names_retained_count: 3,
                      names_discarded_count: 2,
                      truncated: false
                    },
                    passive_dns: { attempted: false, status: "not_attempted" }
                  },
                  observed_names: {
                    count: 3,
                    max_names: 25,
                    sample: ["[REDACTED_DNS_NAME]", "[REDACTED_DNS_NAME]"],
                    truncated: false
                  },
                  summary: {
                    manual_validation_required: true,
                    result_interpretation: "DNS OSINT review indicator",
                    coverage_level: "osint_best_effort",
                    observed_names_count: 3,
                    ct_source_status: "completed",
                    passive_dns_status: "not_attempted"
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
                  surface_caveats: ["Manual validation required."]
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
    render(<ActiveDnsOsintPanel onJobCreated={onJobCreated} />);

    fireEvent.change(screen.getByLabelText("Domain"), { target: { value: " Example.Internal " } });
    fireEvent.change(screen.getByLabelText("Max observed names"), { target: { value: "25" } });
    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to query this domain."));
    fireEvent.click(screen.getByLabelText("I confirm this is my domain or an explicitly authorized domain."));
    fireEvent.click(screen.getByLabelText("I understand this may send bounded public OSINT queries if backend policy accepts it."));
    fireEvent.click(screen.getByRole("button", { name: /Create DNS OSINT job/i }));

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/active/network/dns-osint",
        expect.objectContaining({ method: "POST" })
      );
    });
    const request = vi.mocked(globalThis.fetch).mock.calls[0]?.[1] as RequestInit | undefined;
    expect(JSON.parse(String(request?.body))).toEqual({
      mode: "live_dns_osint",
      profile: "ct_subdomain_discovery_bounded",
      domain: "example.internal",
      include_certificate_transparency: true,
      include_passive_dns: false,
      max_names: 25,
      authorization_confirmed: true,
      owned_or_authorized_domain_confirmed: true,
      public_osint_queries_confirmed: true
    });
    expect(await screen.findByText(/DNS OSINT review indicator job created/i)).toBeInTheDocument();
    expect(screen.getByText("job-active-dns-osint-07")).toBeInTheDocument();
    expect(screen.getAllByText("osint_best_effort").length).toBeGreaterThan(0);
    expect(screen.getByText("[REDACTED_DOMAIN]")).toBeInTheDocument();
    expect(screen.getByText(/retained 3 of 5 observed names/i)).toBeInTheDocument();
    expect(screen.getByText(/3 redacted public-source observed-name indicators/i)).toBeInTheDocument();
    expect(onJobCreated).toHaveBeenCalledWith(expect.objectContaining({ id: "job-active-dns-osint-07" }));
    expect(document.body.textContent ?? "").not.toContain("example.internal");
  });

  it("shows unavailable state without reflecting target details", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        if (String(input).endsWith("/active/network/dns-osint")) {
          return Promise.resolve(jsonResponse({ detail: "example.internal should not render" }, 403));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );
    render(<ActiveDnsOsintPanel />);

    fireEvent.change(screen.getByLabelText("Domain"), { target: { value: "example.internal" } });
    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to query this domain."));
    fireEvent.click(screen.getByLabelText("I confirm this is my domain or an explicitly authorized domain."));
    fireEvent.click(screen.getByLabelText("I understand this may send bounded public OSINT queries if backend policy accepts it."));
    fireEvent.click(screen.getByRole("button", { name: /Create DNS OSINT job/i }));

    expect(await screen.findByText("Active / DNS OSINT is disabled or unavailable in this environment.")).toBeInTheDocument();
    expect(document.body.textContent ?? "").not.toContain("example.internal should not render");
  });

  it("validates domain and max_names bounds without broad target shapes", () => {
    expect(validateActiveDnsOsintDomain("example.internal")).toEqual({ ok: true, domain: "example.internal", error: null });
    for (const value of ["https://example.internal", "*.example.internal", "example.internal,other.internal", "192.0.2.1", "example"]) {
      expect(validateActiveDnsOsintDomain(value).ok).toBe(false);
    }
    expect(parseActiveDnsOsintMaxNames("1")).toEqual({ ok: true, maxNames: 1, error: null });
    expect(parseActiveDnsOsintMaxNames("100")).toEqual({ ok: true, maxNames: 100, error: null });
    expect(parseActiveDnsOsintMaxNames("0").ok).toBe(false);
    expect(parseActiveDnsOsintMaxNames("101").ok).toBe(false);
    expect(parseActiveDnsOsintMaxNames("10,20").ok).toBe(false);
  });
});
