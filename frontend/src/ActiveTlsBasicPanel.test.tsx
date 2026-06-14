import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ActiveTlsBasicPanel, parseActiveTlsBasicPort } from "./ActiveTlsBasicPanel";

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" }
  });
}

describe("ActiveTlsBasicPanel", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("renders the bounded TLS form with safe copy and no dangerous fields", () => {
    render(<ActiveTlsBasicPanel />);

    const panel = screen.getByLabelText("Active / TLS basic");
    expect(screen.getByRole("heading", { name: "Active / TLS basic" })).toBeInTheDocument();
    expect(screen.getByText("Backend gated")).toBeInTheDocument();
    expect(screen.getByLabelText("Target")).toBeInTheDocument();
    expect(screen.getByLabelText("TLS port")).toBeInTheDocument();
    expect(panel.textContent).toContain("Local/private/self-hosted");
    expect(panel.textContent).toContain("Authorized target only");
    expect(panel.textContent).toContain("Bounded TLS handshake");
    expect(panel.textContent).toContain("one authorized TLS handshake review indicator");
    expect(panel.textContent).toContain("no HTTP request");
    expect(panel.textContent).toContain("no credential validation");
    expect(panel.textContent).toContain("no target expansion");
    expect(panel.textContent).toContain("Certificate expiry review indicator");
    expect(panel.textContent).toContain("Manual validation required");
    expect(panel.textContent).toContain("Target redacted");
    expect(panel.textContent).toContain("raw certificate PEM/DER omitted");
    expect(panel.textContent).toContain("443, 8443, or 9443");
    expect(panel.textContent ?? "").not.toMatch(/confirmed\s+vulnerability/i);
    expect(panel.textContent ?? "").not.toMatch(/exploitable/i);
    expect(panel.textContent ?? "").not.toMatch(/target\s+is\s+safe/i);
    expect(panel.textContent ?? "").not.toMatch(/full\s+scan/i);
    expect(panel.textContent ?? "").not.toMatch(/all\s+certs\s+found/i);
    expect(panel.textContent ?? "").not.toMatch(/public\s+scanner/i);
    expect(screen.getByRole("button", { name: /Create TLS review job/i })).toBeDisabled();
    expect(panel.querySelector('input[type="file"]')).toBeNull();
    expect(panel.querySelector("textarea")).toBeNull();
    expect(screen.queryByLabelText(/headers/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/cookies/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/tokens/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/credentials/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/client certificates/i)).not.toBeInTheDocument();
  });

  it("keeps submit disabled until target, allowed port, and all confirmations are present", () => {
    vi.stubGlobal("fetch", vi.fn());
    render(<ActiveTlsBasicPanel />);

    const submit = screen.getByRole("button", { name: /Create TLS review job/i });
    expect(submit).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "service.local" } });
    expect(submit).toBeDisabled();

    fireEvent.change(screen.getByLabelText("TLS port"), { target: { value: "443" } });
    expect(submit).toBeDisabled();

    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to test this target."));
    expect(submit).toBeDisabled();

    fireEvent.click(screen.getByLabelText("I confirm this is local, private, or self-hosted scope."));
    expect(submit).toBeDisabled();

    fireEvent.click(screen.getByLabelText("I understand this capability sends one bounded TLS handshake attempt if backend policy accepts it."));
    expect(submit).not.toBeDisabled();
  });

  it("blocks malformed and unsupported ports before calling the API", () => {
    vi.stubGlobal("fetch", vi.fn());
    render(<ActiveTlsBasicPanel />);

    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "service.local" } });
    fireEvent.change(screen.getByLabelText("TLS port"), { target: { value: "443,8443" } });
    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to test this target."));
    fireEvent.click(screen.getByLabelText("I confirm this is local, private, or self-hosted scope."));
    fireEvent.click(screen.getByLabelText("I understand this capability sends one bounded TLS handshake attempt if backend policy accepts it."));

    expect(screen.getByText("TLS port must be a single TCP port number.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Create TLS review job/i })).toBeDisabled();
    expect(globalThis.fetch).not.toHaveBeenCalled();

    cleanup();
    render(<ActiveTlsBasicPanel />);
    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "service.local" } });
    fireEvent.change(screen.getByLabelText("TLS port"), { target: { value: "80" } });
    expect(screen.getByText("TLS basic allows only ports 443, 8443, or 9443.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Create TLS review job/i })).toBeDisabled();
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("sends the exact backend contract body and renders a redacted JobRecord", async () => {
    const onJobCreated = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        if (String(input).endsWith("/active/network/tls-basic")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-active-tls-basic-04",
                audit_type: "active_tls_basic",
                file_id: null,
                target_url: "[REDACTED_TARGET]",
                target_domain: null,
                status: "completed",
                created_at: "2026-06-14T00:00:00Z",
                updated_at: "2026-06-14T00:00:00Z",
                source_file_deleted_at: null,
                result: {
                  audit_type: "active_tls_basic",
                  capability: "active_tls_basic",
                  mode: "live_tls_basic",
                  profile: "tls_handshake_summary",
                  status: "handshake_succeeded",
                  result_status: "handshake_succeeded",
                  target: "[REDACTED_TARGET]",
                  port: 443,
                  handshake: { status: "succeeded", protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384" },
                  certificate: {
                    available: true,
                    subject: "commonName=[REDACTED_TARGET]",
                    issuer: "commonName=Inspectra Test CA",
                    san_count: 1,
                    san_sample: [{ type: "DNS", value: "[REDACTED_SAN]" }],
                    not_before: "2026-01-01T00:00:00Z",
                    not_after: "2026-01-31T00:00:00Z",
                    days_until_expiry: 30
                  },
                  execution: { tls_handshake_attempted: true, network_requests_sent: 1, http_requests_sent: 0 }
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
    render(<ActiveTlsBasicPanel onJobCreated={onJobCreated} />);

    fireEvent.change(screen.getByLabelText("Target"), { target: { value: " service.local " } });
    fireEvent.change(screen.getByLabelText("TLS port"), { target: { value: "443" } });
    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to test this target."));
    fireEvent.click(screen.getByLabelText("I confirm this is local, private, or self-hosted scope."));
    fireEvent.click(screen.getByLabelText("I understand this capability sends one bounded TLS handshake attempt if backend policy accepts it."));
    fireEvent.click(screen.getByRole("button", { name: /Create TLS review job/i }));

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/active/network/tls-basic",
        expect.objectContaining({ method: "POST" })
      );
    });
    const request = vi.mocked(globalThis.fetch).mock.calls[0]?.[1] as RequestInit | undefined;
    expect(JSON.parse(String(request?.body))).toEqual({
      mode: "live_tls_basic",
      profile: "tls_handshake_summary",
      target: "service.local",
      port: 443,
      authorization_confirmed: true,
      local_private_scope_confirmed: true,
      live_traffic_confirmed: true
    });
    expect(await screen.findByText(/TLS review indicator job created/i)).toBeInTheDocument();
    expect(screen.getByText("job-active-tls-basic-04")).toBeInTheDocument();
    expect(screen.getByText("handshake_succeeded")).toBeInTheDocument();
    expect(screen.getByText("[REDACTED_TARGET]")).toBeInTheDocument();
    expect(screen.getByText("TLSv1.3 / TLS_AES_256_GCM_SHA384")).toBeInTheDocument();
    expect(screen.getByText("30 days. Manual validation required.")).toBeInTheDocument();
    expect(onJobCreated).toHaveBeenCalledWith(expect.objectContaining({ id: "job-active-tls-basic-04" }));
    expect(document.body.textContent ?? "").not.toContain("service.local");
  });

  it("renders disabled backend errors without reflecting target values", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        if (String(input).endsWith("/active/network/tls-basic")) {
          return Promise.resolve(jsonResponse({ detail: "active_tls_basic is disabled in this environment." }, 403));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );
    render(<ActiveTlsBasicPanel />);

    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "service.local" } });
    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to test this target."));
    fireEvent.click(screen.getByLabelText("I confirm this is local, private, or self-hosted scope."));
    fireEvent.click(screen.getByLabelText("I understand this capability sends one bounded TLS handshake attempt if backend policy accepts it."));
    fireEvent.click(screen.getByRole("button", { name: /Create TLS review job/i }));

    expect(await screen.findByText("Active / TLS basic is disabled or unavailable in this environment.")).toBeInTheDocument();
    expect(document.body.textContent ?? "").not.toContain("service.local");
  });

  it("parses the bounded TLS port set", () => {
    expect(parseActiveTlsBasicPort("443")).toEqual({ ok: true, port: 443, error: null });
    expect(parseActiveTlsBasicPort("8443")).toEqual({ ok: true, port: 8443, error: null });
    expect(parseActiveTlsBasicPort("9443")).toEqual({ ok: true, port: 9443, error: null });
    expect(parseActiveTlsBasicPort("80")).toEqual({
      ok: false,
      port: null,
      error: "TLS basic allows only ports 443, 8443, or 9443."
    });
  });
});
