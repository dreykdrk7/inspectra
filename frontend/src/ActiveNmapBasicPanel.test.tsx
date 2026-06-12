import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ActiveNmapBasicPanel,
  getActiveNmapBasicAvailability,
  parseActiveNmapBasicPorts
} from "./ActiveNmapBasicPanel";

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" }
  });
}

describe("ActiveNmapBasicPanel", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("renders the bounded form with safe copy and no dangerous fields", () => {
    render(<ActiveNmapBasicPanel health={null} />);

    const panel = screen.getByLabelText("Active / Nmap basic");
    expect(screen.getByRole("heading", { name: "Active / Nmap basic" })).toBeInTheDocument();
    expect(screen.getByText("Disabled")).toBeInTheDocument();
    expect(screen.getByLabelText("Target")).toBeInTheDocument();
    expect(screen.getByLabelText("TCP ports")).toBeInTheDocument();
    expect(panel.textContent).toContain("Local/private/self-hosted systems only");
    expect(panel.textContent).toContain("targets must be explicitly authorized");
    expect(panel.textContent).toContain("This prepares a bounded authorized Nmap basic request");
    expect(panel.textContent).toContain("Execution may still be disabled or not connected");
    expect(panel.textContent).toContain("live traffic");
    expect(panel.textContent).toContain("Observed TCP exposure / Review indicator");
    expect(panel.textContent).toContain("Manual validation required");
    expect(panel.textContent).toContain("No confirmed vulnerability is asserted");
    expect(panel.textContent).toContain("One explicit target");
    expect(panel.textContent).toContain("up to 32 TCP ports");
    expect(panel.textContent).toContain("timeout bounded");
    expect(panel.textContent).toContain("output bounded");
    expect(panel.textContent).toContain("No raw flags");
    expect(panel.textContent).toContain("no NSE/scripts");
    expect(panel.textContent).toContain("no brute force");
    expect(panel.textContent).toContain("no credential validation");
    expect(panel.textContent).toContain("no crawling");
    expect(panel.textContent).toContain("no DNS expansion");
    expect(panel.textContent).not.toContain("full network scan");
    expect(panel.textContent).not.toContain("scan the internet");
    expect(panel.textContent).not.toContain("find assets");
    expect(panel.textContent).not.toContain("target is safe");
    expect(panel.textContent).not.toContain("exploitable");
    expect(panel.textContent).not.toContain("all ports found");
    expect(screen.getByRole("button", { name: /Prepare bounded request/i })).toBeDisabled();
    expect(panel.querySelector('input[type="file"]')).toBeNull();
    expect(panel.querySelector("textarea")).toBeNull();
    expect(screen.queryByLabelText(/raw flags/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/credentials/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/cookies/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/headers/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/tokens/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/target file/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/custom profile/i)).not.toBeInTheDocument();
  });

  it("renders the prepared state when future backend availability is advertised", () => {
    render(
      <ActiveNmapBasicPanel
        health={{
          status: "ok",
          service: "inspectra-backend",
          active_nmap_basic: { enabled: true }
        }}
      />
    );

    const panel = screen.getByLabelText("Active / Nmap basic");
    expect(screen.getByText("Prepared / available")).toBeInTheDocument();
    expect(panel.textContent).toContain("backend remains the source of truth");
    expect(screen.getByRole("button", { name: /Prepare bounded request/i })).toBeDisabled();
  });

  it("keeps submit disabled until target, ports, and all confirmations are present", () => {
    vi.stubGlobal("fetch", vi.fn());
    render(<ActiveNmapBasicPanel health={null} />);

    const submit = screen.getByRole("button", { name: /Prepare bounded request/i });
    expect(submit).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "router.local" } });
    expect(submit).toBeDisabled();

    fireEvent.change(screen.getByLabelText("TCP ports"), { target: { value: "22, 80, 443" } });
    expect(submit).toBeDisabled();

    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to test this target."));
    expect(submit).toBeDisabled();

    fireEvent.click(screen.getByLabelText("I confirm this is local, private, or self-hosted scope."));
    expect(submit).toBeDisabled();

    fireEvent.click(screen.getByLabelText("I understand this prepares live traffic and may be logged by the target."));
    expect(submit).not.toBeDisabled();
  });

  it("blocks non-numeric ports and excessive port counts before calling the API", () => {
    vi.stubGlobal("fetch", vi.fn());
    render(<ActiveNmapBasicPanel health={null} />);

    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "router.local" } });
    fireEvent.change(screen.getByLabelText("TCP ports"), { target: { value: "22, ssh" } });
    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to test this target."));
    fireEvent.click(screen.getByLabelText("I confirm this is local, private, or self-hosted scope."));
    fireEvent.click(screen.getByLabelText("I understand this prepares live traffic and may be logged by the target."));

    expect(screen.getByText("Ports must be TCP port numbers separated by commas or spaces.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Prepare bounded request/i })).toBeDisabled();
    expect(globalThis.fetch).not.toHaveBeenCalled();

    cleanup();
    render(<ActiveNmapBasicPanel health={null} />);
    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "router.local" } });
    fireEvent.change(screen.getByLabelText("TCP ports"), {
      target: { value: Array.from({ length: 33 }, (_, index) => String(index + 1)).join(",") }
    });
    expect(screen.getByText("Use 32 or fewer TCP ports.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Prepare bounded request/i })).toBeDisabled();
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("sends the exact backend contract body and renders not-executed as expected", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        if (String(input).endsWith("/active/network/nmap-basic")) {
          return Promise.resolve(
            jsonResponse(
              {
                audit_type: "active_nmap_basic",
                status: "not_implemented",
                execution_state: "not_executed",
                job_created: false
              },
              501
            )
          );
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );
    render(<ActiveNmapBasicPanel health={{ status: "ok", service: "inspectra-backend", active_nmap_basic: { enabled: true } }} />);

    fireEvent.change(screen.getByLabelText("Target"), { target: { value: " router.local " } });
    fireEvent.change(screen.getByLabelText("TCP ports"), { target: { value: "22, 80, 443" } });
    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to test this target."));
    fireEvent.click(screen.getByLabelText("I confirm this is local, private, or self-hosted scope."));
    fireEvent.click(screen.getByLabelText("I understand this prepares live traffic and may be logged by the target."));
    fireEvent.click(screen.getByRole("button", { name: /Prepare bounded request/i }));

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledWith(
        "http://localhost:8000/active/network/nmap-basic",
        expect.objectContaining({ method: "POST" })
      );
    });
    const request = vi.mocked(globalThis.fetch).mock.calls[0]?.[1] as RequestInit | undefined;
    expect(JSON.parse(String(request?.body))).toEqual({
      mode: "live_nmap_basic",
      profile: "tcp_connect_small",
      targets: ["router.local"],
      ports: [22, 80, 443],
      authorization_confirmed: true,
      local_private_scope_confirmed: true,
      live_traffic_confirmed: true
    });
    expect(await screen.findByText(/Execution is not implemented and was not executed/i)).toBeInTheDocument();
    expect(screen.queryByText(/completed scan/i)).not.toBeInTheDocument();
  });

  it("renders a created no-live job as controlled and not as a completed live scan", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        if (String(input).endsWith("/active/network/nmap-basic")) {
          return Promise.resolve(
            jsonResponse(
              {
                id: "job-active-nmap-basic",
                audit_type: "active_nmap_basic",
                file_id: null,
                target_url: "[REDACTED_TARGET]",
                status: "completed",
                created_at: "2026-06-12T00:00:00Z",
                updated_at: "2026-06-12T00:00:00Z",
                source_file_deleted_at: null,
                result: {
                  audit_type: "active_nmap_basic",
                  capability: "active_nmap_basic",
                  status: "not_executed",
                  execution_state: "not_executed",
                  adapter: "test_double_no_live",
                  execution_attempted: false
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
    render(<ActiveNmapBasicPanel health={{ status: "ok", service: "inspectra-backend", active_nmap_basic: { enabled: true } }} />);

    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "router.local" } });
    fireEvent.change(screen.getByLabelText("TCP ports"), { target: { value: "22" } });
    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to test this target."));
    fireEvent.click(screen.getByLabelText("I confirm this is local, private, or self-hosted scope."));
    fireEvent.click(screen.getByLabelText("I understand this prepares live traffic and may be logged by the target."));
    fireEvent.click(screen.getByRole("button", { name: /Prepare bounded request/i }));

    expect(await screen.findByText(/controlled no-live test-double job/i)).toBeInTheDocument();
    expect(screen.getByText(/Nmap was not executed/i)).toBeInTheDocument();
    expect(screen.queryByText(/completed live scan/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/completed scan/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Nmap executed/i)).not.toBeInTheDocument();
  });

  it("renders disabled backend errors generically without reflecting target details", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve(
          jsonResponse({ detail: "active_nmap_basic disabled for router.local token_should_never_render" }, 403)
        )
      )
    );
    render(<ActiveNmapBasicPanel health={null} />);

    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "router.local" } });
    fireEvent.change(screen.getByLabelText("TCP ports"), { target: { value: "22" } });
    fireEvent.click(screen.getByLabelText("I confirm I own or am authorized to test this target."));
    fireEvent.click(screen.getByLabelText("I confirm this is local, private, or self-hosted scope."));
    fireEvent.click(screen.getByLabelText("I understand this prepares live traffic and may be logged by the target."));
    fireEvent.click(screen.getByRole("button", { name: /Prepare bounded request/i }));

    expect(await screen.findByText("Active / Nmap basic is disabled or unavailable in this environment.")).toBeInTheDocument();
    expect(screen.queryByText(/token_should_never_render/)).not.toBeInTheDocument();
  });

  it("treats missing or disabled capability metadata as unavailable", () => {
    expect(getActiveNmapBasicAvailability(null)).toBe("disabled");
    expect(getActiveNmapBasicAvailability({ status: "ok", service: "inspectra-backend" })).toBe("disabled");
    expect(
      getActiveNmapBasicAvailability({
        status: "ok",
        service: "inspectra-backend",
        active_nmap_basic: { enabled: false, status: "disabled" }
      })
    ).toBe("disabled");
    expect(
      getActiveNmapBasicAvailability({
        status: "ok",
        service: "inspectra-backend",
        active_nmap_basic: { status: "available" }
      })
    ).toBe("available");
  });

  it("parses bounded unique TCP ports", () => {
    expect(parseActiveNmapBasicPorts("22, 80 443,443")).toEqual({ ok: true, ports: [22, 80, 443], error: null });
    expect(parseActiveNmapBasicPorts("")).toEqual({ ok: false, ports: [], error: "Enter at least one TCP port." });
    expect(parseActiveNmapBasicPorts("22-25").ok).toBe(false);
    expect(parseActiveNmapBasicPorts("0").ok).toBe(false);
    expect(parseActiveNmapBasicPorts("65536").ok).toBe(false);
  });
});
