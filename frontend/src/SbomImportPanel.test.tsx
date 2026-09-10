import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { configureAuthContext } from "./api";
import { SbomImportPanel } from "./SbomImportPanel";


afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("SbomImportPanel", () => {
  it("requires authorization and keeps public identity attestation explicit", async () => {
    const onImported = vi.fn();
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation((input) => Promise.resolve(new Response(JSON.stringify(
      String(input).endsWith("/preflight") ? {
        contract_version: "2026-09-08.1",
        status: "ready",
        preflight_token: "p".repeat(43),
        expires_at: "2026-09-08T10:05:00Z",
        format: "cyclonedx",
        spec_version: "1.6",
        input_components: 3,
        retained_components: 2,
        rejected_or_ambiguous_components: 1,
        potentially_correlatable_components: 2,
        component_limit_reached: false,
        relationship_graph_truncated: false,
      } : {
        project: { id: "a".repeat(32), name: "SBOM project" },
        job: { id: "b".repeat(32), status: "completed" },
      }
    ), { status: String(input).endsWith("/preflight") ? 200 : 201, headers: { "content-type": "application/json" } })));
    configureAuthContext({ csrfRequired: true, csrfToken: "csrf-token" });
    render(<SbomImportPanel onImported={onImported} />);

    fireEvent.change(screen.getByLabelText("Project name"), { target: { value: "SBOM project" } });
    const file = new File(['{"bomFormat":"CycloneDX"}'], "private-name.json", { type: "application/json" });
    fireEvent.change(screen.getByLabelText("SBOM JSON"), { target: { files: [file] } });
    expect(screen.getByRole("button", { name: "Import preflighted SBOM" })).toBeDisabled();
    expect(screen.queryByLabelText(/I am authorized/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Review SBOM safely" }));
    expect(await screen.findByRole("heading", { name: "Preflight ready" })).toBeInTheDocument();
    expect(screen.getByText(/2 retained of 3 observed/)).toBeInTheDocument();
    expect(screen.getByText(/1 entry is rejected or ambiguous/)).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText("I am authorized to import and analyze this exact preflighted SBOM."));
    expect(screen.getByText(/supported npm, PyPI, or Maven identities/)).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText(/I attest that retained supported npm, PyPI, and Maven purls are public identities/));
    fireEvent.submit(screen.getByRole("button", { name: "Import preflighted SBOM" }).closest("form")!);

    await waitFor(() => expect(onImported).toHaveBeenCalledOnce());
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const preflightRequest = fetchMock.mock.calls[0][1];
    const preflightBody = preflightRequest?.body as FormData;
    expect((preflightBody.get("file") as File).name).toBe("sbom.json");
    expect(preflightBody.has("authorization_confirmed")).toBe(false);
    const request = fetchMock.mock.calls[1][1];
    const body = request?.body as FormData;
    expect(body.get("authorization_confirmed")).toBe("true");
    expect(body.get("public_registry_identities_confirmed")).toBe("true");
    expect(body.get("preflight_token")).toBe("p".repeat(43));
    expect((body.get("file") as File).name).toBe("sbom.json");
    expect(new Headers(request?.headers).get("X-CSRF-Token")).toBe("csrf-token");
  });

  it("invalidates the preflight when the selected bytes change and remains accessible", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      contract_version: "2026-09-08.1",
      status: "ready",
      preflight_token: "p".repeat(43),
      expires_at: "2026-09-08T10:05:00Z",
      format: "spdx",
      spec_version: "SPDX-2.3",
      input_components: 1,
      retained_components: 1,
      rejected_or_ambiguous_components: 0,
      potentially_correlatable_components: 1,
      component_limit_reached: true,
      relationship_graph_truncated: true,
    }), { status: 200, headers: { "content-type": "application/json" } }));
    render(<SbomImportPanel onImported={() => undefined} />);
    const input = screen.getByLabelText("SBOM JSON");
    fireEvent.change(input, { target: { files: [new File(["first"], "first.json")] } });
    fireEvent.click(screen.getByRole("button", { name: "Review SBOM safely" }));
    expect(await screen.findByText(/Coverage reached a defensive limit/)).toBeInTheDocument();
    expect((await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);

    fireEvent.change(input, { target: { files: [new File(["second"], "second.json")] } });
    expect(screen.queryByRole("heading", { name: "Preflight ready" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/I am authorized/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Review SBOM safely" })).toBeEnabled();
  });
});
