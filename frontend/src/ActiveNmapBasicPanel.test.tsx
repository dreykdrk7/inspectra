import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { ActiveNmapBasicPanel, getActiveNmapBasicAvailability } from "./ActiveNmapBasicPanel";

describe("ActiveNmapBasicPanel", () => {
  afterEach(() => {
    cleanup();
  });

  it("renders the disabled informational shell with safe copy and no functional submit", () => {
    render(<ActiveNmapBasicPanel health={null} />);

    const panel = screen.getByLabelText("Active / Nmap basic");
    expect(screen.getByRole("heading", { name: "Active / Nmap basic" })).toBeInTheDocument();
    expect(screen.getByText("Disabled")).toBeInTheDocument();
    expect(panel.textContent).toContain("Local/private/self-hosted systems only");
    expect(panel.textContent).toContain("targets must be explicitly authorized");
    expect(panel.textContent).toContain("live TCP traffic");
    expect(panel.textContent).toContain("Observed TCP exposure / Review indicator");
    expect(panel.textContent).toContain("Manual validation required");
    expect(panel.textContent).toContain("no confirmed vulnerability asserted");
    expect(panel.textContent).toContain("Target count bounded");
    expect(panel.textContent).toContain("port count bounded");
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
    expect(panel.textContent).not.toContain("target is safe");
    expect(panel.textContent).not.toContain("exploitable");
    expect(screen.getByRole("button", { name: "Prepared only" })).toBeDisabled();
    expect(panel.querySelector("input")).toBeNull();
    expect(panel.querySelector("textarea")).toBeNull();
    expect(panel.querySelector("form")).toBeNull();
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
    expect(panel.textContent).toContain("informational only");
    expect(panel.textContent).toContain("cannot submit live traffic");
    expect(screen.getByRole("button", { name: "Prepared only" })).toBeDisabled();
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
});
