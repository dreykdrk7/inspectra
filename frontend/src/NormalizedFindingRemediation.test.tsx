import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { FindingRemediationActions, safePublicReferenceUrl } from "./NormalizedFindingRemediation";
import type { NormalizedFindingReference } from "./types";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  Reflect.deleteProperty(navigator, "clipboard");
});

describe("FindingRemediationActions", () => {
  it("exposes a keyboard-focusable local correction path and only a canonical public reference", () => {
    const onRequestNewSnapshot = vi.fn();
    render(
      <FindingRemediationActions
        recommendation="Set DEBUG to false in the reviewed production configuration."
        references={[
          { type: "ghsa", id: "GHSA-abcd-1234-efgh", url: "https://github.com/advisories/GHSA-abcd-1234-efgh" },
          { type: "cve", id: "CVE-2026-0001", url: "https://attacker.example/CVE-2026-0001" },
        ]}
        onRequestNewSnapshot={onRequestNewSnapshot}
      />
    );

    expect(screen.getByText(/not an exploitation verdict/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /GHSA: GHSA-abcd-1234-efgh/ })).toHaveAttribute(
      "href",
      "https://github.com/advisories/GHSA-abcd-1234-efgh"
    );
    expect(screen.queryByText(/CVE: CVE-2026-0001/)).not.toBeInTheDocument();

    const snapshotButton = screen.getByRole("button", { name: "Review a new snapshot" });
    snapshotButton.focus();
    expect(snapshotButton).toHaveFocus();
    fireEvent.click(snapshotButton);
    expect(onRequestNewSnapshot).toHaveBeenCalledOnce();
  });

  it("copies only the recommendation, never retained finding context", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    const recommendation = "Upgrade the reviewed component and validate compatibility locally.";

    render(<FindingRemediationActions recommendation={recommendation} references={[]} onRequestNewSnapshot={vi.fn()} />);

    fireEvent.click(screen.getByRole("button", { name: "Copy recommendation" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(recommendation));
    expect(writeText.mock.calls[0]?.[0]).not.toContain("[REDACTED]");
    expect(writeText.mock.calls[0]?.[0]).not.toContain("config/settings.py");
    expect(screen.getByRole("button", { name: "Recommendation copied" })).toBeInTheDocument();
  });

  it("does not create an action when no recommendation or validated reference is retained", () => {
    render(
      <FindingRemediationActions
        recommendation=""
        references={[{ type: "owasp", id: "A01:2021", url: "http://owasp.org/Top10" }]}
        onRequestNewSnapshot={vi.fn()}
      />
    );

    expect(screen.getByText(/No retained correction guidance/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Copy recommendation" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Review a new snapshot" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
});

describe("safePublicReferenceUrl", () => {
  it("requires a canonical identifier, origin, path and query shape", () => {
    const cases: Array<[NormalizedFindingReference, string | null]> = [
      [{ type: "cve", id: "CVE-2026-0001", url: "https://nvd.nist.gov/vuln/detail/CVE-2026-0001" }, "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"],
      [{ type: "cve", id: "CVE-2026-0001", url: "https://www.cve.org/CVERecord?id=CVE-2026-0001" }, "https://www.cve.org/CVERecord?id=CVE-2026-0001"],
      [{ type: "cve", id: "CVE-2026-0001", url: "https://www.cve.org/CVERecord" }, null],
      [{ type: "ghsa", id: "GHSA-abcd-1234-efgh", url: "https://github.com/advisories/GHSA-abcd-1234-efgh?redirect=1" }, null],
      [{ type: "owasp", id: "A01:2021", url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/" }, "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
    ];

    for (const [reference, expected] of cases) {
      expect(safePublicReferenceUrl(reference)).toBe(expected);
    }
  });
});
