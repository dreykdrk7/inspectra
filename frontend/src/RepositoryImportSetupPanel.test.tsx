import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { configureAuthContext } from "./api";
import { buildRepositoryImportCommand, RepositoryImportSetupPanel } from "./RepositoryImportSetupPanel";


afterEach(() => {
  cleanup();
  configureAuthContext({ csrfRequired: false, csrfToken: null });
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});


describe("RepositoryImportSetupPanel", () => {
  it("removes the one-time grant before showing a source-free command", async () => {
    const secret = `inspectra_ri_${"a".repeat(32)}_${"b".repeat(43)}`;
    const clipboard = { writeText: vi.fn(() => Promise.resolve()) };
    vi.stubGlobal("navigator", { clipboard });
    configureAuthContext({ csrfRequired: true, csrfToken: "csrf-value" });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
      id: "a".repeat(32),
      token: secret,
      created_at: "2026-09-11T12:00:00Z",
      expires_at: "2026-09-11T12:15:00Z",
    }), { status: 201, headers: { "content-type": "application/json" } }));

    render(<RepositoryImportSetupPanel requiresGrant canManage />);
    fireEvent.click(screen.getByRole("button", { name: "Create one-time import grant" }));
    expect(await screen.findByText(secret)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Copy once" }));
    await waitFor(() => expect(clipboard.writeText).toHaveBeenCalledWith(secret));

    fireEvent.click(screen.getByRole("button", { name: "I stored the grant" }));
    expect(screen.queryByText(secret)).not.toBeInTheDocument();
    const command = screen.getByLabelText("Inspectra local Git import command").textContent ?? "";
    expect(command).toContain("INSPECTRA_IMPORT_TOKEN");
    expect(command).toContain("--commit HEAD");
    expect(command).not.toContain(secret);
    expect(command).not.toContain("clone");
  });

  it("explains the administrator boundary and remains accessible", async () => {
    render(<RepositoryImportSetupPanel requiresGrant canManage={false} />);
    expect(screen.getByText(/administrator must issue/i)).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect((await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("accepts HTTPS or loopback only and shell-quotes no untrusted URL text", () => {
    expect(buildRepositoryImportCommand("https://inspectra.example/api", true)).toContain(
      "INSPECTRA_API_URL='https://inspectra.example/api'",
    );
    expect(buildRepositoryImportCommand("http://localhost:8000", false)).not.toContain("INSPECTRA_IMPORT_TOKEN");
    expect(buildRepositoryImportCommand("http://external.example", true)).toMatch(/Setup unavailable/);
    expect(buildRepositoryImportCommand("https://safe.example/\nINJECTED=true", true)).toMatch(/Setup unavailable/);
  });
});
