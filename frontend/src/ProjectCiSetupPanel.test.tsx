import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { configureAuthContext } from "./api";
import { buildCiSnippet, ProjectCiSetupPanel } from "./ProjectCiSetupPanel";
import type { ProjectSummary } from "./types";

const projectId = "a".repeat(32);
const project = {
  project: { id: projectId, name: "CI target", baseline_analysis_id: null, analysis_count: 0 },
  latest_job: null,
} as ProjectSummary;

function response(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }));
}

afterEach(() => {
  cleanup();
  configureAuthContext({ csrfRequired: false, csrfToken: null });
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("ProjectCiSetupPanel", () => {
  it("removes the one-time token before rendering a secret-free GitHub snippet and probes retained metadata", async () => {
    const secret = `inspectra_at_${"b".repeat(32)}_${"c".repeat(43)}`;
    const clipboard = { writeText: vi.fn(() => Promise.resolve()) };
    vi.stubGlobal("navigator", { clipboard });
    configureAuthContext({ csrfRequired: true, csrfToken: "csrf-value" });
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
      const url = String(input);
      if (url.endsWith("/automation/tokens") && init?.method === "POST") {
        return response({
          id: "b".repeat(32), name: "GitHub CI", project_id: projectId,
          scopes: ["project:read", "project:scan", "report:read"],
          created_at: "2026-09-07T12:00:00Z", expires_at: "2026-09-08T12:00:00Z",
          revoked_at: null, last_used_at: null, token: secret,
        }, 201);
      }
      if (url.endsWith(`/automation/tokens/${"b".repeat(32)}`)) {
        return response({
          status: "ready", project_id: projectId,
          scopes: ["project:read", "project:scan", "report:read"],
          scopes_complete: true, expires_at: "2026-09-08T12:00:00Z",
        });
      }
      return response({ detail: "unexpected" }, 500);
    });

    render(<ProjectCiSetupPanel project={project} canManage />);
    fireEvent.click(screen.getByRole("button", { name: "Create project credential" }));
    expect(await screen.findByText(secret)).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent("secrets.INSPECTRA_TOKEN");

    fireEvent.click(screen.getByRole("button", { name: "I stored the secret" }));
    expect(screen.queryByText(secret)).not.toBeInTheDocument();
    const snippet = screen.getByLabelText("github Inspectra pipeline snippet").textContent ?? "";
    expect(snippet).toContain("secrets.INSPECTRA_TOKEN");
    expect(snippet).toContain(`--project-id ${projectId}`);
    expect(snippet).not.toContain(secret);

    fireEvent.click(screen.getByRole("button", { name: "Copy snippet" }));
    await waitFor(() => expect(clipboard.writeText).toHaveBeenCalledWith(snippet));
    fireEvent.click(screen.getByRole("button", { name: "Verify setup" }));
    expect(await screen.findByText(/minimum scopes are ready/)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining(`/automation/tokens/${"b".repeat(32)}`),
      expect.objectContaining({ credentials: "include" }),
    );
  });

  it("quotes the generic contract and rejects values that could inject pipeline syntax", () => {
    const safe = buildCiSnippet("generic", "https://inspectra.example/api", projectId, "strict");
    expect(safe).toContain("INSPECTRA_API_URL='https://inspectra.example/api'");
    expect(safe).toContain(`--project-id '${projectId}' --policy 'strict'`);
    expect(safe).not.toMatch(/^\+/m);
    expect(buildCiSnippet("generic", "https://safe.example/\nINJECTED=true", projectId, "standard"))
      .toBe("# Setup unavailable: the operator API URL or project identifier is invalid.");
    expect(buildCiSnippet("github", "https://inspectra.example", "project; echo leaked", "standard"))
      .toBe("# Setup unavailable: the operator API URL or project identifier is invalid.");
  });

  it("renders a non-administrator explanation without secret controls and passes axe", async () => {
    render(<ProjectCiSetupPanel project={project} canManage={false} />);
    expect(screen.getByText(/administrator must create/)).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect((await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });
});
