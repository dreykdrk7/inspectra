import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { configureAuthContext } from "./api";
import { AutomationTokensPanel } from "./AutomationTokensPanel";
import type { ProjectSummary } from "./types";


const projectId = "a".repeat(32);
const project = {
  project: { id: projectId, name: "Demo project" },
  latest_job: null,
} as ProjectSummary;

function response(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }));
}

describe("AutomationTokensPanel", () => {
  afterEach(() => {
    cleanup();
    configureAuthContext({ csrfRequired: false, csrfToken: null });
    vi.restoreAllMocks();
  });

  it("shows the secret once, sends CSRF and revokes the public record", async () => {
    const secret = `inspectra_at_${"b".repeat(32)}_${"c".repeat(43)}`;
    let records: unknown[] = [];
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
      const url = String(input);
      if (url.endsWith("/automation/tokens") && init?.method === "POST") {
        records = [{ id: "b".repeat(32), name: "CI pipeline", project_id: projectId, scopes: ["project:read", "project:scan", "report:read"], created_at: "2026-09-07T12:00:00Z", expires_at: "2099-09-08T12:00:00Z", revoked_at: null, last_used_at: null }];
        return response({ ...records[0] as object, token: secret }, 201);
      }
      if (url.endsWith(`/automation/tokens/${"b".repeat(32)}`) && init?.method === "DELETE") {
        records = [{ ...records[0] as object, revoked_at: "2026-09-07T13:00:00Z" }];
        return response(records[0]);
      }
      return response(records);
    });
    configureAuthContext({ csrfRequired: true, csrfToken: "csrf-value" });

    render(<AutomationTokensPanel projects={[project]} />);
    await screen.findByText("No automation credentials. Pipelines have no non-interactive access.");
    fireEvent.click(screen.getByRole("button", { name: "Create credential" }));
    expect(await screen.findByText(secret)).toBeInTheDocument();
    const createCall = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(new Headers(createCall?.[1]?.headers).get("X-CSRF-Token")).toBe("csrf-value");
    expect(JSON.parse(String(createCall?.[1]?.body))).toMatchObject({ project_id: projectId, lifetime_seconds: 86400 });

    fireEvent.click(screen.getByRole("button", { name: "I stored this secret" }));
    expect(screen.queryByText(secret)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create replacement" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(screen.getByText("Revoked")).toBeInTheDocument());
    expect(screen.queryByText(secret)).not.toBeInTheDocument();
  });

  it("blocks a third active credential and explains the safe rotation order", async () => {
    const active = ["b", "c"].map((value) => ({
      id: value.repeat(32), name: `Pipeline ${value}`, project_id: projectId,
      scopes: ["project:read", "project:scan", "report:read"],
      created_at: "2026-09-07T12:00:00Z", expires_at: "2099-09-08T12:00:00Z",
      revoked_at: null, last_used_at: null,
    }));
    vi.spyOn(globalThis, "fetch").mockImplementation(() => response(active));

    render(<AutomationTokensPanel projects={[project]} />);

    expect(await screen.findByText(/Two credentials are already active/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create credential" })).toBeDisabled();
  });
});
