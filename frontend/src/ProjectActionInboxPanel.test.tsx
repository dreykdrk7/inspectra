import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ProjectActionInboxPanel } from "./ProjectActionInboxPanel";
import type { ProjectActionPage, ProjectSummary } from "./types";

function response(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

function page(overrides: Partial<ProjectActionPage> = {}): ProjectActionPage {
  return {
    contract_version: "2026-09-10.1",
    items: [{
      id: "a".repeat(32),
      project_id: "b".repeat(32),
      project_name: "Payments service",
      analysis_id: "c".repeat(32),
      reason: "known_exploited",
      priority: "urgent",
      destination: "public_intelligence",
      occurred_at: "2026-09-10T12:00:00Z",
      read: false,
    }],
    total: 1,
    unread: 1,
    source_complete: true,
    retained_limit: 2000,
    state_revision: 1,
    privacy: "closed_reasons_opaque_ids_no_evidence_or_free_text",
    ...overrides,
  };
}

const projectSummary = {
  project: { id: "b".repeat(32), name: "Payments service" },
  latest_job: null,
} as ProjectSummary;

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("ProjectActionInboxPanel", () => {
  it("shows a distinct accessible passive inbox and opens the selected project", async () => {
    const onOpenProject = vi.fn();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(page()))
      .mockResolvedValueOnce(response(projectSummary));
    vi.stubGlobal("fetch", fetchMock);

    const view = render(<ProjectActionInboxPanel canRebuild onOpenProject={onOpenProject} />);

    expect(await screen.findByRole("heading", { name: /Project action inbox/ })).toBeInTheDocument();
    expect(screen.getByText(/separate from Active operations/i)).toBeInTheDocument();
    expect(screen.getByText("Known exploitation signal")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Open project" }));
    await waitFor(() => expect(onOpenProject).toHaveBeenCalledWith(projectSummary));
    expect(fetchMock.mock.calls[0][0]).toContain("unread_only=true");
    expect((await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("marks an action as read and refreshes the current unread view", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(page()))
      .mockResolvedValueOnce(response(page({ items: [], unread: 0, state_revision: 2 })))
      .mockResolvedValueOnce(response(page({ items: [], unread: 0, state_revision: 2 })));
    vi.stubGlobal("fetch", fetchMock);
    render(<ProjectActionInboxPanel canRebuild={false} onOpenProject={vi.fn()} />);

    await screen.findByText("Known exploitation signal");
    expect(screen.queryByRole("button", { name: "Rebuild index" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Mark as read" }));

    expect(await screen.findByText("No unread project actions")).toBeInTheDocument();
    expect(fetchMock.mock.calls[1][1]).toEqual(expect.objectContaining({ method: "PUT" }));
    expect(JSON.parse(String(fetchMock.mock.calls[1][1]?.body))).toEqual({ read: true });
  });

  it("surfaces fail-closed integrity and retained-limit states", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response({ detail: "unavailable" }, 503))
      .mockResolvedValueOnce(response(page({ source_complete: false, total: 2000, unread: 2000 })));
    vi.stubGlobal("fetch", fetchMock);
    const first = render(<ProjectActionInboxPanel canRebuild onOpenProject={vi.fn()} />);

    expect(await screen.findByRole("alert")).toHaveTextContent(/could not be verified/i);
    first.unmount();
    render(<ProjectActionInboxPanel canRebuild onOpenProject={vi.fn()} />);
    expect(await screen.findByRole("note")).toHaveTextContent(/2,000-action safety limit/i);
  });
});
