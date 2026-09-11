import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ProjectWorkspacePanel } from "./ProjectWorkspacePanel";
import type { JobListItem, ProjectSummary } from "./types";

const previousAnalysis = {
  id: "analysis-before",
  project_id: "project-1",
  source_reference: "snapshot-aaaaaaaaaaaaaaaa",
  analysis_profile: "project_archive_basic",
  audit_type: "project_archive_basic",
  file_id: "file-before",
  target_url: null,
  target_domain: null,
  status: "completed",
  created_at: "2026-09-05T09:00:00Z",
  updated_at: "2026-09-05T09:01:00Z",
  source_file_deleted_at: "2026-09-05T10:00:00Z",
  result_integrity_status: "valid",
  summary: null,
  status_detail: { code: "completed", message: "Results are retained and ready to review.", next_action: "view_results" }
} satisfies JobListItem;

const latestAnalysis = {
  ...previousAnalysis,
  id: "analysis-after",
  source_reference: "snapshot-bbbbbbbbbbbbbbbb",
  file_id: "file-after",
  status: "failed",
  created_at: "2026-09-05T11:00:00Z",
  updated_at: "2026-09-05T11:01:00Z",
  source_file_deleted_at: null,
  status_detail: {
    code: "failed",
    message: "The review did not complete. Review the retained record, then run the same snapshot again if appropriate.",
    next_action: "review_and_retry"
  }
} satisfies JobListItem;

const project = {
  project: {
    source_metadata_contract_version: "2026-09-06.1",
    source_name_disclosure: "withheld_use_files_view",
    source_digest_disclosure: "retained_server_side",
    id: "project-1",
    name: "Demo project",
    source_reference: "snapshot-bbbbbbbbbbbbbbbb",
    source_file_deleted_at: null,
    latest_job_id: latestAnalysis.id,
    analysis_count: 2,
    source_snapshots: [
      { id: "snapshot-before", source_reference: "snapshot-aaaaaaaaaaaaaaaa", source_channel: "archive_upload", source_file_deleted_at: "2026-09-05T10:00:00Z", created_at: "2026-09-05T09:00:00Z" },
      { id: "snapshot-after", source_reference: "snapshot-bbbbbbbbbbbbbbbb", source_channel: "ci", source_file_deleted_at: null, created_at: "2026-09-05T11:00:00Z" }
    ],
    created_at: "2026-09-05T09:00:00Z",
    updated_at: "2026-09-05T11:00:00Z"
  },
  latest_job: latestAnalysis
} satisfies ProjectSummary;

function response(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("ProjectWorkspacePanel", () => {
  it("gives a safe timeline, retention state, next action, and direct analysis navigation", async () => {
    const onOpenAnalysis = vi.fn();
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(response([latestAnalysis, previousAnalysis]))));

    render(<ProjectWorkspacePanel project={project} onOpenAnalysis={onOpenAnalysis} />);

    expect(await screen.findByRole("heading", { name: "Project workspace: Demo project" })).toBeInTheDocument();
    expect(screen.getByText("Snapshots")).toBeInTheDocument();
    expect(screen.getAllByText("CI automation").length).toBeGreaterThan(0);
    expect(screen.getByText("Archive upload")).toBeInTheDocument();
    expect(screen.getAllByText("2")).toHaveLength(2);
    expect(screen.getAllByText(/The review did not complete/)).toHaveLength(2);
    expect(screen.getByText(/Source removed; redacted result retained/)).toBeInTheDocument();
    expect(screen.getByText(/Result integrity:/).parentElement).toHaveTextContent("verified");
    expect(screen.getAllByText("snapshot-bbbbbbbbbbbbbbbb").length).toBeGreaterThan(0);
    expect(screen.queryByText("before.zip")).not.toBeInTheDocument();
    expect(document.body).not.toHaveTextContent("a".repeat(64));
    expect(document.body).not.toHaveTextContent("b".repeat(64));

    fireEvent.click(screen.getAllByRole("button", { name: "Open analysis" })[0]);
    expect(onOpenAnalysis).toHaveBeenCalledWith("analysis-after");
  });

  it("uses a controlled error when history cannot be loaded", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(response({ detail: "not found" }, 404))));

    render(<ProjectWorkspacePanel project={project} onOpenAnalysis={() => undefined} />);

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("This project is no longer available.");
    });
  });

  it("continues a bounded project history and restores focus without exposing its cursor", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const request = JSON.parse(String(init?.body || "{}")) as { cursor?: string };
      const indexes = request.cursor ? [50] : Array.from({ length: 50 }, (_value, index) => index);
      const items = indexes.map((index) => ({ ...latestAnalysis, id: `analysis-${index}` }));
      return Promise.resolve(response({
        contract_version: "2026-09-08.1",
        items,
        returned_count: items.length,
        total_count: 51,
        has_more: !request.cursor,
        next_cursor: request.cursor ? null : "project.opaque-cursor",
      }));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<ProjectWorkspacePanel project={project} onOpenAnalysis={() => undefined} />);

    expect(await screen.findByText("Showing 50 of 51 retained analyses.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Load more analyses" }));

    await waitFor(() => expect(screen.getAllByRole("button", { name: "Open analysis" })).toHaveLength(51));
    await waitFor(() => expect(screen.getByRole("list", { name: "Retained project analysis timeline" })).toHaveFocus());
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(String(fetchMock.mock.calls[1][0])).not.toContain("project.opaque-cursor");
    expect(JSON.parse(String(fetchMock.mock.calls[1][1]?.body))).toMatchObject({ cursor: "project.opaque-cursor" });
  });

  it("cancels an active owned analysis and refreshes the terminal state", async () => {
    const runningAnalysis = {
      ...latestAnalysis,
      status: "running",
      status_detail: { code: "running", message: "The bounded review is running.", next_action: "wait" }
    } satisfies JobListItem;
    const cancelledAnalysis = {
      ...runningAnalysis,
      status: "cancelled",
      termination_reason: "cancelled_by_owner",
      status_detail: {
        code: "cancelled",
        message: "The review was cancelled and its execution workspace was removed.",
        next_action: "review_and_retry"
      }
    } satisfies JobListItem;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/cancel") && init?.method === "POST") {
        return Promise.resolve(response(cancelledAnalysis, 202));
      }
      const refreshCount = fetchMock.mock.calls.filter(([calledInput]) => String(calledInput).endsWith("/analyses")).length;
      return Promise.resolve(response(refreshCount > 1 ? [cancelledAnalysis, previousAnalysis] : [runningAnalysis, previousAnalysis]));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<ProjectWorkspacePanel project={{ ...project, latest_job: runningAnalysis }} onOpenAnalysis={() => undefined} />);

    fireEvent.click(await screen.findByRole("button", { name: "Cancel analysis" }));
    await waitFor(() => expect(screen.getAllByText("cancelled").length).toBeGreaterThan(0));
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("/projects/project-1/analyses/analysis-after/cancel"),
      expect.objectContaining({ method: "POST" })
    );
    expect(screen.queryByRole("button", { name: "Cancel analysis" })).not.toBeInTheDocument();
  });

  it("assigns an active workspace member with optimistic concurrency and keeps finding assignment distinct", async () => {
    const onProjectUpdated = vi.fn();
    const updatedProject = {
      ...project.project,
      updated_at: "2026-09-05T12:00:00Z",
      responsibility: {
        state: "assigned" as const,
        responsible_user_id: "reviewer-id",
        revision: 1,
        updated_at: "2026-09-05T12:00:00Z",
      },
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/organization/members")) {
        return Promise.resolve(response([
          { user_id: "team-admin", username: "admin", role: "administrator", joined_at: "2026-09-05T08:00:00Z" },
          { user_id: "reviewer-id", username: "reviewer.one", role: "reader", joined_at: "2026-09-05T08:30:00Z" },
        ]));
      }
      if (url.endsWith("/responsibility") && init?.method === "PUT") {
        return Promise.resolve(response(updatedProject));
      }
      return Promise.resolve(response([latestAnalysis, previousAnalysis]));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(
      <ProjectWorkspacePanel
        project={project}
        onOpenAnalysis={() => undefined}
        canManageResponsibility
        teamMode
        currentOperator={{ user_id: "team-admin", username: "admin" }}
        onProjectUpdated={onProjectUpdated}
      />,
    );

    const selector = await screen.findByLabelText("Accountable member");
    expect(screen.getByText(/separate from assignees on individual findings/i)).toBeInTheDocument();
    fireEvent.change(selector, { target: { value: "reviewer-id" } });
    fireEvent.click(screen.getByRole("button", { name: "Update responsibility" }));

    expect(await screen.findByText("Project responsibility updated.")).toBeInTheDocument();
    expect(screen.getAllByText("reviewer.one")).toHaveLength(2);
    const updateCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/responsibility"));
    expect(JSON.parse(String(updateCall?.[1]?.body))).toEqual({
      responsible_user_id: "reviewer-id",
      expected_updated_at: project.project.updated_at,
      assignment_confirmed: true,
    });
    expect(onProjectUpdated).toHaveBeenCalledWith(updatedProject);
  });

  it("makes revoked-member attention visible while reader access remains view-only", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(response([latestAnalysis, previousAnalysis]))));
    render(
      <ProjectWorkspacePanel
        project={{
          ...project,
          project: {
            ...project.project,
            responsibility: {
              state: "unassigned_attention",
              responsible_user_id: null,
              revision: 2,
              updated_at: "2026-09-05T12:00:00Z",
            },
          },
        }}
        onOpenAnalysis={() => undefined}
      />,
    );

    expect(await screen.findByText("Reassignment required after member departure")).toBeInTheDocument();
    expect(screen.getByText(/never reassigns ownership silently/i)).toBeInTheDocument();
    expect(screen.getByText(/Reader access can inspect project responsibility but cannot change it/i)).toBeInTheDocument();
    expect(screen.queryByLabelText("Accountable member")).not.toBeInTheDocument();
  });

  it("has no automated accessibility violations for the retained-history view", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(response([latestAnalysis, previousAnalysis]))));
    render(<ProjectWorkspacePanel project={project} onOpenAnalysis={() => undefined} />);

    await screen.findByRole("list", { name: "Retained project analysis timeline" });
    expect((await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("offers only the compatible revision flow for an SBOM project", async () => {
    const sbomAnalysis = { ...latestAnalysis, analysis_profile: "sbom_import" };
    const sbomProject = {
      ...project,
      project: { ...project.project, source_type: "sbom" as const },
      latest_job: sbomAnalysis,
    } satisfies ProjectSummary;
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(response([sbomAnalysis]))));

    render(
      <ProjectWorkspacePanel
        project={sbomProject}
        onOpenAnalysis={() => undefined}
        canManageAutomation
        canImportSbomRevision
        onSbomRevisionImported={() => undefined}
      />,
    );

    expect(await screen.findByRole("heading", { name: "Add a compatible SBOM revision" })).toBeInTheDocument();
    expect(screen.getByText("SBOM")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Connect this project to CI" })).not.toBeInTheDocument();
    expect(screen.queryByText(/archive snapshots/)).not.toBeInTheDocument();
  });
});
