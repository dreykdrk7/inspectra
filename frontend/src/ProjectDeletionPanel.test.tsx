import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ProjectDeletionPanel } from "./ProjectDeletionPanel";
import type { ProjectDeletionPreview, ProjectSummary } from "./types";


const project = {
  project: {
    source_metadata_contract_version: "2026-09-06.1",
    source_name_disclosure: "withheld_use_files_view",
    source_digest_disclosure: "retained_server_side",
    id: "a".repeat(32),
    name: "Authorized project",
    source_reference: "snapshot-cccccccccccccccc",
    source_file_deleted_at: null,
    latest_job_id: "d".repeat(32),
    analysis_count: 1,
    source_snapshots: [],
    created_at: "2026-09-06T12:00:00Z",
    updated_at: "2026-09-06T12:01:00Z"
  },
  latest_job: null
} satisfies ProjectSummary;

const preview = {
  contract_version: "2026-09-06.1",
  project_id: project.project.id,
  state: "ready",
  requires_confirmation: true,
  items: [
    { key: "project_metadata", disposition: "delete", item_count: 1, detail: "Project metadata is removed." },
    { key: "analysis_results", disposition: "delete", item_count: 1, detail: "Analysis results are removed." },
    { key: "source_uploads", disposition: "retain", item_count: 1, detail: "Uploaded archives retain an independent lifecycle." },
    { key: "report_exports", disposition: "not_persisted", item_count: 0, detail: "Reports are not persisted." },
    { key: "product_audit", disposition: "retain", item_count: null, detail: "Bounded audit events remain." }
  ]
} satisfies ProjectDeletionPreview;

function response(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("ProjectDeletionPanel", () => {
  it("reviews an explicit scope, requires confirmation and completes the cascade", async () => {
    const onDeleted = vi.fn();
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      if (init?.method === "DELETE") {
        expect(JSON.parse(String(init.body))).toEqual({ deletion_confirmed: true });
        return Promise.resolve(response({
          contract_version: "2026-09-06.1",
          project_id: project.project.id,
          state: "completed",
          completed_at: "2026-09-06T13:00:00Z",
          items: preview.items
        }));
      }
      expect(url.pathname).toBe(`/projects/${project.project.id}/deletion`);
      return Promise.resolve(response(preview));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<ProjectDeletionPanel project={project} canDelete onDeleted={onDeleted} />);
    expect(screen.queryByText("Project metadata")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Review deletion scope" }));
    expect(await screen.findByText("Project metadata")).toBeInTheDocument();
    expect(screen.getByText("Uploaded source files")).toBeInTheDocument();
    expect(screen.getAllByText("Will retain")).toHaveLength(2);
    expect(screen.getByRole("button", { name: "Delete project and derived data" })).toBeDisabled();

    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Delete project and derived data" }));

    expect(await screen.findByText(/project and its derived records were removed/i)).toBeInTheDocument();
    expect(onDeleted).toHaveBeenCalledWith(expect.objectContaining({ state: "completed" }));
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect((await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("explains active-work blocking and keeps readers read-only", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(response({ ...preview, state: "blocked_active_work" }))));
    render(<ProjectDeletionPanel project={project} canDelete={false} onDeleted={() => undefined} />);

    fireEvent.click(screen.getByRole("button", { name: "Review deletion scope" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("blocked while a project analysis"));
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete project and derived data" })).not.toBeInTheDocument();
  });

  it("keeps a retryable, content-free error when deletion storage fails", async () => {
    let call = 0;
    vi.stubGlobal("fetch", vi.fn(() => {
      call += 1;
      return Promise.resolve(call === 1 ? response(preview) : response({ detail: "/private/source.zip" }, 503));
    }));
    render(<ProjectDeletionPanel project={project} canDelete onDeleted={() => undefined} />);

    fireEvent.click(screen.getByRole("button", { name: "Review deletion scope" }));
    await screen.findByText("Project metadata");
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Delete project and derived data" }));

    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("retained a safe retry record"));
    expect(screen.queryByText("/private/source.zip")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete project and derived data" })).toBeEnabled();
  });
});
