import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ProjectSnapshotForm } from "./ProjectSnapshotForm";
import type { FileRecord, ProjectSummary } from "./types";

const project = {
  project: {
    source_metadata_contract_version: "2026-09-06.1",
    source_name_disclosure: "withheld_use_files_view",
    source_digest_disclosure: "retained_server_side",
    id: "project-1",
    name: "Demo project",
    source_reference: "snapshot-aaaaaaaaaaaaaaaa",
    source_file_deleted_at: null,
    latest_job_id: "analysis-before",
    analysis_count: 1,
    created_at: "2026-09-05T09:00:00Z",
    updated_at: "2026-09-05T09:00:00Z"
  },
  latest_job: null
} satisfies ProjectSummary;

const archive = {
  id: "file-after",
  source_reference: "snapshot-bbbbbbbbbbbbbbbb",
  kind: "archive",
  original_filename: "after.zip",
  stored_filename: "file-after.zip",
  content_type: "application/zip",
  size_bytes: 120,
  sha256: "b".repeat(64),
  created_at: "2026-09-05T10:00:00Z"
} satisfies FileRecord;

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("ProjectSnapshotForm", () => {
  it("requires an authorization confirmation before queuing a different archive snapshot", async () => {
    const onCompleted = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(JSON.stringify({ id: "snapshot-job" }), { status: 202 }))));
    render(<ProjectSnapshotForm project={project} files={[archive]} onCompleted={onCompleted} onCancel={() => undefined} />);

    const submit = screen.getByRole("button", { name: "Add snapshot & analyze" });
    expect(submit).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox", { name: "I confirm I own or am authorized to analyze this archive as a project snapshot." }));
    expect(submit).toBeEnabled();
    fireEvent.click(submit);

    await waitFor(() => {
      expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    });
    const [url, init] = vi.mocked(globalThis.fetch).mock.calls[0];
    expect(url).toBe("http://localhost:8000/projects/project-1/snapshots");
    expect(init).toEqual(expect.objectContaining({ method: "POST" }));
    expect(JSON.parse(String(init?.body))).toEqual({
      source_file_id: "file-after",
      idempotency_key: expect.stringMatching(/^[a-f0-9]{32}$/),
      authorization_confirmed: true,
    });
  });

  it("explains the next step when no distinct authorized archive is available", () => {
    render(<ProjectSnapshotForm project={project} files={[]} onCompleted={async () => undefined} onCancel={() => undefined} />);

    expect(screen.getByText(/Upload a different ZIP or TAR archive/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add snapshot & analyze" })).not.toBeInTheDocument();
  });

  it("shows the retryable admission message without exposing queue counts", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(new Response(
        JSON.stringify({ detail: "Analysis capacity is temporarily full. Wait for an active analysis to finish, then retry." }),
        { status: 429, headers: { "content-type": "application/json" } },
      ))),
    );
    render(<ProjectSnapshotForm project={project} files={[archive]} onCompleted={vi.fn()} onCancel={() => undefined} />);

    fireEvent.click(screen.getByRole("checkbox", { name: /I confirm I own or am authorized/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add snapshot & analyze" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Analysis capacity is temporarily full. Wait for an active analysis to finish, then retry.",
    );
    expect(screen.getByRole("alert")).not.toHaveTextContent(/\b\d+\b|owner-a|owner-b/);
  });

  it("reuses the opaque operation key when a retry follows an uncertain failure", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ detail: "Temporary request failure." }), {
        status: 503,
        headers: { "content-type": "application/json" },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: "snapshot-job" }), { status: 202 }));
    vi.stubGlobal("fetch", fetchMock);
    render(<ProjectSnapshotForm project={project} files={[archive]} onCompleted={vi.fn().mockResolvedValue(undefined)} onCancel={() => undefined} />);

    fireEvent.click(screen.getByRole("checkbox", { name: /I confirm I own or am authorized/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add snapshot & analyze" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Temporary request failure.");
    fireEvent.click(screen.getByRole("button", { name: "Add snapshot & analyze" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));

    const firstBody = JSON.parse(String(fetchMock.mock.calls[0][1]?.body));
    const secondBody = JSON.parse(String(fetchMock.mock.calls[1][1]?.body));
    expect(secondBody.idempotency_key).toBe(firstBody.idempotency_key);
  });

  it("fails closed instead of offering an archive picker to an SBOM project", () => {
    const sbomProject = {
      ...project,
      project: { ...project.project, source_type: "sbom" as const },
      latest_job: null,
    } satisfies ProjectSummary;
    render(<ProjectSnapshotForm project={sbomProject} files={[archive]} onCompleted={vi.fn()} onCancel={() => undefined} />);

    expect(screen.getByRole("heading", { name: "Archive snapshot unavailable" })).toBeInTheDocument();
    expect(screen.getByText(/Add a compatible SBOM revision/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add snapshot & analyze" })).not.toBeInTheDocument();
  });
});
