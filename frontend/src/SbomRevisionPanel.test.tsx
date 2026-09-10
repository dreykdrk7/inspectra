import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { configureAuthContext } from "./api";
import { SbomRevisionPanel } from "./SbomRevisionPanel";
import type { ProjectSbomRevisionCreated, ProjectSummary } from "./types";

const project = {
  project: {
    source_metadata_contract_version: "2026-09-06.1",
    source_name_disclosure: "withheld_use_files_view",
    source_digest_disclosure: "retained_server_side",
    id: "a".repeat(32),
    name: "Imported inventory",
    source_reference: "snapshot-aaaaaaaaaaaaaaaa",
    source_file_deleted_at: null,
    latest_job_id: "b".repeat(32),
    analysis_count: 1,
    source_snapshots: [],
    created_at: "2026-09-08T10:00:00Z",
    updated_at: "2026-09-08T10:00:00Z",
  },
  latest_job: {
    id: "b".repeat(32),
    project_id: "a".repeat(32),
    analysis_profile: "sbom_import",
    audit_type: "project_archive_basic",
    file_id: null,
    target_url: null,
    target_domain: null,
    status: "completed",
    created_at: "2026-09-08T10:00:00Z",
    updated_at: "2026-09-08T10:00:00Z",
    source_file_deleted_at: null,
    summary: null,
  },
} satisfies ProjectSummary;

const created = {
  project: { ...project.project, analysis_count: 2 },
  job: { ...project.latest_job!, id: "c".repeat(32) },
  snapshot: {
    id: "d".repeat(32),
    source_reference: "snapshot-cccccccccccccccc",
    source_file_deleted_at: null,
    created_at: "2026-09-08T11:00:00Z",
  },
  replayed: false,
} satisfies ProjectSbomRevisionCreated;

function jsonResponse(payload: unknown, status = 201) {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("SbomRevisionPanel", () => {
  it("requires fresh authorization, sends a private idempotency key, and reports success", async () => {
    configureAuthContext({ csrfRequired: true, csrfToken: "csrf-token" });
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse(created));
    const onImported = vi.fn();
    render(<SbomRevisionPanel project={project} canImport onImported={onImported} />);

    const input = screen.getByLabelText("New SBOM JSON");
    fireEvent.change(input, { target: { files: [new File(['{"bomFormat":"CycloneDX"}'], "private-client-name.json")] } });
    expect(screen.getByRole("button", { name: "Add SBOM revision" })).toBeDisabled();
    fireEvent.click(screen.getByLabelText("I am authorized to import and analyze this SBOM revision."));
    fireEvent.click(screen.getByLabelText(/I attest that retained supported npm, PyPI, and Maven purls are public identities/));
    fireEvent.submit(screen.getByRole("button", { name: "Add SBOM revision" }).closest("form")!);

    await waitFor(() => expect(onImported).toHaveBeenCalledWith(created));
    const [, options] = fetchMock.mock.calls[0];
    const body = options?.body as FormData;
    expect((body.get("file") as File).name).toBe("sbom.json");
    expect(body.get("authorization_confirmed")).toBe("true");
    expect(body.get("public_registry_identities_confirmed")).toBe("true");
    expect(body.get("idempotency_key")).toMatch(/^[a-f0-9]{32}$/);
    expect(new Headers(options?.headers).get("X-CSRF-Token")).toBe("csrf-token");
    expect(screen.getByRole("status")).toHaveTextContent("retained");
    expect(document.body).not.toHaveTextContent("private-client-name");
  });

  it("keeps readers read-only and presents a controlled conflict", async () => {
    const { rerender } = render(<SbomRevisionPanel project={project} canImport={false} onImported={() => undefined} />);
    expect(screen.getByText(/Reader access/)).toBeInTheDocument();
    expect(screen.queryByLabelText("New SBOM JSON")).not.toBeInTheDocument();

    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse({ detail: "private backend detail" }, 409));
    rerender(<SbomRevisionPanel project={project} canImport onImported={() => undefined} />);
    fireEvent.change(screen.getByLabelText("New SBOM JSON"), { target: { files: [new File(["{}"], "revision.json")] } });
    fireEvent.click(screen.getByLabelText("I am authorized to import and analyze this SBOM revision."));
    fireEvent.submit(screen.getByRole("button", { name: "Add SBOM revision" }).closest("form")!);
    expect(await screen.findByRole("alert")).toHaveTextContent("incompatible");
    expect(document.body).not.toHaveTextContent("private backend detail");
  });

  it("has no automated accessibility violations", async () => {
    render(<SbomRevisionPanel project={project} canImport onImported={() => undefined} />);
    expect((await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });
});
