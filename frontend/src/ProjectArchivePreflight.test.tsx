import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ProjectArchivePreflight } from "./ProjectArchivePreflight";
import type { ProjectArchivePreflightResponse } from "./types";

const preflight = {
  contract_version: "2026-09-06.1",
  status: "available",
  accepted_archive_formats: [".zip", ".tar", ".tar.gz", ".tgz"],
  upload_limit_bytes: 20 * 1024 * 1024,
  analysis_profile: {
    contract_version: "2026-09-09.1",
    profile_name: "project_archive_basic",
    title: "Safe manifest and dependency review",
    ruleset_version: "2026-09-06.1",
    safe_default: true,
    selection_mode: "manifest_driven_closed_catalog",
    execution_mode: "passive_no_project_execution",
    network_access: "disabled",
    supported_stacks: ["npm", "PyPI", "Go", "mixed manifest repositories"],
    rules: [
      {
        id: "dependency_repeatability",
        category: "dependency_hygiene",
        applies_to: ["npm", "PyPI", "Go"],
        description: "Flags broad or non-exact requirements without executing a package manager.",
      },
      {
        id: "sensitive_data_indicators",
        category: "sensitive_data",
        applies_to: ["supported text configuration"],
        description: "Detects bounded indicators while retaining only redacted evidence.",
      },
    ],
    exclusions: ["Application-framework and infrastructure deep reviews are separate capabilities."],
  },
  execution_profile: {
    contract_version: "2026-09-06.3",
    profile_name: "project_archive_basic",
    ruleset_version: "2026-09-06.1",
    max_upload_bytes: 20 * 1024 * 1024,
    audit_max_concurrency: 2,
  },
  supported_manifests: [
    { name: "package.json", ecosystem: "npm", coverage: "dependency declarations" },
    { name: "requirements.txt", ecosystem: "PyPI", coverage: "dependency declarations" },
    { name: "Cargo.toml", ecosystem: "Rust", coverage: "same-root marker only" },
  ],
  exact_resolution: [
    { name: "package-lock.json", ecosystem: "npm", coverage: "exact registry versions only when roots match" },
    { name: "pnpm-lock.yaml", ecosystem: "npm", coverage: "exact local versions only when roots match; never public-advisory egress" },
    { name: "yarn.lock (Classic v1)", ecosystem: "npm", coverage: "exact local versions only when selector matches; Berry remains detected but not resolved; never public-advisory egress" },
    { name: "poetry.lock (v2.1)", ecosystem: "PyPI", coverage: "exact local versions only when roots match; never public-advisory egress" },
    { name: "Pipfile.lock (v6)", ecosystem: "PyPI", coverage: "exact grouped local versions only when roots match; never public-advisory egress" },
  ],
  detected_not_resolved: [],
  limitations: ["The preview does not open, upload, hash, or inspect a selected archive."],
  boundaries: [
    "Inspectra does not execute project code or install dependencies.",
    "This preview does not send source contents, paths, or project metadata to public providers.",
  ],
} satisfies ProjectArchivePreflightResponse;

function jsonResponse(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("ProjectArchivePreflight", () => {
  it("degrades safely when a legacy preflight response omits its analysis profile", async () => {
    const legacyResponse = { ...preflight, analysis_profile: undefined };
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(jsonResponse(legacyResponse))));

    render(<ProjectArchivePreflight active />);

    expect(await screen.findByText(/catalog response is incomplete/i)).toHaveAttribute("role", "status");
    expect(screen.getByText("20 MiB")).toBeInTheDocument();
    expect(screen.queryByText(/network is/i)).not.toBeInTheDocument();
  });

  it("renders the source-free passive catalog with no clean-result claim", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(jsonResponse(preflight))));
    const view = render(<ProjectArchivePreflight active />);

    expect(await screen.findByRole("heading", { name: "Coverage preview" })).toBeInTheDocument();
    expect(screen.getByText("20 MiB")).toBeInTheDocument();
    expect(screen.getByText("Safe manifest and dependency review")).toBeInTheDocument();
    expect(screen.getByText("dependency repeatability")).toBeInTheDocument();
    expect(screen.getByText("sensitive data indicators")).toBeInTheDocument();
    expect(screen.getByText(/Application-framework and infrastructure deep reviews/)).toBeInTheDocument();
    expect(screen.getByText("package.json")).toBeInTheDocument();
    expect(screen.getByText("Cargo.toml")).toBeInTheDocument();
    expect(screen.getByText("package-lock.json")).toBeInTheDocument();
    expect(screen.getByText("pnpm-lock.yaml")).toBeInTheDocument();
    expect(screen.getByText("yarn.lock (Classic v1)")).toBeInTheDocument();
    expect(screen.getByText("poetry.lock (v2.1)")).toBeInTheDocument();
    expect(screen.getAllByText(/never public-advisory egress/i)).toHaveLength(4);
    expect(screen.getByText(/Pipfile\.lock/)).toBeInTheDocument();
    expect(screen.getAllByText(/does not open, upload, hash, or inspect/i)).toHaveLength(2);
    expect(screen.getByText(/does not execute project code/i)).toBeInTheDocument();
    expect(view.container.textContent?.toLowerCase()).not.toContain("no vulnerabilities");
    expect(globalThis.fetch).toHaveBeenCalledWith(
      "http://localhost:8000/project-analysis-preflight",
      expect.objectContaining({ credentials: "include" }),
    );
    const [, requestInit] = vi.mocked(globalThis.fetch).mock.calls[0];
    expect(requestInit?.method).toBeUndefined();
    expect(requestInit?.body).toBeUndefined();

    const results = await axe.run(view.container);
    expect(results.violations).toHaveLength(0);
  });

  it("keeps the safe upload action available when the catalog cannot load and supports retry", async () => {
    let calls = 0;
    vi.stubGlobal("fetch", vi.fn(() => {
      calls += 1;
      return calls === 1 ? Promise.reject(new Error("runner unavailable")) : Promise.resolve(jsonResponse(preflight));
    }));
    render(<ProjectArchivePreflight active />);

    expect(await screen.findByText(/Coverage preview is unavailable/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Retry preview" }));
    await waitFor(() => expect(screen.getByText("20 MiB")).toBeInTheDocument());
  });

  it("does not request the catalog while archive mode is inactive", () => {
    vi.stubGlobal("fetch", vi.fn());
    render(<ProjectArchivePreflight active={false} />);

    expect(screen.queryByRole("heading", { name: "Coverage preview" })).not.toBeInTheDocument();
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});
