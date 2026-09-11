import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ProjectPortfolioPanel } from "./ProjectPortfolioPanel";
import type { ProjectPortfolioItem, ProjectPortfolioPage } from "./types";

function response(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function item(id: string, overrides: Partial<ProjectPortfolioItem> = {}): ProjectPortfolioItem {
  const value: ProjectPortfolioItem = {
    project: {
      source_metadata_contract_version: "2026-09-06.1",
      source_name_disclosure: "withheld_use_files_view",
      source_digest_disclosure: "retained_server_side",
      id,
      name: id === "project-1" ? "Payments API" : "Internal portal",
      source_reference: `snapshot-${id}`,
      source_file_deleted_at: null,
      latest_job_id: null,
      baseline_analysis_id: null,
      baseline_version: 0,
      baseline_updated_at: null,
      analysis_count: 0,
      source_snapshots: [],
      created_at: "2026-09-09T09:00:00Z",
      updated_at: "2026-09-09T10:00:00Z",
    },
    latest_job: null,
    latest_completed_analysis: null,
    priority: "urgent",
    priority_reasons: ["known_exploited", "critical_findings", "coverage_lost"],
    finding_counts: { critical: 1, high: 2, medium: 0, low: 0, informational: 0, kev: 1, local: 1, public: 2 },
    changes: { state: "not_comparable", new: 0, persistent: 0, resolved: 0, public_new: 0, public_persistent: 0, public_resolved: 0 },
    coverage: {
      state: "lost",
      current: {
        coverage_status: "partial",
        total_entries_seen: 10,
        supported_manifests_found: 2,
        supported_manifests_parsed: 1,
        supported_manifests_skipped: 1,
        unsupported_manifests_detected: 0,
        lockfiles_detected: 1,
        lockfiles_parsed: 0,
        lockfiles_skipped: 1,
        total_dependencies: 4,
        source_retained: true,
        limitations: ["One supported lockfile was not parsed."],
      },
      comparison: null,
    },
    public_intelligence_state: "stale",
    public_sources: [],
    source_type: "git_or_ci",
    source_type_detail: "commit_attributed_channel_ambiguous",
    operational_state: "no_analysis",
    pending_actions: 3,
    exceptions_due: 1,
    exceptions_overdue: 0,
    responsibility: { state: "unassigned", active_assignees: [], active_assignee_count: 0, inactive_assignment_count: 1, truncated: false },
    project_responsibility: { state: "unassigned_attention", responsible_username: null, revision: 2 },
    last_comparable_analysis_at: null,
    limitations: ["Historical commit metadata does not attest whether the source was CLI or CI."],
  };
  return { ...value, ...overrides };
}

function page(items: ProjectPortfolioItem[], overrides: Partial<ProjectPortfolioPage> = {}): ProjectPortfolioPage {
  return {
    contract_version: "2026-09-10.2",
    snapshot_at: "2026-09-09T10:30:00Z",
    items,
    returned_count: items.length,
    total_count: items.length,
    has_more: false,
    next_cursor: null,
    summary: {
      total_projects: items.length,
      filtered_projects: items.length,
      urgent_projects: items.filter((value) => value.priority === "urgent").length,
      high_priority_projects: items.filter((value) => value.priority === "high").length,
      projects_with_kev: items.filter((value) => value.finding_counts.kev > 0).length,
      projects_without_baseline: items.filter((value) => !value.project.baseline_analysis_id).length,
      projects_with_partial_data: items.filter((value) => value.coverage.state !== "complete").length,
      stale_or_failed_intelligence: items.filter((value) => ["stale", "failed"].includes(value.public_intelligence_state)).length,
      pending_actions: items.reduce((total, value) => total + value.pending_actions, 0),
    },
    priority_model: "closed_signals_no_opaque_score",
    portfolio_complete: true,
    limitations: [
      "Priority, filters and summary use private materialized closed signals; every returned project is revalidated against authoritative records.",
      "Commit-attributed legacy sources remain grouped as Git/CLI or CI.",
    ],
    ...overrides,
  };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("ProjectPortfolioPanel", () => {
  it("shows explainable portfolio signals, evidence limits and an accessible project action", async () => {
    const onOpenProject = vi.fn();
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(response(page([item("project-1")])))));

    const view = render(<ProjectPortfolioPanel onOpenProject={onOpenProject} />);

    expect(await screen.findByRole("heading", { name: "Payments API" })).toBeInTheDocument();
    expect(screen.getByText("Known exploitation (KEV)")).toBeInTheDocument();
    expect(screen.getByText("1 known exploited")).toBeInTheDocument();
    expect(screen.getByText(/Legacy Git \/ CI \(unverified channel\)/)).toBeInTheDocument();
    expect(screen.getByText("Not comparable; no improvement inferred")).toBeInTheDocument();
    expect(screen.getByText(/does not attest whether the source was CLI or CI/i)).toBeInTheDocument();
    expect(screen.getByText(/private materialized closed signals/i)).toBeInTheDocument();
    expect(screen.getByText(/previous member unavailable/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Open project" }));
    expect(onOpenProject).toHaveBeenCalledWith(expect.objectContaining({ project: expect.objectContaining({ id: "project-1" }) }));
    expect((await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("sends closed filters in the request body and renders a no-match state", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(page([item("project-1")])))
      .mockResolvedValueOnce(response(page([], {
        total_count: 0,
        summary: { ...page([item("project-1")]).summary, filtered_projects: 0 },
      })));
    vi.stubGlobal("fetch", fetchMock);
    render(<ProjectPortfolioPanel onOpenProject={vi.fn()} />);
    await screen.findByText("Payments API");

    fireEvent.change(screen.getByLabelText("Project name prefix"), { target: { value: "pay" } });
    fireEvent.change(screen.getByLabelText("Priority"), { target: { value: "urgent" } });
    fireEvent.change(screen.getByLabelText("Coverage"), { target: { value: "lost" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));

    expect(await screen.findByText("No projects match these filters")).toBeInTheDocument();
    const [, init] = fetchMock.mock.calls[1];
    expect(new URL(String(fetchMock.mock.calls[1][0])).search).toBe("");
    expect(JSON.parse(String(init?.body))).toEqual(expect.objectContaining({
      search: "pay",
      search_mode: "prefix",
      priority: "urgent",
      coverage: "lost",
    }));
  });

  it("merges coherent pages and preserves loaded projects when the snapshot changes", async () => {
    const first = item("project-1");
    const second = item("project-2", { priority: "high", priority_reasons: ["high_findings"], finding_counts: { ...item("project-2").finding_counts, kev: 0, critical: 0 } });
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(page([first], { total_count: 2, has_more: true, next_cursor: "signed-page-2" })))
      .mockResolvedValueOnce(response(page([second], { total_count: 2 })))
      .mockResolvedValueOnce(response({ detail: "Portfolio changed" }, 409));
    vi.stubGlobal("fetch", fetchMock);
    render(<ProjectPortfolioPanel onOpenProject={vi.fn()} />);

    await screen.findByText("Payments API");
    fireEvent.click(screen.getByRole("button", { name: /Load more/ }));
    expect(await screen.findByText("Internal portal")).toBeInTheDocument();
    expect(JSON.parse(String(fetchMock.mock.calls[1][1]?.body))).toEqual(expect.objectContaining({ cursor: "signed-page-2" }));

    // Re-run with a paged first response, then simulate a concurrent portfolio mutation.
    cleanup();
    fetchMock.mockReset()
      .mockResolvedValueOnce(response(page([first], { total_count: 2, has_more: true, next_cursor: "stale-page-2" })))
      .mockResolvedValueOnce(response({ detail: "Portfolio changed" }, 409));
    render(<ProjectPortfolioPanel onOpenProject={vi.fn()} />);
    await screen.findByText("Payments API");
    fireEvent.click(screen.getByRole("button", { name: /Load more/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/changed while you were paging/i);
    expect(screen.getByText("Payments API")).toBeInTheDocument();
    expect(within(screen.getByLabelText("Project portfolio results")).getByText("Payments API")).toBeInTheDocument();
  });
});
