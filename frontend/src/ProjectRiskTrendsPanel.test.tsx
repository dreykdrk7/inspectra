import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ProjectRiskTrendsPanel } from "./ProjectRiskTrendsPanel";
import type { RiskTrendResponse, RiskTrendViewResponse } from "./types";

function response(payload: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(typeof payload === "string" ? payload : JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

const trend: RiskTrendResponse = {
  contract_version: "2026-09-10.1",
  generated_at: "2026-09-09T12:00:00Z",
  period_starts_at: "2026-06-11T12:00:00Z",
  period_ends_at: "2026-09-09T12:00:00Z",
  bucket_days: 7,
  summary: {
    projects_in_scope: 2, projects_analyzed_in_period: 1, projects_without_recent_analysis: 1,
    retained_completed_analyses: 3, completed_analyses_in_period: 3,
    comparable_local_transitions: 2, comparable_public_transitions: 1, excluded_transitions: 1,
    pending_actions: 4, overdue_exceptions: 1, current_known_exploited_findings: 1,
    current_critical_or_high_findings: 2,
  },
  changes: { local_new: 1, local_persistent: 1, local_resolved: 1, public_new: 1, public_persistent: 0, public_resolved: 0, critical_or_high_new: 1 },
  buckets: [{
    starts_at: "2026-09-02T12:00:00Z", ends_at: "2026-09-09T12:00:00Z",
    completed_analyses: 2, projects_analyzed: 1, comparable_local_transitions: 1,
    comparable_public_transitions: 1, excluded_transitions: 0, coverage_gained: 0, coverage_lost: 1,
    changes: { local_new: 1, local_persistent: 0, local_resolved: 1, public_new: 1, public_persistent: 0, public_resolved: 0, critical_or_high_new: 1 },
  }],
  ecosystems: [{ key: "npm", current_findings: 1, completed_analyses: 0, comparable_transitions: 1, new_findings: 1, resolved_findings: 0 }],
  source_types: [{ key: "git_or_ci", current_findings: 0, completed_analyses: 3, comparable_transitions: 2, new_findings: 1, resolved_findings: 1 }],
  time_to_first_review: { cohort: "first_retained_observation_in_period", sample_count: 1, median_hours: 12, p90_hours: 12 },
  time_to_verified_resolution: { cohort: "first_retained_observation_in_period", sample_count: 1, median_hours: 48, p90_hours: 48 },
  priority_projects: [{
    project: {
      source_metadata_contract_version: "2026-09-06.1", source_name_disclosure: "withheld_use_files_view",
      source_digest_disclosure: "retained_server_side", id: "a".repeat(32), name: "Payments API",
      source_type: "archive", source_reference: "snapshot-0123456789abcdef", source_file_deleted_at: null,
      latest_job_id: null, baseline_analysis_id: null, baseline_version: 0, baseline_updated_at: null,
      analysis_count: 3, source_snapshots: [], created_at: "2026-06-01T00:00:00Z", updated_at: "2026-09-09T00:00:00Z",
    }, priority: "urgent", reasons: ["known_exploited"], pending_actions: 2,
  }],
  exclusions: [{ reason: "coverage_changed", count: 1 }],
  denominators: { projects: 2, retained_completed_analyses: 3, analyses_in_period: 3, local_comparable_transitions: 2, public_comparable_transitions: 1, first_review_samples: 1, verified_resolution_samples: 1 },
  limitations: ["Change counts use comparable retained analyses."],
};

const readyView: RiskTrendViewResponse = {
  contract_version: "2026-09-10.2",
  materialization: {
    state: "ready",
    data_state: "current",
    refresh_in_progress: false,
    retryable: false,
    requested_at: "2026-09-09T11:59:00Z",
    started_at: null,
    completed_at: "2026-09-09T12:00:00Z",
    failure_code: null,
    retry_after_seconds: null,
  },
  trend,
};

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe("ProjectRiskTrendsPanel", () => {
  it("presents the same facts for three profiles with denominators and accessible navigation", async () => {
    const open = vi.fn();
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(response(readyView))));
    const view = render(<ProjectRiskTrendsPanel onOpenProject={open} />);

    expect(await screen.findByText("Payments API")).toBeInTheDocument();
    expect(screen.getByText("New high/critical")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Security" }));
    expect(screen.getByText("Known exploited")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Executive" }));
    expect(screen.getByText("Without recent analysis")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Open project" }));
    expect(open).toHaveBeenCalledWith(expect.objectContaining({ project: expect.objectContaining({ name: "Payments API" }) }));
    fireEvent.click(screen.getByText("Denominators, exclusions and limitations"));
    expect(screen.getByText(/coverage changed: 1/i)).toBeInTheDocument();
    expect((await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("uses closed body-only period controls and preserves an actionable error state", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(response(readyView)).mockResolvedValueOnce(response({ detail: "temporarily unavailable" }, 503));
    vi.stubGlobal("fetch", fetchMock);
    render(<ProjectRiskTrendsPanel onOpenProject={vi.fn()} />);
    await screen.findByText("Payments API");
    fireEvent.change(screen.getByLabelText("Period"), { target: { value: "30" } });
    fireEvent.change(screen.getByLabelText("Bucket"), { target: { value: "30" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply period" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/temporarily unavailable/i);
    expect(new URL(String(fetchMock.mock.calls[1][0])).search).toBe("");
    expect(JSON.parse(String(fetchMock.mock.calls[1][1]?.body))).toEqual({ period_days: 30, bucket_days: 30 });
  });

  it("requires project-name confirmation before exporting the selected profile", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(readyView))
      .mockResolvedValueOnce(response("{}", 200, {
        "content-type": "application/json", "content-disposition": 'attachment; filename="inspectra-risk-trends-security.json"',
        "x-inspectra-snapshot-sha256": "d".repeat(64),
      }));
    vi.stubGlobal("fetch", fetchMock);
    const create = vi.fn(() => "blob:test");
    const revoke = vi.fn();
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: create });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revoke });
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    render(<ProjectRiskTrendsPanel onOpenProject={vi.fn()} />);
    await screen.findByText("Payments API");
    fireEvent.click(screen.getByRole("tab", { name: "Security" }));
    const exportButton = screen.getByRole("button", { name: "JSON" });
    expect(exportButton).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/confirm this export/i));
    fireEvent.click(exportButton);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(JSON.parse(String(fetchMock.mock.calls[1][1]?.body))).toEqual(expect.objectContaining({ profile: "security", report_format: "json", project_metadata_confirmed: true }));
    expect(await screen.findByText(/SHA-256 d{64}/)).toBeInTheDocument();
    expect(create).toHaveBeenCalled();
    expect(revoke).toHaveBeenCalledWith("blob:test");
  });

  it("labels failed stale data and prevents exporting it as current", async () => {
    const failedView: RiskTrendViewResponse = {
      ...readyView,
      materialization: {
        ...readyView.materialization,
        state: "failed",
        data_state: "stale",
        retryable: true,
        failure_code: "rebuild_failed",
      },
    };
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(response(failedView))));
    render(<ProjectRiskTrendsPanel onOpenProject={vi.fn()} />);

    expect(await screen.findByRole("alert")).toHaveTextContent(/refresh failed/i);
    expect(screen.getByText(/stale facts are never exported as fresh/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/confirm this export/i)).toBeDisabled();
    expect(screen.getByRole("button", { name: "Retry refresh" })).toBeEnabled();
  });
});
