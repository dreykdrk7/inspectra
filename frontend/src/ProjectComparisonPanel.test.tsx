import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ProjectComparisonPanel } from "./ProjectComparisonPanel";
import type { ProjectAnalysisComparisonResponse, ProjectAnalysisCoverage, ProjectSummary } from "./types";

const executionProfile = {
  contract_version: "2026-09-05.1",
  profile_name: "project_archive_basic",
  ruleset_version: "2026-09-05.1",
  max_upload_bytes: 20971520,
  audit_max_concurrency: 4
} as const;

const baseAnalysis = {
  id: "analysis-base",
  project_id: "project-1",
  source_reference: "snapshot-aaaaaaaaaaaaaaaa",
  analysis_profile: "project_archive_basic",
  audit_type: "project_archive_basic",
  file_id: "file-1",
  target_url: null,
  target_domain: null,
  status: "completed",
  created_at: "2026-09-05T09:00:00Z",
  updated_at: "2026-09-05T09:00:00Z",
  source_file_deleted_at: null,
  execution_profile: executionProfile,
  summary: null
} as const;

const targetAnalysis = {
  ...baseAnalysis,
  id: "analysis-target",
  source_reference: "snapshot-bbbbbbbbbbbbbbbb",
  created_at: "2026-09-05T10:00:00Z",
  updated_at: "2026-09-05T10:00:00Z"
} as const;

const project = {
  project: {
    source_metadata_contract_version: "2026-09-06.1",
    source_name_disclosure: "withheld_use_files_view",
    source_digest_disclosure: "retained_server_side",
    id: "project-1",
    name: "Demo project",
    source_reference: "snapshot-bbbbbbbbbbbbbbbb",
    source_file_deleted_at: null,
    latest_job_id: targetAnalysis.id,
    baseline_analysis_id: null,
    baseline_version: 0,
    baseline_updated_at: null,
    analysis_count: 2,
    created_at: "2026-09-05T09:00:00Z",
    updated_at: "2026-09-05T10:00:00Z"
  },
  latest_job: targetAnalysis
} satisfies ProjectSummary;

const comparisonPayload = {
  project: project.project,
  base_analysis: baseAnalysis,
  target_analysis: targetAnalysis,
  state: "ready",
  summary: { new: 1, resolved: 1, persistent: 1 },
  limitations: ["At least one selected analysis reached a configured limit; comparison counts may be incomplete."],
  comparisons: [
    {
      status: "new",
      finding: {
        id: "new-finding",
        rule_id: "new_rule",
        source_audit_type: "project_archive_basic",
        title: "New finding",
        category: "configuration",
        severity: "high",
        confidence: "high",
        description: "New indicator.",
        evidence: "config/new.py: [REDACTED]",
        location: { path: "config/new.py", line: 5 },
        recommendation: "Review the new setting.",
        references: []
      },
      previous_finding: null,
      changed_fields: []
    },
    {
      status: "resolved",
      finding: {
        id: "resolved-finding",
        rule_id: "resolved_rule",
        source_audit_type: "project_archive_basic",
        title: "Resolved finding",
        category: "configuration",
        severity: "medium",
        confidence: "high",
        description: "Resolved indicator.",
        evidence: "config/old.py: [REDACTED]",
        location: { path: "config/old.py", line: 2 },
        recommendation: "Keep the fix.",
        references: []
      },
      previous_finding: null,
      changed_fields: []
    },
    {
      status: "persistent",
      finding: {
        id: "persistent-finding",
        rule_id: "persistent_rule",
        source_audit_type: "project_archive_basic",
        title: "Persistent setting",
        category: "configuration",
        severity: "high",
        confidence: "high",
        description: "Persistent indicator.",
        evidence: "config/settings.py: [REDACTED]",
        location: null,
        location_status: "withheld_unsafe_path",
        recommendation: "Review the setting.",
        references: []
      },
      previous_finding: {
        id: "persistent-finding",
        rule_id: "persistent_rule",
        source_audit_type: "project_archive_basic",
        title: "Persistent setting",
        category: "configuration",
        severity: "medium",
        confidence: "high",
        description: "Persistent indicator.",
        evidence: "config/settings.py: [REDACTED]",
        location: null,
        location_status: "withheld_unsafe_path",
        recommendation: "Review the setting.",
        references: []
      },
      changed_fields: ["severity"],
      lifecycle: {
        finding_id: "persistent-finding",
        rule_id: "persistent_rule",
        current_status: "in_review",
        has_decision: true,
        needs_review: false,
        current_decision: {
          contract_version: "2026-09-06.1",
          id: "d".repeat(32),
          organization_id: "local-admin",
          project_id: "c".repeat(32),
          finding_id: "persistent-finding",
          rule_id: "persistent_rule",
          status: "in_review",
          reason: "Validate the persistent setting",
          comment: null,
          assignee_user_id: null,
          assignee_username: null,
          actor_id: "local-admin",
          actor_username: "local-admin",
          actor_role: "administrator",
          review_at: null,
          created_at: "2026-09-05T10:15:00Z",
          previous_decision_id: null
        },
        history: []
      }
    }
  ],
  uses_saved_baseline: false,
  public_vulnerability_comparison: {
    state: "not_available",
    base_snapshot_id: null,
    target_snapshot_id: null,
    summary: { new: 0, resolved: 0, persistent: 0 },
    comparisons: [],
    limitations: ["No retained OSV snapshot is available for the baseline and comparison analysis."]
  }
} satisfies ProjectAnalysisComparisonResponse;

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("ProjectComparisonPanel", () => {
  it("resolves an old saved baseline directly and pages older retained analyses without a URL cursor", async () => {
    const savedProject = {
      ...project,
      project: {
        ...project.project,
        baseline_analysis_id: baseAnalysis.id,
        baseline_version: 7,
        baseline_updated_at: "2026-09-05T10:30:00Z",
        analysis_count: 52,
      },
    } satisfies ProjectSummary;
    const recent = Array.from({ length: 50 }, (_, index) => ({
      ...targetAnalysis,
      id: index === 0 ? targetAnalysis.id : `analysis-recent-${index}`,
      created_at: new Date(Date.parse(targetAnalysis.created_at) - index * 1_000).toISOString(),
      updated_at: new Date(Date.parse(targetAnalysis.updated_at) - index * 1_000).toISOString(),
    }));
    const fetchMock = vi.fn((url: string, init?: RequestInit) => {
      if (url.endsWith("/projects/project-1/analyses/search")) {
        const body = JSON.parse(String(init?.body));
        return Promise.resolve(jsonResponse(body.cursor
          ? { contract_version: "2026-09-08.1", items: [baseAnalysis, { ...baseAnalysis, id: "analysis-old-2" }], returned_count: 2, total_count: 52, has_more: false, next_cursor: null }
          : { contract_version: "2026-09-08.1", items: recent, returned_count: 50, total_count: 52, has_more: true, next_cursor: "signed-next-page" }));
      }
      if (url.endsWith("/projects/project-1/analyses/analysis-base")) {
        return Promise.resolve(jsonResponse(baseAnalysis));
      }
      if (url.includes("/projects/project-1/comparisons?")) {
        return Promise.resolve(jsonResponse({ ...comparisonPayload, project: savedProject.project, uses_saved_baseline: true }));
      }
      return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);

    const { container } = render(
      <ProjectComparisonPanel project={savedProject} onOpenAnalysis={vi.fn()} onRequestNewSnapshot={vi.fn()} />
    );

    expect(await screen.findByText(/Saved project baseline:.*policy version 7/)).toBeInTheDocument();
    expect(screen.getByText("Showing 51 of 52 retained analyses in this selector.")).toBeInTheDocument();
    expect(screen.getByLabelText("Baseline analysis")).toHaveValue(baseAnalysis.id);
    expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith("/analyses/analysis-base"))).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: "Load older analyses" }));

    expect(await screen.findByRole("button", { name: "All retained analyses loaded" })).toBeDisabled();
    expect(screen.getByText("Showing 52 of 52 retained analyses in this selector.")).toBeInTheDocument();
    const continuation = fetchMock.mock.calls.find(([, init]) => String((init as RequestInit | undefined)?.body).includes("signed-next-page"));
    expect(String(continuation?.[0])).not.toContain("signed-next-page");
    expect(JSON.parse(String((continuation?.[1] as RequestInit).body))).toEqual({ page_size: 50, cursor: "signed-next-page" });
    expect((await axe.run(container)).violations).toEqual([]);
  });

  it("compares two own snapshots, shows limitations, and opens safe redacted evidence", async () => {
    const onOpenAnalysis = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string, init?: RequestInit) => {
        if (url.endsWith("/projects/project-1/analyses")) {
          return Promise.resolve(jsonResponse([targetAnalysis, baseAnalysis]));
        }
        if (url.endsWith("/projects/project-1/baseline") && init?.method === "POST") {
          return Promise.resolve(jsonResponse({ ...project.project, baseline_analysis_id: baseAnalysis.id, baseline_version: 1 }));
        }
        if (url.endsWith("/projects/project-1/baseline") && init?.method === "DELETE") {
          return Promise.resolve(jsonResponse({ ...project.project, baseline_analysis_id: null, baseline_version: 2 }));
        }
        if (url.includes("/projects/project-1/comparisons?")) {
          return Promise.resolve(jsonResponse(comparisonPayload));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<ProjectComparisonPanel project={project} onOpenAnalysis={onOpenAnalysis} onRequestNewSnapshot={vi.fn()} />);

    expect(await screen.findByRole("heading", { name: "Analysis comparison" })).toBeInTheDocument();
    expect(screen.getByText("New findings")).toBeInTheDocument();
    expect(screen.getByText("Resolved findings")).toBeInTheDocument();
    expect(screen.getByText("Persistent findings")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Public vulnerability intelligence" })).toBeInTheDocument();
    expect(screen.getByText("Public advisory comparison is not available for these analyses.")).toBeInTheDocument();
    expect(screen.getByText(/comparison counts may be incomplete/)).toBeInTheDocument();
    expect(screen.getByText("medium → high")).toBeInTheDocument();
    expect(screen.getByText(/No saved project baseline/)).toBeInTheDocument();

    fireEvent.click(screen.getByText("Persistent setting"));
    expect(screen.getAllByText("config/settings.py: [REDACTED]")).toHaveLength(2);
    expect(screen.getByText("Changed:")).toBeInTheDocument();
    expect(screen.getByText("Validate the persistent setting")).toBeInTheDocument();
    expect(screen.getAllByText("In review").length).toBeGreaterThan(0);
    expect(screen.getByText("Withheld: unsafe path reported by analyzer")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Open baseline" }));
    fireEvent.click(screen.getByRole("button", { name: "Open comparison" }));
    expect(onOpenAnalysis).toHaveBeenNthCalledWith(1, "analysis-base");
    expect(onOpenAnalysis).toHaveBeenNthCalledWith(2, "analysis-target");

    fireEvent.change(screen.getByLabelText("Comparison analysis"), { target: { value: "analysis-base" } });
    expect(screen.getByText("Choose two different completed analyses to start a comparison.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Save selected baseline" }));
    await waitFor(() => {
      expect(screen.getByText("Saved baseline updated (policy version 1).")).toBeInTheDocument();
    });
    const baselineRequest = vi.mocked(globalThis.fetch).mock.calls.find(([url, init]) =>
      String(url).endsWith("/projects/project-1/baseline") && (init as RequestInit | undefined)?.method === "POST"
    );
    expect(JSON.parse(String((baselineRequest?.[1] as RequestInit).body))).toEqual({
      analysis_id: "analysis-base",
      baseline_confirmed: true
    });

    fireEvent.click(screen.getByRole("button", { name: "Clear saved baseline" }));
    await waitFor(() => {
      expect(screen.getByText("Saved baseline cleared (policy version 2).")).toBeInTheDocument();
    });
  });

  it("shows NVD as changed CVE evidence without treating CPE as package applicability", async () => {
    const publicFinding = {
      id: "pvf-nvd",
      fingerprint_version: "2026-09-05.1",
      provider: "osv" as const,
      advisory_id: "CVE-2025-1234",
      aliases: ["CVE-2025-1234"],
      ecosystem: "npm" as const,
      component_name: "react",
      component_version: "18.3.1",
      package_url: "pkg:npm/react@18.3.1",
      component_identity_provenance: "npm_registry_lockfile" as const,
      dependency_scope: "direct" as const,
      relationship_status: "reported" as const,
      affected_ranges: [],
      fixed_versions: ["18.3.2"],
      severity: [],
      corroborations: [],
      source_consensus: "osv_only" as const,
      source_conflicts: [],
      kev_signals: [],
      vendor_bulletins: [],
      cvss_base_score: null,
      cvss_band: "unknown" as const,
      cvss_score_status: "not_available" as const,
      references: [],
      published_at: null,
      updated_at: null,
      recommendation: "Review the exact OSV match.",
      evidence_digest: "a".repeat(64),
    };
    const nvdFinding = {
      ...publicFinding,
      nvd_evidence: [{
        provider: "nvd" as const,
        contract_version: "2026-09-09.1",
        cve_id: "CVE-2025-1234",
        status: "analyzed" as const,
        severity: [],
        cwes: ["CWE-79"],
        cpe_status: "present_unmapped" as const,
        cpe_match_count: 1,
        references: [{ type: "source" as const, url: "https://nvd.nist.gov/vuln/detail/CVE-2025-1234" }],
        published_at: "2025-01-02T03:04:05Z",
        updated_at: "2025-02-03T04:05:06Z",
        evidence_digest: "b".repeat(64),
      }],
    };
    const payload = {
      ...comparisonPayload,
      public_vulnerability_comparison: {
        state: "ready" as const,
        base_snapshot_id: "c".repeat(32),
        target_snapshot_id: "d".repeat(32),
        summary: { new: 0, resolved: 0, persistent: 1 },
        comparisons: [{
          status: "persistent" as const,
          finding: nvdFinding,
          previous_finding: publicFinding,
          changed_fields: ["nvd_evidence"],
        }],
        limitations: [],
      },
    } satisfies ProjectAnalysisComparisonResponse;
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([targetAnalysis, baseAnalysis]));
      if (url.includes("/projects/project-1/comparisons?")) return Promise.resolve(jsonResponse(payload));
      return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
    }));

    render(<ProjectComparisonPanel project={project} onOpenAnalysis={vi.fn()} onRequestNewSnapshot={vi.fn()} />);

    expect((await screen.findByText(/NVD CVE evidence:/)).closest("p")).toHaveTextContent("CVE-2025-1234");
    expect(screen.getByText(/CPE records remain deliberately unmapped/i)).toBeInTheDocument();
    expect(screen.getByText(/Evidence updated:/).closest("p")).toHaveTextContent("nvd evidence");
  });

  it("defaults a retained saved baseline for future comparisons", async () => {
    const savedProject = {
      ...project,
      project: {
        ...project.project,
        baseline_analysis_id: baseAnalysis.id,
        baseline_version: 4,
        baseline_updated_at: "2026-09-05T10:30:00Z"
      }
    } satisfies ProjectSummary;
    const fetchMock = vi.fn((url: string) => {
      if (url.endsWith("/projects/project-1/analyses")) {
        return Promise.resolve(jsonResponse([targetAnalysis, baseAnalysis]));
      }
      if (url.includes("/projects/project-1/comparisons?")) {
        return Promise.resolve(jsonResponse({ ...comparisonPayload, project: savedProject.project, uses_saved_baseline: true }));
      }
      return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<ProjectComparisonPanel project={savedProject} onOpenAnalysis={vi.fn()} onRequestNewSnapshot={vi.fn()} />);

    expect(await screen.findByText(/Saved project baseline:.*policy version 4/)).toBeInTheDocument();
    expect(screen.getByText("Saved project baseline", { exact: true })).toBeInTheDocument();
    expect(
      fetchMock.mock.calls.some(([url]) =>
        String(url).includes("base_analysis_id=analysis-base") && String(url).includes("target_analysis_id=analysis-target")
      )
    ).toBe(true);
  });

  it("shows a controlled error when a selected comparison is unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) {
          return Promise.resolve(jsonResponse([targetAnalysis, baseAnalysis]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<ProjectComparisonPanel project={project} onOpenAnalysis={() => undefined} onRequestNewSnapshot={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("This project analysis is no longer available.");
    });
  });

  it("shows changed recorded coverage and withholds resolution counts", async () => {
    const coverage = {
      coverage_status: "complete",
      total_entries_seen: 8,
      supported_manifests_found: 2,
      supported_manifests_parsed: 2,
      supported_manifests_skipped: 0,
      unsupported_manifests_detected: 0,
      lockfiles_detected: 2,
      lockfiles_parsed: 2,
      lockfiles_skipped: 0,
      total_dependencies: 4,
      source_retained: true,
      limitations: []
    } satisfies ProjectAnalysisCoverage;
    const reducedComparison = {
      ...comparisonPayload,
      state: "not_comparable",
      summary: { new: 0, resolved: 0, persistent: 0 },
      comparisons: [],
      limitations: ["The selected analyses have different recorded coverage or analysis limits; findings cannot be classified as resolved or new."],
      coverage_comparison: {
        status: "changed",
        base: coverage,
        target: {
          ...coverage,
          coverage_status: "partial",
          supported_manifests_parsed: 1,
          supported_manifests_skipped: 1,
          lockfiles_parsed: 1,
          lockfiles_skipped: 1,
          limitations: ["supported_manifests_not_parsed", "lockfiles_not_parsed"]
        },
        changed_metrics: ["supported_manifests_parsed", "lockfiles_parsed"]
      }
    } satisfies ProjectAnalysisComparisonResponse;

    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) {
          return Promise.resolve(jsonResponse([targetAnalysis, baseAnalysis]));
        }
        if (url.includes("/projects/project-1/comparisons?")) {
          return Promise.resolve(jsonResponse(reducedComparison));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<ProjectComparisonPanel project={project} onOpenAnalysis={vi.fn()} onRequestNewSnapshot={vi.fn()} />);

    expect(await screen.findByRole("heading", { name: "Recorded analysis coverage" })).toBeInTheDocument();
    expect(screen.getAllByText(/different recorded coverage or analysis limits/)).toHaveLength(2);
    expect(screen.getByText("Changed:")).toBeInTheDocument();
    expect(screen.getByText(/supported manifests parsed, lockfiles parsed/)).toBeInTheDocument();
    expect(screen.getAllByText("1 of 2")).toHaveLength(2);
    expect(screen.queryByRole("heading", { name: "Resolved findings" })).not.toBeInTheDocument();
  });
});
