import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ProjectFindingsPanel } from "./ProjectFindingsPanel";
import type { ProjectFindingsResponse, ProjectSummary } from "./types";

const project = {
  project: {
    source_metadata_contract_version: "2026-09-06.1",
    source_name_disclosure: "withheld_use_files_view",
    source_digest_disclosure: "retained_server_side",
    id: "project-1",
    name: "Demo project",
    source_reference: "snapshot-aaaaaaaaaaaaaaaa",
    source_file_deleted_at: null,
    latest_job_id: "analysis-1",
    analysis_count: 1,
    created_at: "2026-09-05T09:00:00Z",
    updated_at: "2026-09-05T09:01:00Z"
  },
  latest_job: {
    id: "analysis-1",
    project_id: "project-1",
    source_reference: "snapshot-aaaaaaaaaaaaaaaa",
    analysis_profile: "project_archive_basic",
    audit_type: "project_archive_basic",
    file_id: "file-1",
    target_url: null,
    target_domain: null,
    status: "completed",
    created_at: "2026-09-05T09:00:00Z",
    updated_at: "2026-09-05T09:01:00Z",
    source_file_deleted_at: null,
    summary: null
  }
} satisfies ProjectSummary;

const findingsPayload = {
  project: project.project,
  analysis: project.latest_job,
  state: "ready",
  summary: {
    total: 2,
    by_severity: { critical: 0, high: 1, medium: 1, low: 0, info: 0 },
    by_category: { configuration: 1, dependency_hygiene: 1 }
  },
  result_truncated: true,
  coverage: {
    coverage_status: "partial",
    total_entries_seen: 12,
    supported_manifests_found: 3,
    supported_manifests_parsed: 1,
    supported_manifests_skipped: 2,
    unsupported_manifests_detected: 0,
    lockfiles_detected: 2,
    lockfiles_parsed: 1,
    lockfiles_skipped: 1,
    total_dependencies: 4,
    source_retained: false,
    limitations: ["analysis_limit_reached", "source_removed"]
  },
  findings: [
    {
      id: "finding-1",
      rule_id: "configuration_debug_enabled",
      source_audit_type: "project_archive_basic",
      title: "Review production setting",
      category: "configuration",
      severity: "high",
      confidence: "high",
      description: "A production setting needs review.",
      evidence: "settings.py: DEBUG=[REDACTED]",
      location: { path: "config/settings.py", line: 8 },
      recommendation: "Use a reviewed production setting.",
      references: [
        { type: "ghsa", id: "GHSA-abcd-1234-efgh", url: "https://github.com/advisories/GHSA-abcd-1234-efgh" },
        { type: "cve", id: "CVE-2026-0001", url: "https://example.test/CVE-2026-0001" }
      ]
    },
    {
      id: "finding-2",
      rule_id: "dependency_not_exactly_pinned",
      source_audit_type: "project_archive_basic",
      title: "Dependency is not exactly pinned",
      category: "dependency_hygiene",
      severity: "medium",
      confidence: "medium",
      description: "Version coverage is broad.",
      evidence: "requirements.txt: package>=1",
      location: { path: "requirements.txt", line: null },
      recommendation: "Use a reviewed exact version.",
      references: []
    }
  ]
} satisfies ProjectFindingsResponse;

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("ProjectFindingsPanel", () => {
  it("loads a redacted result, filters it, opens detail, and rejects an unsafe reference link", async () => {
    const onOpenAnalysis = vi.fn();
    const onRequestNewSnapshot = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) {
          return Promise.resolve(jsonResponse([project.latest_job]));
        }
        if (url.endsWith("/projects/project-1/findings?analysis_id=analysis-1")) {
          return Promise.resolve(jsonResponse(findingsPayload));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<ProjectFindingsPanel project={project} onOpenAnalysis={onOpenAnalysis} onRequestNewSnapshot={onRequestNewSnapshot} />);

    expect(await screen.findByRole("heading", { name: "Findings: Demo project" })).toBeInTheDocument();
    expect(screen.getByText(/This review reached a configured analysis limit/)).toBeInTheDocument();
    expect(screen.getByText("Review production setting")).toBeInTheDocument();
    expect(screen.getByText("Dependency is not exactly pinned")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Review production setting/ }));
    expect(screen.getByText("settings.py: DEBUG=[REDACTED]")).toBeInTheDocument();
    expect(screen.getByText("config/settings.py:8")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /GHSA: GHSA-abcd-1234-efgh/ })).toHaveAttribute(
      "href",
      "https://github.com/advisories/GHSA-abcd-1234-efgh"
    );
    expect(screen.getByRole("link", { name: "Minimal MARKDOWN" })).toHaveAttribute(
      "href",
      "http://localhost:8000/projects/project-1/analyses/analysis-1/report/markdown"
    );
    expect(screen.getByRole("link", { name: "Minimal HTML" })).toHaveAttribute(
      "href",
      "http://localhost:8000/projects/project-1/analyses/analysis-1/report/html"
    );
    expect(screen.getByRole("link", { name: "Minimal PDF" })).toHaveAttribute(
      "href",
      "http://localhost:8000/projects/project-1/analyses/analysis-1/report/pdf"
    );
    expect(screen.queryByText(/CVE: CVE-2026-0001/)).not.toBeInTheDocument();
    expect(screen.getByText(/not an exploitation verdict/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Review a new archive snapshot" }));
    expect(onRequestNewSnapshot).toHaveBeenCalledOnce();

    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "low" } });
    expect(screen.getByText(/No findings match these filters/)).toBeInTheDocument();
    expect(screen.getByText(/Showing 0 of 2 project findings/)).toHaveAttribute("role", "status");
    fireEvent.click(screen.getByRole("button", { name: "Clear finding filters" }));
    await waitFor(() => expect(screen.getByLabelText("Search findings")).toHaveFocus());
    expect(screen.getByText(/Showing 2 of 2 project findings/)).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "Project finding filters" })).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Filtered project findings" })).toHaveAttribute("aria-describedby", "project-finding-filter-status");

    fireEvent.click(screen.getByRole("button", { name: "Open full analysis" }));
    expect(onOpenAnalysis).toHaveBeenCalledWith("analysis-1");
    expect((await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("keeps minimal reports as direct defaults and gates technical downloads with an explicit confirmation", async () => {
    const fetchMock = vi.fn((url: string, init?: RequestInit) => {
      if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
      if (url.endsWith("/projects/project-1/findings?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(findingsPayload));
      if (url.endsWith("/projects/project-1/analyses/analysis-1/report/pdf") && init?.method === "POST") {
        return Promise.resolve(new Response("%PDF-1.4", {
          headers: {
            "content-type": "application/pdf",
            "content-disposition": 'attachment; filename="inspectra-project-project-1-analysis-analysis-1.pdf"',
          },
        }));
      }
      return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("URL", { ...URL, createObjectURL: vi.fn(() => "blob:technical-report"), revokeObjectURL: vi.fn() });
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);

    const view = render(<ProjectFindingsPanel project={project} onOpenAnalysis={() => undefined} onRequestNewSnapshot={vi.fn()} />);

    expect(await screen.findByText(/Minimal report excludes names, paths, evidence and component identities/)).toBeInTheDocument();
    fireEvent.click(screen.getByText("Technical report options"));
    const technicalPdf = screen.getByRole("button", { name: "Technical PDF" });
    expect(technicalPdf).toBeDisabled();
    fireEvent.click(screen.getByLabelText(/I understand this report contains technical project metadata/));
    fireEvent.click(technicalPdf);
    expect(await screen.findByText("Technical PDF report downloaded.")).toBeInTheDocument();
    const reportCall = fetchMock.mock.calls.find(([url, init]) => String(url).endsWith("/report/pdf") && init?.method === "POST");
    expect(reportCall).toBeDefined();
    expect(JSON.parse(String(reportCall?.[1]?.body))).toEqual({
      profile: "technical",
      technical_detail_confirmed: true,
    });
    expect((await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("does not offer a technical report action to a team reader", async () => {
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
      if (url.endsWith("/projects/project-1/findings?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(findingsPayload));
      return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
    }));

    render(<ProjectFindingsPanel project={project} onOpenAnalysis={() => undefined} onRequestNewSnapshot={vi.fn()} teamMode currentRole="reader" />);

    await screen.findByText(/Minimal report excludes/);
    fireEvent.click(screen.getByText("Technical report options"));
    expect(screen.getByText(/A maintainer or administrator must confirm this export/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Technical PDF" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Minimal PDF" })).toBeInTheDocument();
  });

  it("shows an actionable error when the findings request is unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) {
          return Promise.resolve(jsonResponse([project.latest_job]));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<ProjectFindingsPanel project={project} onOpenAnalysis={() => undefined} onRequestNewSnapshot={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("This project analysis is no longer available.");
    });
  });

  it.each([
    ["failed", "analysis_failed", "Analysis failed without a usable result"],
    ["cancelled", "analysis_cancelled", "Analysis was cancelled"],
  ] as const)("renders an accessible %s terminal state without calling it active", async (status, responseState, title) => {
    const terminalAnalysis = { ...project.latest_job, status };
    const terminalPayload: ProjectFindingsResponse = {
      project: project.project,
      analysis: terminalAnalysis,
      state: responseState,
      findings: [],
      summary: { total: 0, by_severity: {}, by_category: {} },
      result_truncated: false,
      coverage: null,
      lifecycle: {},
    };
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([terminalAnalysis]));
        if (url.endsWith("/projects/project-1/findings?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(terminalPayload));
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    const view = render(<ProjectFindingsPanel project={{ ...project, latest_job: terminalAnalysis }} onOpenAnalysis={() => undefined} onRequestNewSnapshot={vi.fn()} />);

    expect(await screen.findByText(title)).toBeInTheDocument();
    expect(screen.getByText(/Choose a completed snapshot above/)).toBeInTheDocument();
    expect(screen.queryByText(/still queued or running/i)).not.toBeInTheDocument();
    expect((await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("labels a withheld unsafe location without rendering the original path", async () => {
    const withheldPayload = {
      ...findingsPayload,
      findings: [
        {
          ...findingsPayload.findings[0],
          location: null,
          location_status: "withheld_unsafe_path" as const
        }
      ]
    } satisfies ProjectFindingsResponse;
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) {
          return Promise.resolve(jsonResponse([project.latest_job]));
        }
        if (url.endsWith("/projects/project-1/findings?analysis_id=analysis-1")) {
          return Promise.resolve(jsonResponse(withheldPayload));
        }
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      })
    );

    render(<ProjectFindingsPanel project={project} onOpenAnalysis={() => undefined} onRequestNewSnapshot={vi.fn()} />);

    fireEvent.click(await screen.findByRole("button", { name: /Review production setting/ }));
    expect(screen.getByText("Withheld: unsafe path reported by analyzer")).toBeInTheDocument();
    expect(screen.queryByText("/srv/inspectra/customer/settings.py")).not.toBeInTheDocument();
  });

  it("filters by workflow and keeps the latest justified decision with the finding", async () => {
    const decision = {
      contract_version: "2026-09-06.1" as const,
      id: "d".repeat(32),
      organization_id: "local-admin",
      project_id: "project-1",
      finding_id: "finding-1",
      rule_id: "configuration_debug_enabled",
      status: "resolved" as const,
      reason: "Verified in the replacement snapshot",
      comment: null,
      assignee_user_id: null,
      assignee_username: null,
      actor_id: "local-admin",
      actor_username: "local-admin",
      actor_role: "administrator",
      review_at: null,
      created_at: "2026-09-06T10:00:00Z",
      previous_decision_id: null,
    };
    const workflowPayload = {
      ...findingsPayload,
      summary: {
        ...findingsPayload.summary,
        by_status: { open: 1, in_review: 0, accepted: 0, false_positive: 0, resolved: 1 },
        needs_review: 0,
      },
      lifecycle: {
        "finding-1": {
          finding_id: "finding-1",
          rule_id: decision.rule_id,
          current_status: "resolved" as const,
          has_decision: true,
          needs_review: false,
          current_decision: decision,
          history: [decision],
        },
      },
    } satisfies ProjectFindingsResponse;
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/projects/project-1/analyses")) return Promise.resolve(jsonResponse([project.latest_job]));
        if (url.endsWith("/projects/project-1/findings?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(workflowPayload));
        return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
      }),
    );

    render(<ProjectFindingsPanel project={project} onOpenAnalysis={() => undefined} onRequestNewSnapshot={vi.fn()} />);
    await screen.findByText(/1 resolved/);
    fireEvent.change(screen.getByLabelText("Workflow status"), { target: { value: "resolved" } });
    expect(screen.getByText("Review production setting")).toBeInTheDocument();
    expect(screen.queryByText("Dependency is not exactly pinned")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Review production setting/ }));
    expect(screen.getAllByText("Verified in the replacement snapshot")).toHaveLength(2);
    expect(screen.getByText("Decision history (1)")).toBeInTheDocument();
  });

  it("pages older analysis choices and keeps loaded findings usable", async () => {
    const older = {
      ...project.latest_job,
      id: "analysis-old",
      source_reference: "snapshot-bbbbbbbbbbbbbbbb",
      created_at: "2026-08-01T09:00:00Z",
      updated_at: "2026-08-01T09:01:00Z",
    };
    const recent = Array.from({ length: 50 }, (_, index) => ({
      ...project.latest_job,
      id: index === 0 ? "analysis-1" : `analysis-recent-${index}`,
      created_at: new Date(Date.parse(project.latest_job!.created_at) - index * 1_000).toISOString(),
      updated_at: new Date(Date.parse(project.latest_job!.updated_at) - index * 1_000).toISOString(),
    }));
    let continuationAttempts = 0;
    vi.stubGlobal("fetch", vi.fn((url: string, init?: RequestInit) => {
      if (url.endsWith("/projects/project-1/analyses/search")) {
        const body = JSON.parse(String(init?.body));
        if (body.cursor && ++continuationAttempts === 1) {
          return Promise.resolve(jsonResponse({ detail: "temporarily unavailable" }, 503));
        }
        return Promise.resolve(jsonResponse(body.cursor
          ? { contract_version: "2026-09-08.1", items: [older], returned_count: 1, total_count: 51, has_more: false, next_cursor: null }
          : { contract_version: "2026-09-08.1", items: recent, returned_count: 50, total_count: 51, has_more: true, next_cursor: "older-page" }));
      }
      if (url.includes("/findings?analysis_id=analysis-old")) {
        return Promise.resolve(jsonResponse({ ...findingsPayload, analysis: older, findings: [] }));
      }
      if (url.includes("/findings?analysis_id=analysis-1")) return Promise.resolve(jsonResponse(findingsPayload));
      return Promise.resolve(jsonResponse({ detail: "Not found" }, 404));
    }));

    render(<ProjectFindingsPanel project={project} onOpenAnalysis={() => undefined} onRequestNewSnapshot={vi.fn()} />);

    expect(await screen.findByText("Showing 50 of 51 retained analyses in this selector.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Load older analyses" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("The loaded snapshots remain available");
    expect(screen.getByLabelText("Analysis snapshot").querySelectorAll("option")).toHaveLength(50);
    fireEvent.click(screen.getByRole("button", { name: "Load older analyses" }));
    expect(await screen.findByRole("button", { name: "All retained analyses loaded" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Analysis snapshot"), { target: { value: "analysis-old" } });
    await waitFor(() => expect(screen.getByLabelText("Analysis snapshot")).toHaveValue("analysis-old"));
  });
});
