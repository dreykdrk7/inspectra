import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { RemediationCenterPanel } from "./RemediationCenterPanel";
import type { RemediationActionGroup, RemediationPage, RemediationPlanJob } from "./types";


function response(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

function group(overrides: Partial<RemediationActionGroup> = {}): RemediationActionGroup {
  return {
    id: "a".repeat(64),
    revision: "b".repeat(64),
    evidence_kind: "public_vulnerability",
    title: "Update public-package for CVE-2026-1000",
    ecosystem: "npm",
    component_name: "public-package",
    advisory_ids: ["CVE-2026-1000", "GHSA-AAAA-BBBB-CCCC"],
    observed_versions: ["1.0.0"],
    affected_ranges: [{ type: "SEMVER", introduced: "0", fixed: "2.0.0", last_affected: null, expression: null }],
    fixed_versions: ["2.0.0"],
    recommended_fixed_version: "2.0.0",
    recommendation: "Upgrade with the normal dependency workflow, then run a comparable analysis.",
    priority: "urgent",
    priority_reasons: ["known_exploited", "critical", "direct_dependency"],
    highest_severity: "critical",
    known_exploited: true,
    source_conflict: false,
    exposure_state: "not_assessed",
    dependency_scopes: ["direct"],
    affected_project_count: 1,
    occurrence_count: 1,
    occurrences: [{
      project: {
        source_metadata_contract_version: "2026-09-06.1",
        source_name_disclosure: "withheld_use_files_view",
        source_digest_disclosure: "retained_server_side",
        id: "1".repeat(32),
        name: "Payments API",
        source_reference: "snapshot-safe",
        source_file_deleted_at: null,
        latest_job_id: "2".repeat(32),
        baseline_analysis_id: null,
        baseline_version: 0,
        baseline_updated_at: null,
        analysis_count: 1,
        source_snapshots: [],
        created_at: "2026-09-09T09:00:00Z",
        updated_at: "2026-09-09T10:00:00Z",
      },
      analysis: {
        id: "2".repeat(32), project_id: "1".repeat(32), audit_type: "project_archive_basic", target_url: null, target_domain: null,
        analysis_profile: "project_archive_basic", status: "completed", source_reference: "snapshot-safe", source_file_deleted_at: null,
        created_at: "2026-09-09T09:00:00Z", updated_at: "2026-09-09T10:00:00Z", started_at: null, finished_at: "2026-09-09T10:00:00Z",
        termination_reason: "completed", retry_of_job_id: null, summary: null,
      },
      finding_id: "pvf_" + "3".repeat(64),
      rule_id: "public_vulnerability:CVE-2026-1000",
      evidence_kind: "public_vulnerability",
      observed_version: "1.0.0",
      dependency_scope: "direct",
      relationship_status: "reported",
      workflow_state: "open",
      workflow_mutable: true,
      assignee_username: null,
      review_at: null,
      is_new: true,
      coverage_state: "complete",
    }],
    occurrences_truncated: false,
    workflow_counts: { open: 1, in_review: 0, accepted: 0, false_positive: 0, resolved: 0, awaiting_reanalysis: 0, still_detected: 0 },
    limitations: [],
    ...overrides,
  };
}

function page(items: RemediationActionGroup[], overrides: Partial<RemediationPage> = {}): RemediationPage {
  return {
    contract_version: "2026-09-09.1",
    snapshot_at: "2026-09-09T10:00:00Z",
    items,
    returned_count: items.length,
    total_count: items.length,
    has_more: false,
    next_cursor: null,
    summary: { total_groups: items.length, filtered_groups: items.length, urgent_groups: items.length, high_groups: 0, projects_affected: items.length ? 1 : 0, known_exploited_groups: items.length, conflicting_groups: 0, awaiting_reanalysis: 0 },
    resolution_policy: "comparable_reanalysis_required",
    portfolio_complete: true,
    limitations: ["A correction is verified only after a new comparable analysis no longer reports it."],
    ...overrides,
  };
}

function planJob(status: RemediationPlanJob["status"], overrides: Partial<RemediationPlanJob> = {}): RemediationPlanJob {
  return {
    contract_version: "2026-09-09.1",
    id: "e".repeat(32),
    organization_id: "1".repeat(32),
    status,
    filters: { page_size: 100, cursor: null, search: null, search_mode: "prefix", priority: null, evidence_kind: null, ecosystem: null, dependency_scope: null, workflow_state: null, sort: "priority" },
    created_at: "2026-09-09T10:00:00Z",
    updated_at: "2026-09-09T10:00:02Z",
    cutoff_at: "2026-09-09T10:00:00Z",
    expires_at: status === "completed" ? "2026-09-16T10:00:02Z" : null,
    processed_projects: status === "running" ? 50 : status === "completed" ? 100 : 0,
    total_projects: status === "running" || status === "completed" ? 100 : 0,
    included_groups: status === "completed" ? 1 : 0,
    included_occurrences: status === "completed" ? 1 : 0,
    groups_truncated: false,
    occurrences_truncated: false,
    snapshot_sha256: status === "completed" ? "d".repeat(64) : null,
    artifact_bytes: status === "completed" ? 512 : 0,
    failure_reason: status === "failed" ? "source_unavailable" : null,
    retry_of_job_id: null,
    recovery_count: 0,
    replayed: false,
    privacy: "owner_scoped_project_names_no_paths_content_comments_or_actors",
    ...overrides,
  };
}

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe("RemediationCenterPanel", () => {
  it("applies an account default and saves only closed filters without free text", async () => {
    const userId = "1".repeat(32);
    const saved = {
      contract_version: "2026-09-09.1" as const,
      id: "a".repeat(32),
      organization_id: "b".repeat(32),
      owner_user_id: userId,
      name: "Urgent npm",
      filters: { priority: "urgent" as const, ecosystem: "npm" as const, sort: "priority" as const },
      visibility: "private" as const,
      created_at: "2026-09-09T10:00:00Z",
      updated_at: "2026-09-09T10:00:00Z",
    };
    const created = { ...saved, id: "c".repeat(32), name: "Team review", visibility: "organization" as const };
    let createdOnce = false;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/remediation/views") && init?.method === "POST") {
        createdOnce = true;
        return Promise.resolve(response(created, 201));
      }
      if (url.endsWith("/remediation/views")) return Promise.resolve(response({
        contract_version: "2026-09-09.1",
        items: createdOnce ? [saved, created] : [saved],
        default_view_id: saved.id,
        owned_count: createdOnce ? 2 : 1,
        organization_count: createdOnce ? 1 : 0,
        privacy: "closed_filters_only_no_search_cursor_or_resource_ids",
      }));
      if (url.endsWith("/remediation/search")) return Promise.resolve(response(page([])));
      return Promise.resolve(response({ detail: "not found" }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);
    const view = render(<RemediationCenterPanel canManage currentUserId={userId} members={[]} onOpenProject={vi.fn()} />);

    await waitFor(() => expect(screen.getByLabelText("Priority")).toHaveValue("urgent"));
    expect(screen.getByLabelText("Ecosystem")).toHaveValue("npm");
    fireEvent.change(screen.getByLabelText("Component, advisory or title"), { target: { value: "private/customer/path" } });
    fireEvent.change(screen.getByLabelText("Priority"), { target: { value: "high" } });
    fireEvent.click(screen.getByText("Save current closed filters"));
    fireEvent.change(screen.getByLabelText("View name"), { target: { value: "Team review" } });
    fireEvent.change(screen.getByLabelText("Visibility"), { target: { value: "organization" } });
    fireEvent.click(screen.getByRole("button", { name: "Save view" }));

    expect(await screen.findByText(/Saved workspace view/)).toBeInTheDocument();
    const post = fetchMock.mock.calls.find(([input, init]) => String(input).endsWith("/remediation/views") && init?.method === "POST");
    const body = JSON.parse(String(post?.[1]?.body));
    expect(body.filters).toEqual(expect.objectContaining({ priority: "high", ecosystem: "npm" }));
    expect(JSON.stringify(body)).not.toContain("private/customer/path");
    expect(JSON.stringify(body)).not.toContain("cursor");
    expect((await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("shows evidence, KEV semantics and accessible project navigation", async () => {
    const open = vi.fn();
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(response(page([group()])))));
    const view = render(<RemediationCenterPanel canManage={false} onOpenProject={open} />);

    expect(await screen.findByRole("heading", { name: /Update public-package/ })).toBeInTheDocument();
    expect(screen.getByText(/does not establish package affectedness/i)).toBeInTheDocument();
    expect(screen.getByText("2.0.0")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Open" }));
    expect(open).toHaveBeenCalledWith(expect.objectContaining({ project: expect.objectContaining({ name: "Payments API" }) }));
    expect((await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });

  it("submits an explicitly confirmed atomic batch and refreshes the projection", async () => {
    const initial = group();
    const refreshed = group({ workflow_counts: { open: 0, in_review: 1, accepted: 0, false_positive: 0, resolved: 0, awaiting_reanalysis: 0, still_detected: 0 }, occurrences: [{ ...group().occurrences[0], workflow_state: "in_review" }] });
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(page([initial])))
      .mockResolvedValueOnce(response({ contract_version: "2026-09-09.2", group_id: initial.id, applied_count: 1, decisions: [], replayed: false, history_mode: "append_only_recoverable_batch" }, 201))
      .mockResolvedValueOnce(response(page([refreshed])));
    vi.stubGlobal("fetch", fetchMock);
    render(<RemediationCenterPanel canManage members={[]} onOpenProject={vi.fn()} />);
    await screen.findByText("Payments API");

    fireEvent.click(screen.getByRole("checkbox", { name: "Select Payments API" }));
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "Owner review started" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /reviewed the exact projects/i }));
    fireEvent.click(screen.getByRole("button", { name: "Record for 1" }));

    expect(await screen.findByText(/1 append-only decision recorded/i)).toBeInTheDocument();
    const [url, init] = fetchMock.mock.calls[1];
    expect(String(url)).toContain("/remediation/actions");
    expect(JSON.parse(String(init?.body))).toEqual(expect.objectContaining({
      group_id: initial.id,
      expected_revision: initial.revision,
      confirmation: true,
      status: "in_review",
      idempotency_key: expect.stringMatching(/^[a-f0-9]{32}$/),
      selections: [{ project_id: "1".repeat(32), analysis_id: "2".repeat(32), finding_id: "pvf_" + "3".repeat(64) }],
    }));
  });

  it("keeps loaded evidence visible and asks for review after a stale action", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(page([group()])))
      .mockResolvedValueOnce(response({ detail: "changed" }, 409));
    vi.stubGlobal("fetch", fetchMock);
    render(<RemediationCenterPanel canManage members={[]} onOpenProject={vi.fn()} />);
    await screen.findByText("Payments API");
    fireEvent.click(screen.getByRole("checkbox", { name: "Select Payments API" }));
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "Owner review started" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /reviewed the exact projects/i }));
    fireEvent.click(screen.getByRole("button", { name: "Record for 1" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/changed/i);
    expect(within(screen.getByLabelText("Remediation action groups")).getByText("Payments API")).toBeInTheDocument();
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
  });

  it("reuses the exact idempotency key when a recoverable submission is retried", async () => {
    const initial = group();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(response(page([initial])))
      .mockResolvedValueOnce(response({ detail: "temporarily unavailable" }, 503))
      .mockResolvedValueOnce(response({ contract_version: "2026-09-09.2", group_id: initial.id, applied_count: 1, decisions: [], replayed: true, history_mode: "append_only_recoverable_batch" }, 201))
      .mockResolvedValueOnce(response(page([])));
    vi.stubGlobal("fetch", fetchMock);
    render(<RemediationCenterPanel canManage members={[]} onOpenProject={vi.fn()} />);
    await screen.findByText("Payments API");
    fireEvent.click(screen.getByRole("checkbox", { name: "Select Payments API" }));
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "Owner review started" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /reviewed the exact projects/i }));
    fireEvent.click(screen.getByRole("button", { name: "Record for 1" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/No complete batch/i);
    fireEvent.click(screen.getByRole("button", { name: "Record for 1" }));
    expect(await screen.findByText(/recovered safely/i)).toBeInTheDocument();

    const firstKey = JSON.parse(String(fetchMock.mock.calls[1][1]?.body)).idempotency_key;
    const retryKey = JSON.parse(String(fetchMock.mock.calls[2][1]?.body)).idempotency_key;
    expect(retryKey).toBe(firstKey);
  });

  it("does not allow a bulk exception without a bounded review date", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(response(page([group()])));
    vi.stubGlobal("fetch", fetchMock);
    render(<RemediationCenterPanel canManage members={[]} onOpenProject={vi.fn()} />);
    await screen.findByText("Payments API");

    fireEvent.click(screen.getByRole("checkbox", { name: "Select Payments API" }));
    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "accepted" } });
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "Temporary documented exception" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /reviewed the exact projects/i }));

    expect(screen.getByRole("button", { name: "Record for 1" })).toBeDisabled();
    expect(screen.getByText(/Required; future UTC time no more than 366 days away/)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("requires disclosure confirmation and downloads both formats from one durable snapshot", async () => {
    let created = false;
    const completed = planJob("completed", { processed_projects: 1, total_projects: 1 });
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/remediation/search")) return Promise.resolve(response(page([group()])));
      if (url.endsWith("/remediation/views")) return Promise.resolve(response({ contract_version: "2026-09-09.1", items: [], default_view_id: null, owned_count: 0, organization_count: 0, privacy: "closed_filters_only_no_search_cursor_or_resource_ids" }));
      if (url.endsWith("/remediation/plans") && init?.method === "POST") { created = true; return Promise.resolve(response({ ...completed, status: "queued", processed_projects: 0, total_projects: 0, snapshot_sha256: null, expires_at: null })); }
      if (url.endsWith("/remediation/plans")) return Promise.resolve(response({ contract_version: "2026-09-09.1", items: created ? [completed] : [], max_retained_jobs: 100, artifact_ttl_days: 7 }));
      if (url.includes("/remediation/plans/") && url.includes("format=csv")) return Promise.resolve(new Response("record_type,project_name\n", { status: 200, headers: { "content-type": "text/csv", "content-disposition": 'attachment; filename="inspectra-remediation-plan-2026-09-09.csv"', "x-inspectra-snapshot-sha256": "d".repeat(64) } }));
      return Promise.resolve(response({ detail: "unexpected" }, 500));
    });
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("URL", { ...URL, createObjectURL: vi.fn(() => "blob:test"), revokeObjectURL: vi.fn() });
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    render(<RemediationCenterPanel canManage={false} currentUserId={"a".repeat(32)} onOpenProject={vi.fn()} />);
    await screen.findByText("Payments API");

    const createButton = screen.getByRole("button", { name: "Create durable plan" });
    expect(createButton).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox", { name: /may include project names/i }));
    fireEvent.click(createButton);

    expect(await screen.findByText("Plan ready")).toBeInTheDocument();
    const post = fetchMock.mock.calls.find(([input, init]) => String(input).endsWith("/remediation/plans") && init?.method === "POST");
    expect(JSON.parse(String(post?.[1]?.body))).toEqual(expect.objectContaining({
      project_metadata_confirmed: true,
    }));
    fireEvent.click(screen.getByRole("button", { name: "CSV" }));
    expect(await screen.findByText(/immutable snapshot d{12}/)).toBeInTheDocument();
  });

  it("renders bounded progress, safe failure and expiry recovery states", async () => {
    const jobs = [
      planJob("running", { id: "1".repeat(32) }),
      planJob("failed", { id: "2".repeat(32), failure_reason: "source_unavailable" }),
      planJob("expired", { id: "3".repeat(32) }),
    ];
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/remediation/search")) return Promise.resolve(response(page([group()])));
      if (url.endsWith("/remediation/views")) return Promise.resolve(response({ contract_version: "2026-09-09.1", items: [], default_view_id: null, owned_count: 0, organization_count: 0, privacy: "closed_filters_only_no_search_cursor_or_resource_ids" }));
      if (url.endsWith("/remediation/plans")) return Promise.resolve(response({ contract_version: "2026-09-09.1", items: jobs, max_retained_jobs: 100, artifact_ttl_days: 7 }));
      return Promise.resolve(response({ detail: "unexpected" }, 500));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<RemediationCenterPanel canManage currentUserId={"a".repeat(32)} onOpenProject={vi.fn()} />);

    expect(await screen.findByText(/50 of 100 projects/)).toBeInTheDocument();
    expect(screen.getByText("Building plan")).toBeInTheDocument();
    expect(screen.getByText("Artifact expired")).toBeInTheDocument();
    expect(screen.getByText(/seven-day artifact has been removed/)).toBeInTheDocument();
    expect(screen.getByText(/Authoritative evidence was temporarily unavailable/)).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Retry" })).toHaveLength(2);
    expect(screen.getByRole("button", { name: "Cancel" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "JSON" })).not.toBeInTheDocument();
  });
});
