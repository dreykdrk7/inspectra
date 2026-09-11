import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { FindingLifecyclePanel } from "./FindingLifecyclePanel";
import type { FindingLifecycleState, NormalizedFinding } from "./types";


const finding = {
  id: "a".repeat(64),
  rule_id: "configuration_debug_enabled",
  source_audit_type: "project_archive_basic",
  title: "Review production setting",
  category: "configuration",
  severity: "high",
  confidence: "high",
  description: "A production setting needs review.",
  evidence: "DEBUG=[REDACTED]",
  location: { path: "config/settings.py", line: 8 },
  recommendation: "Use a reviewed production setting.",
  references: [],
} satisfies NormalizedFinding;

const currentDecision = {
  contract_version: "2026-09-06.1" as const,
  id: "b".repeat(32),
  organization_id: "local-admin",
  project_id: "c".repeat(32),
  finding_id: finding.id,
  rule_id: finding.rule_id,
  status: "in_review" as const,
  reason: "Validate with the service owner",
  comment: null,
  assignee_user_id: "reader-id",
  assignee_username: "reader.one",
  actor_id: "team-admin",
  actor_username: "admin",
  actor_role: "administrator",
  review_at: null,
  created_at: "2026-09-06T10:00:00Z",
  previous_decision_id: null,
};

const lifecycle = {
  finding_id: finding.id,
  rule_id: finding.rule_id,
  current_status: "in_review",
  has_decision: true,
  needs_review: false,
  current_decision: currentDecision,
  history: [currentDecision],
} satisfies FindingLifecycleState;

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("FindingLifecyclePanel", () => {
  it("records a justified reviewable exception and refreshes immutable state", async () => {
    const onUpdated = vi.fn().mockResolvedValue(undefined);
    const fetchMock = vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
      Promise.resolve(jsonResponse({ ...currentDecision, status: "accepted", reason: "Temporary accepted risk" }, 201))
    );
    vi.stubGlobal("fetch", fetchMock);

    const { container } = render(
      <FindingLifecyclePanel
        projectId={currentDecision.project_id}
        analysisId={"d".repeat(32)}
        finding={finding}
        lifecycle={lifecycle}
        canManage
        members={[
          { user_id: "reader-id", username: "reader.one", role: "reader", joined_at: "2026-09-06T09:00:00Z" },
        ]}
        onUpdated={onUpdated}
      />
    );

    expect(screen.getAllByText("In review")).toHaveLength(2);
    expect(screen.getAllByText("Validate with the service owner")).toHaveLength(2);
    fireEvent.change(screen.getByLabelText("New status"), { target: { value: "accepted" } });
    fireEvent.change(screen.getByLabelText("Decision reason"), { target: { value: "Temporary accepted risk" } });
    fireEvent.change(screen.getByLabelText("Assign to"), { target: { value: "reader-id" } });
    const reviewAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1_000).toISOString().slice(0, 16);
    fireEvent.input(screen.getByLabelText("Review date (UTC)"), { target: { value: reviewAt } });
    expect(screen.getByRole("button", { name: "Record decision" })).toBeDisabled();
    expect((await axe.run(container)).violations).toEqual([]);
    fireEvent.click(screen.getByLabelText(/I confirm this exception/));
    fireEvent.click(screen.getByRole("button", { name: "Record decision" }));

    await waitFor(() => expect(onUpdated).toHaveBeenCalledOnce());
    const payload = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body));
    expect(payload).toEqual({
      analysis_id: "d".repeat(32),
      status: "accepted",
      reason: "Temporary accepted risk",
      comment: null,
      assignee_user_id: "reader-id",
      review_at: `${reviewAt}:00Z`,
    });
    expect(await screen.findByRole("status")).toHaveTextContent("The analyzer evidence was not changed");
  });

  it("requires a bounded review date before an exception can be recorded", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(
      <FindingLifecyclePanel
        projectId={currentDecision.project_id}
        analysisId={"d".repeat(32)}
        finding={finding}
        lifecycle={lifecycle}
        canManage
        onUpdated={vi.fn()}
      />
    );

    fireEvent.change(screen.getByLabelText("New status"), { target: { value: "false_positive" } });
    fireEvent.change(screen.getByLabelText("Decision reason"), { target: { value: "Generated fixture only" } });
    fireEvent.click(screen.getByLabelText(/I confirm this exception/));
    expect(screen.getByRole("button", { name: "Record decision" })).toBeDisabled();
    expect(screen.getByText(/Required for exceptions/)).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("keeps history readable but hides mutations from a reader", async () => {
    const { container } = render(
      <FindingLifecyclePanel
        projectId={currentDecision.project_id}
        analysisId={"d".repeat(32)}
        finding={finding}
        lifecycle={{ ...lifecycle, needs_review: true, review_overdue: true }}
        canManage={false}
        onUpdated={vi.fn()}
      />
    );

    expect(screen.getByText(/requires a new decision/)).toBeInTheDocument();
    expect(screen.getByText(/cannot change finding workflow/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Record decision" })).not.toBeInTheDocument();
    expect(screen.getByText("Decision history (1)")).toBeInTheDocument();
    expect((await axe.run(container)).violations).toEqual([]);
  });

  it("inserts bounded member mentions and loads older redacted activity", async () => {
    const olderDecision = {
      ...currentDecision,
      contract_version: "2026-09-11.1" as const,
      id: "e".repeat(32),
      reason: "Earlier review context",
      comment: "Coordinate with @reader.one",
      mentioned_usernames: ["reader.one"],
      previous_decision_id: "f".repeat(32),
    };
    const fetchMock = vi.fn((_input: RequestInfo | URL) => Promise.resolve(jsonResponse({
      contract_version: "2026-09-11.1",
      items: [olderDecision],
      total_count: 12,
      returned_count: 1,
      has_more: false,
      next_cursor: null,
      privacy: "owner_scoped_redacted_decision_activity",
    })));
    vi.stubGlobal("fetch", fetchMock);

    const { container } = render(
      <FindingLifecyclePanel
        projectId={currentDecision.project_id}
        analysisId={"d".repeat(32)}
        finding={finding}
        lifecycle={{ ...lifecycle, history_total: 12, history_has_more: true }}
        canManage
        members={[
          { user_id: "reader-id", username: "reader.one", role: "reader", joined_at: "2026-09-06T09:00:00Z" },
        ]}
        onUpdated={vi.fn()}
      />
    );

    fireEvent.change(screen.getByLabelText("Insert member mention"), { target: { value: "reader.one" } });
    expect(screen.getByLabelText(/Comment/)).toHaveValue("@reader.one ");
    expect(screen.getByText("Decision history (12)")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Load older activity" }));

    expect(await screen.findByText("Earlier review context")).toBeInTheDocument();
    expect(screen.getByText("Mentions: @reader.one")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Load older activity" })).not.toBeInTheDocument();
    expect(String(fetchMock.mock.calls[0]?.[0])).toContain(`/activity?page_size=10&cursor=${currentDecision.id}`);
    expect((await axe.run(container)).violations).toEqual([]);
  });

  it("shows a recoverable conflict without losing the form", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(jsonResponse({ detail: "Conflict" }, 409))));
    render(
      <FindingLifecyclePanel
        projectId={currentDecision.project_id}
        analysisId={"d".repeat(32)}
        finding={finding}
        lifecycle={lifecycle}
        canManage
        onUpdated={vi.fn()}
      />
    );

    fireEvent.change(screen.getByLabelText("Decision reason"), { target: { value: "Resolve after review" } });
    fireEvent.change(screen.getByLabelText("New status"), { target: { value: "resolved" } });
    fireEvent.click(screen.getByRole("button", { name: "Record decision" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Refresh the finding and reopen it first");
    expect(screen.getByLabelText("Decision reason")).toHaveValue("Resolve after review");
  });
});
