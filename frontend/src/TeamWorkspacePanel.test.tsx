import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { TeamWorkspacePanel } from "./TeamWorkspacePanel";


const organization = {
  id: "local-admin",
  name: "Acme security",
  current_user_id: "team-admin",
  current_username: "admin",
  current_role: "administrator",
};

const members = [
  { user_id: "team-admin", username: "admin", role: "administrator", joined_at: "2026-09-06T10:00:00Z" },
  { user_id: "reviewer-id", username: "reviewer.one", role: "reader", joined_at: "2026-09-06T11:00:00Z" },
];

const publicAdvisoryOperations = {
  contract_version: "2026-09-09.1",
  egress_enabled: false,
  offline_snapshot_active: false,
  providers: ["osv", "github_advisories", "nvd", "cisa_kev"].map((provider) => ({
    provider,
    configured: false,
    cache_entries: 0,
    fresh_entries: 0,
    stale_entries: 0,
    invalid_entries: 0,
    cache_bytes: 0,
    last_updated_at: null,
    truncated: false,
  })),
};

function response(payload: unknown, status = 200): Response {
  return new Response(status === 204 ? null : JSON.stringify(payload), {
    status,
    headers: status === 204 ? undefined : { "content-type": "application/json" },
  });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("TeamWorkspacePanel", () => {
  it("shows members and creates a one-time invitation without persisting it", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/organization/invitations") && init?.method === "POST") {
        return Promise.resolve(response({
          invitation_id: "invitation-id",
          token: "one-time-secret-token-with-enough-entropy",
          username: "new.reader",
          role: "reader",
          expires_at: "2026-09-07T10:00:00Z",
        }, 201));
      }
      if (url.endsWith("/organization/members")) return Promise.resolve(response(members));
      if (url.endsWith("/organizations")) return Promise.resolve(response([{ id: "local-admin", name: "Acme security", role: "administrator", created_at: "2026-09-06T10:00:00Z" }]));
      if (url.endsWith("/operations/public-advisories")) return Promise.resolve(response(publicAdvisoryOperations));
      return Promise.resolve(response(organization));
    });
    vi.stubGlobal("fetch", fetchMock);
    const clipboard = { writeText: vi.fn().mockResolvedValue(undefined) };
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: clipboard });

    render(<TeamWorkspacePanel />);
    expect(await screen.findByRole("heading", { name: "Acme security" })).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Workspace members" })).toHaveTextContent("reviewer.one");

    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "new.reader" } });
    fireEvent.click(screen.getByRole("button", { name: "Create one-time invitation" }));
    expect(await screen.findByText("Invitation ready for new.reader")).toBeInTheDocument();
    expect(screen.getByText("one-time-secret-token-with-enough-entropy")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Copy one-time token" }));
    await waitFor(() => expect(clipboard.writeText).toHaveBeenCalledWith("one-time-secret-token-with-enough-entropy"));

    const invitationCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/organization/invitations"));
    expect(JSON.parse(String(invitationCall?.[1]?.body))).toEqual({ username: "new.reader", role: "reader" });
  });

  it("requires explicit confirmation before revoking a member", async () => {
    const onMembershipChanged = vi.fn();
    let activeMembers = members;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/organization/members/reviewer-id/responsibility-impact")) {
        return Promise.resolve(response({
          affected_asset_count: 2,
          will_become_unassigned_count: 1,
          will_keep_other_responsibles_count: 1,
          affected_project_count: 3,
          projects_requiring_reassignment_count: 3,
        }));
      }
      if (url.endsWith("/organization/members/reviewer-id") && init?.method === "DELETE") {
        activeMembers = [members[0]];
        return Promise.resolve(response(null, 204));
      }
      if (url.endsWith("/organization/members")) return Promise.resolve(response(activeMembers));
      if (url.endsWith("/organizations")) return Promise.resolve(response([{ id: "local-admin", name: "Acme security", role: "administrator", created_at: "2026-09-06T10:00:00Z" }]));
      if (url.endsWith("/operations/public-advisories")) return Promise.resolve(response(publicAdvisoryOperations));
      return Promise.resolve(response(organization));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<TeamWorkspacePanel onMembershipChanged={onMembershipChanged} />);
    await screen.findByText("reviewer.one");
    fireEvent.click(screen.getByRole("button", { name: "Review revocation" }));
    expect(screen.getByRole("button", { name: "Confirm revoke" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Confirm revoke" })).toBeDisabled();
    expect(await screen.findByText(/2 Active asset assignment\(s\) will be removed; 1 asset\(s\) will become unassigned/)).toBeInTheDocument();
    expect(screen.getByText(/3 project assignment\(s\) will be cleared and marked for explicit reassignment/)).toBeInTheDocument();
    expect(screen.getByText(/Sessions in this workspace will be revoked.*final membership.*login identity will be deactivated/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Confirm revoke" })).toBeEnabled();
    expect(fetchMock).not.toHaveBeenCalledWith(expect.stringContaining("reviewer-id"), expect.objectContaining({ method: "DELETE" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm revoke" }));
    await waitFor(() => expect(screen.queryByText("reviewer.one")).not.toBeInTheDocument());
    expect(onMembershipChanged).toHaveBeenCalledTimes(1);
  });

  it("fails closed when Active responsibility impact cannot be reviewed", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/organization/members/reviewer-id/responsibility-impact")) {
        return Promise.resolve(response({ detail: "Active responsibility impact is unavailable." }, 503));
      }
      if (url.endsWith("/organization/members/reviewer-id") && init?.method === "DELETE") {
        throw new Error("revocation must remain blocked");
      }
      if (url.endsWith("/organization/members")) return Promise.resolve(response(members));
      if (url.endsWith("/organizations")) return Promise.resolve(response([{ id: "local-admin", name: "Acme security", role: "administrator", created_at: "2026-09-06T10:00:00Z" }]));
      if (url.endsWith("/operations/public-advisories")) return Promise.resolve(response(publicAdvisoryOperations));
      return Promise.resolve(response(organization));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<TeamWorkspacePanel />);
    await screen.findByText("reviewer.one");
    fireEvent.click(screen.getByRole("button", { name: "Review revocation" }));

    expect(await screen.findByText(/Impact unavailable\. Revocation is blocked/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Confirm revoke" })).toBeDisabled();
    expect(fetchMock.mock.calls.some(([input, init]) => String(input).endsWith("/organization/members/reviewer-id") && init?.method === "DELETE")).toBe(false);
  });

  it("switches workspace explicitly and asks the application to reload scoped data", async () => {
    const onWorkspaceChanged = vi.fn().mockResolvedValue(undefined);
    let activeId = "local-admin";
    const workspaces = [
      { id: "local-admin", name: "Acme security", role: "administrator", created_at: "2026-09-06T10:00:00Z" },
      { id: "b".repeat(32), name: "Second workspace", role: "administrator", created_at: "2026-09-06T11:00:00Z" },
    ];
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/select") && init?.method === "POST") {
        activeId = "b".repeat(32);
        return Promise.resolve(response({ authenticated: true, operator_id: "team-admin", auth_mode: "private_team_lightweight_users", organization_id: activeId, role: "administrator" }));
      }
      if (url.endsWith("/organization/members")) return Promise.resolve(response([members[0]]));
      if (url.endsWith("/organizations")) return Promise.resolve(response(workspaces));
      if (url.endsWith("/operations/public-advisories")) return Promise.resolve(response(publicAdvisoryOperations));
      const active = workspaces.find((item) => item.id === activeId) ?? workspaces[0];
      return Promise.resolve(response({ ...organization, id: active.id, name: active.name }));
    }));

    render(<TeamWorkspacePanel onWorkspaceChanged={onWorkspaceChanged} />);
    const selector = await screen.findByLabelText("Active workspace");
    fireEvent.change(selector, { target: { value: "b".repeat(32) } });

    expect(await screen.findByRole("heading", { name: "Second workspace" })).toBeInTheDocument();
    expect(onWorkspaceChanged).toHaveBeenCalledTimes(1);
    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining(`/organizations/${"b".repeat(32)}/select`),
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("renders reader capability as view-only and has no automated accessibility violations", async () => {
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
      if (String(input).endsWith("/organization/members")) return Promise.resolve(response([members[1]]));
      if (String(input).endsWith("/organizations")) return Promise.resolve(response([{ id: "local-admin", name: "Acme security", role: "reader", created_at: "2026-09-06T10:00:00Z" }]));
      return Promise.resolve(response({ ...organization, current_user_id: "reviewer-id", current_username: "reviewer.one", current_role: "reader" }));
    }));

    render(<TeamWorkspacePanel />);
    expect(await screen.findByText(/Reader access is view-only/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create one-time invitation" })).not.toBeInTheDocument();
    expect((await axe.run(document.body, { rules: { "color-contrast": { enabled: false } } })).violations).toEqual([]);
  });
});
