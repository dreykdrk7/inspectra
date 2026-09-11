import { FormEvent, useCallback, useEffect, useState } from "react";

import { ApiError, api } from "./api";
import { PublicIdentityAttestationPanel } from "./PublicIdentityAttestationPanel";
import { PublicAdvisoryOperationsPanel } from "./PublicAdvisoryOperationsPanel";
import { FederatedIdentityPanel } from "./FederatedIdentityPanel";
import { IntegrationEventStatusPanel } from "./IntegrationEventStatusPanel";
import type { ActiveMemberResponsibilityImpact, TeamInvitation, TeamMember, TeamOrganization, TeamOrganizationListItem, TeamRole } from "./types";


type LoadState = { loading: boolean; error: string | null };
const idle: LoadState = { loading: false, error: null };

type TeamWorkspacePanelProps = {
  onWorkspaceChanged?: () => void | Promise<void>;
  onMembershipChanged?: () => void | Promise<void>;
  federatedLoginAvailable?: boolean;
};

export function TeamWorkspacePanel({
  onWorkspaceChanged = async () => undefined,
  onMembershipChanged = async () => undefined,
  federatedLoginAvailable = false,
}: TeamWorkspacePanelProps) {
  const [organization, setOrganization] = useState<TeamOrganization | null>(null);
  const [organizations, setOrganizations] = useState<TeamOrganizationListItem[]>([]);
  const [members, setMembers] = useState<TeamMember[]>([]);
  const [loadState, setLoadState] = useState<LoadState>({ loading: true, error: null });
  const [actionState, setActionState] = useState<LoadState>(idle);
  const [username, setUsername] = useState("");
  const [role, setRole] = useState<TeamRole>("reader");
  const [invitation, setInvitation] = useState<TeamInvitation | null>(null);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "unavailable">("idle");
  const [revokeCandidate, setRevokeCandidate] = useState<string | null>(null);
  const [revokeImpact, setRevokeImpact] = useState<ActiveMemberResponsibilityImpact | null>(null);
  const [revokeImpactState, setRevokeImpactState] = useState<LoadState>(idle);
  const [workspaceName, setWorkspaceName] = useState("");

  const refresh = useCallback(async () => {
    setLoadState({ loading: true, error: null });
    try {
      const [workspace, availableWorkspaces, currentMembers] = await Promise.all([
        api.getTeamOrganization(),
        api.listTeamOrganizations(),
        api.listTeamMembers(),
      ]);
      setOrganization(workspace);
      setOrganizations(availableWorkspaces);
      setMembers(currentMembers);
      setLoadState(idle);
    } catch (error) {
      setLoadState({ loading: false, error: messageFor(error) });
    }
  }, []);

  async function switchWorkspace(organizationId: string) {
    if (!organization || organizationId === organization.id) return;
    setActionState({ loading: true, error: null });
    setInvitation(null);
    try {
      await api.selectTeamOrganization(organizationId);
      await onWorkspaceChanged();
      await refresh();
      setActionState(idle);
    } catch (error) {
      setActionState({ loading: false, error: messageFor(error) });
    }
  }

  async function createWorkspace(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setActionState({ loading: true, error: null });
    setInvitation(null);
    try {
      const created = await api.createTeamOrganization(workspaceName);
      setWorkspaceName("");
      await api.selectTeamOrganization(created.id);
      await onWorkspaceChanged();
      await refresh();
      setActionState(idle);
    } catch (error) {
      setActionState({ loading: false, error: messageFor(error) });
    }
  }

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function createInvitation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setActionState({ loading: true, error: null });
    setInvitation(null);
    setCopyState("idle");
    try {
      const created = await api.createTeamInvitation(username, role);
      setInvitation(created);
      setUsername("");
      setActionState(idle);
    } catch (error) {
      setActionState({ loading: false, error: messageFor(error) });
    }
  }

  async function updateRole(member: TeamMember, nextRole: TeamRole) {
    setActionState({ loading: true, error: null });
    try {
      await api.changeTeamMemberRole(member.user_id, nextRole);
      await refresh();
      setActionState(idle);
    } catch (error) {
      setActionState({ loading: false, error: messageFor(error) });
    }
  }

  async function revokeMember(userId: string) {
    setActionState({ loading: true, error: null });
    try {
      await api.revokeTeamMember(userId);
      setRevokeCandidate(null);
      setRevokeImpact(null);
      setRevokeImpactState(idle);
      await onMembershipChanged();
      await refresh();
      setActionState(idle);
    } catch (error) {
      setActionState({ loading: false, error: messageFor(error) });
    }
  }

  async function reviewMemberRevocation(userId: string) {
    setRevokeCandidate(userId);
    setRevokeImpact(null);
    setRevokeImpactState({ loading: true, error: null });
    try {
      setRevokeImpact(await api.getTeamMemberActiveImpact(userId));
      setRevokeImpactState(idle);
    } catch (error) {
      setRevokeImpactState({ loading: false, error: messageFor(error) });
    }
  }

  function cancelMemberRevocation() {
    setRevokeCandidate(null);
    setRevokeImpact(null);
    setRevokeImpactState(idle);
  }

  async function copyInvitation() {
    if (!invitation || !navigator.clipboard?.writeText) {
      setCopyState("unavailable");
      return;
    }
    try {
      await navigator.clipboard.writeText(invitation.token);
      setCopyState("copied");
    } catch {
      setCopyState("unavailable");
    }
  }

  return (
    <section className="card team-workspace-card" aria-labelledby="team-workspace-title">
      <div className="section-heading-row">
        <div>
          <p className="eyebrow">Private team workspace</p>
          <h2 id="team-workspace-title">{organization?.name ?? "Team access"}</h2>
          <p className="muted">
            Projects, analyses and exports use this workspace as their isolation boundary. Roles never bypass
            authorization, redaction or analysis limits.
          </p>
        </div>
        {organization ? <span className="status-pill ok">{roleLabel(organization.current_role)}</span> : null}
      </div>

      {loadState.loading ? <p className="muted" role="status">Loading team access…</p> : null}
      {loadState.error ? (
        <div className="alert" role="alert">
          {loadState.error} <button className="inline-button" onClick={() => void refresh()}>Retry</button>
        </div>
      ) : null}

      {organization ? (
        <>
          <div className="team-workspace-switcher">
            <label>
              Active workspace
              <select
                value={organization.id}
                disabled={actionState.loading}
                onChange={(event) => void switchWorkspace(event.target.value)}
              >
                {organizations.map((item) => <option value={item.id} key={item.id}>{item.name} — {roleLabel(item.role)}</option>)}
              </select>
            </label>
            <p className="muted">Switching rotates the session and reloads only the selected workspace's data.</p>
          </div>
          <div className="team-workspace-summary">
            <div><span>Signed in</span><strong>{organization.current_username}</strong></div>
            <div><span>Members</span><strong>{members.length}</strong></div>
            <div><span>Access</span><strong>{roleCapability(organization.current_role)}</strong></div>
          </div>

          <div className="team-member-list" role="list" aria-label="Workspace members">
            {members.map((member) => {
              const isCurrent = member.user_id === organization.current_user_id;
              const canManage = organization.current_role === "administrator" && !isCurrent;
              return (
                <div className="team-member-row" role="listitem" key={member.user_id}>
                  <div>
                    <strong>{member.username}</strong>
                    <span className="muted">{isCurrent ? "Current account" : `Joined ${formatDate(member.joined_at)}`}</span>
                  </div>
                  {canManage ? (
                    <div className="team-member-actions">
                      <label>
                        <span className="sr-only">Role for {member.username}</span>
                        <select
                          value={member.role}
                          disabled={actionState.loading}
                          onChange={(event) => void updateRole(member, event.target.value as TeamRole)}
                        >
                          <option value="administrator">Administrator</option>
                          <option value="maintainer">Maintainer</option>
                          <option value="reader">Reader</option>
                        </select>
                      </label>
                      {revokeCandidate === member.user_id ? (
                        <span className="team-revoke-confirmation">
                          {revokeImpactState.loading ? <span role="status">Checking responsibility impact…</span> : null}
                          {revokeImpact ? <span role="status">
                            {revokeImpact.affected_asset_count === 0
                              ? 'No Active asset assignments will change. '
                              : `${revokeImpact.affected_asset_count} Active asset assignment(s) will be removed; ${revokeImpact.will_become_unassigned_count} asset(s) will become unassigned and ${revokeImpact.will_keep_other_responsibles_count} will retain another responsible. `}
                            {(revokeImpact.affected_project_count ?? 0) === 0
                              ? 'No project ownership will change.'
                              : `${revokeImpact.affected_project_count} project assignment(s) will be cleared and marked for explicit reassignment.`}
                            {' '}Sessions in this workspace will be revoked. If this is the account&apos;s final membership, its login identity will be deactivated; retained audit references stay opaque.
                          </span> : null}
                          {revokeImpactState.error ? <span className="error-text" role="alert">Impact unavailable. Revocation is blocked. {revokeImpactState.error}</span> : null}
                          <button className="danger-button" disabled={actionState.loading || !revokeImpact} onClick={() => void revokeMember(member.user_id)}>
                            Confirm revoke
                          </button>
                          <button className="secondary-button" onClick={cancelMemberRevocation}>Keep member</button>
                        </span>
                      ) : (
                        <button className="secondary-button" onClick={() => void reviewMemberRevocation(member.user_id)}>Review revocation</button>
                      )}
                    </div>
                  ) : (
                    <span className="status-pill">{roleLabel(member.role)}</span>
                  )}
                </div>
              );
            })}
          </div>

          <PublicIdentityAttestationPanel key={organization.id} role={organization.current_role} />
          {organization.current_role === "administrator" ? <PublicAdvisoryOperationsPanel key={`advisories-${organization.id}`} /> : null}
          {organization.current_role === "administrator" ? <IntegrationEventStatusPanel key={`integration-events-${organization.id}`} /> : null}

          {organization.current_role === "administrator" ? (
            <div className="team-administration-actions">
              <FederatedIdentityPanel enabled={federatedLoginAvailable} members={members} />
              <form className="team-workspace-create-form" onSubmit={(event) => void createWorkspace(event)}>
                <div>
                  <h3>Create an isolated workspace</h3>
                  <p className="muted">New projects and analyses remain separate after the session switches.</p>
                </div>
                <label>
                  Workspace name
                  <input value={workspaceName} onChange={(event) => setWorkspaceName(event.target.value)} minLength={3} maxLength={80} required />
                </label>
                <button type="submit" disabled={actionState.loading || workspaceName.trim().length < 3}>Create & switch</button>
              </form>
              <form className="team-invitation-form" onSubmit={(event) => void createInvitation(event)}>
                <div>
                  <h3>Invite a teammate</h3>
                  <p className="muted">Use a non-email username. The one-time token is shown once and must be shared through an approved channel.</p>
                </div>
                <label>
                  Username
                  <input
                    value={username}
                    onChange={(event) => setUsername(event.target.value)}
                    minLength={3}
                    maxLength={64}
                    pattern="[A-Za-z0-9][A-Za-z0-9._-]{2,63}"
                    autoComplete="off"
                    required
                  />
                </label>
                <label>
                  Initial role
                  <select value={role} onChange={(event) => setRole(event.target.value as TeamRole)}>
                    <option value="reader">Reader — view and export</option>
                    <option value="maintainer">Maintainer — analyze and manage findings</option>
                    <option value="administrator">Administrator — manage members</option>
                  </select>
                </label>
                <button type="submit" disabled={actionState.loading || username.trim().length < 3}>
                  {actionState.loading ? "Creating invitation…" : "Create one-time invitation"}
                </button>
              </form>
            </div>
          ) : (
            <p className="query-warning" role="status">
              {organization.current_role === "reader"
                ? "Reader access is view-only. Ask an administrator if you need to run analyses or change workspace data."
                : "Maintainers can run analyses and manage project data; only administrators can invite or revoke members."}
            </p>
          )}

          {invitation ? (
            <div className="team-invitation-result" role="status">
              <strong>Invitation ready for {invitation.username}</strong>
              <p>Expires {formatDate(invitation.expires_at)}. It cannot be recovered after leaving this view.</p>
              <code>{invitation.token}</code>
              <button className="secondary-button" onClick={() => void copyInvitation()}>Copy one-time token</button>
              {copyState === "copied" ? <span>Copied.</span> : null}
              {copyState === "unavailable" ? <span>Select and copy the token manually.</span> : null}
            </div>
          ) : null}
          {actionState.error ? <p className="error-text" role="alert">{actionState.error}</p> : null}
        </>
      ) : null}
    </section>
  );
}

function roleLabel(role: TeamRole): string {
  return role === "administrator" ? "Administrator" : role === "maintainer" ? "Maintainer" : "Reader";
}

function roleCapability(role: TeamRole): string {
  return role === "administrator" ? "Manage team and projects" : role === "maintainer" ? "Manage projects" : "View only";
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "at a recorded time" : date.toLocaleString();
}

function messageFor(error: unknown): string {
  if (error instanceof ApiError && error.status === 401) return "Your session expired. Sign in again.";
  if (error instanceof Error && error.message) return error.message;
  return "Team access could not be updated.";
}
