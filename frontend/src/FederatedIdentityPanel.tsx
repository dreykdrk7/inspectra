import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

import { ApiError, api } from "./api";
import type { FederatedIdentityBinding, TeamMember } from "./types";


type Props = {
  enabled: boolean;
  members: TeamMember[];
};

export function FederatedIdentityPanel({ enabled, members }: Props) {
  const [bindings, setBindings] = useState<FederatedIdentityBinding[]>([]);
  const [userId, setUserId] = useState("");
  const [subject, setSubject] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const eligibleMembers = useMemo(
    () => members.filter((member) => member.role !== "administrator" && !bindings.some((item) => item.user_id === member.user_id)),
    [bindings, members],
  );

  const refresh = useCallback(async () => {
    if (!enabled) return;
    setLoading(true);
    setError(null);
    try {
      setBindings(await api.listFederatedIdentities());
    } catch (reason) {
      setError(messageFor(reason));
    } finally {
      setLoading(false);
    }
  }, [enabled]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (userId && !eligibleMembers.some((member) => member.user_id === userId)) setUserId("");
  }, [eligibleMembers, userId]);

  async function provision(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await api.provisionFederatedIdentity(userId, subject);
      setSubject("");
      setUserId("");
      await refresh();
    } catch (reason) {
      setSubject("");
      setError(messageFor(reason));
      setLoading(false);
    }
  }

  async function revoke(bindingId: string) {
    setLoading(true);
    setError(null);
    try {
      await api.revokeFederatedIdentity(bindingId);
      await refresh();
    } catch (reason) {
      setError(messageFor(reason));
      setLoading(false);
    }
  }

  if (!enabled) return null;
  return (
    <section className="team-federation-panel" aria-labelledby="team-federation-title">
      <h3 id="team-federation-title">Organization SSO</h3>
      <p className="muted">
        Link an existing reader or maintainer to the exact provider subject. Inspectra stores only a keyed digest;
        administrators remain local break-glass accounts.
      </p>
      {loading && bindings.length === 0 ? <p className="muted" role="status">Loading SSO bindings…</p> : null}
      {error ? <p className="error-text" role="alert">{error}</p> : null}
      {bindings.length === 0 && !loading ? <p className="query-warning" role="status">No members are linked to SSO.</p> : null}
      {bindings.length > 0 ? (
        <div className="team-member-list" role="list" aria-label="SSO bindings">
          {bindings.map((binding) => (
            <div className="team-member-row" role="listitem" key={binding.id}>
              <div><strong>{binding.username}</strong><span className="muted">{binding.role}</span></div>
              <button className="secondary-button" disabled={loading} onClick={() => void revoke(binding.id)}>
                Revoke SSO and sessions
              </button>
            </div>
          ))}
        </div>
      ) : null}
      <form className="team-federation-form" onSubmit={(event) => void provision(event)}>
        <label>
          Existing member
          <select value={userId} onChange={(event) => setUserId(event.target.value)} required>
            <option value="">Select a reader or maintainer</option>
            {eligibleMembers.map((member) => <option key={member.user_id} value={member.user_id}>{member.username} — {member.role}</option>)}
          </select>
        </label>
        <label>
          Provider subject (`sub`)
          <input
            type="password"
            value={subject}
            onChange={(event) => setSubject(event.target.value)}
            autoComplete="off"
            minLength={1}
            maxLength={255}
            required
          />
        </label>
        <button type="submit" disabled={loading || !userId || !subject}>Link exact identity</button>
      </form>
      <p className="muted">A failed provider login never falls back to this binding. Membership and group role must match.</p>
    </section>
  );
}

function messageFor(reason: unknown): string {
  if (reason instanceof ApiError && reason.status === 401) return "Your session expired. Sign in again.";
  if (reason instanceof ApiError && reason.status === 404) return "SSO is not available for this workspace.";
  return "SSO bindings could not be updated safely.";
}
