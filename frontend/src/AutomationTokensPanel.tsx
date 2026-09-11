import { FormEvent, useCallback, useEffect, useState } from "react";

import { ApiError, api } from "./api";
import type { AutomationToken, AutomationTokenCreated, ProjectSummary } from "./types";


export function AutomationTokensPanel({ projects }: { projects: ProjectSummary[] }) {
  const [tokens, setTokens] = useState<AutomationToken[]>([]);
  const [name, setName] = useState("CI pipeline");
  const [projectId, setProjectId] = useState("");
  const [lifetimeSeconds, setLifetimeSeconds] = useState(86400);
  const [created, setCreated] = useState<AutomationTokenCreated | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const activeForSelectedProject = tokens.filter(
    (token) => token.project_id === projectId && !token.revoked_at && new Date(token.expires_at).getTime() > Date.now(),
  );

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setTokens(await api.listAutomationTokens());
    } catch (caught) {
      setError(messageFor(caught));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    if (!projectId && projects[0]) setProjectId(projects[0].project.id);
  }, [projectId, projects]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setCreated(null);
    setCopied(false);
    try {
      const result = await api.createAutomationToken({
        name: name.trim(),
        project_id: projectId,
        scopes: ["project:read", "project:scan", "report:read"],
        lifetime_seconds: lifetimeSeconds,
      });
      setCreated(result);
      await refresh();
    } catch (caught) {
      setError(messageFor(caught));
    }
  }

  async function revoke(tokenId: string) {
    setError(null);
    try {
      await api.revokeAutomationToken(tokenId);
      await refresh();
    } catch (caught) {
      setError(messageFor(caught));
    }
  }

  async function copyOnce() {
    if (!created || !navigator.clipboard?.writeText) return;
    await navigator.clipboard.writeText(created.token);
    setCopied(true);
  }

  return (
    <section className="card" aria-labelledby="automation-token-title">
      <p className="eyebrow">CI/CD access</p>
      <h2 id="automation-token-title">Automation credentials</h2>
      <p className="muted">Create a short-lived credential bound to one project. Its secret is shown once and must go directly to your CI secret store.</p>

      {error ? <div className="alert" role="alert">{error} <button className="inline-button" onClick={() => void refresh()}>Retry</button></div> : null}
      {created ? (
        <div className="query-warning" role="status">
          <strong>Copy this secret now. It cannot be displayed again.</strong>
          <code className="one-time-token">{created.token}</code>
          <div className="row-actions">
            <button onClick={() => void copyOnce()}>{copied ? "Copied" : "Copy once"}</button>
            <button className="secondary-button" onClick={() => { setCreated(null); setCopied(false); }}>I stored this secret</button>
          </div>
        </div>
      ) : null}

      <form className="team-invitation-form" onSubmit={(event) => void submit(event)}>
        <label>Name<input value={name} minLength={3} maxLength={80} onChange={(event) => setName(event.target.value)} required /></label>
        <label>
          Project
          <select value={projectId} onChange={(event) => setProjectId(event.target.value)} required>
            <option value="" disabled>Select a project</option>
            {projects.map((item) => <option key={item.project.id} value={item.project.id}>{item.project.name}</option>)}
          </select>
        </label>
        <label>
          Expires
          <select value={lifetimeSeconds} onChange={(event) => setLifetimeSeconds(Number(event.target.value))}>
            <option value={3600}>1 hour</option><option value={86400}>24 hours</option><option value={604800}>7 days</option><option value={2592000}>30 days</option>
          </select>
        </label>
        <button type="submit" disabled={!projectId || name.trim().length < 3 || activeForSelectedProject.length >= 2}>
          {activeForSelectedProject.length === 1 ? "Create replacement" : "Create credential"}
        </button>
      </form>

      {activeForSelectedProject.length === 1 ? (
        <p className="muted" role="status">Rotation is available: create the replacement, validate one authorized pipeline, then revoke the previous credential.</p>
      ) : null}
      {activeForSelectedProject.length >= 2 ? (
        <p className="query-warning" role="alert">Two credentials are already active for this project. Verify the replacement and revoke the previous credential before creating another.</p>
      ) : null}

      {loading ? <p className="muted" role="status">Loading credentials…</p> : null}
      {!loading && tokens.length === 0 ? <p className="empty-state">No automation credentials. Pipelines have no non-interactive access.</p> : null}
      <div role="list" aria-label="Automation credentials">
        {tokens.map((token) => (
          <div className="team-member-row" role="listitem" key={token.id}>
            <div><strong>{token.name}</strong><span className="muted">Expires {new Date(token.expires_at).toLocaleString()} · {token.last_used_at ? "Used" : "Never used"}</span></div>
            {token.revoked_at ? <span className="status-pill">Revoked</span> : new Date(token.expires_at).getTime() <= Date.now() ? <span className="status-pill">Expired</span> : <button className="secondary-button" onClick={() => void revoke(token.id)}>Revoke</button>}
          </div>
        ))}
      </div>
    </section>
  );
}

function messageFor(error: unknown): string {
  return error instanceof ApiError ? error.message : "Automation credentials are temporarily unavailable.";
}
