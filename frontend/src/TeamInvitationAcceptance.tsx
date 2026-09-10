import { FormEvent, useState } from "react";

import { api } from "./api";


export function TeamInvitationAcceptance({ onAccepted }: { onAccepted: (username: string) => void }) {
  const [open, setOpen] = useState(false);
  const [token, setToken] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [acceptedUsername, setAcceptedUsername] = useState<string | null>(null);

  async function accept(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (password !== confirmation) {
      setError("Passwords do not match.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const result = await api.acceptTeamInvitation(token, password);
      setToken("");
      setPassword("");
      setConfirmation("");
      setAcceptedUsername(result.username);
      onAccepted(result.username);
    } catch {
      setToken("");
      setPassword("");
      setConfirmation("");
      setError("This invitation is invalid, expired or already used. Ask an administrator for a new one.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="team-invitation-acceptance">
      <button className="inline-button" type="button" aria-expanded={open} onClick={() => setOpen((current) => !current)}>
        {open ? "Hide invitation setup" : "I have a one-time invitation"}
      </button>
      {open ? (
        <form className="auth-form" onSubmit={(event) => void accept(event)}>
          <p className="muted">The token is used only for this request and is never saved in the browser.</p>
          <label className="auth-field">
            <span>Invitation token</span>
            <input value={token} onChange={(event) => setToken(event.target.value)} autoComplete="off" minLength={32} maxLength={128} required />
          </label>
          <label className="auth-field">
            <span>Create password</span>
            <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" minLength={12} maxLength={256} required />
          </label>
          <label className="auth-field">
            <span>Confirm password</span>
            <input type="password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} autoComplete="new-password" minLength={12} maxLength={256} required />
          </label>
          <button type="submit" disabled={loading || !token || !password || !confirmation}>
            {loading ? "Activating account…" : "Activate team account"}
          </button>
          {error ? <p className="error-text" role="alert">{error}</p> : null}
          {acceptedUsername ? <p className="success-text" role="status">Account activated. Sign in as {acceptedUsername}.</p> : null}
        </form>
      ) : null}
    </div>
  );
}
