import { useEffect, useMemo, useRef, useState } from "react";
import { Clipboard, KeyRound, ShieldCheck } from "lucide-react";

import { ApiError, api } from "./api";
import type { RepositoryImportGrantCreated } from "./types";


export function RepositoryImportSetupPanel({
  requiresGrant,
  canManage,
  focusOnMount = false,
}: {
  requiresGrant: boolean;
  canManage: boolean;
  focusOnMount?: boolean;
}) {
  const section = useRef<HTMLElement>(null);
  const secretHeading = useRef<HTMLHeadingElement>(null);
  const commandHeading = useRef<HTMLHeadingElement>(null);
  const [stage, setStage] = useState<"configure" | "secret" | "command">(
    requiresGrant ? "configure" : "command",
  );
  const [grant, setGrant] = useState<RepositoryImportGrantCreated | null>(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const command = useMemo(() => buildRepositoryImportCommand(api.baseUrl(), requiresGrant), [requiresGrant]);

  useEffect(() => {
    if (focusOnMount) section.current?.focus({ preventScroll: false });
  }, [focusOnMount]);

  useEffect(() => {
    if (stage === "secret") secretHeading.current?.focus();
    if (stage === "command") commandHeading.current?.focus();
  }, [stage]);

  async function createGrant() {
    setLoading(true);
    setMessage(null);
    try {
      const created = await api.createRepositoryImportGrant(900);
      setGrant(created);
      setStage("secret");
    } catch (error) {
      setMessage(error instanceof ApiError ? error.message : "Unable to create the repository import grant.");
    } finally {
      setLoading(false);
    }
  }

  async function copy(value: string, success: string) {
    if (!navigator.clipboard?.writeText) {
      setMessage("Clipboard access is unavailable. Select the value manually.");
      return;
    }
    await navigator.clipboard.writeText(value);
    setMessage(success);
  }

  return (
    <section id="repository-import-setup" ref={section} className="ci-setup-card" aria-labelledby="repository-import-title" tabIndex={-1}>
      <p className="eyebrow">Local Git import</p>
      <h3 id="repository-import-title">Analyze an exact local commit</h3>
      <p className="muted">
        The CLI reads tracked Git blobs locally, runs the mandatory secret preflight and uploads a generic snapshot. Inspectra never clones, fetches or receives a repository URL, local path or Git credential.
      </p>

      {requiresGrant && !canManage ? (
        <p className="empty-state">An administrator must issue the short-lived, single-use import grant. It authorizes one new project and no other route.</p>
      ) : null}

      {stage === "configure" && canManage ? (
        <div className="ci-secret-step">
          <p>The grant expires after 15 minutes, is stored only as a hash and is consumed before source bytes are retained.</p>
          <button type="button" onClick={() => void createGrant()} disabled={loading}>
            <KeyRound size={16} aria-hidden="true" /> {loading ? "Creating" : "Create one-time import grant"}
          </button>
        </div>
      ) : null}

      {stage === "secret" && grant ? (
        <div className="ci-secret-step" role="status">
          <h4 ref={secretHeading} tabIndex={-1}>Store the one-time grant</h4>
          <p>Export it as <code>INSPECTRA_IMPORT_TOKEN</code> only in the terminal that will run the authorized import. Do not pass it as a CLI argument or enable shell tracing.</p>
          <code className="one-time-token">{grant.token}</code>
          <div className="row-actions">
            <button type="button" className="secondary-button" onClick={() => void copy(grant.token, "Import grant copied.")}>
              <Clipboard size={15} aria-hidden="true" /> Copy once
            </button>
            <button type="button" onClick={() => { setGrant(null); setMessage(null); setStage("command"); }}>
              I stored the grant
            </button>
          </div>
        </div>
      ) : null}

      {stage === "command" ? (
        <div className="ci-snippet-step">
          <h4 ref={commandHeading} tabIndex={-1}>Run the bounded local preflight and import</h4>
          <pre tabIndex={0} aria-label="Inspectra local Git import command"><code>{command}</code></pre>
          <div className="row-actions">
            <button type="button" className="secondary-button" onClick={() => void copy(command, "Import command copied without credential material.")}>
              <Clipboard size={15} aria-hidden="true" /> Copy command
            </button>
            {requiresGrant ? <button type="button" onClick={() => { setMessage(null); setStage("configure"); }}>Create another grant</button> : null}
          </div>
          <p className="entry-note"><ShieldCheck size={15} aria-hidden="true" /> Use <code>--dry-run</code> first when reviewing an unfamiliar repository. The standard suite never needs Internet.</p>
        </div>
      ) : null}

      {message ? <p className={message.startsWith("Unable") ? "error-text" : "success-text"} role={message.startsWith("Unable") ? "alert" : "status"}>{message}</p> : null}
    </section>
  );
}


export function buildRepositoryImportCommand(apiUrl: string, requiresGrant: boolean): string {
  const normalized = normalizeApiUrl(apiUrl);
  if (!normalized) return "# Setup unavailable: the operator API URL is invalid.";
  return `${requiresGrant ? "# INSPECTRA_IMPORT_TOKEN must be exported from the one-time value above.\n" : ""}export INSPECTRA_API_URL=${shellQuote(normalized)}
inspectra scan /path/to/authorized/repository --commit HEAD \\
  --name 'My project' --yes --confirm-authorized`;
}


function normalizeApiUrl(value: string): string | null {
  if (/[\u0000-\u0020\u007f]/.test(value)) return null;
  try {
    const parsed = new URL(value);
    const loopbackHttp = parsed.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
    if (parsed.protocol !== "https:" && !loopbackHttp) return null;
    if (parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname.includes("'")) return null;
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return null;
  }
}


function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}
