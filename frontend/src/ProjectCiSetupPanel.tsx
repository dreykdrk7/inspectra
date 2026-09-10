import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { CheckCircle2, Clipboard, KeyRound, PlayCircle } from "lucide-react";

import { ApiError, api } from "./api";
import type { AutomationTokenCreated, ProjectSummary } from "./types";

type Provider = "github" | "generic";
type Policy = "observe" | "standard" | "strict";

export function ProjectCiSetupPanel({ project, canManage, focusOnMount = false }: { project: ProjectSummary; canManage: boolean; focusOnMount?: boolean }) {
  const [provider, setProvider] = useState<Provider>("github");
  const [policy, setPolicy] = useState<Policy>("standard");
  const [lifetime, setLifetime] = useState(86400);
  const [created, setCreated] = useState<AutomationTokenCreated | null>(null);
  const [credentialId, setCredentialId] = useState<string | null>(null);
  const [stage, setStage] = useState<"configure" | "secret" | "snippet">("configure");
  const [state, setState] = useState<"idle" | "creating" | "checking" | "ready" | "error">("idle");
  const [message, setMessage] = useState<string | null>(null);
  const secretHeading = useRef<HTMLHeadingElement>(null);
  const snippetHeading = useRef<HTMLHeadingElement>(null);
  const section = useRef<HTMLElement>(null);
  const baselineAvailable = Boolean(project.project.baseline_analysis_id);
  const snippet = useMemo(
    () => buildCiSnippet(provider, api.baseUrl(), project.project.id, policy),
    [policy, project.project.id, provider],
  );

  useEffect(() => {
    if (stage === "secret") secretHeading.current?.focus();
    if (stage === "snippet") snippetHeading.current?.focus();
  }, [stage]);

  useEffect(() => {
    if (focusOnMount) section.current?.focus({ preventScroll: false });
  }, [focusOnMount]);

  async function createCredential(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setState("creating");
    setMessage(null);
    try {
      const result = await api.createAutomationToken({
        name: `${provider === "github" ? "GitHub" : "Generic"} CI · ${project.project.name}`.slice(0, 80),
        project_id: project.project.id,
        scopes: ["project:read", "project:scan", "report:read"],
        lifetime_seconds: lifetime,
      });
      setCreated(result);
      setCredentialId(result.id);
      setStage("secret");
      setState("idle");
    } catch (error) {
      setState("error");
      setMessage(messageFor(error, "Unable to create the project credential."));
    }
  }

  async function copySecret() {
    if (!created || !navigator.clipboard?.writeText) {
      setMessage("Clipboard access is unavailable. Select the one-time secret manually.");
      return;
    }
    await navigator.clipboard.writeText(created.token);
    setMessage("One-time secret copied. Store it as INSPECTRA_TOKEN before continuing.");
  }

  function confirmSecretStored() {
    setCreated(null);
    setMessage(null);
    setStage("snippet");
  }

  async function copySnippet() {
    if (!navigator.clipboard?.writeText) {
      setMessage("Clipboard access is unavailable. Select the snippet manually.");
      return;
    }
    await navigator.clipboard.writeText(snippet);
    setMessage("Snippet copied without credential material.");
  }

  async function checkSetup() {
    if (!credentialId) return;
    setState("checking");
    setMessage(null);
    try {
      const result = await api.probeAutomationToken(credentialId);
      if (result.status !== "ready" || !result.scopes_complete || result.project_id !== project.project.id) {
        throw new Error("not ready");
      }
      setState("ready");
      setMessage("Credential metadata, project binding and minimum scopes are ready. No pipeline was executed.");
    } catch (error) {
      setState("error");
      setMessage(messageFor(error, "Setup could not be verified. Create a replacement credential before running CI."));
    }
  }

  if (!canManage) {
    return (
      <section id="ci-setup" ref={section} className="ci-setup-card" aria-labelledby="ci-setup-title" tabIndex={-1}>
        <p className="eyebrow">CI adoption</p>
        <h3 id="ci-setup-title">Connect this project to CI</h3>
        <p className="empty-state">An administrator must create the project-bound credential. Readers and maintainers cannot reveal or issue automation secrets.</p>
      </section>
    );
  }

  return (
    <section id="ci-setup" ref={section} className="ci-setup-card" aria-labelledby="ci-setup-title" tabIndex={-1}>
      <p className="eyebrow">CI adoption</p>
      <h3 id="ci-setup-title">Connect this project to CI</h3>
      <p className="muted">Create one short-lived credential, store it once, then copy a snippet that references — but never contains — the secret.</p>

      {stage === "configure" ? (
        <form className="ci-setup-form" onSubmit={(event) => void createCredential(event)}>
          <fieldset>
            <legend>Pipeline provider</legend>
            <div className="segmented-control">
              <button type="button" className={provider === "github" ? "active" : ""} aria-pressed={provider === "github"} onClick={() => setProvider("github")}>GitHub Actions</button>
              <button type="button" className={provider === "generic" ? "active" : ""} aria-pressed={provider === "generic"} onClick={() => setProvider("generic")}>Generic shell</button>
            </div>
          </fieldset>
          <label>Policy
            <select value={policy} onChange={(event) => setPolicy(event.target.value as Policy)}>
              <option value="observe">Observe — report without severity gate</option>
              <option value="standard">Standard — critical, KEV and high regressions</option>
              <option value="strict">Strict — high current and medium regressions</option>
            </select>
          </label>
          <label>Credential lifetime
            <select value={lifetime} onChange={(event) => setLifetime(Number(event.target.value))}>
              <option value={3600}>1 hour</option><option value={86400}>24 hours</option><option value={604800}>7 days</option>
            </select>
          </label>
          <div className="ci-baseline-note" role="status">
            <strong>Baseline: {baselineAvailable ? "saved" : "not configured"}</strong>
            <span>{baselineAvailable ? "New/resolved findings use the saved compatible analysis." : "The first run establishes current debt; save a compatible baseline before gating regressions."}</span>
          </div>
          <button type="submit" disabled={state === "creating"}><KeyRound size={16} aria-hidden="true" /> {state === "creating" ? "Creating" : "Create project credential"}</button>
        </form>
      ) : null}

      {stage === "secret" && created ? (
        <div className="ci-secret-step" role="status">
          <h4 ref={secretHeading} tabIndex={-1}>Store the one-time secret</h4>
          <p>Save it as <code>INSPECTRA_TOKEN</code> in the provider secret store. It will be removed from this page when you continue.</p>
          <code className="one-time-token">{created.token}</code>
          <div className="row-actions">
            <button type="button" className="secondary-button" onClick={() => void copySecret()}><Clipboard size={15} aria-hidden="true" /> Copy once</button>
            <button type="button" onClick={confirmSecretStored}>I stored the secret</button>
          </div>
        </div>
      ) : null}

      {stage === "snippet" ? (
        <div className="ci-snippet-step">
          <h4 ref={snippetHeading} tabIndex={-1}>Add the verified CLI step</h4>
          <pre tabIndex={0} aria-label={`${provider} Inspectra pipeline snippet`}><code>{snippet}</code></pre>
          <div className="row-actions">
            <button type="button" className="secondary-button" onClick={() => void copySnippet()}><Clipboard size={15} aria-hidden="true" /> Copy snippet</button>
            <button type="button" onClick={() => void checkSetup()} disabled={state === "checking"}><PlayCircle size={15} aria-hidden="true" /> {state === "checking" ? "Checking" : "Verify setup"}</button>
          </div>
          <details>
            <summary>How the policy exits</summary>
            <p><strong>0</strong> completed and policy passed; <strong>8</strong> confirmed evidence violated the gate; <strong>9</strong> evidence, freshness, coverage or baseline was insufficient. Code 9 is never a clean result.</p>
          </details>
          <button type="button" className="inline-button" onClick={() => { setCredentialId(null); setState("idle"); setMessage(null); setStage("configure"); }}>Create another credential</button>
        </div>
      ) : null}

      {message ? <p className={state === "error" ? "error-text" : "success-text"} role={state === "error" ? "alert" : "status"}>{state === "ready" ? <CheckCircle2 size={15} aria-hidden="true" /> : null}{message}</p> : null}
    </section>
  );
}

export function buildCiSnippet(provider: Provider, apiUrl: string, projectId: string, policy: Policy): string {
  const normalizedApiUrl = normalizeCiApiUrl(apiUrl);
  if (!normalizedApiUrl || !/^[a-f0-9]{32}$/.test(projectId)) {
    return "# Setup unavailable: the operator API URL or project identifier is invalid.";
  }
  if (provider === "github") {
    return `# Install only your locally verified inspectra-cli wheel before this step.\n- name: Inspectra project scan\n  env:\n    INSPECTRA_TOKEN: \${{ secrets.INSPECTRA_TOKEN }}\n    INSPECTRA_API_URL: ${JSON.stringify(normalizedApiUrl)}\n  run: >-\n    inspectra scan . --commit "\${{ github.sha }}"\n    --project-id ${projectId} --policy ${policy}\n    --yes --confirm-authorized --format sarif --output inspectra.sarif`;
  }
  return `# INSPECTRA_TOKEN must come from the pipeline secret store.\nexport INSPECTRA_API_URL=${shellQuote(normalizedApiUrl)}\ninspectra scan . --commit "\${CI_COMMIT_SHA:?exact commit required}" \\\n  --project-id ${shellQuote(projectId)} --policy ${shellQuote(policy)} \\\n  --yes --confirm-authorized --format json --output inspectra.json`;
}

function normalizeCiApiUrl(value: string): string | null {
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

function messageFor(error: unknown, fallback: string): string {
  return error instanceof ApiError ? error.message : fallback;
}
