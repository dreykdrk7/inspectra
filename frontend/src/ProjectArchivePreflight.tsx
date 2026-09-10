import { useEffect, useState } from "react";
import { CircleHelp, RefreshCw, ShieldCheck } from "lucide-react";

import { api } from "./api";
import type { ProjectArchivePreflightResponse } from "./types";

type LoadState = { loading: boolean; unavailable: boolean };

const initialLoadState: LoadState = { loading: false, unavailable: false };

export function ProjectArchivePreflight({ active }: { active: boolean }) {
  const [result, setResult] = useState<ProjectArchivePreflightResponse | null>(null);
  const [state, setState] = useState<LoadState>(initialLoadState);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!active) {
      return;
    }
    let disposed = false;
    async function load() {
      setState({ loading: true, unavailable: false });
      try {
        const nextResult = await api.getProjectArchivePreflight();
        if (!disposed) {
          setResult(nextResult);
          setState(initialLoadState);
        }
      } catch {
        if (!disposed) {
          setResult(null);
          setState({ loading: false, unavailable: true });
        }
      }
    }
    void load();
    return () => {
      disposed = true;
    };
  }, [active, attempt]);

  if (!active) {
    return null;
  }

  return (
    <section className="project-archive-preflight" aria-labelledby="project-archive-preflight-title">
      <div className="project-archive-preflight-heading">
        <h3 id="project-archive-preflight-title"><CircleHelp size={17} aria-hidden="true" /> Coverage preview</h3>
        {result ? <span className="status-pill ok">Passive catalog</span> : null}
      </div>
      <p className="muted">
        This catalog is source-free: it does not open, upload, hash, or inspect the file you choose.
      </p>

      {state.loading ? <p className="muted" role="status">Loading supported coverage…</p> : null}
      {state.unavailable ? (
        <div className="query-warning" role="status">
          <p>Coverage preview is unavailable. You can still choose an authorized archive safely; Inspectra will report actual coverage and limits after analysis.</p>
          <button className="secondary-button" type="button" onClick={() => setAttempt((value) => value + 1)}>
            <RefreshCw size={15} aria-hidden="true" /> Retry preview
          </button>
        </div>
      ) : null}

      {result ? <PreflightDetails result={result} /> : null}
    </section>
  );
}

function PreflightDetails({ result }: { result: ProjectArchivePreflightResponse }) {
  if (!result.analysis_profile) {
    return (
      <div className="project-archive-preflight-details">
        <dl className="project-archive-preflight-summary">
          <div><dt>Accepted archives</dt><dd>{result.accepted_archive_formats.join(", ")}</dd></div>
          <div><dt>Configured upload limit</dt><dd>{formatBytes(result.upload_limit_bytes)}</dd></div>
        </dl>
        <div className="query-warning" role="status">
          The coverage catalog response is incomplete. You may still select an authorized archive; actual analysis coverage will be reported after submission.
        </div>
      </div>
    );
  }
  return (
    <div className="project-archive-preflight-details">
      <dl className="project-archive-preflight-summary">
        <div><dt>Accepted archives</dt><dd>{result.accepted_archive_formats.join(", ")}</dd></div>
        <div><dt>Configured upload limit</dt><dd>{formatBytes(result.upload_limit_bytes)}</dd></div>
        <div><dt>Analysis profile</dt><dd>{result.analysis_profile.title}</dd></div>
        <div><dt>Ruleset</dt><dd><code>{result.analysis_profile.ruleset_version}</code></dd></div>
      </dl>

      <section aria-labelledby="project-archive-profile-rules">
        <h4 id="project-archive-profile-rules">Safe default profile</h4>
        <p className="muted">
          Inspectra selects rule packs only from detected supported manifests. Network is {result.analysis_profile.network_access}; project code is not executed.
        </p>
        <ul>
          {result.analysis_profile.rules.map((rule) => (
            <li key={rule.id}>
              <strong>{rule.id.replace(/_/g, " ")}</strong>
              <span>{rule.applies_to.join(", ")} · {rule.description}</span>
            </li>
          ))}
        </ul>
        <details>
          <summary>Not included in this profile</summary>
          <ul>{result.analysis_profile.exclusions.map((item) => <li key={item}>{item}</li>)}</ul>
        </details>
      </section>

      <section aria-labelledby="project-archive-supported-manifests">
        <h4 id="project-archive-supported-manifests">Detected and parsed</h4>
        <ul>
          {result.supported_manifests.map((item) => <li key={item.name}><strong>{item.name}</strong> <span>{item.ecosystem} · {item.coverage}</span></li>)}
        </ul>
      </section>
      <section aria-labelledby="project-archive-exact-resolution">
        <h4 id="project-archive-exact-resolution">Exact version resolution</h4>
        <ul>
          {result.exact_resolution.map((item) => <li key={item.name}><strong>{item.name}</strong> <span>{item.ecosystem} · {item.coverage}</span></li>)}
        </ul>
      </section>
      <p className="muted preflight-detected-limit">
        <strong>Detected but not used for resolution:</strong> {result.detected_not_resolved.join(", ")}.
      </p>
      <div className="project-archive-preflight-boundary" role="note">
        <ShieldCheck size={17} aria-hidden="true" />
        <ul>
          {result.boundaries.map((item) => <li key={item}>{item}</li>)}
        </ul>
      </div>
      <p className="muted preflight-limitations">{result.limitations.join(" ")}</p>
    </div>
  );
}

function formatBytes(value: number) {
  const mebibytes = value / (1024 * 1024);
  return Number.isInteger(mebibytes) ? `${mebibytes} MiB` : `${Math.ceil(mebibytes * 10) / 10} MiB`;
}
