import { FormEvent, useState } from "react";

import { ApiError, api } from "./api";
import type { ProjectCreated, SbomImportPreflight } from "./types";


export function SbomImportPanel({ onImported }: { onImported: (created: ProjectCreated) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [name, setName] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [publicIdentities, setPublicIdentities] = useState(false);
  const [loading, setLoading] = useState(false);
  const [preflightLoading, setPreflightLoading] = useState(false);
  const [preflight, setPreflight] = useState<SbomImportPreflight | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file || !preflight || !authorized) return;
    setLoading(true);
    setError(null);
    try {
      onImported(await api.importSbomProject(file, name.trim(), preflight.preflight_token, publicIdentities));
      setFile(null);
      setName("");
      setAuthorized(false);
      setPublicIdentities(false);
      setPreflight(null);
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "The SBOM could not be imported safely.");
    } finally {
      setLoading(false);
    }
  }

  async function runPreflight() {
    if (!file) return;
    setPreflightLoading(true);
    setPreflight(null);
    setAuthorized(false);
    setPublicIdentities(false);
    setError(null);
    try {
      setPreflight(await api.preflightSbomProject(file));
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "The SBOM preflight could not be completed safely.");
    } finally {
      setPreflightLoading(false);
    }
  }

  function selectFile(selected: File | null) {
    setFile(selected);
    setPreflight(null);
    setAuthorized(false);
    setPublicIdentities(false);
    setError(null);
  }

  return (
    <section id="sbom-import" className="card" aria-labelledby="sbom-import-title">
      <p className="eyebrow">Repository-free onboarding</p>
      <h2 id="sbom-import-title">Import an immutable SBOM</h2>
      <p className="muted">CycloneDX JSON 1.4–1.6 or SPDX JSON 2.2–2.3. Inspectra keeps only normalized npm, PyPI, or supported Maven purls; URLs, hashes, paths and free-form metadata are discarded.</p>
      <form className="sbom-import-form" onSubmit={(event) => void submit(event)}>
        <label>Project name<input value={name} minLength={3} maxLength={120} onChange={(event) => setName(event.target.value)} required /></label>
        <label>SBOM JSON<input id="sbom-import-file" type="file" accept="application/json,.json" onChange={(event) => selectFile(event.target.files?.[0] ?? null)} required /></label>
        <button type="button" className="secondary-button" onClick={() => void runPreflight()} disabled={!file || preflightLoading || loading}>
          {preflightLoading ? "Checking privately…" : preflight ? "Run preflight again" : "Review SBOM safely"}
        </button>
        {preflight ? (
          <section className="sbom-preflight-result" aria-labelledby="sbom-preflight-result-title">
            <h3 id="sbom-preflight-result-title">Preflight ready</h3>
            <p><strong>{preflight.format === "cyclonedx" ? "CycloneDX" : "SPDX"} {preflight.spec_version}</strong> · {preflight.retained_components} retained of {preflight.input_components} observed components.</p>
            <p>{preflight.potentially_correlatable_components} exact supported npm, PyPI, or Maven identities can become eligible only after your attestation; {preflight.rejected_or_ambiguous_components} {preflight.rejected_or_ambiguous_components === 1 ? "entry is" : "entries are"} rejected or ambiguous.</p>
            {preflight.component_limit_reached || preflight.relationship_graph_truncated ? <p className="warning-text">Coverage reached a defensive limit. Import is possible, but component or relationship coverage will be explicitly partial.</p> : null}
            <p className="muted">This review expires at {formatExpiry(preflight.expires_at)} and retained no original SBOM, filename, package name, purl, path, URL, hash, or free-form metadata.</p>
          </section>
        ) : <p className="muted sbom-preflight-prompt">Run the private, no-egress preflight to review aggregate coverage before authorization and public-identity attestation become available.</p>}
        {preflight ? <>
          <label className="checkbox-field"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} />I am authorized to import and analyze this exact preflighted SBOM.</label>
          <label className="checkbox-field"><input type="checkbox" checked={publicIdentities} onChange={(event) => setPublicIdentities(event.target.checked)} />I attest that retained supported npm, PyPI, and Maven purls are public identities that may be sent to enabled advisory providers.</label>
        </> : null}
        <button type="submit" disabled={loading || !file || !preflight || !authorized || name.trim().length < 3}>{loading ? "Importing…" : "Import preflighted SBOM"}</button>
      </form>
      {error ? <div className="alert" role="alert">{error}</div> : null}
    </section>
  );
}

function formatExpiry(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "an unknown time" : date.toLocaleTimeString();
}
