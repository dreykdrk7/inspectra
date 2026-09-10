import { FormEvent, useState } from "react";

import { ApiError, api, createIdempotencyKey } from "./api";
import type { ProjectSbomRevisionCreated, ProjectSummary } from "./types";

export function SbomRevisionPanel({
  project,
  canImport,
  onImported,
}: {
  project: ProjectSummary;
  canImport: boolean;
  onImported: (created: ProjectSbomRevisionCreated) => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [idempotencyKey, setIdempotencyKey] = useState<string | null>(null);
  const [authorized, setAuthorized] = useState(false);
  const [publicIdentities, setPublicIdentities] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  function selectFile(selected: File | null) {
    setFile(selected);
    setIdempotencyKey(selected ? createIdempotencyKey() : null);
    setError(null);
    setNotice(null);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file || !idempotencyKey || !authorized || !canImport) return;
    setLoading(true);
    setError(null);
    setNotice(null);
    try {
      const created = await api.importProjectSbomRevision(
        project.project.id,
        file,
        idempotencyKey,
        publicIdentities,
      );
      onImported(created);
      setNotice(created.replayed
        ? "This exact SBOM revision was already retained. Its existing analysis is selected."
        : "The SBOM revision is retained and its completed analysis is ready to review.");
      setFile(null);
      setIdempotencyKey(null);
      setAuthorized(false);
      setPublicIdentities(false);
    } catch (caught) {
      setError(revisionErrorMessage(caught));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section id="sbom-revision" className="sbom-revision-card" aria-labelledby="sbom-revision-title" tabIndex={-1}>
      <p className="eyebrow">Immutable SBOM history</p>
      <h3 id="sbom-revision-title">Add a compatible SBOM revision</h3>
      <p className="muted">
        Upload the same SBOM format as this project. Inspectra normalizes it before retention and never stores the original filename, URLs, hashes, paths, or free-form metadata.
      </p>
      {!canImport ? (
        <p className="empty-state">Reader access can review SBOM history but cannot add a revision.</p>
      ) : (
        <form className="sbom-revision-form" onSubmit={(event) => void submit(event)}>
          <label>
            New SBOM JSON
            <input
              type="file"
              accept="application/json,.json"
              onChange={(event) => selectFile(event.target.files?.[0] ?? null)}
              required
            />
          </label>
          <label className="checkbox-field">
            <input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} />
            I am authorized to import and analyze this SBOM revision.
          </label>
          <label className="checkbox-field">
            <input type="checkbox" checked={publicIdentities} onChange={(event) => setPublicIdentities(event.target.checked)} />
            I attest that retained supported npm, PyPI, and Maven purls are public identities that may be sent to enabled advisory providers.
          </label>
          <button type="submit" disabled={loading || !file || !authorized}>
            {loading ? "Importing revision…" : "Add SBOM revision"}
          </button>
        </form>
      )}
      {error ? <p className="error-text" role="alert">{error}</p> : null}
      {notice ? <p className="success-text" role="status">{notice}</p> : null}
    </section>
  );
}

function revisionErrorMessage(error: unknown): string {
  if (error instanceof ApiError && error.status === 409) {
    return "This SBOM is incompatible, already retained under another request, or the project revision limit was reached. Review the current project history.";
  }
  if (error instanceof ApiError && error.status === 413) {
    return "The SBOM exceeds the configured upload limit.";
  }
  if (error instanceof ApiError && error.status === 400) {
    return "The SBOM format, version, component contract, or authorization is invalid.";
  }
  if (error instanceof ApiError && error.status === 404) {
    return "This project is no longer available to the current workspace.";
  }
  return "The SBOM revision could not be retained safely. The current project revision was not changed.";
}
