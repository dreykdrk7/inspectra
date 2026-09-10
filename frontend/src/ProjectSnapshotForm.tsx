import { FormEvent, useMemo, useRef, useState } from "react";
import { FilePlus2, Play, X } from "lucide-react";

import { ApiError, api, createIdempotencyKey } from "./api";
import type { FileRecord, ProjectSnapshotCreated, ProjectSummary } from "./types";

type ProjectSnapshotFormProps = {
  project: ProjectSummary;
  files: FileRecord[];
  onCompleted: (created: ProjectSnapshotCreated) => Promise<void>;
  onCancel: () => void;
};

export function ProjectSnapshotForm({ project, files, onCompleted, onCancel }: ProjectSnapshotFormProps) {
  const archives = useMemo(() => {
    const retainedReferences = new Set(
      (project.project.source_snapshots ?? []).map((snapshot) => snapshot.source_reference)
    );
    retainedReferences.add(project.project.source_reference);
    return files.filter((file) => file.kind === "archive" && !retainedReferences.has(file.source_reference ?? ""));
  }, [files, project.project.source_reference, project.project.source_snapshots]);
  const [sourceFileId, setSourceFileId] = useState(archives[0]?.id ?? "");
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pendingIdempotencyKey = useRef<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!sourceFileId || !authorizationConfirmed || loading) {
      return;
    }
    setError(null);
    setLoading(true);
    try {
      pendingIdempotencyKey.current ??= createIdempotencyKey();
      await onCompleted(await api.createProjectSnapshot(project.project.id, sourceFileId, pendingIdempotencyKey.current));
      pendingIdempotencyKey.current = null;
    } catch (requestError) {
      setError(requestError instanceof ApiError ? requestError.message : "Unable to add the project snapshot. Try again.");
    } finally {
      setLoading(false);
    }
  }

  if (project.project.source_type === "sbom" || project.latest_job?.analysis_profile === "sbom_import") {
    return (
      <section className="panel project-snapshot-form" aria-labelledby="project-snapshot-title">
        <h2 id="project-snapshot-title">Archive snapshot unavailable</h2>
        <p className="empty-state">This is an SBOM project. Add a compatible SBOM revision from its workspace instead of attaching an archive.</p>
        <button type="button" className="secondary-button" onClick={onCancel}><X size={15} aria-hidden="true" /> Close</button>
      </section>
    );
  }

  return (
    <section className="panel project-snapshot-form" aria-labelledby="project-snapshot-title">
      <div className="panel-header">
        <div>
          <h2 id="project-snapshot-title"><FilePlus2 size={18} aria-hidden="true" /> Add project snapshot</h2>
          <p className="muted">Choose a new archive you own or are authorized to analyze. The recorded history remains unchanged.</p>
        </div>
      </div>
      {archives.length === 0 ? (
        <p className="empty-state">Upload a different ZIP or TAR archive before adding another snapshot to {project.project.name}.</p>
      ) : (
        <form className="web-audit-form" onSubmit={(event) => void submit(event)}>
          <label className="auth-field">
            <span>New archive snapshot</span>
            <select
              value={sourceFileId}
              onChange={(event) => {
                setSourceFileId(event.target.value);
                pendingIdempotencyKey.current = null;
                setError(null);
              }}
              disabled={loading}
            >
              {archives.map((archive) => <option key={archive.id} value={archive.id}>{archive.original_filename}</option>)}
            </select>
          </label>
          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={authorizationConfirmed}
              onChange={(event) => setAuthorizationConfirmed(event.target.checked)}
              disabled={loading}
            />
            I confirm I own or am authorized to analyze this archive as a project snapshot.
          </label>
          <div className="row-actions">
            <button type="submit" disabled={!sourceFileId || !authorizationConfirmed || loading}>
              <Play size={15} aria-hidden="true" />
              {loading ? "Adding snapshot" : "Add snapshot & analyze"}
            </button>
            <button type="button" className="secondary-button" onClick={onCancel} disabled={loading}>
              <X size={15} aria-hidden="true" /> Cancel
            </button>
          </div>
          {error ? <p className="error-text" role="alert">{error}</p> : null}
        </form>
      )}
    </section>
  );
}
