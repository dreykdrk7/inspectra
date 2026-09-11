import { useEffect, useId, useState } from "react";
import { AlertTriangle, RefreshCw, ShieldAlert, Trash2 } from "lucide-react";

import { ApiError, api } from "./api";
import type {
  ProjectDeletionPreview,
  ProjectDeletionResponse,
  ProjectDeletionScopeItem,
  ProjectSummary
} from "./types";

type PanelState = {
  loading: boolean;
  deleting: boolean;
  error: string | null;
};

const initialState: PanelState = { loading: false, deleting: false, error: null };

export function ProjectDeletionPanel({
  project,
  canDelete,
  onDeleted
}: {
  project: ProjectSummary;
  canDelete: boolean;
  onDeleted: (result: ProjectDeletionResponse) => void | Promise<void>;
}) {
  const [preview, setPreview] = useState<ProjectDeletionPreview | null>(null);
  const [result, setResult] = useState<ProjectDeletionResponse | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [state, setState] = useState<PanelState>(initialState);
  const confirmationId = useId();

  useEffect(() => {
    setPreview(null);
    setResult(null);
    setConfirmed(false);
    setState(initialState);
  }, [project.project.id]);

  async function reviewScope() {
    setState({ loading: true, deleting: false, error: null });
    setConfirmed(false);
    try {
      setPreview(await api.getProjectDeletionPreview(project.project.id));
      setState(initialState);
    } catch (error) {
      setState({ loading: false, deleting: false, error: deletionErrorMessage(error, "preview") });
    }
  }

  async function deleteProject() {
    setState({ loading: false, deleting: true, error: null });
    try {
      const deleted = await api.deleteProject(project.project.id);
      setResult(deleted);
      setState(initialState);
      await onDeleted(deleted);
    } catch (error) {
      setState({ loading: false, deleting: false, error: deletionErrorMessage(error, "delete") });
    }
  }

  return (
    <section className="panel project-deletion-panel" aria-labelledby="project-deletion-title">
      <div className="panel-header">
        <div>
          <h2 id="project-deletion-title"><ShieldAlert size={18} aria-hidden="true" /> Delete project data</h2>
          <p className="muted">
            Review the exact local cascade before removing this project. Uploaded archives, bounded audit events and the shared public-advisory cache have independent lifecycles.
          </p>
        </div>
        <button className="secondary-button" onClick={() => void reviewScope()} disabled={state.loading || state.deleting}>
          <RefreshCw size={16} aria-hidden="true" /> {state.loading ? "Reviewing" : preview ? "Refresh scope" : "Review deletion scope"}
        </button>
      </div>

      {!preview && !result && !state.loading ? (
        <div className="project-deletion-notice" role="note">
          <AlertTriangle size={18} aria-hidden="true" />
          <p>This action is irreversible for project history. Inspectra will not infer that an uploaded source can be deleted safely.</p>
        </div>
      ) : null}
      {state.loading ? <p className="muted" role="status">Checking active work and project-scoped data…</p> : null}
      {state.error ? <p className="error-text" role="alert">{state.error}</p> : null}
      {result ? (
        <p className="success-text" role="status">
          The project and its derived records were removed. Uploaded source files remain visible in Files until you delete them or retention expires.
        </p>
      ) : null}

      {preview ? (
        <>
          <div className="project-deletion-scope" aria-label="Project deletion scope">
            {preview.items.map((item) => <ScopeItem key={item.key} item={item} />)}
          </div>

          {preview.state === "blocked_active_work" ? (
            <p className="alert" role="alert">
              Deletion is blocked while a project analysis or snapshot admission is active. Cancel it and wait for a completed, failed or cancelled state, then refresh this scope.
            </p>
          ) : canDelete ? (
            <div className="project-deletion-confirmation">
              <label className="confirmation-row" htmlFor={confirmationId}>
                <input
                  id={confirmationId}
                  type="checkbox"
                  checked={confirmed}
                  onChange={(event) => setConfirmed(event.target.checked)}
                />
                <span>
                  I understand that project history, analysis results, vulnerability snapshots and triage decisions will be permanently deleted, while uploaded archives and bounded audit records remain.
                </span>
              </label>
              <button
                className="danger-button"
                disabled={!confirmed || state.deleting}
                onClick={() => void deleteProject()}
              >
                <Trash2 size={16} aria-hidden="true" /> {state.deleting ? "Deleting safely" : "Delete project and derived data"}
              </button>
            </div>
          ) : (
            <p className="muted">Your reader role can review this scope but cannot delete workspace data.</p>
          )}
        </>
      ) : null}
    </section>
  );
}

function ScopeItem({ item }: { item: ProjectDeletionScopeItem }) {
  const count = item.item_count === null ? "Policy" : `${item.item_count} ${item.item_count === 1 ? "item" : "items"}`;
  return (
    <article className={`project-deletion-scope-item disposition-${item.disposition}`}>
      <div>
        <strong>{scopeLabel(item.key)}</strong>
        <span className="subtle-id">{count}</span>
      </div>
      <span className="status-pill">{dispositionLabel(item.disposition)}</span>
      <p className="muted">{item.detail}</p>
    </article>
  );
}

function scopeLabel(key: ProjectDeletionScopeItem["key"]): string {
  return ({
    project_metadata: "Project metadata",
    analysis_results: "Analysis results",
    public_advisory_snapshots: "Vulnerability snapshots",
    finding_decisions: "Triage decisions",
    snapshot_admissions: "Snapshot recovery records",
    execution_workspaces: "Execution workspaces",
    passive_project_actions: "Passive project actions",
    source_uploads: "Uploaded source files",
    report_exports: "Generated reports",
    public_advisory_cache: "Shared advisory cache",
    product_audit: "Product audit events"
  } as const)[key];
}

function dispositionLabel(disposition: ProjectDeletionScopeItem["disposition"]): string {
  if (disposition === "delete") return "Will delete";
  if (disposition === "retain") return "Will retain";
  return "Not stored";
}

function deletionErrorMessage(error: unknown, phase: "preview" | "delete"): string {
  if (error instanceof ApiError && error.status === 404) {
    return "This project is no longer available in the active workspace.";
  }
  if (error instanceof ApiError && error.status === 409) {
    return "Deletion is blocked by active project work. Cancel it, wait for a terminal state and review the scope again.";
  }
  if (error instanceof ApiError && error.status === 503) {
    return phase === "delete"
      ? "Deletion did not complete. Inspectra retained a safe retry record; check service health and try again."
      : "Deletion scope is temporarily unavailable. Check service health before continuing.";
  }
  return phase === "delete"
    ? "Unable to delete this project safely. No source upload was deleted. Review service health and try again."
    : "Unable to review the deletion scope. Refresh and try again.";
}
