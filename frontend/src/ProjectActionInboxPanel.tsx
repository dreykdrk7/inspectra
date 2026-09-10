import { useEffect, useRef, useState } from "react";
import { BellRing, FolderOpen, RefreshCw } from "lucide-react";

import { ApiError, api } from "./api";
import type { ProjectActionItem, ProjectActionPage, ProjectSummary } from "./types";

type ProjectActionInboxPanelProps = {
  canRebuild: boolean;
  onOpenProject: (project: ProjectSummary) => void;
};

const reasonCopy: Record<ProjectActionItem["reason"], { title: string; next: string }> = {
  known_exploited: { title: "Known exploitation signal", next: "Review the correlated CVE and prioritize mitigation." },
  critical_findings: { title: "Critical findings", next: "Open findings and assign the highest-impact remediation." },
  latest_analysis_failed: { title: "Latest analysis failed", next: "Review the execution state before retrying the same snapshot." },
  coverage_lost: { title: "Coverage decreased", next: "Compare coverage before interpreting resolved findings." },
  high_findings: { title: "High-severity findings", next: "Review and assign high-severity remediation." },
  new_findings: { title: "New findings", next: "Compare with the baseline and triage the new evidence." },
  analysis_incomplete: { title: "Analysis evidence is incomplete", next: "Review skipped or truncated coverage before making a risk decision." },
  public_intelligence_stale: { title: "Public intelligence is stale", next: "Refresh only with the operator-approved egress policy." },
  public_intelligence_failed: { title: "Public source is degraded", next: "Keep the retained result and retry after provider recovery." },
  exception_review_due: { title: "Exception review is due", next: "Reassess the temporary exception before its deadline." },
  pending_triage: { title: "Findings need triage", next: "Confirm, assign, or justify a time-bounded exception." },
  no_baseline: { title: "No comparison baseline", next: "Choose a trustworthy completed analysis as the baseline." },
  no_recent_analysis: { title: "No recent analysis", next: "Submit a new authorized snapshot when the project changes." },
  no_completed_analysis: { title: "No completed analysis", next: "Review the latest execution or start the first analysis." },
};

export function ProjectActionInboxPanel({ canRebuild, onOpenProject }: ProjectActionInboxPanelProps) {
  const [page, setPage] = useState<ProjectActionPage | null>(null);
  const [unreadOnly, setUnreadOnly] = useState(true);
  const [loading, setLoading] = useState(true);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const statusRef = useRef<HTMLParagraphElement>(null);

  useEffect(() => {
    let disposed = false;
    setLoading(true);
    setError(null);
    void api.getProjectActions({ unreadOnly, limit: 100 })
      .then((result) => {
        if (!disposed) setPage(result);
      })
      .catch((failure) => {
        if (!disposed) setError(actionErrorMessage(failure));
      })
      .finally(() => {
        if (!disposed) setLoading(false);
      });
    return () => { disposed = true; };
  }, [unreadOnly]);

  async function refresh() {
    setLoading(true);
    setError(null);
    try {
      setPage(await api.getProjectActions({ unreadOnly, limit: 100 }));
    } catch (failure) {
      setError(actionErrorMessage(failure));
    } finally {
      setLoading(false);
    }
  }

  async function markRead(action: ProjectActionItem) {
    setBusyAction(action.id);
    setError(null);
    try {
      await api.markProjectActionRead(action.id);
      setPage(await api.getProjectActions({ unreadOnly, limit: 100 }));
    } catch (failure) {
      setError(actionErrorMessage(failure));
      window.requestAnimationFrame(() => statusRef.current?.focus());
    } finally {
      setBusyAction(null);
    }
  }

  async function openProject(action: ProjectActionItem) {
    setBusyAction(action.id);
    setError(null);
    try {
      onOpenProject(await api.getProject(action.project_id));
    } catch (failure) {
      setError(actionErrorMessage(failure));
      window.requestAnimationFrame(() => statusRef.current?.focus());
    } finally {
      setBusyAction(null);
    }
  }

  async function rebuild() {
    setLoading(true);
    setError(null);
    try {
      const result = await api.rebuildProjectActions();
      setPage(unreadOnly ? { ...result, items: result.items.filter((item) => !item.read) } : result);
    } catch (failure) {
      setError(actionErrorMessage(failure));
    } finally {
      setLoading(false);
    }
  }

  const visibleCount = page?.items.length ?? 0;

  return (
    <section className="project-action-inbox" aria-labelledby="project-action-inbox-title" aria-busy={loading}>
      <div className="project-action-inbox-heading">
        <div>
          <p className="eyebrow">Passive review</p>
          <h2 id="project-action-inbox-title"><BellRing size={19} aria-hidden="true" /> Project action inbox</h2>
          <p className="muted">Durable reminders derived from passive project state. This is separate from Active operations and stores no finding evidence or free text.</p>
        </div>
        <div className="project-action-inbox-controls">
          <button className="secondary-button" type="button" onClick={() => void refresh()} disabled={loading}>
            <RefreshCw size={16} aria-hidden="true" /> Refresh
          </button>
          {canRebuild ? <button className="secondary-button" type="button" onClick={() => void rebuild()} disabled={loading}>Rebuild index</button> : null}
        </div>
      </div>

      <label className="project-action-inbox-filter">
        <input type="checkbox" checked={unreadOnly} onChange={(event) => setUnreadOnly(event.target.checked)} />
        Show unread actions only
      </label>

      <p className="sr-only" role="status" aria-live="polite">
        {loading ? "Loading passive project actions." : page ? `${visibleCount} actions shown; ${page.unread} unread of ${page.total}.` : "Passive project actions unavailable."}
      </p>
      {error ? <p ref={statusRef} className="error-text" role="alert" tabIndex={-1}>{error}</p> : null}
      {loading && !page ? <p className="muted" role="status">Reconciling actions from the owner-scoped portfolio…</p> : null}
      {!loading && page && page.items.length === 0 ? (
        <div className="empty-state">
          <strong>{page.total === 0 ? "No project actions" : "No unread project actions"}</strong>
          <p>{page.total === 0 ? "No current passive risk or coverage signal requires action." : "Show all actions to revisit read reminders."}</p>
        </div>
      ) : null}
      {page && !page.source_complete ? (
        <p className="query-warning" role="note">The inbox reached its {page.retained_limit.toLocaleString()}-action safety limit. The visible list is incomplete; narrow work through the project portfolio.</p>
      ) : null}

      {page?.items.length ? (
        <ul className="project-action-inbox-list" aria-label="Passive project actions">
          {page.items.map((action) => {
            const copy = reasonCopy[action.reason];
            const busy = busyAction === action.id;
            return (
              <li className={`project-action-card priority-${action.priority}${action.read ? " is-read" : ""}`} key={action.id}>
                <div>
                  <span className={`status-pill portfolio-${action.priority}`}>{priorityLabel(action.priority)}</span>
                  <h3>{copy.title}</h3>
                  <p><strong>{action.project_name}</strong> · {destinationLabel(action.destination)}</p>
                  <p className="muted">{copy.next}</p>
                  <p className="muted"><time dateTime={action.occurred_at}>{formatDate(action.occurred_at)}</time>{action.read ? " · Read" : " · Unread"}</p>
                </div>
                <div className="project-action-card-actions">
                  <button type="button" onClick={() => void openProject(action)} disabled={busy}>
                    <FolderOpen size={16} aria-hidden="true" /> Open project
                  </button>
                  {!action.read ? <button className="secondary-button" type="button" onClick={() => void markRead(action)} disabled={busy}>Mark as read</button> : null}
                </div>
              </li>
            );
          })}
        </ul>
      ) : null}
    </section>
  );
}

function priorityLabel(priority: ProjectActionItem["priority"]): string {
  return ({ urgent: "Urgent", high: "High priority", review: "Review", monitor: "Monitor" })[priority];
}

function destinationLabel(destination: ProjectActionItem["destination"]): string {
  return ({ analysis: "analysis", findings: "findings", comparison: "comparison", public_intelligence: "public intelligence" })[destination];
}

function formatDate(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Unknown time" : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(parsed);
}

function actionErrorMessage(failure: unknown): string {
  if (failure instanceof ApiError && failure.status === 404) return "This action was resolved or rebuilt. Refresh the inbox for current state.";
  if (failure instanceof ApiError && failure.status === 503) return "The passive action index could not be verified. An administrator can rebuild it from the project portfolio.";
  return "Unable to update passive project actions. Project evidence was not changed; check service health and try again.";
}
