import { FormEvent, useEffect, useMemo, useState } from "react";

import { ApiError, api } from "./api";
import type {
  FindingDecisionStatus,
  FindingLifecycleState,
  NormalizedFinding,
  TeamMember,
} from "./types";


const labels: Record<FindingDecisionStatus, string> = {
  open: "Open",
  in_review: "In review",
  accepted: "Risk accepted",
  false_positive: "False positive",
  resolved: "Resolved",
};

const transitions: Record<FindingDecisionStatus, FindingDecisionStatus[]> = {
  open: ["in_review", "accepted", "false_positive", "resolved"],
  in_review: ["open", "accepted", "false_positive", "resolved"],
  accepted: ["open", "in_review", "resolved"],
  false_positive: ["open", "in_review"],
  resolved: ["open", "in_review"],
};

type FindingLifecyclePanelProps = {
  projectId: string;
  analysisId: string;
  finding: NormalizedFinding;
  lifecycle?: FindingLifecycleState;
  canManage: boolean;
  members?: TeamMember[];
  onUpdated: () => Promise<void>;
};

export function FindingLifecyclePanel({
  projectId,
  analysisId,
  finding,
  lifecycle,
  canManage,
  members = [],
  onUpdated,
}: FindingLifecyclePanelProps) {
  const currentStatus = lifecycle?.current_status ?? "open";
  const availableStatuses = useMemo(
    () => lifecycle?.has_decision ? transitions[currentStatus] : (["open", ...transitions.open] as FindingDecisionStatus[]),
    [currentStatus, lifecycle?.has_decision],
  );
  const [status, setStatus] = useState<FindingDecisionStatus>(availableStatuses[0] ?? "in_review");
  const [reason, setReason] = useState("");
  const [comment, setComment] = useState("");
  const [assigneeUserId, setAssigneeUserId] = useState("");
  const [reviewAt, setReviewAt] = useState("");
  const [exceptionConfirmed, setExceptionConfirmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const isException = status === "accepted" || status === "false_positive";
  const reviewDateBounds = useMemo(() => exceptionReviewDateBounds(), []);

  useEffect(() => {
    if (!availableStatuses.includes(status)) {
      setStatus(availableStatuses[0] ?? "in_review");
      setExceptionConfirmed(false);
    }
  }, [availableStatuses, status]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    setNotice(null);
    try {
      await api.createProjectFindingDecision(projectId, finding.id, {
        analysis_id: analysisId,
        status,
        reason,
        comment: comment.trim() || null,
        assignee_user_id: assigneeUserId || null,
        review_at: isException && reviewAt ? `${reviewAt}:00Z` : null,
      });
      setReason("");
      setComment("");
      setReviewAt("");
      setExceptionConfirmed(false);
      await onUpdated();
      setNotice(`${labels[status]} decision recorded. The analyzer evidence was not changed.`);
    } catch (caught) {
      setError(decisionErrorMessage(caught));
    } finally {
      setSubmitting(false);
    }
  }

  const decision = lifecycle?.current_decision;
  return (
    <section className="finding-lifecycle" aria-label={`Workflow for ${finding.title}`}>
      <div className="finding-lifecycle-heading">
        <div>
          <h3>Finding workflow</h3>
          <p className="muted">Decisions are append-only and never rewrite the recorded analyzer evidence.</p>
        </div>
        <span className={`finding-status-badge ${currentStatus}`}>{labels[currentStatus]}</span>
      </div>

      {lifecycle?.review_overdue ? (
        <p className="query-warning" role="status">The review date has passed. This finding requires a new decision.</p>
      ) : null}
      {decision ? (
        <dl className="summary-list finding-lifecycle-summary">
          <dt>Latest reason</dt>
          <dd>{decision.reason}</dd>
          <dt>Assigned to</dt>
          <dd>{decision.assignee_username ?? "Unassigned"}</dd>
          <dt>Recorded by</dt>
          <dd>{decision.actor_username}</dd>
          <dt>Recorded at</dt>
          <dd>{formatDate(decision.created_at)}</dd>
          <dt>Review at</dt>
          <dd>{decision.review_at ? formatDate(decision.review_at) : "Not scheduled"}</dd>
        </dl>
      ) : (
        <p className="empty-state compact-empty-state">No triage decision has been recorded. The default state is open.</p>
      )}

      {canManage ? (
        <form className="finding-decision-form" onSubmit={(event) => void submit(event)}>
          <label className="auth-field">
            <span>New status</span>
            <select value={status} onChange={(event) => {
              setStatus(event.target.value as FindingDecisionStatus);
              setExceptionConfirmed(false);
            }}>
              {availableStatuses.map((item) => <option key={item} value={item}>{labels[item]}</option>)}
            </select>
          </label>
          <label className="auth-field">
            <span>Decision reason</span>
            <input
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              minLength={3}
              maxLength={240}
              required
              placeholder="Why this status is appropriate"
            />
          </label>
          {members.length ? (
            <label className="auth-field">
              <span>Assign to</span>
              <select value={assigneeUserId} onChange={(event) => setAssigneeUserId(event.target.value)}>
                <option value="">Unassigned</option>
                {members.map((member) => (
                  <option key={member.user_id} value={member.user_id}>{member.username} — {member.role}</option>
                ))}
              </select>
            </label>
          ) : null}
          {isException ? (
            <>
              <label className="auth-field">
                <span>Review date (UTC)</span>
                <input
                  type="datetime-local"
                  value={reviewAt}
                  min={reviewDateBounds.minimum}
                  max={reviewDateBounds.maximum}
                  aria-describedby={`exception-review-help-${finding.id}`}
                  onInput={(event) => setReviewAt(event.currentTarget.value)}
                  required
                />
              </label>
              <p id={`exception-review-help-${finding.id}`} className="muted finding-decision-review-help">
                Required for exceptions. Choose a future UTC time no more than 366 days away.
              </p>
              <label className="authorization-check finding-decision-confirmation">
                <input
                  type="checkbox"
                  checked={exceptionConfirmed}
                  onChange={(event) => setExceptionConfirmed(event.target.checked)}
                />
                <span>I confirm this exception does not remove evidence and must be reviewed when its date expires.</span>
              </label>
            </>
          ) : null}
          <label className="auth-field finding-decision-comment">
            <span>Comment (optional; do not include secrets)</span>
            <textarea value={comment} onChange={(event) => setComment(event.target.value)} maxLength={1_000} rows={3} />
          </label>
          {error ? <p className="error-text" role="alert">{error}</p> : null}
          {notice ? <p className="success-text" role="status">{notice}</p> : null}
          <button type="submit" disabled={submitting || reason.trim().length < 3 || (isException && (!exceptionConfirmed || !reviewAt))}>
            {submitting ? "Recording decision" : "Record decision"}
          </button>
        </form>
      ) : (
        <p className="muted">Your role can review this history but cannot change finding workflow.</p>
      )}

      {lifecycle?.history.length ? (
        <details className="finding-decision-history">
          <summary>Decision history ({lifecycle.history.length})</summary>
          <ol>
            {lifecycle.history.map((item) => (
              <li key={item.id}>
                <strong>{labels[item.status]}</strong> · {formatDate(item.created_at)} · {item.actor_username}
                <span>{item.reason}</span>
                {item.comment ? <span>{item.comment}</span> : null}
              </li>
            ))}
          </ol>
        </details>
      ) : null}
    </section>
  );
}

export function findingStatusLabel(status: FindingDecisionStatus): string {
  return labels[status];
}

function decisionErrorMessage(error: unknown): string {
  if (error instanceof ApiError && error.status === 409) {
    return "This status changed or cannot follow the latest decision. Refresh the finding and reopen it first if needed.";
  }
  if (error instanceof ApiError && error.status === 422) {
    return "Review the reason, assignment and future review date, then try again.";
  }
  return "The decision could not be recorded. The finding evidence remains unchanged; refresh and try again.";
}

function formatDate(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Unknown time" : parsed.toLocaleString();
}

function exceptionReviewDateBounds(now = new Date()): { minimum: string; maximum: string } {
  const minimum = new Date(now.getTime() + 60_000);
  const maximum = new Date(now.getTime() + 366 * 24 * 60 * 60 * 1_000);
  return { minimum: utcDateTimeLocal(minimum), maximum: utcDateTimeLocal(maximum) };
}

function utcDateTimeLocal(value: Date): string {
  return value.toISOString().slice(0, 16);
}
