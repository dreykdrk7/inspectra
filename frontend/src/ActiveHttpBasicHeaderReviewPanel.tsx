import { FormEvent, useState } from "react";
import { Play, ShieldCheck } from "lucide-react";

import { ApiError, api } from "./api";
import { buildActiveHttpBasicHeaderReviewReport } from "./activeHttpBasicHeaderReviewReport";
import type { ActiveHttpBasicHeaderReviewRequest, JobRecord } from "./types";

type ActiveHttpBasicHeaderReviewPanelProps = {
  onJobCreated?: (job: JobRecord) => void | Promise<void>;
};

type RequestState = {
  loading: boolean;
  error: string | null;
  job: JobRecord | null;
};

const initialRequestState: RequestState = {
  loading: false,
  error: null,
  job: null
};

export function ActiveHttpBasicHeaderReviewPanel({ onJobCreated }: ActiveHttpBasicHeaderReviewPanelProps) {
  const [target, setTarget] = useState("");
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [targetControlConfirmed, setTargetControlConfirmed] = useState(false);
  const [delegatedPermissionConfirmed, setDelegatedPermissionConfirmed] = useState(false);
  const [liveHttpRequestConfirmed, setLiveHttpRequestConfirmed] = useState(false);
  const [requestState, setRequestState] = useState<RequestState>(initialRequestState);
  const targetPermissionConfirmed = targetControlConfirmed || delegatedPermissionConfirmed;
  const canSubmit =
    !requestState.loading &&
    target.trim().length > 0 &&
    authorizationConfirmed &&
    targetPermissionConfirmed &&
    liveHttpRequestConfirmed;

  async function submitActiveHttpBasicHeaderReview(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canSubmit) {
      return;
    }

    const request: ActiveHttpBasicHeaderReviewRequest = {
      mode: "live_http_basic_header_review",
      profile: "http_headers_single_request",
      target: target.trim(),
      method: "HEAD",
      authorization_confirmed: authorizationConfirmed,
      target_control_confirmed: targetControlConfirmed,
      delegated_permission_confirmed: delegatedPermissionConfirmed,
      live_http_request_confirmed: liveHttpRequestConfirmed
    };

    setRequestState({ loading: true, error: null, job: null });
    try {
      const job = await api.createActiveHttpBasicHeaderReview(request);
      if (!isAcceptedJobRecord(job)) {
        setRequestState({
          loading: false,
          job: null,
          error: "Active / HTTP header review was not accepted as a stored no-live job. Review bounds and confirmations."
        });
        return;
      }
      await onJobCreated?.(job);
      setRequestState({ loading: false, error: null, job });
    } catch (error) {
      const disabled = error instanceof ApiError && error.status === 403;
      setRequestState({
        loading: false,
        job: null,
        error: disabled
          ? "Active / HTTP header review is disabled or unavailable in this environment."
          : "Active / HTTP header review request was not accepted. Review bounds and confirmations."
      });
    }
  }

  return (
    <section className="panel active-http-basic-header-review-panel" aria-label="Active / HTTP header review">
      <div className="panel-header">
        <h2>
          <ShieldCheck size={18} aria-hidden="true" />
          Active / HTTP header review
        </h2>
        <span className="status-pill">No-live record</span>
      </div>

      <div className="badge-row" aria-label="Active HTTP header review guardrails">
        <span className="status-pill">One authorized URL</span>
        <span className="status-pill">HEAD fixed</span>
        <span className="status-pill">No HTTP request in this phase</span>
        <span className="status-pill">Manual validation required</span>
      </div>

      <p className="muted">
        This creates an Active / HTTP header review job record through the backend contract. The current phase stores a no-live review record
        and no HTTP request is performed yet.
      </p>

      <div className="query-warning" role="status">
        Stored display is redaction-first: target is shown as [REDACTED_TARGET], result status is not_executed, requests_sent is 0, redirects
        are not followed, and response body is not read.
      </div>

      <dl className="summary-list">
        <dt>Mode</dt>
        <dd className="mono">live_http_basic_header_review</dd>
        <dt>Profile</dt>
        <dd className="mono">http_headers_single_request</dd>
        <dt>Method</dt>
        <dd className="mono">HEAD</dd>
        <dt>Result wording</dt>
        <dd>HTTP header review indicator. Manual validation required.</dd>
        <dt>Current execution</dt>
        <dd>No live HTTP request was performed; no headers, cookies, redirects, or response body are stored.</dd>
      </dl>

      <form className="web-audit-form" onSubmit={(event) => void submitActiveHttpBasicHeaderReview(event)}>
        <label className="auth-field">
          <span>URL target</span>
          <input
            type="url"
            value={target}
            onChange={(event) => {
              setTarget(event.target.value);
              setRequestState(initialRequestState);
            }}
            required
          />
        </label>
        <label className="auth-field">
          <span>Method</span>
          <input type="text" value="HEAD" readOnly aria-readonly="true" />
        </label>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={authorizationConfirmed}
            onChange={(event) => {
              setAuthorizationConfirmed(event.target.checked);
              setRequestState(initialRequestState);
            }}
          />
          I confirm I own or am authorized to test this URL.
        </label>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={targetControlConfirmed}
            onChange={(event) => {
              setTargetControlConfirmed(event.target.checked);
              setRequestState(initialRequestState);
            }}
          />
          I confirm I control this target.
        </label>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={delegatedPermissionConfirmed}
            onChange={(event) => {
              setDelegatedPermissionConfirmed(event.target.checked);
              setRequestState(initialRequestState);
            }}
          />
          I confirm I have delegated permission for this target.
        </label>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={liveHttpRequestConfirmed}
            onChange={(event) => {
              setLiveHttpRequestConfirmed(event.target.checked);
              setRequestState(initialRequestState);
            }}
          />
          I understand this contract is for a future live HTTP request, while this phase stores a no-live record and performs no HTTP request.
        </label>
        <button type="submit" disabled={!canSubmit}>
          <Play size={16} aria-hidden="true" />
          {requestState.loading ? "Creating HTTP header review job" : "Create HTTP header review job"}
        </button>
      </form>
      {requestState.error ? <p className="error-text">{requestState.error}</p> : null}
      {requestState.job ? <ActiveHttpBasicHeaderReviewJobCreatedNotice job={requestState.job} /> : null}
    </section>
  );
}

function ActiveHttpBasicHeaderReviewJobCreatedNotice({ job }: { job: JobRecord }) {
  const report = buildActiveHttpBasicHeaderReviewReport(job);
  return (
    <div className="query-warning" role="status">
      <strong>HTTP header review indicator job created.</strong>
      <dl className="summary-list">
        <dt>Job</dt>
        <dd className="mono">{job.id}</dd>
        <dt>Result status</dt>
        <dd className="mono">{report.status}</dd>
        <dt>Target</dt>
        <dd className="mono">{report.target}</dd>
        <dt>Method</dt>
        <dd className="mono">{report.method}</dd>
        <dt>Requests sent</dt>
        <dd>0</dd>
        <dt>Live request performed</dt>
        <dd>false</dd>
        <dt>Validation</dt>
        <dd>Manual validation required.</dd>
      </dl>
      <p className="muted">No live HTTP request was performed. The job record was opened below when the dashboard integration is available.</p>
    </div>
  );
}

function isAcceptedJobRecord(job: JobRecord): boolean {
  return (
    typeof job.id === "string" &&
    job.audit_type === "active_http_basic_header_review" &&
    job.status === "completed" &&
    job.result?.result_status === "not_executed"
  );
}
