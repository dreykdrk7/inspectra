import { FormEvent, useMemo, useState } from "react";
import { LockKeyhole, Play } from "lucide-react";

import { ApiError, api } from "./api";
import type { ActiveTlsBasicRequest, JobRecord } from "./types";

type ActiveTlsBasicPanelProps = {
  onJobCreated?: (job: JobRecord) => void | Promise<void>;
};

type RequestState = {
  loading: boolean;
  error: string | null;
  job: JobRecord | null;
};

type PortValidationResult =
  | { ok: true; port: number; error: null }
  | { ok: false; port: null; error: string };

const ACTIVE_TLS_BASIC_ALLOWED_PORTS = new Set([443, 8443, 9443]);
const initialRequestState: RequestState = {
  loading: false,
  error: null,
  job: null
};

export function ActiveTlsBasicPanel({ onJobCreated }: ActiveTlsBasicPanelProps) {
  const [target, setTarget] = useState("");
  const [portText, setPortText] = useState("443");
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [localPrivateScopeConfirmed, setLocalPrivateScopeConfirmed] = useState(false);
  const [liveTrafficConfirmed, setLiveTrafficConfirmed] = useState(false);
  const [requestState, setRequestState] = useState<RequestState>(initialRequestState);
  const portValidation = useMemo(() => parseActiveTlsBasicPort(portText), [portText]);
  const canSubmit =
    !requestState.loading &&
    target.trim().length > 0 &&
    portValidation.ok &&
    authorizationConfirmed &&
    localPrivateScopeConfirmed &&
    liveTrafficConfirmed;

  async function submitActiveTlsBasic(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canSubmit || !portValidation.ok) {
      return;
    }

    const request: ActiveTlsBasicRequest = {
      mode: "live_tls_basic",
      profile: "tls_handshake_summary",
      target: target.trim(),
      port: portValidation.port,
      authorization_confirmed: true,
      local_private_scope_confirmed: true,
      live_traffic_confirmed: true
    };

    setRequestState({ loading: true, error: null, job: null });
    try {
      const job = await api.createActiveTlsBasic(request);
      await onJobCreated?.(job);
      setRequestState({ loading: false, error: null, job });
    } catch (error) {
      const disabled = error instanceof ApiError && error.status === 403;
      setRequestState({
        loading: false,
        job: null,
        error: disabled
          ? "Active / TLS basic is disabled or unavailable in this environment."
          : "Active / TLS basic request was not accepted. Review bounds and confirmations."
      });
    }
  }

  return (
    <section className="panel active-tls-basic-panel" aria-label="Active / TLS basic">
      <div className="panel-header">
        <h2>
          <LockKeyhole size={18} aria-hidden="true" />
          Active / TLS basic
        </h2>
        <span className="status-pill">Backend gated</span>
      </div>

      <div className="badge-row" aria-label="Active TLS basic guardrails">
        <span className="status-pill">Local/private/self-hosted only</span>
        <span className="status-pill">Authorized target only</span>
        <span className="status-pill">Bounded TLS handshake</span>
      </div>

      <p className="muted">
        This creates one authorized TLS handshake review indicator job through the backend contract.
      </p>

      <div className="query-warning" role="status">
        The backend remains the policy and storage authority. Certificate material, raw target values, exception details, and secrets are not
        displayed.
      </div>

      <dl className="summary-list">
        <dt>Mode</dt>
        <dd className="mono">live_tls_basic</dd>
        <dt>Profile</dt>
        <dd className="mono">tls_handshake_summary</dd>
        <dt>Scope</dt>
        <dd>One explicit local, private, or self-hosted target that the operator is allowed to test.</dd>
        <dt>Traffic</dt>
        <dd>One bounded TLS handshake attempt; no HTTP request, no crawling, no credential validation, and no target expansion.</dd>
        <dt>Result wording</dt>
        <dd>TLS handshake review indicator. Certificate expiry review indicator. Manual validation required.</dd>
        <dt>Stored display</dt>
        <dd>Target redacted, raw certificate PEM/DER omitted, raw exception details omitted, and Raw JSON redacted.</dd>
        <dt>Ports</dt>
        <dd className="mono">443, 8443, or 9443</dd>
        <dt>Excluded</dt>
        <dd>No custom headers, no cookies, no tokens, no credentials, no client certificates, no protocol fuzzing, and no crawler inputs.</dd>
      </dl>

      <form className="web-audit-form" onSubmit={(event) => void submitActiveTlsBasic(event)}>
        <label className="auth-field">
          <span>Target</span>
          <input
            type="text"
            value={target}
            onChange={(event) => {
              setTarget(event.target.value);
              setRequestState(initialRequestState);
            }}
            placeholder="service.local"
            required
          />
        </label>
        <label className="auth-field">
          <span>TLS port</span>
          <input
            type="text"
            inputMode="numeric"
            value={portText}
            onChange={(event) => {
              setPortText(event.target.value);
              setRequestState(initialRequestState);
            }}
            required
          />
        </label>
        {!portValidation.ok && portText.trim() ? <p className="error-text">{portValidation.error}</p> : null}
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={authorizationConfirmed}
            onChange={(event) => {
              setAuthorizationConfirmed(event.target.checked);
              setRequestState(initialRequestState);
            }}
          />
          I confirm I own or am authorized to test this target.
        </label>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={localPrivateScopeConfirmed}
            onChange={(event) => {
              setLocalPrivateScopeConfirmed(event.target.checked);
              setRequestState(initialRequestState);
            }}
          />
          I confirm this is local, private, or self-hosted scope.
        </label>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={liveTrafficConfirmed}
            onChange={(event) => {
              setLiveTrafficConfirmed(event.target.checked);
              setRequestState(initialRequestState);
            }}
          />
          I understand this capability sends one bounded TLS handshake attempt if backend policy accepts it.
        </label>
        <button type="submit" disabled={!canSubmit}>
          <Play size={16} aria-hidden="true" />
          {requestState.loading ? "Creating TLS review job" : "Create TLS review job"}
        </button>
      </form>
      {requestState.error ? <p className="error-text">{requestState.error}</p> : null}
      {requestState.job ? <ActiveTlsBasicJobCreatedNotice job={requestState.job} /> : null}
    </section>
  );
}

export function parseActiveTlsBasicPort(value: string): PortValidationResult {
  const token = value.trim();
  if (!token) {
    return { ok: false, port: null, error: "Enter one TLS port." };
  }
  if (!/^\d+$/.test(token)) {
    return { ok: false, port: null, error: "TLS port must be a single TCP port number." };
  }
  const port = Number(token);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    return { ok: false, port: null, error: "TLS port must be an integer between 1 and 65535." };
  }
  if (!ACTIVE_TLS_BASIC_ALLOWED_PORTS.has(port)) {
    return { ok: false, port: null, error: "TLS basic allows only ports 443, 8443, or 9443." };
  }
  return { ok: true, port, error: null };
}

function ActiveTlsBasicJobCreatedNotice({ job }: { job: JobRecord }) {
  const result = asRecord(job.result);
  const handshake = asRecord(result?.handshake);
  const certificate = asRecord(result?.certificate);
  const execution = asRecord(result?.execution);
  const status = asString(result?.result_status) ?? asString(result?.status) ?? "tls_error_controlled";
  const protocol = asString(handshake?.protocol) ?? "Not available";
  const cipher = asString(handshake?.cipher) ?? "Not available";
  const daysUntilExpiry = asNumber(certificate?.days_until_expiry);
  const networkRequestsSent = asNumber(execution?.network_requests_sent) ?? 0;
  const tlsHandshakeAttempted = execution?.tls_handshake_attempted === true;

  return (
    <div className="query-warning" role="status">
      <strong>TLS review indicator job created.</strong>
      <dl className="summary-list">
        <dt>Job</dt>
        <dd className="mono">{job.id}</dd>
        <dt>Status</dt>
        <dd className="mono">{status}</dd>
        <dt>Target</dt>
        <dd className="mono">[REDACTED_TARGET]</dd>
        <dt>Handshake</dt>
        <dd>{tlsHandshakeAttempted ? "Bounded TLS handshake attempted by backend policy." : "No TLS handshake attempted."}</dd>
        <dt>Network</dt>
        <dd>{`${networkRequestsSent} network request${networkRequestsSent === 1 ? "" : "s"}. 0 HTTP requests.`}</dd>
        <dt>Protocol / cipher</dt>
        <dd>{`${protocol} / ${cipher}`}</dd>
        <dt>Certificate expiry</dt>
        <dd>{daysUntilExpiry === null ? "Not available. Manual validation required." : `${daysUntilExpiry} days. Manual validation required.`}</dd>
      </dl>
      <p className="muted">The job record was opened below when the dashboard integration is available.</p>
    </div>
  );
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}
