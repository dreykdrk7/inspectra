import { FormEvent, useMemo, useState } from "react";
import { Network, Play } from "lucide-react";

import { ApiError, api } from "./api";
import type { ActiveNmapBasicRequest, HealthResponse, JobRecord } from "./types";

type ActiveNmapBasicPanelProps = {
  health: HealthResponse | null;
  onJobCreated?: (job: JobRecord) => void | Promise<void>;
};

const ACTIVE_NMAP_BASIC_MAX_PORTS = 32;

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

export function ActiveNmapBasicPanel({ health, onJobCreated }: ActiveNmapBasicPanelProps) {
  const availability = getActiveNmapBasicAvailability(health);
  const isAvailable = availability === "available";
  const [target, setTarget] = useState("");
  const [portsText, setPortsText] = useState("");
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [localPrivateScopeConfirmed, setLocalPrivateScopeConfirmed] = useState(false);
  const [liveTrafficConfirmed, setLiveTrafficConfirmed] = useState(false);
  const [requestState, setRequestState] = useState<RequestState>(initialRequestState);
  const portValidation = useMemo(() => parseActiveNmapBasicPorts(portsText), [portsText]);
  const canSubmit =
    !requestState.loading &&
    target.trim().length > 0 &&
    portValidation.ok &&
    authorizationConfirmed &&
    localPrivateScopeConfirmed &&
    liveTrafficConfirmed;

  async function submitActiveNmapBasic(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canSubmit || !portValidation.ok) {
      return;
    }

    const request: ActiveNmapBasicRequest = {
      mode: "live_nmap_basic",
      profile: "tcp_connect_small",
      targets: [target.trim()],
      ports: portValidation.ports,
      authorization_confirmed: true,
      local_private_scope_confirmed: true,
      live_traffic_confirmed: true
    };

    setRequestState({ loading: true, error: null, job: null });
    try {
      const job = await api.createActiveNmapBasic(request);
      await onJobCreated?.(job);
      setRequestState({ loading: false, error: null, job });
    } catch (error) {
      const disabled = error instanceof ApiError && error.status === 403;
      setRequestState({
        loading: false,
        job: null,
        error: disabled
          ? "Active / Nmap basic is disabled or unavailable in this environment."
          : "Active / Nmap basic request was not accepted. Review bounds and confirmations."
      });
    }
  }

  return (
    <section className="panel active-nmap-basic-panel" aria-label="Active / Nmap basic">
      <div className="panel-header">
        <h2>
          <Network size={18} aria-hidden="true" />
          Active / Nmap basic
        </h2>
        <span className={`status-pill ${isAvailable ? "ok" : ""}`}>
          {isAvailable ? "Prepared / available" : "Disabled"}
        </span>
      </div>

      <div className="badge-row" aria-label="Active Nmap basic guardrails">
        <span className="status-pill">Local/private/self-hosted only</span>
        <span className="status-pill">Authorized targets only</span>
        <span className="status-pill">Bounded TCP ports</span>
      </div>

      <p className="muted">
        This creates a bounded authorized no-live lifecycle record for the future Nmap basic capability.
      </p>

      <div className="query-warning" role="status">
        {isAvailable
          ? "Backend availability is advertised as prepared, but this panel still records only backend-controlled no-live lifecycle state."
          : "Backend availability is unavailable or not advertised. Submissions may be rejected as disabled or unavailable."}
      </div>

      <dl className="summary-list">
        <dt>Mode</dt>
        <dd className="mono">live_nmap_basic</dd>
        <dt>Profile</dt>
        <dd className="mono">tcp_connect_small</dd>
        <dt>Scope</dt>
        <dd>Local/private/self-hosted systems only; targets must be explicitly authorized by the operator.</dd>
        <dt>Live traffic</dt>
        <dd>The request includes the live-scope confirmation required by the backend contract; this phase records no network requests.</dd>
        <dt>Evidence</dt>
        <dd>No Nmap executed, no network requests, no DNS queries, no evidence collected, and no observations available.</dd>
        <dt>Report wording</dt>
        <dd>No-live lifecycle record. Manual validation required. No security finding is asserted.</dd>
        <dt>Bounds</dt>
        <dd>One explicit target, up to {ACTIVE_NMAP_BASIC_MAX_PORTS} TCP ports, timeout bounded, output bounded, and storage bounded.</dd>
        <dt>Excluded</dt>
        <dd>No raw flags, no NSE/scripts, no brute force, no credential validation, no crawling, and no DNS expansion.</dd>
      </dl>

      <form className="web-audit-form" onSubmit={(event) => void submitActiveNmapBasic(event)}>
        <label className="auth-field">
          <span>Target</span>
          <input
            type="text"
            value={target}
            onChange={(event) => {
              setTarget(event.target.value);
              setRequestState(initialRequestState);
            }}
            placeholder="router.local"
            required
          />
        </label>
        <label className="auth-field">
          <span>TCP ports</span>
          <input
            type="text"
            inputMode="numeric"
            value={portsText}
            onChange={(event) => {
              setPortsText(event.target.value);
              setRequestState(initialRequestState);
            }}
            placeholder="22, 80, 443"
            required
          />
        </label>
        {!portValidation.ok && portsText.trim() ? <p className="error-text">{portValidation.error}</p> : null}
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
          I understand this capability is live-traffic scoped, while this phase creates only a no-live record.
        </label>
        <button type="submit" disabled={!canSubmit}>
          <Play size={16} aria-hidden="true" />
          {requestState.loading ? "Creating no-live record" : "Create bounded no-live record"}
        </button>
      </form>
      {requestState.error ? <p className="error-text">{requestState.error}</p> : null}
      {requestState.job ? <ActiveNmapBasicJobCreatedNotice job={requestState.job} /> : null}
    </section>
  );
}

function ActiveNmapBasicJobCreatedNotice({ job }: { job: JobRecord }) {
  const result = asRecord(job.result);
  const lifecycleState = asString(result?.lifecycle_state) ?? asString(result?.status) ?? "not_executed";
  const controlledError =
    lifecycleState === "client_error_controlled" || lifecycleState === "unsafe_lifecycle_result";

  return (
    <div className={`query-warning ${controlledError ? "error-text" : ""}`} role="status">
      <strong>No-live lifecycle record created.</strong>
      <dl className="summary-list">
        <dt>Job</dt>
        <dd className="mono">{job.id}</dd>
        <dt>Lifecycle state</dt>
        <dd className="mono">{lifecycleState}</dd>
        <dt>Target</dt>
        <dd className="mono">[REDACTED_TARGET]</dd>
        <dt>Nmap</dt>
        <dd>No Nmap executed.</dd>
        <dt>Network</dt>
        <dd>No network requests. No DNS queries.</dd>
        <dt>Evidence</dt>
        <dd>No evidence collected. No observations available. Manual validation required.</dd>
      </dl>
      <p className="muted">The job record was opened below when the dashboard integration is available.</p>
    </div>
  );
}

export function getActiveNmapBasicAvailability(health: HealthResponse | null): "available" | "disabled" {
  const capability = health?.active_nmap_basic;
  if (!capability) {
    return "disabled";
  }

  const status = typeof capability.status === "string" ? capability.status.toLowerCase() : "";
  if (capability.enabled === true || capability.available === true || status === "available" || status === "enabled") {
    return "available";
  }

  return "disabled";
}

type PortValidationResult =
  | { ok: true; ports: number[]; error: null }
  | { ok: false; ports: number[]; error: string };

export function parseActiveNmapBasicPorts(value: string): PortValidationResult {
  const tokens = value
    .split(/[,\s]+/)
    .map((item) => item.trim())
    .filter(Boolean);

  if (tokens.length === 0) {
    return { ok: false, ports: [], error: "Enter at least one TCP port." };
  }
  if (tokens.length > ACTIVE_NMAP_BASIC_MAX_PORTS) {
    return { ok: false, ports: [], error: `Use ${ACTIVE_NMAP_BASIC_MAX_PORTS} or fewer TCP ports.` };
  }

  const ports: number[] = [];
  const seen = new Set<number>();
  for (const token of tokens) {
    if (!/^\d+$/.test(token)) {
      return { ok: false, ports: [], error: "Ports must be TCP port numbers separated by commas or spaces." };
    }
    const port = Number(token);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
      return { ok: false, ports: [], error: "Ports must be integers between 1 and 65535." };
    }
    if (!seen.has(port)) {
      seen.add(port);
      ports.push(port);
    }
  }

  return { ok: true, ports, error: null };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}
