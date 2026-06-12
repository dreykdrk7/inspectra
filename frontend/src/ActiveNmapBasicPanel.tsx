import { Network } from "lucide-react";

import type { HealthResponse } from "./types";

type ActiveNmapBasicPanelProps = {
  health: HealthResponse | null;
};

export function ActiveNmapBasicPanel({ health }: ActiveNmapBasicPanelProps) {
  const availability = getActiveNmapBasicAvailability(health);
  const isAvailable = availability === "available";

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
        <span className="status-pill">No submit in this phase</span>
      </div>

      <p className="muted">
        Bounded TCP exposure review shell for future authorized use. This panel does not create jobs, call the backend
        Nmap contract, or run Nmap.
      </p>

      <div className="query-warning" role="status">
        {isAvailable
          ? "Backend availability is advertised as prepared, but this frontend phase is informational only and cannot submit live traffic."
          : "Backend availability is unavailable or not advertised. This frontend phase is informational only and cannot submit live traffic."}
      </div>

      <dl className="summary-list">
        <dt>Scope</dt>
        <dd>Local/private/self-hosted systems only; targets must be explicitly authorized by the operator.</dd>
        <dt>Live traffic</dt>
        <dd>Future execution would send bounded live TCP traffic and may be logged by the target.</dd>
        <dt>Evidence</dt>
        <dd>Observed TCP exposure / Review indicator. Manual validation required; no confirmed vulnerability asserted.</dd>
        <dt>Bounds</dt>
        <dd>Target count bounded, port count bounded, timeout bounded, output bounded, and storage bounded.</dd>
        <dt>Excluded</dt>
        <dd>No raw flags, no NSE/scripts, no brute force, no credential validation, no crawling, and no DNS expansion.</dd>
      </dl>

      <button type="button" disabled aria-disabled="true">
        Prepared only
      </button>
    </section>
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
