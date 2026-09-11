import { useEffect, useState } from "react";

import { api } from "./api";
import type { IntegrationEventReplayPreflight, IntegrationEventStatus } from "./types";

export function IntegrationEventStatusPanel() {
  const [status, setStatus] = useState<IntegrationEventStatus | null>(null);
  const [error, setError] = useState("");
  const [preflight, setPreflight] = useState<IntegrationEventReplayPreflight | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [message, setMessage] = useState("");

  async function load() {
    setError("");
    try {
      setStatus(await api.getIntegrationEventStatus());
    } catch {
      setError("Signed integration delivery status is temporarily unavailable.");
    }
  }

  async function reviewReplay() {
    setError("");
    setMessage("");
    setConfirmed(false);
    try {
      setPreflight(await api.getIntegrationEventReplayPreflight());
    } catch {
      setError("Dead deliveries could not be reviewed safely.");
    }
  }

  async function replay() {
    if (!preflight || !confirmed) return;
    setError("");
    try {
      const result = await api.replayDeadIntegrationEvents(preflight);
      setPreflight(null);
      setConfirmed(false);
      setMessage(`${result.replayed_events} delivery event${result.replayed_events === 1 ? "" : "s"} returned to the signed queue.`);
      await load();
    } catch {
      setError("Replay scope changed or expired. Review it again.");
      setPreflight(null);
      setConfirmed(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  return (
    <section className="integration-event-panel" aria-labelledby="integration-event-title">
      <div>
        <p className="eyebrow">Outbound automation</p>
        <h3 id="integration-event-title">Signed analysis events</h3>
        <p className="muted">
          The operator controls one fixed HTTPS receiver. Only terminal project analysis state and opaque IDs leave Inspectra; source, paths and evidence are excluded.
        </p>
      </div>
      {error ? <p className="form-error" role="alert">{error}</p> : null}
      {message ? <p className="success-message" role="status">{message}</p> : null}
      {!error && !status ? <p role="status">Loading signed delivery status…</p> : null}
      {status ? (
        <>
          <p className={`status-pill ${status.enabled ? "success" : "neutral"}`} role="status">
            {status.enabled ? "Operator enabled" : "Disabled by default"}
          </p>
          {status.enabled ? (
            <dl className="integration-event-metrics" aria-label="Signed event delivery queue">
              <div><dt>Pending</dt><dd>{status.pending + status.delivering}</dd></div>
              <div><dt>Delivered</dt><dd>{status.delivered}</dd></div>
              <div><dt>Needs operator review</dt><dd>{status.dead}</dd></div>
            </dl>
          ) : (
            <p className="empty-state">No outbound event destination is active. Analysis remains entirely local.</p>
          )}
          <button className="secondary-button" type="button" onClick={() => void load()}>Refresh delivery status</button>
          {status.enabled && status.dead > 0 && !preflight ? (
            <button className="secondary-button" type="button" onClick={() => void reviewReplay()}>Review dead deliveries</button>
          ) : null}
          {preflight ? (
            <div className="integration-event-replay">
              <p className="query-warning" role="status">
                {preflight.selected_events} of {preflight.total_dead} dead deliveries are selected{preflight.truncated ? "; additional deliveries require another review" : ""}. Payloads and identifiers remain hidden.
              </p>
              <label className="checkbox-row">
                <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />
                I confirm the receiver is healthy and deduplicates the original event IDs.
              </label>
              <div className="button-row">
                <button type="button" disabled={!confirmed || preflight.selected_events === 0} onClick={() => void replay()}>Replay reviewed deliveries</button>
                <button className="secondary-button" type="button" onClick={() => { setPreflight(null); setConfirmed(false); }}>Cancel replay</button>
              </div>
            </div>
          ) : null}
        </>
      ) : null}
    </section>
  );
}
