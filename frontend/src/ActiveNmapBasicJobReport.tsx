import type { ReactNode } from "react";

import {
  buildActiveNmapBasicReport,
  type ActiveNmapBasicPortObservation
} from "./activeNmapBasicReport";
import type { MetadataEntry } from "./pdfReport";
import type { JobRecord, JobStatus } from "./types";

export function ActiveNmapBasicJobReport({ job }: { job: JobRecord }) {
  const report = buildActiveNmapBasicReport(job);

  if (!report.isActiveNmapBasic) {
    return (
      <div className="result-layout">
        <p className="muted">No readable report is available for this audit type yet.</p>
        <RawJson rawJson={report.rawJson} />
      </div>
    );
  }

  return (
    <div className="report-layout">
      <section className="report-section">
        <div className="section-title-row">
          <div>
            <h3>Active / Nmap basic report</h3>
            <p className="muted">
              {report.isNoLiveLifecycle
                ? "No-live lifecycle record. No Nmap executed. Manual validation required. No security finding is asserted."
                : "Observed TCP exposure. Review indicator. Manual validation required. No security finding is asserted."}
            </p>
          </div>
          <div className="badge-row">
            <span className="status-pill">Active / Network</span>
            <span className="status-pill">{report.isNoLiveLifecycle ? "No-live record" : "Bounded TCP observations"}</span>
            <span className="status-pill">Raw evidence redacted</span>
            <StatusBadge status={job.status} />
          </div>
        </div>
        <div className="report-summary-grid">
          {report.overview.map((entry) => (
            <div className="report-metric" key={entry.label}>
              <span>{entry.label}</span>
              <strong>{entry.value}</strong>
            </div>
          ))}
        </div>
        <dl className="summary-list">
          <MetadataRow label="Audit type" value={job.audit_type} />
          <MetadataRow label="Category" value="Active / Network" />
          <MetadataRow label="Mode" value={report.mode ?? "live_nmap_basic"} />
          <MetadataRow label="Profile" value={report.profile ?? "tcp_connect_small"} />
          <MetadataRow label="Job ID" value={job.id} mono />
          <MetadataRow label="Created" value={formatDate(job.created_at)} />
          <MetadataRow label="Updated" value={formatDate(job.updated_at)} />
        </dl>
      </section>

      <div className="alert" role="status">
        {statusMessage(report.status, report.isSparse, report.lifecycleState)}
      </div>

      {report.isNoLiveLifecycle ? <ListSection title="No-Live Caveats" items={report.noLiveCaveats} empty="No caveats were returned." /> : null}

      <ReportSection title="Authorization Notice">
        <p className="muted">
          Authorization is user asserted, not proof of ownership. Use these observations only for local, private, or self-hosted targets you are
          allowed to test.
        </p>
      </ReportSection>

      <ReportSection title="Port Observations">
        <PortObservationTable observations={report.observations} noLive={report.isNoLiveLifecycle} />
      </ReportSection>

      <div className="report-grid">
        <ReportSection title="Limits">
          <MetadataList entries={report.limits} empty="No active_nmap_basic limits were returned." />
        </ReportSection>
        <ReportSection title="Controlled State Details">
          <dl className="summary-list">
            <MetadataRow label="Output truncated" value={String(report.outputTruncated)} />
            <MetadataRow label="Stderr truncated" value={String(report.stderrTruncated)} />
            <MetadataRow label="Timed out" value={String(report.timedOut)} />
            {report.isNoLiveLifecycle ? (
              <>
                <MetadataRow label="Nmap executed" value="false" />
                <MetadataRow label="Network requests" value="0" />
                <MetadataRow label="DNS queries" value="0" />
                <MetadataRow label="Evidence collected" value="false" />
                <MetadataRow label="Observations available" value="false" />
              </>
            ) : null}
          </dl>
        </ReportSection>
      </div>

      <ListSection title="Warnings" items={report.warnings} empty="No parser or limit warnings were returned." />
      <ListSection title="Controlled Errors" items={report.errors} empty="No controlled errors were reported." />

      <RawJson rawJson={report.rawJson} />
    </div>
  );
}

function ReportSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="report-section">
      <h3>{title}</h3>
      {children}
    </section>
  );
}

function MetadataList({ entries, empty }: { entries: MetadataEntry[]; empty: string }) {
  if (entries.length === 0) {
    return <p className="empty-state">{empty}</p>;
  }
  return (
    <dl className="summary-list">
      {entries.map((entry) => (
        <MetadataRow key={entry.label} label={entry.label} value={entry.value} />
      ))}
    </dl>
  );
}

function MetadataRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <>
      <dt>{label}</dt>
      <dd className={mono ? "mono" : undefined}>{value}</dd>
    </>
  );
}

function PortObservationTable({ observations, noLive }: { observations: ActiveNmapBasicPortObservation[]; noLive: boolean }) {
  if (observations.length === 0) {
    return (
      <p className="empty-state">
        {noLive
          ? "No observations available. No evidence collected. Manual validation required."
          : "No TCP port observations were returned. Manual validation required."}
      </p>
    );
  }
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Port</th>
            <th>Protocol</th>
            <th>State</th>
            <th>Reason</th>
            <th>Interpretation</th>
          </tr>
        </thead>
        <tbody>
          {observations.map((observation) => (
            <tr key={`${observation.protocol}-${observation.port}-${observation.state}`}>
              <td className="mono">{observation.port}</td>
              <td>{observation.protocol}</td>
              <td>{observation.state}</td>
              <td>{observation.reason ?? "Not available"}</td>
              <td>{observation.indicator}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ListSection({ title, items, empty }: { title: string; items: string[]; empty: string }) {
  return (
    <ReportSection title={title}>
      {items.length === 0 ? (
        <p className="empty-state">{empty}</p>
      ) : (
        <ul className="warning-list">
          {items.map((item, index) => (
            <li key={`${item}-${index}`}>{item}</li>
          ))}
        </ul>
      )}
    </ReportSection>
  );
}

function StatusBadge({ status }: { status: JobStatus }) {
  return <span className={`status-pill ${status}`}>{status}</span>;
}

function RawJson({ rawJson }: { rawJson: string }) {
  return (
    <section className="report-section">
      <h3>Raw JSON (redacted)</h3>
      <p className="muted">
        Frontend defensive redaction hides raw target values, command fragments, raw XML, stdout/stderr, service/banner fields, and sensitive
        header, cookie, token, or credential-shaped fields.
      </p>
      <details className="raw-json">
        <summary>Show redacted Raw JSON</summary>
        <pre>{rawJson}</pre>
      </details>
    </section>
  );
}

function statusMessage(status: string, isSparse: boolean, lifecycleState: string | null): string {
  if (lifecycleState === "completed_no_live") {
    return "active_nmap_basic no-live lifecycle completed. No Nmap executed, no network requests, no DNS queries, no evidence, and no observations.";
  }
  if (lifecycleState === "client_error_controlled") {
    return "active_nmap_basic ended in a controlled client-error lifecycle state. No target details are shown.";
  }
  if (lifecycleState === "unsafe_lifecycle_result") {
    return "active_nmap_basic returned a controlled unsafe lifecycle state. No target details are shown.";
  }
  if (lifecycleState === "blocked_unconfigured" || lifecycleState === "blocked_missing_approval") {
    return "active_nmap_basic was blocked before execution. No Nmap executed and no network requests were sent.";
  }
  if (isSparse) {
    return "Sparse active_nmap_basic payload. Showing available redacted data without assertions.";
  }
  if (status === "completed") {
    return "active_nmap_basic completed with bounded observations. Manual validation required.";
  }
  if (status === "timed_out") {
    return "active_nmap_basic timed out in a controlled state. Partial or missing observations require manual review.";
  }
  if (status === "nmap_missing") {
    return "Nmap was unavailable for this controlled result. No completed Nmap observation is asserted.";
  }
  if (status === "truncated") {
    return "active_nmap_basic output was truncated before display. Treat observations as incomplete.";
  }
  if (status === "malformed" || status === "unsupported_shape") {
    return "active_nmap_basic returned malformed or unsupported structured output. No port conclusion is asserted.";
  }
  if (status === "no_ports" || status === "empty") {
    return "active_nmap_basic returned no TCP port observations. This is not proof that no exposure exists.";
  }
  if (status === "blocked") {
    return "active_nmap_basic was blocked by policy. Review authorization and target scope.";
  }
  if (status === "failed") {
    return "active_nmap_basic failed in a controlled state. Review redacted state details below.";
  }
  if (status === "not_executed" || status === "not_implemented") {
    return "active_nmap_basic was not executed. This report shows only the controlled contract state.";
  }
  return "Controlled active_nmap_basic state. Manual validation required.";
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}
