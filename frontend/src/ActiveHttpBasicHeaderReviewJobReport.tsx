import { ShieldCheck } from "lucide-react";

import { buildActiveHttpBasicHeaderReviewReport } from "./activeHttpBasicHeaderReviewReport";
import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export function ActiveHttpBasicHeaderReviewJobReport({ job }: { job: JobRecord }) {
  const report = buildActiveHttpBasicHeaderReviewReport(job);

  return (
    <div className="job-report active-http-basic-header-review-report">
      <div className="report-header">
        <h3>
          <ShieldCheck size={18} aria-hidden="true" />
          Active / HTTP header review report
        </h3>
        <span className="status-pill">No-live review record</span>
      </div>
      <p className="muted">
        HTTP header review indicator. Manual validation required. This report shows the stored no-live record only.
      </p>

      <section className="report-section" aria-label="HTTP header review scope">
        <h4>Scope Boundary</h4>
        <dl className="summary-list">
          <dt>Audit type</dt>
          <dd className="mono">active_http_basic_header_review</dd>
          <dt>Mode</dt>
          <dd className="mono">{report.mode}</dd>
          <dt>Profile</dt>
          <dd className="mono">{report.profile}</dd>
          <dt>Result status</dt>
          <dd className="mono">{report.status}</dd>
          <dt>Target</dt>
          <dd className="mono">{report.target}</dd>
          <dt>Method</dt>
          <dd className="mono">{report.method}</dd>
          <dt>Review wording</dt>
          <dd>{report.reviewWording}</dd>
          <dt>Job status meaning</dt>
          <dd>{report.jobStatusMeaning}</dd>
        </dl>
      </section>

      <section className="report-section" aria-label="HTTP header review indicators">
        <h4>Review Indicators</h4>
        <dl className="summary-list">
          {report.overview.map((entry) => (
            <MetadataRow key={entry.label} entry={entry} />
          ))}
        </dl>
      </section>

      <div className="query-warning" role="status">
        No live HTTP request was performed. Completed job status only means the no-live review record was stored.
      </div>

      <div className="report-grid">
        <section className="report-section" aria-label="Execution boundary">
          <h4>Execution Boundary</h4>
          <MetadataList entries={report.execution} empty="No execution boundary fields were returned." />
        </section>

        <section className="report-section" aria-label="Storage limits">
          <h4>Storage Limits</h4>
          <MetadataList entries={report.limits} empty="No limit fields were returned." />
        </section>
      </div>

      <section className="report-section" aria-label="No-live caveats">
        <h4>No-Live Caveats</h4>
        <ul className="warning-list">
          {report.caveats.map((caveat) => (
            <li key={caveat}>{caveat}</li>
          ))}
        </ul>
      </section>

      <section className="report-section" aria-label="Reason codes">
        <h4>Reason Codes</h4>
        {report.reasonCodes.length > 0 ? (
          <ul className="warning-list">
            {report.reasonCodes.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        ) : (
          <p className="muted">No reason codes retained for this accepted no-live record.</p>
        )}
      </section>

      <section className="report-section" aria-label="Raw JSON">
        <h4>Raw JSON (redacted)</h4>
        <p className="muted">Raw JSON is reconstructed from allowlisted no-live fields before display.</p>
        <pre className="raw-json">{report.rawJson}</pre>
      </section>
    </div>
  );
}

function MetadataList({ entries, empty }: { entries: MetadataEntry[]; empty: string }) {
  if (entries.length === 0) {
    return <p className="empty-state">{empty}</p>;
  }
  return (
    <dl className="summary-list">
      {entries.map((entry) => (
        <MetadataRow key={entry.label} entry={entry} />
      ))}
    </dl>
  );
}

function MetadataRow({ entry }: { entry: MetadataEntry }) {
  return (
    <>
      <dt>{entry.label}</dt>
      <dd className="mono">{entry.value}</dd>
    </>
  );
}
