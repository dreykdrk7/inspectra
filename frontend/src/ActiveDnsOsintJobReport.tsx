import { Search } from "lucide-react";

import { buildActiveDnsOsintReport } from "./activeDnsOsintReport";
import type { JobRecord } from "./types";

type ActiveDnsOsintJobReportProps = {
  job: JobRecord;
};

export function ActiveDnsOsintJobReport({ job }: ActiveDnsOsintJobReportProps) {
  const report = buildActiveDnsOsintReport(job);

  return (
    <div className="job-report active-dns-osint-report">
      <div className="report-header">
        <h3>
          <Search size={18} aria-hidden="true" />
          Active / DNS OSINT report
        </h3>
        <span className="status-pill">Public-source review indicator</span>
      </div>
      <p className="muted">
        DNS OSINT review indicator. OSINT best-effort. Source-limited observed names only. Manual validation required.
      </p>

      <section className="report-section" aria-label="DNS OSINT scope">
        <h4>Scope Boundary</h4>
        <dl className="summary-list">
          <dt>Capability</dt>
          <dd className="mono">active_dns_osint</dd>
          <dt>Mode</dt>
          <dd className="mono">live_dns_osint</dd>
          <dt>Profile</dt>
          <dd className="mono">ct_subdomain_discovery_bounded</dd>
          <dt>Status</dt>
          <dd className="mono">{report.status}</dd>
          <dt>Coverage</dt>
          <dd className="mono">{report.coverageLevel}</dd>
          <dt>Domain</dt>
          <dd className="mono">{report.domain}</dd>
          <dt>Interpretation</dt>
          <dd>{report.resultInterpretation}</dd>
          <dt>Validation</dt>
          <dd>{report.manualValidationRequired ? "Manual validation required." : "Review before relying on this result."}</dd>
        </dl>
      </section>

      <section className="report-section" aria-label="Certificate Transparency source">
        <h4>Certificate Transparency Source</h4>
        <dl className="summary-list">
          <dt>Status</dt>
          <dd className="mono">{report.certificateTransparency.status}</dd>
          <dt>Attempted</dt>
          <dd>{String(report.certificateTransparency.attempted)}</dd>
          <dt>Observed count</dt>
          <dd>{report.certificateTransparency.namesObservedCount}</dd>
          <dt>Retained count</dt>
          <dd>{report.certificateTransparency.namesRetainedCount}</dd>
          <dt>Discarded count</dt>
          <dd>{report.certificateTransparency.namesDiscardedCount}</dd>
          <dt>Truncated</dt>
          <dd>{String(report.certificateTransparency.truncated)}</dd>
          <dt>Source note</dt>
          <dd>{sourceStatusMessage(report.certificateTransparency.status)}</dd>
        </dl>
      </section>

      <section className="report-section" aria-label="Observed names">
        <h4>Observed Names</h4>
        <dl className="summary-list">
          <dt>Count</dt>
          <dd>{report.observedNames.count}</dd>
          <dt>Max retained</dt>
          <dd>{report.observedNames.maxNames}</dd>
          <dt>Truncated</dt>
          <dd>{String(report.observedNames.truncated)}</dd>
          <dt>Sample</dt>
          <dd>
            {report.observedNames.sample.length > 0 ? (
              <ul className="inline-list">
                {report.observedNames.sample.map((item, index) => (
                  <li key={`${item}-${index}`} className="mono">
                    {item}
                  </li>
                ))}
              </ul>
            ) : (
              "No redacted sample retained."
            )}
          </dd>
        </dl>
      </section>

      <section className="report-section" aria-label="Passive DNS source">
        <h4>Passive DNS</h4>
        <dl className="summary-list">
          <dt>Status</dt>
          <dd className="mono">{report.passiveDns.status}</dd>
          <dt>Attempted</dt>
          <dd>{String(report.passiveDns.attempted)}</dd>
          <dt>Boundary</dt>
          <dd>Passive DNS is not part of this product flow.</dd>
        </dl>
      </section>

      <section className="report-section" aria-label="Execution bounds">
        <h4>Execution Bounds</h4>
        <dl className="summary-list">
          <dt>External source requests</dt>
          <dd>{report.execution.externalRequestsSent}</dd>
          <dt>CT queries</dt>
          <dd>{report.execution.ctQueriesSent}</dd>
          <dt>Passive DNS queries</dt>
          <dd>{report.execution.passiveDnsQueriesSent}</dd>
          <dt>DNS queries</dt>
          <dd>{report.execution.dnsQueriesSent}</dd>
          <dt>HTTP requests</dt>
          <dd>{report.execution.httpRequestsSent}</dd>
          <dt>Provider API used</dt>
          <dd>{String(report.execution.providerApiUsed)}</dd>
          <dt>Crawling performed</dt>
          <dd>{String(report.execution.crawlingPerformed)}</dd>
          <dt>Observed names auto-scanned</dt>
          <dd>{String(report.execution.observedNameAutoScanPerformed)}</dd>
        </dl>
      </section>

      <section className="report-section" aria-label="Limits and caveats">
        <h4>Limits And Caveats</h4>
        <dl className="summary-list">
          {Object.entries(report.limits).map(([key, value]) => (
            <div key={key} className="summary-pair">
              <dt>{key}</dt>
              <dd className="mono">{formatValue(value)}</dd>
            </div>
          ))}
        </dl>
        <StatusList title="Warnings" items={report.warnings} emptyText="No warnings retained." />
        <StatusList title="Errors" items={report.errors} emptyText="No controlled source errors retained." />
        <StatusList
          title="Caveats"
          items={report.caveats.length ? report.caveats : ["Manual validation required.", "Observed names are not auto-scanned."]}
          emptyText="Manual validation required."
        />
      </section>

      <section className="report-section" aria-label="Raw JSON">
        <h4>Raw JSON (redacted)</h4>
        <pre className="raw-json">{report.rawJson}</pre>
      </section>
    </div>
  );
}

function StatusList({ title, items, emptyText }: { title: string; items: string[]; emptyText: string }) {
  return (
    <div>
      <h5>{title}</h5>
      {items.length > 0 ? (
        <ul>
          {items.map((item, index) => (
            <li key={`${title}-${index}`}>{item}</li>
          ))}
        </ul>
      ) : (
        <p className="muted">{emptyText}</p>
      )}
    </div>
  );
}

function sourceStatusMessage(status: string): string {
  switch (status) {
    case "completed":
      return "CT source completed within configured bounds.";
    case "partial":
      return "CT source returned partial bounded output and was normalized as controlled output.";
    case "timed_out":
      return "CT source timed out and was normalized as controlled output.";
    case "rate_limited":
      return "CT source rate limit was normalized as controlled output.";
    case "source_unavailable":
      return "CT source was unavailable and was normalized as controlled output.";
    case "invalid_source_response":
      return "CT response shape was invalid and was normalized as controlled output.";
    case "truncated":
      return "CT output was truncated by configured caps.";
    case "disabled":
      return "CT source is disabled by backend configuration.";
    case "blocked_by_policy":
      return "CT source was blocked by backend policy.";
    default:
      return "CT source was not attempted or returned a controlled status.";
  }
}

function formatValue(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (value === null || value === undefined) {
    return "N/A";
  }
  return JSON.stringify(value);
}
