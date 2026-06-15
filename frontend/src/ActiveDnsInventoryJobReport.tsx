import type { ReactNode } from "react";

import {
  buildActiveDnsInventoryReport,
  type ActiveDnsInventoryRecordGroup,
  type ActiveDnsInventorySecurityIndicator,
  type ActiveDnsInventorySubdomainSummary,
  type ActiveDnsInventoryZoneTransferSummary
} from "./activeDnsInventoryReport";
import type { MetadataEntry } from "./pdfReport";
import type { JobRecord, JobStatus } from "./types";

export function ActiveDnsInventoryJobReport({ job }: { job: JobRecord }) {
  const report = buildActiveDnsInventoryReport(job);

  if (!report.isActiveDnsInventory) {
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
            <h3>Active / DNS inventory report</h3>
            <p className="muted">
              DNS configuration review indicator. Best-effort DNS inventory or partial inventory unless authorized AXFR is accepted by an
              authoritative server. Manual validation required.
            </p>
          </div>
          <div className="badge-row">
            <span className="status-pill">Active / Network</span>
            <span className="status-pill">DNS review indicator</span>
            <span className="status-pill">Domain redacted</span>
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
          <MetadataRow label="Mode" value={report.mode ?? "live_dns_inventory"} />
          <MetadataRow label="Profile" value={report.profile ?? "dns_inventory_authorized"} />
          <MetadataRow label="Job ID" value={job.id} mono />
          <MetadataRow label="Created" value={formatDate(job.created_at)} />
          <MetadataRow label="Updated" value={formatDate(job.updated_at)} />
        </dl>
      </section>

      <div className="alert" role="status">
        {statusMessage(report.coverageLevel)}
      </div>

      <ReportSection title="Authorization Notice">
        <p className="muted">
          Authorization is user asserted, not proof of ownership. Use this DNS inventory only for local, private, self-hosted, or owned domains
          you are allowed to query.
        </p>
      </ReportSection>

      <div className="report-grid">
        <ReportSection title="Coverage Boundary">
          <dl className="summary-list">
            <MetadataRow label="Coverage level" value={report.coverageLevel} />
            <MetadataRow label="Result wording" value="DNS configuration review indicator" />
            <MetadataRow label="Domain display" value="[REDACTED_DOMAIN]" mono />
            <MetadataRow label="Zone transfer" value={report.zoneTransferStatus} />
            <MetadataRow label="Provider import" value={report.providerImportStatus} />
            <MetadataRow label="Manual validation required" value="true" />
          </dl>
        </ReportSection>

        <ReportSection title="DNS Query Bounds">
          <dl className="summary-list">
            <MetadataRow label="DNS queries sent" value={String(report.dnsQueriesSent)} />
            <MetadataRow label="Subdomain queries sent" value={String(report.subdomainQueriesSent)} />
            <MetadataRow label="Record types" value={report.recordTypes.length > 0 ? report.recordTypes.join(", ") : "Not available"} />
            <MetadataRow label="AXFR" value={report.zoneTransfer.status} />
            <MetadataRow label="Provider API" value="not attempted" />
            <MetadataRow label="CT/passive DNS" value="not attempted" />
          </dl>
        </ReportSection>
      </div>

      <ReportSection title="Grouped DNS Records">
        <RecordGroups groups={report.recordGroups} />
      </ReportSection>

      <div className="report-grid">
        <ReportSection title="Security Record Indicators">
          <SecurityIndicators indicators={report.securityIndicators} />
        </ReportSection>

        <ReportSection title="Bounded Subdomain Summary">
          <SubdomainSummary subdomains={report.subdomains} />
        </ReportSection>
      </div>

      <ReportSection title="Authorized Zone Transfer (AXFR)">
        <ZoneTransferSummary zoneTransfer={report.zoneTransfer} />
      </ReportSection>

      <ReportSection title="Limits">
        <MetadataList entries={report.limits} empty="No active_dns_inventory limits were returned." />
      </ReportSection>

      <ListSection title="Caveats" items={report.caveats} empty="No caveats were returned." />
      <ListSection title="Warnings" items={report.warnings} empty="No DNS warnings were returned." />
      <ListSection title="Controlled Errors" items={report.errors} empty="No controlled DNS errors were reported." />

      <RawJson rawJson={report.rawJson} />
    </div>
  );
}

function RecordGroups({ groups }: { groups: ActiveDnsInventoryRecordGroup[] }) {
  if (groups.length === 0) {
    return <p className="empty-state">No public DNS record groups were returned.</p>;
  }
  return (
    <div className="report-grid">
      {groups.map((group) => (
        <section className="report-section" key={group.type}>
          <h4>{group.type}</h4>
          <dl className="summary-list">
            <MetadataRow label="Count" value={String(group.count)} />
            <MetadataRow label="Sample truncated" value={String(group.truncated)} />
          </dl>
          {group.sample.length === 0 ? (
            <p className="empty-state">No redacted sample returned.</p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Value</th>
                    <th>TTL</th>
                    <th>Priority</th>
                  </tr>
                </thead>
                <tbody>
                  {group.sample.map((record, index) => (
                    <tr key={`${group.type}-${index}`}>
                      <td className="mono">{record.name}</td>
                      <td>{record.type}</td>
                      <td className="mono">{record.value}</td>
                      <td>{record.ttl === null ? "N/A" : record.ttl}</td>
                      <td>{record.priority === null ? "N/A" : record.priority}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      ))}
    </div>
  );
}

function SecurityIndicators({
  indicators
}: {
  indicators: Record<"spf" | "dmarc" | "caa" | "dkim", ActiveDnsInventorySecurityIndicator>;
}) {
  return (
    <dl className="summary-list">
      <MetadataRow label="SPF" value={indicatorSummary(indicators.spf)} />
      <MetadataRow label="DMARC" value={indicatorSummary(indicators.dmarc)} />
      <MetadataRow label="CAA" value={indicatorSummary(indicators.caa)} />
      <MetadataRow label="DKIM" value={indicators.dkim.checked ? indicatorSummary(indicators.dkim) : "not attempted"} />
    </dl>
  );
}

function SubdomainSummary({ subdomains }: { subdomains: ActiveDnsInventorySubdomainSummary }) {
  return (
    <>
      <dl className="summary-list">
        <MetadataRow label="Enabled" value={String(subdomains.enabled)} />
        <MetadataRow label="Strategy" value={subdomains.strategy} />
        <MetadataRow label="Candidates checked" value={String(subdomains.candidatesChecked)} />
        <MetadataRow label="Query record types" value={subdomains.queryRecordTypes.length > 0 ? subdomains.queryRecordTypes.join(", ") : "none"} />
        <MetadataRow label="Observed candidate count" value={String(subdomains.count)} />
        <MetadataRow label="Sample truncated" value={String(subdomains.sampleTruncated)} />
      </dl>
      {subdomains.sample.length === 0 ? (
        <p className="empty-state">No redacted subdomain sample returned.</p>
      ) : (
        <ul className="warning-list">
          {subdomains.sample.map((item, index) => (
            <li key={`${item.name}-${index}`}>
              <span className="mono">{item.name}</span> - {item.recordCount} record indicators ({item.recordTypes.join(", ") || "none"})
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

function ZoneTransferSummary({ zoneTransfer }: { zoneTransfer: ActiveDnsInventoryZoneTransferSummary }) {
  const complete = zoneTransfer.status === "zone_transfer_complete";
  return (
    <>
      <dl className="summary-list">
        <MetadataRow label="Status" value={zoneTransfer.status} />
        <MetadataRow label="Attempted" value={String(zoneTransfer.attempted)} />
        <MetadataRow label="Nameservers considered" value={String(zoneTransfer.nameserversConsidered)} />
        <MetadataRow label="Nameservers attempted" value={String(zoneTransfer.nameserversAttempted)} />
        <MetadataRow label="Records received" value={String(zoneTransfer.recordsReceivedCount)} />
        <MetadataRow label="Records retained" value={String(zoneTransfer.recordsRetainedCount)} />
        <MetadataRow label="Truncated" value={String(zoneTransfer.truncated)} />
        <MetadataRow label="Reason" value={zoneTransfer.reasonCode ?? "not provided"} />
      </dl>
      {complete ? (
        <div className="alert" role="status">
          zone transfer accepted by authoritative server. high-risk configuration review indicator. Manual validation required.
        </div>
      ) : (
        <p className="muted">{zoneTransferStatusMessage(zoneTransfer.status)}</p>
      )}
      {zoneTransfer.interpretation ? <p className="muted">{zoneTransfer.interpretation}</p> : null}
    </>
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
        Frontend defensive redaction hides raw domains, DNS values, resolver logs, DNS packets, provider IDs, provider secrets, credentials,
        headers, cookies, and tokens.
      </p>
      <details className="raw-json">
        <summary>Show redacted Raw JSON</summary>
        <pre>{rawJson}</pre>
      </details>
    </section>
  );
}

function indicatorSummary(indicator: ActiveDnsInventorySecurityIndicator): string {
  if (indicator.status) {
    return indicator.status;
  }
  if (indicator.present === true) {
    return "present / review indicator";
  }
  if (indicator.present === false) {
    return "not observed / review indicator";
  }
  if (indicator.recordCount !== null) {
    return `${indicator.recordCount} redacted records / review indicator`;
  }
  return indicator.checked ? "checked / review indicator" : "not attempted";
}

function statusMessage(coverageLevel: string): string {
  if (coverageLevel === "best_effort_inventory") {
    return "active_dns_inventory produced a best-effort DNS inventory review indicator. Manual validation required.";
  }
  if (coverageLevel === "zone_transfer_complete") {
    return "active_dns_inventory recorded an authorized zone transfer accepted by an authoritative server as a high-risk DNS configuration review indicator. Manual validation required.";
  }
  if (coverageLevel === "not_executed") {
    return "active_dns_inventory was not executed. This report shows only the controlled contract state.";
  }
  return "active_dns_inventory produced a partial inventory review indicator. Manual validation required.";
}

function zoneTransferStatusMessage(status: string): string {
  if (status === "not_attempted") {
    return "AXFR was not attempted.";
  }
  if (status === "authorization_required") {
    return "AXFR was blocked because specific zone transfer authorization was not confirmed.";
  }
  if (status === "no_authoritative_nameservers") {
    return "No authoritative nameservers were available for a bounded AXFR attempt.";
  }
  if (status === "refused") {
    return "Authoritative nameserver refused AXFR. This remains a controlled partial inventory result.";
  }
  if (status === "unavailable") {
    return "AXFR was unavailable. This remains a controlled partial inventory result.";
  }
  if (status === "timed_out") {
    return "AXFR timed out within configured bounds. This remains a controlled partial inventory result.";
  }
  if (status === "malformed_response") {
    return "AXFR response was malformed or incomplete. This remains a controlled partial inventory result.";
  }
  if (status === "record_limit_exceeded") {
    return "AXFR record limit was exceeded and retained output was bounded.";
  }
  if (status === "zone_transfer_complete") {
    return "zone transfer accepted by authoritative server. high-risk configuration review indicator. Manual validation required.";
  }
  return "AXFR returned a controlled state. Manual validation required.";
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}
