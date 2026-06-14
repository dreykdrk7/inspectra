import type { ReactNode } from "react";

import {
  buildActiveTlsBasicReport,
  type ActiveTlsBasicCertificateSummary
} from "./activeTlsBasicReport";
import type { MetadataEntry } from "./pdfReport";
import type { JobRecord, JobStatus } from "./types";

export function ActiveTlsBasicJobReport({ job }: { job: JobRecord }) {
  const report = buildActiveTlsBasicReport(job);

  if (!report.isActiveTlsBasic) {
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
            <h3>Active / TLS basic report</h3>
            <p className="muted">
              TLS handshake review indicator. Certificate expiry review indicator. Manual validation required. No security finding is asserted.
            </p>
          </div>
          <div className="badge-row">
            <span className="status-pill">Active / Network</span>
            <span className="status-pill">TLS review indicator</span>
            <span className="status-pill">Raw certificate redacted</span>
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
          <MetadataRow label="Mode" value={report.mode ?? "live_tls_basic"} />
          <MetadataRow label="Profile" value={report.profile ?? "tls_handshake_summary"} />
          <MetadataRow label="Job ID" value={job.id} mono />
          <MetadataRow label="Created" value={formatDate(job.created_at)} />
          <MetadataRow label="Updated" value={formatDate(job.updated_at)} />
        </dl>
      </section>

      <div className="alert" role="status">
        {statusMessage(report.status)}
      </div>

      <ReportSection title="Authorization Notice">
        <p className="muted">
          Authorization is user asserted, not proof of ownership. Use this TLS review only for local, private, or self-hosted targets you are
          allowed to test.
        </p>
      </ReportSection>

      <div className="report-grid">
        <ReportSection title="TLS Handshake Review Indicator">
          <dl className="summary-list">
            <MetadataRow label="Handshake status" value={report.handshakeStatus} />
            <MetadataRow label="Protocol" value={report.protocol ?? "Not available"} />
            <MetadataRow label="Cipher" value={report.cipher ?? "Not available"} />
            <MetadataRow label="Network requests" value="Bounded by backend result" />
            <MetadataRow label="HTTP requests" value="0" />
          </dl>
        </ReportSection>

        <ReportSection title="Certificate Expiry Review Indicator">
          <CertificateSummary certificate={report.certificate} />
        </ReportSection>
      </div>

      <div className="report-grid">
        <ReportSection title="Limits">
          <MetadataList entries={report.limits} empty="No active_tls_basic limits were returned." />
        </ReportSection>
        <ReportSection title="Controlled State Details">
          <dl className="summary-list">
            <MetadataRow label="Manual validation required" value="true" />
            <MetadataRow label="Target display" value="[REDACTED_TARGET]" mono />
            <MetadataRow label="Raw certificate persisted" value="false" />
            <MetadataRow label="Raw target persisted" value="false" />
            <MetadataRow label="Crawler input" value="none" />
            <MetadataRow label="Credentials" value="none" />
          </dl>
        </ReportSection>
      </div>

      <ListSection title="Reason Codes" items={report.reasonCodes} empty="No reason codes were returned." />
      <ListSection title="Warnings" items={report.warnings} empty="No TLS parser or limit warnings were returned." />
      <ListSection title="Controlled Errors" items={report.errors} empty="No controlled errors were reported." />

      <RawJson rawJson={report.rawJson} />
    </div>
  );
}

function CertificateSummary({ certificate }: { certificate: ActiveTlsBasicCertificateSummary }) {
  return (
    <dl className="summary-list">
      <MetadataRow label="Certificate available" value={String(certificate.available)} />
      <MetadataRow label="Subject" value={certificate.subject ?? "Not available"} />
      <MetadataRow label="Issuer" value={certificate.issuer ?? "Not available"} />
      <MetadataRow label="SAN count" value={String(certificate.sanCount)} />
      <MetadataRow
        label="SAN sample"
        value={certificate.sanSample.length > 0 ? certificate.sanSample.join(", ") : "Not available"}
      />
      <MetadataRow label="Not before" value={certificate.notBefore ?? "Not available"} />
      <MetadataRow label="Not after" value={certificate.notAfter ?? "Not available"} />
      <MetadataRow
        label="Days until expiry"
        value={certificate.daysUntilExpiry === null ? "Not available" : String(certificate.daysUntilExpiry)}
      />
    </dl>
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
        Frontend defensive redaction hides raw target values, raw certificate PEM/DER, raw exceptions, credentials, headers, cookies, and tokens.
      </p>
      <details className="raw-json">
        <summary>Show redacted Raw JSON</summary>
        <pre>{rawJson}</pre>
      </details>
    </section>
  );
}

function statusMessage(status: string): string {
  if (status === "handshake_succeeded") {
    return "active_tls_basic completed one bounded TLS handshake review indicator. Manual validation required.";
  }
  if (status === "timed_out") {
    return "active_tls_basic timed out in a controlled state. Certificate details may be unavailable. No target details are shown.";
  }
  if (status === "handshake_failed") {
    return "active_tls_basic handshake failed in a controlled state. No target details are shown.";
  }
  if (status === "certificate_unavailable") {
    return "active_tls_basic completed a bounded handshake path in a controlled state, but no public certificate summary is available. No target details are shown.";
  }
  if (status === "not_executed") {
    return "active_tls_basic was not executed. This report shows only the controlled contract state.";
  }
  return "active_tls_basic ended in a controlled TLS error state. No target details are shown. Raw exceptions are redacted.";
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}
