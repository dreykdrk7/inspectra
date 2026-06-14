import { FormEvent, useMemo, useState } from "react";
import { Network, Play } from "lucide-react";

import { ApiError, api } from "./api";
import type { ActiveDnsInventoryRequest, JobRecord } from "./types";

type ActiveDnsInventoryPanelProps = {
  onJobCreated?: (job: JobRecord) => void | Promise<void>;
};

type RequestState = {
  loading: boolean;
  error: string | null;
  job: JobRecord | null;
};

const ACTIVE_DNS_INVENTORY_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"] as const;
const initialRequestState: RequestState = {
  loading: false,
  error: null,
  job: null
};

export function ActiveDnsInventoryPanel({ onJobCreated }: ActiveDnsInventoryPanelProps) {
  const [domain, setDomain] = useState("");
  const [selectedRecordTypes, setSelectedRecordTypes] = useState<string[]>([...ACTIVE_DNS_INVENTORY_RECORD_TYPES]);
  const [includeSecurityRecords, setIncludeSecurityRecords] = useState(true);
  const [includeSubdomainDiscovery, setIncludeSubdomainDiscovery] = useState(true);
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [localPrivateOrOwnedScopeConfirmed, setLocalPrivateOrOwnedScopeConfirmed] = useState(false);
  const [liveDnsQueriesConfirmed, setLiveDnsQueriesConfirmed] = useState(false);
  const [requestState, setRequestState] = useState<RequestState>(initialRequestState);
  const domainValidation = useMemo(() => validateActiveDnsInventoryDomain(domain), [domain]);
  const canSubmit =
    !requestState.loading &&
    domainValidation.ok &&
    selectedRecordTypes.length > 0 &&
    authorizationConfirmed &&
    localPrivateOrOwnedScopeConfirmed &&
    liveDnsQueriesConfirmed;

  async function submitActiveDnsInventory(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canSubmit || !domainValidation.ok) {
      return;
    }

    const request: ActiveDnsInventoryRequest = {
      mode: "live_dns_inventory",
      profile: "dns_inventory_authorized",
      domain: domainValidation.domain,
      record_types: selectedRecordTypes,
      include_security_records: includeSecurityRecords,
      include_subdomain_discovery: includeSubdomainDiscovery,
      attempt_zone_transfer: false,
      authorization_confirmed: true,
      local_private_or_owned_scope_confirmed: true,
      live_dns_queries_confirmed: true
    };

    setRequestState({ loading: true, error: null, job: null });
    try {
      const job = await api.createActiveDnsInventory(request);
      await onJobCreated?.(job);
      setRequestState({ loading: false, error: null, job });
    } catch (error) {
      const disabled = error instanceof ApiError && error.status === 403;
      setRequestState({
        loading: false,
        job: null,
        error: disabled
          ? "Active / DNS inventory is disabled or unavailable in this environment."
          : "Active / DNS inventory request was not accepted. Review bounds and confirmations."
      });
    }
  }

  function toggleRecordType(recordType: string) {
    setSelectedRecordTypes((current) =>
      current.includes(recordType) ? current.filter((item) => item !== recordType) : [...current, recordType]
    );
    setRequestState(initialRequestState);
  }

  return (
    <section className="panel active-dns-inventory-panel" aria-label="Active / DNS inventory">
      <div className="panel-header">
        <h2>
          <Network size={18} aria-hidden="true" />
          Active / DNS inventory
        </h2>
        <span className="status-pill">Backend gated</span>
      </div>

      <div className="badge-row" aria-label="Active DNS inventory guardrails">
        <span className="status-pill">Local/private/owned only</span>
        <span className="status-pill">Authorized domain only</span>
        <span className="status-pill">Best-effort inventory</span>
      </div>

      <p className="muted">
        This creates one authorized DNS configuration review indicator job with redacted grouped records.
      </p>

      <div className="query-warning" role="status">
        DNS queries are live when backend policy accepts the request. Results are best-effort or partial inventory review indicators, not
        complete-zone coverage.
      </div>

      <dl className="summary-list">
        <dt>Mode</dt>
        <dd className="mono">live_dns_inventory</dd>
        <dt>Profile</dt>
        <dd className="mono">dns_inventory_authorized</dd>
        <dt>Scope</dt>
        <dd>One explicit local, private, self-hosted, or owned domain that the operator is allowed to query.</dd>
        <dt>Records</dt>
        <dd className="mono">{ACTIVE_DNS_INVENTORY_RECORD_TYPES.join(", ")}</dd>
        <dt>Subdomain discovery</dt>
        <dd>Optional fixed candidate allowlist only: www, mail, smtp, imap, pop, api, app, admin, portal, dev, staging, test.</dd>
        <dt>Zone transfer</dt>
        <dd>Not available in this phase and always sent as false.</dd>
        <dt>Provider import</dt>
        <dd>Not available in this phase.</dd>
        <dt>Stored display</dt>
        <dd>Domain redacted, DNS names/values redacted, resolver logs and packets omitted, Raw JSON redacted.</dd>
      </dl>

      <form className="web-audit-form" onSubmit={(event) => void submitActiveDnsInventory(event)}>
        <label className="auth-field">
          <span>Domain</span>
          <input
            type="text"
            value={domain}
            onChange={(event) => {
              setDomain(event.target.value);
              setRequestState(initialRequestState);
            }}
            placeholder="example.internal"
            required
          />
        </label>
        {!domainValidation.ok && domain.trim() ? <p className="error-text">{domainValidation.error}</p> : null}

        <fieldset className="auth-field">
          <legend>Record types</legend>
          <div className="badge-row" aria-label="DNS record type selection">
            {ACTIVE_DNS_INVENTORY_RECORD_TYPES.map((recordType) => (
              <label className="checkbox-row compact-checkbox" key={recordType}>
                <input
                  type="checkbox"
                  checked={selectedRecordTypes.includes(recordType)}
                  onChange={() => toggleRecordType(recordType)}
                />
                {recordType}
              </label>
            ))}
          </div>
        </fieldset>
        {selectedRecordTypes.length === 0 ? <p className="error-text">Select at least one allowlisted DNS record type.</p> : null}

        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={includeSecurityRecords}
            onChange={(event) => {
              setIncludeSecurityRecords(event.target.checked);
              setRequestState(initialRequestState);
            }}
          />
          Include SPF, DMARC, and CAA review indicators.
        </label>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={includeSubdomainDiscovery}
            onChange={(event) => {
              setIncludeSubdomainDiscovery(event.target.checked);
              setRequestState(initialRequestState);
            }}
          />
          Include bounded fixed-candidate subdomain summary.
        </label>
        <label className="checkbox-row">
          <input type="checkbox" checked={false} disabled readOnly />
          Zone transfer is not available and will not be attempted.
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
          I confirm I own or am authorized to query this domain.
        </label>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={localPrivateOrOwnedScopeConfirmed}
            onChange={(event) => {
              setLocalPrivateOrOwnedScopeConfirmed(event.target.checked);
              setRequestState(initialRequestState);
            }}
          />
          I confirm this domain is local, private, self-hosted, or owned scope.
        </label>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={liveDnsQueriesConfirmed}
            onChange={(event) => {
              setLiveDnsQueriesConfirmed(event.target.checked);
              setRequestState(initialRequestState);
            }}
          />
          I understand this capability sends bounded live DNS queries if backend policy accepts it.
        </label>
        <button type="submit" disabled={!canSubmit}>
          <Play size={16} aria-hidden="true" />
          {requestState.loading ? "Creating DNS inventory job" : "Create DNS inventory job"}
        </button>
      </form>
      {requestState.error ? <p className="error-text">{requestState.error}</p> : null}
      {requestState.job ? <ActiveDnsInventoryJobCreatedNotice job={requestState.job} /> : null}
    </section>
  );
}

type DomainValidationResult =
  | { ok: true; domain: string; error: null }
  | { ok: false; domain: null; error: string };

export function validateActiveDnsInventoryDomain(value: string): DomainValidationResult {
  const domain = value.trim().toLowerCase();
  if (!domain) {
    return { ok: false, domain: null, error: "Enter one domain." };
  }
  if (/^https?:\/\//i.test(domain) || domain.includes("/") || domain.includes("?") || domain.includes("#") || domain.includes("@")) {
    return { ok: false, domain: null, error: "Enter a bare domain, not a URL, path, credential, query, or fragment." };
  }
  if (domain.includes("*") || domain.includes(",") || /\s/.test(domain)) {
    return { ok: false, domain: null, error: "DNS inventory accepts one explicit domain only." };
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain) || domain.includes(":") || domain.includes("/")) {
    return { ok: false, domain: null, error: "DNS inventory accepts domain names, not IPs, CIDR, or ranges." };
  }
  if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{1,62}$/.test(domain)) {
    return { ok: false, domain: null, error: "Enter a valid explicit domain with at least one dot." };
  }
  if (domain.length > 253) {
    return { ok: false, domain: null, error: "Domain is too long for DNS inventory." };
  }
  return { ok: true, domain, error: null };
}

function ActiveDnsInventoryJobCreatedNotice({ job }: { job: JobRecord }) {
  const result = asRecord(job.result);
  const summary = asRecord(result?.summary);
  const records = asRecord(result?.records);
  const securityRecords = asRecord(result?.security_records);
  const subdomains = asRecord(result?.subdomains);
  const status = asString(result?.result_status) ?? asString(result?.status) ?? "partial_inventory";
  const coverageLevel = asString(result?.coverage_level) ?? asString(summary?.coverage_level) ?? status;
  const recordCount = records
    ? Object.values(records).reduce<number>((total, group) => total + (asNumber(asRecord(group)?.count) ?? 0), 0)
    : 0;
  const spfPresent = asRecord(securityRecords?.spf)?.present === true;
  const dmarcPresent = asRecord(securityRecords?.dmarc)?.present === true;
  const caaPresent = asRecord(securityRecords?.caa)?.present === true;
  const subdomainCount = asNumber(subdomains?.count) ?? 0;

  return (
    <div className="query-warning" role="status">
      <strong>DNS configuration review indicator job created.</strong>
      <dl className="summary-list">
        <dt>Job</dt>
        <dd className="mono">{job.id}</dd>
        <dt>Status</dt>
        <dd className="mono">{status}</dd>
        <dt>Coverage</dt>
        <dd className="mono">{coverageLevel}</dd>
        <dt>Domain</dt>
        <dd className="mono">[REDACTED_DOMAIN]</dd>
        <dt>Grouped records</dt>
        <dd>{`${recordCount} redacted DNS record indicators.`}</dd>
        <dt>Mail/security indicators</dt>
        <dd>{`SPF ${spfPresent ? "present" : "not observed"}, DMARC ${dmarcPresent ? "present" : "not observed"}, CAA ${
          caaPresent ? "present" : "not observed"
        }.`}</dd>
        <dt>Subdomains</dt>
        <dd>{`${subdomainCount} bounded redacted subdomain candidates observed.`}</dd>
        <dt>Zone transfer / provider import</dt>
        <dd>Not attempted. Manual validation required.</dd>
      </dl>
      <p className="muted">The job record was opened below when the dashboard integration is available.</p>
    </div>
  );
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}
