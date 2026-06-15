import { FormEvent, useMemo, useState } from "react";
import { Search, Play } from "lucide-react";

import { ApiError, api } from "./api";
import { buildActiveDnsOsintReport } from "./activeDnsOsintReport";
import type { ActiveDnsOsintRequest, JobRecord } from "./types";

type ActiveDnsOsintPanelProps = {
  onJobCreated?: (job: JobRecord) => void | Promise<void>;
};

type RequestState = {
  loading: boolean;
  error: string | null;
  job: JobRecord | null;
};

type DomainValidationResult =
  | { ok: true; domain: string; error: null }
  | { ok: false; domain: null; error: string };

type MaxNamesValidationResult =
  | { ok: true; maxNames: number; error: null }
  | { ok: false; maxNames: null; error: string };

const initialRequestState: RequestState = {
  loading: false,
  error: null,
  job: null
};

export function ActiveDnsOsintPanel({ onJobCreated }: ActiveDnsOsintPanelProps) {
  const [domain, setDomain] = useState("");
  const [maxNamesText, setMaxNamesText] = useState("100");
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [ownedOrAuthorizedDomainConfirmed, setOwnedOrAuthorizedDomainConfirmed] = useState(false);
  const [publicOsintQueriesConfirmed, setPublicOsintQueriesConfirmed] = useState(false);
  const [requestState, setRequestState] = useState<RequestState>(initialRequestState);
  const domainValidation = useMemo(() => validateActiveDnsOsintDomain(domain), [domain]);
  const maxNamesValidation = useMemo(() => parseActiveDnsOsintMaxNames(maxNamesText), [maxNamesText]);
  const canSubmit =
    !requestState.loading &&
    domainValidation.ok &&
    maxNamesValidation.ok &&
    authorizationConfirmed &&
    ownedOrAuthorizedDomainConfirmed &&
    publicOsintQueriesConfirmed;

  async function submitActiveDnsOsint(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canSubmit || !domainValidation.ok || !maxNamesValidation.ok) {
      return;
    }

    const request: ActiveDnsOsintRequest = {
      mode: "live_dns_osint",
      profile: "ct_subdomain_discovery_bounded",
      domain: domainValidation.domain,
      include_certificate_transparency: true,
      include_passive_dns: false,
      max_names: maxNamesValidation.maxNames,
      authorization_confirmed: true,
      owned_or_authorized_domain_confirmed: true,
      public_osint_queries_confirmed: true
    };

    setRequestState({ loading: true, error: null, job: null });
    try {
      const job = await api.createActiveDnsOsint(request);
      await onJobCreated?.(job);
      setRequestState({ loading: false, error: null, job });
    } catch (error) {
      const disabled = error instanceof ApiError && error.status === 403;
      setRequestState({
        loading: false,
        job: null,
        error: disabled
          ? "Active / DNS OSINT is disabled or unavailable in this environment."
          : "Active / DNS OSINT request was not accepted. Review bounds and confirmations."
      });
    }
  }

  return (
    <section className="panel active-dns-osint-panel" aria-label="Active / DNS OSINT">
      <div className="panel-header">
        <h2>
          <Search size={18} aria-hidden="true" />
          Active / DNS OSINT
        </h2>
        <span className="status-pill">Backend gated</span>
      </div>

      <div className="badge-row" aria-label="Active DNS OSINT guardrails">
        <span className="status-pill">Authorized domain only</span>
        <span className="status-pill">Certificate Transparency bounded</span>
        <span className="status-pill">Passive DNS unavailable</span>
        <span className="status-pill">Best-effort review</span>
      </div>

      <p className="muted">
        This creates one public-source observed-name review job for an authorized domain through the backend contract.
      </p>

      <div className="query-warning" role="status">
        Certificate Transparency is the only OSINT source in this flow. Passive DNS, provider import, observed-name auto-scan, broad
        wordlists, crawling, and browser-side source calls are not available. Results are source-limited and need manual validation.
      </div>

      <dl className="summary-list">
        <dt>Mode</dt>
        <dd className="mono">live_dns_osint</dd>
        <dt>Profile</dt>
        <dd className="mono">ct_subdomain_discovery_bounded</dd>
        <dt>Coverage</dt>
        <dd className="mono">osint_best_effort</dd>
        <dt>Source</dt>
        <dd>Certificate Transparency enabled by request contract when backend policy accepts it.</dd>
        <dt>Passive DNS</dt>
        <dd>Not available in this phase and always sent as disabled.</dd>
        <dt>Stored display</dt>
        <dd>Domain and observed-name samples are redacted; raw CT payloads and certificate bodies are omitted.</dd>
        <dt>Result wording</dt>
        <dd>DNS OSINT review indicator. Public-source observed names. Manual validation required.</dd>
      </dl>

      <form className="web-audit-form" onSubmit={(event) => void submitActiveDnsOsint(event)}>
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
        {domain.trim() && !domainValidation.ok ? <p className="error-text">{domainValidation.error}</p> : null}
        <label className="auth-field">
          <span>Max observed names</span>
          <input
            type="number"
            min={1}
            max={100}
            step={1}
            value={maxNamesText}
            onChange={(event) => {
              setMaxNamesText(event.target.value);
              setRequestState(initialRequestState);
            }}
            required
          />
        </label>
        {!maxNamesValidation.ok && maxNamesText.trim() ? <p className="error-text">{maxNamesValidation.error}</p> : null}
        <p className="muted">Retained names are capped between 1 and 100. Observed names are not queued for scanning.</p>
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
            checked={ownedOrAuthorizedDomainConfirmed}
            onChange={(event) => {
              setOwnedOrAuthorizedDomainConfirmed(event.target.checked);
              setRequestState(initialRequestState);
            }}
          />
          I confirm this is my domain or an explicitly authorized domain.
        </label>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={publicOsintQueriesConfirmed}
            onChange={(event) => {
              setPublicOsintQueriesConfirmed(event.target.checked);
              setRequestState(initialRequestState);
            }}
          />
          I understand this may send bounded public OSINT queries if backend policy accepts it.
        </label>
        <button type="submit" disabled={!canSubmit}>
          <Play size={16} aria-hidden="true" />
          {requestState.loading ? "Creating DNS OSINT job" : "Create DNS OSINT job"}
        </button>
      </form>
      {requestState.error ? <p className="error-text">{requestState.error}</p> : null}
      {requestState.job ? <ActiveDnsOsintJobCreatedNotice job={requestState.job} /> : null}
    </section>
  );
}

export function validateActiveDnsOsintDomain(value: string): DomainValidationResult {
  const domain = value.trim().toLowerCase();
  if (!domain) {
    return { ok: false, domain: null, error: "Enter one domain." };
  }
  if (/^https?:\/\//i.test(domain) || domain.includes("/") || domain.includes("?") || domain.includes("#") || domain.includes("@")) {
    return { ok: false, domain: null, error: "Enter a bare domain, not a URL, path, credential, query, or fragment." };
  }
  if (domain.includes("*") || domain.includes(",") || /\s/.test(domain)) {
    return { ok: false, domain: null, error: "DNS OSINT accepts one explicit domain only." };
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain) || domain.includes(":") || domain.includes("/")) {
    return { ok: false, domain: null, error: "DNS OSINT accepts domain names, not IPs, CIDR, or ranges." };
  }
  if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{1,62}$/.test(domain)) {
    return { ok: false, domain: null, error: "Enter a valid explicit domain with at least one dot." };
  }
  if (domain.length > 253) {
    return { ok: false, domain: null, error: "Domain is too long for DNS OSINT." };
  }
  return { ok: true, domain, error: null };
}

export function parseActiveDnsOsintMaxNames(value: string): MaxNamesValidationResult {
  const token = value.trim();
  if (!token) {
    return { ok: false, maxNames: null, error: "Enter a retained-name cap." };
  }
  if (!/^\d+$/.test(token)) {
    return { ok: false, maxNames: null, error: "Max observed names must be a whole number." };
  }
  const maxNames = Number(token);
  if (!Number.isSafeInteger(maxNames) || maxNames < 1 || maxNames > 100) {
    return { ok: false, maxNames: null, error: "Max observed names must be between 1 and 100." };
  }
  return { ok: true, maxNames, error: null };
}

function ActiveDnsOsintJobCreatedNotice({ job }: { job: JobRecord }) {
  const report = buildActiveDnsOsintReport(job);
  return (
    <div className="query-warning" role="status">
      <strong>DNS OSINT review indicator job created.</strong>
      <dl className="summary-list">
        <dt>Job</dt>
        <dd className="mono">{job.id}</dd>
        <dt>Status</dt>
        <dd className="mono">{report.status}</dd>
        <dt>Coverage</dt>
        <dd className="mono">{report.coverageLevel}</dd>
        <dt>Domain</dt>
        <dd className="mono">[REDACTED_DOMAIN]</dd>
        <dt>Certificate Transparency</dt>
        <dd>{`${report.certificateTransparency.status}; retained ${report.certificateTransparency.namesRetainedCount} of ${report.certificateTransparency.namesObservedCount} observed names.`}</dd>
        <dt>Observed names</dt>
        <dd>{`${report.observedNames.count} redacted public-source observed-name indicator${report.observedNames.count === 1 ? "" : "s"}.`}</dd>
        <dt>Passive DNS</dt>
        <dd className="mono">{report.passiveDns.status}</dd>
        <dt>Validation</dt>
        <dd>Manual validation required. Observed names are not auto-scanned.</dd>
      </dl>
      <p className="muted">The job record was opened below when the dashboard integration is available.</p>
    </div>
  );
}
