import type { JobRecord } from "./types";

export type ActiveDnsOsintSourceSummary = {
  attempted: boolean;
  status: string;
  namesObservedCount: number;
  namesRetainedCount: number;
  namesDiscardedCount: number;
  truncated: boolean;
};

export type ActiveDnsOsintObservedNamesSummary = {
  count: number;
  maxNames: number;
  truncated: boolean;
  sample: string[];
};

export type ActiveDnsOsintExecutionSummary = {
  externalRequestsSent: number;
  ctQueriesSent: number;
  passiveDnsQueriesSent: number;
  dnsQueriesSent: number;
  httpRequestsSent: number;
  providerApiUsed: boolean;
  crawlingPerformed: boolean;
  observedNameAutoScanPerformed: boolean;
};

export type ActiveDnsOsintReport = {
  isActiveDnsOsint: boolean;
  status: string;
  coverageLevel: string;
  domain: string;
  resultInterpretation: string;
  manualValidationRequired: boolean;
  certificateTransparency: ActiveDnsOsintSourceSummary;
  passiveDns: { attempted: boolean; status: string };
  observedNames: ActiveDnsOsintObservedNamesSummary;
  execution: ActiveDnsOsintExecutionSummary;
  limits: Record<string, unknown>;
  warnings: string[];
  errors: string[];
  caveats: string[];
  rawJson: string;
};

const SOURCE_STATUSES = new Set([
  "not_attempted",
  "completed",
  "partial",
  "timed_out",
  "rate_limited",
  "source_unavailable",
  "source_error_controlled",
  "invalid_source_response",
  "truncated",
  "disabled",
  "blocked_by_policy"
]);

const RESULT_STATUSES = new Set([
  "osint_best_effort",
  "completed",
  "partial",
  "timed_out",
  "rate_limited",
  "source_unavailable",
  "source_error_controlled",
  "invalid_source_response",
  "failed_controlled"
]);

const SENSITIVE_KEYS = new Set([
  "raw_ct_payload",
  "raw_payload",
  "certificate_body",
  "raw_certificate",
  "raw_cert",
  "pem",
  "der",
  "raw_source_error",
  "source_exception",
  "exception",
  "stack",
  "traceback",
  "provider_secret",
  "provider_token",
  "provider_api_token",
  "api_key",
  "api_token",
  "authorization",
  "cookie",
  "cookies",
  "headers",
  "token",
  "credentials",
  "password",
  "secret"
]);

const DNS_NAME_KEYS = new Set(["name", "observed_name", "common_name", "subject", "subject_alt_name"]);
const DNS_VALUE_KEYS = new Set(["value", "email", "issuer"]);
const CLAIM_PATTERN = new RegExp(
  [
    ["all", "\\s+", "subdomains", "\\s+", "found"].join(""),
    ["all", "\\s+", "records", "\\s+", "found"].join(""),
    ["complete", "\\s+", "coverage"].join(""),
    ["confirmed", "\\s+", "vulnerability"].join(""),
    ["exploit", "able"].join(""),
    ["target", "\\s+", "is", "\\s+", "safe"].join(""),
    ["public", "\\s+", "scanner"].join("")
  ].join("|"),
  "gi"
);

export function buildActiveDnsOsintReport(job: JobRecord): ActiveDnsOsintReport {
  const result = asRecord(job.result);
  const sources = asRecord(result?.sources);
  const certificateTransparency = sourceSummary(asRecord(sources?.certificate_transparency));
  const passiveDnsSource = asRecord(sources?.passive_dns);
  const observedNames = observedNamesSummary(asRecord(result?.observed_names), certificateTransparency);
  const summary = asRecord(result?.summary);
  const execution = executionSummary(asRecord(result?.execution));
  const statusValue = asString(result?.result_status) ?? asString(result?.status) ?? "osint_best_effort";
  const status = RESULT_STATUSES.has(statusValue) ? statusValue : "failed_controlled";
  const coverageLevel = "osint_best_effort";
  const warnings = listStrings(result?.warnings);
  const errors = errorStrings(result?.errors, job.error);
  const caveats = listStrings(result?.surface_caveats);
  const publicValue = redactActiveDnsOsintValue({
    job: {
      id: job.id,
      audit_type: job.audit_type,
      file_id: job.file_id,
      target_url: "[REDACTED_DOMAIN]",
      target_domain: null,
      status: job.status,
      created_at: job.created_at,
      updated_at: job.updated_at,
      source_file_deleted_at: job.source_file_deleted_at,
      error: job.error
    },
    result: job.result
  });

  return {
    isActiveDnsOsint: job.audit_type === "active_dns_osint" || result?.capability === "active_dns_osint",
    status,
    coverageLevel,
    domain: "[REDACTED_DOMAIN]",
    resultInterpretation: asString(summary?.result_interpretation) ?? asString(result?.result_interpretation) ?? "DNS OSINT review indicator",
    manualValidationRequired: summary?.manual_validation_required !== false && result?.manual_validation_required !== false,
    certificateTransparency,
    passiveDns: {
      attempted: false,
      status: sourceStatus(asString(passiveDnsSource?.status), "not_attempted") === "not_attempted" ? "not_attempted" : "not_attempted"
    },
    observedNames,
    execution,
    limits: redactActiveDnsOsintValue(asRecord(result?.limits) ?? {}) as Record<string, unknown>,
    warnings: warnings.map(redactActiveDnsOsintText),
    errors: errors.map(redactActiveDnsOsintText),
    caveats: caveats.map(redactActiveDnsOsintText),
    rawJson: JSON.stringify(publicValue, null, 2)
  };
}

export function redactActiveDnsOsintValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactActiveDnsOsintText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactActiveDnsOsintValue(item));
  }
  if (value && typeof value === "object") {
    const redacted: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      const normalizedKey = key.toLowerCase().replace(/-/g, "_");
      if (normalizedKey === "domain" || normalizedKey === "raw_domain" || normalizedKey === "target_domain") {
        redacted[key] = "[REDACTED_DOMAIN]";
      } else if (DNS_NAME_KEYS.has(normalizedKey)) {
        redacted[key] = item ? "[REDACTED_DNS_NAME]" : item;
      } else if (DNS_VALUE_KEYS.has(normalizedKey)) {
        redacted[key] = item ? "[REDACTED_DNS_VALUE]" : item;
      } else if (SENSITIVE_KEYS.has(normalizedKey) || normalizedKey.includes("token") || normalizedKey.includes("secret")) {
        redacted[key] = item ? "[REDACTED]" : item;
      } else {
        redacted[key] = redactActiveDnsOsintValue(item);
      }
    }
    return redacted;
  }
  return value;
}

export function redactActiveDnsOsintText(value: string): string {
  return value
    .replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, "[REDACTED_CERTIFICATE]")
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[REDACTED_DNS_VALUE]")
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[REDACTED_DNS_VALUE]")
    .replace(/\b(?:[A-F0-9]{1,4}:){2,}[A-F0-9:]{1,}\b/gi, "[REDACTED_DNS_VALUE]")
    .replace(
      /\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b/gi,
      "[REDACTED_DNS_NAME]"
    )
    .replace(CLAIM_PATTERN, "[REDACTED_CLAIM]")
    .replace(/(?:Bearer|Token|Api-Key)\s+[A-Za-z0-9._~+/=-]{6,}/gi, "[REDACTED]")
    .replace(/\b(?:raw|provider)-[a-z0-9-]{4,}\b/gi, "[REDACTED]")
    .replace(/[A-Za-z0-9._%+-]*secret[A-Za-z0-9._%+-]*/gi, "[REDACTED]");
}

function sourceSummary(source: Record<string, unknown> | null): ActiveDnsOsintSourceSummary {
  return {
    attempted: source?.attempted === true,
    status: sourceStatus(asString(source?.status), "not_attempted"),
    namesObservedCount: nonNegativeNumber(source?.names_observed_count),
    namesRetainedCount: nonNegativeNumber(source?.names_retained_count),
    namesDiscardedCount: nonNegativeNumber(source?.names_discarded_count),
    truncated: source?.truncated === true
  };
}

function observedNamesSummary(
  observed: Record<string, unknown> | null,
  certificateTransparency: ActiveDnsOsintSourceSummary
): ActiveDnsOsintObservedNamesSummary {
  const count = nonNegativeNumber(observed?.count ?? certificateTransparency.namesRetainedCount);
  const maxNames = boundedNumber(observed?.max_names, 1, 100, 100);
  const rawSample = Array.isArray(observed?.sample) ? observed.sample : [];
  const sampleSize = Math.min(count, rawSample.length || count, 5);
  const sample = Array.from({ length: sampleSize }, () => "[REDACTED_DNS_NAME]");
  return {
    count,
    maxNames,
    truncated: observed?.truncated === true || certificateTransparency.truncated,
    sample
  };
}

function executionSummary(execution: Record<string, unknown> | null): ActiveDnsOsintExecutionSummary {
  return {
    externalRequestsSent: nonNegativeNumber(execution?.external_requests_sent),
    ctQueriesSent: nonNegativeNumber(execution?.ct_queries_sent),
    passiveDnsQueriesSent: nonNegativeNumber(execution?.passive_dns_queries_sent),
    dnsQueriesSent: nonNegativeNumber(execution?.dns_queries_sent),
    httpRequestsSent: nonNegativeNumber(execution?.http_requests_sent),
    providerApiUsed: execution?.provider_api_used === true,
    crawlingPerformed: execution?.crawling_performed === true,
    observedNameAutoScanPerformed: execution?.observed_name_auto_scan_performed === true
  };
}

function sourceStatus(value: string | null, fallback: string): string {
  if (!value) {
    return fallback;
  }
  return SOURCE_STATUSES.has(value) ? value : "invalid_source_response";
}

function errorStrings(value: unknown, jobError: string | null): string[] {
  const errors = Array.isArray(value) ? value : [];
  const normalized = errors
    .slice(0, 8)
    .map((error) => {
      if (typeof error === "string") {
        return error;
      }
      const record = asRecord(error);
      if (!record) {
        return null;
      }
      const code = asString(record.code) ?? "source_error_controlled";
      const source = asString(record.source) ?? "certificate_transparency";
      return `${source}: ${code}`;
    })
    .filter((item): item is string => Boolean(item));
  if (jobError) {
    normalized.unshift(jobError);
  }
  return normalized;
}

function listStrings(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => (typeof item === "string" ? item : null)).filter((item): item is string => Boolean(item));
}

function nonNegativeNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? Math.floor(value) : 0;
}

function boundedNumber(value: unknown, min: number, max: number, fallback: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.floor(value)));
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}
