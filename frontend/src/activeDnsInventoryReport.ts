import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type ActiveDnsInventoryRecordSample = {
  name: string;
  type: string;
  value: string;
  ttl: number | null;
  priority: number | null;
};

export type ActiveDnsInventoryRecordGroup = {
  type: string;
  count: number;
  sample: ActiveDnsInventoryRecordSample[];
  truncated: boolean;
};

export type ActiveDnsInventorySecurityIndicator = {
  checked: boolean;
  present: boolean | null;
  status: string | null;
  recordCount: number | null;
  interpretation: string | null;
};

export type ActiveDnsInventorySubdomainSample = {
  name: string;
  recordTypes: string[];
  recordCount: number;
};

export type ActiveDnsInventorySubdomainSummary = {
  enabled: boolean;
  strategy: string;
  candidatesChecked: number;
  queryRecordTypes: string[];
  count: number;
  sample: ActiveDnsInventorySubdomainSample[];
  sampleTruncated: boolean;
};

export type ActiveDnsInventoryZoneTransferSummary = {
  attempted: boolean;
  status: string;
  nameserversConsidered: number;
  nameserversAttempted: number;
  recordsReceivedCount: number;
  recordsRetainedCount: number;
  truncated: boolean;
  reasonCode: string | null;
  interpretation: string | null;
};

export type ActiveDnsInventoryReport = {
  isActiveDnsInventory: boolean;
  status: string;
  coverageLevel: string;
  mode: string | null;
  profile: string | null;
  recordTypes: string[];
  recordGroups: ActiveDnsInventoryRecordGroup[];
  securityIndicators: Record<"spf" | "dmarc" | "caa" | "dkim", ActiveDnsInventorySecurityIndicator>;
  subdomains: ActiveDnsInventorySubdomainSummary;
  zoneTransfer: ActiveDnsInventoryZoneTransferSummary;
  zoneTransferStatus: string;
  providerImportStatus: string;
  dnsQueriesSent: number;
  subdomainQueriesSent: number;
  overview: MetadataEntry[];
  limits: MetadataEntry[];
  warnings: string[];
  errors: string[];
  caveats: string[];
  rawJson: string;
};

const ALLOWED_RECORD_TYPES = new Set(["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"]);
const CONTROLLED_STATUS_LABELS: Record<string, string> = {
  best_effort_inventory: "best_effort_inventory",
  partial_inventory: "partial_inventory",
  not_executed: "not_executed",
  zone_transfer_complete: "zone_transfer_complete",
  dns_inventory_error_controlled: "partial_inventory",
  failed: "partial_inventory",
  completed: "best_effort_inventory"
};
const ALLOWED_ZONE_TRANSFER_STATUSES = new Set([
  "not_attempted",
  "authorization_required",
  "no_authoritative_nameservers",
  "refused",
  "unavailable",
  "timed_out",
  "malformed_response",
  "record_limit_exceeded",
  "zone_transfer_complete"
]);

export function buildActiveDnsInventoryReport(job: JobRecord): ActiveDnsInventoryReport {
  const redactedJob = redactActiveDnsInventoryValue(job) as JobRecord;
  const result = asRecord(redactedJob.result);
  const rawResult = asRecord(job.result);
  const summary = asRecord(result?.summary);
  const execution = asRecord(result?.execution);
  const limitsRecord = asRecord(result?.limits);
  const status = normalizeStatus(
    asString(result?.result_status) ?? asString(result?.status) ?? asString(rawResult?.result_status) ?? asString(rawResult?.status) ?? job.status
  );
  const coverageLevel = normalizeCoverageLevel(asString(result?.coverage_level) ?? asString(summary?.coverage_level) ?? status);
  const recordTypes = asStringArray(result?.record_types).map((item) => item.toUpperCase()).filter((item) => ALLOWED_RECORD_TYPES.has(item));
  const recordGroups = recordGroupsFromValue(result?.records);
  const securityIndicators = securityIndicatorsFromValue(result?.security_records);
  const subdomains = subdomainsFromValue(result?.subdomains);
  const zoneTransfer = zoneTransferFromValue(result?.zone_transfer);
  const providerImport = asRecord(result?.provider_import);
  const dnsQueriesSent = asNumber(result?.dns_queries_sent) ?? asNumber(execution?.dns_queries_sent) ?? 0;
  const subdomainQueriesSent = asNumber(result?.subdomain_queries_sent) ?? asNumber(execution?.subdomain_queries_sent) ?? 0;
  const errors = errorsFromValue(result?.errors, redactedJob.error);
  const warnings = asStringArray(result?.warnings);
  const caveats = asStringArray(result?.surface_caveats);

  return {
    isActiveDnsInventory:
      job.audit_type === "active_dns_inventory" ||
      asString(rawResult?.capability) === "active_dns_inventory" ||
      asString(rawResult?.audit_type) === "active_dns_inventory",
    status,
    coverageLevel,
    mode: asString(result?.mode) ?? asString(rawResult?.mode),
    profile: asString(result?.profile) ?? asString(rawResult?.profile),
    recordTypes,
    recordGroups,
    securityIndicators,
    subdomains,
    zoneTransfer,
    zoneTransferStatus: zoneTransfer.status,
    providerImportStatus: asString(providerImport?.status) ?? "not_attempted",
    dnsQueriesSent,
    subdomainQueriesSent,
    overview: [
      { label: "Mode", value: asString(result?.mode) ?? "live_dns_inventory" },
      { label: "Profile", value: asString(result?.profile) ?? "dns_inventory_authorized" },
      { label: "Result status", value: status },
      { label: "Coverage level", value: coverageLevel },
      { label: "Record groups", value: String(recordGroups.length) },
      { label: "Redacted record count", value: String(recordGroups.reduce((total, group) => total + group.count, 0)) },
      { label: "Bounded subdomain candidates", value: String(subdomains.candidatesChecked) },
      { label: "Bounded subdomain observations", value: String(subdomains.count) },
      { label: "Zone transfer", value: zoneTransfer.status },
      { label: "AXFR records retained", value: String(zoneTransfer.recordsRetainedCount) },
      { label: "DNS queries sent", value: String(dnsQueriesSent) },
      { label: "Subdomain queries sent", value: String(subdomainQueriesSent) }
    ],
    limits: entriesFromRecord(limitsRecord),
    warnings,
    errors,
    caveats,
    rawJson: JSON.stringify(redactActiveDnsInventoryValue(job), null, 2)
  };
}

export function redactActiveDnsInventoryValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactActiveDnsInventoryText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactActiveDnsInventoryValue(item));
  }
  const record = asRecord(value);
  if (record) {
    return Object.fromEntries(
      Object.entries(record).map(([key, item]) => {
        if (isDomainKey(key)) {
          return [key, item === null || item === undefined || item === "" ? item : "[REDACTED_DOMAIN]"];
        }
        if (isDnsNameKey(key)) {
          return [key, item === null || item === undefined || item === "" ? item : "[REDACTED_DNS_NAME]"];
        }
        if (isDnsValueKey(key)) {
          return [key, item === null || item === undefined || item === "" ? item : "[REDACTED_DNS_VALUE]"];
        }
        if (isSensitiveDnsValueKey(key)) {
          return [redactedKeyForKey(key), item === null || item === undefined || item === "" ? item : redactedValueForKey(key)];
        }
        return [key, redactActiveDnsInventoryValue(item)];
      })
    );
  }
  return value;
}

export function redactActiveDnsInventoryText(value: string): string {
  return value
    .replace(/\b(?:dig|host|nslookup)\b\s+[^\n\r"'}\]]*/gi, "[REDACTED_COMMAND]")
    .replace(/\b(?:AXFR|IXFR)\b\s+[^\n\r"'}\]]*/gi, "[REDACTED_DNS_VALUE]")
    .replace(/\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "Authorization: [REDACTED]")
    .replace(/\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "[REDACTED]")
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)([^:\s/@;"']+):([^@\s/;"']+)@([^\s;"']+)/gi, "$1[REDACTED]@$4")
    .replace(
      /([?&](?:access_token|refresh_token|id_token|api_key|apikey|key|token|secret|password|passwd|pwd|session|sid|auth|authorization|jwt|bearer|sig|signature|client_secret|provider_token|zone_id)=)[^&#\s]+/gi,
      "$1[REDACTED]"
    )
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[REDACTED_DNS_VALUE]")
    .replace(
      /\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b(?!:\d{2})/gi,
      (match) => (match.includes("::") || match.split(":").length > 3 ? "[REDACTED_DNS_VALUE]" : match)
    )
    .replace(
      /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|local|internal|lan|home|test|invalid)\b/gi,
      "[REDACTED_DOMAIN]"
    )
    .replace(/\bv=spf1\b[^\n\r,"'}\]]*/gi, "[REDACTED_DNS_VALUE]")
    .replace(/\bv=DMARC1\b[^\n\r,"'}\]]*/gi, "[REDACTED_DNS_VALUE]")
    .replace(/\b(?:super-secret-password|raw-api-key-[a-z0-9_-]+|token_should_never_render|session_should_not_render|cookie_should_not_render|[a-z0-9._-]*should_(?:never|not)_render[a-z0-9._-]*)\b/gi, "[REDACTED]")
    .replace(
      /(^|[\s,{])([A-Z0-9_$.-]*(?:AUTHORIZATION|COOKIE|SET_COOKIE|SESSION|PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|CLIENT_SECRET|CREDENTIAL|AUTH|PROVIDER|ZONE_ID|ACCOUNT_ID)[A-Z0-9_$.-]*)(\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2$3$4[REDACTED]"
    )
    .replace(
      /(\b(?:authorization|cookie|set-cookie|session|password|passwd|pwd|secret|token|api_key|apikey|private_key|client_secret|credential|auth|provider_api_token|provider_account_id|provider_zone_id|raw_dns_packet|raw_dns_message|dns_message|dns_packet|raw_resolver_log|raw_zone|zone_file|zone_transfer_payload)\b\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2[REDACTED]"
    )
    .replace(
      /\b(?:raw_dns_packet|raw_dns_message|dns_message|dns_packet|raw_resolver_log|raw_zone|zone_file|zone_transfer_payload|provider_api_token|provider_account_id|provider_zone_id)\b/gi,
      "[REDACTED]"
    )
    .replace(/\bconfirmed\s+vulnerability\b/gi, "[REDACTED_CLAIM]")
    .replace(/\bexploitable\b/gi, "[REDACTED_CLAIM]")
    .replace(/\btarget\s+is\s+safe\b/gi, "[REDACTED_CLAIM]")
    .replace(/\ball\s+records\s+found\b/gi, "[REDACTED_CLAIM]")
    .replace(/\bfull\s+DNS\s+inventory\b/gi, "[REDACTED_CLAIM]")
    .replace(/\bpublic\s+scanner\b/gi, "[REDACTED_CLAIM]")
    .replace(/\[REDACTED\]\]+/g, "[REDACTED]");
}

function recordGroupsFromValue(value: unknown): ActiveDnsInventoryRecordGroup[] {
  const record = asRecord(value);
  if (!record) {
    return [];
  }
  return Object.entries(record)
    .flatMap(([recordType, groupValue]) => {
      const type = recordType.toUpperCase();
      if (!ALLOWED_RECORD_TYPES.has(type)) {
        return [];
      }
      const group = asRecord(groupValue);
      const sample = Array.isArray(group?.sample) ? group.sample : [];
      return [
        {
          type,
          count: asNumber(group?.count) ?? 0,
          sample: sample.flatMap(recordSampleFromValue).slice(0, 12),
          truncated: group?.truncated === true
        }
      ];
    })
    .sort((left, right) => left.type.localeCompare(right.type));
}

function recordSampleFromValue(value: unknown): ActiveDnsInventoryRecordSample[] {
  const record = asRecord(value);
  if (!record) {
    return [];
  }
  return [
    {
      name: safeDnsName(asString(record.name)),
      type: safeRecordType(asString(record.type)),
      value: "[REDACTED_DNS_VALUE]",
      ttl: asNumber(record.ttl),
      priority: asNumber(record.priority)
    }
  ];
}

function securityIndicatorsFromValue(value: unknown): Record<"spf" | "dmarc" | "caa" | "dkim", ActiveDnsInventorySecurityIndicator> {
  const record = asRecord(value);
  return {
    spf: securityIndicatorFromRecord(asRecord(record?.spf)),
    dmarc: securityIndicatorFromRecord(asRecord(record?.dmarc)),
    caa: securityIndicatorFromRecord(asRecord(record?.caa)),
    dkim: securityIndicatorFromRecord(asRecord(record?.dkim))
  };
}

function securityIndicatorFromRecord(record: Record<string, unknown> | null): ActiveDnsInventorySecurityIndicator {
  return {
    checked: record?.checked === true,
    present: typeof record?.present === "boolean" ? record.present : null,
    status: safeDnsText(asString(record?.status)),
    recordCount: asNumber(record?.record_count),
    interpretation: safeDnsText(asString(record?.interpretation))
  };
}

function subdomainsFromValue(value: unknown): ActiveDnsInventorySubdomainSummary {
  const record = asRecord(value);
  const sample = Array.isArray(record?.sample) ? record.sample : [];
  return {
    enabled: record?.enabled === true,
    strategy: safeDnsText(asString(record?.strategy)) ?? "fixed_candidate_allowlist",
    candidatesChecked: asNumber(record?.candidates_checked) ?? 0,
    queryRecordTypes: asStringArray(record?.query_record_types).map((item) => safeRecordType(item)),
    count: asNumber(record?.count) ?? 0,
    sample: sample
      .flatMap((item) => {
        const sampleRecord = asRecord(item);
        if (!sampleRecord) {
          return [];
        }
        return [
          {
            name: safeDnsName(asString(sampleRecord.name)),
            recordTypes: asStringArray(sampleRecord.record_types).map((item) => safeRecordType(item)),
            recordCount: asNumber(sampleRecord.record_count) ?? 0
          }
        ];
      })
      .slice(0, 12),
    sampleTruncated: record?.sample_truncated === true
  };
}

function zoneTransferFromValue(value: unknown): ActiveDnsInventoryZoneTransferSummary {
  const record = asRecord(value);
  const status = safeZoneTransferStatus(asString(record?.status));
  return {
    attempted: record?.attempted === true,
    status,
    nameserversConsidered: safeCount(asNumber(record?.nameservers_considered)),
    nameserversAttempted: safeCount(asNumber(record?.nameservers_attempted)),
    recordsReceivedCount: safeCount(asNumber(record?.records_received_count)),
    recordsRetainedCount: safeCount(asNumber(record?.records_retained_count)),
    truncated: record?.truncated === true,
    reasonCode: safeDnsText(asString(record?.reason_code)),
    interpretation: safeDnsText(asString(record?.interpretation))
  };
}

function errorsFromValue(value: unknown, jobError: unknown): string[] {
  const errors = [...asStringArray(value), ...(typeof jobError === "string" && jobError.trim() ? [jobError] : [])].map(redactActiveDnsInventoryText);
  return dedupeStrings(errors.map((item) => (item.includes("[REDACTED") ? "[REDACTED_ERROR]" : item)));
}

function entriesFromRecord(record: Record<string, unknown> | null, prefix = ""): MetadataEntry[] {
  if (!record) {
    return [];
  }
  return Object.entries(record)
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .flatMap(([key, value]) => {
      const label = prefix ? `${prefix}.${key}` : key;
      const nested = asRecord(value);
      if (nested) {
        return entriesFromRecord(nested, label);
      }
      return [{ label, value: stringifyValue(value) }];
    });
}

function safeDnsName(value: string | null): string {
  if (!value) {
    return "[REDACTED_DNS_NAME]";
  }
  return value === "[REDACTED_DOMAIN]" ? "[REDACTED_DOMAIN]" : "[REDACTED_DNS_NAME]";
}

function safeDnsText(value: string | null): string | null {
  if (!value) {
    return null;
  }
  return redactActiveDnsInventoryText(value).slice(0, 160);
}

function safeRecordType(value: string | null): string {
  const type = value?.trim().toUpperCase() ?? "UNKNOWN";
  return ALLOWED_RECORD_TYPES.has(type) ? type : "UNKNOWN";
}

function safeZoneTransferStatus(value: string | null): string {
  const status = value?.trim().toLowerCase() ?? "not_attempted";
  return ALLOWED_ZONE_TRANSFER_STATUSES.has(status) ? status : "unavailable";
}

function safeCount(value: number | null): number {
  if (value === null || value < 0) {
    return 0;
  }
  return Math.floor(Math.min(value, 100000));
}

function normalizeStatus(value: string | null): string {
  if (!value) {
    return "partial_inventory";
  }
  const normalized = value.trim().toLowerCase();
  return CONTROLLED_STATUS_LABELS[normalized] ?? "partial_inventory";
}

function normalizeCoverageLevel(value: string | null): string {
  const normalized = value?.trim().toLowerCase() ?? "partial_inventory";
  return normalized === "best_effort_inventory" ||
    normalized === "partial_inventory" ||
    normalized === "not_executed" ||
    normalized === "zone_transfer_complete"
    ? normalized
    : "partial_inventory";
}

function isDomainKey(key: string): boolean {
  const normalized = normalizeKey(key);
  return ["domain", "raw_domain", "root_domain", "target", "target_domain", "target_url"].includes(normalized);
}

function isDnsNameKey(key: string): boolean {
  const normalized = normalizeKey(key);
  return [
    "authoritative_nameserver",
    "authoritative_nameservers",
    "hostname",
    "host",
    "name",
    "nameserver",
    "nameservers",
    "normalized_domain",
    "owner_name",
    "qname"
  ].includes(normalized);
}

function isDnsValueKey(key: string): boolean {
  const normalized = normalizeKey(key);
  return ["address", "addresses", "data", "ip", "ips", "record_value", "raw_value", "rdata", "value", "values"].includes(normalized);
}

function isSensitiveDnsValueKey(key: string): boolean {
  const normalized = normalizeKey(key);
  if (normalized.includes("redacted") || normalized.endsWith("_count")) {
    return false;
  }
  return [
    "account_id",
    "api_key",
    "api_token",
    "axfr_server_override",
    "command",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "header",
    "headers",
    "payload",
    "provider_account_id",
    "provider_api_token",
    "provider_credentials",
    "provider_token",
    "provider_zone_id",
    "raw_dns_packet",
    "raw_dns_message",
    "raw_zone",
    "raw_payload",
    "raw_resolver_log",
    "resolver_log",
    "resolver_override",
    "shell_command",
    "stderr",
    "stdout",
    "target_file",
    "token",
    "tokens",
    "zone_file",
    "zone_transfer_payload",
    "wordlist",
    "zone_id"
  ].includes(normalized);
}

function redactedValueForKey(key: string): string {
  const normalized = normalizeKey(key);
  if (normalized === "command" || normalized === "shell_command") {
    return "[REDACTED_COMMAND]";
  }
  if (
    normalized.includes("dns_packet") ||
    normalized.includes("dns_message") ||
    normalized.includes("resolver_log") ||
    normalized === "raw_zone" ||
    normalized === "zone_file" ||
    normalized === "zone_transfer_payload"
  ) {
    return "[REDACTED_DNS_VALUE]";
  }
  if (normalized === "payload" || normalized === "raw_payload") {
    return "[REDACTED_PAYLOAD]";
  }
  if (normalized === "stderr" || normalized === "stdout") {
    return "[REDACTED_ERROR]";
  }
  return "[REDACTED]";
}

function redactedKeyForKey(key: string): string {
  const normalized = normalizeKey(key);
  if (normalized === "command" || normalized === "shell_command") {
    return "redacted_command";
  }
  if (
    normalized.includes("dns_packet") ||
    normalized.includes("dns_message") ||
    normalized.includes("resolver_log") ||
    normalized === "raw_zone" ||
    normalized === "zone_file" ||
    normalized === "zone_transfer_payload"
  ) {
    return "redacted_dns_material";
  }
  if (normalized === "payload" || normalized === "raw_payload") {
    return "redacted_payload";
  }
  if (normalized.startsWith("provider") || normalized === "account_id" || normalized === "zone_id") {
    return "redacted_provider_material";
  }
  if (normalized === "stderr" || normalized === "stdout") {
    return "redacted_error_material";
  }
  return "redacted_secret_material";
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? redactActiveDnsInventoryText(value.trim()) : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return typeof value === "string" && value.trim() ? [redactActiveDnsInventoryText(value)] : [];
  }
  return value
    .map((item) => stringifyValue(item))
    .filter((item) => item.trim().length > 0);
}

function stringifyValue(value: unknown): string {
  if (typeof value === "string") {
    return redactActiveDnsInventoryText(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (value === null || value === undefined) {
    return "";
  }
  return redactActiveDnsInventoryText(JSON.stringify(value));
}

function normalizeKey(key: string): string {
  return key.replace(/([a-z])([A-Z])/g, "$1_$2").replace(/[^a-zA-Z0-9]+/g, "_").replace(/^_+|_+$/g, "").toLowerCase();
}

function dedupeStrings(values: string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const value of values) {
    if (!value || seen.has(value)) {
      continue;
    }
    seen.add(value);
    result.push(value);
  }
  return result;
}
