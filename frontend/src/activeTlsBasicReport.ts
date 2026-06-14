import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type ActiveTlsBasicCertificateSummary = {
  available: boolean;
  subject: string | null;
  issuer: string | null;
  sanCount: number;
  sanSample: string[];
  notBefore: string | null;
  notAfter: string | null;
  daysUntilExpiry: number | null;
};

export type ActiveTlsBasicReport = {
  isActiveTlsBasic: boolean;
  status: string;
  mode: string | null;
  profile: string | null;
  port: number | null;
  handshakeStatus: string;
  protocol: string | null;
  cipher: string | null;
  certificate: ActiveTlsBasicCertificateSummary;
  overview: MetadataEntry[];
  limits: MetadataEntry[];
  warnings: string[];
  errors: string[];
  reasonCodes: string[];
  rawJson: string;
};

const CONTROLLED_STATUS_LABELS: Record<string, string> = {
  certificate_unavailable: "certificate_unavailable",
  failed: "tls_error_controlled",
  handshake_failed: "handshake_failed",
  handshake_succeeded: "handshake_succeeded",
  not_executed: "not_executed",
  not_implemented: "not_executed",
  timed_out: "timed_out",
  timeout: "timed_out",
  tls_error_controlled: "tls_error_controlled",
  unknown: "tls_error_controlled"
};

const SAFE_HANDSHAKE_STATUSES = new Set([
  "certificate_unavailable",
  "handshake_failed",
  "succeeded",
  "timed_out",
  "tls_error_controlled"
]);

export function buildActiveTlsBasicReport(job: JobRecord): ActiveTlsBasicReport {
  const redactedJob = redactActiveTlsBasicValue(job) as JobRecord;
  const result = asRecord(redactedJob.result);
  const rawResult = asRecord(job.result);
  const handshake = asRecord(result?.handshake);
  const certificate = asRecord(result?.certificate);
  const limitsRecord = asRecord(result?.limits);
  const summary = asRecord(result?.summary);
  const status = normalizeStatus(
    asString(result?.result_status) ?? asString(result?.status) ?? asString(rawResult?.result_status) ?? asString(rawResult?.status) ?? job.status
  );
  const mode = asString(result?.mode) ?? asString(rawResult?.mode);
  const profile = asString(result?.profile) ?? asString(rawResult?.profile);
  const port = asNumber(result?.port) ?? asNumber(rawResult?.port);
  const certificateSummary = certificateFromRecord(certificate);
  const handshakeStatus = safeHandshakeStatus(asString(handshake?.status) ?? status);
  const protocol = safeTlsText(asString(handshake?.protocol));
  const cipher = safeTlsText(asString(handshake?.cipher));
  const reasonCodes = dedupeStrings([
    ...asStringArray(result?.reason_codes),
    ...asStringArray(summary?.reason_codes)
  ]);
  const warnings = asStringArray(result?.warnings);
  const errors = errorsFromValue(result?.errors, redactedJob.error);

  return {
    isActiveTlsBasic:
      job.audit_type === "active_tls_basic" ||
      asString(rawResult?.capability) === "active_tls_basic" ||
      asString(rawResult?.audit_type) === "active_tls_basic",
    status,
    mode,
    profile,
    port,
    handshakeStatus,
    protocol,
    cipher,
    certificate: certificateSummary,
    overview: [
      { label: "Mode", value: mode ?? "live_tls_basic" },
      { label: "Profile", value: profile ?? "tls_handshake_summary" },
      { label: "Result status", value: status },
      { label: "Handshake status", value: handshakeStatus },
      { label: "Port", value: port === null ? "N/A" : String(port) },
      { label: "Protocol", value: protocol ?? "N/A" },
      { label: "Cipher", value: cipher ?? "N/A" },
      { label: "Certificate available", value: String(certificateSummary.available) },
      { label: "Days until expiry", value: certificateSummary.daysUntilExpiry === null ? "N/A" : String(certificateSummary.daysUntilExpiry) }
    ],
    limits: entriesFromRecord(limitsRecord),
    warnings,
    errors,
    reasonCodes,
    rawJson: JSON.stringify(redactActiveTlsBasicValue(job), null, 2)
  };
}

export function redactActiveTlsBasicValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactActiveTlsBasicText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactActiveTlsBasicValue(item));
  }
  const record = asRecord(value);
  if (record) {
    return Object.fromEntries(
      Object.entries(record).map(([key, item]) => {
        if (isTargetKey(key)) {
          return [key, item === null || item === undefined || item === "" ? item : "[REDACTED_TARGET]"];
        }
        if (isSensitiveTlsValueKey(key)) {
          return [key, item === null || item === undefined || item === "" ? item : redactedValueForKey(key)];
        }
        return [key, redactActiveTlsBasicValue(item)];
      })
    );
  }
  return value;
}

export function redactActiveTlsBasicText(value: string): string {
  return value
    .replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gi, "[REDACTED_CERTIFICATE]")
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi, "[REDACTED]")
    .replace(/-----BEGIN CERTIFICATE-----/gi, "[REDACTED_CERTIFICATE]")
    .replace(/\b(?:certificate_pem|certificate_der|raw_certificate|raw_der|pem|der)\b\s*[:=]\s*['"]?[^,'"}\]\s]+/gi, "[REDACTED_CERTIFICATE]")
    .replace(/\bPRIVATE KEY\b/gi, "[REDACTED]")
    .replace(/\b(?:openssl|s_client)\b\s+[^\n\r"'}\]]*/gi, "[REDACTED_COMMAND]")
    .replace(/\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "Authorization: [REDACTED]")
    .replace(/\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "[REDACTED]")
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)([^:\s/@;"']+):([^@\s/;"']+)@([^\s;"']+)/gi, "$1[REDACTED]@$4")
    .replace(
      /([?&](?:access_token|refresh_token|id_token|api_key|apikey|key|token|secret|password|passwd|pwd|session|sid|auth|authorization|jwt|bearer|sig|signature|client_secret|code|state)=)[^&#\s]+/gi,
      "$1[REDACTED]"
    )
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[REDACTED_TARGET]")
    .replace(
      /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|local|internal|lan|home|test|invalid)\b/gi,
      "[REDACTED_TARGET]"
    )
    .replace(
      /\b(?:super-secret-password|raw-api-key-[a-z0-9_-]+|token_should_never_render|session_should_not_render|cookie_should_not_render|[a-z0-9._-]*should_(?:never|not)_render[a-z0-9._-]*)\b/gi,
      "[REDACTED]"
    )
    .replace(
      /(^|[\s,{])([A-Z0-9_$.-]*(?:AUTHORIZATION|COOKIE|SET_COOKIE|SESSION|PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|CLIENT_SECRET|CREDENTIAL|AUTH|CLIENT_CERT)[A-Z0-9_$.-]*)(\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2$3$4[REDACTED]"
    )
    .replace(
      /(\b(?:authorization|cookie|set-cookie|session|password|passwd|pwd|secret|token|api_key|apikey|private_key|client_secret|credential|auth|client_certificate|client_certificates)\b\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2[REDACTED]"
    )
    .replace(/\bconfirmed\s+vulnerability\b/gi, "[REDACTED_CLAIM]")
    .replace(/\bexploitable\b/gi, "[REDACTED_CLAIM]")
    .replace(/\btarget\s+is\s+safe\b/gi, "[REDACTED_CLAIM]")
    .replace(/\ball\s+certs\s+found\b/gi, "[REDACTED_CLAIM]")
    .replace(/\bfull\s+scan\b/gi, "[REDACTED_CLAIM]")
    .replace(/\bpublic\s+scanner\b/gi, "[REDACTED_CLAIM]")
    .replace(/\[REDACTED\]\]+/g, "[REDACTED]");
}

function certificateFromRecord(record: Record<string, unknown> | null): ActiveTlsBasicCertificateSummary {
  const sanSample = Array.isArray(record?.san_sample)
    ? record.san_sample.flatMap((item) => {
        const sample = asRecord(item);
        if (!sample) {
          return [];
        }
        const type = safeTlsText(asString(sample.type)) ?? "SAN";
        const value = safeTlsText(asString(sample.value)) ?? "[REDACTED_SAN]";
        return [`${type}: ${value}`];
      })
    : [];

  return {
    available: record?.available === true,
    subject: safeTlsText(asString(record?.subject)),
    issuer: safeTlsText(asString(record?.issuer)),
    sanCount: asNumber(record?.san_count) ?? 0,
    sanSample,
    notBefore: safeTlsText(asString(record?.not_before)),
    notAfter: safeTlsText(asString(record?.not_after)),
    daysUntilExpiry: asNumber(record?.days_until_expiry)
  };
}

function errorsFromValue(value: unknown, jobError: unknown): string[] {
  const errors = [...asStringArray(value), ...(typeof jobError === "string" && jobError.trim() ? [jobError] : [])].map(redactActiveTlsBasicText);
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

function safeTlsText(value: string | null): string | null {
  if (!value) {
    return null;
  }
  return redactActiveTlsBasicText(value).slice(0, 160);
}

function safeHandshakeStatus(value: string | null): string {
  const normalized = value?.trim().toLowerCase() ?? "tls_error_controlled";
  return SAFE_HANDSHAKE_STATUSES.has(normalized) ? normalized : "tls_error_controlled";
}

function normalizeStatus(value: string | null): string {
  if (!value) {
    return "tls_error_controlled";
  }
  const normalized = value.trim().toLowerCase();
  return CONTROLLED_STATUS_LABELS[normalized] ?? "tls_error_controlled";
}

function isTargetKey(key: string): boolean {
  const normalized = normalizeKey(key);
  return [
    "address",
    "addresses",
    "addr",
    "host",
    "hostname",
    "hostnames",
    "ip",
    "ips",
    "normalized_target",
    "raw_target",
    "server_hostname",
    "sni",
    "target",
    "target_domain",
    "target_host",
    "target_url"
  ].includes(normalized);
}

function isSensitiveTlsValueKey(key: string): boolean {
  const normalized = normalizeKey(key);
  if (normalized.includes("redacted") || normalized.endsWith("_count")) {
    return false;
  }
  return [
    "certificate_der",
    "certificate_pem",
    "client_certificate",
    "client_certificates",
    "command",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "exception",
    "header",
    "headers",
    "payload",
    "private_key",
    "raw_certificate",
    "raw_der",
    "raw_exception",
    "raw_payload",
    "raw_pem",
    "stderr",
    "stdout",
    "token",
    "tokens"
  ].includes(normalized);
}

function redactedValueForKey(key: string): string {
  const normalized = normalizeKey(key);
  if (normalized.includes("certificate") || normalized.includes("pem") || normalized.includes("der")) {
    return "[REDACTED_CERTIFICATE]";
  }
  if (normalized === "command") {
    return "[REDACTED_COMMAND]";
  }
  if (normalized === "exception" || normalized === "raw_exception" || normalized === "stderr" || normalized === "stdout") {
    return "[REDACTED_ERROR]";
  }
  if (normalized === "payload" || normalized === "raw_payload") {
    return "[REDACTED_PAYLOAD]";
  }
  return "[REDACTED]";
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? redactActiveTlsBasicText(value.trim()) : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return typeof value === "string" && value.trim() ? [redactActiveTlsBasicText(value)] : [];
  }
  return value
    .map((item) => stringifyValue(item))
    .filter((item) => item.trim().length > 0);
}

function stringifyValue(value: unknown): string {
  if (typeof value === "string") {
    return redactActiveTlsBasicText(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (value === null || value === undefined) {
    return "";
  }
  return redactActiveTlsBasicText(JSON.stringify(value));
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
