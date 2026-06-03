import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type ActiveHttpHeaderProbeListItem = {
  title: string;
  entries: MetadataEntry[];
};

export type ActiveHttpHeaderProbeHeader = {
  name: string;
  value: string;
  truncated: boolean | null;
};

export type ActiveHttpHeaderProbeReport = {
  isActiveHttpHeaderProbe: boolean;
  analyzer: string | null;
  mode: string | null;
  profile: string | null;
  overview: MetadataEntry[];
  target: MetadataEntry[];
  authorization: MetadataEntry[];
  policy: MetadataEntry[];
  dns: MetadataEntry[];
  request: MetadataEntry[];
  response: MetadataEntry[];
  responseHeaders: ActiveHttpHeaderProbeHeader[];
  observations: ActiveHttpHeaderProbeListItem[];
  findings: ActiveHttpHeaderProbeListItem[];
  blockedReasons: ActiveHttpHeaderProbeListItem[];
  auditLog: ActiveHttpHeaderProbeListItem[];
  limits: MetadataEntry[];
  errors: string[];
  rawJson: string;
  allowed: boolean | null;
  networkRequestsSent: number | null;
  bodyBytesRead: number | null;
  redirectsFollowed: number | null;
  isSparse: boolean;
};

export function buildActiveHttpHeaderProbeReport(job: JobRecord): ActiveHttpHeaderProbeReport {
  const result = asRecord(redactActiveHttpHeaderProbeValue(job.result));
  const summary = asRecord(result?.summary);
  const target = asRecord(result?.target);
  const authorization = asRecord(result?.authorization);
  const policy = asRecord(result?.policy);
  const dns = asRecord(result?.dns);
  const request = asRecord(result?.request);
  const response = asRecord(result?.response);
  const responseHeaders = headersFromValue(response?.headers ?? result?.response_headers ?? result?.headers);
  const observations = listItemsFromValue(result?.observations, "Observation");
  const findings = listItemsFromValue(result?.findings, "Finding");
  const blockedReasons = listItemsFromValue(result?.blocked_reasons, "Blocked reason");
  const auditLog = listItemsFromValue(result?.audit_log, "Audit log entry");
  const errors = [...asStringArray(result?.errors), ...(job.error ? [redactActiveHttpHeaderProbeText(job.error)] : [])];
  const allowed = asBoolean(policy?.allowed) ?? asBoolean(summary?.allowed);
  const networkRequestsSent = asNumber(summary?.network_requests_sent) ?? asNumber(request?.network_requests_sent);
  const bodyBytesRead = asNumber(summary?.body_bytes_read) ?? asNumber(response?.body_bytes_read);
  const redirectsFollowed = asNumber(summary?.redirects_followed) ?? asNumber(response?.redirects_followed);
  const isSparse =
    !result ||
    (!target &&
      !policy &&
      !dns &&
      !request &&
      !response &&
      responseHeaders.length === 0 &&
      observations.length === 0 &&
      findings.length === 0 &&
      blockedReasons.length === 0 &&
      auditLog.length === 0);

  return {
    isActiveHttpHeaderProbe: job.audit_type === "active_http_header_probe" || asString(result?.analyzer) === "active_http_header_probe",
    analyzer: asString(result?.analyzer),
    mode: asString(result?.mode),
    profile: asString(result?.profile),
    overview: [
      { label: "Mode", value: asString(result?.mode) ?? "live_header_probe" },
      { label: "Profile", value: asString(result?.profile) ?? "http_header_probe" },
      { label: "Policy allowed", value: allowed === null ? "Not available" : String(allowed) },
      { label: "Network requests sent", value: networkRequestsSent === null ? "0" : String(networkRequestsSent) },
      { label: "Body bytes read", value: bodyBytesRead === null ? "0" : String(bodyBytesRead) },
      { label: "Redirects followed", value: redirectsFollowed === null ? "0" : String(redirectsFollowed) },
      { label: "Response headers", value: String(responseHeaders.length) }
    ],
    target: entriesFromRecord(target),
    authorization: entriesFromRecord(authorization),
    policy: entriesFromRecord(policy),
    dns: entriesFromRecord(dns),
    request: entriesFromRecord(request),
    response: entriesFromRecord(omitKeys(response, ["headers"])),
    responseHeaders,
    observations,
    findings,
    blockedReasons,
    auditLog,
    limits: entriesFromRecord(asRecord(result?.limits)),
    errors,
    rawJson: JSON.stringify(redactActiveHttpHeaderProbeValue(job), null, 2),
    allowed,
    networkRequestsSent,
    bodyBytesRead,
    redirectsFollowed,
    isSparse
  };
}

export function redactActiveHttpHeaderProbeValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactActiveHttpHeaderProbeText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactActiveHttpHeaderProbeValue(item));
  }
  const record = asRecord(value);
  if (record) {
    const recordHasSecretName = activeHttpRecordHasSecretName(record);
    return Object.fromEntries(
      Object.entries(record).map(([key, item]) => {
        const normalizedKey = normalizeKey(key);
        const redactValue =
          isActiveHttpSecretValueKey(key) ||
          (recordHasSecretName &&
            ["value", "raw_value", "default", "data", "content", "header_value", "authorization", "location"].includes(normalizedKey));
        return [key, redactValue ? "[REDACTED]" : redactActiveHttpHeaderProbeValue(item)];
      })
    );
  }
  return value;
}

export function redactActiveHttpHeaderProbeText(value: string): string {
  return value
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi, "[REDACTED]")
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----/gi, "[REDACTED]")
    .replace(/\bPRIVATE KEY\b/gi, "[REDACTED]")
    .replace(/\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "Authorization: [REDACTED]")
    .replace(/\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "[REDACTED]")
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)([^:\s/@;"']+):([^@\s/;"']+)@([^\s;"']+)/gi, "$1[REDACTED]@$4")
    .replace(
      /([?&](?:access_token|refresh_token|id_token|api_key|apikey|key|token|secret|password|passwd|pwd|session|sid|auth|authorization|jwt|bearer|sig|signature|client_secret|code|state)=)[^&#\s]+/gi,
      "$1[REDACTED]"
    )
    .replace(
      /\b(?:super-secret-password|raw-api-key-[a-z0-9_-]+|token_should_never_render|session_should_not_render|cookie_should_not_render|[a-z0-9._-]*should_(?:never|not)_render[a-z0-9._-]*)\b/gi,
      "[REDACTED]"
    )
    .replace(
      /(^|[\s,{])([A-Z0-9_$.-]*(?:AUTHORIZATION|COOKIE|SET_COOKIE|SESSION|PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|CLIENT_SECRET|CREDENTIAL|AUTH)[A-Z0-9_$.-]*)(\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2$3$4[REDACTED]"
    )
    .replace(
      /(\b(?:authorization|cookie|set-cookie|session|password|passwd|pwd|secret|token|api_key|apikey|private_key|client_secret|credential|auth)\b\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2[REDACTED]"
    )
    .replace(/\[REDACTED\]\]+/g, "[REDACTED]");
}

function headersFromValue(value: unknown): ActiveHttpHeaderProbeHeader[] {
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => {
      const record = asRecord(item);
      if (!record) {
        return [{ name: `header_${index + 1}`, value: stringifyValue(item), truncated: null }];
      }
      const name = asString(record.name) ?? asString(record.header) ?? asString(record.key) ?? `header_${index + 1}`;
      const headerNameSecret = isActiveHttpSecretValueKey(name);
      return [
        {
          name,
          value: headerNameSecret ? "[REDACTED]" : stringifyValue(record.value ?? record.header_value ?? record.data ?? record.raw_value ?? ""),
          truncated: asBoolean(record.truncated)
        }
      ];
    });
  }
  const record = asRecord(value);
  if (record) {
    return Object.entries(record).map(([name, item]) => ({
      name: redactActiveHttpHeaderProbeText(name),
      value: isActiveHttpSecretValueKey(name) ? "[REDACTED]" : stringifyValue(item),
      truncated: null
    }));
  }
  return [];
}

function listItemsFromValue(value: unknown, fallbackTitle: string): ActiveHttpHeaderProbeListItem[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item, index) => {
    const record = asRecord(item);
    if (!record) {
      return {
        title: `${fallbackTitle} ${index + 1}`,
        entries: [{ label: "value", value: stringifyValue(item) }]
      };
    }
    return {
      title:
        asString(record.code) ??
        asString(record.id) ??
        asString(record.name) ??
        asString(record.title) ??
        asString(record.event) ??
        `${fallbackTitle} ${index + 1}`,
      entries: entriesFromRecord(record)
    };
  });
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

function activeHttpRecordHasSecretName(record: Record<string, unknown>): boolean {
  for (const marker of ["key", "name", "setting", "variable", "field_path", "header", "target", "raw", "url"]) {
    const candidate = record[marker];
    if (typeof candidate === "string" && isActiveHttpSecretValueKey(candidate)) {
      return true;
    }
  }
  return false;
}

function isActiveHttpSecretValueKey(key: string): boolean {
  const normalized = normalizeKey(key);
  if (normalized.includes("redacted") || normalized.endsWith("_count")) {
    return false;
  }
  return [
    "authorization",
    "proxy_authorization",
    "set_cookie",
    "cookie",
    "bearer",
    "basic",
    "session",
    "access_token",
    "refresh_token",
    "id_token",
    "auth_token",
    "client_secret",
    "private_key",
    "api_key",
    "apikey",
    "password",
    "passwd",
    "pwd",
    "credential",
    "secret",
    "token"
  ].some((token) => normalized.includes(token));
}

function omitKeys(record: Record<string, unknown> | null, keys: string[]): Record<string, unknown> | null {
  if (!record) {
    return null;
  }
  return Object.fromEntries(Object.entries(record).filter(([key]) => !keys.includes(key)));
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? redactActiveHttpHeaderProbeText(value) : null;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && item.trim().length > 0).map(redactActiveHttpHeaderProbeText)
    : [];
}

function asNumber(value: unknown): number | null {
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function stringifyValue(value: unknown): string {
  if (typeof value === "string") {
    return redactActiveHttpHeaderProbeText(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return redactActiveHttpHeaderProbeText(JSON.stringify(value));
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[-.\s]/g, "_");
}
