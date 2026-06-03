import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type ActiveDryRunListItem = {
  title: string;
  entries: MetadataEntry[];
};

export type ActiveDryRunReport = {
  isActiveDryRun: boolean;
  analyzer: string | null;
  mode: string | null;
  profile: string | null;
  overview: MetadataEntry[];
  target: MetadataEntry[];
  authorization: MetadataEntry[];
  policy: MetadataEntry[];
  limits: MetadataEntry[];
  plannedChecks: ActiveDryRunListItem[];
  blockedReasons: ActiveDryRunListItem[];
  auditLog: ActiveDryRunListItem[];
  errors: string[];
  rawJson: string;
  allowed: boolean | null;
  networkRequestsSent: number | null;
  plannedChecksCount: number;
  blockedReasonsCount: number;
  isSparse: boolean;
};

export function buildActiveDryRunReport(job: JobRecord): ActiveDryRunReport {
  const result = asRecord(redactActiveDryRunValue(job.result));
  const summary = asRecord(result?.summary);
  const target = asRecord(result?.target);
  const authorization = asRecord(result?.authorization);
  const policy = asRecord(result?.policy);
  const plannedChecks = listItemsFromValue(result?.planned_checks, "Planned check");
  const blockedReasons = listItemsFromValue(result?.blocked_reasons, "Blocked reason");
  const auditLog = listItemsFromValue(result?.audit_log, "Audit log entry");
  const errors = [...asStringArray(result?.errors), ...(job.error ? [redactActiveDryRunText(job.error)] : [])];
  const allowed = asBoolean(policy?.allowed) ?? asBoolean(summary?.allowed);
  const networkRequestsSent = asNumber(summary?.network_requests_sent);
  const plannedChecksCount = asNumber(summary?.planned_checks_count) ?? plannedChecks.length;
  const blockedReasonsCount = asNumber(summary?.blocked_reasons_count) ?? blockedReasons.length;
  const isSparse = !result || (!target && !policy && plannedChecks.length === 0 && blockedReasons.length === 0 && auditLog.length === 0);

  return {
    isActiveDryRun: job.audit_type === "active_network_dry_run" || asString(result?.analyzer) === "active_network_dry_run",
    analyzer: asString(result?.analyzer),
    mode: asString(result?.mode),
    profile: asString(result?.profile),
    overview: [
      { label: "Mode", value: asString(result?.mode) ?? "dry_run" },
      { label: "Profile", value: asString(result?.profile) ?? "http_header_probe_preview" },
      { label: "Policy allowed", value: allowed === null ? "Not available" : String(allowed) },
      { label: "Planned checks", value: String(plannedChecksCount) },
      { label: "Blocked reasons", value: String(blockedReasonsCount) },
      { label: "Network requests sent", value: networkRequestsSent === null ? "0" : String(networkRequestsSent) }
    ],
    target: entriesFromRecord(target),
    authorization: entriesFromRecord(authorization),
    policy: entriesFromRecord(policy),
    limits: entriesFromRecord(asRecord(result?.limits)),
    plannedChecks,
    blockedReasons,
    auditLog,
    errors,
    rawJson: JSON.stringify(redactActiveDryRunValue(job), null, 2),
    allowed,
    networkRequestsSent,
    plannedChecksCount,
    blockedReasonsCount,
    isSparse
  };
}

export function redactActiveDryRunValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactActiveDryRunText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactActiveDryRunValue(item));
  }
  const record = asRecord(value);
  if (record) {
    const recordHasSecretName = activeRecordHasSecretName(record);
    return Object.fromEntries(
      Object.entries(record).map(([key, item]) => {
        const normalizedKey = normalizeKey(key);
        const redactValue =
          isActiveSecretValueKey(key) ||
          (recordHasSecretName && ["value", "raw_value", "default", "data", "content", "header_value", "authorization"].includes(normalizedKey));
        return [key, redactValue ? "[REDACTED]" : redactActiveDryRunValue(item)];
      })
    );
  }
  return value;
}

export function redactActiveDryRunText(value: string): string {
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
      /\b(?:super-secret-password|raw-api-key-[a-z0-9_-]+|token_should_never_render|[a-z0-9._-]*should_(?:never|not)_render[a-z0-9._-]*)\b/gi,
      "[REDACTED]"
    )
    .replace(
      /(^|[\s,{])([A-Z0-9_$.-]*(?:AUTHORIZATION|COOKIE|SESSION|PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|CLIENT_SECRET|CREDENTIAL|AUTH)[A-Z0-9_$.-]*)(\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2$3$4[REDACTED]"
    )
    .replace(
      /(\b(?:authorization|cookie|session|password|passwd|pwd|secret|token|api_key|apikey|private_key|client_secret|credential|auth)\b\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2[REDACTED]"
    )
    .replace(/\[REDACTED\]\]+/g, "[REDACTED]");
}

function activeRecordHasSecretName(record: Record<string, unknown>): boolean {
  for (const marker of ["key", "name", "setting", "variable", "field_path", "header", "target", "raw", "url"]) {
    const candidate = record[marker];
    if (typeof candidate === "string" && isActiveSecretValueKey(candidate)) {
      return true;
    }
  }
  return false;
}

function isActiveSecretValueKey(key: string): boolean {
  const normalized = normalizeKey(key);
  if (normalized === "authorization" || normalized.includes("redacted") || normalized.endsWith("_count")) {
    return false;
  }
  return [
    "authorization_header",
    "bearer",
    "cookie",
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

function listItemsFromValue(value: unknown, fallbackTitle: string): ActiveDryRunListItem[] {
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
        asString(record.name) ??
        asString(record.id) ??
        asString(record.check) ??
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

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? redactActiveDryRunText(value) : null;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && item.trim().length > 0).map(redactActiveDryRunText)
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
    return redactActiveDryRunText(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return redactActiveDryRunText(JSON.stringify(value));
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[-.]/g, "_");
}
