import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type ActiveNmapBasicPortObservation = {
  port: number;
  protocol: string;
  state: string;
  reason: string | null;
  indicator: string;
};

export type ActiveNmapBasicReport = {
  isActiveNmapBasic: boolean;
  status: string;
  lifecycleState: string | null;
  mode: string | null;
  profile: string | null;
  overview: MetadataEntry[];
  observations: ActiveNmapBasicPortObservation[];
  noLiveCaveats: string[];
  limits: MetadataEntry[];
  warnings: string[];
  errors: string[];
  rawJson: string;
  outputTruncated: boolean;
  stderrTruncated: boolean;
  timedOut: boolean;
  isSparse: boolean;
  isNoLiveLifecycle: boolean;
};

const SAFE_PORT_STATES = new Set([
  "closed",
  "closed|filtered",
  "filtered",
  "open",
  "open|filtered",
  "unfiltered",
  "unknown"
]);

const SAFE_REASONS = new Set([
  "admin-prohibited",
  "arp-response",
  "conn-refused",
  "echo-reply",
  "host-prohibited",
  "host-unreach",
  "localhost-response",
  "net-prohibited",
  "net-unreach",
  "no-response",
  "no-responses",
  "port-unreach",
  "proto-response",
  "reset",
  "reset-ttl",
  "syn-ack",
  "timestamp-reply",
  "udp-response",
  "user-set"
]);

const CONTROLLED_STATUS_LABELS: Record<string, string> = {
  blocked: "blocked",
  blocked_missing_approval: "blocked_missing_approval",
  blocked_unconfigured: "blocked_unconfigured",
  client_error_controlled: "client_error_controlled",
  completed: "completed",
  completed_no_live: "completed_no_live",
  empty: "no_ports",
  failed: "failed",
  malformed: "malformed",
  nmap_missing: "nmap_missing",
  no_ports: "no_ports",
  not_executed: "not_executed",
  not_implemented: "not_implemented",
  timed_out: "timed_out",
  truncated: "truncated",
  unsafe_client_result: "unsafe_lifecycle_result",
  unsafe_lifecycle_result: "unsafe_lifecycle_result",
  unsupported_shape: "unsupported_shape"
};

const NO_LIVE_LIFECYCLE_STATES = new Set([
  "blocked_unconfigured",
  "blocked_missing_approval",
  "not_executed",
  "client_error_controlled",
  "completed_no_live",
  "unsafe_lifecycle_result"
]);

const DEFAULT_NO_LIVE_CAVEATS = [
  "No Nmap executed.",
  "No network requests.",
  "No DNS queries.",
  "No evidence collected.",
  "No observations available.",
  "Manual validation required."
];

export function buildActiveNmapBasicReport(job: JobRecord): ActiveNmapBasicReport {
  const redactedJob = redactActiveNmapBasicValue(job) as JobRecord;
  const result = asRecord(redactedJob.result);
  const rawResult = asRecord(job.result);
  const limitsRecord = asRecord(result?.limits);
  const lifecycleState = normalizeOptionalStatus(asString(result?.lifecycle_state) ?? asString(rawResult?.lifecycle_state));
  const status = normalizeStatus(
    asString(result?.status) ??
      asString(result?.execution_state) ??
      asString(result?.result_status) ??
      asString(rawResult?.status) ??
      asString(rawResult?.execution_state) ??
      job.status
  );
  const isNoLiveLifecycle =
    (lifecycleState !== null && NO_LIVE_LIFECYCLE_STATES.has(lifecycleState)) ||
    status === "not_executed" ||
    asBoolean(result?.no_live_lifecycle_record) === true ||
    asBoolean(result?.nmap_executed) === false ||
    asBoolean(asRecord(result?.execution)?.nmap_executed) === false;
  const observations = isNoLiveLifecycle ? [] : observationsFromValue(result?.port_observations);
  const outputTruncated =
    asBoolean(result?.output_truncated) ?? asBoolean(limitsRecord?.output_truncated) ?? asBoolean(rawResult?.output_truncated) ?? false;
  const stderrTruncated =
    asBoolean(result?.stderr_truncated) ?? asBoolean(limitsRecord?.stderr_truncated) ?? asBoolean(rawResult?.stderr_truncated) ?? false;
  const timedOut = asBoolean(result?.timed_out) ?? asBoolean(limitsRecord?.timed_out) ?? status === "timed_out";
  const warnings = [
    ...asStringArray(result?.parser_warnings),
    ...asStringArray(result?.warnings),
    ...(outputTruncated ? ["output_truncated"] : []),
    ...(stderrTruncated ? ["stderr_truncated"] : []),
    ...(timedOut ? ["timed_out"] : [])
  ].map(redactActiveNmapBasicText);
  const errors = errorsFromValue(result?.errors, redactedJob.error);
  const mode = asString(result?.mode) ?? asString(rawResult?.mode);
  const profile = asString(result?.profile) ?? asString(rawResult?.profile);
  const observationCount = isNoLiveLifecycle
    ? 0
    : asNumber(result?.observation_count) ?? asNumber(asRecord(result?.summary)?.observation_count) ?? observations.length;
  const openObservationCount = observations.filter((item) => item.state === "open").length;
  const isSparse = !result || (observations.length === 0 && entriesFromRecord(limitsRecord).length === 0 && warnings.length === 0 && errors.length === 0);
  const noLiveCaveats = isNoLiveLifecycle ? caveatsFromValue(result?.surface_caveats) : [];

  return {
    isActiveNmapBasic:
      job.audit_type === "active_nmap_basic" ||
      asString(rawResult?.capability) === "active_nmap_basic" ||
      asString(rawResult?.audit_type) === "active_nmap_basic",
    status,
    lifecycleState,
    mode,
    profile,
    overview: [
      { label: "Mode", value: mode ?? "live_nmap_basic" },
      { label: "Profile", value: profile ?? "tcp_connect_small" },
      { label: "Result status", value: status },
      ...(lifecycleState ? [{ label: "Lifecycle state", value: lifecycleState }] : []),
      { label: "Port observations", value: String(observationCount) },
      { label: "Open TCP observations", value: String(openObservationCount) },
      { label: "Output truncated", value: String(outputTruncated) },
      { label: "Timed out", value: String(timedOut) }
    ],
    observations,
    noLiveCaveats,
    limits: entriesFromRecord(limitsRecord),
    warnings: dedupeStrings(warnings),
    errors,
    rawJson: JSON.stringify(redactActiveNmapBasicValue(job), null, 2),
    outputTruncated,
    stderrTruncated,
    timedOut,
    isSparse,
    isNoLiveLifecycle
  };
}

export function redactActiveNmapBasicValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactActiveNmapBasicText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactActiveNmapBasicValue(item));
  }
  const record = asRecord(value);
  if (record) {
    return Object.fromEntries(
      Object.entries(record).map(([key, item]) => {
        if (isTargetKey(key)) {
          return [key, item === null || item === undefined || item === "" ? item : "[REDACTED_TARGET]"];
        }
        if (isSensitiveNmapValueKey(key)) {
          return [key, item === null || item === undefined || item === "" ? item : redactedValueForKey(key)];
        }
        return [key, redactActiveNmapBasicValue(item)];
      })
    );
  }
  return value;
}

export function redactActiveNmapBasicText(value: string): string {
  return value
    .replace(/<\?xml[\s\S]*?<\/nmaprun>/gi, "[REDACTED_XML]")
    .replace(/<nmaprun[\s\S]*?<\/nmaprun>/gi, "[REDACTED_XML]")
    .replace(/<nmaprun[\s\S]*/gi, "[REDACTED_XML]")
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi, "[REDACTED]")
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----/gi, "[REDACTED]")
    .replace(/\bPRIVATE KEY\b/gi, "[REDACTED]")
    .replace(/\bnmap(?:\.exe)?\b\s+[^\n\r"'}\]]*/gi, "[REDACTED_COMMAND]")
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
      /(^|[\s,{])([A-Z0-9_$.-]*(?:AUTHORIZATION|COOKIE|SET_COOKIE|SESSION|PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|CLIENT_SECRET|CREDENTIAL|AUTH)[A-Z0-9_$.-]*)(\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2$3$4[REDACTED]"
    )
    .replace(
      /(\b(?:authorization|cookie|set-cookie|session|password|passwd|pwd|secret|token|api_key|apikey|private_key|client_secret|credential|auth)\b\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2[REDACTED]"
    )
    .replace(/\bconfirmed vulnerability\b/gi, "[REDACTED_CLAIM]")
    .replace(/\bexploitable\b/gi, "[REDACTED_CLAIM]")
    .replace(/\btarget is safe\b/gi, "[REDACTED_CLAIM]")
    .replace(/\ball ports found\b/gi, "[REDACTED_CLAIM]")
    .replace(/\bfull network scan\b/gi, "[REDACTED_CLAIM]")
    .replace(/\bscan the internet\b/gi, "[REDACTED_CLAIM]")
    .replace(/\[REDACTED\]\]+/g, "[REDACTED]");
}

function observationsFromValue(value: unknown): ActiveNmapBasicPortObservation[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.flatMap((item) => {
    const record = asRecord(item);
    if (!record) {
      return [];
    }
    const port = asNumber(record.port);
    if (port === null || port < 1 || port > 65535) {
      return [];
    }
    const protocol = normalizeProtocol(asString(record.protocol));
    const state = normalizeState(asString(record.state));
    const reason = safeReason(asString(record.reason));
    return [
      {
        port,
        protocol,
        state,
        reason,
        indicator: indicatorForState(state)
      }
    ];
  });
}

function errorsFromValue(value: unknown, jobError: unknown): string[] {
  const errors = [...asStringArray(value), ...(typeof jobError === "string" && jobError.trim() ? [jobError] : [])].map(redactActiveNmapBasicText);
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
    "target",
    "target_domain",
    "target_host",
    "target_url"
  ].includes(normalized);
}

function isSensitiveNmapValueKey(key: string): boolean {
  const normalized = normalizeKey(key);
  if (normalized.includes("redacted") || normalized.endsWith("_count")) {
    return false;
  }
  return [
    "args",
    "argv",
    "argv_preview",
    "authorization",
    "banner",
    "command",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "error",
    "errors",
    "header",
    "headers",
    "input_payload",
    "observation",
    "payload",
    "raw_evidence",
    "raw_command",
    "request_payload",
    "raw_output",
    "raw_xml",
    "service",
    "service_banner",
    "service_name",
    "stderr",
    "stdout",
    "token",
    "tokens",
    "xml"
  ].includes(normalized);
}

function redactedValueForKey(key: string): string {
  const normalized = normalizeKey(key);
  if (normalized === "raw_xml" || normalized === "xml") {
    return "[REDACTED_XML]";
  }
  if (normalized === "command" || normalized === "raw_command" || normalized === "argv" || normalized === "argv_preview" || normalized === "args") {
    return "[REDACTED_COMMAND]";
  }
  if (normalized === "error" || normalized === "errors" || normalized === "stderr" || normalized === "stdout") {
    return "[REDACTED_ERROR]";
  }
  if (normalized === "payload" || normalized === "input_payload" || normalized === "request_payload") {
    return "[REDACTED_PAYLOAD]";
  }
  if (normalized === "observation" || normalized === "raw_evidence") {
    return "[REDACTED_EVIDENCE]";
  }
  return "[REDACTED]";
}

function normalizeStatus(value: string | null): string {
  if (!value) {
    return "unknown";
  }
  const normalized = value.trim().toLowerCase();
  return CONTROLLED_STATUS_LABELS[normalized] ?? normalized;
}

function normalizeOptionalStatus(value: string | null): string | null {
  return value ? normalizeStatus(value) : null;
}

function normalizeProtocol(value: string | null): string {
  return value?.toLowerCase() === "tcp" ? "tcp" : "tcp";
}

function normalizeState(value: string | null): string {
  const normalized = value?.trim().toLowerCase() ?? "";
  return SAFE_PORT_STATES.has(normalized) ? normalized : "unknown";
}

function safeReason(value: string | null): string | null {
  const normalized = value?.trim().toLowerCase() ?? "";
  return SAFE_REASONS.has(normalized) ? normalized : null;
}

function indicatorForState(state: string): string {
  if (state === "open") {
    return "Observed TCP exposure / Review indicator";
  }
  if (state === "closed" || state === "filtered" || state === "closed|filtered") {
    return "Conservative TCP state / Review indicator";
  }
  return "TCP observation / Review indicator";
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? redactActiveNmapBasicText(value) : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return typeof value === "string" && value.trim() ? [value] : [];
  }
  return value
    .map((item) => stringifyValue(item))
    .filter((item) => item.trim().length > 0);
}

function caveatsFromValue(value: unknown): string[] {
  const backendCaveats = asStringArray(value);
  return dedupeStrings([...DEFAULT_NO_LIVE_CAVEATS, ...backendCaveats.map(redactActiveNmapBasicText)]);
}

function stringifyValue(value: unknown): string {
  if (typeof value === "string") {
    return redactActiveNmapBasicText(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (value === null || value === undefined) {
    return "";
  }
  return redactActiveNmapBasicText(JSON.stringify(value));
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
