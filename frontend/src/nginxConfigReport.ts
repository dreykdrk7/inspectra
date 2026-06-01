import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type NginxFile = {
  path: string;
  category: string;
  read: boolean;
  skipReason: string | null;
  sizeBytes: number | null;
  bytesRead: number | null;
  context: string | null;
};

export type NginxServer = {
  path: string;
  context: string | null;
  line: number | null;
  serverName: string | null;
  listen: string[];
  tls: boolean | null;
};

export type NginxLocation = {
  path: string;
  context: string | null;
  line: number | null;
  location: string | null;
  serverName: string | null;
};

export type NginxUpstream = {
  path: string;
  context: string | null;
  line: number | null;
  name: string | null;
};

export type NginxInclude = {
  path: string;
  context: string | null;
  line: number | null;
  target: string | null;
  absolute: boolean | null;
  glob: boolean | null;
  resolved: boolean | null;
};

export type NginxDirective = {
  path: string;
  context: string | null;
  line: number | null;
  directive: string | null;
  arguments: string | null;
  blockType: string | null;
  serverName: string | null;
  location: string | null;
  upstream: string | null;
};

export type NginxFinding = {
  id: string;
  title: string;
  level: string;
  confidence: string | null;
  category: string | null;
  description: string;
  evidence: string;
  recommendation: string;
  filePath: string | null;
  context: string | null;
  blockType: string | null;
  serverName: string | null;
  location: string | null;
  upstream: string | null;
  directive: string | null;
  line: number | null;
};

export type NginxFindingGroup = {
  level: string;
  findings: NginxFinding[];
};

export type NginxConfigAuditReport = {
  isNginxConfigAudit: boolean;
  analyzer: string | null;
  archiveType: string | null;
  overview: MetadataEntry[];
  summary: MetadataEntry[];
  limits: MetadataEntry[];
  detectedFiles: NginxFile[];
  reviewedFiles: NginxFile[];
  servers: NginxServer[];
  locations: NginxLocation[];
  upstreams: NginxUpstream[];
  includes: NginxInclude[];
  directives: NginxDirective[];
  findings: NginxFinding[];
  findingGroups: NginxFindingGroup[];
  redactionNotes: string[];
  errors: string[];
  truncated: boolean;
  filesConsideredCount: number;
  filesReviewedCount: number;
  nginxFilesDetectedCount: number;
  serverBlocksDetectedCount: number;
  locationBlocksDetectedCount: number;
  upstreamBlocksDetectedCount: number;
  includesDetectedCount: number;
  tlsServersDetectedCount: number;
  findingsCount: number;
  redactedValuesCount: number;
};

export function buildNginxConfigAuditReport(job: JobRecord): NginxConfigAuditReport {
  const result = asRecord(redactNginxConfigValue(job.result));
  const summary = asRecord(result?.summary);
  const detectedFiles = filesFromValue(result?.files_detected);
  const reviewedFiles = reviewedFilesFromValues(result?.files_reviewed, detectedFiles);
  const servers = serversFromValue(result?.servers);
  const locations = locationsFromValue(result?.locations);
  const upstreams = upstreamsFromValue(result?.upstreams);
  const includes = includesFromValue(result?.includes);
  const directives = directivesFromValue(result?.directives);
  const findings = findingsFromValue(result?.findings);
  const filesConsideredCount = asNumber(summary?.files_considered) ?? detectedFiles.length;
  const filesReviewedCount = asNumber(summary?.files_reviewed) ?? reviewedFiles.length;
  const nginxFilesDetectedCount = asNumber(summary?.nginx_files_detected) ?? detectedFiles.length;
  const serverBlocksDetectedCount = asNumber(summary?.server_blocks_detected) ?? servers.length;
  const locationBlocksDetectedCount = asNumber(summary?.location_blocks_detected) ?? locations.length;
  const upstreamBlocksDetectedCount = asNumber(summary?.upstream_blocks_detected) ?? upstreams.length;
  const includesDetectedCount = asNumber(summary?.includes_detected) ?? includes.length;
  const tlsServersDetectedCount = asNumber(summary?.tls_servers_detected) ?? servers.filter((server) => server.tls).length;
  const findingsCount = asNumber(summary?.findings_count) ?? findings.length;
  const redactedValuesCount = asNumber(summary?.redacted_values_count) ?? 0;
  const truncated = Boolean(summary?.truncated) || Boolean(result?.truncated);
  const errors = asStringArray(result?.errors).map(redactNginxConfigText);
  const reportStatus = truncated ? `${job.status} (truncated)` : errors.length > 0 ? `${job.status} with errors` : job.status;

  return {
    isNginxConfigAudit: job.audit_type === "nginx_config_basic" || asString(result?.analyzer) === "nginx_config_basic",
    analyzer: asString(result?.analyzer),
    archiveType: asString(result?.archive_type),
    overview: [
      { label: "Files reviewed", value: String(filesReviewedCount) },
      { label: "Servers", value: String(serverBlocksDetectedCount) },
      { label: "Locations", value: String(locationBlocksDetectedCount) },
      { label: "Upstreams", value: String(upstreamBlocksDetectedCount) },
      { label: "Includes", value: String(includesDetectedCount) },
      { label: "Findings", value: String(findingsCount) },
      { label: "Status", value: reportStatus }
    ],
    summary: entriesFromRecord(summary),
    limits: entriesFromRecord(asRecord(result?.limits)),
    detectedFiles,
    reviewedFiles,
    servers,
    locations,
    upstreams,
    includes,
    directives,
    findings,
    findingGroups: groupFindingsByLevel(findings),
    redactionNotes: asStringArray(result?.redaction_notes).map(redactNginxConfigText),
    errors,
    truncated,
    filesConsideredCount,
    filesReviewedCount,
    nginxFilesDetectedCount,
    serverBlocksDetectedCount,
    locationBlocksDetectedCount,
    upstreamBlocksDetectedCount,
    includesDetectedCount,
    tlsServersDetectedCount,
    findingsCount,
    redactedValuesCount
  };
}

export function redactNginxConfigValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactNginxConfigText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactNginxConfigValue(item));
  }
  const record = asRecord(value);
  if (record) {
    const recordHasSecretName = nginxRecordHasSecretName(record);
    return Object.fromEntries(
      Object.entries(record).map(([key, item]) => {
        const normalizedKey = key.toLowerCase().replace(/-/g, "_");
        const redactValue =
          isNginxSecretValueKey(key) ||
          (recordHasSecretName &&
            ["value", "raw_value", "default", "data", "content", "arguments", "header_value", "variable_value", "map_value"].includes(normalizedKey));
        return [key, redactValue ? "[REDACTED]" : redactNginxConfigValue(item)];
      })
    );
  }
  return value;
}

export function redactNginxConfigText(value: string): string {
  return value
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi, "[REDACTED]")
    .replace(/\bPRIVATE KEY\b/gi, "[REDACTED]")
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)([^:@/\s;'"<>]+):([^@\s;'"<>]+)@/gi, "$1[REDACTED]@")
    .replace(/\b(?:[a-z0-9._-]*user|username|login):(?:[a-z0-9._-]*(?:pass|password|secret|token|key)[a-z0-9._-]*)\b/gi, "[REDACTED]")
    .replace(/\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "Authorization: [REDACTED]")
    .replace(/\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "[REDACTED]")
    .replace(
      /([?&](?:access_token|refresh_token|id_token|api_key|apikey|key|token|secret|password|passwd|pwd|session|sid|auth|authorization|jwt|bearer|sig|signature|client_secret|code|state)=)[^&#\s]+/gi,
      "$1[REDACTED]"
    )
    .replace(
      /(\b(?:proxy_set_header|add_header|set)\s+[$A-Za-z0-9_-]*(?:authorization|cookie|session|secret|token|api[_-]?key|client[_-]?secret|password|passwd|private[_-]?key|credential|auth)[$A-Za-z0-9_-]*\s+)[^;\n]+/gi,
      "$1[REDACTED]"
    )
    .replace(
      /(^|[\s,{])([A-Z0-9_$.-]*(?:AUTHORIZATION|COOKIE|SESSION|SECRET|TOKEN|PASSWORD|PASS|API_KEY|APIKEY|PRIVATE_KEY|CLIENT_SECRET|CREDENTIAL|AUTH)[A-Z0-9_$.-]*)(\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2$3$4[REDACTED]"
    )
    .replace(
      /(\b(?:authorization|cookie|session|password|passwd|token|secret|api_key|apikey|private_key|client_secret|credential|auth)\b\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2[REDACTED]"
    )
    .replace(/\[REDACTED\]\]+/g, "[REDACTED]");
}

function nginxRecordHasSecretName(record: Record<string, unknown>): boolean {
  for (const marker of ["key", "name", "setting", "variable", "header", "directive", "arguments", "field_path"]) {
    const candidate = record[marker];
    if (typeof candidate === "string" && isNginxSecretValueKey(candidate)) {
      return true;
    }
  }
  return false;
}

function isNginxSecretValueKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/-/g, "_");
  if (normalized.includes("redacted") || normalized.endsWith("_count")) {
    return false;
  }
  if (["content", "raw", "raw_content", "certificate_content", "key_content", "private_key_content"].includes(normalized)) {
    return true;
  }
  if (["proxy_pass", "pass_proxy", "passwords"].includes(normalized)) {
    return false;
  }
  return [
    "authorization",
    "cookie",
    "session",
    "api_key",
    "apikey",
    "token",
    "client_secret",
    "private_key",
    "password",
    "passwd",
    "secret",
    "credential",
    "auth"
  ].some((token) => normalized.includes(token));
}

function filesFromValue(value: unknown): NginxFile[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      category: asString(record?.category) ?? "unknown",
      read: asBoolean(record?.read) ?? false,
      skipReason: asString(record?.skip_reason),
      sizeBytes: asNumber(record?.size_bytes),
      bytesRead: asNumber(record?.bytes_read),
      context: asString(record?.context)
    };
  });
}

function reviewedFilesFromValues(value: unknown, detectedFiles: NginxFile[]): NginxFile[] {
  if (Array.isArray(value)) {
    return filesFromValue(value).map((item) => ({ ...item, read: true }));
  }
  return detectedFiles.filter((item) => item.read);
}

function serversFromValue(value: unknown): NginxServer[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      context: asString(record?.context),
      line: asNumber(record?.line),
      serverName: asString(record?.server_name),
      listen: asStringArray(record?.listen),
      tls: asBoolean(record?.tls)
    };
  });
}

function locationsFromValue(value: unknown): NginxLocation[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      context: asString(record?.context),
      line: asNumber(record?.line),
      location: asString(record?.location) ?? asString(record?.path_pattern),
      serverName: asString(record?.server_name)
    };
  });
}

function upstreamsFromValue(value: unknown): NginxUpstream[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      context: asString(record?.context),
      line: asNumber(record?.line),
      name: asString(record?.name) ?? asString(record?.upstream)
    };
  });
}

function includesFromValue(value: unknown): NginxInclude[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      context: asString(record?.context),
      line: asNumber(record?.line),
      target: asString(record?.target) ?? asString(record?.include),
      absolute: asBoolean(record?.absolute),
      glob: asBoolean(record?.glob),
      resolved: asBoolean(record?.resolved)
    };
  });
}

function directivesFromValue(value: unknown): NginxDirective[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      context: asString(record?.context),
      line: asNumber(record?.line),
      directive: asString(record?.directive),
      arguments: asString(record?.arguments) ?? asString(record?.args),
      blockType: asString(record?.block_type),
      serverName: asString(record?.server_name),
      location: asString(record?.location),
      upstream: asString(record?.upstream)
    };
  });
}

function findingsFromValue(value: unknown): NginxFinding[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      id: asString(record?.id) ?? asString(record?.code) ?? "finding",
      title: asString(record?.title) ?? asString(record?.message) ?? "Nginx config finding",
      level: normalizeFindingLevel(asString(record?.level) ?? asString(record?.severity)),
      confidence: normalizeConfidence(asString(record?.confidence)),
      category: asString(record?.category),
      description: asString(record?.description) ?? "",
      evidence: asString(record?.evidence) ?? "",
      recommendation: asString(record?.recommendation) ?? "",
      filePath: asString(record?.file_path),
      context: asString(record?.context),
      blockType: asString(record?.block_type),
      serverName: asString(record?.server_name),
      location: asString(record?.location),
      upstream: asString(record?.upstream),
      directive: asString(record?.directive),
      line: asNumber(record?.line)
    };
  });
}

function groupFindingsByLevel(findings: NginxFinding[]): NginxFindingGroup[] {
  const order = ["critical", "high", "medium", "low", "info", "review", "unknown"];
  const groups = new Map<string, NginxFinding[]>();
  findings.forEach((finding) => {
    const level = normalizeFindingLevel(finding.level);
    const existing = groups.get(level) ?? [];
    existing.push(finding);
    groups.set(level, existing);
  });
  return order.filter((level) => groups.has(level)).map((level) => ({ level, findings: groups.get(level) ?? [] }));
}

function normalizeFindingLevel(value: string | null): string {
  const normalized = value?.toLowerCase().trim();
  if (normalized && ["critical", "high", "medium", "low", "info", "review"].includes(normalized)) {
    return normalized;
  }
  return "unknown";
}

function normalizeConfidence(value: string | null): string | null {
  const normalized = value?.toLowerCase().trim();
  if (normalized && ["high", "medium", "low"].includes(normalized)) {
    return normalized;
  }
  return normalized ? "unknown" : null;
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
  return typeof value === "string" && value.trim() ? redactNginxConfigText(value) : null;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.trim().length > 0).map(redactNginxConfigText) : [];
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
    return redactNginxConfigText(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return redactNginxConfigText(JSON.stringify(value));
}
