import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type RedisFile = {
  path: string;
  category: string;
  read: boolean;
  skipReason: string | null;
  sizeBytes: number | null;
  bytesRead: number | null;
  context: string | null;
  configType: string | null;
};

export type RedisConfigFile = {
  path: string;
  configType: string | null;
  context: string | null;
};

export type RedisSetting = {
  configType: string | null;
  directive: string | null;
  setting: string | null;
  value: string | null;
  filePath: string;
  context: string | null;
  line: number | null;
};

export type RedisInclude = {
  directive: string | null;
  target: string | null;
  resolved: boolean | null;
  filePath: string;
  configType: string | null;
  context: string | null;
  line: number | null;
};

export type RedisSensitiveFile = {
  path: string;
  category: string;
  read: boolean | null;
  skipReason: string | null;
  sizeBytes: number | null;
  context: string | null;
};

export type RedisFinding = {
  id: string;
  title: string;
  level: string;
  confidence: string | null;
  category: string | null;
  context: string | null;
  configType: string | null;
  directive: string | null;
  setting: string | null;
  address: string | null;
  port: string | null;
  path: string | null;
  filePath: string | null;
  line: number | null;
  description: string;
  evidence: string;
  recommendation: string;
};

export type RedisFindingGroup = {
  level: string;
  findings: RedisFinding[];
};

export type RedisConfigAuditReport = {
  isRedisConfigAudit: boolean;
  analyzer: string | null;
  archiveType: string | null;
  overview: MetadataEntry[];
  summary: MetadataEntry[];
  limits: MetadataEntry[];
  detectedFiles: RedisFile[];
  reviewedFiles: RedisFile[];
  configs: RedisConfigFile[];
  redisSettings: RedisSetting[];
  sentinelSettings: RedisSetting[];
  includes: RedisInclude[];
  aclFiles: RedisSensitiveFile[];
  dumpOrAofFiles: RedisSensitiveFile[];
  findings: RedisFinding[];
  findingGroups: RedisFindingGroup[];
  redactionNotes: string[];
  errors: string[];
  truncated: boolean;
  filesConsideredCount: number;
  filesReviewedCount: number;
  redisFilesDetectedCount: number;
  sentinelFilesDetectedCount: number;
  aclFilesDetectedCount: number;
  dumpOrAofFilesDetectedCount: number;
  configsDetectedCount: number;
  findingsCount: number;
  redactedValuesCount: number;
};

export function buildRedisConfigAuditReport(job: JobRecord): RedisConfigAuditReport {
  const result = asRecord(redactRedisConfigValue(job.result));
  const summary = asRecord(result?.summary);
  const detectedFiles = filesFromValue(result?.files_detected);
  const reviewedFiles = reviewedFilesFromValues(result?.files_reviewed, detectedFiles);
  const configs = configsFromValue(result?.configs);
  const redisSettings = settingsFromValue(result?.redis_settings);
  const sentinelSettings = settingsFromValue(result?.sentinel_settings);
  const includes = includesFromValue(result?.includes);
  const aclFiles = sensitiveFilesFromValue(result?.acl_files);
  const dumpOrAofFiles = sensitiveFilesFromValue(result?.dump_or_aof_files);
  const findings = findingsFromValue(result?.findings);
  const filesConsideredCount = asNumber(summary?.files_considered) ?? detectedFiles.length;
  const filesReviewedCount = asNumber(summary?.files_reviewed) ?? reviewedFiles.length;
  const redisFilesDetectedCount = asNumber(summary?.redis_files_detected) ?? detectedFiles.filter((file) => file.category.includes("redis")).length;
  const sentinelFilesDetectedCount = asNumber(summary?.sentinel_files_detected) ?? detectedFiles.filter((file) => file.category.includes("sentinel")).length;
  const aclFilesDetectedCount = asNumber(summary?.acl_files_detected) ?? aclFiles.length;
  const dumpOrAofFilesDetectedCount = asNumber(summary?.dump_or_aof_files_detected) ?? dumpOrAofFiles.length;
  const configsDetectedCount = asNumber(summary?.configs_detected) ?? configs.length;
  const findingsCount = asNumber(summary?.findings_count) ?? findings.length;
  const redactedValuesCount = asNumber(summary?.redacted_values_count) ?? 0;
  const truncated = Boolean(summary?.truncated) || Boolean(result?.truncated);
  const errors = asStringArray(result?.errors).map(redactRedisConfigText);
  const reportStatus = truncated ? `${job.status} (truncated)` : errors.length > 0 ? `${job.status} with errors` : job.status;

  return {
    isRedisConfigAudit: job.audit_type === "redis_config_basic" || asString(result?.analyzer) === "redis_config_basic",
    analyzer: asString(result?.analyzer),
    archiveType: asString(result?.archive_type),
    overview: [
      { label: "Files reviewed", value: String(filesReviewedCount) },
      { label: "Redis configs", value: String(redisFilesDetectedCount) },
      { label: "Sentinel configs", value: String(sentinelFilesDetectedCount) },
      { label: "ACL files", value: String(aclFilesDetectedCount) },
      { label: "Dumps/AOF/backups", value: String(dumpOrAofFilesDetectedCount) },
      { label: "Findings", value: String(findingsCount) },
      { label: "Status", value: reportStatus }
    ],
    summary: entriesFromRecord(summary),
    limits: entriesFromRecord(asRecord(result?.limits)),
    detectedFiles,
    reviewedFiles,
    configs,
    redisSettings,
    sentinelSettings,
    includes,
    aclFiles,
    dumpOrAofFiles,
    findings,
    findingGroups: groupFindingsByLevel(findings),
    redactionNotes: asStringArray(result?.redaction_notes).map(redactRedisConfigText),
    errors,
    truncated,
    filesConsideredCount,
    filesReviewedCount,
    redisFilesDetectedCount,
    sentinelFilesDetectedCount,
    aclFilesDetectedCount,
    dumpOrAofFilesDetectedCount,
    configsDetectedCount,
    findingsCount,
    redactedValuesCount
  };
}

export function redactRedisConfigValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactRedisConfigText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactRedisConfigValue(item));
  }
  const record = asRecord(value);
  if (record) {
    const recordHasSecretName = redisRecordHasSecretName(record);
    return Object.fromEntries(
      Object.entries(record).map(([key, item]) => {
        const normalizedKey = normalizeKey(key);
        const redactValue =
          isRedisSecretValueKey(key) ||
          (recordHasSecretName &&
            [
              "value",
              "raw_value",
              "default",
              "data",
              "content",
              "dump",
              "aof",
              "acl",
              "arguments",
              "environment",
              "command",
              "url",
              "uri",
              "connection_string"
            ].includes(normalizedKey));
        return [key, redactValue ? "[REDACTED]" : redactRedisConfigValue(item)];
      })
    );
  }
  return value;
}

export function redactRedisConfigText(value: string): string {
  return value
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi, "[REDACTED]")
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----/gi, "[REDACTED]")
    .replace(/\bPRIVATE KEY\b/gi, "[REDACTED]")
    .replace(/\b((?:redis|rediss|[a-z][a-z0-9+.-]*):\/\/)([^:@/\s;'"<>]+):([^@\s;'"<>]+)@/gi, "$1[REDACTED]@")
    .replace(/\b((?:redis|rediss):\/\/):([^@\s;'"<>]+)@/gi, "$1[REDACTED]@")
    .replace(/\b(?:[a-z0-9._-]*user|username|login):(?:[a-z0-9._-]*(?:pass|password|secret|token|key)[a-z0-9._-]*)\b/gi, "[REDACTED]")
    .replace(/\bAuthorization:\s*Bearer\s+[^\s,'"}\]]+/gi, "Authorization: Bearer [REDACTED]")
    .replace(/\b(requirepass|masterauth)\b\s+(?!(?:is|was|present|missing|configured|observed|detected|not)\b)[^,\n\r;}\]]+/gi, "$1 [REDACTED]")
    .replace(/\bsentinel\s+auth-pass\s+\S+\s+[^,\n\r;}\]]+/gi, "sentinel auth-pass [REDACTED]")
    .replace(
      /\b(?:super-secret-password|raw-api-key-[a-z0-9_-]+|raw-redis-password-[a-z0-9_-]+|token_should_never_render|acl_password_hash_should_not_render|dump_value_should_not_render|[a-z0-9._-]*should_(?:never|not)_render[a-z0-9._-]*|ACLHASHSECRET[a-z0-9._-]*)\b/gi,
      "[REDACTED]"
    )
    .replace(
      /([?&](?:access_token|refresh_token|id_token|api_key|apikey|key|token|secret|password|passwd|pwd|session|sid|auth|authorization|jwt|bearer|sig|signature|client_secret|code|state)=)[^&#\s]+/gi,
      "$1[REDACTED]"
    )
    .replace(
      /(^|[\s,{])([A-Z0-9_$.-]*(?:REDIS_PASSWORD|REQUIREPASS|MASTERAUTH|AUTH_PASS|REDIS_URL|CONNECTION_STRING|PASSWORD|PASS|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|CLIENT_SECRET|CREDENTIAL|AUTH)[A-Z0-9_$.-]*)(\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2$3$4[REDACTED]"
    )
    .replace(
      /(\b(?:redis_password|requirepass|masterauth|auth_pass|redis_url|connection_string|password|passwd|token|secret|api_key|apikey|private_key|client_secret|credential|auth)\b\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2[REDACTED]"
    )
    .replace(/\[REDACTED\]\]+/g, "[REDACTED]");
}

function redisRecordHasSecretName(record: Record<string, unknown>): boolean {
  for (const marker of ["key", "name", "setting", "directive", "target", "path", "environment", "env", "url", "field_path"]) {
    const candidate = record[marker];
    if (typeof candidate === "string" && isRedisSecretValueKey(candidate)) {
      return true;
    }
    if (Array.isArray(candidate) && candidate.some((item) => typeof item === "string" && isRedisSecretValueKey(item))) {
      return true;
    }
  }
  return false;
}

function isRedisSecretValueKey(key: string): boolean {
  const normalized = normalizeKey(key);
  if (normalized.includes("redacted") || normalized.endsWith("_count")) {
    return false;
  }
  if (["redaction_notes", "skip_reason", "reason", "config_type", "category", "context", "directive", "setting"].includes(normalized)) {
    return false;
  }
  if (
    [
      "content",
      "raw",
      "raw_content",
      "dump_content",
      "aof_content",
      "acl_content",
      "appendonly_content",
      "backup_content",
      "private_key",
      "private_key_content",
      "certificate_key",
      "env_file_content",
      "credential_file_content"
    ].includes(normalized)
  ) {
    return true;
  }
  return [
    "authorization",
    "access_token",
    "refresh_token",
    "auth_token",
    "auth_pass",
    "requirepass",
    "masterauth",
    "redis_password",
    "redis_url",
    "connection_string",
    "acl_hash",
    "api_key",
    "apikey",
    "token",
    "client_secret",
    "private_key",
    "password",
    "passwd",
    "credential",
    "secret",
    "auth"
  ].some((token) => normalized.includes(token));
}

function filesFromValue(value: unknown): RedisFile[] {
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
      context: asString(record?.context),
      configType: asString(record?.config_type)
    };
  });
}

function reviewedFilesFromValues(value: unknown, detectedFiles: RedisFile[]): RedisFile[] {
  if (Array.isArray(value)) {
    return filesFromValue(value).map((item) => ({ ...item, read: true }));
  }
  return detectedFiles.filter((item) => item.read);
}

function configsFromValue(value: unknown): RedisConfigFile[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      configType: asString(record?.config_type) ?? asString(record?.type),
      context: asString(record?.context)
    };
  });
}

function settingsFromValue(value: unknown): RedisSetting[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      configType: asString(record?.config_type),
      directive: asString(record?.directive),
      setting: asString(record?.setting) ?? asString(record?.name) ?? asString(record?.key),
      value: asString(record?.safe_value) ?? asString(record?.value),
      filePath: asString(record?.file_path) ?? asString(record?.path) ?? "",
      context: asString(record?.context),
      line: asNumber(record?.line)
    };
  });
}

function includesFromValue(value: unknown): RedisInclude[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      directive: asString(record?.directive) ?? "include",
      target: asString(record?.target) ?? asString(record?.path) ?? asString(record?.include_path),
      resolved: asBoolean(record?.resolved),
      filePath: asString(record?.file_path) ?? asString(record?.source_file) ?? "",
      configType: asString(record?.config_type),
      context: asString(record?.context),
      line: asNumber(record?.line)
    };
  });
}

function sensitiveFilesFromValue(value: unknown): RedisSensitiveFile[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      category: asString(record?.category) ?? "unknown",
      read: asBoolean(record?.read),
      skipReason: asString(record?.skip_reason),
      sizeBytes: asNumber(record?.size_bytes),
      context: asString(record?.context)
    };
  });
}

function findingsFromValue(value: unknown): RedisFinding[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      id: asString(record?.id) ?? asString(record?.code) ?? "finding",
      title: asString(record?.title) ?? asString(record?.message) ?? "Redis config finding",
      level: normalizeFindingLevel(asString(record?.level) ?? asString(record?.severity)),
      confidence: normalizeConfidence(asString(record?.confidence)),
      category: asString(record?.category),
      context: asString(record?.context),
      configType: asString(record?.config_type),
      directive: asString(record?.directive),
      setting: asString(record?.setting) ?? asString(record?.field_path),
      address: asString(record?.address),
      port: asString(record?.port),
      path: asString(record?.path),
      filePath: asString(record?.file_path),
      line: asNumber(record?.line),
      description: asString(record?.description) ?? "",
      evidence: asString(record?.evidence) ?? "",
      recommendation: asString(record?.recommendation) ?? ""
    };
  });
}

function groupFindingsByLevel(findings: RedisFinding[]): RedisFindingGroup[] {
  const order = ["critical", "high", "medium", "low", "info", "review", "unknown"];
  const groups = new Map<string, RedisFinding[]>();
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
  return typeof value === "string" && value.trim() ? redactRedisConfigText(value) : null;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.trim().length > 0).map(redactRedisConfigText) : [];
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
    return redactRedisConfigText(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return redactRedisConfigText(JSON.stringify(value));
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[-.]/g, "_");
}
