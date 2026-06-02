import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type SqlDatabaseFile = {
  path: string;
  category: string;
  read: boolean;
  skipReason: string | null;
  sizeBytes: number | null;
  bytesRead: number | null;
  context: string | null;
  engine: string | null;
};

export type SqlDatabaseConfigFile = {
  filePath: string;
  category: string | null;
  engine: string | null;
  context: string | null;
  read: boolean | null;
  bytesRead: number | null;
  settingsCount: number | null;
};

export type SqlDatabaseSetting = {
  engine: string | null;
  section: string | null;
  setting: string | null;
  value: string | null;
  filePath: string;
  context: string | null;
  line: number | null;
};

export type SqlDatabasePgHbaRule = {
  type: string | null;
  database: string | null;
  user: string | null;
  address: string | null;
  authMethod: string | null;
  filePath: string;
  context: string | null;
  line: number | null;
};

export type SqlDatabaseInclude = {
  directive: string | null;
  target: string | null;
  resolved: boolean | null;
  filePath: string;
  engine: string | null;
  context: string | null;
  line: number | null;
};

export type SqlDatabaseNoReadFile = {
  path: string;
  category: string;
  read: boolean | null;
  skipReason: string | null;
  sizeBytes: number | null;
  context: string | null;
};

export type SqlDatabaseFinding = {
  id: string;
  title: string;
  level: string;
  confidence: string | null;
  category: string | null;
  context: string | null;
  engine: string | null;
  filePath: string | null;
  line: number | null;
  section: string | null;
  setting: string | null;
  authMethod: string | null;
  address: string | null;
  description: string;
  evidence: string;
  recommendation: string;
};

export type SqlDatabaseFindingGroup = {
  level: string;
  findings: SqlDatabaseFinding[];
};

export type SqlDatabaseConfigAuditReport = {
  isSqlDatabaseConfigAudit: boolean;
  analyzer: string | null;
  archiveType: string | null;
  overview: MetadataEntry[];
  summary: MetadataEntry[];
  limits: MetadataEntry[];
  detectedFiles: SqlDatabaseFile[];
  reviewedFiles: SqlDatabaseFile[];
  postgresConfigs: SqlDatabaseConfigFile[];
  postgresHbaRules: SqlDatabasePgHbaRule[];
  mysqlConfigs: SqlDatabaseConfigFile[];
  databaseSettings: SqlDatabaseSetting[];
  includes: SqlDatabaseInclude[];
  sensitiveFiles: SqlDatabaseNoReadFile[];
  dumpOrBackupFiles: SqlDatabaseNoReadFile[];
  dataFiles: SqlDatabaseNoReadFile[];
  findings: SqlDatabaseFinding[];
  findingGroups: SqlDatabaseFindingGroup[];
  redactionNotes: string[];
  errors: string[];
  truncated: boolean;
  filesConsideredCount: number;
  filesReviewedCount: number;
  postgresConfigsDetectedCount: number;
  postgresHbaFilesDetectedCount: number;
  mysqlConfigsDetectedCount: number;
  mariadbConfigsDetectedCount: number;
  dumpOrBackupFilesDetectedCount: number;
  dataFilesDetectedCount: number;
  sensitiveFilesDetectedCount: number;
  findingsCount: number;
  redactedValuesCount: number;
};

export function buildSqlDatabaseConfigAuditReport(job: JobRecord): SqlDatabaseConfigAuditReport {
  const result = asRecord(redactSqlDatabaseConfigValue(job.result));
  const summary = asRecord(result?.summary);
  const detectedFiles = filesFromValue(result?.files_detected);
  const reviewedFiles = reviewedFilesFromValues(result?.files_reviewed, detectedFiles);
  const postgresConfigs = configFilesFromValue(result?.postgres_configs);
  const postgresHbaRules = pgHbaRulesFromValue(result?.postgres_hba_rules);
  const mysqlConfigs = configFilesFromValue(result?.mysql_configs);
  const databaseSettings = settingsFromValue(result?.database_settings);
  const includes = includesFromValue(result?.includes);
  const sensitiveFiles = noReadFilesFromValue(result?.sensitive_files);
  const dumpOrBackupFiles = noReadFilesFromValue(result?.dump_or_backup_files);
  const dataFiles = noReadFilesFromValue(result?.data_files);
  const findings = findingsFromValue(result?.findings);
  const filesConsideredCount = asNumber(summary?.files_considered) ?? detectedFiles.length;
  const filesReviewedCount = asNumber(summary?.files_reviewed) ?? reviewedFiles.length;
  const postgresConfigsDetectedCount = asNumber(summary?.postgres_configs_detected) ?? postgresConfigs.length;
  const postgresHbaFilesDetectedCount = asNumber(summary?.postgres_hba_files_detected) ?? postgresHbaRules.length;
  const mysqlConfigsDetectedCount = asNumber(summary?.mysql_configs_detected) ?? mysqlConfigs.filter((file) => file.engine !== "mariadb").length;
  const mariadbConfigsDetectedCount = asNumber(summary?.mariadb_configs_detected) ?? mysqlConfigs.filter((file) => file.engine === "mariadb").length;
  const dumpOrBackupFilesDetectedCount = asNumber(summary?.dump_or_backup_files_detected) ?? dumpOrBackupFiles.length;
  const dataFilesDetectedCount = asNumber(summary?.data_files_detected) ?? dataFiles.length;
  const sensitiveFilesDetectedCount = asNumber(summary?.sensitive_files_detected) ?? sensitiveFiles.length;
  const findingsCount = asNumber(summary?.findings_count) ?? findings.length;
  const redactedValuesCount = asNumber(summary?.redacted_values_count) ?? 0;
  const truncated = Boolean(summary?.truncated) || Boolean(result?.truncated);
  const errors = asStringArray(result?.errors).map(redactSqlDatabaseConfigText);
  const reportStatus = truncated ? `${job.status} (truncated)` : errors.length > 0 ? `${job.status} with errors` : job.status;

  return {
    isSqlDatabaseConfigAudit: job.audit_type === "sql_database_config_basic" || asString(result?.analyzer) === "sql_database_config_basic",
    analyzer: asString(result?.analyzer),
    archiveType: asString(result?.archive_type),
    overview: [
      { label: "Files reviewed", value: String(filesReviewedCount) },
      { label: "PostgreSQL configs", value: String(postgresConfigsDetectedCount) },
      { label: "pg_hba files", value: String(postgresHbaFilesDetectedCount) },
      { label: "MySQL/MariaDB configs", value: String(mysqlConfigsDetectedCount + mariadbConfigsDetectedCount) },
      { label: "No-read files", value: String(sensitiveFilesDetectedCount + dumpOrBackupFilesDetectedCount + dataFilesDetectedCount) },
      { label: "Findings", value: String(findingsCount) },
      { label: "Status", value: reportStatus }
    ],
    summary: entriesFromRecord(summary),
    limits: entriesFromRecord(asRecord(result?.limits)),
    detectedFiles,
    reviewedFiles,
    postgresConfigs,
    postgresHbaRules,
    mysqlConfigs,
    databaseSettings,
    includes,
    sensitiveFiles,
    dumpOrBackupFiles,
    dataFiles,
    findings,
    findingGroups: groupFindingsByLevel(findings),
    redactionNotes: asStringArray(result?.redaction_notes).map(redactSqlDatabaseConfigText),
    errors,
    truncated,
    filesConsideredCount,
    filesReviewedCount,
    postgresConfigsDetectedCount,
    postgresHbaFilesDetectedCount,
    mysqlConfigsDetectedCount,
    mariadbConfigsDetectedCount,
    dumpOrBackupFilesDetectedCount,
    dataFilesDetectedCount,
    sensitiveFilesDetectedCount,
    findingsCount,
    redactedValuesCount
  };
}

export function redactSqlDatabaseConfigValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactSqlDatabaseConfigText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactSqlDatabaseConfigValue(item));
  }
  const record = asRecord(value);
  if (record) {
    const recordHasSecretName = sqlDatabaseRecordHasSecretName(record);
    return Object.fromEntries(
      Object.entries(record).map(([key, item]) => {
        const normalizedKey = normalizeKey(key);
        const redactValue =
          isSqlDatabaseSecretValueKey(key) ||
          (recordHasSecretName &&
            [
              "value",
              "raw_value",
              "default",
              "data",
              "content",
              "sql",
              "statement",
              "environment",
              "command",
              "arguments",
              "url",
              "uri",
              "dsn",
              "conninfo",
              "connection_string"
            ].includes(normalizedKey));
        return [key, redactValue ? "[REDACTED]" : redactSqlDatabaseConfigValue(item)];
      })
    );
  }
  return value;
}

export function redactSqlDatabaseConfigText(value: string): string {
  return value
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi, "[REDACTED]")
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----/gi, "[REDACTED]")
    .replace(/\bPRIVATE KEY\b/gi, "[REDACTED]")
    .replace(/\b((?:postgres|postgresql|mysql|mariadb|jdbc:[a-z]+|[a-z][a-z0-9+.-]*):\/\/)([^:@/\s;'"<>]+):([^@\s;'"<>]+)@/gi, "$1[REDACTED]@")
    .replace(/\b(?:[a-z0-9._-]*user|username|login):(?:[a-z0-9._-]*(?:pass|password|secret|token|key)[a-z0-9._-]*)\b/gi, "[REDACTED]")
    .replace(
      /\b(?:super-secret-password|raw-db-password-[a-z0-9_-]+|raw-api-key-[a-z0-9_-]+|replication_password_should_not_render|db_password_plaintext|[a-z0-9._-]*should_(?:never|not)_render[a-z0-9._-]*)\b/gi,
      "[REDACTED]"
    )
    .replace(
      /([?&](?:access_token|refresh_token|id_token|api_key|apikey|key|token|secret|password|passwd|pwd|session|sid|auth|authorization|jwt|bearer|sig|signature|client_secret|code|state)=)[^&#\s]+/gi,
      "$1[REDACTED]"
    )
    .replace(
      /(^|[\s,{])([A-Z0-9_$.-]*(?:PGPASSWORD|MYSQL_PWD|DATABASE_URL|DB_URL|DSN|CONNINFO|CONNECTION_STRING|REPLICATION_PASSWORD|SSL_KEY|SECRET|TOKEN|PASSWORD|PASS|API_KEY|APIKEY|PRIVATE_KEY|CLIENT_SECRET|CREDENTIAL|AUTH)[A-Z0-9_$.-]*)(\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2$3$4[REDACTED]"
    )
    .replace(
      /(\b(?:pgpassword|mysql_pwd|database_url|db_url|dsn|conninfo|connection_string|replication_password|password|passwd|token|secret|api_key|apikey|private_key|client_secret|credential|auth)\b\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2[REDACTED]"
    )
    .replace(/\[REDACTED\]\]+/g, "[REDACTED]");
}

function sqlDatabaseRecordHasSecretName(record: Record<string, unknown>): boolean {
  for (const marker of ["key", "name", "setting", "variable", "field_path", "attribute", "directive", "environment", "section"]) {
    const candidate = record[marker];
    if (typeof candidate === "string" && isSqlDatabaseSecretValueKey(candidate)) {
      return true;
    }
    if (Array.isArray(candidate) && candidate.some((item) => typeof item === "string" && isSqlDatabaseSecretValueKey(item))) {
      return true;
    }
  }
  return false;
}

function isSqlDatabaseSecretValueKey(key: string): boolean {
  const normalized = normalizeKey(key);
  if (normalized.includes("redacted") || normalized.endsWith("_count")) {
    return false;
  }
  if (
    [
      "redaction_notes",
      "skip_reason",
      "reason",
      "auth_method",
      "method",
      "engine",
      "engines",
      "category",
      "context",
      "password_encryption"
    ].includes(normalized)
  ) {
    return false;
  }
  if (
    [
      "content",
      "raw",
      "raw_content",
      "dump_content",
      "backup_content",
      "data_content",
      "wal_content",
      "binlog_content",
      "innodb_content",
      "sql",
      "statement",
      "private_key_content",
      "env_file_content",
      "credential_file_content",
      "pgpass_content",
      "my_cnf_content",
      "mylogin_cnf_content"
    ].includes(normalized)
  ) {
    return true;
  }
  return [
    "pgpassword",
    "mysql_pwd",
    "database_url",
    "db_url",
    "dsn",
    "conninfo",
    "connection_string",
    "replication_password",
    "ssl_key",
    "api_key",
    "apikey",
    "access_key",
    "secret_key",
    "token",
    "client_secret",
    "private_key",
    "password",
    "passwd",
    "credential",
    "auth"
  ].some((token) => normalized.includes(token));
}

function filesFromValue(value: unknown): SqlDatabaseFile[] {
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
      engine: asString(record?.engine)
    };
  });
}

function reviewedFilesFromValues(value: unknown, detectedFiles: SqlDatabaseFile[]): SqlDatabaseFile[] {
  if (Array.isArray(value)) {
    return filesFromValue(value).map((item) => ({ ...item, read: true }));
  }
  return detectedFiles.filter((item) => item.read);
}

function configFilesFromValue(value: unknown): SqlDatabaseConfigFile[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      filePath: asString(record?.file_path) ?? asString(record?.path) ?? "",
      category: asString(record?.category),
      engine: asString(record?.engine),
      context: asString(record?.context),
      read: asBoolean(record?.read),
      bytesRead: asNumber(record?.bytes_read),
      settingsCount: asNumber(record?.settings_count)
    };
  });
}

function settingsFromValue(value: unknown): SqlDatabaseSetting[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      engine: asString(record?.engine),
      section: asString(record?.section),
      setting: asString(record?.setting) ?? asString(record?.name) ?? asString(record?.key),
      value: asString(record?.safe_value) ?? asString(record?.value),
      filePath: asString(record?.file_path) ?? asString(record?.path) ?? "",
      context: asString(record?.context),
      line: asNumber(record?.line)
    };
  });
}

function pgHbaRulesFromValue(value: unknown): SqlDatabasePgHbaRule[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      type: asString(record?.type),
      database: asString(record?.database),
      user: asString(record?.user),
      address: asString(record?.address),
      authMethod: asString(record?.auth_method) ?? asString(record?.method),
      filePath: asString(record?.file_path) ?? asString(record?.path) ?? "",
      context: asString(record?.context),
      line: asNumber(record?.line)
    };
  });
}

function includesFromValue(value: unknown): SqlDatabaseInclude[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      directive: asString(record?.directive) ?? asString(record?.type),
      target: asString(record?.target) ?? asString(record?.path) ?? asString(record?.include_path),
      resolved: asBoolean(record?.resolved),
      filePath: asString(record?.file_path) ?? asString(record?.source_file) ?? "",
      engine: asString(record?.engine),
      context: asString(record?.context),
      line: asNumber(record?.line)
    };
  });
}

function noReadFilesFromValue(value: unknown): SqlDatabaseNoReadFile[] {
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

function findingsFromValue(value: unknown): SqlDatabaseFinding[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      id: asString(record?.id) ?? asString(record?.code) ?? "finding",
      title: asString(record?.title) ?? asString(record?.message) ?? "SQL database config finding",
      level: normalizeFindingLevel(asString(record?.level) ?? asString(record?.severity)),
      confidence: normalizeConfidence(asString(record?.confidence)),
      category: asString(record?.category),
      context: asString(record?.context),
      engine: asString(record?.engine),
      filePath: asString(record?.file_path),
      line: asNumber(record?.line),
      section: asString(record?.section),
      setting: asString(record?.setting) ?? asString(record?.field_path),
      authMethod: asString(record?.auth_method) ?? asString(record?.method),
      address: asString(record?.address),
      description: asString(record?.description) ?? "",
      evidence: asString(record?.evidence) ?? "",
      recommendation: asString(record?.recommendation) ?? ""
    };
  });
}

function groupFindingsByLevel(findings: SqlDatabaseFinding[]): SqlDatabaseFindingGroup[] {
  const order = ["critical", "high", "medium", "low", "info", "review", "unknown"];
  const groups = new Map<string, SqlDatabaseFinding[]>();
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
  return typeof value === "string" && value.trim() ? redactSqlDatabaseConfigText(value) : null;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && item.trim().length > 0).map(redactSqlDatabaseConfigText)
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
    return redactSqlDatabaseConfigText(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return redactSqlDatabaseConfigText(JSON.stringify(value));
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[-.]/g, "_");
}
