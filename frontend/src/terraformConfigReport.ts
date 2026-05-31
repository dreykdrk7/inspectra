import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type TerraformFile = {
  path: string;
  category: string;
  read: boolean;
  skipReason: string | null;
  sizeBytes: number | null;
  bytesRead: number | null;
  context: string | null;
};

export type TerraformProvider = {
  filePath: string;
  name: string | null;
  source: string | null;
  version: string | null;
  context: string | null;
};

export type TerraformBackend = {
  filePath: string;
  type: string | null;
  configKeys: string[];
  context: string | null;
};

export type TerraformModule = {
  filePath: string;
  name: string | null;
  source: string | null;
  version: string | null;
  ref: string | null;
  context: string | null;
};

export type TerraformResource = {
  filePath: string;
  provider: string | null;
  resourceType: string | null;
  resourceName: string | null;
  context: string | null;
};

export type TerraformVariable = {
  filePath: string;
  kind: "variable" | "output";
  name: string | null;
  sensitive: boolean | null;
  defaultPresent: boolean | null;
  context: string | null;
};

export type TerraformStateFile = {
  path: string;
  category: string;
  read: boolean;
  skipReason: string | null;
  context: string | null;
};

export type TerraformFinding = {
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
  provider: string | null;
  resourceType: string | null;
  resourceName: string | null;
  blockType: string | null;
  fieldPath: string | null;
  line: number | null;
};

export type TerraformFindingGroup = {
  level: string;
  findings: TerraformFinding[];
};

export type TerraformConfigAuditReport = {
  isTerraformConfigAudit: boolean;
  analyzer: string | null;
  archiveType: string | null;
  overview: MetadataEntry[];
  summary: MetadataEntry[];
  limits: MetadataEntry[];
  detectedFiles: TerraformFile[];
  reviewedFiles: TerraformFile[];
  providers: TerraformProvider[];
  backends: TerraformBackend[];
  modules: TerraformModule[];
  resources: TerraformResource[];
  variables: TerraformVariable[];
  outputs: TerraformVariable[];
  stateFiles: TerraformStateFile[];
  findings: TerraformFinding[];
  findingGroups: TerraformFindingGroup[];
  redactionNotes: string[];
  errors: string[];
  truncated: boolean;
  filesConsideredCount: number;
  filesReviewedCount: number;
  terraformFilesDetectedCount: number;
  tfvarsFilesDetectedCount: number;
  stateFilesDetectedCount: number;
  providersDetectedCount: number;
  backendsDetectedCount: number;
  modulesDetectedCount: number;
  resourcesDetectedCount: number;
  findingsCount: number;
  redactedValuesCount: number;
};

export function buildTerraformConfigAuditReport(job: JobRecord): TerraformConfigAuditReport {
  const result = asRecord(redactTerraformConfigValue(job.result));
  const summary = asRecord(result?.summary);
  const detectedFiles = filesFromValue(result?.files_detected);
  const reviewedFiles = reviewedFilesFromValues(result?.files_reviewed, detectedFiles);
  const providers = providersFromValue(result?.providers);
  const backends = backendsFromValue(result?.backends);
  const modules = modulesFromValue(result?.modules);
  const resources = resourcesFromValue(result?.resources);
  const variables = variablesFromValue(result?.variables, "variable");
  const outputs = variablesFromValue(result?.outputs, "output");
  const stateFiles = stateFilesFromValue(result?.state_files);
  const findings = findingsFromValue(result?.findings);
  const filesConsideredCount = asNumber(summary?.files_considered) ?? detectedFiles.length;
  const filesReviewedCount = asNumber(summary?.files_reviewed) ?? reviewedFiles.length;
  const terraformFilesDetectedCount =
    asNumber(summary?.terraform_files_detected) ??
    detectedFiles.filter((item) => item.category.includes("terraform") || item.path.endsWith(".tf") || item.path.endsWith(".tf.json")).length;
  const tfvarsFilesDetectedCount =
    asNumber(summary?.tfvars_files_detected) ?? detectedFiles.filter((item) => item.path.includes(".tfvars")).length;
  const stateFilesDetectedCount = asNumber(summary?.state_files_detected) ?? stateFiles.length;
  const providersDetectedCount = asNumber(summary?.providers_detected) ?? providers.length;
  const backendsDetectedCount = asNumber(summary?.backends_detected) ?? backends.length;
  const modulesDetectedCount = asNumber(summary?.modules_detected) ?? modules.length;
  const resourcesDetectedCount = asNumber(summary?.resources_detected) ?? resources.length;
  const findingsCount = asNumber(summary?.findings_count) ?? findings.length;
  const redactedValuesCount = asNumber(summary?.redacted_values_count) ?? 0;
  const truncated = Boolean(summary?.truncated) || Boolean(result?.truncated);
  const errors = asStringArray(result?.errors).map(redactTerraformConfigText);
  const reportStatus = truncated ? `${job.status} (truncated)` : errors.length > 0 ? `${job.status} with errors` : job.status;

  return {
    isTerraformConfigAudit:
      job.audit_type === "terraform_config_basic" || asString(result?.analyzer) === "terraform_config_basic",
    analyzer: asString(result?.analyzer),
    archiveType: asString(result?.archive_type),
    overview: [
      { label: "Files reviewed", value: String(filesReviewedCount) },
      { label: "Resources", value: String(resourcesDetectedCount) },
      { label: "Providers", value: String(providersDetectedCount) },
      { label: "State files", value: String(stateFilesDetectedCount) },
      { label: "Findings", value: String(findingsCount) },
      { label: "Status", value: reportStatus }
    ],
    summary: entriesFromRecord(summary),
    limits: entriesFromRecord(asRecord(result?.limits)),
    detectedFiles,
    reviewedFiles,
    providers,
    backends,
    modules,
    resources,
    variables,
    outputs,
    stateFiles,
    findings,
    findingGroups: groupFindingsByLevel(findings),
    redactionNotes: asStringArray(result?.redaction_notes).map(redactTerraformConfigText),
    errors,
    truncated,
    filesConsideredCount,
    filesReviewedCount,
    terraformFilesDetectedCount,
    tfvarsFilesDetectedCount,
    stateFilesDetectedCount,
    providersDetectedCount,
    backendsDetectedCount,
    modulesDetectedCount,
    resourcesDetectedCount,
    findingsCount,
    redactedValuesCount
  };
}

export function redactTerraformConfigValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactTerraformConfigText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactTerraformConfigValue(item));
  }
  const record = asRecord(value);
  if (record) {
    const recordHasSecretName = terraformRecordHasSecretName(record);
    return Object.fromEntries(
      Object.entries(record).map(([key, item]) => {
        const normalizedKey = key.toLowerCase().replace(/-/g, "_");
        const redactValue =
          isTerraformSecretValueKey(key) ||
          isTerraformStateContentKey(key) ||
          (recordHasSecretName &&
            [
              "value",
              "raw_value",
              "default",
              "data",
              "config",
              "user_data",
              "startup_script",
              "connection_string"
            ].includes(normalizedKey));
        return [key, redactValue ? "[REDACTED]" : redactTerraformConfigValue(item)];
      })
    );
  }
  return value;
}

export function redactTerraformConfigText(value: string): string {
  return value
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi, "[REDACTED]")
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "[REDACTED]")
    .replace(/\bPRIVATE KEY\b/gi, "[REDACTED]")
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)([^:@/\s]+):([^@\s]+)@/gi, "$1[REDACTED]@")
    .replace(
      /([?&](?:access_token|refresh_token|id_token|api_key|apikey|key|token|secret|password|passwd|pwd|session|sid|auth|authorization|jwt|bearer|sig|signature|client_secret|code|state)=)[^&#\s]+/gi,
      "$1[REDACTED]"
    )
    .replace(
      /(^|[\s,{])([A-Z0-9_.:/@-]*(?:SECRET_KEY|SECRET_ACCESS_KEY|ACCESS_KEY|SESSION_TOKEN|TOKEN|PASSWORD|PASS|API_KEY|APIKEY|PRIVATE_KEY|CLIENT_SECRET|CONNECTION_STRING|SECRET)[A-Z0-9_.:/@-]*)(\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2$3$4[REDACTED]"
    )
    .replace(
      /(\b(?:password|passwd|token|secret|api_key|apikey|private_key|client_secret|access_key|secret_key|session_token|connection_string|user_data|startup_script|key)\b\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2[REDACTED]"
    );
}

function terraformRecordHasSecretName(record: Record<string, unknown>): boolean {
  for (const marker of ["key", "name", "setting", "variable", "attribute", "field_path", "output"]) {
    const candidate = record[marker];
    if (typeof candidate === "string" && isTerraformSecretValueKey(candidate)) {
      return true;
    }
  }
  return false;
}

function isTerraformSecretValueKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/-/g, "_");
  if (normalized.includes("redacted") || normalized.endsWith("_count")) {
    return false;
  }
  if (normalized === "secrets") {
    return false;
  }
  return [
    "access_key",
    "secret_key",
    "session_token",
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
    "token",
    "secret",
    "credential",
    "connection_string",
    "certificate"
  ].some((token) => normalized.includes(token));
}

function isTerraformStateContentKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/-/g, "_");
  return ["state", "tfstate", "state_content", "terraform_state", "raw_state", "raw_content", "content", "raw"].includes(normalized);
}

function filesFromValue(value: unknown): TerraformFile[] {
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

function reviewedFilesFromValues(value: unknown, detectedFiles: TerraformFile[]): TerraformFile[] {
  if (Array.isArray(value)) {
    return filesFromValue(value).map((item) => ({ ...item, read: true }));
  }
  return detectedFiles.filter((item) => item.read);
}

function providersFromValue(value: unknown): TerraformProvider[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      filePath: asString(record?.file_path) ?? asString(record?.path) ?? "",
      name: asString(record?.name) ?? asString(record?.provider),
      source: asString(record?.source),
      version: asString(record?.version) ?? asString(record?.constraint),
      context: asString(record?.context)
    };
  });
}

function backendsFromValue(value: unknown): TerraformBackend[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    const configRecord = asRecord(record?.config);
    return {
      filePath: asString(record?.file_path) ?? asString(record?.path) ?? "",
      type: asString(record?.type) ?? asString(record?.backend_type),
      configKeys: asStringArray(record?.config_keys).concat(configRecord ? Object.keys(configRecord) : []),
      context: asString(record?.context)
    };
  });
}

function modulesFromValue(value: unknown): TerraformModule[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      filePath: asString(record?.file_path) ?? asString(record?.path) ?? "",
      name: asString(record?.name) ?? asString(record?.module),
      source: asString(record?.source),
      version: asString(record?.version),
      ref: asString(record?.ref) ?? asString(record?.reference),
      context: asString(record?.context)
    };
  });
}

function resourcesFromValue(value: unknown): TerraformResource[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      filePath: asString(record?.file_path) ?? asString(record?.path) ?? "",
      provider: asString(record?.provider),
      resourceType: asString(record?.resource_type) ?? asString(record?.type),
      resourceName: asString(record?.resource_name) ?? asString(record?.name),
      context: asString(record?.context)
    };
  });
}

function variablesFromValue(value: unknown, kind: "variable" | "output"): TerraformVariable[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      filePath: asString(record?.file_path) ?? asString(record?.path) ?? "",
      kind,
      name: asString(record?.name) ?? asString(record?.output) ?? asString(record?.variable),
      sensitive: asBoolean(record?.sensitive),
      defaultPresent: asBoolean(record?.default_present) ?? (record?.default === undefined ? null : true),
      context: asString(record?.context)
    };
  });
}

function stateFilesFromValue(value: unknown): TerraformStateFile[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      category: asString(record?.category) ?? "terraform_state",
      read: asBoolean(record?.read) ?? false,
      skipReason: asString(record?.skip_reason) ?? "state_file_not_read",
      context: asString(record?.context)
    };
  });
}

function findingsFromValue(value: unknown): TerraformFinding[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      id: asString(record?.id) ?? asString(record?.code) ?? "finding",
      title: asString(record?.title) ?? asString(record?.message) ?? "Terraform config finding",
      level: normalizeFindingLevel(asString(record?.level) ?? asString(record?.severity)),
      confidence: normalizeConfidence(asString(record?.confidence)),
      category: asString(record?.category),
      description: asString(record?.description) ?? "",
      evidence: asString(record?.evidence) ?? "",
      recommendation: asString(record?.recommendation) ?? "",
      filePath: asString(record?.file_path),
      context: asString(record?.context),
      provider: asString(record?.provider),
      resourceType: asString(record?.resource_type),
      resourceName: asString(record?.resource_name),
      blockType: asString(record?.block_type),
      fieldPath: asString(record?.field_path),
      line: asNumber(record?.line)
    };
  });
}

function groupFindingsByLevel(findings: TerraformFinding[]): TerraformFindingGroup[] {
  const order = ["critical", "high", "medium", "low", "info", "review", "unknown"];
  const groups = new Map<string, TerraformFinding[]>();
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
  return typeof value === "string" && value.trim() ? value : null;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.trim().length > 0) : [];
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
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return JSON.stringify(value);
}
