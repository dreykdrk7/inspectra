import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type NodePackageFinding = {
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
  line: number | null;
};

export type NodePackageFile = {
  path: string;
  category: string;
  read: boolean;
  skipReason: string | null;
  sizeBytes: number | null;
  bytesRead: number | null;
  context: string | null;
};

export type NodePackageOverview = {
  path: string;
  name: string | null;
  version: string | null;
  privateFlag: boolean | null;
  packageManager: string | null;
  workspace: string | null;
  context: string | null;
};

export type NodePackageScript = {
  path: string;
  name: string;
  category: string | null;
  excerpt: string;
  context: string | null;
};

export type NodeDependencyGroup = {
  path: string;
  group: string;
  context: string | null;
  dependencies: NodeDependency[];
};

export type NodeDependency = {
  name: string;
  specifier: string;
  sourceType: string | null;
  indicators: string[];
};

export type NodePackageManagerSignal = {
  path: string;
  key: string | null;
  value: string | null;
  signal: string | null;
  line: number | null;
  context: string | null;
};

export type NodeLockfileSignal = {
  path: string;
  lockfile: string | null;
  manager: string | null;
  read: boolean | null;
  skipReason: string | null;
  sizeBytes: number | null;
  context: string | null;
};

export type NodeFindingGroup = {
  level: string;
  findings: NodePackageFinding[];
};

export type NodePackageConfigAuditReport = {
  isNodePackageConfigAudit: boolean;
  analyzer: string | null;
  archiveType: string | null;
  overview: MetadataEntry[];
  summary: MetadataEntry[];
  limits: MetadataEntry[];
  detectedFiles: NodePackageFile[];
  reviewedFiles: NodePackageFile[];
  packages: NodePackageOverview[];
  scripts: NodePackageScript[];
  dependencyGroups: NodeDependencyGroup[];
  packageManagerConfigSignals: NodePackageManagerSignal[];
  lockfileSignals: NodeLockfileSignal[];
  findings: NodePackageFinding[];
  findingGroups: NodeFindingGroup[];
  redactionNotes: string[];
  errors: string[];
  truncated: boolean;
  findingsCount: number;
  filesConsideredCount: number;
  filesReviewedCount: number;
  packageManifestsDetectedCount: number;
  lockfilesDetectedCount: number;
  packageManagerConfigsDetectedCount: number;
  packagesDetectedCount: number;
  scriptsDetectedCount: number;
  redactedValuesCount: number;
};

export function buildNodePackageConfigAuditReport(job: JobRecord): NodePackageConfigAuditReport {
  const result = asRecord(redactNodePackageConfigValue(job.result));
  const summary = asRecord(result?.summary);
  const detectedFiles = filesFromValue(result?.files_detected);
  const reviewedFiles = reviewedFilesFromValues(result?.files_reviewed, detectedFiles);
  const packages = packagesFromValue(result?.packages);
  const scripts = scriptsFromValue(result?.scripts);
  const dependencyGroups = dependencyGroupsFromValue(result?.dependency_groups);
  const packageManagerConfigSignals = packageManagerConfigSignalsFromValue(result?.package_manager_config_signals);
  const lockfileSignals = lockfileSignalsFromValue(result?.lockfile_signals);
  const findings = findingsFromValue(result?.findings);
  const findingsCount = asNumber(summary?.findings_count) ?? findings.length;
  const filesConsideredCount = asNumber(summary?.files_considered) ?? detectedFiles.length;
  const filesReviewedCount = asNumber(summary?.files_reviewed) ?? reviewedFiles.length;
  const packageManifestsDetectedCount =
    asNumber(summary?.package_manifests_detected) ?? detectedFiles.filter((item) => item.category === "package_manifest").length;
  const lockfilesDetectedCount =
    asNumber(summary?.lockfiles_detected) ?? detectedFiles.filter((item) => item.category === "lockfile").length;
  const packageManagerConfigsDetectedCount =
    asNumber(summary?.package_manager_configs_detected) ??
    detectedFiles.filter((item) => item.category === "package_manager_config").length;
  const packagesDetectedCount = asNumber(summary?.packages_detected) ?? packages.length;
  const scriptsDetectedCount = asNumber(summary?.scripts_detected) ?? scripts.length;
  const redactedValuesCount = asNumber(summary?.redacted_values_count) ?? 0;
  const truncated = Boolean(summary?.truncated) || Boolean(result?.truncated);
  const errors = asStringArray(result?.errors);
  const reportStatus = truncated ? `${job.status} (truncated)` : errors.length > 0 ? `${job.status} with errors` : job.status;

  return {
    isNodePackageConfigAudit:
      job.audit_type === "node_package_config_basic" || asString(result?.analyzer) === "node_package_config_basic",
    analyzer: asString(result?.analyzer),
    archiveType: asString(result?.archive_type),
    overview: [
      { label: "Files reviewed", value: String(filesReviewedCount) },
      { label: "Packages", value: String(packagesDetectedCount) },
      { label: "Scripts", value: String(scriptsDetectedCount) },
      { label: "Lockfiles", value: String(lockfilesDetectedCount) },
      { label: "Findings", value: String(findingsCount) },
      { label: "Status", value: reportStatus }
    ],
    summary: entriesFromRecord(summary),
    limits: entriesFromRecord(asRecord(result?.limits)),
    detectedFiles,
    reviewedFiles,
    packages,
    scripts,
    dependencyGroups,
    packageManagerConfigSignals,
    lockfileSignals,
    findings,
    findingGroups: groupFindingsByLevel(findings),
    redactionNotes: asStringArray(result?.redaction_notes),
    errors,
    truncated,
    findingsCount,
    filesConsideredCount,
    filesReviewedCount,
    packageManifestsDetectedCount,
    lockfilesDetectedCount,
    packageManagerConfigsDetectedCount,
    packagesDetectedCount,
    scriptsDetectedCount,
    redactedValuesCount
  };
}

export function redactNodePackageConfigValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactNodePackageConfigText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactNodePackageConfigValue(item));
  }
  const record = asRecord(value);
  if (record) {
    const recordHasSecretName = nodeRecordHasSecretName(record);
    return Object.fromEntries(
      Object.entries(record).map(([key, item]) => [
        key,
        isNodeSecretLikeObjectKey(key) || (recordHasSecretName && ["value", "raw_value", "default"].includes(key.toLowerCase()))
          ? "[REDACTED]"
          : redactNodePackageConfigValue(item)
      ])
    );
  }
  return value;
}

export function redactNodePackageConfigText(value: string): string {
  return value
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)([^:@/\s]+):([^@\s]+)@/gi, "$1[REDACTED]@")
    .replace(
      /([?&](?:access_token|refresh_token|id_token|api_key|apikey|key|token|secret|password|passwd|pwd|session|sid|auth|authorization|jwt|bearer|sig|signature|client_secret|code|state)=)[^&#\s]+/gi,
      "$1[REDACTED]"
    )
    .replace(
      /(^|[\s,{])([A-Z0-9_.:/@-]*(?:_authToken|_auth|_password|password|token|api_key|apikey|secret|key)[A-Z0-9_.:/@-]*)(\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2$3$4[REDACTED]"
    );
}

function nodeRecordHasSecretName(record: Record<string, unknown>): boolean {
  for (const marker of ["key", "name", "setting", "variable", "env"]) {
    const candidate = record[marker];
    if (typeof candidate === "string" && isNodeSecretLikeObjectKey(candidate)) {
      return true;
    }
  }
  return false;
}

function isNodeSecretLikeObjectKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/-/g, "_");
  if (normalized.includes("redacted") || normalized.endsWith("_count")) {
    return false;
  }
  return [
    "_auth",
    "auth_token",
    "authtoken",
    "_password",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "token",
    "secret"
  ].some((token) => normalized.includes(token));
}

function filesFromValue(value: unknown): NodePackageFile[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? "",
      category: asString(record?.category) ?? "unknown",
      read: asBoolean(record?.read) ?? false,
      skipReason: asString(record?.skip_reason),
      sizeBytes: asNumber(record?.size_bytes),
      bytesRead: asNumber(record?.bytes_read),
      context: asString(record?.context)
    };
  });
}

function reviewedFilesFromValues(value: unknown, detectedFiles: NodePackageFile[]): NodePackageFile[] {
  if (Array.isArray(value)) {
    return filesFromValue(value).map((item) => ({ ...item, read: true }));
  }
  return detectedFiles.filter((item) => item.read);
}

function packagesFromValue(value: unknown): NodePackageOverview[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      name: asString(record?.name),
      version: asString(record?.version),
      privateFlag: asBoolean(record?.private),
      packageManager: asString(record?.package_manager),
      workspace: asString(record?.workspace) ?? asString(record?.workspace_hint),
      context: asString(record?.context)
    };
  });
}

function scriptsFromValue(value: unknown): NodePackageScript[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    const name = asString(record?.name) ?? asString(record?.script) ?? "script";
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      name,
      category: asString(record?.category) ?? lifecycleCategory(name),
      excerpt: asString(record?.excerpt) ?? asString(record?.command) ?? asString(record?.value) ?? "",
      context: asString(record?.context)
    };
  });
}

function dependencyGroupsFromValue(value: unknown): NodeDependencyGroup[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      group: asString(record?.group) ?? "dependencies",
      context: asString(record?.context),
      dependencies: dependenciesFromValue(record?.dependencies)
    };
  });
}

function dependenciesFromValue(value: unknown): NodeDependency[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      name: asString(record?.name) ?? "dependency",
      specifier: asString(record?.specifier) ?? asString(record?.version) ?? "",
      sourceType: asString(record?.source_type) ?? asString(record?.type),
      indicators: asStringArray(record?.indicators)
    };
  });
}

function packageManagerConfigSignalsFromValue(value: unknown): NodePackageManagerSignal[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      key: asString(record?.key),
      value: asString(record?.value),
      signal: asString(record?.signal) ?? asString(record?.setting),
      line: asNumber(record?.line),
      context: asString(record?.context)
    };
  });
}

function lockfileSignalsFromValue(value: unknown): NodeLockfileSignal[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      lockfile: asString(record?.lockfile) ?? asString(record?.type),
      manager: asString(record?.manager),
      read: asBoolean(record?.read),
      skipReason: asString(record?.skip_reason),
      sizeBytes: asNumber(record?.size_bytes),
      context: asString(record?.context)
    };
  });
}

function findingsFromValue(value: unknown): NodePackageFinding[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      id: asString(record?.id) ?? asString(record?.code) ?? "finding",
      title: asString(record?.title) ?? asString(record?.message) ?? "Node package config finding",
      level: normalizeFindingLevel(asString(record?.level) ?? asString(record?.severity)),
      confidence: normalizeConfidence(asString(record?.confidence)),
      category: asString(record?.category),
      description: asString(record?.description) ?? "",
      evidence: asString(record?.evidence) ?? "",
      recommendation: asString(record?.recommendation) ?? "",
      filePath: asString(record?.file_path),
      context: asString(record?.context),
      line: asNumber(record?.line)
    };
  });
}

function groupFindingsByLevel(findings: NodePackageFinding[]): NodeFindingGroup[] {
  const order = ["critical", "high", "medium", "low", "info", "review", "unknown"];
  const groups = new Map<string, NodePackageFinding[]>();
  findings.forEach((finding) => {
    const level = normalizeFindingLevel(finding.level);
    const existing = groups.get(level) ?? [];
    existing.push(finding);
    groups.set(level, existing);
  });
  return order.filter((level) => groups.has(level)).map((level) => ({ level, findings: groups.get(level) ?? [] }));
}

function lifecycleCategory(name: string): string | null {
  return ["preinstall", "install", "postinstall", "prepare"].includes(name) ? "lifecycle" : null;
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
