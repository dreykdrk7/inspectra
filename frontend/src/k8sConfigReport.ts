import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type K8sFile = {
  path: string;
  category: string;
  read: boolean;
  skipReason: string | null;
  sizeBytes: number | null;
  bytesRead: number | null;
  context: string | null;
};

export type K8sResource = {
  path: string;
  kind: string | null;
  name: string | null;
  namespace: string | null;
  context: string | null;
};

export type K8sContainer = K8sResource & {
  resourceName: string | null;
  container: string | null;
  image: string | null;
};

export type K8sService = K8sResource & {
  type: string | null;
};

export type K8sHelmKustomizeSignal = {
  path: string;
  category: string | null;
  context: string | null;
  rendered: boolean | null;
  built: boolean | null;
  evidence: string | null;
};

export type K8sFinding = {
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
  kind: string | null;
  resourceName: string | null;
  namespace: string | null;
  container: string | null;
  fieldPath: string | null;
  line: number | null;
};

export type K8sFindingGroup = {
  level: string;
  findings: K8sFinding[];
};

export type K8sConfigAuditReport = {
  isK8sConfigAudit: boolean;
  analyzer: string | null;
  archiveType: string | null;
  overview: MetadataEntry[];
  summary: MetadataEntry[];
  limits: MetadataEntry[];
  detectedFiles: K8sFile[];
  reviewedFiles: K8sFile[];
  resources: K8sResource[];
  workloads: K8sResource[];
  containers: K8sContainer[];
  services: K8sService[];
  ingress: K8sResource[];
  rbac: K8sResource[];
  secrets: K8sResource[];
  helmKustomizeSignals: K8sHelmKustomizeSignal[];
  findings: K8sFinding[];
  findingGroups: K8sFindingGroup[];
  redactionNotes: string[];
  errors: string[];
  truncated: boolean;
  filesConsideredCount: number;
  filesReviewedCount: number;
  manifestFilesDetectedCount: number;
  resourcesDetectedCount: number;
  workloadsDetectedCount: number;
  servicesDetectedCount: number;
  secretsDetectedCount: number;
  rbacResourcesDetectedCount: number;
  findingsCount: number;
  redactedValuesCount: number;
};

export function buildK8sConfigAuditReport(job: JobRecord): K8sConfigAuditReport {
  const result = asRecord(redactK8sConfigValue(job.result));
  const summary = asRecord(result?.summary);
  const detectedFiles = filesFromValue(result?.files_detected);
  const reviewedFiles = reviewedFilesFromValues(result?.files_reviewed, detectedFiles);
  const resources = resourcesFromValue(result?.resources);
  const workloads = resourcesFromValue(result?.workloads);
  const containers = containersFromValue(result?.containers);
  const services = servicesFromValue(result?.services);
  const ingress = resourcesFromValue(result?.ingress);
  const rbac = resourcesFromValue(result?.rbac);
  const secrets = resourcesFromValue(result?.secrets);
  const helmKustomizeSignals = helmKustomizeSignalsFromValue(result?.helm_kustomize_signals);
  const findings = findingsFromValue(result?.findings);
  const filesConsideredCount = asNumber(summary?.files_considered) ?? detectedFiles.length;
  const filesReviewedCount = asNumber(summary?.files_reviewed) ?? reviewedFiles.length;
  const manifestFilesDetectedCount =
    asNumber(summary?.manifest_files_detected) ??
    detectedFiles.filter((item) => item.category !== "env_sensitive").length;
  const resourcesDetectedCount = asNumber(summary?.resources_detected) ?? resources.length;
  const workloadsDetectedCount = asNumber(summary?.workloads_detected) ?? workloads.length;
  const servicesDetectedCount = asNumber(summary?.services_detected) ?? services.length;
  const secretsDetectedCount = asNumber(summary?.secrets_detected) ?? secrets.length;
  const rbacResourcesDetectedCount = asNumber(summary?.rbac_resources_detected) ?? rbac.length;
  const findingsCount = asNumber(summary?.findings_count) ?? findings.length;
  const redactedValuesCount = asNumber(summary?.redacted_values_count) ?? 0;
  const truncated = Boolean(summary?.truncated) || Boolean(result?.truncated);
  const errors = asStringArray(result?.errors);
  const reportStatus = truncated ? `${job.status} (truncated)` : errors.length > 0 ? `${job.status} with errors` : job.status;

  return {
    isK8sConfigAudit: job.audit_type === "k8s_config_basic" || asString(result?.analyzer) === "k8s_config_basic",
    analyzer: asString(result?.analyzer),
    archiveType: asString(result?.archive_type),
    overview: [
      { label: "Files reviewed", value: String(filesReviewedCount) },
      { label: "Resources", value: String(resourcesDetectedCount) },
      { label: "Workloads", value: String(workloadsDetectedCount) },
      { label: "Services", value: String(servicesDetectedCount) },
      { label: "Findings", value: String(findingsCount) },
      { label: "Status", value: reportStatus }
    ],
    summary: entriesFromRecord(summary),
    limits: entriesFromRecord(asRecord(result?.limits)),
    detectedFiles,
    reviewedFiles,
    resources,
    workloads,
    containers,
    services,
    ingress,
    rbac,
    secrets,
    helmKustomizeSignals,
    findings,
    findingGroups: groupFindingsByLevel(findings),
    redactionNotes: asStringArray(result?.redaction_notes),
    errors,
    truncated,
    filesConsideredCount,
    filesReviewedCount,
    manifestFilesDetectedCount,
    resourcesDetectedCount,
    workloadsDetectedCount,
    servicesDetectedCount,
    secretsDetectedCount,
    rbacResourcesDetectedCount,
    findingsCount,
    redactedValuesCount
  };
}

export function redactK8sConfigValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactK8sConfigText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactK8sConfigValue(item));
  }
  const record = asRecord(value);
  if (record) {
    const recordHasSecretName = k8sRecordHasSecretName(record);
    return Object.fromEntries(
      Object.entries(record).map(([key, item]) => [
        key,
        isK8sSecretValueKey(key) || (recordHasSecretName && ["value", "raw_value", "default", "data", "stringdata", "string_data"].includes(key.toLowerCase()))
          ? "[REDACTED]"
          : redactK8sConfigValue(item)
      ])
    );
  }
  return value;
}

export function redactK8sConfigText(value: string): string {
  return value
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi, "[REDACTED]")
    .replace(/\b(?:[a-z0-9._-]*user|username|login):(?:[a-z0-9._-]*(?:pass|password|secret|token|key)[a-z0-9._-]*)\b/gi, "[REDACTED]")
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)([^:@/\s]+):([^@\s]+)@/gi, "$1[REDACTED]@")
    .replace(
      /([?&](?:access_token|refresh_token|id_token|api_key|apikey|key|token|secret|password|passwd|pwd|session|sid|auth|authorization|jwt|bearer|sig|signature|client_secret|code|state)=)[^&#\s]+/gi,
      "$1[REDACTED]"
    )
    .replace(
      /(^|[\s,{])([A-Z0-9_.:/@-]*(?:SECRET_KEY|TOKEN|PASSWORD|PASS|API_KEY|APIKEY|PRIVATE_KEY|CLIENT_SECRET|ACCESS_TOKEN|ID_TOKEN|REFRESH_TOKEN|SECRET)[A-Z0-9_.:/@-]*)(\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2$3$4[REDACTED]"
    )
    .replace(
      /(\b(?:password|token|secret|api_key|apikey|private_key|client_secret|key)\b\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2[REDACTED]"
    );
}

function k8sRecordHasSecretName(record: Record<string, unknown>): boolean {
  for (const marker of ["key", "name", "setting", "variable", "env", "field_path"]) {
    const candidate = record[marker];
    if (typeof candidate === "string" && isK8sSecretValueKey(candidate)) {
      return true;
    }
  }
  return false;
}

function isK8sSecretValueKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/-/g, "_");
  if (normalized.includes("redacted") || normalized.endsWith("_count")) {
    return false;
  }
  if (normalized === "secret" || normalized === "secrets") {
    return false;
  }
  if (["data", "stringdata", "string_data"].includes(normalized)) {
    return true;
  }
  return [
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
    "secret"
  ].some((token) => normalized.includes(token));
}

function filesFromValue(value: unknown): K8sFile[] {
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

function reviewedFilesFromValues(value: unknown, detectedFiles: K8sFile[]): K8sFile[] {
  if (Array.isArray(value)) {
    return filesFromValue(value).map((item) => ({ ...item, read: true }));
  }
  return detectedFiles.filter((item) => item.read);
}

function resourcesFromValue(value: unknown): K8sResource[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      kind: asString(record?.kind),
      name: asString(record?.name) ?? asString(record?.resource_name),
      namespace: asString(record?.namespace),
      context: asString(record?.context)
    };
  });
}

function containersFromValue(value: unknown): K8sContainer[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      kind: asString(record?.kind),
      name: asString(record?.name),
      resourceName: asString(record?.resource_name) ?? asString(record?.workload),
      namespace: asString(record?.namespace),
      container: asString(record?.container) ?? asString(record?.name),
      image: asString(record?.image),
      context: asString(record?.context)
    };
  });
}

function servicesFromValue(value: unknown): K8sService[] {
  return resourcesFromValue(value).map((item, index) => {
    const record = Array.isArray(value) ? asRecord(value[index]) : null;
    return {
      ...item,
      type: asString(record?.type) ?? asString(record?.service_type)
    };
  });
}

function helmKustomizeSignalsFromValue(value: unknown): K8sHelmKustomizeSignal[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      category: asString(record?.category) ?? asString(record?.type),
      context: asString(record?.context),
      rendered: asBoolean(record?.rendered),
      built: asBoolean(record?.built),
      evidence: asString(record?.evidence)
    };
  });
}

function findingsFromValue(value: unknown): K8sFinding[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      id: asString(record?.id) ?? asString(record?.code) ?? "finding",
      title: asString(record?.title) ?? asString(record?.message) ?? "Kubernetes config finding",
      level: normalizeFindingLevel(asString(record?.level) ?? asString(record?.severity)),
      confidence: normalizeConfidence(asString(record?.confidence)),
      category: asString(record?.category),
      description: asString(record?.description) ?? "",
      evidence: asString(record?.evidence) ?? "",
      recommendation: asString(record?.recommendation) ?? "",
      filePath: asString(record?.file_path),
      context: asString(record?.context),
      kind: asString(record?.kind),
      resourceName: asString(record?.resource_name) ?? asString(record?.name),
      namespace: asString(record?.namespace),
      container: asString(record?.container),
      fieldPath: asString(record?.field_path),
      line: asNumber(record?.line)
    };
  });
}

function groupFindingsByLevel(findings: K8sFinding[]): K8sFindingGroup[] {
  const order = ["critical", "high", "medium", "low", "info", "review", "unknown"];
  const groups = new Map<string, K8sFinding[]>();
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
