import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type CiCdFinding = {
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
  job: string | null;
  step: string | null;
  line: number | null;
};

export type CiCdFile = {
  path: string;
  category: string;
  read: boolean;
  skipReason: string | null;
  sizeBytes: number | null;
  bytesRead: number | null;
  context: string | null;
};

export type CiCdWorkflow = {
  path: string;
  provider: string | null;
  context: string | null;
  name: string | null;
  jobsCount: number | null;
  triggers: string[];
  read: boolean | null;
  skipReason: string | null;
};

export type CiCdTrigger = {
  path: string;
  provider: string | null;
  context: string | null;
  trigger: string;
  evidence: string | null;
};

export type CiCdPermission = {
  path: string;
  provider: string | null;
  context: string | null;
  permission: string;
  value: string | null;
  evidence: string | null;
};

export type CiCdJobStep = {
  path: string;
  provider: string | null;
  context: string | null;
  job: string | null;
  step: string | null;
  stepsDetected: number | null;
  excerpt: string | null;
};

export type CiCdActionImage = {
  path: string;
  provider: string | null;
  context: string | null;
  action: string | null;
  ref: string | null;
  image: string | null;
  pinned: boolean | null;
  signal: string | null;
  job: string | null;
  step: string | null;
};

export type CiCdServiceContainer = {
  path: string;
  provider: string | null;
  context: string | null;
  service: string | null;
  image: string | null;
  privileged: boolean | null;
  defaultCredentialsHint: string | null;
};

export type CiCdPublishDeploySignal = {
  path: string;
  provider: string | null;
  context: string | null;
  job: string | null;
  step: string | null;
  signal: string;
  evidence: string | null;
};

export type CiCdFindingGroup = {
  level: string;
  findings: CiCdFinding[];
};

export type CiCdConfigAuditReport = {
  isCiCdConfigAudit: boolean;
  analyzer: string | null;
  archiveType: string | null;
  overview: MetadataEntry[];
  summary: MetadataEntry[];
  limits: MetadataEntry[];
  detectedFiles: CiCdFile[];
  reviewedFiles: CiCdFile[];
  workflows: CiCdWorkflow[];
  triggers: CiCdTrigger[];
  permissions: CiCdPermission[];
  jobs: CiCdJobStep[];
  actions: CiCdActionImage[];
  serviceContainers: CiCdServiceContainer[];
  publishDeploySignals: CiCdPublishDeploySignal[];
  findings: CiCdFinding[];
  findingGroups: CiCdFindingGroup[];
  redactionNotes: string[];
  errors: string[];
  truncated: boolean;
  findingsCount: number;
  filesConsideredCount: number;
  filesReviewedCount: number;
  workflowFilesDetectedCount: number;
  jobsDetectedCount: number;
  stepsDetectedCount: number;
  triggersDetectedCount: number;
  redactedValuesCount: number;
};

export function buildCiCdConfigAuditReport(job: JobRecord): CiCdConfigAuditReport {
  const result = asRecord(redactCiCdConfigValue(job.result));
  const summary = asRecord(result?.summary);
  const detectedFiles = filesFromValue(result?.files_detected);
  const reviewedFiles = reviewedFilesFromValues(result?.files_reviewed, detectedFiles);
  const workflows = workflowsFromValue(result?.workflows);
  const triggers = triggersFromValue(result?.triggers);
  const permissions = permissionsFromValue(result?.permissions);
  const jobs = jobsFromValue(result?.jobs);
  const actions = actionsFromValue(result?.actions);
  const serviceContainers = serviceContainersFromValue(result?.service_containers);
  const publishDeploySignals = publishDeploySignalsFromValue(result?.publish_deploy_signals);
  const findings = findingsFromValue(result?.findings);
  const findingsCount = asNumber(summary?.findings_count) ?? findings.length;
  const filesConsideredCount = asNumber(summary?.files_considered) ?? detectedFiles.length;
  const filesReviewedCount = asNumber(summary?.files_reviewed) ?? reviewedFiles.length;
  const workflowFilesDetectedCount =
    asNumber(summary?.workflow_files_detected) ??
    detectedFiles.filter((item) => item.category !== "env_sensitive").length;
  const jobsDetectedCount = asNumber(summary?.jobs_detected) ?? jobs.length;
  const stepsDetectedCount = asNumber(summary?.steps_detected) ?? jobs.reduce((total, item) => total + (item.stepsDetected ?? 0), 0);
  const triggersDetectedCount = asNumber(summary?.triggers_detected) ?? triggers.length;
  const redactedValuesCount = asNumber(summary?.redacted_values_count) ?? 0;
  const truncated = Boolean(summary?.truncated) || Boolean(result?.truncated);
  const errors = asStringArray(result?.errors);
  const reportStatus = truncated ? `${job.status} (truncated)` : errors.length > 0 ? `${job.status} with errors` : job.status;

  return {
    isCiCdConfigAudit: job.audit_type === "ci_cd_config_basic" || asString(result?.analyzer) === "ci_cd_config_basic",
    analyzer: asString(result?.analyzer),
    archiveType: asString(result?.archive_type),
    overview: [
      { label: "Files reviewed", value: String(filesReviewedCount) },
      { label: "Workflows", value: String(workflowFilesDetectedCount) },
      { label: "Jobs", value: String(jobsDetectedCount) },
      { label: "Triggers", value: String(triggersDetectedCount) },
      { label: "Findings", value: String(findingsCount) },
      { label: "Status", value: reportStatus }
    ],
    summary: entriesFromRecord(summary),
    limits: entriesFromRecord(asRecord(result?.limits)),
    detectedFiles,
    reviewedFiles,
    workflows,
    triggers,
    permissions,
    jobs,
    actions,
    serviceContainers,
    publishDeploySignals,
    findings,
    findingGroups: groupFindingsByLevel(findings),
    redactionNotes: asStringArray(result?.redaction_notes),
    errors,
    truncated,
    findingsCount,
    filesConsideredCount,
    filesReviewedCount,
    workflowFilesDetectedCount,
    jobsDetectedCount,
    stepsDetectedCount,
    triggersDetectedCount,
    redactedValuesCount
  };
}

export function redactCiCdConfigValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactCiCdConfigText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactCiCdConfigValue(item));
  }
  const record = asRecord(value);
  if (record) {
    const recordHasSecretName = ciCdRecordHasSecretName(record);
    return Object.fromEntries(
      Object.entries(record).map(([key, item]) => [
        key,
        isCiCdSecretLikeObjectKey(key) || (recordHasSecretName && ["value", "raw_value", "default", "command", "script", "excerpt"].includes(key.toLowerCase()))
          ? "[REDACTED]"
          : redactCiCdConfigValue(item)
      ])
    );
  }
  return value;
}

export function redactCiCdConfigText(value: string): string {
  return value
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi, "[REDACTED PRIVATE KEY]")
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)([^:@/\s]+):([^@\s]+)@/gi, "$1[REDACTED]@")
    .replace(
      /([?&](?:access_token|refresh_token|id_token|api_key|apikey|key|token|secret|password|passwd|pwd|session|sid|auth|authorization|jwt|bearer|sig|signature|client_secret|code|state)=)[^&#\s]+/gi,
      "$1[REDACTED]"
    )
    .replace(
      /(^|[\s,{])([A-Z0-9_.:/@-]*(?:SECRET_KEY|TOKEN|PASSWORD|PASS|API_KEY|APIKEY|PRIVATE_KEY|CLIENT_SECRET|ACCESS_TOKEN|ID_TOKEN|REFRESH_TOKEN|SECRET)[A-Z0-9_.:/@-]*)(\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2$3$4[REDACTED]"
    );
}

function ciCdRecordHasSecretName(record: Record<string, unknown>): boolean {
  for (const marker of ["key", "name", "setting", "variable", "env"]) {
    const candidate = record[marker];
    if (typeof candidate === "string" && isCiCdSecretLikeObjectKey(candidate)) {
      return true;
    }
  }
  return false;
}

function isCiCdSecretLikeObjectKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/-/g, "_");
  if (normalized.includes("redacted") || normalized.endsWith("_count")) {
    return false;
  }
  return [
    "password",
    "passwd",
    "api_key",
    "apikey",
    "token",
    "secret",
    "private_key",
    "client_secret",
    "access_token",
    "id_token",
    "refresh_token"
  ].some((token) => normalized.includes(token));
}

function filesFromValue(value: unknown): CiCdFile[] {
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

function reviewedFilesFromValues(value: unknown, detectedFiles: CiCdFile[]): CiCdFile[] {
  if (Array.isArray(value)) {
    return filesFromValue(value).map((item) => ({ ...item, read: true }));
  }
  return detectedFiles.filter((item) => item.read);
}

function workflowsFromValue(value: unknown): CiCdWorkflow[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      provider: asString(record?.provider),
      context: asString(record?.context),
      name: asString(record?.name) ?? asString(record?.workflow),
      jobsCount: asNumber(record?.jobs_count) ?? asNumber(record?.jobs_detected),
      triggers: asStringArray(record?.triggers),
      read: asBoolean(record?.read),
      skipReason: asString(record?.skip_reason)
    };
  });
}

function triggersFromValue(value: unknown): CiCdTrigger[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      provider: asString(record?.provider),
      context: asString(record?.context),
      trigger: asString(record?.trigger) ?? asString(record?.name) ?? asString(record?.type) ?? "trigger",
      evidence: asString(record?.evidence)
    };
  });
}

function permissionsFromValue(value: unknown): CiCdPermission[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      provider: asString(record?.provider),
      context: asString(record?.context),
      permission: asString(record?.permission) ?? asString(record?.key) ?? "permission",
      value: asString(record?.value),
      evidence: asString(record?.evidence)
    };
  });
}

function jobsFromValue(value: unknown): CiCdJobStep[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      provider: asString(record?.provider),
      context: asString(record?.context),
      job: asString(record?.job) ?? asString(record?.name),
      step: asString(record?.step) ?? asString(record?.step_name),
      stepsDetected: asNumber(record?.steps_detected),
      excerpt: asString(record?.excerpt) ?? asString(record?.command) ?? asString(record?.script) ?? asString(record?.evidence)
    };
  });
}

function actionsFromValue(value: unknown): CiCdActionImage[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    const actionWithRef = splitActionRef(asString(record?.action) ?? asString(record?.uses));
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      provider: asString(record?.provider),
      context: asString(record?.context),
      action: actionWithRef.action,
      ref: asString(record?.ref) ?? actionWithRef.ref,
      image: asString(record?.image) ?? asString(record?.image_ref),
      pinned: asBoolean(record?.pinned),
      signal: asString(record?.signal) ?? asString(record?.indicator),
      job: asString(record?.job),
      step: asString(record?.step)
    };
  });
}

function splitActionRef(value: string | null): { action: string | null; ref: string | null } {
  if (!value || value.startsWith("./") || value.startsWith("../") || !value.includes("@")) {
    return { action: value, ref: null };
  }
  const [action, ref] = value.split(/@(.+)/, 2);
  return { action: action || value, ref: ref || null };
}

function serviceContainersFromValue(value: unknown): CiCdServiceContainer[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      provider: asString(record?.provider),
      context: asString(record?.context),
      service: asString(record?.service) ?? asString(record?.name),
      image: asString(record?.image),
      privileged: asBoolean(record?.privileged),
      defaultCredentialsHint: asString(record?.default_credentials_hint) ?? asString(record?.credentials_hint)
    };
  });
}

function publishDeploySignalsFromValue(value: unknown): CiCdPublishDeploySignal[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? asString(record?.file_path) ?? "",
      provider: asString(record?.provider),
      context: asString(record?.context),
      job: asString(record?.job),
      step: asString(record?.step),
      signal: asString(record?.signal) ?? asString(record?.type) ?? "publish/deploy signal",
      evidence: asString(record?.evidence)
    };
  });
}

function findingsFromValue(value: unknown): CiCdFinding[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      id: asString(record?.id) ?? asString(record?.code) ?? "finding",
      title: asString(record?.title) ?? asString(record?.message) ?? "CI/CD config finding",
      level: normalizeFindingLevel(asString(record?.level) ?? asString(record?.severity)),
      confidence: normalizeConfidence(asString(record?.confidence)),
      category: asString(record?.category),
      description: asString(record?.description) ?? "",
      evidence: asString(record?.evidence) ?? "",
      recommendation: asString(record?.recommendation) ?? "",
      filePath: asString(record?.file_path),
      context: asString(record?.context),
      provider: asString(record?.provider),
      job: asString(record?.job),
      step: asString(record?.step),
      line: asNumber(record?.line)
    };
  });
}

function groupFindingsByLevel(findings: CiCdFinding[]): CiCdFindingGroup[] {
  const order = ["critical", "high", "medium", "low", "info", "review", "unknown"];
  const groups = new Map<string, CiCdFinding[]>();
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
