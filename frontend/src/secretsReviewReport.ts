import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type SecretsReviewFinding = {
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

export type SecretsReviewFile = {
  path: string;
  category: string;
  read: boolean;
  skipReason: string | null;
  sizeBytes: number | null;
  bytesRead: number | null;
  context: string | null;
};

export type SecretsFindingGroup = {
  level: string;
  findings: SecretsReviewFinding[];
};

export type SecretsReviewAuditReport = {
  isSecretsReviewAudit: boolean;
  analyzer: string | null;
  archiveType: string | null;
  overview: MetadataEntry[];
  summary: MetadataEntry[];
  limits: MetadataEntry[];
  sensitiveFiles: SecretsReviewFile[];
  detectedFiles: SecretsReviewFile[];
  reviewedFiles: SecretsReviewFile[];
  findings: SecretsReviewFinding[];
  findingGroups: SecretsFindingGroup[];
  redactionNotes: string[];
  errors: string[];
  truncated: boolean;
  findingsCount: number;
  filesConsideredCount: number;
  filesReviewedCount: number;
  sensitiveFilesDetectedCount: number;
  highConfidenceCount: number;
  redactedValuesCount: number;
};

export function buildSecretsReviewAuditReport(job: JobRecord): SecretsReviewAuditReport {
  const result = asRecord(redactSecretsReviewValue(job.result));
  const summary = asRecord(result?.summary);
  const detectedFiles = filesFromValue(result?.files_detected);
  const sensitiveFiles = sensitiveFilesFromValues(result?.sensitive_files, detectedFiles);
  const reviewedFiles = reviewedFilesFromValues(result?.files_reviewed, detectedFiles);
  const findings = findingsFromValue(result?.findings);
  const findingsCount = asNumber(summary?.findings_count) ?? findings.length;
  const filesConsideredCount = asNumber(summary?.files_considered) ?? detectedFiles.length;
  const filesReviewedCount = asNumber(summary?.files_reviewed) ?? reviewedFiles.length;
  const sensitiveFilesDetectedCount = asNumber(summary?.sensitive_files_detected) ?? sensitiveFiles.length;
  const highConfidenceCount =
    asNumber(summary?.high_confidence_count) ?? findings.filter((finding) => finding.confidence === "high").length;
  const redactedValuesCount = asNumber(summary?.redacted_values_count) ?? 0;
  const truncated = Boolean(summary?.truncated) || Boolean(result?.truncated);
  const errors = asStringArray(result?.errors);
  const reportStatus = truncated ? `${job.status} (truncated)` : errors.length > 0 ? `${job.status} with errors` : job.status;

  return {
    isSecretsReviewAudit: job.audit_type === "secrets_review_basic" || asString(result?.analyzer) === "secrets_review_basic",
    analyzer: asString(result?.analyzer),
    archiveType: asString(result?.archive_type),
    overview: [
      { label: "Files reviewed", value: String(filesReviewedCount) },
      { label: "Sensitive files", value: String(sensitiveFilesDetectedCount) },
      { label: "Findings", value: String(findingsCount) },
      { label: "High confidence", value: String(highConfidenceCount) },
      { label: "Redacted values", value: String(redactedValuesCount) },
      { label: "Status", value: reportStatus }
    ],
    summary: entriesFromRecord(summary),
    limits: entriesFromRecord(asRecord(result?.limits)),
    sensitiveFiles,
    detectedFiles,
    reviewedFiles,
    findings,
    findingGroups: groupFindingsByLevel(findings),
    redactionNotes: asStringArray(result?.redaction_notes),
    errors,
    truncated,
    findingsCount,
    filesConsideredCount,
    filesReviewedCount,
    sensitiveFilesDetectedCount,
    highConfidenceCount,
    redactedValuesCount
  };
}

export function redactSecretsReviewValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactSecretsReviewText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactSecretsReviewValue(item));
  }
  const record = asRecord(value);
  if (record) {
    return Object.fromEntries(
      Object.entries(record).map(([key, item]) => [
        key,
        isSecretLikeObjectKey(key) ? "[REDACTED]" : redactSecretsReviewValue(item)
      ])
    );
  }
  return value;
}

export function redactSecretsReviewText(value: string): string {
  const keywords =
    "(SECRET_KEY|DJANGO_SECRET_KEY|CLIENT_SECRET|PRIVATE_KEY|DATABASE_URL|REDIS_URL|EMAIL_HOST_PASSWORD|AWS_SECRET_ACCESS_KEY|API_KEY|PASSWORD|PASS|TOKEN|SECRET)";
  return value
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi, "[REDACTED PRIVATE KEY]")
    .replace(/\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g, "[REDACTED JWT]")
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)([^:@/\s]+):([^@\s]+)@/gi, "$1[REDACTED]@")
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/):([^@\s]+)@/gi, "$1[REDACTED]@")
    .replace(
      /([?&](?:access_token|refresh_token|id_token|api_key|apikey|key|token|secret|password|passwd|pwd|session|sid|auth|authorization|jwt|bearer|sig|signature|client_secret|code|state)=)[^&#\s]+/gi,
      "$1[REDACTED]"
    )
    .replace(new RegExp(`\\b${keywords}\\b(\\s*[:=]\\s*)(['"])(.*?)(['"])`, "gi"), "$1$2$3[REDACTED]$5")
    .replace(new RegExp(`\\b${keywords}\\b(\\s*[:=]\\s*)([^\\s,}\\]\\n]+)`, "gi"), "$1$2[REDACTED]");
}

function isSecretLikeObjectKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/-/g, "_");
  if (normalized.includes("redacted") || normalized.endsWith("_count")) {
    return false;
  }
  return [
    "secret_key",
    "django_secret_key",
    "client_secret",
    "private_key",
    "database_url",
    "redis_url",
    "api_key",
    "apikey",
    "password",
    "passwd",
    "token",
    "secret"
  ].some((token) => normalized.includes(token));
}

function sensitiveFilesFromValues(value: unknown, detectedFiles: SecretsReviewFile[]): SecretsReviewFile[] {
  if (Array.isArray(value)) {
    return filesFromValue(value);
  }
  return detectedFiles.filter((item) => !item.read && (item.category === "env_sensitive" || item.category === "sensitive_file"));
}

function reviewedFilesFromValues(value: unknown, detectedFiles: SecretsReviewFile[]): SecretsReviewFile[] {
  if (Array.isArray(value)) {
    return filesFromValue(value).map((item) => ({ ...item, read: true }));
  }
  return detectedFiles.filter((item) => item.read);
}

function filesFromValue(value: unknown): SecretsReviewFile[] {
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

function findingsFromValue(value: unknown): SecretsReviewFinding[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      id: asString(record?.id) ?? asString(record?.code) ?? "finding",
      title: asString(record?.title) ?? asString(record?.message) ?? "Secret review finding",
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

function groupFindingsByLevel(findings: SecretsReviewFinding[]): SecretsFindingGroup[] {
  const order = ["critical", "high", "medium", "low", "info", "review", "unknown"];
  const groups = new Map<string, SecretsReviewFinding[]>();
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
