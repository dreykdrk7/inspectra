import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type DjangoConfigFinding = {
  id: string;
  title: string;
  level: string;
  description: string;
  evidence: string;
  recommendation: string;
  filePath: string | null;
};

export type DjangoDetectedFile = {
  path: string;
  category: string;
  read: boolean;
  skipReason: string | null;
  sizeBytes: number | null;
};

export type DjangoConfigAuditReport = {
  isDjangoConfigAudit: boolean;
  analyzer: string | null;
  archiveType: string | null;
  summary: MetadataEntry[];
  limits: MetadataEntry[];
  detectedFiles: DjangoDetectedFile[];
  signals: MetadataEntry[];
  findings: DjangoConfigFinding[];
  errors: string[];
  truncated: boolean;
  secretsRedactedCount: number;
};

export function buildDjangoConfigAuditReport(job: JobRecord): DjangoConfigAuditReport {
  const result = asRecord(redactDjangoConfigValue(job.result));
  const summary = asRecord(result?.summary);
  return {
    isDjangoConfigAudit: job.audit_type === "django_config_basic",
    analyzer: asString(result?.analyzer),
    archiveType: asString(result?.archive_type),
    summary: entriesFromRecord(summary),
    limits: entriesFromRecord(asRecord(result?.limits)),
    detectedFiles: detectedFilesFromValue(result?.detected_files),
    signals: entriesFromRecord(asRecord(result?.django_signals)),
    findings: findingsFromValue(result?.findings),
    errors: asStringArray(result?.errors),
    truncated: Boolean(summary?.truncated),
    secretsRedactedCount: asNumber(summary?.secrets_redacted_count) ?? 0
  };
}

export function redactDjangoConfigValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactDjangoSecretText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactDjangoConfigValue(item));
  }
  const record = asRecord(value);
  if (record) {
    return Object.fromEntries(Object.entries(record).map(([key, item]) => [key, redactDjangoConfigValue(item)]));
  }
  return value;
}

function redactDjangoSecretText(value: string): string {
  const keywords = "(SECRET_KEY|PASSWORD|PASS|TOKEN|API_KEY|SECRET|DATABASE_URL|REDIS_URL|EMAIL_HOST_PASSWORD|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY)";
  return value
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi, "[REDACTED PRIVATE KEY]")
    .replace(/django-insecure-[^\s'"<>)\]}]+/gi, "django-insecure-[REDACTED]")
    .replace(/\b((?:postgres(?:ql)?|mysql|redis|https?):\/\/[^:/@\s]+):([^@\s]+)@/gi, "$1:[REDACTED]@")
    .replace(/\b((?:postgres(?:ql)?|mysql|redis|https?):\/\/):([^@\s]+)@/gi, "$1:[REDACTED]@")
    .replace(new RegExp(`\\b${keywords}\\b(\\s*[:=]\\s*)(['"])(.*?)(['"])`, "gi"), "$1$2$3[REDACTED]$5")
    .replace(new RegExp(`\\b${keywords}\\b(\\s*[:=]\\s*)([^\\s,}\\n]+)`, "gi"), "$1$2[REDACTED]");
}

function detectedFilesFromValue(value: unknown): DjangoDetectedFile[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? "",
      category: asString(record?.category) ?? "unknown",
      read: Boolean(record?.read),
      skipReason: asString(record?.skip_reason),
      sizeBytes: asNumber(record?.size_bytes)
    };
  });
}

function findingsFromValue(value: unknown): DjangoConfigFinding[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      id: asString(record?.id) ?? "finding",
      title: asString(record?.title) ?? "Informational finding",
      level: asString(record?.level) ?? asString(record?.severity) ?? "info",
      description: asString(record?.description) ?? "",
      evidence: asString(record?.evidence) ?? "",
      recommendation: asString(record?.recommendation) ?? "",
      filePath: asString(record?.file_path)
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
  return typeof value === "string" && value.trim() ? value : null;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.trim().length > 0) : [];
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
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
