import type { MetadataEntry } from "./pdfReport";
import type { FileRecord, JobRecord } from "./types";

export type ProjectArchiveFinding = {
  id: string;
  title: string;
  level: string;
  description: string;
  evidence: string;
  recommendation: string;
};

export type ProjectArchiveManifest = {
  path: string;
  manifestType: string;
  status: string | null;
  reason: string | null;
  sizeBytes: number | null;
};

export type ParsedProjectManifest = {
  path: string;
  manifestType: string;
  sizeBytes: number | null;
  project: MetadataEntry[];
  dependencies: Array<{ name: string; dependencies: Array<{ name: string; specifier: string; source: string | null }> }>;
  scripts: MetadataEntry[];
  findings: ProjectArchiveFinding[];
  errors: string[];
};

export type ProjectArchiveAuditReport = {
  isProjectArchiveAudit: boolean;
  analyzer: string | null;
  completedAt: string | null;
  archiveType: string | null;
  hashes: MetadataEntry[];
  fileInfo: {
    originalFilename: string | null;
    sizeBytes: number | null;
  };
  summary: MetadataEntry[];
  limits: MetadataEntry[];
  supportedManifests: ProjectArchiveManifest[];
  unsupportedManifests: ProjectArchiveManifest[];
  parsedManifests: ParsedProjectManifest[];
  findings: ProjectArchiveFinding[];
  errors: string[];
};

export function buildProjectArchiveAuditReport(job: JobRecord, file?: FileRecord): ProjectArchiveAuditReport {
  const result = asRecord(job.result);
  const fileIdentification = asRecord(result?.file_identification);

  return {
    isProjectArchiveAudit: job.audit_type === "project_archive_basic",
    analyzer: asString(result?.analyzer),
    completedAt: asString(result?.completed_at),
    archiveType: asString(result?.archive_type),
    hashes: entriesFromRecord(asRecord(result?.hashes)),
    fileInfo: {
      originalFilename: asString(fileIdentification?.original_filename) ?? file?.original_filename ?? null,
      sizeBytes: asNumber(fileIdentification?.size_bytes) ?? file?.size_bytes ?? null
    },
    summary: entriesFromRecord(asRecord(result?.summary)),
    limits: entriesFromRecord(asRecord(result?.limits)),
    supportedManifests: manifestsFromValue(result?.supported_manifests),
    unsupportedManifests: manifestsFromValue(result?.unsupported_manifests),
    parsedManifests: parsedManifestsFromValue(result?.parsed_manifests),
    findings: findingsFromValue(result?.findings),
    errors: asStringArray(result?.errors)
  };
}

function manifestsFromValue(value: unknown): ProjectArchiveManifest[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? "unknown",
      manifestType: asString(record?.manifest_type) ?? asString(record?.manifest_name) ?? "manifest",
      status: asString(record?.status),
      reason: asString(record?.reason),
      sizeBytes: asNumber(record?.size_bytes)
    };
  });
}

function parsedManifestsFromValue(value: unknown): ParsedProjectManifest[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    const parsed = asRecord(record?.parsed);
    return {
      path: asString(record?.path) ?? "unknown",
      manifestType: asString(record?.manifest_type) ?? "manifest",
      sizeBytes: asNumber(record?.size_bytes),
      project: entriesFromRecord(asRecord(parsed?.project)),
      dependencies: dependencyGroupsFromRecord(asRecord(parsed?.dependencies)),
      scripts: entriesFromRecord(asRecord(parsed?.scripts)),
      findings: findingsFromValue(record?.findings),
      errors: asStringArray(record?.errors)
    };
  });
}

function dependencyGroupsFromRecord(record: Record<string, unknown> | null) {
  if (!record) {
    return [];
  }
  return Object.entries(record).map(([name, value]) => ({
    name,
    dependencies: Array.isArray(value) ? value.map(dependencyFromValue).filter((item): item is { name: string; specifier: string; source: string | null } => item !== null) : []
  }));
}

function dependencyFromValue(value: unknown): { name: string; specifier: string; source: string | null } | null {
  const record = asRecord(value);
  if (!record) {
    return null;
  }
  return {
    name: asString(record.name) ?? "unknown",
    specifier: asString(record.specifier) ?? "",
    source: asString(record.source)
  };
}

function findingsFromValue(value: unknown): ProjectArchiveFinding[] {
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
      recommendation: asString(record?.recommendation) ?? ""
    };
  });
}

function entriesFromRecord(record: Record<string, unknown> | null): MetadataEntry[] {
  if (!record) {
    return [];
  }
  return Object.entries(record)
    .filter(([, value]) => isPresent(value))
    .map(([label, value]) => ({ label, value: stringifyValue(value) }));
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.trim().length > 0) : [];
}

function isPresent(value: unknown): boolean {
  return value !== null && value !== undefined && value !== "";
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
