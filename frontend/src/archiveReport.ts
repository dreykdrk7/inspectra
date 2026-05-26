import type { FileRecord, JobRecord } from "./types";
import type { MetadataEntry } from "./pdfReport";

export type ArchiveFinding = {
  id: string;
  title: string;
  level: string;
  description: string;
  evidence: string;
  recommendation: string;
};

export type ArchiveEntry = {
  path: string;
  type: string;
  size: number | null;
  compressedSize: number | null;
  mode: string | null;
  depth: number | null;
  flags: MetadataEntry[];
  linkTarget: string | null;
};

export type ArchiveManifest = {
  path: string;
  manifestType: string;
};

export type ArchiveAuditReport = {
  isArchiveAudit: boolean;
  analyzer: string | null;
  completedAt: string | null;
  archiveType: string | null;
  hashes: MetadataEntry[];
  fileInfo: {
    originalFilename: string | null;
    sizeBytes: number | null;
  };
  summary: MetadataEntry[];
  detectedManifests: ArchiveManifest[];
  findings: ArchiveFinding[];
  entriesSample: ArchiveEntry[];
  errors: string[];
};

export function buildArchiveAuditReport(job: JobRecord, file?: FileRecord): ArchiveAuditReport {
  const result = asRecord(job.result);
  const fileIdentification = asRecord(result?.file_identification);

  return {
    isArchiveAudit: job.audit_type === "archive_basic",
    analyzer: asString(result?.analyzer),
    completedAt: asString(result?.completed_at),
    archiveType: asString(result?.archive_type),
    hashes: entriesFromRecord(asRecord(result?.hashes)),
    fileInfo: {
      originalFilename: asString(fileIdentification?.original_filename) ?? file?.original_filename ?? null,
      sizeBytes: asNumber(fileIdentification?.size_bytes) ?? file?.size_bytes ?? null
    },
    summary: entriesFromRecord(asRecord(result?.summary)),
    detectedManifests: manifestsFromValue(result?.detected_manifests),
    findings: findingsFromValue(result?.findings),
    entriesSample: entriesFromValue(result?.entries_sample),
    errors: asStringArray(result?.errors)
  };
}

function manifestsFromValue(value: unknown): ArchiveManifest[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? "unknown",
      manifestType: asString(record?.manifest_type) ?? "manifest"
    };
  });
}

function findingsFromValue(value: unknown): ArchiveFinding[] {
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

function entriesFromValue(value: unknown): ArchiveEntry[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? "unknown",
      type: asString(record?.type) ?? "unknown",
      size: asNumber(record?.size),
      compressedSize: asNumber(record?.compressed_size),
      mode: asString(record?.mode),
      depth: asNumber(record?.depth),
      flags: entriesFromRecord(asRecord(record?.flags)).filter((entry) => entry.value === "true"),
      linkTarget: asString(record?.link_target)
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
