import type { FileRecord, JobRecord } from "./types";
import type { MetadataEntry } from "./pdfReport";

export type DependencyEntry = {
  name: string;
  specifier: string;
  source: string | null;
};

export type DependencyGroup = {
  name: string;
  dependencies: DependencyEntry[];
};

export type ManifestFinding = {
  id: string;
  title: string;
  level: string;
  description: string;
  evidence: string;
  recommendation: string;
};

export type ManifestAuditReport = {
  isManifestAudit: boolean;
  analyzer: string | null;
  completedAt: string | null;
  manifestType: string | null;
  hashes: MetadataEntry[];
  fileInfo: {
    originalFilename: string | null;
    sizeBytes: number | null;
  };
  project: MetadataEntry[];
  dependencies: DependencyGroup[];
  scripts: MetadataEntry[];
  engines: MetadataEntry[];
  summary: {
    totalDependencies: number | null;
    dependencyGroups: string[];
    informationalFindingsCount: number | null;
  };
  findings: ManifestFinding[];
  errors: string[];
};

export function buildManifestAuditReport(job: JobRecord, file?: FileRecord): ManifestAuditReport {
  const result = asRecord(job.result);
  const parsed = asRecord(result?.parsed);
  const fileIdentification = asRecord(result?.file_identification);
  const summary = asRecord(result?.summary);

  return {
    isManifestAudit: job.audit_type === "manifest_basic",
    analyzer: asString(result?.analyzer),
    completedAt: asString(result?.completed_at),
    manifestType: asString(result?.manifest_type),
    hashes: entriesFromRecord(asRecord(result?.hashes)),
    fileInfo: {
      originalFilename: asString(fileIdentification?.original_filename) ?? file?.original_filename ?? null,
      sizeBytes: asNumber(fileIdentification?.size_bytes) ?? file?.size_bytes ?? null
    },
    project: entriesFromRecord(asRecord(parsed?.project)),
    dependencies: dependencyGroupsFromRecord(asRecord(parsed?.dependencies)),
    scripts: entriesFromRecord(asRecord(parsed?.scripts)),
    engines: entriesFromRecord(asRecord(parsed?.engines)),
    summary: {
      totalDependencies: asNumber(summary?.total_dependencies),
      dependencyGroups: asStringArray(summary?.dependency_groups),
      informationalFindingsCount: asNumber(summary?.informational_findings_count)
    },
    findings: findingsFromValue(result?.findings),
    errors: asStringArray(result?.errors)
  };
}

function dependencyGroupsFromRecord(record: Record<string, unknown> | null): DependencyGroup[] {
  if (!record) {
    return [];
  }
  return Object.entries(record).map(([name, value]) => ({
    name,
    dependencies: Array.isArray(value) ? value.map(dependencyFromValue).filter((item): item is DependencyEntry => item !== null) : []
  }));
}

function dependencyFromValue(value: unknown): DependencyEntry | null {
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

function findingsFromValue(value: unknown): ManifestFinding[] {
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
