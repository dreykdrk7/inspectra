import { redactDjangoConfigValue } from "./djangoConfigReport";
import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type DockerConfigFinding = {
  id: string;
  title: string;
  level: string;
  category: string | null;
  description: string;
  evidence: string;
  recommendation: string;
  filePath: string | null;
  context: string | null;
  service: string | null;
  stage: string | null;
};

export type DockerDetectedFile = {
  path: string;
  category: string;
  read: boolean;
  skipReason: string | null;
  sizeBytes: number | null;
  context: string | null;
};

export type DockerfileStage = {
  filePath: string;
  context: string | null;
  stage: string | null;
  baseImage: string | null;
  userObserved: boolean | null;
  healthcheckObserved: boolean | null;
};

export type ComposeService = {
  filePath: string;
  name: string;
  context: string | null;
  image: string | null;
  ports: string[];
  privileged: boolean | null;
  readOnly: boolean | null;
  networkMode: string | null;
};

export type DockerFindingGroup = {
  level: string;
  findings: DockerConfigFinding[];
};

export type DockerConfigAuditReport = {
  isDockerConfigAudit: boolean;
  analyzer: string | null;
  archiveType: string | null;
  overview: MetadataEntry[];
  summary: MetadataEntry[];
  limits: MetadataEntry[];
  detectedFiles: DockerDetectedFile[];
  reviewedFiles: DockerDetectedFile[];
  stages: DockerfileStage[];
  composeServices: ComposeService[];
  findings: DockerConfigFinding[];
  findingGroups: DockerFindingGroup[];
  redactionNotes: string[];
  errors: string[];
  truncated: boolean;
  secretsRedactedCount: number;
  findingsCount: number;
  filesReviewedCount: number;
  dockerfilesDetectedCount: number;
  composeFilesDetectedCount: number;
  servicesDetectedCount: number;
};

export function buildDockerConfigAuditReport(job: JobRecord): DockerConfigAuditReport {
  const result = asRecord(redactDockerConfigValue(job.result));
  const summary = asRecord(result?.summary);
  const detectedFiles = detectedFilesFromValue(result?.files_detected);
  const reviewedFiles = filesReviewedFromValues(result?.files_reviewed, detectedFiles);
  const stages = stagesFromValue(result?.dockerfile_stages);
  const composeServices = composeServicesFromValue(result?.compose_services);
  const findings = findingsFromValue(result?.findings);
  const findingsCount = asNumber(summary?.findings_count) ?? findings.length;
  const filesReviewedCount = asNumber(summary?.files_reviewed) ?? reviewedFiles.length;
  const dockerfilesDetectedCount = asNumber(summary?.dockerfiles_detected) ?? detectedFiles.filter((item) => item.category === "dockerfile").length;
  const composeFilesDetectedCount = asNumber(summary?.compose_files_detected) ?? detectedFiles.filter((item) => item.category === "compose").length;
  const servicesDetectedCount = asNumber(summary?.services_detected) ?? composeServices.length;
  const truncated = Boolean(summary?.truncated) || Boolean(result?.truncated);
  const errors = asStringArray(result?.errors);
  const reportStatus = truncated ? `${job.status} (truncated)` : errors.length > 0 ? `${job.status} with errors` : job.status;

  return {
    isDockerConfigAudit: job.audit_type === "docker_config_basic" || asString(result?.analyzer) === "docker_config_basic",
    analyzer: asString(result?.analyzer),
    archiveType: asString(result?.archive_type),
    overview: [
      { label: "Files reviewed", value: String(filesReviewedCount) },
      { label: "Dockerfiles", value: String(dockerfilesDetectedCount) },
      { label: "Compose files", value: String(composeFilesDetectedCount) },
      { label: "Services", value: String(servicesDetectedCount) },
      { label: "Findings", value: String(findingsCount) },
      { label: "Status", value: reportStatus }
    ],
    summary: entriesFromRecord(summary),
    limits: entriesFromRecord(asRecord(result?.limits)),
    detectedFiles,
    reviewedFiles,
    stages,
    composeServices,
    findings,
    findingGroups: groupFindingsByLevel(findings),
    redactionNotes: asStringArray(result?.redaction_notes),
    errors,
    truncated,
    secretsRedactedCount: asNumber(summary?.secrets_redacted_count) ?? 0,
    findingsCount,
    filesReviewedCount,
    dockerfilesDetectedCount,
    composeFilesDetectedCount,
    servicesDetectedCount
  };
}

export function redactDockerConfigValue(value: unknown): unknown {
  return redactDjangoConfigValue(value);
}

function detectedFilesFromValue(value: unknown): DockerDetectedFile[] {
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
      sizeBytes: asNumber(record?.size_bytes),
      context: asString(record?.context)
    };
  });
}

function filesReviewedFromValues(value: unknown, detectedFiles: DockerDetectedFile[]): DockerDetectedFile[] {
  if (!Array.isArray(value)) {
    return detectedFiles.filter((item) => item.read);
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      path: asString(record?.path) ?? "",
      category: asString(record?.category) ?? "unknown",
      read: true,
      skipReason: null,
      sizeBytes: asNumber(record?.size_bytes) ?? asNumber(record?.bytes_read),
      context: asString(record?.context)
    };
  });
}

function stagesFromValue(value: unknown): DockerfileStage[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      filePath: asString(record?.file_path) ?? "",
      context: asString(record?.context),
      stage: asString(record?.stage),
      baseImage: asString(record?.base_image),
      userObserved: asBoolean(record?.user_observed),
      healthcheckObserved: asBoolean(record?.healthcheck_observed)
    };
  });
}

function composeServicesFromValue(value: unknown): ComposeService[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      filePath: asString(record?.file_path) ?? "",
      name: asString(record?.name) ?? asString(record?.service) ?? "service",
      context: asString(record?.context),
      image: asString(record?.image),
      ports: asStringArray(record?.ports),
      privileged: asBoolean(record?.privileged),
      readOnly: asBoolean(record?.read_only),
      networkMode: asString(record?.network_mode)
    };
  });
}

function findingsFromValue(value: unknown): DockerConfigFinding[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      id: asString(record?.id) ?? "finding",
      title: asString(record?.title) ?? "Informational finding",
      level: normalizeFindingLevel(asString(record?.level) ?? asString(record?.severity)),
      category: asString(record?.category),
      description: asString(record?.description) ?? "",
      evidence: asString(record?.evidence) ?? "",
      recommendation: asString(record?.recommendation) ?? "",
      filePath: asString(record?.file_path),
      context: asString(record?.context),
      service: asString(record?.service),
      stage: asString(record?.stage)
    };
  });
}

function groupFindingsByLevel(findings: DockerConfigFinding[]): DockerFindingGroup[] {
  const order = ["critical", "high", "medium", "low", "info", "review", "unknown"];
  const groups = new Map<string, DockerConfigFinding[]>();
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
