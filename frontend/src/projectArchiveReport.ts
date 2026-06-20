import type { MetadataEntry } from "./pdfReport";
import type { FileRecord, JobRecord } from "./types";

export type ProjectArchiveFinding = {
  id: string;
  title: string;
  level: string;
  category: string;
  categoryLabel: string;
  ecosystem: string;
  ecosystemLabel: string;
  description: string;
  evidence: string;
  recommendation: string;
};

type ProjectArchiveFindingMetadata = {
  category: string;
  categoryLabel: string;
  ecosystem: string;
  ecosystemLabel: string;
};

export type ProjectArchiveEcosystemSummary = {
  ecosystem: string;
  ecosystemLabel: string;
  findingsCount: number;
};

const UNCATEGORIZED_PROJECT_ARCHIVE_FINDING = {
  category: "uncategorized_review_indicator",
  categoryLabel: "Uncategorized review indicator",
  ecosystem: "unknown_ecosystem",
  ecosystemLabel: "Unknown ecosystem"
} satisfies ProjectArchiveFindingMetadata;

const PROJECT_ARCHIVE_ECOSYSTEM_LABELS: Record<string, string> = {
  python_requirements: "Python / requirements",
  node_package: "Node / package.json",
  docker_compose: "Docker / Compose",
  ci_cd: "CI/CD",
  framework_config: "Framework/config",
  generic_project_metadata: "Generic project metadata",
  unknown_ecosystem: "Unknown ecosystem"
};

const PROJECT_ARCHIVE_FINDING_METADATA: Record<string, ProjectArchiveFindingMetadata> = {
  dependency_not_exactly_pinned: {
    category: "dependency_hygiene",
    categoryLabel: "Dependency hygiene",
    ecosystem: "unknown_ecosystem",
    ecosystemLabel: "Unknown ecosystem"
  },
  requirements_dependency_not_exactly_pinned: pythonRequirementsMetadata("dependency_hygiene", "Dependency hygiene"),
  dependency_broad_range: unknownEcosystemMetadata("dependency_hygiene", "Dependency hygiene"),
  requirements_option_present: pythonRequirementsMetadata("dependency_hygiene", "Dependency hygiene"),
  dependency_external_or_local_source: unknownEcosystemMetadata("dependency_source_review", "Dependency source review"),
  requirements_custom_index: pythonRequirementsMetadata("dependency_source_review", "Dependency source review"),
  requirements_editable_install: pythonRequirementsMetadata("dependency_source_review", "Dependency source review"),
  package_scripts_present: nodePackageMetadata("package_script_review", "Package script review"),
  package_sensitive_lifecycle_script: nodePackageMetadata("package_script_review", "Package script review"),
  project_archive_multiple_ecosystems: genericProjectMetadata("ecosystem_inventory", "Ecosystem inventory"),
  project_archive_manifest_parse_error: unknownEcosystemMetadata("manifest_parse_limits", "Manifest parsing and limits"),
  project_archive_manifest_read_error: unknownEcosystemMetadata("manifest_parse_limits", "Manifest parsing and limits"),
  project_archive_manifest_decode_error: unknownEcosystemMetadata("manifest_parse_limits", "Manifest parsing and limits"),
  project_archive_manifest_too_large: unknownEcosystemMetadata("manifest_parse_limits", "Manifest parsing and limits"),
  project_archive_too_many_supported_manifests: unknownEcosystemMetadata("manifest_parse_limits", "Manifest parsing and limits"),
  project_archive_total_manifest_bytes_limit: unknownEcosystemMetadata("manifest_parse_limits", "Manifest parsing and limits"),
  project_archive_entry_name_too_long: genericProjectMetadata("manifest_parse_limits", "Manifest parsing and limits"),
  project_archive_entry_limit_reached: genericProjectMetadata("archive_safety_metadata", "Archive safety metadata"),
  project_archive_path_traversal: genericProjectMetadata("archive_safety_metadata", "Archive safety metadata"),
  project_archive_absolute_path: genericProjectMetadata("archive_safety_metadata", "Archive safety metadata"),
  project_archive_manifest_not_regular_file: genericProjectMetadata("archive_safety_metadata", "Archive safety metadata"),
  project_archive_zip_entry_limit_preflight: genericProjectMetadata("archive_safety_metadata", "Archive safety metadata"),
  project_archive_zip_central_directory_too_large: genericProjectMetadata("archive_safety_metadata", "Archive safety metadata"),
  project_archive_zip64_metadata_requires_review: genericProjectMetadata("archive_safety_metadata", "Archive safety metadata"),
  project_archive_multidisk_zip_unsupported: genericProjectMetadata("archive_safety_metadata", "Archive safety metadata"),
  project_archive_zip_metadata_preflight_unavailable: genericProjectMetadata("archive_safety_metadata", "Archive safety metadata")
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
  ecosystemSummary: ProjectArchiveEcosystemSummary[];
  findings: ProjectArchiveFinding[];
  errors: string[];
};

export function buildProjectArchiveAuditReport(job: JobRecord, file?: FileRecord): ProjectArchiveAuditReport {
  const result = asRecord(job.result);
  const fileIdentification = asRecord(result?.file_identification);

  const findings = findingsFromValue(result?.findings);

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
    ecosystemSummary: ecosystemSummaryFromValue(result?.ecosystem_summary, findings),
    findings,
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
      findings: findingsFromValue(record?.findings, {
        path: asString(record?.path),
        manifestType: asString(record?.manifest_type)
      }),
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

function findingsFromValue(value: unknown, context?: { path?: string | null; manifestType?: string | null }): ProjectArchiveFinding[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    const id = asString(record?.id) ?? "finding";
    const metadata = projectArchiveFindingMetadata(id, {
      evidence: asString(record?.evidence),
      path: context?.path,
      manifestType: context?.manifestType
    });
    const category = asString(record?.category) ?? metadata.category;
    const ecosystem = asString(record?.ecosystem) ?? metadata.ecosystem;
    return {
      id,
      title: asString(record?.title) ?? "Informational finding",
      level: asString(record?.level) ?? asString(record?.severity) ?? "info",
      category,
      categoryLabel: asString(record?.category_label) ?? asString(record?.categoryLabel) ?? metadata.categoryLabel,
      ecosystem,
      ecosystemLabel:
        asString(record?.ecosystem_label) ??
        asString(record?.ecosystemLabel) ??
        PROJECT_ARCHIVE_ECOSYSTEM_LABELS[ecosystem] ??
        metadata.ecosystemLabel,
      description: asString(record?.description) ?? "",
      evidence: asString(record?.evidence) ?? "",
      recommendation: asString(record?.recommendation) ?? ""
    };
  });
}

function projectArchiveFindingMetadata(
  findingId: string,
  context: { evidence?: string | null; path?: string | null; manifestType?: string | null } = {}
): ProjectArchiveFindingMetadata {
  const metadata = PROJECT_ARCHIVE_FINDING_METADATA[findingId] ?? UNCATEGORIZED_PROJECT_ARCHIVE_FINDING;
  if (!CONTEXTUAL_ECOSYSTEM_FINDING_IDS.has(findingId)) {
    return metadata;
  }
  const ecosystem = inferProjectArchiveEcosystem(context);
  return ecosystem ? { ...metadata, ecosystem: ecosystem.id, ecosystemLabel: ecosystem.label } : metadata;
}

function ecosystemSummaryFromValue(value: unknown, findings: ProjectArchiveFinding[]): ProjectArchiveEcosystemSummary[] {
  if (Array.isArray(value)) {
    return value
      .map((item) => {
        const record = asRecord(item);
        if (!record) {
          return null;
        }
        return {
          ecosystem: asString(record.ecosystem) ?? "unknown_ecosystem",
          ecosystemLabel: asString(record.ecosystem_label) ?? asString(record.ecosystemLabel) ?? "Unknown ecosystem",
          findingsCount: asNumber(record.findings_count) ?? asNumber(record.findingsCount) ?? 0
        };
      })
      .filter((item): item is ProjectArchiveEcosystemSummary => item !== null);
  }

  const groups = new Map<string, ProjectArchiveEcosystemSummary>();
  findings.forEach((finding) => {
    const group = groups.get(finding.ecosystem) ?? {
      ecosystem: finding.ecosystem,
      ecosystemLabel: finding.ecosystemLabel,
      findingsCount: 0
    };
    group.findingsCount += 1;
    groups.set(finding.ecosystem, group);
  });
  return Array.from(groups.values()).sort(compareEcosystemSummary);
}

const CONTEXTUAL_ECOSYSTEM_FINDING_IDS = new Set([
  "dependency_not_exactly_pinned",
  "dependency_broad_range",
  "dependency_external_or_local_source",
  "project_archive_manifest_parse_error",
  "project_archive_manifest_read_error",
  "project_archive_manifest_decode_error",
  "project_archive_manifest_too_large"
]);

function inferProjectArchiveEcosystem(context: {
  evidence?: string | null;
  path?: string | null;
  manifestType?: string | null;
}): { id: string; label: string } | null {
  const normalized = [context.path, context.manifestType, context.evidence]
    .filter((value): value is string => typeof value === "string" && value.trim().length > 0)
    .join(" ")
    .replace(/\\/g, "/")
    .toLowerCase();
  if (!normalized) {
    return null;
  }
  if (["package.json", "package-lock.json", "package_json", "package-lock"].some((marker) => normalized.includes(marker))) {
    return { id: "node_package", label: PROJECT_ARCHIVE_ECOSYSTEM_LABELS.node_package };
  }
  if (["requirements.txt", "requirements_txt", "pyproject.toml", "pyproject_toml"].some((marker) => normalized.includes(marker))) {
    return { id: "python_requirements", label: PROJECT_ARCHIVE_ECOSYSTEM_LABELS.python_requirements };
  }
  if (["docker-compose.yml", "docker-compose.yaml", "compose.yaml", "compose.yml"].some((marker) => normalized.includes(marker))) {
    return { id: "docker_compose", label: PROJECT_ARCHIVE_ECOSYSTEM_LABELS.docker_compose };
  }
  if ([".github/workflows/", ".gitlab-ci.yml", "circleci/config.yml", "jenkinsfile"].some((marker) => normalized.includes(marker))) {
    return { id: "ci_cd", label: PROJECT_ARCHIVE_ECOSYSTEM_LABELS.ci_cd };
  }
  if (["vite.config.", "next.config.", "nuxt.config.", "django", "settings.py"].some((marker) => normalized.includes(marker))) {
    return { id: "framework_config", label: PROJECT_ARCHIVE_ECOSYSTEM_LABELS.framework_config };
  }
  return null;
}

function pythonRequirementsMetadata(category: string, categoryLabel: string): ProjectArchiveFindingMetadata {
  return {
    category,
    categoryLabel,
    ecosystem: "python_requirements",
    ecosystemLabel: PROJECT_ARCHIVE_ECOSYSTEM_LABELS.python_requirements
  };
}

function nodePackageMetadata(category: string, categoryLabel: string): ProjectArchiveFindingMetadata {
  return {
    category,
    categoryLabel,
    ecosystem: "node_package",
    ecosystemLabel: PROJECT_ARCHIVE_ECOSYSTEM_LABELS.node_package
  };
}

function genericProjectMetadata(category: string, categoryLabel: string): ProjectArchiveFindingMetadata {
  return {
    category,
    categoryLabel,
    ecosystem: "generic_project_metadata",
    ecosystemLabel: PROJECT_ARCHIVE_ECOSYSTEM_LABELS.generic_project_metadata
  };
}

function unknownEcosystemMetadata(category: string, categoryLabel: string): ProjectArchiveFindingMetadata {
  return { category, categoryLabel, ecosystem: "unknown_ecosystem", ecosystemLabel: PROJECT_ARCHIVE_ECOSYSTEM_LABELS.unknown_ecosystem };
}

function compareEcosystemSummary(a: ProjectArchiveEcosystemSummary, b: ProjectArchiveEcosystemSummary): number {
  if (a.ecosystem === "unknown_ecosystem" && b.ecosystem !== "unknown_ecosystem") {
    return 1;
  }
  if (a.ecosystem !== "unknown_ecosystem" && b.ecosystem === "unknown_ecosystem") {
    return -1;
  }
  return a.ecosystemLabel.localeCompare(b.ecosystemLabel);
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
