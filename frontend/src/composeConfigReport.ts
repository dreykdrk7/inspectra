import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type ComposeFile = {
  path: string;
  category: string;
  read: boolean;
  skipReason: string | null;
  sizeBytes: number | null;
  bytesRead: number | null;
  context: string | null;
};

export type ComposeService = {
  name: string | null;
  filePath: string;
  context: string | null;
  image: string | null;
  build: string | null;
  restart: string | null;
  healthcheck: boolean | null;
  readOnly: boolean | null;
  privileged: boolean | null;
  user: string | null;
  networkMode: string | null;
};

export type ComposeImage = {
  service: string | null;
  image: string | null;
  tag: string | null;
  digest: string | null;
  filePath: string;
  context: string | null;
};

export type ComposeBuildContext = {
  service: string | null;
  contextPath: string | null;
  dockerfile: string | null;
  filePath: string;
  context: string | null;
};

export type ComposePort = {
  service: string | null;
  hostIp: string | null;
  published: string | null;
  target: string | null;
  protocol: string | null;
  mode: string | null;
  filePath: string;
  context: string | null;
};

export type ComposeVolume = {
  service: string | null;
  source: string | null;
  hostPath: string | null;
  target: string | null;
  readOnly: boolean | null;
  type: string | null;
  filePath: string;
  context: string | null;
};

export type ComposeNetwork = {
  name: string | null;
  service: string | null;
  external: boolean | null;
  internal: boolean | null;
  filePath: string;
  context: string | null;
};

export type ComposeSecret = {
  name: string | null;
  service: string | null;
  file: string | null;
  fieldPath: string | null;
  read: boolean | null;
  skipReason: string | null;
  filePath: string;
  context: string | null;
};

export type ComposeEnvFile = {
  service: string | null;
  path: string | null;
  read: boolean | null;
  skipReason: string | null;
  filePath: string;
  context: string | null;
};

export type ComposeFinding = {
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
  service: string | null;
  fieldPath: string | null;
  image: string | null;
  port: string | null;
  protocol: string | null;
  hostPath: string | null;
  containerPath: string | null;
  network: string | null;
};

export type ComposeFindingGroup = {
  level: string;
  findings: ComposeFinding[];
};

export type ComposeConfigAuditReport = {
  isComposeConfigAudit: boolean;
  analyzer: string | null;
  archiveType: string | null;
  overview: MetadataEntry[];
  summary: MetadataEntry[];
  limits: MetadataEntry[];
  detectedFiles: ComposeFile[];
  reviewedFiles: ComposeFile[];
  services: ComposeService[];
  ports: ComposePort[];
  volumes: ComposeVolume[];
  networks: ComposeNetwork[];
  secrets: ComposeSecret[];
  envFiles: ComposeEnvFile[];
  buildContexts: ComposeBuildContext[];
  images: ComposeImage[];
  findings: ComposeFinding[];
  findingGroups: ComposeFindingGroup[];
  redactionNotes: string[];
  errors: string[];
  truncated: boolean;
  filesConsideredCount: number;
  filesReviewedCount: number;
  composeFilesDetectedCount: number;
  servicesDetectedCount: number;
  networksDetectedCount: number;
  volumesDetectedCount: number;
  secretsDetectedCount: number;
  publishedPortsDetectedCount: number;
  envFilesDetectedCount: number;
  findingsCount: number;
  redactedValuesCount: number;
};

export function buildComposeConfigAuditReport(job: JobRecord): ComposeConfigAuditReport {
  const result = asRecord(redactComposeConfigValue(job.result));
  const summary = asRecord(result?.summary);
  const detectedFiles = filesFromValue(result?.files_detected);
  const reviewedFiles = reviewedFilesFromValues(result?.files_reviewed, detectedFiles);
  const services = servicesFromValue(result?.services);
  const ports = portsFromValue(result?.ports);
  const volumes = volumesFromValue(result?.volumes);
  const networks = networksFromValue(result?.networks);
  const secrets = secretsFromValue(result?.secrets);
  const envFiles = envFilesFromValue(result?.env_files);
  const buildContexts = buildContextsFromValue(result?.build_contexts);
  const images = imagesFromValue(result?.images);
  const findings = findingsFromValue(result?.findings);
  const filesConsideredCount = asNumber(summary?.files_considered) ?? detectedFiles.length;
  const filesReviewedCount = asNumber(summary?.files_reviewed) ?? reviewedFiles.length;
  const composeFilesDetectedCount = asNumber(summary?.compose_files_detected) ?? detectedFiles.filter((file) => file.category.includes("compose")).length;
  const servicesDetectedCount = asNumber(summary?.services_detected) ?? services.length;
  const networksDetectedCount = asNumber(summary?.networks_detected) ?? networks.length;
  const volumesDetectedCount = asNumber(summary?.volumes_detected) ?? volumes.length;
  const secretsDetectedCount = asNumber(summary?.secrets_detected) ?? secrets.length;
  const publishedPortsDetectedCount = asNumber(summary?.published_ports_detected) ?? ports.length;
  const envFilesDetectedCount = asNumber(summary?.env_files_detected) ?? envFiles.length;
  const findingsCount = asNumber(summary?.findings_count) ?? findings.length;
  const redactedValuesCount = asNumber(summary?.redacted_values_count) ?? 0;
  const truncated = Boolean(summary?.truncated) || Boolean(result?.truncated);
  const errors = asStringArray(result?.errors).map(redactComposeConfigText);
  const reportStatus = truncated ? `${job.status} (truncated)` : errors.length > 0 ? `${job.status} with errors` : job.status;

  return {
    isComposeConfigAudit: job.audit_type === "compose_config_basic" || asString(result?.analyzer) === "compose_config_basic",
    analyzer: asString(result?.analyzer),
    archiveType: asString(result?.archive_type),
    overview: [
      { label: "Files reviewed", value: String(filesReviewedCount) },
      { label: "Services", value: String(servicesDetectedCount) },
      { label: "Ports", value: String(publishedPortsDetectedCount) },
      { label: "Volumes", value: String(volumesDetectedCount) },
      { label: "Env files", value: String(envFilesDetectedCount) },
      { label: "Findings", value: String(findingsCount) },
      { label: "Status", value: reportStatus }
    ],
    summary: entriesFromRecord(summary),
    limits: entriesFromRecord(asRecord(result?.limits)),
    detectedFiles,
    reviewedFiles,
    services,
    ports,
    volumes,
    networks,
    secrets,
    envFiles,
    buildContexts,
    images,
    findings,
    findingGroups: groupFindingsByLevel(findings),
    redactionNotes: asStringArray(result?.redaction_notes).map(redactComposeConfigText),
    errors,
    truncated,
    filesConsideredCount,
    filesReviewedCount,
    composeFilesDetectedCount,
    servicesDetectedCount,
    networksDetectedCount,
    volumesDetectedCount,
    secretsDetectedCount,
    publishedPortsDetectedCount,
    envFilesDetectedCount,
    findingsCount,
    redactedValuesCount
  };
}

export function redactComposeConfigValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactComposeConfigText(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactComposeConfigValue(item));
  }
  const record = asRecord(value);
  if (record) {
    const recordHasSecretName = composeRecordHasSecretName(record);
    return Object.fromEntries(
      Object.entries(record).map(([key, item]) => {
        const normalizedKey = normalizeKey(key);
        const redactValue =
          isComposeSecretValueKey(key) ||
          (recordHasSecretName &&
            [
              "value",
              "raw_value",
              "default",
              "data",
              "content",
              "environment",
              "labels",
              "command",
              "entrypoint",
              "arguments",
              "url",
              "uri"
            ].includes(normalizedKey));
        return [key, redactValue ? "[REDACTED]" : redactComposeConfigValue(item)];
      })
    );
  }
  return value;
}

export function redactComposeConfigText(value: string): string {
  return value
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi, "[REDACTED]")
    .replace(/\bPRIVATE KEY\b/gi, "[REDACTED]")
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)([^:@/\s;'"<>]+):([^@\s;'"<>]+)@/gi, "$1[REDACTED]@")
    .replace(/\b(?:[a-z0-9._-]*user|username|login):(?:[a-z0-9._-]*(?:pass|password|secret|token|key)[a-z0-9._-]*)\b/gi, "[REDACTED]")
    .replace(/\b(?:registry-user:registry-pass|super-secret-password|raw-api-key-[a-z0-9_-]+|token_should_never_render|db_password_plaintext)\b/gi, "[REDACTED]")
    .replace(
      /([?&](?:access_token|refresh_token|id_token|api_key|apikey|key|token|secret|password|passwd|pwd|session|sid|auth|authorization|jwt|bearer|sig|signature|client_secret|code|state)=)[^&#\s]+/gi,
      "$1[REDACTED]"
    )
    .replace(
      /(^|[\s,{])([A-Z0-9_$.-]*(?:DATABASE_URL|REDIS_URL|REGISTRY_AUTH|AUTHORIZATION|COOKIE|SESSION|SECRET|TOKEN|PASSWORD|PASS|API_KEY|APIKEY|PRIVATE_KEY|CLIENT_SECRET|CREDENTIAL|AUTH)[A-Z0-9_$.-]*)(\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2$3$4[REDACTED]"
    )
    .replace(
      /(\b(?:database_url|redis_url|authorization|cookie|session|password|passwd|token|secret|api_key|apikey|private_key|client_secret|credential|auth|registry_auth)\b\s*[:=]\s*)(['"]?)[^\s,'"}\]]+/gi,
      "$1$2[REDACTED]"
    )
    .replace(/\[REDACTED\]\]+/g, "[REDACTED]");
}

function composeRecordHasSecretName(record: Record<string, unknown>): boolean {
  for (const marker of ["key", "name", "setting", "variable", "field_path", "env", "environment", "label", "labels", "command", "entrypoint", "arguments"]) {
    const candidate = record[marker];
    if (typeof candidate === "string" && isComposeSecretValueKey(candidate)) {
      return true;
    }
    if (Array.isArray(candidate) && candidate.some((item) => typeof item === "string" && isComposeSecretValueKey(item))) {
      return true;
    }
  }
  return false;
}

function isComposeSecretValueKey(key: string): boolean {
  const normalized = normalizeKey(key);
  if (normalized.includes("redacted") || normalized.endsWith("_count")) {
    return false;
  }
  if (
    [
      "secret",
      "secrets",
      "secret_name",
      "secrets_detected",
      "env_files",
      "env_files_detected",
      "redaction_notes",
      "skip_reason",
      "reason"
    ].includes(normalized)
  ) {
    return false;
  }
  if (["content", "raw", "raw_content", "private_key_content", "env_file_content", "secret_file_content"].includes(normalized)) {
    return true;
  }
  return [
    "database_url",
    "redis_url",
    "registry_auth",
    "authorization",
    "cookie",
    "session",
    "api_key",
    "apikey",
    "access_key",
    "secret_key",
    "token",
    "client_secret",
    "private_key",
    "password",
    "passwd",
    "credential",
    "auth"
  ].some((token) => normalized.includes(token));
}

function filesFromValue(value: unknown): ComposeFile[] {
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

function reviewedFilesFromValues(value: unknown, detectedFiles: ComposeFile[]): ComposeFile[] {
  if (Array.isArray(value)) {
    return filesFromValue(value).map((item) => ({ ...item, read: true }));
  }
  return detectedFiles.filter((item) => item.read);
}

function servicesFromValue(value: unknown): ComposeService[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      name: asString(record?.name) ?? asString(record?.service),
      filePath: asString(record?.file_path) ?? asString(record?.path) ?? "",
      context: asString(record?.context),
      image: asString(record?.image),
      build: asString(record?.build) ?? asString(record?.build_context),
      restart: asString(record?.restart),
      healthcheck: asBoolean(record?.healthcheck) ?? asBoolean(record?.has_healthcheck),
      readOnly: asBoolean(record?.read_only),
      privileged: asBoolean(record?.privileged),
      user: asString(record?.user),
      networkMode: asString(record?.network_mode)
    };
  });
}

function imagesFromValue(value: unknown): ComposeImage[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      service: asString(record?.service) ?? asString(record?.service_name),
      image: asString(record?.image) ?? asString(record?.reference),
      tag: asString(record?.tag),
      digest: asString(record?.digest),
      filePath: asString(record?.file_path) ?? asString(record?.path) ?? "",
      context: asString(record?.context)
    };
  });
}

function buildContextsFromValue(value: unknown): ComposeBuildContext[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      service: asString(record?.service) ?? asString(record?.service_name),
      contextPath: asString(record?.context_path) ?? asString(record?.context) ?? asString(record?.build),
      dockerfile: asString(record?.dockerfile),
      filePath: asString(record?.file_path) ?? asString(record?.path) ?? "",
      context: asString(record?.route_context) ?? asString(record?.compose_context)
    };
  });
}

function portsFromValue(value: unknown): ComposePort[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      service: asString(record?.service) ?? asString(record?.service_name),
      hostIp: asString(record?.host_ip) ?? asString(record?.host),
      published: asString(record?.published) ?? asString(record?.published_port) ?? asString(record?.host_port),
      target: asString(record?.target) ?? asString(record?.target_port) ?? asString(record?.container_port),
      protocol: asString(record?.protocol) ?? "tcp",
      mode: asString(record?.mode),
      filePath: asString(record?.file_path) ?? asString(record?.path) ?? "",
      context: asString(record?.context)
    };
  });
}

function volumesFromValue(value: unknown): ComposeVolume[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      service: asString(record?.service) ?? asString(record?.service_name),
      source: asString(record?.source) ?? asString(record?.name),
      hostPath: asString(record?.host_path),
      target: asString(record?.target) ?? asString(record?.container_path),
      readOnly: asBoolean(record?.read_only),
      type: asString(record?.type),
      filePath: asString(record?.file_path) ?? asString(record?.path) ?? "",
      context: asString(record?.context)
    };
  });
}

function networksFromValue(value: unknown): ComposeNetwork[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      name: asString(record?.name) ?? asString(record?.network),
      service: asString(record?.service) ?? asString(record?.service_name),
      external: asBoolean(record?.external),
      internal: asBoolean(record?.internal),
      filePath: asString(record?.file_path) ?? asString(record?.path) ?? "",
      context: asString(record?.context)
    };
  });
}

function secretsFromValue(value: unknown): ComposeSecret[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      name: asString(record?.name) ?? asString(record?.secret),
      service: asString(record?.service) ?? asString(record?.service_name),
      file: asString(record?.file) ?? asString(record?.source_file),
      fieldPath: asString(record?.field_path),
      read: asBoolean(record?.read),
      skipReason: asString(record?.skip_reason),
      filePath: asString(record?.file_path) ?? asString(record?.path) ?? "",
      context: asString(record?.context)
    };
  });
}

function envFilesFromValue(value: unknown): ComposeEnvFile[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      service: asString(record?.service) ?? asString(record?.service_name),
      path: asString(record?.path) ?? asString(record?.env_file),
      read: asBoolean(record?.read),
      skipReason: asString(record?.skip_reason),
      filePath: asString(record?.file_path) ?? asString(record?.compose_file) ?? "",
      context: asString(record?.context)
    };
  });
}

function findingsFromValue(value: unknown): ComposeFinding[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      id: asString(record?.id) ?? asString(record?.code) ?? "finding",
      title: asString(record?.title) ?? asString(record?.message) ?? "Compose config finding",
      level: normalizeFindingLevel(asString(record?.level) ?? asString(record?.severity)),
      confidence: normalizeConfidence(asString(record?.confidence)),
      category: asString(record?.category),
      description: asString(record?.description) ?? "",
      evidence: asString(record?.evidence) ?? "",
      recommendation: asString(record?.recommendation) ?? "",
      filePath: asString(record?.file_path),
      context: asString(record?.context),
      line: asNumber(record?.line),
      service: asString(record?.service) ?? asString(record?.service_name),
      fieldPath: asString(record?.field_path),
      image: asString(record?.image),
      port: asString(record?.port) ?? asString(record?.published) ?? asString(record?.target),
      protocol: asString(record?.protocol),
      hostPath: asString(record?.host_path),
      containerPath: asString(record?.container_path) ?? asString(record?.target_path),
      network: asString(record?.network)
    };
  });
}

function groupFindingsByLevel(findings: ComposeFinding[]): ComposeFindingGroup[] {
  const order = ["critical", "high", "medium", "low", "info", "review", "unknown"];
  const groups = new Map<string, ComposeFinding[]>();
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
  return typeof value === "string" && value.trim() ? redactComposeConfigText(value) : null;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.trim().length > 0).map(redactComposeConfigText) : [];
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
    return redactComposeConfigText(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return redactComposeConfigText(JSON.stringify(value));
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[-.]/g, "_");
}
