import type { FileRecord, JobRecord } from "./types";
import type { MetadataEntry, ToolReport, ToolStatus } from "./pdfReport";

export type PrivacyIndicator = {
  key: string;
  label: string;
  present: boolean;
  fields: string[];
};

export type ImageAuditReport = {
  isImageAudit: boolean;
  analyzer: string | null;
  completedAt: string | null;
  hashes: MetadataEntry[];
  fileInfo: {
    detectedFormat: string | null;
    mimeType: string | null;
    sizeBytes: number | null;
    fileOutput: string | null;
  };
  metadata: MetadataEntry[];
  privacyIndicators: PrivacyIndicator[];
  validation: {
    warnings: string[];
  };
  tools: ToolReport[];
};

const IMAGE_METADATA_KEYS = [
  "FileType",
  "MIMEType",
  "ImageWidth",
  "ImageHeight",
  "Megapixels",
  "Make",
  "Model",
  "LensModel",
  "Software",
  "CreatorTool",
  "Artist",
  "Author",
  "CreateDate",
  "ModifyDate"
];

const PRIVACY_LABELS: Record<string, string> = {
  gps: "GPS/location metadata",
  author_or_creator: "Author or creator",
  serial_number: "Serial number",
  software_or_toolchain: "Software or toolchain",
  device: "Device or camera info"
};

export function buildImageAuditReport(job: JobRecord, file?: FileRecord): ImageAuditReport {
  const result = asRecord(job.result);
  const metadata = asRecord(result?.metadata);
  const identification = asRecord(result?.identification);
  const validation = asRecord(result?.validation);
  const hashes = asRecord(result?.hashes);
  const exiftool = asRecord(metadata?.exiftool);
  const toolOutputs = asRecord(result?.tool_outputs);
  const tools = Object.entries(toolOutputs ?? {}).map(([name, value]) => buildToolReport(name, asRecord(value)));

  return {
    isImageAudit: job.audit_type === "image_basic",
    analyzer: asString(result?.analyzer),
    completedAt: asString(result?.completed_at),
    hashes: entriesFromRecord(hashes),
    fileInfo: {
      detectedFormat: asString(identification?.detected_format),
      mimeType: asString(identification?.mime_type) ?? asString(validation?.mime_type),
      sizeBytes: file?.size_bytes ?? null,
      fileOutput: asString(identification?.file_output)
    },
    metadata: selectedEntries(exiftool, IMAGE_METADATA_KEYS),
    privacyIndicators: buildPrivacyIndicators(asRecord(result?.privacy_indicators)),
    validation: {
      warnings: asStringArray(validation?.warnings)
    },
    tools
  };
}

function buildToolReport(name: string, output: Record<string, unknown> | null): ToolReport {
  const timedOut = asBoolean(output?.timed_out) ?? false;
  const exitCode = asNumber(output?.exit_code);
  const status: ToolStatus = output === null ? "not_run" : timedOut ? "timeout" : exitCode === 0 ? "ok" : "error";

  return {
    name,
    command: asString(output?.command) ?? name,
    status,
    exitCode,
    durationMs: asNumber(output?.duration_ms),
    stdout: asString(output?.stdout) ?? "",
    stderr: asString(output?.stderr) ?? "",
    timeoutSeconds: asNumber(output?.timeout_seconds)
  };
}

function buildPrivacyIndicators(indicators: Record<string, unknown> | null): PrivacyIndicator[] {
  const fields = asRecord(indicators?.fields);
  const entries = [
    ["gps", "gps_present"],
    ["author_or_creator", "author_or_creator_present"],
    ["serial_number", "serial_number_present"],
    ["software_or_toolchain", "software_or_toolchain_present"],
    ["device", "device_info_present"]
  ];

  return entries.map(([key, presentKey]) => ({
    key,
    label: PRIVACY_LABELS[key],
    present: asBoolean(indicators?.[presentKey]) ?? false,
    fields: asStringArray(fields?.[key])
  }));
}

function selectedEntries(record: Record<string, unknown> | null, keys: string[]): MetadataEntry[] {
  if (!record) {
    return [];
  }
  const preferred = keys.flatMap((key) => (record[key] === undefined ? [] : [{ label: key, value: stringifyValue(record[key]) }]));
  const remaining = Object.entries(record)
    .filter(([key, value]) => !keys.includes(key) && isPresent(value))
    .slice(0, 14)
    .map(([key, value]) => ({ label: key, value: stringifyValue(value) }));
  return [...preferred, ...remaining];
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

function asBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
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
