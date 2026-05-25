import type { FileRecord, JobRecord } from "./types";

export type ToolStatus = "ok" | "error" | "timeout" | "not_run";

export type ToolReport = {
  name: string;
  command: string;
  status: ToolStatus;
  exitCode: number | null;
  durationMs: number | null;
  stdout: string;
  stderr: string;
  timeoutSeconds: number | null;
};

export type MetadataEntry = {
  label: string;
  value: string;
};

export type PdfAuditReport = {
  isPdfAudit: boolean;
  analyzer: string | null;
  completedAt: string | null;
  hashes: MetadataEntry[];
  fileInfo: {
    mimeType: string | null;
    sizeBytes: number | null;
    fileOutput: string | null;
  };
  pdfInfo: MetadataEntry[];
  exiftool: MetadataEntry[];
  validation: {
    qpdfOk: boolean | null;
    warnings: string[];
    qpdfStdout: string;
    qpdfStderr: string;
    qpdfExitCode: number | null;
  };
  tools: ToolReport[];
};

const PDFINFO_KEYS = [
  "Title",
  "Author",
  "Subject",
  "Creator",
  "Producer",
  "CreationDate",
  "ModDate",
  "Pages",
  "Encrypted",
  "Page size",
  "PDF version"
];

const EXIFTOOL_KEYS = [
  "FileType",
  "MIMEType",
  "PDFVersion",
  "PageCount",
  "Title",
  "Author",
  "Creator",
  "Producer",
  "CreateDate",
  "ModifyDate",
  "Linearized"
];

export function buildPdfAuditReport(job: JobRecord, file?: FileRecord): PdfAuditReport {
  const result = asRecord(job.result);
  const metadata = asRecord(result?.metadata);
  const validation = asRecord(result?.validation);
  const hashes = asRecord(result?.hashes);
  const toolOutputs = asRecord(result?.tool_outputs);
  const fileTool = asRecord(toolOutputs?.file);
  const qpdfTool = asRecord(toolOutputs?.qpdf);
  const tools = Object.entries(toolOutputs ?? {}).map(([name, value]) => buildToolReport(name, asRecord(value)));

  return {
    isPdfAudit: job.audit_type === "pdf_basic",
    analyzer: asString(result?.analyzer),
    completedAt: asString(result?.completed_at),
    hashes: entriesFromRecord(hashes),
    fileInfo: {
      mimeType: asString(validation?.mime_type),
      sizeBytes: file?.size_bytes ?? null,
      fileOutput: asString(fileTool?.stdout)
    },
    pdfInfo: selectedEntries(asRecord(metadata?.pdfinfo), PDFINFO_KEYS),
    exiftool: selectedEntries(asRecord(metadata?.exiftool), EXIFTOOL_KEYS),
    validation: {
      qpdfOk: asBoolean(validation?.qpdf_ok),
      warnings: asStringArray(validation?.warnings),
      qpdfStdout: asString(qpdfTool?.stdout) ?? "",
      qpdfStderr: asString(qpdfTool?.stderr) ?? "",
      qpdfExitCode: asNumber(qpdfTool?.exit_code)
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

function selectedEntries(record: Record<string, unknown> | null, keys: string[]): MetadataEntry[] {
  if (!record) {
    return [];
  }
  const preferred = keys.flatMap((key) => (record[key] === undefined ? [] : [{ label: key, value: stringifyValue(record[key]) }]));
  const remaining = Object.entries(record)
    .filter(([key, value]) => !keys.includes(key) && isPresent(value))
    .slice(0, 12)
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
