import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type DomainFinding = {
  id: string;
  title: string;
  level: string;
  description: string;
  evidence: string;
  recommendation: string;
};

export type DomainAuditReport = {
  isDomainAudit: boolean;
  analyzer: string | null;
  target: MetadataEntry[];
  dns: MetadataEntry[];
  www: MetadataEntry[];
  spf: MetadataEntry[];
  dmarc: MetadataEntry[];
  dkim: MetadataEntry[];
  findings: DomainFinding[];
  errors: string[];
};

export function buildDomainAuditReport(job: JobRecord): DomainAuditReport {
  const result = asRecord(job.result);
  const dns = asRecord(result?.dns);
  const emailSecurity = asRecord(result?.email_security);
  return {
    isDomainAudit: job.audit_type === "domain_basic",
    analyzer: asString(result?.analyzer),
    target: entriesFromRecord(asRecord(result?.target)),
    dns: entriesFromRecord(dns, ["www"]),
    www: entriesFromRecord(asRecord(dns?.www)),
    spf: entriesFromRecord(asRecord(emailSecurity?.spf)),
    dmarc: entriesFromRecord(asRecord(emailSecurity?.dmarc)),
    dkim: entriesFromRecord(asRecord(emailSecurity?.dkim)),
    findings: findingsFromValue(result?.findings),
    errors: asStringArray(result?.errors)
  };
}

function findingsFromValue(value: unknown): DomainFinding[] {
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

function entriesFromRecord(record: Record<string, unknown> | null, exclude: string[] = []): MetadataEntry[] {
  if (!record) {
    return [];
  }
  return Object.entries(record)
    .filter(([key, value]) => !exclude.includes(key) && value !== null && value !== undefined && value !== "")
    .map(([label, value]) => ({ label, value: stringifyValue(value) }));
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

function stringifyValue(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return JSON.stringify(value);
}
