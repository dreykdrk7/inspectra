import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type SubdomainFinding = {
  id: string;
  title: string;
  level: string;
  description: string;
  evidence: string;
  recommendation: string;
};

export type SubdomainCandidate = {
  input: string;
  fqdn: string | null;
  status: string;
  rejectionReason: string | null;
};

export type SubdomainResult = {
  fqdn: string;
  resolves: boolean;
  status: string;
  skipReason: string | null;
  a: string[];
  aaaa: string[];
  cname: string[];
  deadlineReached: boolean;
  privateOrReservedIpDetected: boolean;
  errors: string[];
};

export type SubdomainAuditReport = {
  isSubdomainAudit: boolean;
  analyzer: string | null;
  target: MetadataEntry[];
  summary: MetadataEntry[];
  limits: MetadataEntry[];
  truncated: boolean;
  deadlineReached: boolean;
  candidates: SubdomainCandidate[];
  results: SubdomainResult[];
  wildcardDns: MetadataEntry[];
  findings: SubdomainFinding[];
  errors: string[];
};

export function buildSubdomainAuditReport(job: JobRecord): SubdomainAuditReport {
  const result = asRecord(job.result);
  return {
    isSubdomainAudit: job.audit_type === "subdomain_inventory_basic",
    analyzer: asString(result?.analyzer),
    target: entriesFromRecord(asRecord(result?.target)),
    summary: entriesFromRecord(asRecord(result?.summary)),
    limits: entriesFromRecord(asRecord(result?.limits)),
    truncated: Boolean(asRecord(result?.summary)?.truncated),
    deadlineReached: Boolean(asRecord(result?.summary)?.deadline_reached),
    candidates: candidatesFromValue(result?.candidates),
    results: resultsFromValue(result?.results),
    wildcardDns: entriesFromRecord(asRecord(result?.wildcard_dns), ["probes"]),
    findings: findingsFromValue(result?.findings),
    errors: asStringArray(result?.errors)
  };
}

function candidatesFromValue(value: unknown): SubdomainCandidate[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      input: asString(record?.input) ?? "",
      fqdn: asString(record?.fqdn),
      status: asString(record?.status) ?? "unknown",
      rejectionReason: asString(record?.rejection_reason)
    };
  });
}

function resultsFromValue(value: unknown): SubdomainResult[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      fqdn: asString(record?.fqdn) ?? "unknown",
      resolves: Boolean(record?.resolves),
      status: asString(record?.status) ?? "processed",
      skipReason: asString(record?.skip_reason),
      a: asStringArray(record?.A),
      aaaa: asStringArray(record?.AAAA),
      cname: asStringArray(record?.CNAME),
      deadlineReached: Boolean(record?.deadline_reached),
      privateOrReservedIpDetected: Boolean(record?.private_or_reserved_ip_detected),
      errors: asStringArray(record?.errors)
    };
  });
}

function findingsFromValue(value: unknown): SubdomainFinding[] {
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
