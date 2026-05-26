import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type WebFinding = {
  id: string;
  title: string;
  level: string;
  description: string;
  evidence: string;
  recommendation: string;
};

export type WebCookie = {
  name: string;
  secure: boolean;
  httponly: boolean;
  samesite: string | null;
  domain: string | null;
  path: string | null;
};

export type WebAuditReport = {
  isWebAudit: boolean;
  analyzer: string | null;
  completedAt: string | null;
  target: MetadataEntry[];
  http: MetadataEntry[];
  securityHeaders: Array<{ name: string; present: boolean; value: string | null }>;
  cookies: WebCookie[];
  tls: MetadataEntry[];
  robotsTxt: MetadataEntry[];
  securityTxt: MetadataEntry[];
  findings: WebFinding[];
  errors: string[];
};

export function buildWebAuditReport(job: JobRecord): WebAuditReport {
  const result = asRecord(job.result);

  return {
    isWebAudit: job.audit_type === "web_basic",
    analyzer: asString(result?.analyzer),
    completedAt: asString(result?.completed_at),
    target: entriesFromRecord(asRecord(result?.target)),
    http: entriesFromRecord(asRecord(result?.http)),
    securityHeaders: securityHeadersFromRecord(asRecord(result?.security_headers)),
    cookies: cookiesFromValue(result?.cookies),
    tls: entriesFromRecord(asRecord(result?.tls)),
    robotsTxt: entriesFromRecord(asRecord(result?.robots_txt)),
    securityTxt: entriesFromRecord(asRecord(result?.security_txt)),
    findings: findingsFromValue(result?.findings),
    errors: asStringArray(result?.errors)
  };
}

function securityHeadersFromRecord(record: Record<string, unknown> | null): Array<{ name: string; present: boolean; value: string | null }> {
  if (!record) {
    return [];
  }
  return Object.entries(record).map(([name, value]) => {
    const payload = asRecord(value);
    return {
      name,
      present: asBoolean(payload?.present),
      value: asString(payload?.value)
    };
  });
}

function cookiesFromValue(value: unknown): WebCookie[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => {
    const record = asRecord(item);
    return {
      name: asString(record?.name) ?? "cookie",
      secure: asBoolean(record?.secure),
      httponly: asBoolean(record?.httponly),
      samesite: asString(record?.samesite),
      domain: asString(record?.domain),
      path: asString(record?.path)
    };
  });
}

function findingsFromValue(value: unknown): WebFinding[] {
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
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .map(([label, value]) => ({ label, value: stringifyValue(value) }));
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function asBoolean(value: unknown): boolean {
  return typeof value === "boolean" ? value : false;
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
