import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type ActiveHttpBasicHeaderReviewReport = {
  isActiveHttpBasicHeaderReview: boolean;
  status: string;
  mode: string;
  profile: string;
  target: string;
  method: "HEAD";
  reviewWording: string;
  resultInterpretation: string;
  jobStatusMeaning: string;
  manualValidationRequired: boolean;
  reasonCodes: string[];
  overview: MetadataEntry[];
  execution: MetadataEntry[];
  limits: MetadataEntry[];
  caveats: string[];
  rawJson: string;
};

const REDACTED_TARGET = "[REDACTED_TARGET]";
const REVIEW_WORDING = "HTTP header review indicator";
const JOB_STATUS_MEANING = "Completed job status means the no-live record was stored; no HTTP request was performed.";
const DEFAULT_CAVEATS = [
  "No live HTTP request was performed",
  "No redirect was followed",
  "No response body was read",
  "Manual validation required",
  "HTTP header review indicator wording only"
];
const SAFE_STATUSES = new Set(["not_executed", "blocked_unconfigured", "blocked_missing_approval", "blocked_by_policy"]);

export function buildActiveHttpBasicHeaderReviewReport(job: JobRecord): ActiveHttpBasicHeaderReviewReport {
  const publicResult = publicActiveHttpBasicHeaderReviewResult(job);
  const status = asSafeStatus(publicResult.result_status ?? publicResult.status);
  const summary = asRecord(publicResult.summary);
  const execution = asRecord(publicResult.execution);
  const limits = asRecord(publicResult.limits);
  const caveats = asStringArray(publicResult.surface_caveats);
  const reasonCodes = asStringArray(publicResult.reason_codes);
  const reviewWording = asString(summary?.review_wording) ?? REVIEW_WORDING;
  const resultInterpretation = asString(summary?.result_interpretation) ?? REVIEW_WORDING;
  const jobStatusMeaning = asString(summary?.job_status_meaning) ?? JOB_STATUS_MEANING;

  return {
    isActiveHttpBasicHeaderReview: job.audit_type === "active_http_basic_header_review" || publicResult.capability === "active_http_basic_header_review",
    status,
    mode: "live_http_basic_header_review",
    profile: "http_headers_single_request",
    target: REDACTED_TARGET,
    method: "HEAD",
    reviewWording,
    resultInterpretation,
    jobStatusMeaning,
    manualValidationRequired: true,
    reasonCodes,
    overview: [
      { label: "Result status", value: status },
      { label: "Target", value: REDACTED_TARGET },
      { label: "Method", value: "HEAD" },
      { label: "Requests sent", value: "0" },
      { label: "Live request performed", value: "false" },
      { label: "Redirect followed", value: "false" },
      { label: "Body read", value: "false" },
      { label: "Manual validation required", value: "true" }
    ],
    execution: entriesFromRecord(execution),
    limits: entriesFromRecord(limits),
    caveats: caveats.length > 0 ? caveats : DEFAULT_CAVEATS,
    rawJson: JSON.stringify(publicResult, null, 2)
  };
}

export function redactActiveHttpBasicHeaderReviewText(value: string): string {
  return value.trim() ? REDACTED_TARGET : value;
}

function publicActiveHttpBasicHeaderReviewResult(job: JobRecord): Record<string, unknown> {
  const result = asRecord(job.result);
  const summary = asRecord(result?.summary);
  const execution = asRecord(result?.execution);
  const limits = asRecord(result?.limits);
  const resultStatus = asSafeStatus(result?.result_status ?? result?.status);
  const reasonCodes = asStringArray(result?.reason_codes).map(safeCode);

  return {
    audit_type: "active_http_basic_header_review",
    capability: "active_http_basic_header_review",
    job_type: "active_http_basic_header_review",
    mode: "live_http_basic_header_review",
    profile: "http_headers_single_request",
    status: resultStatus,
    result_status: resultStatus,
    lifecycle_state: "not_executed",
    target: REDACTED_TARGET,
    target_display: REDACTED_TARGET,
    method: "HEAD",
    headers: [],
    cookies: [],
    redirect_chain: [],
    findings: [],
    reason_codes: reasonCodes,
    errors: errorsFromValue(result?.errors),
    warnings: [],
    manual_validation_required: true,
    review_wording: REVIEW_WORDING,
    result_interpretation: REVIEW_WORDING,
    job_status_meaning: JOB_STATUS_MEANING,
    execution: {
      live_request_performed: false,
      network_requests_sent: 0,
      requests_sent: 0,
      http_requests_sent: 0,
      dns_queries_sent: 0,
      tls_handshake_attempted: false,
      nmap_executed: false,
      subprocess_invoked: false,
      docker_invoked: false,
      browser_side_request_performed: false,
      redirect_followed: false,
      body_read: false,
      job_created: asBoolean(execution?.job_created) ?? true,
      storage_persisted: asBoolean(execution?.storage_persisted) ?? true
    },
    summary: {
      status: resultStatus,
      reason_codes: reasonCodes,
      manual_validation_required: true,
      review_wording: REVIEW_WORDING,
      result_interpretation: REVIEW_WORDING,
      job_status_meaning: JOB_STATUS_MEANING,
      live_request_performed: false,
      redirect_followed: false,
      body_read: false,
      job_created: asBoolean(summary?.job_created) ?? true,
      storage_persisted: asBoolean(summary?.storage_persisted) ?? true,
      network_requests_sent: 0,
      requests_sent: 0,
      http_requests_sent: 0
    },
    limits: {
      max_targets: 1,
      max_url_length: asNumber(limits?.max_url_length) ?? 2048,
      method: "HEAD",
      max_redirects: 0,
      response_body_bytes: 0,
      raw_target_persisted: false,
      headers_persisted: false,
      cookies_persisted: false,
      response_body_persisted: false
    },
    surface_caveats: safeCaveats(result?.surface_caveats)
  };
}

function entriesFromRecord(record: Record<string, unknown> | null): MetadataEntry[] {
  if (!record) {
    return [];
  }
  return Object.entries(record).map(([label, value]) => ({ label, value: stringifyValue(value) }));
}

function errorsFromValue(value: unknown): Array<{ code: string }> {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.slice(0, 8).map((item) => {
    const record = asRecord(item);
    return { code: safeCode(asString(record?.code) ?? "controlled_no_live") };
  });
}

function safeCaveats(value: unknown): string[] {
  const requested = asStringArray(value);
  if (requested.length === 0) {
    return DEFAULT_CAVEATS;
  }
  const allowed = new Set(DEFAULT_CAVEATS);
  return requested.filter((item) => allowed.has(item));
}

function asSafeStatus(value: unknown): string {
  const status = asString(value) ?? "not_executed";
  return SAFE_STATUSES.has(status) ? status : "not_executed";
}

function safeCode(value: string): string {
  return /^[a-z0-9_]{1,64}$/.test(value) ? value : "controlled_no_live";
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.flatMap((item) => {
    const text = asString(item);
    return text && /^[A-Za-z0-9 _.;-]{1,120}$/.test(text) ? [text] : [];
  });
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
  if (value === null || value === undefined) {
    return "N/A";
  }
  return JSON.stringify(value);
}
