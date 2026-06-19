import type { MetadataEntry } from "./pdfReport";
import type { JobRecord } from "./types";

export type ActiveHttpBasicHeaderReviewReport = {
  isActiveHttpBasicHeaderReview: boolean;
  status: string;
  isLiveResult: boolean;
  mode: string;
  profile: string;
  target: string;
  method: "HEAD";
  reviewWording: string;
  resultInterpretation: string;
  jobStatusMeaning: string;
  manualValidationRequired: boolean;
  reasonCodes: string[];
  errors: string[];
  overview: MetadataEntry[];
  response: MetadataEntry[];
  headerIndicators: MetadataEntry[];
  execution: MetadataEntry[];
  limits: MetadataEntry[];
  caveats: string[];
  rawJson: string;
};

const REDACTED_TARGET = "[REDACTED_TARGET]";
const REVIEW_WORDING = "HTTP header review indicator";
const JOB_STATUS_MEANING = "Completed job status means the no-live record was stored; no HTTP request was performed.";
const LIVE_JOB_STATUS_MEANING = "Job status means a bounded live HEAD attempt reached a controlled terminal state; manual validation required.";
const DEFAULT_CAVEATS = [
  "No live HTTP request was performed",
  "No redirect was followed",
  "No response body was read",
  "Manual validation required",
  "HTTP header review indicator wording only"
];
const LIVE_CAVEATS = [
  "One authorized HTTP HEAD request was attempted",
  "No redirect was followed",
  "No response body was read",
  "Manual validation required",
  "HTTP header review indicator wording only"
];
const SAFE_STATUSES = new Set([
  "not_executed",
  "observed",
  "completed_review",
  "timed_out",
  "request_failed",
  "client_error_controlled",
  "blocked_unconfigured",
  "blocked_missing_approval",
  "blocked_by_policy"
]);
const LIVE_STATUSES = new Set(["observed", "completed_review", "timed_out", "request_failed", "client_error_controlled"]);
const SAFE_CODES = new Set([
  "controlled_no_live",
  "feature_disabled",
  "authorization_missing",
  "target_permission_missing",
  "live_http_request_missing",
  "url_required",
  "url_too_long",
  "pasted_list_rejected",
  "wildcard_rejected",
  "unsupported_scheme",
  "host_required",
  "url_credentials_rejected",
  "query_not_allowed",
  "unsupported_host",
  "custom_port_rejected",
  "ip_range_rejected",
  "fragment_rejected",
  "cidr_rejected",
  "path_not_allowed",
  "control_plane_host_blocked",
  "loopback_host_blocked",
  "resolver_guard_failed",
  "resolver_answer_limit_exceeded",
  "resolved_ip_blocked",
  "request_timed_out",
  "controlled_network_error"
]);
const HEADER_INDICATOR_KEYS = [
  "hsts_present",
  "csp_present",
  "x_content_type_options_present",
  "x_frame_options_present",
  "referrer_policy_present",
  "permissions_policy_present",
  "server_header_present",
  "server_header_value_redacted",
  "set_cookie_present",
  "set_cookie_count",
  "set_cookie_count_truncated",
  "set_cookie_secure_attribute_present",
  "set_cookie_httponly_attribute_present",
  "set_cookie_samesite_attribute_present",
  "location_header_present"
];

export function buildActiveHttpBasicHeaderReviewReport(job: JobRecord): ActiveHttpBasicHeaderReviewReport {
  const publicResult = publicActiveHttpBasicHeaderReviewResult(job);
  const status = asSafeStatus(publicResult.result_status ?? publicResult.status);
  const summary = asRecord(publicResult.summary);
  const execution = asRecord(publicResult.execution);
  const limits = asRecord(publicResult.limits);
  const response = asRecord(publicResult.response);
  const headerIndicators = asRecord(publicResult.header_indicators);
  const caveats = asStringArray(publicResult.surface_caveats);
  const reasonCodes = asStringArray(publicResult.reason_codes);
  const errors = errorCodesFromValue(publicResult.errors);
  const reviewWording = asString(summary?.review_wording) ?? REVIEW_WORDING;
  const resultInterpretation = asString(summary?.result_interpretation) ?? REVIEW_WORDING;
  const jobStatusMeaning = asString(summary?.job_status_meaning) ?? JOB_STATUS_MEANING;
  const isLiveResult = LIVE_STATUSES.has(status);
  const requestsSent = safeRequestCount(execution?.requests_sent ?? summary?.requests_sent, isLiveResult);
  const liveRequestPerformed = isLiveResult && ((asBoolean(execution?.live_request_performed) ?? asBoolean(summary?.live_request_performed)) !== false);
  const redirectFollowed = false;
  const bodyRead = false;

  return {
    isActiveHttpBasicHeaderReview: job.audit_type === "active_http_basic_header_review" || publicResult.capability === "active_http_basic_header_review",
    status,
    isLiveResult,
    mode: "live_http_basic_header_review",
    profile: "http_headers_single_request",
    target: REDACTED_TARGET,
    method: "HEAD",
    reviewWording,
    resultInterpretation,
    jobStatusMeaning,
    manualValidationRequired: true,
    reasonCodes,
    errors,
    overview: [
      { label: "Result status", value: status },
      { label: "Target", value: REDACTED_TARGET },
      { label: "Method", value: "HEAD" },
      { label: "Requests sent", value: String(requestsSent) },
      { label: "Live request performed", value: String(liveRequestPerformed) },
      { label: "Redirect followed", value: String(redirectFollowed) },
      { label: "Body read", value: String(bodyRead) },
      { label: "Manual validation required", value: "true" }
    ],
    response: entriesFromRecord(response),
    headerIndicators: entriesFromRecord(headerIndicators),
    execution: entriesFromRecord(execution),
    limits: entriesFromRecord(limits),
    caveats: caveats.length > 0 ? caveats : isLiveResult ? LIVE_CAVEATS : DEFAULT_CAVEATS,
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
  const response = asRecord(result?.response);
  const headerIndicators = asRecord(result?.header_indicators);
  const resultStatus = asSafeStatus(result?.result_status ?? result?.status);
  const reasonCodes = asStringArray(result?.reason_codes).map(safeCode);
  const live = LIVE_STATUSES.has(resultStatus);
  const requestsSent = safeRequestCount(execution?.requests_sent ?? summary?.requests_sent, live);
  const dnsQueriesSent = safeZeroOrOne(execution?.dns_queries_sent);
  const statusCode = safeStatusCode(response?.status_code ?? summary?.status_code);
  const statusClass = safeStatusClass(response?.status_class ?? summary?.status_class ?? statusClassFromCode(statusCode));
  const publicHeaderIndicators = publicHeaderIndicatorsFromValue(headerIndicators);
  const redirectPresent = asBoolean(response?.redirect_present) ?? asBoolean(summary?.redirect_present) ?? false;
  const locationHeaderPresent =
    publicHeaderIndicators.location_header_present || asBoolean(response?.location_header_present) || asBoolean(summary?.location_header_present) || false;
  const jobStatusMeaning = live ? LIVE_JOB_STATUS_MEANING : JOB_STATUS_MEANING;
  const surfaceCaveats = safeCaveats(result?.surface_caveats, live);

  return {
    audit_type: "active_http_basic_header_review",
    capability: "active_http_basic_header_review",
    job_type: "active_http_basic_header_review",
    mode: "live_http_basic_header_review",
    profile: "http_headers_single_request",
    status: resultStatus,
    result_status: resultStatus,
    lifecycle_state: resultStatus,
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
    job_status_meaning: jobStatusMeaning,
    execution: {
      live_request_performed: live,
      network_requests_sent: requestsSent,
      requests_sent: requestsSent,
      http_requests_sent: requestsSent,
      dns_queries_sent: dnsQueriesSent,
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
    response: {
      status_code: statusCode,
      status_class: statusClass,
      redirect_present: redirectPresent,
      location_header_present: locationHeaderPresent,
      redirect_followed: false,
      body_read: false,
      body_bytes_read: 0
    },
    header_indicators: publicHeaderIndicators,
    summary: {
      status: resultStatus,
      reason_codes: reasonCodes,
      manual_validation_required: true,
      review_wording: REVIEW_WORDING,
      result_interpretation: REVIEW_WORDING,
      job_status_meaning: jobStatusMeaning,
      live_request_performed: live,
      redirect_followed: false,
      body_read: false,
      job_created: asBoolean(summary?.job_created) ?? true,
      storage_persisted: asBoolean(summary?.storage_persisted) ?? true,
      network_requests_sent: requestsSent,
      requests_sent: requestsSent,
      http_requests_sent: requestsSent,
      dns_queries_sent: dnsQueriesSent,
      status_code: statusCode,
      status_class: statusClass,
      redirect_present: redirectPresent,
      location_header_present: locationHeaderPresent,
      headers_received_count: safeCount(summary?.headers_received_count),
      headers_processed_count: safeCount(summary?.headers_processed_count),
      redacted_headers_count: safeCount(summary?.redacted_headers_count),
      truncated_headers_count: safeCount(summary?.truncated_headers_count)
    },
    limits: {
      max_targets: 1,
      max_url_length: asNumber(limits?.max_url_length) ?? 2048,
      method: "HEAD",
      max_redirects: 0,
      timeout_seconds: asNumber(limits?.timeout_seconds) ?? 5,
      max_response_header_bytes: asNumber(limits?.max_response_header_bytes) ?? 32768,
      max_dns_answers: asNumber(limits?.max_dns_answers) ?? 8,
      response_body_bytes: 0,
      raw_target_persisted: false,
      headers_persisted: false,
      cookies_persisted: false,
      response_body_persisted: false
    },
    surface_caveats: surfaceCaveats
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

function errorCodesFromValue(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.slice(0, 8).map((item) => safeCode(asString(asRecord(item)?.code) ?? "controlled_no_live"));
}

function safeCaveats(value: unknown, live = false): string[] {
  const requested = asStringArray(value);
  if (requested.length === 0) {
    return live ? LIVE_CAVEATS : DEFAULT_CAVEATS;
  }
  const allowed = new Set([...DEFAULT_CAVEATS, ...LIVE_CAVEATS]);
  return requested.filter((item) => allowed.has(item));
}

function asSafeStatus(value: unknown): string {
  const status = asString(value) ?? "not_executed";
  return SAFE_STATUSES.has(status) ? status : "not_executed";
}

function safeCode(value: string): string {
  return /^[a-z0-9_]{1,64}$/.test(value) && SAFE_CODES.has(value) ? value : "controlled_no_live";
}

function publicHeaderIndicatorsFromValue(value: Record<string, unknown> | null): Record<string, boolean | number> {
  const indicators: Record<string, boolean | number> = {};
  for (const key of HEADER_INDICATOR_KEYS) {
    indicators[key] = key === "set_cookie_count" ? Math.min(safeCount(value?.[key]), 8) : asBoolean(value?.[key]) ?? false;
  }
  return indicators;
}

function safeRequestCount(value: unknown, live: boolean): number {
  const count = safeCount(value);
  if (!live) {
    return 0;
  }
  return Math.min(count || 1, 1);
}

function safeZeroOrOne(value: unknown): number {
  return Math.min(safeCount(value), 1);
}

function safeCount(value: unknown): number {
  if (typeof value === "number" && Number.isInteger(value) && value > 0) {
    return value;
  }
  return 0;
}

function safeStatusCode(value: unknown): number | null {
  if (typeof value === "number" && Number.isInteger(value) && value >= 100 && value <= 599) {
    return value;
  }
  return null;
}

function safeStatusClass(value: unknown): string | null {
  const text = asString(value);
  return text && /^[1-5]xx$/.test(text) ? text : null;
}

function statusClassFromCode(value: number | null): string | null {
  return value === null ? null : `${Math.floor(value / 100)}xx`;
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
