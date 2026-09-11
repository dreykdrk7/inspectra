import type {
  AutomationToken,
  AutomationTokenCreated,
  AutomationTokenProbe,
  AutomationTokenScope,
  RepositoryImportGrantCreated,
  ActiveAsset,
  ActiveAssetBatchCommit,
  ActiveAssetBatchPreflight,
  ActiveAssetPage,
  ActiveAssetDeletionPreview,
  ActiveAssetDeletionResponse,
  ActiveAssetCreateRequest,
  ActiveAssetRenewRequest,
  ActiveAssetRenewalResponse,
  ActiveChangeApproval,
  ActiveChangeApprovalPage,
  ActiveAssetResponsiblesUpdateRequest,
  ActiveMemberResponsibilityImpact,
  ActiveAssetStatus,
  ActiveAssetPostureResponse,
  ActiveAssetVerification,
  ActiveAssetVerificationChallenge,
  ActiveAssetVerificationConfiguration,
  ActiveAssetVerificationMethod,
  ActiveRecurrence,
  ActiveRecurrenceList,
  ActiveOperationsSummary,
  ActiveWeeklyReportFormat,
  ActiveWeeklyReportPeriod,
  ActiveWeeklyReportPreflight,
  ActiveWeeklyReviewOutcome,
  ActiveWeeklyReviewReceiptMutation,
  ActiveWeeklyReviewReceiptPage,
  ActiveWeeklyReviewReceiptVerification,
  ActiveAuditExportPreflight,
  ActiveDryRunRequest,
  ActiveDnsInventoryRequest,
  ActiveDnsOsintRequest,
  ActiveHttpBasicHeaderReviewRequest,
  ActiveHttpHeaderProbeRequest,
  ActiveNmapBasicRequest,
  ActiveTlsBasicRequest,
  AuthSessionResponse,
  AuthStatusResponse,
  DeletedFileResponse,
  FileRecord,
  FindingDecisionCreateRequest,
  FindingDecisionRecord,
  FindingActivityPage,
  HealthResponse,
  JobListItem,
  JobPage,
  JobRecord,
  ProjectCreated,
  ProjectRecord,
  ProjectDeletionPreview,
  ProjectDeletionResponse,
  ProjectArchivePreflightResponse,
  ProjectSnapshotCreated,
  ProjectSbomRevisionCreated,
  ProjectAnalysisComparisonResponse,
  ProjectComponentInventoryResponse,
  ProjectVulnerabilityIntelligenceResponse,
  ProjectFindingsResponse,
  ProductAuditEventsResponse,
  ProductAuditExportPreflight,
  ProductAuditIntegrityResponse,
  PublicAdvisoryCacheCleanup,
  PublicAdvisoryOperations,
  PublicIdentityAttestation,
  PublicIdentityEcosystem,
  RetentionCleanupResponse,
  RetentionPolicyResponse,
  ProjectSummary,
  ProjectPage,
  ProjectPortfolioPage,
  ProjectPortfolioSearch,
  ProjectActionPage,
  RemediationPage,
  RemediationSearch,
  RemediationBulkActionRequest,
  RemediationBulkActionResponse,
  RemediationSavedView,
  RemediationSavedViewFilters,
  RemediationSavedViewPage,
  RemediationPlanJob,
  RemediationPlanJobPage,
  RiskTrendProfile,
  RiskTrendViewResponse,
  ReportFormat,
  SbomFormat,
  SbomImportPreflight,
  TeamInvitation,
  FederatedIdentityBinding,
  IntegrationEventStatus,
  IntegrationEventReplayPreflight,
  IntegrationEventReplayResult,
  TeamMember,
  TeamOrganization,
  TeamOrganizationListItem,
  TeamRole
} from './types';

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');
const CSRF_HEADER_NAME = 'X-CSRF-Token';
const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

type ApiAuthContext = {
  csrfRequired: boolean;
  csrfToken: string | null;
  onAuthFailure?: (status: number) => void;
};

let authContext: ApiAuthContext = {
  csrfRequired: false,
  csrfToken: null
};

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

export function configureAuthContext(context: ApiAuthContext): void {
  authContext = context;
}

async function parseJsonResponse<T>(response: Response, options: { skipAuthFailure?: boolean } = {}): Promise<T> {
  const contentType = response.headers.get('content-type') || '';
  const payload = contentType.includes('application/json') ? await response.json() : null;

  if (!response.ok) {
    const detail = payload?.detail || payload?.message || response.statusText;
    if (!options.skipAuthFailure && (response.status === 401 || response.status === 403)) {
      authContext.onAuthFailure?.(response.status);
    }
    throw new ApiError(typeof detail === 'string' ? detail : JSON.stringify(detail), response.status);
  }

  return payload as T;
}

async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const method = (init.method || 'GET').toUpperCase();
  const headers = new Headers(init.headers);
  if (
    authContext.csrfRequired &&
    authContext.csrfToken &&
    MUTATING_METHODS.has(method) &&
    path !== '/auth/login'
  ) {
    headers.set(CSRF_HEADER_NAME, authContext.csrfToken);
  }
  return fetch(`${API_BASE_URL}${path}`, {
    ...init,
    credentials: init.credentials ?? 'include',
    headers
  });
}

export function apiBaseUrl(): string {
  return API_BASE_URL;
}

export async function listActiveAssetPage(options: {
  pageSize?: number;
  cursor?: string | null;
  status?: ActiveAssetStatus;
  query?: string;
  queryMode?: 'prefix' | 'exact';
  capability?: ActiveAsset['capabilities'][number];
  updatedWithinDays?: 7 | 30;
} = {}): Promise<ActiveAssetPage> {
  const payload: Record<string, unknown> = {
    page_size: options.pageSize ?? 24,
    query_mode: options.queryMode ?? 'prefix',
  };
  if (options.cursor) payload.cursor = options.cursor;
  if (options.status) payload.status = options.status;
  if (options.query?.trim()) payload.query = options.query.trim();
  if (options.capability) payload.capability = options.capability;
  if (options.updatedWithinDays) payload.updated_within_days = options.updatedWithinDays;
  return parseJsonResponse<ActiveAssetPage>(await apiFetch('/active/assets/search', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  }));
}

export async function getActiveOperationsSummary(): Promise<ActiveOperationsSummary> {
  return parseJsonResponse<ActiveOperationsSummary>(await apiFetch('/active/operations/summary'));
}

export async function getActiveWeeklyReportPreflight(
  period: ActiveWeeklyReportPeriod,
): Promise<ActiveWeeklyReportPreflight> {
  const params = new URLSearchParams({ period });
  return parseJsonResponse<ActiveWeeklyReportPreflight>(
    await apiFetch(`/active/operations/weekly-report/preflight?${params.toString()}`),
  );
}

export async function exportActiveWeeklyReport(
  preflight: ActiveWeeklyReportPreflight,
  reportFormat: ActiveWeeklyReportFormat,
): Promise<{ blob: Blob; digest: string; filename: string }> {
  const response = await apiFetch('/active/operations/weekly-report', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      period: preflight.period,
      report_format: reportFormat,
      state_at: preflight.state_at,
      snapshot_digest: preflight.snapshot_digest,
      sensitive_targets_confirmed: true,
    }),
  });
  if (!response.ok) {
    const contentType = response.headers.get('content-type') || '';
    const payload = contentType.includes('application/json') ? await response.json() : null;
    const detail = payload?.detail || response.statusText || 'Weekly report could not be generated.';
    if (response.status === 401 || response.status === 403) authContext.onAuthFailure?.(response.status);
    throw new ApiError(typeof detail === 'string' ? detail : JSON.stringify(detail), response.status);
  }
  const digest = response.headers.get('x-inspectra-snapshot-sha256');
  if (!digest || digest !== preflight.snapshot_digest) {
    throw new ApiError('Weekly report digest did not match its preflight.', 502);
  }
  return {
    blob: await response.blob(),
    digest,
    filename: `inspectra-active-weekly-${preflight.period}.${reportFormat === 'markdown' ? 'md' : 'json'}`,
  };
}

export async function listActiveWeeklyReviewReceipts(): Promise<ActiveWeeklyReviewReceiptPage> {
  return parseJsonResponse<ActiveWeeklyReviewReceiptPage>(
    await apiFetch('/active/operations/weekly-review-receipts'),
  );
}

export async function createActiveWeeklyReviewReceipt(
  preflight: ActiveWeeklyReportPreflight,
  outcome: ActiveWeeklyReviewOutcome,
  expectedRevision: number,
  idempotencyKey: string,
): Promise<ActiveWeeklyReviewReceiptMutation> {
  return parseJsonResponse<ActiveWeeklyReviewReceiptMutation>(
    await apiFetch('/active/operations/weekly-review-receipts', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        period: preflight.period,
        state_at: preflight.state_at,
        snapshot_digest: preflight.snapshot_digest,
        outcome,
        expected_revision: expectedRevision,
        idempotency_key: idempotencyKey,
        review_confirmed: true,
      }),
    }),
  );
}

export async function verifyActiveWeeklyReviewReceipt(
  receiptId: string,
  snapshotDigest: string,
): Promise<ActiveWeeklyReviewReceiptVerification> {
  return parseJsonResponse<ActiveWeeklyReviewReceiptVerification>(
    await apiFetch('/active/operations/weekly-review-receipts/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ receipt_id: receiptId, snapshot_digest: snapshotDigest }),
    }),
  );
}

export async function getActiveAsset(assetId: string): Promise<ActiveAsset> {
  return parseJsonResponse<ActiveAsset>(await apiFetch(`/active/assets/${encodeURIComponent(assetId)}`));
}

export async function createActiveAsset(payload: ActiveAssetCreateRequest, approvalId?: string): Promise<ActiveAsset> {
  const response = await apiFetch('/active/assets', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(approvalId ? { 'X-Inspectra-Active-Approval': approvalId } : {}) },
    body: JSON.stringify(payload),
  });
  return parseJsonResponse<ActiveAsset>(response);
}

export async function preflightActiveAssetBatch(file: File): Promise<ActiveAssetBatchPreflight> {
  const form = new FormData();
  form.set('file', file, file.name);
  return parseJsonResponse<ActiveAssetBatchPreflight>(await apiFetch('/active/assets/batch/preflight', {
    method: 'POST',
    body: form,
  }));
}

export async function createActiveAssetBatch(
  file: File,
  preflightToken: string,
  idempotencyKey: string,
): Promise<ActiveAssetBatchCommit> {
  const form = new FormData();
  form.set('file', file, file.name);
  form.set('preflight_token', preflightToken);
  form.set('idempotency_key', idempotencyKey);
  form.set('batch_confirmed', 'true');
  return parseJsonResponse<ActiveAssetBatchCommit>(await apiFetch('/active/assets/batch', {
    method: 'POST',
    body: form,
  }));
}

export async function revokeActiveAsset(
  assetId: string,
  reasonCode: 'authorization_withdrawn' | 'asset_retired' | 'scope_changed' | 'security_hold',
  approvalId?: string,
): Promise<ActiveAsset> {
  const response = await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/revoke`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(approvalId ? { 'X-Inspectra-Active-Approval': approvalId } : {}) },
    body: JSON.stringify({ reason_code: reasonCode }),
  });
  return parseJsonResponse<ActiveAsset>(response);
}

export async function getActiveAssetDeletionPreview(assetId: string): Promise<ActiveAssetDeletionPreview> {
  return parseJsonResponse<ActiveAssetDeletionPreview>(
    await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/deletion`)
  );
}

export async function deleteActiveAsset(assetId: string): Promise<ActiveAssetDeletionResponse> {
  return parseJsonResponse<ActiveAssetDeletionResponse>(await apiFetch(`/active/assets/${encodeURIComponent(assetId)}`, {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ confirmation: 'DELETE ACTIVE ASSET' }),
  }));
}

export async function renewActiveAsset(
  assetId: string,
  payload: ActiveAssetRenewRequest,
  approvalId?: string,
): Promise<ActiveAssetRenewalResponse> {
  const response = await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/renew`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(approvalId ? { 'X-Inspectra-Active-Approval': approvalId } : {}) },
    body: JSON.stringify(payload),
  });
  return parseJsonResponse<ActiveAssetRenewalResponse>(response);
}

export async function updateActiveAssetResponsibles(
  assetId: string,
  payload: ActiveAssetResponsiblesUpdateRequest,
): Promise<ActiveAsset> {
  const response = await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/responsibles`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return parseJsonResponse<ActiveAsset>(response);
}

export async function listActiveChangeApprovals(): Promise<ActiveChangeApprovalPage> {
  return parseJsonResponse<ActiveChangeApprovalPage>(await apiFetch('/active/change-approvals'));
}

export async function requestActiveRegistrationApproval(
  payload: ActiveAssetCreateRequest,
): Promise<ActiveChangeApproval> {
  return parseJsonResponse<ActiveChangeApproval>(await apiFetch('/active/change-approvals/registrations', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload),
  }));
}

export async function requestActiveRenewalApproval(
  assetId: string, payload: ActiveAssetRenewRequest,
): Promise<ActiveChangeApproval> {
  return parseJsonResponse<ActiveChangeApproval>(await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/change-approvals/renewals`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload),
  }));
}

export async function requestActiveRevocationApproval(
  assetId: string,
  reasonCode: 'authorization_withdrawn' | 'asset_retired' | 'scope_changed' | 'security_hold',
): Promise<ActiveChangeApproval> {
  return parseJsonResponse<ActiveChangeApproval>(await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/change-approvals/revocations`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ reason_code: reasonCode }),
  }));
}

export async function decideActiveChangeApproval(
  approvalId: string, decision: 'approve' | 'reject',
): Promise<ActiveChangeApproval> {
  return parseJsonResponse<ActiveChangeApproval>(await apiFetch(`/active/change-approvals/${encodeURIComponent(approvalId)}/${decision}`, {
    method: 'POST',
  }));
}

export async function createActiveAssetExecution(
  assetId: string,
  payload: { capability: ActiveAsset['capabilities'][number]; port?: number; authorization_reconfirmed: true; idempotency_key: string },
): Promise<JobRecord> {
  const response = await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/executions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function cancelActiveAssetExecution(assetId: string, jobId: string): Promise<JobRecord> {
  const response = await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/executions/${encodeURIComponent(jobId)}/cancel`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ cancellation_confirmed: true }),
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function retryActiveAssetExecution(assetId: string, jobId: string): Promise<JobRecord> {
  const response = await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/executions/${encodeURIComponent(jobId)}/retry`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ authorization_reconfirmed: true, idempotency_key: createIdempotencyKey() }),
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function getActiveAssetPosture(assetId: string): Promise<ActiveAssetPostureResponse> {
  const response = await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/posture`);
  return parseJsonResponse<ActiveAssetPostureResponse>(response);
}

export async function listActiveAssetExecutionPage(
  assetId: string,
  cursor?: string | null,
): Promise<JobPage> {
  const response = await apiFetch(
    `/active/assets/${encodeURIComponent(assetId)}/executions/search`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ page_size: 50, ...(cursor ? { cursor } : {}) }),
    },
  );
  return parseJsonResponse<JobPage>(response);
}

export async function getActiveAssetExecutionSummary(
  assetId: string,
  executionId: string,
): Promise<JobListItem> {
  const response = await apiFetch(
    `/active/assets/${encodeURIComponent(assetId)}/executions/${encodeURIComponent(executionId)}`,
  );
  return parseJsonResponse<JobListItem>(response);
}

export async function setActiveAssetBaseline(assetId: string, executionId: string): Promise<ActiveAsset> {
  const response = await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/baseline`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ execution_id: executionId, baseline_confirmed: true }),
  });
  return parseJsonResponse<ActiveAsset>(response);
}

export async function setActiveAssetTriage(
  assetId: string,
  payload: { observation_key: string; status: 'needs_review' | 'acknowledged' | 'expected_change' | 'dismissed'; comment_code: 'planned_change' | 'expected_service' | 'investigating' | 'needs_owner_review' | 'not_applicable' },
): Promise<ActiveAsset> {
  const response = await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/triage`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload),
  });
  return parseJsonResponse<ActiveAsset>(response);
}

export function activeAssetReportUrl(assetId: string): string {
  return `${API_BASE_URL}/active/assets/${encodeURIComponent(assetId)}/report`;
}

export function activeAssetEvidenceBundleUrl(assetId: string, period: '30d' | '90d' | '365d' | 'all'): string {
  const params = new URLSearchParams({ period });
  return `${API_BASE_URL}/active/assets/${encodeURIComponent(assetId)}/evidence-bundle?${params.toString()}`;
}

export async function getActiveAssetVerificationConfiguration(): Promise<ActiveAssetVerificationConfiguration> {
  return parseJsonResponse<ActiveAssetVerificationConfiguration>(await apiFetch('/active/verification/configuration'));
}

export async function getActiveAssetVerification(assetId: string): Promise<ActiveAssetVerification | null> {
  return parseJsonResponse<ActiveAssetVerification | null>(await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/verification`));
}

export async function startActiveAssetVerification(assetId: string, method: ActiveAssetVerificationMethod): Promise<ActiveAssetVerificationChallenge> {
  return parseJsonResponse<ActiveAssetVerificationChallenge>(await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/verification/challenge`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ method, valid_for_days: 30, control_check_confirmed: true }),
  }));
}

export async function checkActiveAssetVerification(
  assetId: string,
  payload: { verification_id: string; challenge_token: string; manual_attestation_confirmed: boolean },
): Promise<ActiveAssetVerification> {
  return parseJsonResponse<ActiveAssetVerification>(await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/verification/check`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  }));
}

export async function revokeActiveAssetVerification(assetId: string, verificationId: string): Promise<ActiveAssetVerification> {
  return parseJsonResponse<ActiveAssetVerification>(await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/verification/revoke`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ verification_id: verificationId, revocation_confirmed: true }),
  }));
}

export async function listActiveRecurrences(assetId: string): Promise<ActiveRecurrenceList> {
  return parseJsonResponse<ActiveRecurrenceList>(await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/recurrences`));
}

export async function createActiveRecurrence(
  assetId: string,
  payload: { capability: ActiveAsset['capabilities'][number]; port?: number; interval_days: 7 | 14 | 30; timezone_name: string; window_weekdays: ActiveRecurrence['window_weekdays']; window_start_hour: number; window_duration_hours: number; recurrence_confirmed: true; idempotency_key: string },
): Promise<ActiveRecurrence> {
  return parseJsonResponse<ActiveRecurrence>(await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/recurrences`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload),
  }));
}

export async function pauseActiveRecurrence(assetId: string, schedule: ActiveRecurrence): Promise<ActiveRecurrence> {
  return parseJsonResponse<ActiveRecurrence>(await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/recurrences/${encodeURIComponent(schedule.id)}/pause`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ expected_updated_at: schedule.updated_at }),
  }));
}

export async function resumeActiveRecurrence(assetId: string, schedule: ActiveRecurrence): Promise<ActiveRecurrence> {
  return parseJsonResponse<ActiveRecurrence>(await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/recurrences/${encodeURIComponent(schedule.id)}/resume`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ expected_updated_at: schedule.updated_at }),
  }));
}

export async function deleteActiveRecurrence(assetId: string, scheduleId: string): Promise<void> {
  const response = await apiFetch(`/active/assets/${encodeURIComponent(assetId)}/recurrences/${encodeURIComponent(scheduleId)}`, {
    method: 'DELETE', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ confirmation: 'DELETE ACTIVE SCHEDULE' }),
  });
  if (!response.ok) await parseJsonResponse<never>(response);
}

export async function getHealth(): Promise<HealthResponse> {
  const response = await apiFetch('/health');
  return parseJsonResponse<HealthResponse>(response);
}

export async function getAuthStatus(): Promise<AuthStatusResponse> {
  const response = await apiFetch('/auth/status');
  return parseJsonResponse<AuthStatusResponse>(response, { skipAuthFailure: true });
}

export async function login(password: string, username?: string): Promise<AuthSessionResponse> {
  const response = await apiFetch('/auth/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password, ...(username ? { username } : {}) }),
  });
  return parseJsonResponse<AuthSessionResponse>(response, { skipAuthFailure: true });
}

export async function acceptTeamInvitation(token: string, password: string): Promise<{ accepted: true; username: string }> {
  const response = await apiFetch('/auth/invitations/accept', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token, password }),
  });
  return parseJsonResponse<{ accepted: true; username: string }>(response, { skipAuthFailure: true });
}

export async function getTeamOrganization(): Promise<TeamOrganization> {
  const response = await apiFetch('/organization');
  return parseJsonResponse<TeamOrganization>(response);
}

export async function listTeamOrganizations(): Promise<TeamOrganizationListItem[]> {
  const response = await apiFetch('/organizations');
  return parseJsonResponse<TeamOrganizationListItem[]>(response);
}

export async function createTeamOrganization(name: string): Promise<TeamOrganizationListItem> {
  const response = await apiFetch('/organizations', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name }),
  });
  return parseJsonResponse<TeamOrganizationListItem>(response);
}

export async function selectTeamOrganization(organizationId: string): Promise<AuthSessionResponse> {
  const response = await apiFetch(`/organizations/${encodeURIComponent(organizationId)}/select`, {
    method: 'POST',
  });
  return parseJsonResponse<AuthSessionResponse>(response);
}

export async function listTeamMembers(): Promise<TeamMember[]> {
  const response = await apiFetch('/organization/members');
  return parseJsonResponse<TeamMember[]>(response);
}

export async function createTeamInvitation(username: string, role: TeamRole): Promise<TeamInvitation> {
  const response = await apiFetch('/organization/invitations', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, role }),
  });
  return parseJsonResponse<TeamInvitation>(response);
}

export async function changeTeamMemberRole(userId: string, role: TeamRole): Promise<TeamMember> {
  const response = await apiFetch(`/organization/members/${encodeURIComponent(userId)}/role`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ role }),
  });
  return parseJsonResponse<TeamMember>(response);
}

export async function revokeTeamMember(userId: string): Promise<void> {
  const response = await apiFetch(`/organization/members/${encodeURIComponent(userId)}`, {
    method: 'DELETE',
  });
  if (!response.ok) {
    await parseJsonResponse<never>(response);
  }
}

export async function listFederatedIdentities(): Promise<FederatedIdentityBinding[]> {
  return parseJsonResponse<FederatedIdentityBinding[]>(await apiFetch('/organization/federated-identities'));
}

export async function provisionFederatedIdentity(userId: string, subject: string): Promise<FederatedIdentityBinding> {
  return parseJsonResponse<FederatedIdentityBinding>(await apiFetch('/organization/federated-identities', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: userId, subject }),
  }));
}

export async function revokeFederatedIdentity(bindingId: string): Promise<FederatedIdentityBinding> {
  return parseJsonResponse<FederatedIdentityBinding>(await apiFetch(
    `/organization/federated-identities/${encodeURIComponent(bindingId)}`,
    { method: 'DELETE' },
  ));
}

export async function getIntegrationEventStatus(): Promise<IntegrationEventStatus> {
  return parseJsonResponse<IntegrationEventStatus>(await apiFetch('/operations/integration-events'));
}

export async function getIntegrationEventReplayPreflight(): Promise<IntegrationEventReplayPreflight> {
  return parseJsonResponse<IntegrationEventReplayPreflight>(await apiFetch('/operations/integration-events/replay-preflight'));
}

export async function replayDeadIntegrationEvents(
  preflight: IntegrationEventReplayPreflight,
): Promise<IntegrationEventReplayResult> {
  return parseJsonResponse<IntegrationEventReplayResult>(await apiFetch('/operations/integration-events/replay', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      observed_at: preflight.observed_at,
      snapshot_digest: preflight.snapshot_digest,
      confirmation: 'replay_dead_integration_events',
    }),
  }));
}

export async function getTeamMemberActiveImpact(userId: string): Promise<ActiveMemberResponsibilityImpact> {
  const response = await apiFetch(`/organization/members/${encodeURIComponent(userId)}/responsibility-impact`);
  return parseJsonResponse<ActiveMemberResponsibilityImpact>(response);
}

export async function listPublicIdentityAttestations(): Promise<PublicIdentityAttestation[]> {
  return parseJsonResponse<PublicIdentityAttestation[]>(await apiFetch('/organization/public-identities'));
}

export async function proposePublicIdentityAttestation(
  ecosystem: PublicIdentityEcosystem,
  packageName: string,
  requestedTtlDays: number,
): Promise<PublicIdentityAttestation> {
  return parseJsonResponse<PublicIdentityAttestation>(await apiFetch('/organization/public-identities', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ecosystem, package_name: packageName, requested_ttl_days: requestedTtlDays }),
  }));
}

export async function approvePublicIdentityAttestation(attestationId: string): Promise<PublicIdentityAttestation> {
  return parseJsonResponse<PublicIdentityAttestation>(await apiFetch(
    `/organization/public-identities/${encodeURIComponent(attestationId)}/approve`,
    { method: 'POST' },
  ));
}

export async function revokePublicIdentityAttestation(attestationId: string): Promise<PublicIdentityAttestation> {
  return parseJsonResponse<PublicIdentityAttestation>(await apiFetch(
    `/organization/public-identities/${encodeURIComponent(attestationId)}`,
    { method: 'DELETE' },
  ));
}

export async function listAutomationTokens(): Promise<AutomationToken[]> {
  const response = await apiFetch('/automation/tokens');
  return parseJsonResponse<AutomationToken[]>(response);
}

export async function createAutomationToken(payload: {
  name: string;
  project_id: string;
  scopes: AutomationTokenScope[];
  lifetime_seconds: number;
}): Promise<AutomationTokenCreated> {
  const response = await apiFetch('/automation/tokens', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return parseJsonResponse<AutomationTokenCreated>(response);
}

export async function revokeAutomationToken(tokenId: string): Promise<AutomationToken> {
  const response = await apiFetch(`/automation/tokens/${encodeURIComponent(tokenId)}`, { method: 'DELETE' });
  return parseJsonResponse<AutomationToken>(response);
}

export async function probeAutomationToken(tokenId: string): Promise<AutomationTokenProbe> {
  const response = await apiFetch(`/automation/tokens/${encodeURIComponent(tokenId)}`);
  return parseJsonResponse<AutomationTokenProbe>(response);
}

export async function createRepositoryImportGrant(lifetimeSeconds = 900): Promise<RepositoryImportGrantCreated> {
  const response = await apiFetch('/repository-import/grants', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ lifetime_seconds: lifetimeSeconds }),
  });
  return parseJsonResponse<RepositoryImportGrantCreated>(response);
}

export async function listProductAuditEvents(options: {
  limit?: number;
  cursor?: string | null;
  action?: string;
} = {}): Promise<ProductAuditEventsResponse> {
  const params = new URLSearchParams();
  params.set('limit', String(options.limit ?? 25));
  if (options.cursor) params.set('cursor', options.cursor);
  if (options.action) params.set('action', options.action);
  const response = await apiFetch(`/audit/events?${params.toString()}`);
  return parseJsonResponse<ProductAuditEventsResponse>(response);
}

export async function verifyProductAuditIntegrity(): Promise<ProductAuditIntegrityResponse> {
  return parseJsonResponse<ProductAuditIntegrityResponse>(await apiFetch('/audit/integrity'));
}

export async function getProductAuditExportPreflight(
  period: '7d' | '30d' | '90d' | '365d',
  actionFilter?: string,
): Promise<ProductAuditExportPreflight> {
  const params = new URLSearchParams({ period });
  if (actionFilter) params.set('action_filter', actionFilter);
  return parseJsonResponse<ProductAuditExportPreflight>(await apiFetch(`/audit/export/preflight?${params.toString()}`));
}

export async function exportProductAudit(
  preflight: ProductAuditExportPreflight,
  exportFormat: 'json' | 'csv',
): Promise<{ blob: Blob; digest: string; filename: string }> {
  const response = await apiFetch('/audit/export', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      period: preflight.period,
      export_format: exportFormat,
      action_filter: preflight.action_filter,
      state_at: preflight.state_at,
      snapshot_digest: preflight.snapshot_digest,
      redacted_export_confirmed: true,
    }),
  });
  if (!response.ok) {
    const contentType = response.headers.get('content-type') || '';
    const payload = contentType.includes('application/json') ? await response.json() : null;
    const detail = payload?.detail || response.statusText || 'Product audit export could not be generated.';
    if (response.status === 401 || response.status === 403) authContext.onAuthFailure?.(response.status);
    throw new ApiError(typeof detail === 'string' ? detail : JSON.stringify(detail), response.status);
  }
  const digest = response.headers.get('x-inspectra-snapshot-sha256');
  if (!digest || digest !== preflight.snapshot_digest) {
    throw new ApiError('Product audit export digest did not match its preflight.', 502);
  }
  return {
    blob: await response.blob(),
    digest,
    filename: `inspectra-product-audit.${exportFormat}`,
  };
}

export async function getActiveAuditExportPreflight(
  period: '7d' | '30d' | '90d' | '365d',
  assetId?: string,
): Promise<ActiveAuditExportPreflight> {
  const params = new URLSearchParams({ period });
  if (assetId) params.set('asset_id', assetId);
  return parseJsonResponse<ActiveAuditExportPreflight>(await apiFetch(`/audit/active-export/preflight?${params.toString()}`));
}

export function activeAuditExportUrl(
  period: '7d' | '30d' | '90d' | '365d',
  format: 'json' | 'csv',
  assetId?: string,
): string {
  const params = new URLSearchParams({ period, format });
  if (assetId) params.set('asset_id', assetId);
  return `${API_BASE_URL}/audit/active-export?${params.toString()}`;
}

export async function getRetentionPolicy(): Promise<RetentionPolicyResponse> {
  const response = await apiFetch('/privacy/retention');
  return parseJsonResponse<RetentionPolicyResponse>(response);
}

export async function runRetentionCleanup(): Promise<RetentionCleanupResponse> {
  const response = await apiFetch('/privacy/retention/run', { method: 'POST' });
  return parseJsonResponse<RetentionCleanupResponse>(response);
}

export async function getPublicAdvisoryOperations(): Promise<PublicAdvisoryOperations> {
  return parseJsonResponse<PublicAdvisoryOperations>(await apiFetch('/operations/public-advisories'));
}

export async function purgeExpiredPublicAdvisoryCache(): Promise<PublicAdvisoryCacheCleanup> {
  return parseJsonResponse<PublicAdvisoryCacheCleanup>(await apiFetch('/operations/public-advisories/cache/purge-expired', { method: 'POST' }));
}

export async function logout(): Promise<AuthSessionResponse> {
  const response = await apiFetch('/auth/logout', {
    method: 'POST',
  });
  return parseJsonResponse<AuthSessionResponse>(response);
}

export async function listFiles(): Promise<FileRecord[]> {
  const response = await apiFetch('/files');
  return parseJsonResponse<FileRecord[]>(response);
}

export async function uploadPdf(file: File): Promise<FileRecord> {
  const formData = new FormData();
  formData.append('file', file);
  const response = await apiFetch('/files/pdf', {
    method: 'POST',
    body: formData,
  });
  return parseJsonResponse<FileRecord>(response);
}

export async function uploadImage(file: File): Promise<FileRecord> {
  const formData = new FormData();
  formData.append('file', file);
  const response = await apiFetch('/files/image', {
    method: 'POST',
    body: formData,
  });
  return parseJsonResponse<FileRecord>(response);
}

export async function uploadManifest(file: File): Promise<FileRecord> {
  const formData = new FormData();
  formData.append('file', file);
  const response = await apiFetch('/files/manifest', {
    method: 'POST',
    body: formData,
  });
  return parseJsonResponse<FileRecord>(response);
}

export async function uploadArchive(file: File): Promise<FileRecord> {
  const formData = new FormData();
  formData.append('file', file);
  const response = await apiFetch('/files/archive', {
    method: 'POST',
    body: formData,
  });
  return parseJsonResponse<FileRecord>(response);
}

export async function deleteFile(fileId: string): Promise<DeletedFileResponse> {
  const response = await apiFetch(`/files/${fileId}`, {
    method: 'DELETE',
  });
  return parseJsonResponse<DeletedFileResponse>(response);
}

export async function listProjects(): Promise<ProjectSummary[]> {
  const response = await apiFetch('/projects');
  return parseJsonResponse<ProjectSummary[]>(response);
}

export async function listProjectPage(cursor?: string | null): Promise<ProjectPage> {
  const payload: Record<string, unknown> = { page_size: 50 };
  if (cursor) payload.cursor = cursor;
  try {
    return await parseJsonResponse<ProjectPage>(await apiFetch('/projects/search', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    }));
  } catch (error) {
    if (!(error instanceof ApiError) || error.status !== 404 || cursor) throw error;
    const items = await listProjects();
    return {
      contract_version: '2026-09-09.1',
      items,
      returned_count: items.length,
      total_count: items.length,
      has_more: false,
      next_cursor: null,
    };
  }
}

export async function getProject(projectId: string): Promise<ProjectSummary> {
  return parseJsonResponse<ProjectSummary>(await apiFetch(`/projects/${encodeURIComponent(projectId)}`));
}

export async function updateProjectResponsibility(
  projectId: string,
  responsibleUserId: string | null,
  expectedUpdatedAt: string,
): Promise<ProjectRecord> {
  return parseJsonResponse<ProjectRecord>(await apiFetch(
    `/projects/${encodeURIComponent(projectId)}/responsibility`,
    {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        responsible_user_id: responsibleUserId,
        expected_updated_at: expectedUpdatedAt,
        assignment_confirmed: true,
      }),
    },
  ));
}

export async function searchProjectPortfolio(options: ProjectPortfolioSearch = {}): Promise<ProjectPortfolioPage> {
  const payload: Record<string, unknown> = {
    page_size: options.pageSize ?? 24,
    search_mode: options.searchMode ?? 'prefix',
    sort: options.sort ?? 'priority',
  };
  if (options.cursor) payload.cursor = options.cursor;
  if (options.search?.trim()) payload.search = options.search.trim();
  if (options.priority) payload.priority = options.priority;
  if (options.severity) payload.severity = options.severity;
  if (options.sourceType) payload.source_type = options.sourceType;
  if (options.operationalState) payload.operational_state = options.operationalState;
  if (options.coverage) payload.coverage = options.coverage;
  if (options.publicIntelligence) payload.public_intelligence = options.publicIntelligence;
  if (options.baseline) payload.baseline = options.baseline;
  if (options.responsibility) payload.responsibility = options.responsibility;
  return parseJsonResponse<ProjectPortfolioPage>(await apiFetch('/projects/portfolio/search', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  }));
}

export async function getProjectActions(options: {
  unreadOnly?: boolean;
  limit?: number;
} = {}): Promise<ProjectActionPage> {
  const params = new URLSearchParams({
    unread_only: String(options.unreadOnly ?? false),
    limit: String(options.limit ?? 100),
  });
  return parseJsonResponse<ProjectActionPage>(await apiFetch(`/projects/actions?${params.toString()}`));
}

export async function markProjectActionRead(actionId: string): Promise<ProjectActionPage> {
  return parseJsonResponse<ProjectActionPage>(await apiFetch(
    `/projects/actions/${encodeURIComponent(actionId)}/read`,
    {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ read: true }),
    },
  ));
}

export async function rebuildProjectActions(): Promise<ProjectActionPage> {
  return parseJsonResponse<ProjectActionPage>(await apiFetch('/projects/actions/rebuild', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ rebuild_confirmed: true }),
  }));
}

export async function searchRemediationCenter(options: RemediationSearch = {}): Promise<RemediationPage> {
  const payload: Record<string, unknown> = {
    page_size: options.pageSize ?? 24,
    search_mode: options.searchMode ?? 'prefix',
    sort: options.sort ?? 'priority',
  };
  if (options.cursor) payload.cursor = options.cursor;
  if (options.search?.trim()) payload.search = options.search.trim();
  if (options.priority) payload.priority = options.priority;
  if (options.evidenceKind) payload.evidence_kind = options.evidenceKind;
  if (options.ecosystem) payload.ecosystem = options.ecosystem;
  if (options.dependencyScope) payload.dependency_scope = options.dependencyScope;
  if (options.workflowState) payload.workflow_state = options.workflowState;
  return parseJsonResponse<RemediationPage>(await apiFetch('/remediation/search', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  }));
}

export async function applyRemediationAction(
  payload: RemediationBulkActionRequest,
): Promise<RemediationBulkActionResponse> {
  return parseJsonResponse<RemediationBulkActionResponse>(await apiFetch('/remediation/actions', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  }));
}

export async function listRemediationSavedViews(): Promise<RemediationSavedViewPage> {
  return parseJsonResponse<RemediationSavedViewPage>(await apiFetch('/remediation/views'));
}

export async function createRemediationSavedView(payload: {
  name: string;
  filters: RemediationSavedViewFilters;
  visibility: 'private' | 'organization';
  make_default: boolean;
}): Promise<RemediationSavedView> {
  return parseJsonResponse<RemediationSavedView>(await apiFetch('/remediation/views', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload),
  }));
}

export async function setDefaultRemediationSavedView(viewId: string | null): Promise<RemediationSavedViewPage> {
  return parseJsonResponse<RemediationSavedViewPage>(await apiFetch('/remediation/views/default', {
    method: 'PUT', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ view_id: viewId, confirmation: true }),
  }));
}

export async function deleteRemediationSavedView(viewId: string): Promise<void> {
  const response = await apiFetch(`/remediation/views/${encodeURIComponent(viewId)}`, { method: 'DELETE' });
  if (!response.ok) await parseJsonResponse<never>(response);
}

export async function exportRemediationReport(
  options: RemediationSearch,
  reportFormat: 'json' | 'csv',
): Promise<{ blob: Blob; filename: string; digest: string }> {
  const filters: Record<string, unknown> = {
    page_size: options.pageSize ?? 100,
    search_mode: options.searchMode ?? 'prefix',
    sort: options.sort ?? 'priority',
  };
  if (options.search?.trim()) filters.search = options.search.trim();
  if (options.priority) filters.priority = options.priority;
  if (options.evidenceKind) filters.evidence_kind = options.evidenceKind;
  if (options.ecosystem) filters.ecosystem = options.ecosystem;
  if (options.dependencyScope) filters.dependency_scope = options.dependencyScope;
  if (options.workflowState) filters.workflow_state = options.workflowState;
  const response = await apiFetch('/remediation/report', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ filters, report_format: reportFormat, project_metadata_confirmed: true }),
  });
  if (!response.ok) {
    const payload = response.headers.get('content-type')?.includes('application/json') ? await response.json() : null;
    if (response.status === 401 || response.status === 403) authContext.onAuthFailure?.(response.status);
    throw new ApiError(payload?.detail || 'Remediation report could not be generated.', response.status);
  }
  const disposition = response.headers.get('content-disposition') || '';
  const filename = /filename="([^"]+)"/.exec(disposition)?.[1] ?? `inspectra-remediation.${reportFormat}`;
  return {
    blob: await response.blob(),
    filename,
    digest: response.headers.get('x-inspectra-snapshot-sha256') || '',
  };
}

export async function listRemediationPlans(): Promise<RemediationPlanJobPage> {
  return parseJsonResponse<RemediationPlanJobPage>(await apiFetch('/remediation/plans'));
}

export async function createRemediationPlan(
  options: RemediationSearch,
  idempotencyKey: string,
): Promise<RemediationPlanJob> {
  const filters = remediationFilters(options);
  return parseJsonResponse<RemediationPlanJob>(await apiFetch('/remediation/plans', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ filters, idempotency_key: idempotencyKey, project_metadata_confirmed: true }),
  }));
}

export async function cancelRemediationPlan(planId: string): Promise<RemediationPlanJob> {
  return parseJsonResponse<RemediationPlanJob>(await apiFetch(`/remediation/plans/${encodeURIComponent(planId)}/cancel`, { method: 'POST' }));
}

export async function retryRemediationPlan(planId: string, idempotencyKey: string): Promise<RemediationPlanJob> {
  return parseJsonResponse<RemediationPlanJob>(await apiFetch(`/remediation/plans/${encodeURIComponent(planId)}/retry`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ idempotency_key: idempotencyKey, confirmation: true }),
  }));
}

export async function downloadRemediationPlan(
  planId: string,
  reportFormat: 'json' | 'csv',
): Promise<{ blob: Blob; filename: string; digest: string }> {
  const response = await apiFetch(`/remediation/plans/${encodeURIComponent(planId)}/download?${new URLSearchParams({ format: reportFormat })}`);
  if (!response.ok) {
    const payload = response.headers.get('content-type')?.includes('application/json') ? await response.json() : null;
    throw new ApiError(payload?.detail || 'Remediation plan could not be downloaded.', response.status);
  }
  const disposition = response.headers.get('content-disposition') || '';
  return {
    blob: await response.blob(),
    filename: /filename="([^"]+)"/.exec(disposition)?.[1] ?? `inspectra-remediation-plan.${reportFormat}`,
    digest: response.headers.get('x-inspectra-snapshot-sha256') || '',
  };
}

function remediationFilters(options: RemediationSearch): Record<string, unknown> {
  const filters: Record<string, unknown> = {
    page_size: options.pageSize ?? 100,
    search_mode: options.searchMode ?? 'prefix',
    sort: options.sort ?? 'priority',
  };
  if (options.search?.trim()) filters.search = options.search.trim();
  if (options.priority) filters.priority = options.priority;
  if (options.evidenceKind) filters.evidence_kind = options.evidenceKind;
  if (options.ecosystem) filters.ecosystem = options.ecosystem;
  if (options.dependencyScope) filters.dependency_scope = options.dependencyScope;
  if (options.workflowState) filters.workflow_state = options.workflowState;
  return filters;
}

export async function getProjectRiskTrends(
  periodDays: 30 | 90 | 180 = 90,
  bucketDays: 7 | 30 = 7,
): Promise<RiskTrendViewResponse> {
  return parseJsonResponse<RiskTrendViewResponse>(await apiFetch('/projects/trends', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ period_days: periodDays, bucket_days: bucketDays }),
  }));
}

export async function refreshProjectRiskTrends(
  periodDays: 30 | 90 | 180 = 90,
  bucketDays: 7 | 30 = 7,
): Promise<RiskTrendViewResponse> {
  return parseJsonResponse<RiskTrendViewResponse>(await apiFetch('/projects/trends/refresh', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ period_days: periodDays, bucket_days: bucketDays }),
  }));
}

export async function exportProjectRiskTrends(
  periodDays: 30 | 90 | 180,
  bucketDays: 7 | 30,
  profile: RiskTrendProfile,
  reportFormat: 'json' | 'csv',
): Promise<{ blob: Blob; filename: string; digest: string }> {
  const response = await apiFetch('/projects/trends/report', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      filters: { period_days: periodDays, bucket_days: bucketDays },
      profile,
      report_format: reportFormat,
      project_metadata_confirmed: true,
    }),
  });
  if (!response.ok) {
    const payload = response.headers.get('content-type')?.includes('application/json') ? await response.json() : null;
    if (response.status === 401 || response.status === 403) authContext.onAuthFailure?.(response.status);
    throw new ApiError(payload?.detail || 'Risk trend report could not be generated.', response.status);
  }
  const disposition = response.headers.get('content-disposition') || '';
  const filename = /filename="([^"]+)"/.exec(disposition)?.[1] ?? `inspectra-risk-trends-${profile}.${reportFormat}`;
  return {
    blob: await response.blob(),
    filename,
    digest: response.headers.get('x-inspectra-snapshot-sha256') || '',
  };
}

export async function getProjectArchivePreflight(): Promise<ProjectArchivePreflightResponse> {
  const response = await apiFetch('/project-analysis-preflight');
  return parseJsonResponse<ProjectArchivePreflightResponse>(response);
}

export async function createProject(sourceFileId: string, name?: string): Promise<ProjectCreated> {
  const response = await apiFetch('/projects', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ source_file_id: sourceFileId, authorization_confirmed: true, ...(name ? { name } : {}) }),
  });
  return parseJsonResponse<ProjectCreated>(response);
}

export async function importSbomProject(
  file: File,
  name: string,
  preflightToken: string,
  publicRegistryIdentitiesConfirmed: boolean,
): Promise<ProjectCreated> {
  const form = new FormData();
  form.append('file', file, 'sbom.json');
  form.append('name', name);
  form.append('preflight_token', preflightToken);
  form.append('authorization_confirmed', 'true');
  form.append('public_registry_identities_confirmed', String(publicRegistryIdentitiesConfirmed));
  const response = await apiFetch('/projects/import/sbom', { method: 'POST', body: form });
  return parseJsonResponse<ProjectCreated>(response);
}

export async function preflightSbomProject(file: File): Promise<SbomImportPreflight> {
  const form = new FormData();
  form.append('file', file, 'sbom.json');
  const response = await apiFetch('/projects/import/sbom/preflight', { method: 'POST', body: form });
  return parseJsonResponse<SbomImportPreflight>(response);
}

export async function importProjectSbomRevision(
  projectId: string,
  file: File,
  idempotencyKey: string,
  publicRegistryIdentitiesConfirmed: boolean,
): Promise<ProjectSbomRevisionCreated> {
  const form = new FormData();
  form.append('file', file, 'sbom.json');
  form.append('idempotency_key', idempotencyKey);
  form.append('authorization_confirmed', 'true');
  form.append('public_registry_identities_confirmed', String(publicRegistryIdentitiesConfirmed));
  const response = await apiFetch(`/projects/${encodeURIComponent(projectId)}/sbom-revisions`, {
    method: 'POST',
    body: form,
  });
  return parseJsonResponse<ProjectSbomRevisionCreated>(response);
}

export async function listProjectAnalysisPage(projectId: string, cursor?: string | null): Promise<JobPage> {
  const basePath = `/projects/${encodeURIComponent(projectId)}/analyses`;
  try {
    const payload = await parseJsonResponse<JobPage | JobListItem[]>(await apiFetch(`${basePath}/search`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ page_size: 50, ...(cursor ? { cursor } : {}) }),
    }));
    if (!Array.isArray(payload)) {
      return payload;
    }
    if (cursor) {
      throw new ApiError('Project analysis history response is invalid.', 502);
    }
  } catch (error) {
    if (cursor || !(error instanceof ApiError) || error.status !== 404) {
      throw error;
    }
  }
  const legacyItems = await parseJsonResponse<JobListItem[]>(await apiFetch(basePath));
  return {
    contract_version: '2026-09-08.1',
    items: legacyItems,
    returned_count: legacyItems.length,
    total_count: legacyItems.length,
    has_more: false,
    next_cursor: null,
  };
}

export async function listProjectAnalyses(projectId: string): Promise<JobListItem[]> {
  return (await listProjectAnalysisPage(projectId)).items;
}

export async function getProjectAnalysisSummary(projectId: string, analysisId: string): Promise<JobListItem> {
  const response = await apiFetch(
    `/projects/${encodeURIComponent(projectId)}/analyses/${encodeURIComponent(analysisId)}`
  );
  return parseJsonResponse<JobListItem>(response);
}

export async function getProjectDeletionPreview(projectId: string): Promise<ProjectDeletionPreview> {
  const response = await apiFetch(`/projects/${encodeURIComponent(projectId)}/deletion`);
  return parseJsonResponse<ProjectDeletionPreview>(response);
}

export async function deleteProject(projectId: string): Promise<ProjectDeletionResponse> {
  const response = await apiFetch(`/projects/${encodeURIComponent(projectId)}`, {
    method: 'DELETE',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ deletion_confirmed: true }),
  });
  return parseJsonResponse<ProjectDeletionResponse>(response);
}

export function createIdempotencyKey(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

export async function createProjectSnapshot(
  projectId: string,
  sourceFileId: string,
  idempotencyKey: string,
): Promise<ProjectSnapshotCreated> {
  const response = await apiFetch(`/projects/${encodeURIComponent(projectId)}/snapshots`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ source_file_id: sourceFileId, idempotency_key: idempotencyKey, authorization_confirmed: true }),
  });
  return parseJsonResponse<ProjectSnapshotCreated>(response);
}

export async function getProjectFindings(projectId: string, analysisId?: string): Promise<ProjectFindingsResponse> {
  const params = analysisId ? `?analysis_id=${encodeURIComponent(analysisId)}` : '';
  const response = await apiFetch(`/projects/${projectId}/findings${params}`);
  return parseJsonResponse<ProjectFindingsResponse>(response);
}

export async function createProjectFindingDecision(
  projectId: string,
  findingId: string,
  decision: FindingDecisionCreateRequest,
): Promise<FindingDecisionRecord> {
  const response = await apiFetch(
    `/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/decisions`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(decision),
    },
  );
  return parseJsonResponse<FindingDecisionRecord>(response);
}

export async function getProjectFindingActivity(
  projectId: string,
  findingId: string,
  cursor?: string,
): Promise<FindingActivityPage> {
  const params = new URLSearchParams({ page_size: '10' });
  if (cursor) params.set('cursor', cursor);
  const response = await apiFetch(
    `/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}/activity?${params.toString()}`,
  );
  return parseJsonResponse<FindingActivityPage>(response);
}

export async function getProjectComponentInventory(projectId: string, analysisId?: string): Promise<ProjectComponentInventoryResponse> {
  const params = analysisId ? `?analysis_id=${encodeURIComponent(analysisId)}` : '';
  const response = await apiFetch(`/projects/${projectId}/components${params}`);
  return parseJsonResponse<ProjectComponentInventoryResponse>(response);
}

export async function getProjectVulnerabilityIntelligence(
  projectId: string,
  analysisId: string,
  snapshotId?: string
): Promise<ProjectVulnerabilityIntelligenceResponse> {
  const params = snapshotId ? `?${new URLSearchParams({ snapshot_id: snapshotId }).toString()}` : '';
  const response = await apiFetch(
    `/projects/${encodeURIComponent(projectId)}/analyses/${encodeURIComponent(analysisId)}/vulnerability-intelligence${params}`
  );
  return parseJsonResponse<ProjectVulnerabilityIntelligenceResponse>(response);
}

export async function runProjectOsvVulnerabilityIntelligence(
  projectId: string,
  analysisId: string
): Promise<ProjectVulnerabilityIntelligenceResponse> {
  const response = await apiFetch(
    `/projects/${encodeURIComponent(projectId)}/analyses/${encodeURIComponent(analysisId)}/vulnerability-intelligence/osv`,
    { method: 'POST' }
  );
  return parseJsonResponse<ProjectVulnerabilityIntelligenceResponse>(response);
}

export async function runProjectGithubVulnerabilityIntelligence(
  projectId: string,
  analysisId: string,
): Promise<ProjectVulnerabilityIntelligenceResponse> {
  const response = await apiFetch(
    `/projects/${encodeURIComponent(projectId)}/analyses/${encodeURIComponent(analysisId)}/vulnerability-intelligence/github`,
    { method: "POST" },
  );
  return parseJsonResponse<ProjectVulnerabilityIntelligenceResponse>(response);
}

export async function runProjectCisaKevVulnerabilityIntelligence(
  projectId: string,
  analysisId: string,
): Promise<ProjectVulnerabilityIntelligenceResponse> {
  const response = await apiFetch(
    `/projects/${encodeURIComponent(projectId)}/analyses/${encodeURIComponent(analysisId)}/vulnerability-intelligence/cisa-kev`,
    { method: "POST" },
  );
  return parseJsonResponse<ProjectVulnerabilityIntelligenceResponse>(response);
}

export async function runProjectNvdVulnerabilityIntelligence(
  projectId: string,
  analysisId: string,
): Promise<ProjectVulnerabilityIntelligenceResponse> {
  const response = await apiFetch(
    `/projects/${encodeURIComponent(projectId)}/analyses/${encodeURIComponent(analysisId)}/vulnerability-intelligence/nvd`,
    { method: "POST" },
  );
  return parseJsonResponse<ProjectVulnerabilityIntelligenceResponse>(response);
}

export async function getProjectAnalysisComparison(
  projectId: string,
  baseAnalysisId: string,
  targetAnalysisId: string
): Promise<ProjectAnalysisComparisonResponse> {
  const params = new URLSearchParams({ base_analysis_id: baseAnalysisId, target_analysis_id: targetAnalysisId });
  const response = await apiFetch(`/projects/${projectId}/comparisons?${params.toString()}`);
  return parseJsonResponse<ProjectAnalysisComparisonResponse>(response);
}

export async function setProjectBaseline(projectId: string, analysisId: string): Promise<ProjectRecord> {
  const response = await apiFetch(`/projects/${encodeURIComponent(projectId)}/baseline`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ analysis_id: analysisId, baseline_confirmed: true }),
  });
  return parseJsonResponse<ProjectRecord>(response);
}

export async function clearProjectBaseline(projectId: string): Promise<ProjectRecord> {
  const response = await apiFetch(`/projects/${encodeURIComponent(projectId)}/baseline`, { method: "DELETE" });
  return parseJsonResponse<ProjectRecord>(response);
}

export async function launchProjectAnalysis(projectId: string, retryOfAnalysisId?: string): Promise<JobListItem> {
  const response = await apiFetch(`/projects/${projectId}/analyses`, {
    method: 'POST',
    ...(retryOfAnalysisId
      ? { headers: { 'content-type': 'application/json' }, body: JSON.stringify({ retry_of_analysis_id: retryOfAnalysisId }) }
      : {}),
  });
  return parseJsonResponse<JobListItem>(response);
}

export async function cancelProjectAnalysis(projectId: string, analysisId: string): Promise<JobListItem> {
  const response = await apiFetch(
    `/projects/${encodeURIComponent(projectId)}/analyses/${encodeURIComponent(analysisId)}/cancel`,
    { method: 'POST' }
  );
  return parseJsonResponse<JobListItem>(response);
}

export async function launchPdfAudit(fileId: string): Promise<JobRecord> {
  const response = await apiFetch(`/audits/pdf/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchImageAudit(fileId: string): Promise<JobRecord> {
  const response = await apiFetch(`/audits/image/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchManifestAudit(fileId: string): Promise<JobRecord> {
  const response = await apiFetch(`/audits/manifest/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchArchiveAudit(fileId: string): Promise<JobRecord> {
  const response = await apiFetch(`/audits/archive/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchProjectArchiveAudit(fileId: string): Promise<JobRecord> {
  const response = await apiFetch(`/audits/project-archive/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchDjangoConfigAudit(fileId: string): Promise<JobRecord> {
  const response = await apiFetch(`/audits/django-config/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchDockerConfigAudit(fileId: string): Promise<JobRecord> {
  const response = await apiFetch(`/audits/docker-config/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchSecretsReviewAudit(fileId: string): Promise<JobRecord> {
  const response = await apiFetch(`/audits/secrets-review/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchNodePackageConfigAudit(fileId: string): Promise<JobRecord> {
  const response = await apiFetch(`/audits/node-package-config/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchCiCdConfigAudit(fileId: string): Promise<JobRecord> {
  const response = await apiFetch(`/audits/ci-cd-config/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchK8sConfigAudit(fileId: string): Promise<JobRecord> {
  const response = await apiFetch(`/audits/k8s-config/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchTerraformConfigAudit(fileId: string): Promise<JobRecord> {
  const response = await apiFetch(`/audits/terraform-config/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchNginxConfigAudit(fileId: string): Promise<JobRecord> {
  const response = await apiFetch(`/audits/nginx-config/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchComposeConfigAudit(fileId: string): Promise<JobRecord> {
  const response = await apiFetch(`/audits/compose-config/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchDatabaseConfigAudit(fileId: string): Promise<JobRecord> {
  const response = await apiFetch(`/audits/database-config/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchRedisConfigAudit(fileId: string): Promise<JobRecord> {
  const response = await apiFetch(`/audits/redis-config/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchSqlDatabaseConfigAudit(fileId: string): Promise<JobRecord> {
  const response = await apiFetch(`/audits/sql-database-config/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchWebBasicAudit(url: string, authorizationConfirmed: boolean): Promise<JobRecord> {
  const response = await apiFetch('/audits/web/basic', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url, authorization_confirmed: authorizationConfirmed }),
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchDomainBasicAudit(domain: string, authorizationConfirmed: boolean): Promise<JobRecord> {
  const response = await apiFetch('/audits/domain/basic', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ domain, authorization_confirmed: authorizationConfirmed }),
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchSubdomainInventoryAudit(rootDomain: string, subdomains: string[], authorizationConfirmed: boolean): Promise<JobRecord> {
  const response = await apiFetch('/audits/subdomains/basic', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ root_domain: rootDomain, subdomains, authorization_confirmed: authorizationConfirmed }),
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function createActiveNetworkDryRun(request: ActiveDryRunRequest): Promise<JobRecord> {
  const response = await apiFetch('/active/network/dry-run', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(request),
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function createActiveHttpHeaderProbe(request: ActiveHttpHeaderProbeRequest): Promise<JobRecord> {
  const response = await apiFetch('/active/network/http-header-probe', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(request),
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function createActiveHttpBasicHeaderReview(request: ActiveHttpBasicHeaderReviewRequest): Promise<JobRecord> {
  const response = await apiFetch('/active/web/http-basic-header-review', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(request),
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function createActiveNmapBasic(request: ActiveNmapBasicRequest): Promise<JobRecord> {
  const response = await apiFetch('/active/network/nmap-basic', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(request),
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function createActiveTlsBasic(request: ActiveTlsBasicRequest): Promise<JobRecord> {
  const response = await apiFetch('/active/network/tls-basic', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(request),
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function createActiveDnsInventory(request: ActiveDnsInventoryRequest): Promise<JobRecord> {
  const response = await apiFetch('/active/network/dns-inventory', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(request),
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function createActiveDnsOsint(request: ActiveDnsOsintRequest): Promise<JobRecord> {
  const response = await apiFetch('/active/network/dns-osint', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(request),
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function listJobPage(cursor?: string | null): Promise<JobPage> {
  try {
    const response = await apiFetch('/jobs/search', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ page_size: 50, ...(cursor ? { cursor } : {}) }),
    });
    const payload = await parseJsonResponse<JobPage | JobListItem[]>(response);
    if (!Array.isArray(payload)) {
      return payload;
    }
    if (cursor) {
      throw new ApiError('Job history response is invalid.', 502);
    }
  } catch (error) {
    if (cursor || !(error instanceof ApiError) || error.status !== 404) {
      throw error;
    }
  }
  const legacyItems = await parseJsonResponse<JobListItem[]>(await apiFetch('/jobs'));
  return {
    contract_version: '2026-09-08.1',
    items: legacyItems,
    returned_count: legacyItems.length,
    total_count: legacyItems.length,
    has_more: false,
    next_cursor: null,
  };
}

export async function getJob(jobId: string): Promise<JobRecord> {
  const response = await apiFetch(`/jobs/${jobId}`);
  return parseJsonResponse<JobRecord>(response);
}

export function jobExportUrl(jobId: string, format: ReportFormat): string {
  return `${API_BASE_URL}/jobs/${jobId}/export/${format}`;
}

export function jobSbomUrl(jobId: string, format: SbomFormat): string {
  return `${API_BASE_URL}/jobs/${jobId}/sbom/${format}`;
}

export function projectAnalysisReportUrl(
  projectId: string,
  analysisId: string,
  format: 'markdown' | 'html' | 'pdf',
  vulnerabilitySnapshotId?: string | null,
): string {
  const params = vulnerabilitySnapshotId
    ? `?${new URLSearchParams({ vulnerability_snapshot_id: vulnerabilitySnapshotId }).toString()}`
    : '';
  return `${API_BASE_URL}/projects/${encodeURIComponent(projectId)}/analyses/${encodeURIComponent(analysisId)}/report/${format}${params}`;
}

export async function exportProjectAnalysisTechnicalReport(
  projectId: string,
  analysisId: string,
  format: 'markdown' | 'html' | 'pdf',
  vulnerabilitySnapshotId?: string | null,
): Promise<{ blob: Blob; filename: string }> {
  const response = await apiFetch(
    `/projects/${encodeURIComponent(projectId)}/analyses/${encodeURIComponent(analysisId)}/report/${format}`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        profile: 'technical',
        technical_detail_confirmed: true,
        ...(vulnerabilitySnapshotId ? { vulnerability_snapshot_id: vulnerabilitySnapshotId } : {}),
      }),
    },
  );
  if (!response.ok) {
    const payload = response.headers.get('content-type')?.includes('application/json')
      ? await response.json()
      : null;
    if (response.status === 401 || response.status === 403) authContext.onAuthFailure?.(response.status);
    throw new ApiError(payload?.detail || 'Technical project report could not be generated.', response.status);
  }
  const disposition = response.headers.get('content-disposition') || '';
  const extension = format === 'markdown' ? 'md' : format;
  return {
    blob: await response.blob(),
    filename: /filename="([^"]+)"/.exec(disposition)?.[1] ?? `inspectra-project-technical.${extension}`,
  };
}

export const api = {
  baseUrl: apiBaseUrl,
  configureAuthContext,
  getAuthStatus,
  login,
  logout,
  acceptTeamInvitation,
  getTeamOrganization,
  listTeamOrganizations,
  createTeamOrganization,
  selectTeamOrganization,
  listTeamMembers,
  createTeamInvitation,
  changeTeamMemberRole,
  revokeTeamMember,
  listFederatedIdentities,
  provisionFederatedIdentity,
  revokeFederatedIdentity,
  getIntegrationEventStatus,
  getIntegrationEventReplayPreflight,
  replayDeadIntegrationEvents,
  getTeamMemberActiveImpact,
  listPublicIdentityAttestations,
  proposePublicIdentityAttestation,
  approvePublicIdentityAttestation,
  revokePublicIdentityAttestation,
  listAutomationTokens,
  createAutomationToken,
  revokeAutomationToken,
  probeAutomationToken,
  createRepositoryImportGrant,
  listProductAuditEvents,
  verifyProductAuditIntegrity,
  getProductAuditExportPreflight,
  exportProductAudit,
  getActiveAuditExportPreflight,
  activeAuditExportUrl,
  getRetentionPolicy,
  runRetentionCleanup,
  getPublicAdvisoryOperations,
  purgeExpiredPublicAdvisoryCache,
  health: getHealth,
  listFiles,
  uploadPdf,
  uploadImage,
  uploadManifest,
  uploadArchive,
  deleteFile,
  listProjects,
  listProjectPage,
  getProject,
  updateProjectResponsibility,
  searchProjectPortfolio,
  getProjectActions,
  markProjectActionRead,
  rebuildProjectActions,
  searchRemediationCenter,
  applyRemediationAction,
  listRemediationSavedViews,
  createRemediationSavedView,
  setDefaultRemediationSavedView,
  deleteRemediationSavedView,
  exportRemediationReport,
  listRemediationPlans,
  createRemediationPlan,
  cancelRemediationPlan,
  retryRemediationPlan,
  downloadRemediationPlan,
  getProjectRiskTrends,
  refreshProjectRiskTrends,
  exportProjectRiskTrends,
  getProjectArchivePreflight,
  createProject,
  importSbomProject,
  preflightSbomProject,
  importProjectSbomRevision,
  listProjectAnalysisPage,
  listProjectAnalyses,
  getProjectAnalysisSummary,
  getProjectDeletionPreview,
  deleteProject,
  createProjectSnapshot,
  getProjectFindings,
  createProjectFindingDecision,
  getProjectFindingActivity,
  getProjectComponentInventory,
  getProjectVulnerabilityIntelligence,
  runProjectOsvVulnerabilityIntelligence,
  runProjectGithubVulnerabilityIntelligence,
  runProjectNvdVulnerabilityIntelligence,
  runProjectCisaKevVulnerabilityIntelligence,
  getProjectAnalysisComparison,
  setProjectBaseline,
  clearProjectBaseline,
  launchProjectAnalysis,
  cancelProjectAnalysis,
  launchPdfAudit,
  launchImageAudit,
  launchManifestAudit,
  launchArchiveAudit,
  launchProjectArchiveAudit,
  launchDjangoConfigAudit,
  launchDockerConfigAudit,
  launchSecretsReviewAudit,
  launchNodePackageConfigAudit,
  launchCiCdConfigAudit,
  launchK8sConfigAudit,
  launchTerraformConfigAudit,
  launchNginxConfigAudit,
  launchComposeConfigAudit,
  launchDatabaseConfigAudit,
  launchRedisConfigAudit,
  launchSqlDatabaseConfigAudit,
  launchWebBasicAudit,
  launchDomainBasicAudit,
  launchSubdomainInventoryAudit,
  createActiveNetworkDryRun,
  createActiveHttpHeaderProbe,
  createActiveHttpBasicHeaderReview,
  createActiveNmapBasic,
  createActiveTlsBasic,
  createActiveDnsInventory,
  createActiveDnsOsint,
  listActiveAssetPage,
  createActiveAssetExecution,
  cancelActiveAssetExecution,
  retryActiveAssetExecution,
  renewActiveAsset,
  updateActiveAssetResponsibles,
  listJobPage,
  getJob,
  jobExportUrl,
  jobSbomUrl,
  projectAnalysisReportUrl,
  exportProjectAnalysisTechnicalReport,
};
