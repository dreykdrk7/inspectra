import type {
  ActiveDryRunRequest,
  ActiveHttpHeaderProbeRequest,
  ActiveNmapBasicContractResponse,
  ActiveNmapBasicRequest,
  AuthSessionResponse,
  AuthStatusResponse,
  DeletedFileResponse,
  FileRecord,
  HealthResponse,
  JobListItem,
  JobRecord,
  ReportFormat,
  SbomFormat
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

export async function getHealth(): Promise<HealthResponse> {
  const response = await apiFetch('/health');
  return parseJsonResponse<HealthResponse>(response);
}

export async function getAuthStatus(): Promise<AuthStatusResponse> {
  const response = await apiFetch('/auth/status');
  return parseJsonResponse<AuthStatusResponse>(response, { skipAuthFailure: true });
}

export async function login(password: string): Promise<AuthSessionResponse> {
  const response = await apiFetch('/auth/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password }),
  });
  return parseJsonResponse<AuthSessionResponse>(response, { skipAuthFailure: true });
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

export async function createActiveNmapBasic(request: ActiveNmapBasicRequest): Promise<ActiveNmapBasicContractResponse> {
  const response = await apiFetch('/active/network/nmap-basic', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(request),
  });
  if (response.status === 501) {
    const payload = await response.json();
    return payload as ActiveNmapBasicContractResponse;
  }
  return parseJsonResponse<ActiveNmapBasicContractResponse>(response);
}

export async function listJobs(): Promise<JobListItem[]> {
  const response = await apiFetch('/jobs');
  return parseJsonResponse<JobListItem[]>(response);
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

export const api = {
  baseUrl: apiBaseUrl,
  configureAuthContext,
  getAuthStatus,
  login,
  logout,
  health: getHealth,
  listFiles,
  uploadPdf,
  uploadImage,
  uploadManifest,
  uploadArchive,
  deleteFile,
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
  createActiveNmapBasic,
  listJobs,
  getJob,
  jobExportUrl,
  jobSbomUrl,
};
