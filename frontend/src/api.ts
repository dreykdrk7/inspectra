import type { DeletedFileResponse, FileRecord, HealthResponse, JobListItem, JobRecord, ReportFormat, SbomFormat } from './types';

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

async function parseJsonResponse<T>(response: Response): Promise<T> {
  const contentType = response.headers.get('content-type') || '';
  const payload = contentType.includes('application/json') ? await response.json() : null;

  if (!response.ok) {
    const detail = payload?.detail || payload?.message || response.statusText;
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
  }

  return payload as T;
}

export function apiBaseUrl(): string {
  return API_BASE_URL;
}

export async function getHealth(): Promise<HealthResponse> {
  const response = await fetch(`${API_BASE_URL}/health`);
  return parseJsonResponse<HealthResponse>(response);
}

export async function listFiles(): Promise<FileRecord[]> {
  const response = await fetch(`${API_BASE_URL}/files`);
  return parseJsonResponse<FileRecord[]>(response);
}

export async function uploadPdf(file: File): Promise<FileRecord> {
  const formData = new FormData();
  formData.append('file', file);
  const response = await fetch(`${API_BASE_URL}/files/pdf`, {
    method: 'POST',
    body: formData,
  });
  return parseJsonResponse<FileRecord>(response);
}

export async function uploadImage(file: File): Promise<FileRecord> {
  const formData = new FormData();
  formData.append('file', file);
  const response = await fetch(`${API_BASE_URL}/files/image`, {
    method: 'POST',
    body: formData,
  });
  return parseJsonResponse<FileRecord>(response);
}

export async function uploadManifest(file: File): Promise<FileRecord> {
  const formData = new FormData();
  formData.append('file', file);
  const response = await fetch(`${API_BASE_URL}/files/manifest`, {
    method: 'POST',
    body: formData,
  });
  return parseJsonResponse<FileRecord>(response);
}

export async function uploadArchive(file: File): Promise<FileRecord> {
  const formData = new FormData();
  formData.append('file', file);
  const response = await fetch(`${API_BASE_URL}/files/archive`, {
    method: 'POST',
    body: formData,
  });
  return parseJsonResponse<FileRecord>(response);
}

export async function deleteFile(fileId: string): Promise<DeletedFileResponse> {
  const response = await fetch(`${API_BASE_URL}/files/${fileId}`, {
    method: 'DELETE',
  });
  return parseJsonResponse<DeletedFileResponse>(response);
}

export async function launchPdfAudit(fileId: string): Promise<JobRecord> {
  const response = await fetch(`${API_BASE_URL}/audits/pdf/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchImageAudit(fileId: string): Promise<JobRecord> {
  const response = await fetch(`${API_BASE_URL}/audits/image/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchManifestAudit(fileId: string): Promise<JobRecord> {
  const response = await fetch(`${API_BASE_URL}/audits/manifest/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchArchiveAudit(fileId: string): Promise<JobRecord> {
  const response = await fetch(`${API_BASE_URL}/audits/archive/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchProjectArchiveAudit(fileId: string): Promise<JobRecord> {
  const response = await fetch(`${API_BASE_URL}/audits/project-archive/${fileId}`, {
    method: 'POST',
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchWebBasicAudit(url: string, authorizationConfirmed: boolean): Promise<JobRecord> {
  const response = await fetch(`${API_BASE_URL}/audits/web/basic`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url, authorization_confirmed: authorizationConfirmed }),
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchDomainBasicAudit(domain: string, authorizationConfirmed: boolean): Promise<JobRecord> {
  const response = await fetch(`${API_BASE_URL}/audits/domain/basic`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ domain, authorization_confirmed: authorizationConfirmed }),
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function launchSubdomainInventoryAudit(rootDomain: string, subdomains: string[], authorizationConfirmed: boolean): Promise<JobRecord> {
  const response = await fetch(`${API_BASE_URL}/audits/subdomains/basic`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ root_domain: rootDomain, subdomains, authorization_confirmed: authorizationConfirmed }),
  });
  return parseJsonResponse<JobRecord>(response);
}

export async function listJobs(): Promise<JobListItem[]> {
  const response = await fetch(`${API_BASE_URL}/jobs`);
  return parseJsonResponse<JobListItem[]>(response);
}

export async function getJob(jobId: string): Promise<JobRecord> {
  const response = await fetch(`${API_BASE_URL}/jobs/${jobId}`);
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
  launchWebBasicAudit,
  launchDomainBasicAudit,
  launchSubdomainInventoryAudit,
  listJobs,
  getJob,
  jobExportUrl,
  jobSbomUrl,
};
