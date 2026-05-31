export type HealthResponse = {
  status: string;
  service: string;
};

export type FileRecord = {
  id: string;
  kind: 'pdf' | 'image' | 'manifest' | 'archive';
  original_filename: string;
  stored_filename: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  created_at: string;
};

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed';
export type AuditType =
  | 'pdf_basic'
  | 'image_basic'
  | 'manifest_basic'
  | 'archive_basic'
  | 'project_archive_basic'
  | 'web_basic'
  | 'domain_basic'
  | 'subdomain_inventory_basic'
  | 'django_config_basic'
  | 'docker_config_basic'
  | 'secrets_review_basic'
  | 'node_package_config_basic'
  | 'ci_cd_config_basic'
  | 'k8s_config_basic'
  | 'terraform_config_basic';
export type ReportFormat = 'markdown' | 'html' | 'xml' | 'pdf';
export type SbomFormat = 'cyclonedx-json' | 'spdx-json';

export type JobRecord = {
  id: string;
  audit_type: AuditType;
  file_id: string | null;
  target_url: string | null;
  target_domain: string | null;
  status: JobStatus;
  created_at: string;
  updated_at: string;
  source_file_deleted_at: string | null;
  result: Record<string, unknown> | null;
  error: string | null;
};

export type JobListItem = Omit<JobRecord, 'result' | 'error'> & {
  summary: Record<string, unknown> | null;
};

export type DeletedFileResponse = {
  deleted_file: FileRecord;
  associated_jobs_marked: number;
};
