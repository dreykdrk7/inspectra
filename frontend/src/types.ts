export type HealthResponse = {
  status: string;
  service: string;
};

export type FileRecord = {
  id: string;
  original_filename: string;
  stored_filename: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  created_at: string;
};

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed';

export type JobRecord = {
  id: string;
  audit_type: 'pdf_basic';
  file_id: string;
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
