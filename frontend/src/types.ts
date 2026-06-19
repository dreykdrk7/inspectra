export type HealthResponse = {
  status: string;
  service: string;
  active_nmap_basic?: {
    enabled?: boolean;
    available?: boolean;
    status?: string;
  } | null;
};

export type AuthMode =
  | 'trusted_local_no_auth'
  | 'self_hosted_single_admin'
  | 'private_team_lightweight_users'
  | 'public_community_limited_instance';

export type AuthStatusResponse = {
  auth_mode: AuthMode;
  auth_required: boolean;
  configured: boolean;
  trusted_local: boolean;
  default_operator_id: string;
  login_available: boolean;
  authenticated: boolean;
  operator_id: string | null;
  csrf_required: boolean;
  csrf_token: string | null;
};

export type AuthSessionResponse = {
  authenticated: boolean;
  operator_id: string | null;
  auth_mode: AuthMode;
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
  | 'active_network_dry_run'
  | 'active_http_header_probe'
  | 'active_http_basic_header_review'
  | 'active_nmap_basic'
  | 'active_tls_basic'
  | 'active_dns_inventory'
  | 'active_dns_osint'
  | 'django_config_basic'
  | 'docker_config_basic'
  | 'secrets_review_basic'
  | 'node_package_config_basic'
  | 'ci_cd_config_basic'
  | 'k8s_config_basic'
  | 'terraform_config_basic'
  | 'nginx_config_basic'
  | 'compose_config_basic'
  | 'database_config_basic'
  | 'redis_config_basic'
  | 'sql_database_config_basic';
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

export type ActiveDryRunRequest = {
  target: string;
  authorization: {
    confirmed: boolean;
    statement: 'I confirm I own or am authorized to test this target.';
    scope: 'single-target';
  };
  mode: 'dry_run';
  profile: 'http_header_probe_preview';
  limits: {
    max_requests: 0;
    timeout_seconds: 0;
    max_redirects: 0;
    response_size_bytes: 0;
  };
};

export type ActiveHttpHeaderProbeRequest = {
  target: string;
  authorization: {
    confirmed: boolean;
    live_traffic_confirmed: boolean;
    statement: 'I confirm I own or am authorized to test this target.';
    scope: 'single-target';
  };
  mode: 'live_header_probe';
  profile: 'http_header_probe';
  limits: {
    max_targets: 1;
    max_requests: 1;
    timeout_seconds: 3;
    max_redirects: 0;
    response_body_bytes: 0;
    max_response_header_bytes: 32768;
    max_dns_answers: 8;
    retries: 0;
    concurrency: 1;
  };
};

export type ActiveHttpBasicHeaderReviewRequest = {
  mode: 'live_http_basic_header_review';
  profile: 'http_headers_single_request';
  target: string;
  method: 'HEAD';
  authorization_confirmed: boolean;
  target_control_confirmed: boolean;
  delegated_permission_confirmed: boolean;
  live_http_request_confirmed: boolean;
};

export type ActiveNmapBasicRequest = {
  mode: 'live_nmap_basic';
  profile: 'tcp_connect_small';
  targets: string[];
  ports: number[];
  authorization_confirmed: true;
  local_private_scope_confirmed: true;
  live_traffic_confirmed: true;
};

export type ActiveTlsBasicRequest = {
  mode: 'live_tls_basic';
  profile: 'tls_handshake_summary';
  target: string;
  port: number;
  authorization_confirmed: true;
  local_private_scope_confirmed: true;
  live_traffic_confirmed: true;
};

export type ActiveDnsInventoryRequest = {
  mode: 'live_dns_inventory';
  profile: 'dns_inventory_authorized';
  domain: string;
  record_types: string[];
  include_security_records: boolean;
  include_subdomain_discovery: boolean;
  attempt_zone_transfer: boolean;
  zone_transfer_authorized_confirmed?: true;
  authorization_confirmed: true;
  local_private_or_owned_scope_confirmed: true;
  live_dns_queries_confirmed: true;
};

export type ActiveDnsOsintRequest = {
  mode: 'live_dns_osint';
  profile: 'ct_subdomain_discovery_bounded';
  domain: string;
  include_certificate_transparency: true;
  include_passive_dns: false;
  max_names: number;
  authorization_confirmed: true;
  owned_or_authorized_domain_confirmed: true;
  public_osint_queries_confirmed: true;
};
