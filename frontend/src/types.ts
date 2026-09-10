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
  username?: string | null;
  organization_id?: string | null;
  organization_name?: string | null;
  role?: TeamRole | null;
  csrf_required: boolean;
  csrf_token: string | null;
};

export type AuthSessionResponse = {
  authenticated: boolean;
  operator_id: string | null;
  auth_mode: AuthMode;
  organization_id?: string | null;
  role?: TeamRole | null;
};

export type TeamRole = 'administrator' | 'maintainer' | 'reader';

export type AutomationTokenScope = 'project:read' | 'project:scan' | 'report:read';
export type AutomationToken = {
  id: string;
  name: string;
  project_id: string;
  scopes: AutomationTokenScope[];
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
};
export type AutomationTokenCreated = AutomationToken & { token: string };
export type AutomationTokenProbe = {
  status: 'ready' | 'expired' | 'revoked' | 'project_unavailable';
  project_id: string;
  scopes: AutomationTokenScope[];
  scopes_complete: boolean;
  expires_at: string;
};

export type TeamOrganization = {
  id: string;
  name: string;
  current_user_id: string;
  current_username: string;
  current_role: TeamRole;
};

export type TeamOrganizationListItem = {
  id: string;
  name: string;
  role: TeamRole;
  created_at: string;
};

export type TeamMember = {
  user_id: string;
  username: string;
  role: TeamRole;
  joined_at: string;
};

export type TeamInvitation = {
  invitation_id: string;
  token: string;
  username: string;
  role: TeamRole;
  expires_at: string;
};

export type PublicIdentityEcosystem = 'npm' | 'pypi' | 'go' | 'cargo' | 'composer' | 'maven' | 'nuget';

export type PublicIdentityAttestation = {
  contract_version: '2026-09-09.1';
  id: string;
  ecosystem: PublicIdentityEcosystem;
  package_name: string;
  status: 'pending' | 'approved' | 'expired' | 'revoked';
  revision: number;
  requested_ttl_days: number;
  proposed_at: string;
  approved_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
};

export type PublicAdvisoryProviderOperations = {
  provider: 'osv' | 'github_advisories' | 'nvd' | 'cisa_kev';
  configured: boolean;
  cache_entries: number;
  fresh_entries: number;
  stale_entries: number;
  invalid_entries: number;
  cache_bytes: number;
  last_updated_at: string | null;
  truncated: boolean;
};

export type PublicAdvisoryOperations = {
  contract_version: '2026-09-09.1';
  egress_enabled: boolean;
  offline_snapshot_active: boolean;
  providers: PublicAdvisoryProviderOperations[];
};

export type PublicAdvisoryCacheCleanup = {
  removed_entries: number;
  operations: PublicAdvisoryOperations;
};

export type ProductAuditEvent = {
  contract_version: '2026-09-06.1';
  id: string;
  organization_id: string;
  actor_id: string;
  actor_role: TeamRole;
  action: string;
  resource_type: string;
  resource_id: string;
  result: 'succeeded' | 'denied' | 'failed';
  correlation_id: string;
  occurred_at: string;
  metadata: Record<string, string | number | boolean>;
};

export type ProductAuditEventsResponse = {
  items: ProductAuditEvent[];
  next_cursor: string | null;
  retention_days: number;
};

export type ProductAuditIntegrityResponse = {
  contract_version: '2026-09-10.1';
  state: 'valid' | 'empty' | 'invalid';
  checked_at: string;
  bootstrap_performed: boolean;
  generation: number | null;
  retained_events: number | null;
  anchor_sequence: number | null;
  head_sequence: number | null;
  head_digest: string | null;
  failure_reason: 'integrity_check_failed' | null;
};

export type ProductAuditExportPreflight = {
  contract_version: '2026-09-10.1';
  state: 'ready' | 'no_matches';
  period: '7d' | '30d' | '90d' | '365d';
  starts_at: string;
  state_at: string;
  expires_at: string;
  action_filter: string | null;
  total_events: number;
  included_events: number;
  truncated: boolean;
  snapshot_digest: string;
  max_events: 1000;
  max_bytes: 1048576;
  retention_days: number;
  available_formats: ['json' | 'csv', 'json' | 'csv'];
  privacy: {
    organization_identifier_included: false;
    original_actor_identifier_included: false;
    original_resource_identifier_included: false;
    correlation_identifier_included: false;
    metadata_included: false;
    names_paths_targets_included: false;
    source_or_evidence_included: false;
  };
};

export type ActiveAuditExportPreflight = {
  contract_version: '2026-09-08.1';
  state: 'ready' | 'no_matches';
  period: '7d' | '30d' | '90d' | '365d';
  starts_at: string;
  ends_at: string;
  asset_filter_applied: boolean;
  total_events: number;
  included_events: number;
  truncated: boolean;
  max_events: 1000;
  retention_days: number;
  available_formats: ['json' | 'csv', 'json' | 'csv'];
  privacy: {
    target_included: false;
    authorization_reference_included: false;
    notes_included: false;
    client_ip_included: false;
    correlation_id_included: false;
    raw_metadata_included: false;
    raw_evidence_included: false;
  };
};

export type ActiveAssetBatchRow = {
  row: number;
  status: 'ready' | 'invalid' | 'duplicate_in_batch' | 'already_registered';
  reason_code: 'ready' | 'invalid_contract' | 'duplicate_identity' | 'identity_already_registered';
  asset_type: ActiveAsset['asset_type'] | null;
  canonical_value: string | null;
};

export type ActiveAssetBatchPreflight = {
  contract_version: '2026-09-08.1';
  state: 'ready' | 'needs_correction';
  format: 'json' | 'csv';
  input_count: number;
  ready_count: number;
  invalid_count: number;
  duplicate_count: number;
  conflict_count: number;
  can_confirm: boolean;
  review_digest_sha256: string;
  preflight_token: string | null;
  expires_at: string | null;
  rows: ActiveAssetBatchRow[];
};

export type ActiveAssetBatchCommit = {
  contract_version: '2026-09-08.1';
  batch_id: string;
  created_count: number;
  replayed: boolean;
  assets: ActiveAsset[];
};

export type RetentionPolicyClass = {
  key:
    | 'source_uploads'
    | 'analysis_results'
    | 'analysis_inventories'
    | 'public_advisory_snapshots'
    | 'public_advisory_cache'
    | 'report_exports'
    | 'remediation_plan_artifacts'
    | 'project_metadata'
    | 'finding_decisions'
    | 'passive_project_actions'
    | 'active_asset_metadata'
    | 'active_authorization_revisions'
    | 'active_verification_records'
    | 'active_execution_records'
    | 'active_change_approvals'
    | 'active_weekly_review_receipts'
    | 'execution_workspaces'
    | 'operation_journals'
    | 'product_audit'
    | 'auth_sessions'
    | 'automation_credentials'
    | 'team_invitations'
    | 'team_identity'
    | 'backup_bundles';
  label: string;
  category: 'project_data' | 'public_intelligence' | 'identity_and_operations' | 'external_copies';
  scope: 'organization' | 'shared_public_data' | 'request' | 'execution' | 'deployment' | 'operator_external';
  storage:
    | 'durable_upload_store'
    | 'durable_analysis_store'
    | 'embedded_in_analysis_result'
    | 'durable_public_intelligence_store'
    | 'durable_public_cache'
    | 'request_only'
    | 'durable_remediation_plan_store'
    | 'durable_project_store'
    | 'durable_finding_decision_store'
    | 'durable_project_action_store'
    | 'durable_active_asset_store'
    | 'durable_active_verification_store'
    | 'durable_active_change_approval_store'
    | 'durable_active_weekly_review_receipt_store'
    | 'ephemeral_workspace'
    | 'recoverable_operation_journal'
    | 'durable_product_audit_store'
    | 'durable_auth_state'
    | 'operator_external';
  sensitivity: 'project_content' | 'project_security_metadata' | 'public_provider_data' | 'credential_derived' | 'operational_metadata';
  retention_mode: 'bounded' | 'until_explicit_deletion' | 'not_persisted' | 'ephemeral' | 'follows_parent' | 'external_policy';
  retention_days: number | null;
  freshness_seconds: number | null;
  retention_seconds: number | null;
  automatic_cleanup: boolean;
  manual_cleanup: boolean;
  follows_class: 'analysis_results' | 'project_metadata' | 'active_asset_metadata' | null;
  deletion_triggers: Array<
    | 'retention_expiry'
    | 'explicit_source_deletion'
    | 'explicit_analysis_deletion'
    | 'explicit_project_deletion'
    | 'explicit_active_asset_deletion'
    | 'execution_completion'
    | 'startup_recovery'
    | 'session_expiry_or_revocation'
    | 'membership_revocation'
    | 'operator_restore'
    | 'operator_external_policy'
    | 'not_applicable'
  >;
  backup_disposition: 'included_sensitive' | 'included_regenerable' | 'excluded_ephemeral' | 'not_server_persisted' | 'operator_managed';
  restore_behavior: 'restored' | 'restored_sessions_revoked' | 'regenerated' | 'discarded' | 'not_applicable' | 'operator_managed';
  description: string;
};

export type RetentionPolicyResponse = {
  contract_version: '2026-09-10.6';
  cleanup_scope: 'active_organization_plus_shared_public_cache';
  cleanup_runs_at_startup: boolean;
  manual_cleanup_allowed: boolean;
  application_encryption_at_rest: 'operator_managed';
  backups: 'offline_bundle_operator_encrypted_not_automatically_purged';
  data_classification_complete: true;
  backup_contract_version: '2026-09-06.1';
  source_metadata_contract_version: '2026-09-09.2';
  source_metadata: SourceMetadataPolicy[];
  classes: RetentionPolicyClass[];
};

export type SourceMetadataPolicy = {
  key: 'original_filename' | 'content_sha256' | 'source_file_id' | 'source_reference' | 'source_channel';
  label: string;
  retained_in: Array<'source_upload' | 'project_record' | 'analysis_record' | 'derived_projection'>;
  sensitivity: 'private_source_label' | 'correlatable_content_digest' | 'opaque_internal_identifier' | 'safe_presentation_reference' | 'non_sensitive_provenance_enum';
  project_view_disclosure: 'withheld' | 'opaque_internal_only' | 'shown';
  report_disclosure: 'withheld' | 'shown';
  integration_disclosure: 'withheld' | 'shown';
  retention_relation: 'follows_each_parent_record' | 'derived_not_stored';
  description: string;
};

export type RetentionCleanupResponse = {
  contract_version: '2026-09-10.1';
  state: 'completed' | 'partial' | 'failed';
  scope: 'active_organization_plus_shared_public_cache';
  ran_at: string;
  results: Array<{
    key: 'source_uploads' | 'analysis_results' | 'public_advisory_cache' | 'automation_credentials' | 'team_invitations' | 'active_change_approvals' | 'active_weekly_review_receipts' | 'product_audit';
    status: 'completed' | 'failed' | 'disabled';
    removed_items: number | null;
    detail: string;
  }>;
};

export type FileRecord = {
  id: string;
  organization_id?: string | null;
  source_reference?: string;
  kind: 'pdf' | 'image' | 'manifest' | 'archive';
  original_filename: string;
  stored_filename: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  created_at: string;
};

export type JobStatus = 'queued' | 'running' | 'cancelling' | 'cancelled' | 'completed' | 'failed';
export type JobExecutionProfile = {
  contract_version: string;
  profile_name: string;
  ruleset_version: string;
  max_upload_bytes: number;
  audit_max_concurrency: number;
  audit_max_inflight_jobs?: number | null;
  audit_max_inflight_jobs_per_owner?: number | null;
  timeout_seconds?: number | null;
  workspace_policy?: 'isolated_copy_cleanup_v1' | 'isolated_copy_stream_worker_v1' | 'isolated_stream_worker_v1' | 'shared_source_v1' | null;
  workspace_max_bytes?: number | null;
  worker_contract_version?: string | null;
  worker_source_transport?: 'inline_base64_sha256_v1' | null;
  worker_lifecycle?: 'ephemeral_subprocess' | null;
  worker_max_concurrency?: number | null;
  worker_cpu_seconds?: number | null;
  worker_memory_bytes?: number | null;
  worker_max_result_bytes?: number | null;
  worker_max_file_bytes?: number | null;
  worker_max_open_files?: number | null;
  worker_max_processes?: number | null;
  max_total_uncompressed_bytes?: number | null;
  max_archive_entries?: number | null;
  max_manifests?: number | null;
  max_manifest_bytes?: number | null;
  max_total_manifest_bytes?: number | null;
  max_lockfiles?: number | null;
  max_lockfile_packages?: number | null;
  max_lockfile_edges?: number | null;
  license_policy_contract_version?: string | null;
  license_policy_denied_identifiers?: string[];
};
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
  organization_id?: string | null;
  project_id?: string | null;
  active_asset_id?: string | null;
  active_authorization_contract?: string | null;
  active_authorization_revision_id?: string | null;
  active_authorization_revision_digest_sha256?: string | null;
  active_authorization_revision_sequence?: number | null;
  active_execution_port?: number | null;
  active_execution_phase?: 'admitted' | 'waiting_for_runner' | 'executing' | 'normalizing' | 'terminal' | null;
  source_sha256?: string | null;
  source_reference?: string | null;
  analysis_profile?: string | null;
  execution_profile?: JobExecutionProfile | null;
  audit_type: AuditType;
  file_id?: string | null;
  target_url: string | null;
  target_domain: string | null;
  status: JobStatus;
  created_at: string;
  updated_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  cancellation_requested_at?: string | null;
  termination_reason?: string | null;
  retry_of_job_id?: string | null;
  recovery_count?: number;
  last_recovered_at?: string | null;
  source_file_deleted_at: string | null;
  result_integrity_status?: 'valid' | 'unknown';
  result: Record<string, unknown> | null;
  error: string | null;
};

export type JobListItem = Omit<JobRecord, 'result' | 'error' | 'source_sha256'> & {
  source_reference?: string | null;
  summary: Record<string, unknown> | null;
  status_detail?: {
    code: 'queued' | 'running' | 'cancelling' | 'cancelled' | 'completed' | 'interrupted_after_restart' | 'failed';
    message: string;
    next_action: 'wait' | 'view_results' | 'review_and_retry';
  };
};

export type JobPage = {
  contract_version: '2026-09-08.1';
  items: JobListItem[];
  returned_count: number;
  total_count: number;
  has_more: boolean;
  next_cursor: string | null;
};

export type ProjectRecord = {
  source_metadata_contract_version: '2026-09-06.1' | '2026-09-09.2';
  source_name_disclosure: 'withheld_use_files_view';
  source_digest_disclosure: 'retained_server_side';
  id: string;
  organization_id?: string | null;
  name: string;
  source_type?: 'archive' | 'sbom';
  source_reference: string;
  source_file_deleted_at: string | null;
  latest_job_id: string | null;
  baseline_analysis_id?: string | null;
  baseline_version?: number;
  baseline_updated_at?: string | null;
  analysis_count: number;
  responsibility?: {
    state: 'assigned' | 'unassigned' | 'unassigned_attention';
    responsible_user_id: string | null;
    revision: number;
    updated_at: string | null;
  };
  source_snapshots?: ProjectSourceSnapshot[];
  created_at: string;
  updated_at: string;
};

export type ProjectSourceSnapshot = {
  id: string;
  source_reference: string;
  source_commit_sha?: string | null;
  source_branch?: string | null;
  source_channel?: 'archive_upload' | 'git_cli' | 'ci' | 'sbom' | 'unknown_git_or_ci';
  source_file_deleted_at: string | null;
  created_at: string;
};

export type ProjectSummary = {
  project: ProjectRecord;
  latest_job: JobListItem | null;
};

export type ProjectPage = {
  contract_version: "2026-09-09.1";
  items: ProjectSummary[];
  returned_count: number;
  total_count: number;
  has_more: boolean;
  next_cursor: string | null;
};

export type ProjectCreated = {
  project: ProjectRecord;
  job: JobListItem;
};

export type SbomImportPreflight = {
  contract_version: '2026-09-08.1';
  status: 'ready';
  preflight_token: string;
  expires_at: string;
  format: 'cyclonedx' | 'spdx';
  spec_version: string;
  input_components: number;
  retained_components: number;
  rejected_or_ambiguous_components: number;
  potentially_correlatable_components: number;
  component_limit_reached: boolean;
  relationship_graph_truncated: boolean;
};

export type ProjectSnapshotCreated = {
  project: ProjectRecord;
  job: JobListItem;
  snapshot: ProjectSourceSnapshot;
};

export type ProjectSbomRevisionCreated = ProjectSnapshotCreated & {
  replayed: boolean;
};

export type ProjectDeletionScopeItem = {
  key:
    | 'project_metadata'
    | 'analysis_results'
    | 'public_advisory_snapshots'
    | 'finding_decisions'
    | 'snapshot_admissions'
    | 'execution_workspaces'
    | 'passive_project_actions'
    | 'source_uploads'
    | 'report_exports'
    | 'public_advisory_cache'
    | 'product_audit';
  disposition: 'delete' | 'retain' | 'not_persisted';
  item_count: number | null;
  detail: string;
};

export type ProjectDeletionPreview = {
  contract_version: '2026-09-06.1';
  project_id: string;
  state: 'ready' | 'blocked_active_work';
  requires_confirmation: true;
  items: ProjectDeletionScopeItem[];
};

export type ProjectDeletionResponse = {
  contract_version: '2026-09-06.1';
  project_id: string;
  state: 'completed' | 'already_absent';
  completed_at: string;
  items: ProjectDeletionScopeItem[];
};

export type ProjectArchivePreflightCapability = {
  name: string;
  ecosystem: string;
  coverage: string;
};

export type PassiveAnalysisProfileRule = {
  id: string;
  category: 'archive_safety' | 'dependency_hygiene' | 'package_execution' | 'coverage' | 'sensitive_data' | 'license';
  applies_to: string[];
  description: string;
};

export type PassiveAnalysisProfile = {
  contract_version: string;
  profile_name: string;
  title: string;
  ruleset_version: string;
  safe_default: boolean;
  selection_mode: 'manifest_driven_closed_catalog';
  execution_mode: 'passive_no_project_execution';
  network_access: 'disabled';
  supported_stacks: string[];
  rules: PassiveAnalysisProfileRule[];
  exclusions: string[];
};

export type ProjectArchivePreflightResponse = {
  contract_version: string;
  status: 'available';
  accepted_archive_formats: string[];
  upload_limit_bytes: number;
  analysis_profile: PassiveAnalysisProfile;
  execution_profile: JobExecutionProfile;
  supported_manifests: ProjectArchivePreflightCapability[];
  exact_resolution: ProjectArchivePreflightCapability[];
  detected_not_resolved: string[];
  limitations: string[];
  boundaries: string[];
};

export type NormalizedFindingReference = {
  type: 'cve' | 'ghsa' | 'owasp';
  id: string;
  url: string;
};

export type NormalizedFindingLocation = {
  path: string | null;
  line: number | null;
};

export type NormalizedFinding = {
  id: string;
  rule_id: string;
  source_audit_type: string;
  title: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'high' | 'medium' | 'low' | 'unknown';
  description: string;
  evidence: string;
  location: NormalizedFindingLocation | null;
  location_status?: 'reported' | 'withheld_unsafe_path' | 'not_reported';
  recommendation: string;
  references: NormalizedFindingReference[];
};

export type FindingDecisionStatus = 'open' | 'in_review' | 'accepted' | 'false_positive' | 'resolved';

export type FindingDecisionRecord = {
  contract_version: '2026-09-06.1';
  id: string;
  organization_id: string;
  project_id: string;
  finding_id: string;
  rule_id: string;
  status: FindingDecisionStatus;
  reason: string;
  comment: string | null;
  assignee_user_id: string | null;
  assignee_username: string | null;
  actor_id: string;
  actor_username: string;
  actor_role: string;
  review_at: string | null;
  created_at: string;
  previous_decision_id: string | null;
};

export type FindingLifecycleState = {
  finding_id: string;
  rule_id: string;
  current_status: FindingDecisionStatus;
  has_decision: boolean;
  needs_review: boolean;
  review_overdue?: boolean;
  current_decision: FindingDecisionRecord | null;
  history: FindingDecisionRecord[];
};

export type FindingDecisionCreateRequest = {
  analysis_id: string;
  status: FindingDecisionStatus;
  reason: string;
  comment?: string | null;
  assignee_user_id?: string | null;
  review_at?: string | null;
};

export type ProjectFindingsState =
  | 'ready'
  | 'analysis_pending'
  | 'analysis_failed'
  | 'analysis_cancelled'
  | 'no_completed_analysis'
  | 'no_normalized_findings';

export type ProjectFindingsResponse = {
  project: ProjectRecord;
  analysis: JobListItem | null;
  state: ProjectFindingsState;
  findings: NormalizedFinding[];
  summary: {
    total: number;
    by_severity: Record<string, number>;
    by_category: Record<string, number>;
    by_status?: Record<string, number>;
    needs_review?: number;
  };
  result_truncated: boolean;
  coverage?: {
    coverage_status: 'complete' | 'partial' | 'unknown';
    total_entries_seen: number;
    supported_manifests_found: number;
    supported_manifests_parsed: number;
    supported_manifests_skipped: number;
    unsupported_manifests_detected: number;
    lockfiles_detected: number;
    lockfiles_parsed: number;
    lockfiles_skipped: number;
    total_dependencies: number;
    source_retained: boolean;
    limitations: string[];
  } | null;
  lifecycle?: Record<string, FindingLifecycleState>;
};

export type ProjectComponent = {
  id: string;
  ecosystem: 'npm' | 'pypi' | 'go' | 'cargo' | 'composer' | 'maven' | 'nuget';
  name: string;
  manifest_path: string | null;
  manifest_path_status: 'reported' | 'withheld_unsafe_path' | 'not_reported';
  dependency_group: string;
  source_type: 'registry' | 'url' | 'vcs' | 'local' | 'editable' | 'workspace' | 'alias' | 'unknown';
  declared_version: string | null;
  exact_version: string | null;
  package_url?: string | null;
  dependency_scope?: 'direct' | 'transitive' | 'optional';
  relationship_status?: 'reported' | 'not_reported' | 'truncated';
  version_status: 'exact_declared' | 'exact_resolved' | 'declared_range' | 'not_correlatable';
  correlation_eligible: boolean;
  resolution: 'declared' | 'lockfile';
  lockfile_match_status?: 'matched' | 'not_matched' | 'ambiguous' | 'not_applicable';
  manifest_type: 'package_json' | 'requirements_txt' | 'pyproject_toml' | 'pipfile' | 'go_mod' | 'cargo_toml' | 'composer_json' | 'gradle_build' | 'dotnet_project' | 'cyclonedx' | 'spdx';
  lockfile_path: string | null;
  lockfile_path_status: 'reported' | 'withheld_unsafe_path' | 'not_reported';
  lockfile_type: 'npm_package_lock' | 'pnpm_lock' | 'yarn_classic_lock' | 'poetry_lock' | 'pipfile_lock' | 'go_sum' | 'cargo_lock' | 'composer_lock' | 'gradle_lock' | 'nuget_packages_lock' | null;
  enabled_feature_count?: number | null;
  target_variant_count?: number | null;
  build_scope_count?: number | null;
};

export type ProjectComponentInventoryState =
  | 'ready'
  | 'analysis_pending'
  | 'analysis_failed'
  | 'analysis_cancelled'
  | 'no_completed_analysis'
  | 'no_component_inventory';

export type ProjectComponentCoverage = {
  id: 'npm-package-lock' | 'npm-pnpm-lock' | 'npm-yarn-lock' | 'pypi-requirements' | 'pypi-pyproject' | 'pypi-poetry-lock' | 'pypi-pipfile-lock' | 'go-mod-sum' | 'cargo-lock' | 'composer-lock' | 'gradle-lock' | 'nuget-packages-lock';
  coverage_contract_version: string;
  ecosystem: 'npm' | 'pypi' | 'go' | 'cargo' | 'composer' | 'maven' | 'nuget';
  manager: 'npm' | 'pnpm' | 'yarn' | 'pip' | 'python-packaging' | 'poetry' | 'pipenv' | 'go-modules' | 'cargo' | 'composer' | 'gradle' | 'nuget';
  manifest: 'package.json' | 'requirements.txt' | 'pyproject.toml' | 'Pipfile' | 'go.mod' | 'Cargo.toml' | 'composer.json' | 'build.gradle' | '*.csproj';
  lockfile: 'package-lock.json' | 'pnpm-lock.yaml' | 'yarn.lock' | 'poetry.lock' | 'Pipfile.lock' | 'go.sum' | 'Cargo.lock' | 'composer.lock' | 'gradle.lockfile' | 'packages.lock.json' | 'not_applicable';
  parser_version: 'package-lock-json-v2-v3' | 'pnpm-lock-yaml-v9' | 'yarn-classic-lock-v1' | 'poetry-lock-toml-v2.1' | 'pipfile-lock-json-v6' | 'requirements-lines-v2-hash-summary' | 'pyproject-toml-v1' | 'go-mod-sum-v1' | 'cargo-lock-toml-v3-v4' | 'composer-lock-json-v1' | 'gradle-lockfile-v1' | 'nuget-packages-lock-json-v1' | 'not_available';
  direct_coverage: 'exact_same_root_when_matched' | 'exact_same_root_local_only' | 'exact_ci_graph' | 'declared_manifest_only' | 'not_available';
  transitive_coverage: 'bounded_registry_graph' | 'bounded_ci_graph' | 'not_available';
  manifest_status: 'not_detected' | 'parsed' | 'detected_not_parsed';
  lockfile_status: 'not_applicable' | 'not_detected' | 'parsed' | 'detected_not_parsed';
  exclusion_reason: 'none' | 'not_detected' | 'no_lockfile_contract' | 'unsupported_lockfile_parser' | 'defensive_limit_or_invalid_input' | 'no_same_root_match' | 'ambiguous_root_pair' | 'graph_truncated' | 'graph_divergent' | 'relationship_evidence_not_provided';
};

export type ProjectDependencyGraphEvidence = {
  contract_version: '2026-09-10.1';
  ecosystem: 'go';
  state: 'accepted' | 'truncated' | 'divergent';
  reason: 'none' | 'producer_truncated' | 'no_single_source_root' | 'identity_not_in_lockfile' | 'replaced_identity' | 'root_set_mismatch' | 'complete_graph_omits_manifest_requirement' | 'unreachable_node';
  artifact_sha256: string;
  source_commit_sha: string;
  source_binding_verified: true;
  nodes_reported: number;
  edges_reported: number;
  components_matched: number;
  components_unmatched: number;
  cycles_detected: boolean;
  truncation_reason: 'node_limit' | 'edge_limit' | 'producer_limit' | null;
};

export type CargoProjectDependencyGraphEvidence = {
  contract_version: '2026-09-10.2';
  ecosystem: 'cargo';
  state: 'accepted' | 'truncated' | 'divergent';
  reason: 'none' | 'producer_truncated' | 'no_single_source_root' | 'identity_not_in_lockfile' | 'unresolved_manifest_root' | 'root_set_mismatch' | 'unreachable_node';
  artifact_sha256: string;
  source_commit_sha: string;
  source_binding_verified: true;
  target_coverage: 'all_locked_targets';
  nodes_reported: number;
  edges_reported: number;
  features_reported: number;
  targets_reported: number;
  components_matched: number;
  components_unmatched: number;
  cycles_detected: boolean;
  truncation_reason: 'node_limit' | 'edge_limit' | 'feature_limit' | 'target_limit' | 'producer_limit' | null;
};

export type ProjectComponentInventoryResponse = {
  project: ProjectRecord;
  analysis: JobListItem | null;
  state: ProjectComponentInventoryState;
  contract_version: string | null;
  components: ProjectComponent[];
  summary: {
    total_components: number;
    exact_registry_components: number;
    resolved_registry_components: number;
    unverified_lockfile_components?: number;
    transitive_registry_components?: number;
    relationship_reported_components?: number;
    relationship_not_reported_components?: number;
    relationship_truncated_components?: number;
    optional_registry_components?: number;
    matched_lockfile_components?: number;
    unmatched_lockfile_components?: number;
    ambiguous_lockfile_components?: number;
    declared_range_components: number;
    not_correlatable_components: number;
    parsed_manifest_count: number;
    supported_manifest_count: number;
    skipped_manifest_count: number;
    result_truncated: boolean;
    parsed_lockfile_count: number;
    skipped_lockfile_count: number;
    skipped_lockfile_reasons: string[];
    lockfile_graph_truncated?: boolean;
    resolution: 'declared_only' | 'declared_and_lockfile';
  };
  coverage_matrix?: ProjectComponentCoverage[];
  dependency_graph?: ProjectDependencyGraphEvidence | null;
  cargo_dependency_graph?: CargoProjectDependencyGraphEvidence | null;
  composer_dependency_graph?: ComposerProjectDependencyGraphEvidence | null;
  gradle_dependency_graph?: GradleProjectDependencyGraphEvidence | null;
  nuget_dependency_graph?: NugetProjectDependencyGraphEvidence | null;
};

export type ComposerProjectDependencyGraphEvidence = {
  contract_version: '2026-09-10.3';
  ecosystem: 'composer';
  state: 'accepted' | 'truncated' | 'divergent';
  reason: 'none' | 'producer_truncated' | 'no_single_source_root' | 'custom_repository_declared' | 'identity_not_in_lockfile' | 'unresolved_manifest_root' | 'root_set_mismatch' | 'unreachable_node';
  artifact_sha256: string;
  source_commit_sha: string;
  source_binding_verified: true;
  nodes_reported: number;
  edges_reported: number;
  components_matched: number;
  components_unmatched: number;
  cycles_detected: boolean;
  truncation_reason: 'node_limit' | 'edge_limit' | 'producer_limit' | null;
};

export type GradleProjectDependencyGraphEvidence = {
  contract_version: '2026-09-10.4';
  ecosystem: 'maven';
  producer: 'gradle';
  state: 'accepted' | 'truncated' | 'divergent';
  reason: 'none' | 'producer_truncated' | 'no_single_source_root' | 'identity_not_in_lockfile' | 'unreachable_node';
  artifact_sha256: string;
  source_commit_sha: string;
  source_binding_verified: true;
  relationship_origin: 'ci_reported';
  scope_coverage: Array<'compile' | 'runtime' | 'test'>;
  nodes_reported: number;
  edges_reported: number;
  scope_assignments_reported: number;
  components_matched: number;
  components_unmatched: number;
  cycles_detected: boolean;
  truncation_reason: 'node_limit' | 'edge_limit' | 'producer_limit' | null;
};

export type NugetProjectDependencyGraphEvidence = {
  contract_version: '2026-09-10.5';
  ecosystem: 'nuget';
  producer: 'nuget';
  state: 'accepted' | 'truncated' | 'divergent';
  reason: 'none' | 'producer_truncated' | 'no_single_source_root' | 'target_count_mismatch' | 'identity_not_in_lockfile' | 'unreachable_node';
  artifact_sha256: string;
  source_commit_sha: string;
  source_binding_verified: true;
  relationship_origin: 'ci_reported';
  target_coverage: 'all_locked_targets';
  targets_reported: number;
  target_assignments_reported: number;
  nodes_reported: number;
  edges_reported: number;
  components_matched: number;
  components_unmatched: number;
  cycles_detected: boolean;
  truncation_reason: 'node_limit' | 'edge_limit' | 'target_limit' | 'producer_limit' | null;
};

export type PublicVulnerabilityReference = {
  type: 'source' | 'reference';
  url: string;
};

export type PublicVulnerabilityAffectedRange = {
  type: 'SEMVER' | 'ECOSYSTEM' | 'GIT' | 'UNKNOWN';
  introduced: string | null;
  fixed: string | null;
  last_affected: string | null;
  expression: string | null;
};

export type PublicVulnerabilitySeverity = {
  type: string;
  vector: string;
  base_score: number | null;
  band: 'none' | 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  score_status: 'derived_from_vector' | 'source_provided' | 'not_available';
  cvss_version?: '3.0' | '3.1' | '4.0' | null;
};

export type PublicVulnerabilityCorroboration = {
  provider: 'github_advisories';
  advisory_id: string;
  aliases: string[];
  affected_ranges: PublicVulnerabilityAffectedRange[];
  fixed_versions: string[];
  severity: PublicVulnerabilitySeverity[];
  references: PublicVulnerabilityReference[];
  published_at: string | null;
  updated_at: string | null;
  withdrawn_at: string | null;
  evidence_digest: string;
};

export type PublicVulnerabilitySourceConflict = {
  provider: 'github_advisories';
  advisory_id: string;
  type: 'fixed_version' | 'cvss_severity' | 'github_advisory_withdrawn';
  observed_at: string | null;
  evidence_digest: string;
};

export type PublicVulnerabilityKevSignal = {
  provider: 'cisa_kev';
  status: 'known_exploited' | 'not_listed' | 'unavailable' | 'not_evaluated';
  cve_id: string | null;
  catalog_version: string | null;
  date_released: string | null;
  date_added: string | null;
  due_date: string | null;
  required_action: string | null;
  known_ransomware_campaign_use: string | null;
  source_url: string;
  evidence_digest: string;
};

export type PublicVulnerabilityVendorBulletin = {
  publisher: string;
  advisory_id: string;
  url: string;
  policy_version: string;
};

export type PublicVulnerabilityNvdEvidence = {
  provider: 'nvd';
  contract_version: string;
  cve_id: string;
  status: 'analyzed' | 'modified' | 'rejected' | 'under_analysis' | 'deferred' | 'unknown';
  severity: PublicVulnerabilitySeverity[];
  cwes: string[];
  cpe_status: 'not_present' | 'present_unmapped' | 'identity_corroborated';
  cpe_match_count: number;
  cpe_corroborated_match_count?: number;
  cpe_mapping_ids?: string[];
  cpe_mapping_policy_version?: string;
  references: PublicVulnerabilityReference[];
  published_at: string | null;
  updated_at: string | null;
  evidence_digest: string;
};

export type PublicVulnerabilityFieldSource = {
  provider: 'osv' | 'github_advisories' | 'nvd' | 'cisa_kev' | 'vendor_bulletin';
  evidence_id: string;
  observed_at: string | null;
  status: 'primary' | 'supporting' | 'conflicting' | 'withdrawn' | 'unmapped' | 'derived' | 'not_available';
  evidence_digest: string;
};

export type PublicVulnerabilityFieldProvenance = {
  field: 'advisory_identity' | 'affected_ranges' | 'fixed_versions' | 'severity' | 'lifecycle_dates' | 'references' | 'weaknesses' | 'cpe_applicability' | 'known_exploitation' | 'vendor_guidance' | 'recommendation';
  state: 'primary_only' | 'corroborated' | 'conflicting' | 'secondary_withdrawn' | 'source_specific' | 'derived' | 'not_available' | 'not_applicable';
  sources: PublicVulnerabilityFieldSource[];
};

export type ProjectVulnerabilityFinding = {
  id: string;
  // Older retained snapshots predate the explicit stable-fingerprint field.
  // The backend labels them on validation; the client remains tolerant while
  // a self-hosted deployment still has legacy files on disk.
  fingerprint_version?: string;
  provider: 'osv';
  advisory_id: string;
  aliases: string[];
  ecosystem: 'npm' | 'pypi' | 'go' | 'cargo' | 'composer' | 'maven' | 'nuget';
  component_name: string;
  component_version: string;
  package_url: string;
  component_identity_provenance?: 'npm_registry_lockfile' | 'operator_attested_public_pypi' | 'operator_attested_public_go' | 'cargo_crates_io_lockfile' | 'operator_attested_public_composer' | 'operator_attested_public_maven' | 'operator_attested_public_nuget' | 'operator_attested_public_sbom' | 'not_applicable';
  dependency_scope: 'direct' | 'transitive' | 'optional';
  relationship_status?: 'reported' | 'not_reported' | 'truncated';
  affected_ranges: PublicVulnerabilityAffectedRange[];
  fixed_versions: string[];
  severity: PublicVulnerabilitySeverity[];
  corroborations: PublicVulnerabilityCorroboration[];
  nvd_evidence?: PublicVulnerabilityNvdEvidence[];
  source_consensus: 'osv_only' | 'corroborated' | 'conflicting' | 'secondary_withdrawn';
  source_conflicts: PublicVulnerabilitySourceConflict[];
  kev_signals: PublicVulnerabilityKevSignal[];
  vendor_bulletins?: PublicVulnerabilityVendorBulletin[];
  field_provenance?: PublicVulnerabilityFieldProvenance[];
  cvss_base_score: number | null;
  cvss_band: 'none' | 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  cvss_score_status: 'derived_from_vector' | 'source_provided' | 'not_available';
  references: PublicVulnerabilityReference[];
  published_at: string | null;
  updated_at: string | null;
  recommendation: string;
  evidence_digest: string;
};

export type ProjectVulnerabilityIntelligenceState =
  | 'not_requested'
  | 'analysis_pending'
  | 'analysis_failed'
  | 'analysis_cancelled'
  | 'no_completed_analysis'
  | 'no_component_inventory'
  | 'disabled'
  | 'no_correlatable_components'
  | 'ready'
  | 'degraded'
  | 'stale';

export type PublicVulnerabilitySourceFreshness = {
  provider: 'osv' | 'github_advisories' | 'nvd' | 'cisa_kev';
  state: 'fresh' | 'stale' | 'unavailable' | 'not_requested';
  reason: 'not_requested' | 'network_refreshed' | 'fresh_cache' | 'stale_cache_fallback' | 'provider_unavailable' | 'provider_circuit_open' | 'provider_catalog_stale' | 'invalid_source_data';
  as_of: string | null;
  expires_at: string | null;
  evidence_count?: number;
  evidence_sha256?: string | null;
  offline_snapshot_id?: string | null;
};

export type PublicVulnerabilityComponentCorrelation = {
  component_id: string;
  ecosystem: 'npm' | 'pypi' | 'go' | 'cargo' | 'composer' | 'maven' | 'nuget';
  component_name: string;
  component_version: string | null;
  dependency_scope: 'direct' | 'transitive' | 'optional';
  relationship_status?: 'reported' | 'not_reported' | 'truncated';
  identity_provenance?: 'npm_registry_lockfile' | 'operator_attested_public_pypi' | 'operator_attested_public_go' | 'cargo_crates_io_lockfile' | 'operator_attested_public_composer' | 'operator_attested_public_maven' | 'operator_attested_public_nuget' | 'not_applicable';
  provider: 'osv';
  state: 'affected' | 'not_affected' | 'not_correlatable' | 'unavailable';
  reason: 'affected_exact_version' | 'no_matching_advisory' | 'not_public_registry_component' | 'exact_version_unavailable' | 'identity_not_approved' | 'private_namespace' | 'public_pypi_identity_not_attested' | 'public_go_identity_not_attested' | 'public_composer_identity_not_attested' | 'public_maven_identity_not_attested' | 'public_nuget_identity_not_attested' | 'organization_identity_not_attested' | 'public_registry_provenance_unverified' | 'provider_unavailable' | 'invalid_source_data';
};

export type ProjectVulnerabilityIntelligenceSnapshot = {
  id: string;
  recorded_at: string;
  state: ProjectVulnerabilityIntelligenceState;
  queried_at: string | null;
  expires_at: string | null;
  sources: PublicVulnerabilitySourceFreshness[];
  finding_count: number;
  snapshot_sha256?: string | null;
  snapshot_integrity_status?: 'valid' | 'unknown';
};

export type ProjectVulnerabilityIntelligenceResponse = {
  project: ProjectRecord;
  analysis: JobListItem | null;
  state: ProjectVulnerabilityIntelligenceState;
  contract_version: string | null;
  provider: 'osv';
  egress_enabled: boolean;
  nvd_enabled?: boolean;
  offline_snapshot_id?: string | null;
  snapshot_id: string | null;
  snapshot_recorded_at: string | null;
  snapshot_sha256?: string | null;
  snapshot_integrity_status?: 'valid' | 'unknown';
  latest_snapshot_id: string | null;
  is_latest_snapshot: boolean;
  snapshot_history: ProjectVulnerabilityIntelligenceSnapshot[];
  queried_at: string | null;
  expires_at: string | null;
  sources: PublicVulnerabilitySourceFreshness[];
  component_correlations: PublicVulnerabilityComponentCorrelation[];
  findings: ProjectVulnerabilityFinding[];
  summary: {
    inventory_components: number;
    correlation_eligible_components: number;
    queryable_components: number;
    queried_components: number;
    osv_pages?: number;
    findings: number;
    fixed_version_available: number;
    excluded_components: number;
    unverified_advisories: number;
    withdrawn_advisories: number;
    failed_batches: number;
    fresh_cache_batches: number;
    stale_cache_batches: number;
    github_queries: number;
    github_corroborated: number;
    github_not_correlated: number;
    github_failed: number;
    github_withdrawn: number;
    github_conflicts: number;
    affected_components: number;
    not_affected_components: number;
    not_correlatable_components: number;
    unavailable_components: number;
    cisa_kev_feed_queries: number;
    cisa_kev_known_exploited: number;
    cisa_kev_not_listed: number;
    cisa_kev_not_evaluated: number;
    cisa_kev_unavailable: number;
    nvd_queries?: number;
    nvd_enriched?: number;
    nvd_not_found?: number;
    nvd_rejected?: number;
    nvd_unavailable?: number;
  };
  errors: string[];
};

export type ProjectFindingComparison = {
  status: 'new' | 'resolved' | 'persistent';
  finding: NormalizedFinding;
  previous_finding: NormalizedFinding | null;
  changed_fields: string[];
  lifecycle?: FindingLifecycleState | null;
};

export type ProjectPublicVulnerabilityFindingComparison = {
  status: 'new' | 'resolved' | 'persistent';
  finding: ProjectVulnerabilityFinding;
  previous_finding: ProjectVulnerabilityFinding | null;
  changed_fields: string[];
};

export type ProjectPublicVulnerabilityComparison = {
  state: 'ready' | 'not_available' | 'not_comparable';
  base_snapshot_id: string | null;
  target_snapshot_id: string | null;
  summary: {
    new: number;
    resolved: number;
    persistent: number;
  };
  comparisons: ProjectPublicVulnerabilityFindingComparison[];
  limitations: string[];
};

export type ProjectAnalysisCoverage = {
  coverage_status: 'complete' | 'partial' | 'unknown';
  total_entries_seen: number;
  supported_manifests_found: number;
  supported_manifests_parsed: number;
  supported_manifests_skipped: number;
  unsupported_manifests_detected: number;
  lockfiles_detected: number;
  lockfiles_parsed: number;
  lockfiles_skipped: number;
  total_dependencies: number;
  source_retained: boolean;
  limitations: string[];
};

export type ProjectAnalysisCoverageComparison = {
  status: 'equivalent' | 'changed' | 'unknown';
  base: ProjectAnalysisCoverage;
  target: ProjectAnalysisCoverage;
  changed_metrics: Array<
    | 'coverage_summary'
    | 'analysis_limit_reached'
    | 'total_entries_seen'
    | 'supported_manifests_found'
    | 'supported_manifests_parsed'
    | 'unsupported_manifests_detected'
    | 'lockfiles_detected'
    | 'lockfiles_parsed'
    | 'total_dependencies'
  >;
};

export type ProjectPortfolioPriority = 'urgent' | 'high' | 'review' | 'monitor';
export type ProjectPortfolioSourceType = 'archive' | 'git_or_ci' | 'sbom';
export type ProjectPortfolioOperationalState = 'no_analysis' | JobStatus;
export type ProjectPortfolioPublicState = 'fresh' | 'stale' | 'partial' | 'failed' | 'disabled' | 'not_requested';

export type ProjectPortfolioSearch = {
  pageSize?: number;
  cursor?: string | null;
  search?: string;
  searchMode?: 'prefix' | 'exact';
  priority?: ProjectPortfolioPriority;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  sourceType?: ProjectPortfolioSourceType;
  operationalState?: ProjectPortfolioOperationalState;
  coverage?: 'complete' | 'partial' | 'unknown' | 'lost';
  publicIntelligence?: ProjectPortfolioPublicState;
  baseline?: 'available' | 'missing';
  responsibility?: 'assigned' | 'multiple' | 'unassigned';
  sort?: 'priority' | 'name' | 'updated';
};

export type ProjectPortfolioItem = {
  project: ProjectRecord;
  latest_job: JobListItem | null;
  latest_completed_analysis: JobListItem | null;
  priority: ProjectPortfolioPriority;
  priority_reasons: Array<
    | 'known_exploited'
    | 'critical_findings'
    | 'latest_analysis_failed'
    | 'coverage_lost'
    | 'high_findings'
    | 'new_findings'
    | 'analysis_incomplete'
    | 'public_intelligence_stale'
    | 'public_intelligence_failed'
    | 'exception_review_due'
    | 'pending_triage'
    | 'no_baseline'
    | 'no_recent_analysis'
    | 'no_completed_analysis'
  >;
  finding_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
    kev: number;
    local: number;
    public: number;
  };
  changes: {
    state: 'ready' | 'baseline_is_latest' | 'missing_baseline' | 'not_comparable';
    new: number;
    persistent: number;
    resolved: number;
    public_new: number;
    public_persistent: number;
    public_resolved: number;
  };
  coverage: {
    state: 'complete' | 'partial' | 'unknown' | 'lost';
    current: ProjectAnalysisCoverage | null;
    comparison: ProjectAnalysisCoverageComparison | null;
  };
  public_intelligence_state: ProjectPortfolioPublicState;
  public_sources: PublicVulnerabilitySourceFreshness[];
  source_type: ProjectPortfolioSourceType;
  source_type_detail:
    | 'uploaded_archive'
    | 'normalized_sbom'
    | 'attested_git_cli'
    | 'attested_ci'
    | 'commit_attributed_channel_ambiguous';
  operational_state: ProjectPortfolioOperationalState;
  pending_actions: number;
  exceptions_due: number;
  exceptions_overdue: number;
  responsibility: {
    state: 'assigned' | 'multiple' | 'unassigned';
    active_assignees: string[];
    active_assignee_count: number;
    inactive_assignment_count: number;
    truncated: boolean;
  };
  project_responsibility: {
    state: 'assigned' | 'unassigned' | 'unassigned_attention';
    responsible_username: string | null;
    revision: number;
  };
  last_comparable_analysis_at: string | null;
  limitations: string[];
};

export type ProjectPortfolioPage = {
  contract_version: '2026-09-10.2';
  snapshot_at: string;
  items: ProjectPortfolioItem[];
  returned_count: number;
  total_count: number;
  has_more: boolean;
  next_cursor: string | null;
  summary: {
    total_projects: number;
    filtered_projects: number;
    urgent_projects: number;
    high_priority_projects: number;
    projects_with_kev: number;
    projects_without_baseline: number;
    projects_with_partial_data: number;
    stale_or_failed_intelligence: number;
    pending_actions: number;
  };
  priority_model: 'closed_signals_no_opaque_score';
  portfolio_complete: boolean;
  limitations: string[];
};

export type ProjectActionReason = ProjectPortfolioItem['priority_reasons'][number];
export type ProjectActionDestination = 'analysis' | 'findings' | 'comparison' | 'public_intelligence';

export type ProjectActionItem = {
  id: string;
  project_id: string;
  project_name: string;
  analysis_id: string | null;
  reason: ProjectActionReason;
  priority: ProjectPortfolioPriority;
  destination: ProjectActionDestination;
  occurred_at: string;
  read: boolean;
};

export type ProjectActionPage = {
  contract_version: '2026-09-10.1';
  items: ProjectActionItem[];
  total: number;
  unread: number;
  source_complete: boolean;
  retained_limit: 2000;
  state_revision: number;
  privacy: 'closed_reasons_opaque_ids_no_evidence_or_free_text';
};

export type RemediationPriority = 'urgent' | 'high' | 'review';
export type RemediationWorkflowState = FindingDecisionStatus | 'awaiting_reanalysis' | 'still_detected';

export type RemediationOccurrence = {
  project: ProjectRecord;
  analysis: JobListItem;
  finding_id: string;
  rule_id: string;
  evidence_kind: 'public_vulnerability' | 'local_finding';
  observed_version: string | null;
  dependency_scope: 'direct' | 'transitive' | 'optional' | 'unknown';
  relationship_status: 'reported' | 'not_reported' | 'truncated' | 'not_applicable';
  workflow_state: RemediationWorkflowState;
  workflow_mutable: boolean;
  assignee_username: string | null;
  review_at: string | null;
  is_new: boolean | null;
  coverage_state: 'complete' | 'partial' | 'unknown' | 'lost';
};

export type RemediationActionGroup = {
  id: string;
  revision: string;
  evidence_kind: 'public_vulnerability' | 'local_finding';
  title: string;
  ecosystem: 'npm' | 'pypi' | 'go' | 'cargo' | 'composer' | 'maven' | 'nuget' | null;
  component_name: string | null;
  advisory_ids: string[];
  observed_versions: string[];
  affected_ranges: PublicVulnerabilityAffectedRange[];
  fixed_versions: string[];
  recommended_fixed_version: string | null;
  recommendation: string;
  priority: RemediationPriority;
  priority_reasons: Array<'known_exploited' | 'critical' | 'high' | 'source_conflict' | 'new_finding' | 'direct_dependency' | 'coverage_incomplete' | 'exception_review_due' | 'awaiting_reanalysis'>;
  highest_severity: 'none' | 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  known_exploited: boolean;
  source_conflict: boolean;
  exposure_state: 'not_assessed';
  dependency_scopes: Array<'direct' | 'transitive' | 'optional' | 'unknown'>;
  affected_project_count: number;
  occurrence_count: number;
  occurrences: RemediationOccurrence[];
  occurrences_truncated: boolean;
  workflow_counts: Record<RemediationWorkflowState, number>;
  limitations: string[];
};

export type RemediationSearch = {
  pageSize?: number;
  cursor?: string | null;
  search?: string;
  searchMode?: 'prefix' | 'exact';
  priority?: RemediationPriority;
  evidenceKind?: 'public_vulnerability' | 'local_finding';
  ecosystem?: 'npm' | 'pypi' | 'go' | 'cargo' | 'composer' | 'maven' | 'nuget';
  dependencyScope?: 'direct' | 'transitive' | 'optional' | 'unknown';
  workflowState?: RemediationWorkflowState;
  sort?: 'priority' | 'component' | 'projects';
};

export type RemediationSavedViewFilters = {
  priority?: RemediationPriority | null;
  evidence_kind?: 'public_vulnerability' | 'local_finding' | null;
  ecosystem?: 'npm' | 'pypi' | 'go' | 'cargo' | 'composer' | 'maven' | 'nuget' | null;
  dependency_scope?: 'direct' | 'transitive' | 'optional' | 'unknown' | null;
  workflow_state?: RemediationWorkflowState | null;
  sort: 'priority' | 'component' | 'projects';
};

export type RemediationSavedView = {
  contract_version: '2026-09-09.1';
  id: string;
  organization_id: string;
  owner_user_id: string;
  name: string;
  filters: RemediationSavedViewFilters;
  visibility: 'private' | 'organization';
  created_at: string;
  updated_at: string;
};

export type RemediationSavedViewPage = {
  contract_version: '2026-09-09.1';
  items: RemediationSavedView[];
  default_view_id: string | null;
  owned_count: number;
  organization_count: number;
  privacy: 'closed_filters_only_no_search_cursor_or_resource_ids';
};

export type RemediationPage = {
  contract_version: '2026-09-09.1';
  snapshot_at: string;
  items: RemediationActionGroup[];
  returned_count: number;
  total_count: number;
  has_more: boolean;
  next_cursor: string | null;
  summary: {
    total_groups: number;
    filtered_groups: number;
    urgent_groups: number;
    high_groups: number;
    projects_affected: number;
    known_exploited_groups: number;
    conflicting_groups: number;
    awaiting_reanalysis: number;
  };
  resolution_policy: 'comparable_reanalysis_required';
  portfolio_complete: boolean;
  limitations: string[];
};

export type RemediationBulkActionRequest = {
  group_id: string;
  idempotency_key: string;
  expected_revision: string;
  selections: Array<{ project_id: string; analysis_id: string; finding_id: string }>;
  status: FindingDecisionStatus;
  reason: string;
  comment?: string | null;
  assignee_user_id?: string | null;
  review_at?: string | null;
  confirmation: true;
};

export type RemediationBulkActionResponse = {
  contract_version: '2026-09-09.2';
  group_id: string;
  applied_count: number;
  decisions: FindingDecisionRecord[];
  replayed: boolean;
  history_mode: 'append_only_recoverable_batch';
};

export type RemediationPlanJobStatus = 'queued' | 'running' | 'cancelling' | 'cancelled' | 'completed' | 'failed' | 'expired';

export type RemediationPlanJob = {
  contract_version: '2026-09-09.1';
  id: string;
  organization_id: string;
  status: RemediationPlanJobStatus;
  filters: {
    page_size: number;
    cursor: null;
    search: string | null;
    search_mode: 'prefix' | 'exact';
    priority: RemediationPriority | null;
    evidence_kind: 'public_vulnerability' | 'local_finding' | null;
    ecosystem: 'npm' | 'pypi' | 'go' | 'cargo' | 'composer' | 'maven' | 'nuget' | null;
    dependency_scope: 'direct' | 'transitive' | 'optional' | 'unknown' | null;
    workflow_state: RemediationWorkflowState | null;
    sort: 'priority' | 'component' | 'projects';
  };
  created_at: string;
  updated_at: string;
  cutoff_at: string;
  expires_at: string | null;
  processed_projects: number;
  total_projects: number;
  included_groups: number;
  included_occurrences: number;
  groups_truncated: boolean;
  occurrences_truncated: boolean;
  snapshot_sha256: string | null;
  artifact_bytes: number;
  failure_reason: 'portfolio_changed' | 'source_unavailable' | 'safe_limit_reached' | 'artifact_too_large' | 'internal_error' | null;
  retry_of_job_id: string | null;
  recovery_count: number;
  replayed: boolean;
  privacy: 'owner_scoped_project_names_no_paths_content_comments_or_actors';
};

export type RemediationPlanJobPage = {
  contract_version: '2026-09-09.1';
  items: RemediationPlanJob[];
  max_retained_jobs: 100;
  artifact_ttl_days: 7;
};

export type RiskTrendProfile = 'developer' | 'security' | 'executive';

export type RiskTrendChangeCounts = {
  local_new: number;
  local_persistent: number;
  local_resolved: number;
  public_new: number;
  public_persistent: number;
  public_resolved: number;
  critical_or_high_new: number;
};

export type RiskTrendBucket = {
  starts_at: string;
  ends_at: string;
  completed_analyses: number;
  projects_analyzed: number;
  comparable_local_transitions: number;
  comparable_public_transitions: number;
  excluded_transitions: number;
  coverage_gained: number;
  coverage_lost: number;
  changes: RiskTrendChangeCounts;
};

export type RiskTrendDimension = {
  key: string;
  current_findings: number;
  completed_analyses: number;
  comparable_transitions: number;
  new_findings: number;
  resolved_findings: number;
};

export type RiskTrendResponse = {
  contract_version: '2026-09-10.1';
  generated_at: string;
  period_starts_at: string;
  period_ends_at: string;
  bucket_days: 7 | 30;
  summary: {
    projects_in_scope: number;
    projects_analyzed_in_period: number;
    projects_without_recent_analysis: number;
    retained_completed_analyses: number;
    completed_analyses_in_period: number;
    comparable_local_transitions: number;
    comparable_public_transitions: number;
    excluded_transitions: number;
    pending_actions: number;
    overdue_exceptions: number;
    current_known_exploited_findings: number;
    current_critical_or_high_findings: number;
  };
  changes: RiskTrendChangeCounts;
  buckets: RiskTrendBucket[];
  ecosystems: RiskTrendDimension[];
  source_types: RiskTrendDimension[];
  time_to_first_review: { cohort: 'first_retained_observation_in_period'; sample_count: number; median_hours: number | null; p90_hours: number | null };
  time_to_verified_resolution: { cohort: 'first_retained_observation_in_period'; sample_count: number; median_hours: number | null; p90_hours: number | null };
  priority_projects: Array<{ project: ProjectRecord; priority: ProjectPortfolioPriority; reasons: string[]; pending_actions: number }>;
  exclusions: Array<{ reason: string; count: number }>;
  denominators: Record<string, number>;
  limitations: string[];
};

export type RiskTrendMaterialization = {
  state: 'ready' | 'rebuilding' | 'stale' | 'failed';
  data_state: 'current' | 'stale' | 'unavailable';
  refresh_in_progress: boolean;
  retryable: boolean;
  requested_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  failure_code: 'limit' | 'source_changed' | 'rebuild_failed' | null;
  retry_after_seconds: 1 | null;
};

export type RiskTrendViewResponse = {
  contract_version: '2026-09-10.2';
  materialization: RiskTrendMaterialization;
  trend: RiskTrendResponse | null;
};

export type ProjectComparisonState = 'ready' | 'analysis_pending' | 'not_comparable' | 'no_normalized_findings';

export type ProjectAnalysisComparisonResponse = {
  project: ProjectRecord;
  base_analysis: JobListItem;
  target_analysis: JobListItem;
  state: ProjectComparisonState;
  summary: {
    new: number;
    resolved: number;
    persistent: number;
  };
  comparisons: ProjectFindingComparison[];
  limitations: string[];
  uses_saved_baseline?: boolean;
  coverage_comparison?: ProjectAnalysisCoverageComparison | null;
  public_vulnerability_comparison?: ProjectPublicVulnerabilityComparison | null;
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

export type ActiveCapability =
  | 'active_nmap_basic'
  | 'active_dns_inventory'
  | 'active_dns_osint'
  | 'active_http_basic_header_review'
  | 'active_tls_basic';

export type ActiveAssetStatus = 'active' | 'expired' | 'revoked';

export type ActiveAssetEvent = {
  id: string;
  kind: 'registered' | 'renewed' | 'revoked' | 'responsibles_updated' | 'verification_started' | 'verified' | 'verification_failed' | 'execution_requested' | 'baseline_selected' | 'triage_updated';
  occurred_at: string;
  actor_id: string;
  reason_code: string | null;
};

export type ActiveAuthorizationRevision = {
  contract_version: string;
  id: string;
  sequence: number;
  source: 'registration' | 'renewal';
  scope_expanded: boolean;
  created_at: string;
  authorized_at: string;
  expires_at: string;
  authorization_method: ActiveAsset['authorization_method'];
  capabilities: ActiveCapability[];
  allowed_ports: number[];
  allowed_protocols: ActiveAsset['allowed_protocols'];
  digest_sha256: string;
};

export type ActiveAsset = {
  contract_version: '2026-09-09.1';
  id: string;
  organization_id: string;
  owner_id: string;
  responsible_user_ids: string[];
  asset_type: 'domain' | 'host' | 'ip' | 'http_origin';
  canonical_value: string;
  capabilities: ActiveCapability[];
  allowed_ports: number[];
  allowed_protocols: Array<'tcp' | 'dns' | 'http' | 'https' | 'tls'>;
  authorization_method: 'manual_attestation' | 'dns_txt' | 'http_well_known' | 'managed_private';
  authorization_reference: string;
  authorized_at: string;
  expires_at: string;
  revoked_at: string | null;
  status: ActiveAssetStatus;
  notes: Array<{ kind: 'business_context' | 'scope_constraint' | 'operational_contact'; value: string }>;
  created_at: string;
  updated_at: string;
  baseline_execution_id?: string | null;
  triage?: Array<{
    observation_key: string;
    status: 'needs_review' | 'acknowledged' | 'expected_change' | 'dismissed';
    comment_code: 'planned_change' | 'expected_service' | 'investigating' | 'needs_owner_review' | 'not_applicable';
    actor_id: string;
    updated_at: string;
  }>;
  history: ActiveAssetEvent[];
  /** Missing/empty means a legacy record that must be re-attested before execution. */
  authorization_revisions?: ActiveAuthorizationRevision[];
};

export type ActiveAssetPage = {
  contract_version: '2026-09-08.1';
  items: ActiveAsset[];
  returned_count: number;
  page_size: number;
  has_more: boolean;
  next_cursor: string | null;
};

export type ActiveAssetCreateRequest = {
  asset_type: ActiveAsset['asset_type'];
  value: string;
  responsible_user_ids: string[];
  capabilities: ActiveCapability[];
  allowed_ports: number[];
  allowed_protocols: ActiveAsset['allowed_protocols'];
  authorization_method: ActiveAsset['authorization_method'];
  authorization_reference: string;
  authorized_at: string;
  expires_at: string;
  notes: ActiveAsset['notes'];
};

export type ActiveAssetRenewRequest = {
  idempotency_key: string;
  expected_revision_id: string | null;
  responsible_user_ids: string[];
  capabilities: ActiveCapability[];
  allowed_ports: number[];
  allowed_protocols: ActiveAsset['allowed_protocols'];
  authorization_method: ActiveAsset['authorization_method'];
  authorization_reference: string;
  authorized_at: string;
  expires_at: string;
  renewal_confirmed: true;
  scope_expansion_confirmed: boolean;
};

export type ActiveAssetRenewalResponse = {
  asset: ActiveAsset;
  replayed: boolean;
  scope_expanded: boolean;
};

export type ActiveChangeApproval = {
  contract_version: '2026-09-10.1';
  id: string;
  asset_id: string | null;
  kind: 'registration' | 'renewal' | 'revocation';
  status: 'pending' | 'approved' | 'executing' | 'consumed' | 'rejected' | 'expired' | 'interrupted';
  operation_digest_prefix: string;
  requested_at: string;
  expires_at: string;
  decided_at: string | null;
  consumed_at: string | null;
  requested_by_current_user: boolean;
  can_approve: boolean;
  can_apply: boolean;
  summary: {
    asset_type: ActiveAsset['asset_type'];
    review_target: string | null;
    scope_change: 'new_registration' | 'same_scope' | 'expanded_scope' | 'reduced_scope' | 'revocation';
    capabilities: ActiveCapability[];
    allowed_ports: number[];
    allowed_protocols: ActiveAsset['allowed_protocols'];
    authorization_expires_at: string | null;
    reason_code: 'authorization_withdrawn' | 'asset_retired' | 'scope_changed' | 'security_hold' | null;
  };
};

export type ActiveChangeApprovalPage = {
  contract_version: '2026-09-10.1';
  enabled: boolean;
  items: ActiveChangeApproval[];
  pending_count: number;
  privacy: 'no_notes_references_responsible_identities_or_complete_payload';
};

export type ActiveAssetResponsiblesUpdateRequest = {
  responsible_user_ids: string[];
  expected_updated_at: string;
  assignment_confirmed: true;
};

export type ActiveMemberResponsibilityImpact = {
  affected_asset_count: number;
  will_become_unassigned_count: number;
  will_keep_other_responsibles_count: number;
  affected_project_count: number;
  projects_requiring_reassignment_count: number;
};

export type ActiveAssetVerificationMethod = 'manual_attestation' | 'dns_txt' | 'http_well_known' | 'managed_private';
export type ActiveAssetVerificationStatus = 'pending' | 'verified' | 'failed' | 'expired' | 'revoked';

export type ActiveAssetVerificationConfiguration = {
  contract_version: string;
  enabled: boolean;
  methods: Record<ActiveAssetVerificationMethod, boolean>;
  remote_runner_ready?: boolean;
  challenge_ttl_seconds: number;
  max_attempts_per_hour: number;
  legal_authorization_established: false;
  target_expansion_allowed: false;
};

export type ActiveAssetVerification = {
  contract_version: string;
  id: string;
  asset_id: string;
  method: ActiveAssetVerificationMethod;
  status: ActiveAssetVerificationStatus;
  created_at: string;
  challenge_expires_at: string;
  attempts: number;
  last_attempt_at: string | null;
  verified_at: string | null;
  verification_expires_at: string | null;
  revoked_at: string | null;
  reason_code: string | null;
};

export type ActiveAssetVerificationChallenge = {
  verification: ActiveAssetVerification;
  challenge_token: string;
  placement: string;
  one_time_display: true;
  legal_authorization_established: false;
};

export type ActiveRecurrence = {
  contract_version: '2026-09-08.2';
  id: string;
  asset_id: string;
  capability: ActiveCapability;
  port: number | null;
  interval_days: 7 | 14 | 30;
  timezone_name: string;
  window_weekdays: Array<'monday' | 'tuesday' | 'wednesday' | 'thursday' | 'friday' | 'saturday' | 'sunday'>;
  window_start_hour: number;
  window_duration_hours: number;
  authorization_revision_id: string;
  authorization_revision_sequence: number;
  authorization_expires_at: string | null;
  verification_id: string;
  status: 'active' | 'paused' | 'suspended';
  reason_code: string;
  next_run_at: string;
  last_scheduled_at: string | null;
  last_job_id: string | null;
  failure_count: number;
  next_retry_at: string | null;
  last_attempt_at: string | null;
  last_outcome: 'never' | 'scheduled' | 'runner_unavailable' | 'capacity_saturated' | 'dispatch_conflict';
  created_at: string;
  updated_at: string;
};

export type ActiveRecurrenceList = {
  contract_version: '2026-09-08.2';
  enabled: boolean;
  items: ActiveRecurrence[];
};

export type ActiveAssetDeletionScopeItem = {
  key: 'asset_metadata' | 'batch_replay_receipts' | 'recurrence_policies' | 'change_approvals' | 'authorization_revisions' | 'verification_challenges' | 'execution_jobs' | 'execution_results' | 'report_exports' | 'product_audit';
  disposition: 'delete' | 'anonymize' | 'not_persisted';
  item_count: number | null;
  detail: string;
};

export type ActiveAssetDeletionPreview = {
  contract_version: '2026-09-10.4';
  asset_id: string;
  state: 'ready' | 'blocked_active_work';
  items: ActiveAssetDeletionScopeItem[];
};

export type ActiveAssetDeletionResponse = {
  contract_version: '2026-09-10.4';
  asset_id: string;
  deletion_receipt_id: string;
  state: 'completed' | 'already_absent';
  completed_at: string;
  items: ActiveAssetDeletionScopeItem[];
};

export type ActiveOperationsSummary = {
  contract_version: string;
  generated_at: string;
  assets: { total: number; active: number; expired: number; revoked: number; expiring_14_days: number; duplicate_identity_groups: number; duplicate_identity_records: number };
  verifications: { not_started: number; pending: number; verified: number; failed: number; expired: number; revoked: number };
  jobs: { total: number; queued: number; running: number; cancelling: number; cancelled: number; completed: number; failed: number; degraded: number };
  changes: { assets_compared: number; assets_with_changes: number; observations_changed: number; inconclusive: number };
  actions: { total: number; authorization_expiring: number; authorization_expired: number; failed_jobs: number; degraded_jobs: number; verification_attention: number; observation_changes: number };
  action_queue: {
    items: ActiveOperationsAction[];
    returned: number;
    total: number;
    items_truncated: boolean;
    source_incomplete: boolean;
  };
  capabilities: Array<{
    capability: ActiveCapability;
    enabled: boolean;
    backend_enabled: boolean;
    runner_enabled: boolean | null;
    readiness: 'disabled' | 'ready' | 'degraded' | 'unavailable';
    reason_code: 'ready' | 'backend_disabled' | 'backend_disabled_runner_enabled' | 'runner_unconfigured' | 'runner_unavailable' | 'runner_health_invalid' | 'runner_gate_disabled' | 'runner_contract_mismatch';
    asset_count: number;
    execution_count: number;
  }>;
  configuration: { verification_enabled: boolean; recurrence_enabled?: boolean; four_eyes_enabled?: boolean; legacy_free_targets_enabled: boolean; all_live_capabilities_disabled: boolean };
  capacity: { admission: 'ready' | 'saturated'; retry_after_seconds: number };
  limits: { assets_considered: number; assets_total: number; jobs_considered: number; jobs_total: number; incomplete: boolean; selection_strategy: 'priority_then_recency'; priority_candidates: number };
  interpretation: string;
};

export type ActiveOperationsAction = {
  id: string;
  kind: 'authorization_expired' | 'authorization_expiring' | 'verification_failed' | 'verification_expired' | 'execution_failed' | 'execution_degraded' | 'observations_changed';
  urgency: 'immediate' | 'high' | 'scheduled' | 'review';
  action_code: 'renew_authorization' | 'reverify_control' | 'retry_execution' | 'review_execution' | 'triage_changes';
  asset_id: string;
  job_id: string | null;
  reference_at: string;
  due_at: string | null;
  occurrence_count: number;
};

export type ActiveWeeklyReportPeriod = '7d' | '30d';
export type ActiveWeeklyReportFormat = 'markdown' | 'json';

export type ActiveWeeklyReportPreflight = {
  contract_version: '2026-09-09.1';
  state: 'ready' | 'partial' | 'no_assets';
  period: ActiveWeeklyReportPeriod;
  starts_at: string;
  state_at: string;
  snapshot_digest: string;
  assets_total: number;
  assets_included: number;
  jobs_total: number;
  jobs_included: number;
  actions_total: number;
  actions_included: number;
  recurrence_attention_total: number;
  recurrence_attention_included: number;
  incomplete: boolean;
  available_formats: ['markdown', 'json'];
  max_bytes: 1048576;
  privacy: {
    exact_targets_included: true;
    notes_included: false;
    authorization_references_included: false;
    authorization_digests_included: false;
    responsible_accounts_included: false;
    actor_identifiers_included: false;
    challenge_material_included: false;
    raw_results_included: false;
    runner_responses_included: false;
  };
};

export type ActiveWeeklyReviewOutcome = 'reviewed' | 'follow_up_required';

export type ActiveWeeklyReviewReceipt = {
  contract_version: '2026-09-10.1';
  id: string;
  report_contract_version: '2026-09-09.1';
  period: ActiveWeeklyReportPeriod;
  starts_at: string;
  state_at: string;
  outcome: ActiveWeeklyReviewOutcome;
  coverage_state: 'ready' | 'partial' | 'no_assets';
  coverage_incomplete: boolean;
  snapshot_hmac_sha256: string;
  reviewed_at: string;
  privacy: 'target_free_no_raw_digest_report_actor_notes_or_results';
};

export type ActiveWeeklyReviewReceiptPage = {
  contract_version: '2026-09-10.1';
  revision: number;
  items: ActiveWeeklyReviewReceipt[];
  max_retained: 52;
  retention_days: 400;
};

export type ActiveWeeklyReviewReceiptMutation = {
  contract_version: '2026-09-10.1';
  revision: number;
  receipt: ActiveWeeklyReviewReceipt;
  replayed: boolean;
};

export type ActiveWeeklyReviewReceiptVerification = {
  contract_version: '2026-09-10.1';
  receipt_id: string;
  valid: boolean;
  verification: 'local_hmac_no_external_provider';
};

export type ActiveAssetPostureResponse = {
  asset: ActiveAsset;
  executions: JobListItem[];
  baseline_execution: JobListItem | null;
  history: {
    returned_count: number;
    total_count: number;
    has_more: boolean;
    next_cursor: string | null;
    posture_records_considered: number;
    posture_incomplete: boolean;
  };
  posture: {
    contract_version: string;
    execution_count: number;
    counts: { completed: number; failed: number; cancelled: number };
    capabilities: Array<{ capability: string; execution_count: number; latest_execution_id: string; latest_status: JobStatus; latest_at: string; latest_authorization_revision_id?: string | null; latest_authorization_revision_sequence?: number | null }>;
    baseline_execution_id: string | null;
    comparison: null | {
      state: 'ready' | 'inconclusive';
      capability: string;
      base_execution_id: string;
      target_execution_id: string;
      summary: { new: number; changed: number; disappeared: number; persistent: number };
      changes: Array<{ kind: 'new' | 'changed' | 'disappeared'; signal: string; before: string | number | boolean | null; after: string | number | boolean | null; interpretation: string }>;
      changes_truncated: boolean;
      coverage: Record<string, unknown>;
      authorization?: {
        base: { id: string | null; sequence: number | null; label: string };
        target: { id: string | null; sequence: number | null; label: string };
        same_revision: boolean | null;
      };
    };
    limitations: string[];
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
