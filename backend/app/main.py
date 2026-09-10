from contextlib import asynccontextmanager
import asyncio
from contextlib import suppress
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import secrets
import time
from typing import Any, Callable, Literal
from uuid import uuid4

from fastapi import BackgroundTasks, Body, FastAPI, File, Form, HTTPException, Query, Request, Response, UploadFile, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.version import PRODUCT_VERSION

from app.active_http_basic_header_review import (
    ActiveHttpBasicHeaderReviewContractError,
    active_http_basic_header_review_is_persistable,
    active_http_basic_header_review_job_status,
    build_active_http_basic_header_review_persisted_result,
    build_active_http_basic_header_review_response,
)
from app.active_assets import (
    ACTIVE_ASSET_CONTRACT_VERSION,
    ACTIVE_CAPABILITIES,
    ActiveAssetCreateRequest,
    ActiveAssetBaselineRequest,
    ActiveAssetExecutionCancelRequest,
    ActiveAssetExecutionRequest,
    ActiveAssetExecutionRetryRequest,
    ActiveAssetPage,
    ActiveAssetPageRequest,
    ActiveAssetRecord,
    ActiveAssetRenewRequest,
    ActiveAssetRenewalResponse,
    ActiveAssetResponsiblesUpdateRequest,
    ActiveMemberResponsibilityImpact,
    ActiveAssetRevokeRequest,
    ActiveAssetStatus,
    ActiveAssetStore,
    ActiveAssetStoreError,
    ActiveAssetTriageRequest,
    ActiveCapability,
    asset_target_for_capability,
    current_active_authorization_revision,
)
from app.active_asset_verification import (
    ACTIVE_ASSET_VERIFICATION_CHALLENGE_TTL_SECONDS,
    ACTIVE_ASSET_VERIFICATION_CONTRACT_VERSION,
    ACTIVE_ASSET_VERIFICATION_MAX_ATTEMPTS_PER_HOUR,
    ActiveAssetVerificationChallengeResponse,
    ActiveAssetVerificationCheckRequest,
    ActiveAssetVerificationError,
    ActiveAssetVerificationObservation,
    ActiveAssetVerificationRevokeRequest,
    ActiveAssetVerificationStartRequest,
    ActiveAssetVerificationStore,
    ActiveAssetVerificationView,
    ManagedActiveAssetVerificationTransport,
    verification_placement,
    verify_observation,
)
from app.active_asset_deletion import (
    ACTIVE_ASSET_DELETION_CONTRACT_VERSION,
    ActiveAssetDeletionError,
    ActiveAssetDeletionPreview,
    ActiveAssetDeletionRequest,
    ActiveAssetDeletionResponse,
    ActiveAssetDeletionService,
)
from app.active_asset_batch import (
    ACTIVE_ASSET_BATCH_MAX_BYTES,
    ActiveAssetBatchCommitResponse,
    ActiveAssetBatchError,
    ActiveAssetBatchPreflightStore,
    ActiveAssetBatchPreflightResponse,
    build_active_asset_batch_preflight,
    mark_existing_active_asset_conflicts,
    parse_active_asset_batch,
)
from app.active_change_approvals import (
    ActiveChangeApprovalError,
    ActiveChangeApprovalPage,
    ActiveChangeApprovalRecord,
    ActiveChangeApprovalStore,
    ActiveChangeApprovalView,
    ActiveChangeSummary,
    active_change_operation_digest,
)
from app.active_recurrence import (
    ActiveRecurrenceCreateRequest,
    ActiveRecurrenceDeleteRequest,
    ActiveRecurrenceError,
    ActiveRecurrenceListResponse,
    ActiveRecurrenceMutationRequest,
    ActiveRecurrenceRecord,
    ActiveRecurrenceStore,
    ActiveRecurrenceView,
    recurrence_occurrence_key,
)
from app.active_evidence_bundle import (
    ActiveEvidenceBundleError,
    build_active_asset_markdown_report,
    build_active_evidence_bundle,
)
from app.active_audit_export import (
    ActiveAuditExportError,
    ActiveAuditExportPreflight,
    render_active_audit_export,
    select_active_audit_export,
)
from app.product_audit_export import (
    ProductAuditExportError,
    ProductAuditExportPreflight,
    ProductAuditExportRequest,
    render_product_audit_export,
    select_product_audit_export,
    validate_product_audit_export_request,
)
from app.active_tools_client import check_active_tools_health
from app.active_capability_runner import ActiveCapabilityRunnerError, ActiveToolsCapabilityRunner
from app.active_verification_runner import (
    ActiveToolsVerificationRunner,
    ActiveVerificationRunnerError,
    verification_runner_target,
)
from app.active_posture import build_active_posture
from app.active_operations import build_active_capability_readiness, build_active_operations_summary
from app.active_weekly_report import (
    ActiveWeeklyReportError,
    ActiveWeeklyReportExportRequest,
    ActiveWeeklyReportPeriod,
    ActiveWeeklyReportPreflight,
    build_active_weekly_report_snapshot,
    render_active_weekly_report,
)
from app.active_weekly_review_receipts import (
    ActiveWeeklyReviewReceiptCreateRequest,
    ActiveWeeklyReviewReceiptError,
    ActiveWeeklyReviewReceiptMutation,
    ActiveWeeklyReviewReceiptPage,
    ActiveWeeklyReviewReceiptStore,
    ActiveWeeklyReviewReceiptVerification,
    ActiveWeeklyReviewReceiptVerifyRequest,
)
from app.active_nmap_lifecycle import (
    ActiveNmapBasicRouteActiveToolsClient,
    ActiveNmapBasicRouteNoLiveClient,
    active_nmap_basic_no_live_job_error,
    active_nmap_basic_no_live_job_status,
    active_nmap_basic_real_job_error,
    active_nmap_basic_real_job_status,
    build_active_nmap_basic_no_live_job_result,
    build_active_nmap_basic_real_job_result,
    is_active_nmap_basic_real_lifecycle_result,
    normalize_active_nmap_basic_lifecycle_route_result,
    run_active_nmap_basic_lifecycle_skeleton,
)
from app.active_nmap_policy import (
    ACTIVE_NMAP_BASIC_MAX_TARGETS,
    ActiveNmapTargetPolicyError,
    ActiveNmapTargetPolicyResult,
    validate_active_nmap_basic_targets,
)
from app.active_nmap_handoff import build_active_nmap_basic_handoff_plan
from app.active_dns_inventory import (
    ACTIVE_DNS_INVENTORY_ALLOWED_RECORD_TYPES,
    ActiveDnsInventoryContract,
    ActiveDnsInventoryPolicyError,
    active_dns_inventory_job_error,
    active_dns_inventory_job_status,
    normalize_active_dns_inventory_domain,
    normalize_active_dns_inventory_record_types,
    run_active_dns_inventory,
)
from app.active_dns_osint import (
    ACTIVE_DNS_OSINT_DEFAULT_MAX_NAMES,
    ACTIVE_DNS_OSINT_MAX_NAMES,
    ACTIVE_DNS_OSINT_MIN_NAMES,
    ACTIVE_DNS_OSINT_MODE,
    ACTIVE_DNS_OSINT_PROFILE,
    ActiveDnsOsintContract,
    ActiveDnsOsintPolicyError,
    active_dns_osint_job_error,
    active_dns_osint_job_status,
    build_active_dns_osint_ct_source,
    normalize_active_dns_osint_domain,
    normalize_active_dns_osint_max_names,
    run_active_dns_osint,
)
from app.active_tls_basic import (
    ACTIVE_TLS_BASIC_DEFAULT_TIMEOUT_SECONDS,
    ActiveTlsBasicRequest,
    active_tls_basic_job_error,
    active_tls_basic_job_status,
    run_active_tls_basic,
)
from app.auth import (
    ADMIN_CSRF_HEADER_NAME,
    ADMIN_SESSION_COOKIE_NAME,
    AdminSession,
    AdminSessionStore,
    LoginAttemptStore,
    build_session_cookie_settings,
    is_supported_admin_password_hash,
    verify_admin_csrf_token,
    verify_admin_password,
)
from app.auth_state_sqlite import SQLiteAdminSessionStore, SQLiteLoginAttemptStore
from app.automation_tokens import AutomationPrincipal, AutomationTokenError, AutomationTokenRecord, AutomationTokenStore
from app.config import (
    get_auth_mode,
    get_current_operator_for_trusted_local,
    is_auth_configured,
    is_auth_required,
    is_single_admin_auth_configured,
    load_settings,
)
from app.domain_security import normalize_domain, normalize_subdomain_candidates
from app.execution_profile import build_execution_profile, execution_profile_comparison_limitation, execution_profiles_are_compatible
from app.finding_normalization import normalize_project_relative_path
from app.finding_lifecycle import FindingDecisionStore, FindingLifecycleError
from app.cargo_dependency_graph import (
    CARGO_DEPENDENCY_GRAPH_MAX_BYTES,
    CargoDependencyGraphError,
    parse_cargo_dependency_graph_artifact,
)
from app.composer_dependency_graph import (
    COMPOSER_DEPENDENCY_GRAPH_MAX_BYTES,
    ComposerDependencyGraphError,
    parse_composer_dependency_graph_artifact,
)
from app.gradle_dependency_graph import (
    GRADLE_DEPENDENCY_GRAPH_MAX_BYTES,
    GradleDependencyGraphError,
    parse_gradle_dependency_graph_artifact,
)
from app.nuget_dependency_graph import (
    NUGET_DEPENDENCY_GRAPH_MAX_BYTES,
    NugetDependencyGraphError,
    parse_nuget_dependency_graph_artifact,
)
from app.go_dependency_graph import (
    GO_DEPENDENCY_GRAPH_MAX_BYTES,
    GoDependencyGraphError,
    parse_go_dependency_graph_artifact,
)
from app.remediation_saved_views import (
    RemediationSavedViewCreateRequest,
    RemediationSavedViewDefaultRequest,
    RemediationSavedViewError,
    RemediationSavedViewPage,
    RemediationSavedViewRecord,
    RemediationSavedViewStore,
)
from app.component_inventory import build_component_coverage_matrix
from app.client_capabilities import ClientCapabilitiesResponse, build_client_capabilities
from app.models import (
    ActiveExecutionPageRequest,
    AutomationTokenCreateRequest,
    AutomationTokenCreatedResponse,
    AutomationTokenProbeResponse,
    AutomationTokenResponse,
    CiProjectSnapshotCreated,
    DeletedFileResponse,
    DeletedJobResponse,
    DomainAuditRequest,
    FindingDecisionCreateRequest,
    FindingDecisionRecord,
    FindingLifecycleState,
    AuthLoginRequest,
    AuthSessionResponse,
    AuthStatusResponse,
    JobListItem,
    JobPage,
    JobPageRequest,
    JobDetailView,
    JobRecord,
    FindingLocation,
    NormalizedFinding,
    ProjectAnalysisComparisonResponse,
    ProjectAnalysisCoverageComparison,
    ProjectAnalysisCreateRequest,
    ProjectBaselineSetRequest,
    ProjectArchivePreflightResponse,
    ProjectComponent,
    ProjectComponentCoverage,
    ProjectComponentInventoryResponse,
    ProjectComponentInventorySummary,
    CargoProjectDependencyGraphEvidence,
    ComposerProjectDependencyGraphEvidence,
    GradleProjectDependencyGraphEvidence,
    NugetProjectDependencyGraphEvidence,
    ProjectDependencyGraphEvidence,
    ProjectComparisonSummary,
    ProjectCreated,
    ProjectCreateRequest,
    ProjectDeletionPreview,
    ProjectDeletionRequest,
    ProjectDeletionResponse,
    ProjectFindingComparison,
    ProjectFindingsResponse,
    ProjectFindingSummary,
    ProjectRecord,
    ProjectPortfolioPage,
    ProjectPortfolioSearchRequest,
    ProjectPage,
    ProjectPageRequest,
    ProjectTechnicalReportRequest,
    ProjectResponsibilityUpdateRequest,
    RemediationPage,
    RemediationSearchRequest,
    RemediationBulkActionRequest,
    RemediationBulkActionResponse,
    RemediationReportRequest,
    RiskTrendReportRequest,
    RiskTrendRequest,
    RiskTrendResponse,
    RiskTrendViewResponse,
    ProjectView,
    current_project_responsibility,
    opaque_source_reference,
    ProjectSnapshotCreated,
    ProjectSbomRevisionCreated,
    SbomImportPreflightResponse,
    ProjectSnapshotCreateRequest,
    ProjectSummary,
    ProjectPublicVulnerabilityComparison,
    ProjectPublicVulnerabilityComparisonSummary,
    ProductAuditEventsResponse,
    PublicAdvisoryCacheCleanupResponse,
    PublicAdvisoryOperationsResponse,
    PublicAdvisoryProviderOperations,
    PublicIdentityAttestationCreateRequest,
    PublicIdentityAttestationResponse,
    ProjectPublicVulnerabilityFindingComparison,
    ProjectVulnerabilityFinding,
    ProjectVulnerabilityIntelligenceResponse,
    RetentionCleanupResponse,
    RetentionPolicyResponse,
    TeamInvitationAcceptRequest,
    TeamInvitationAcceptedResponse,
    TeamInvitationCreateRequest,
    TeamInvitationCreatedResponse,
    TeamMemberResponse,
    TeamMemberRoleUpdateRequest,
    TeamOrganizationResponse,
    TeamOrganizationCreateRequest,
    TeamOrganizationListItem,
    ProjectVulnerabilityIntelligenceSummary,
    StoredFile,
    StoredFileView,
    SubdomainInventoryRequest,
    WebAuditRequest,
)
from app.observability import log_audit_event
from app.adoption_metrics import AdoptionMetricsError, AdoptionMetricsStore
from app.product_audit import (
    PRODUCT_AUDIT_MAX_PAGE_SIZE,
    ProductAuditError,
    ProductAuditIntegrityResponse,
    ProductAuditStore,
)
from app.operational_readiness import OperationalReadinessService, probe_private_storage
from app.project_coverage import build_project_analysis_coverage, compare_project_analysis_coverage
from app.project_archive_capabilities import build_project_archive_preflight
from app.project_deletion import ProjectDeletionError, ProjectDeletionService
from app.project_action_inbox import (
    ProjectActionInboxError,
    ProjectActionInboxService,
    ProjectActionInboxStore,
    ProjectActionPage,
    ProjectActionReadRequest,
    ProjectActionRebuildRequest,
)
from app.project_portfolio import ProjectPortfolioService
from app.project_risk_trends import ProjectRiskTrendsService
from app.remediation_center import RemediationCenterService, public_vulnerability_rule_id
from app.remediation_plan_jobs import (
    RemediationPlanCreateRequest,
    RemediationPlanJob,
    RemediationPlanJobError,
    RemediationPlanJobPage,
    RemediationPlanJobStore,
    RemediationPlanRetryRequest,
    build_remediation_plan,
)
from app.remediation_reporting import (
    REMEDIATION_REPORT_MAX_GROUPS,
    render_durable_remediation_plan,
    render_remediation_report,
)
from app.risk_trend_reporting import render_risk_trend_report
from app.project_vulnerability_intelligence import (
    OsvVulnerabilityIntelligenceService,
    ProjectVulnerabilityIntelligenceStore,
    with_public_vulnerability_field_provenance,
)
from app.public_advisory_egress import PublicAdvisoryEgressClient, PublicAdvisoryNamespacePolicy, PublicComponentIdentity
from app.retention import RetentionMaintenanceService, build_retention_policy
from app.vulnerability_fingerprint import PUBLIC_VULNERABILITY_FINDING_FINGERPRINT_VERSION
from app.reporting import (
    build_report_filename,
    build_project_report_filename,
    public_job_error,
    public_job_target_url,
    public_result_for_job,
    redact_active_secret_text,
    render_html_report,
    render_markdown_report,
    render_pdf_report,
    render_project_html_report,
    render_project_markdown_report,
    render_project_pdf_report,
    render_xml_report,
)
from app.sbom import build_sbom_filename, generate_cyclonedx_json, generate_spdx_json
from app.sbom_import import SbomImportError, normalize_sbom, sbom_project_result
from app.sbom_preflight import SbomPreflightError, SbomPreflightStore
from app.services import (
    ArchiveAuditService,
    ActiveHttpHeaderProbeService,
    ActiveNmapBasicService,
    ActiveNetworkDryRunService,
    CiCdConfigAuditService,
    ComposeConfigAuditService,
    DatabaseConfigAuditService,
    DjangoConfigAuditService,
    DomainAuditService,
    DockerConfigAuditService,
    ImageAuditService,
    K8sConfigAuditService,
    ManifestAuditService,
    NodePackageConfigAuditService,
    NginxConfigAuditService,
    PdfAuditService,
    ProjectArchiveAuditService,
    RedisConfigAuditService,
    SecretsReviewAuditService,
    SqlDatabaseConfigAuditService,
    SubdomainInventoryAuditService,
    TerraformConfigAuditService,
    WebAuditService,
)
from app.storage import (
    ExecutionWorkspaceError,
    ExecutionWorkspaceStore,
    FileStore,
    JobStore,
    ProjectSnapshotAdmissionStore,
    ProjectStore,
    run_retention_cleanup,
    storage_lock,
)
from app.web_security import redact_url_query, validate_web_target_url
from app.team_identity import (
    PUBLIC_IDENTITY_ATTESTATION_CONTRACT_VERSION,
    PublicIdentityAttestation,
    TeamIdentityError,
    TeamIdentityStore,
    TeamPrincipal,
    team_role_allows,
)
from active_runner.models import ActiveDryRunRequest, ActiveHttpHeaderProbeRequest


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = load_settings()
    settings.ensure_directories()
    adoption_metrics = AdoptionMetricsStore(settings)
    try:
        adoption_metrics.purge_expired()
    except AdoptionMetricsError:
        log_audit_event("adoption_metrics.startup_failed", result="failed")
    product_audit = ProductAuditStore(settings)
    product_audit.purge_expired()
    file_store = FileStore(settings)
    job_store = JobStore(settings)
    active_asset_store = ActiveAssetStore(settings)
    active_change_approvals = ActiveChangeApprovalStore(settings)
    active_weekly_review_receipts = ActiveWeeklyReviewReceiptStore(settings)
    active_asset_verification_store = ActiveAssetVerificationStore(settings)
    active_recurrences = ActiveRecurrenceStore(settings)
    project_store = ProjectStore(settings)
    finding_decision_store = FindingDecisionStore(settings)
    remediation_saved_views = RemediationSavedViewStore(settings)
    remediation_plan_jobs = RemediationPlanJobStore(settings)
    try:
        app.state.recovered_remediation_batches = finding_decision_store.recover_pending_batches()
    except FindingLifecycleError:
        # Keep the service fail-closed and let readiness expose the pending
        # recovery without logging journal or decision contents.
        app.state.recovered_remediation_batches = 0
        log_audit_event("remediation.batch_recovery_failed", result="failed")
    public_advisory_egress_client = PublicAdvisoryEgressClient.from_settings(settings)
    project_vulnerability_intelligence_store = ProjectVulnerabilityIntelligenceStore(
        settings.public_advisories_dir,
        settings=settings,
    )
    project_snapshot_admissions = ProjectSnapshotAdmissionStore(settings, file_store, project_store, job_store)
    execution_workspaces = ExecutionWorkspaceStore(settings, file_store)
    project_action_inbox_store = ProjectActionInboxStore(settings)
    project_deletions = ProjectDeletionService(
        settings,
        project_store,
        job_store,
        finding_decision_store,
        project_snapshot_admissions,
        project_vulnerability_intelligence_store,
        execution_workspaces,
        project_action_inbox_store,
    )
    active_asset_deletions = ActiveAssetDeletionService(
        settings,
        active_asset_store,
        active_asset_verification_store,
        job_store,
        product_audit,
        active_recurrences,
        active_change_approvals,
    )
    app.state.recovered_project_deletions = project_deletions.recover_pending()
    app.state.recovered_active_asset_deletions = active_asset_deletions.recover_pending()
    app.state.recovered_snapshot_admissions = project_snapshot_admissions.recover_pending()
    app.state.interrupted_jobs = job_store.recover_interrupted_jobs(
        preserve_queued_project_jobs=True,
        preserve_queued_active_jobs=True,
    )
    app.state.orphaned_workspaces_cleaned = execution_workspaces.cleanup_orphans()
    app.state.retention_cleanup = run_retention_cleanup(
        settings,
        file_store,
        job_store,
        project_store,
        project_vulnerability_intelligence_store,
    )
    try:
        advisory_cache = public_advisory_egress_client.cache
        app.state.retention_cleanup["public_advisory_cache_entries_deleted"] = (
            advisory_cache.purge_expired() if advisory_cache is not None else 0
        )
    except (OSError, ValueError):
        app.state.retention_cleanup["public_advisory_cache_cleanup_failed"] = 1
        log_audit_event("retention.startup.cache_failed", result="failed")
    app.state.audit_semaphore = asyncio.Semaphore(settings.audit_max_concurrency)
    app.state.audit_cancellation_events = {}
    app.state.durable_audit_tasks = set()
    app.state.scheduled_project_audit_job_ids = set()
    app.state.scheduled_active_execution_job_ids = set()
    app.state.scheduled_remediation_plan_job_ids = set()
    app.state.scheduled_risk_trend_refresh_owner_ids = set()
    app.state.remediation_plan_semaphore = asyncio.Semaphore(2)
    app.state.risk_trend_refresh_semaphore = asyncio.Semaphore(1)
    app.state.active_execution_cancellation_events = {}
    app.state.active_asset_revocation_events = {}
    app.state.active_verification_cancellation_events = {}

    app.state.settings = settings
    app.state.product_audit = product_audit
    app.state.adoption_metrics = adoption_metrics
    app.state.auth_mode = get_auth_mode(settings)
    app.state.default_local_operator = get_current_operator_for_trusted_local(settings)
    app.state.single_admin_auth_configured = is_single_admin_auth_configured(settings)
    app.state.team_identity = create_team_identity_store(settings)
    if app.state.team_identity is not None:
        try:
            app.state.retention_cleanup["team_invitations_deleted"] = (
                app.state.team_identity.purge_terminal_invitations(
                    cutoff=datetime.now(timezone.utc)
                    - timedelta(days=settings.team_invitation_retention_days),
                )
            )
        except TeamIdentityError:
            app.state.retention_cleanup["team_invitation_cleanup_failed"] = 1
            log_audit_event("retention.startup.team_invitations_failed", result="failed")
    app.state.project_portfolio = ProjectPortfolioService(
        project_store,
        job_store,
        project_vulnerability_intelligence_store,
        finding_decision_store,
        app.state.team_identity,
    )
    app.state.project_action_inbox = ProjectActionInboxService(
        app.state.project_portfolio,
        project_action_inbox_store,
    )
    app.state.remediation_center = RemediationCenterService(
        project_store,
        job_store,
        project_vulnerability_intelligence_store,
        finding_decision_store,
    )
    app.state.project_risk_trends = ProjectRiskTrendsService(
        project_store,
        job_store,
        project_vulnerability_intelligence_store,
        finding_decision_store,
        app.state.project_portfolio,
    )
    try:
        with storage_lock(settings):
            app.state.risk_trend_source_clock_reset = (
                app.state.project_risk_trends.trend_index.source_clock.recover()
            )
    except Exception:
        app.state.risk_trend_source_clock_reset = False
        log_audit_event("project_risk_trends.source_clock_recovery_failed", result="failed")
    try:
        recovered_risk_trend_refreshes = (
            app.state.project_risk_trends.recover_pending_refreshes()
        )
    except Exception:
        recovered_risk_trend_refreshes = []
        log_audit_event("project_risk_trends.recovery_failed", result="failed")
    app.state.recovered_risk_trend_refreshes = len(recovered_risk_trend_refreshes)
    app.state.admin_sessions = create_admin_session_store(settings)
    app.state.login_attempts = create_login_attempt_store(settings)
    app.state.automation_tokens = create_automation_token_store(settings)
    app.state.session_cookie_settings = build_session_cookie_settings(
        settings.session_ttl_seconds,
        secure=settings.session_cookie_secure,
    )
    app.state.files = file_store
    app.state.jobs = job_store
    app.state.projects = project_store
    app.state.active_assets = active_asset_store
    app.state.active_change_approvals = active_change_approvals
    app.state.active_weekly_review_receipts = active_weekly_review_receipts
    app.state.active_asset_batch_preflights = ActiveAssetBatchPreflightStore()
    app.state.active_asset_verifications = active_asset_verification_store
    app.state.active_recurrences = active_recurrences
    app.state.active_asset_verification_transport = ManagedActiveAssetVerificationTransport()
    app.state.active_asset_verification_runner = ActiveToolsVerificationRunner(settings.active_tools_url)
    app.state.active_capability_runner = ActiveToolsCapabilityRunner(
        settings.active_tools_url,
        timeout_seconds=min(settings.active_tools_health_timeout_seconds * 4, 8.0),
    )
    app.state.active_capability_semaphore = asyncio.Semaphore(min(settings.audit_max_concurrency, 4))
    app.state.finding_decisions = finding_decision_store
    app.state.remediation_saved_views = remediation_saved_views
    app.state.remediation_plan_jobs = remediation_plan_jobs
    app.state.project_snapshot_admissions = project_snapshot_admissions
    app.state.sbom_preflights = SbomPreflightStore()
    app.state.project_deletions = project_deletions
    app.state.active_asset_deletions = active_asset_deletions
    app.state.execution_workspaces = execution_workspaces
    app.state.operational_readiness = OperationalReadinessService(
        settings,
        job_store,
        project_snapshot_admissions,
        execution_workspaces,
        storage_probe=lambda: probe_private_storage(settings.runtime_dir)
        and active_asset_store.index_ready()
        and job_store.active_job_index_ready()
        and app.state.project_portfolio.priority_index.ready()
        and app.state.project_risk_trends.trend_index.source_clock.ready()
        and app.state.project_risk_trends.trend_index.ready()
        and adoption_metrics.ready()
        and active_asset_verification_store.index_ready()
        and active_recurrences.index_ready(),
        deletion_pending_probe=lambda: (
            project_deletions.has_pending()
            or active_asset_deletions.has_pending()
            or finding_decision_store.has_pending_batches()
        ),
    )
    app.state.public_advisory_egress_client = public_advisory_egress_client
    app.state.project_vulnerability_intelligence_store = project_vulnerability_intelligence_store
    app.state.retention_maintenance = RetentionMaintenanceService(
        settings,
        file_store,
        job_store,
        project_store,
        project_vulnerability_intelligence_store,
        public_advisory_egress_client.cache,
        product_audit,
        app.state.automation_tokens,
        app.state.team_identity,
        active_change_approvals,
        active_weekly_review_receipts,
    )
    app.state.project_vulnerability_intelligence = OsvVulnerabilityIntelligenceService(
        app.state.public_advisory_egress_client,
        cache_ttl_seconds=settings.public_advisory_cache_ttl_seconds,
    )
    app.state.pdf_audits = PdfAuditService(settings, file_store, job_store)
    app.state.image_audits = ImageAuditService(settings, file_store, job_store)
    app.state.manifest_audits = ManifestAuditService(settings, file_store, job_store)
    app.state.archive_audits = ArchiveAuditService(settings, file_store, job_store)
    app.state.project_archive_audits = ProjectArchiveAuditService(settings, file_store, job_store, execution_workspaces)
    app.state.django_config_audits = DjangoConfigAuditService(settings, file_store, job_store)
    app.state.docker_config_audits = DockerConfigAuditService(settings, file_store, job_store)
    app.state.secrets_review_audits = SecretsReviewAuditService(settings, file_store, job_store)
    app.state.node_package_config_audits = NodePackageConfigAuditService(settings, file_store, job_store)
    app.state.ci_cd_config_audits = CiCdConfigAuditService(settings, file_store, job_store)
    app.state.k8s_config_audits = K8sConfigAuditService(settings, file_store, job_store)
    app.state.terraform_config_audits = TerraformConfigAuditService(settings, file_store, job_store)
    app.state.nginx_config_audits = NginxConfigAuditService(settings, file_store, job_store)
    app.state.compose_config_audits = ComposeConfigAuditService(settings, file_store, job_store)
    app.state.database_config_audits = DatabaseConfigAuditService(settings, file_store, job_store)
    app.state.sql_database_config_audits = SqlDatabaseConfigAuditService(settings, file_store, job_store)
    app.state.redis_config_audits = RedisConfigAuditService(settings, file_store, job_store)
    app.state.active_network_dry_runs = ActiveNetworkDryRunService(settings, job_store)
    app.state.active_http_header_probes = ActiveHttpHeaderProbeService(settings, job_store)
    app.state.active_http_basic_header_review_resolver = None
    app.state.active_http_basic_header_review_head_transport = None
    app.state.active_nmap_basic_service = ActiveNmapBasicService(settings, job_store)
    app.state.active_tools_health_checker = check_active_tools_health
    app.state.active_nmap_basic_lifecycle_client = ActiveNmapBasicRouteActiveToolsClient()
    app.state.active_dns_inventory_resolver = None
    app.state.active_dns_inventory_axfr_transport = None
    app.state.active_dns_osint_ct_source = build_active_dns_osint_ct_source(
        enabled=settings.active_dns_osint_ct_source_enabled,
        source_url=settings.active_dns_osint_ct_source_url,
        timeout_seconds=settings.active_dns_osint_ct_source_timeout_seconds,
        max_response_bytes=settings.active_dns_osint_ct_source_max_response_bytes,
        max_names_parsed=settings.active_dns_osint_ct_source_max_names_parsed,
    )
    try:
        recovered_remediation_plans = remediation_plan_jobs.recover()
    except RemediationPlanJobError:
        recovered_remediation_plans = []
        log_audit_event("remediation.plan_recovery_failed", result="failed")
    app.state.recovered_remediation_plan_jobs = len(recovered_remediation_plans)
    for recovered in recovered_remediation_plans:
        app.state.scheduled_remediation_plan_job_ids.add(recovered.id)
        task = asyncio.create_task(
            run_scheduled_remediation_plan(app, recovered.organization_id, recovered.id),
            name=f"inspectra-remediation-plan-{recovered.id}",
        )
        app.state.durable_audit_tasks.add(task)
    if recovered_risk_trend_refreshes:
        app.state.scheduled_risk_trend_refresh_owner_ids.update(
            recovered_risk_trend_refreshes
        )
        task = asyncio.create_task(
            run_recovered_risk_trend_refreshes(
                app, recovered_risk_trend_refreshes
            ),
            name="inspectra-risk-trend-refresh-recovery",
        )
        app.state.durable_audit_tasks.add(task)
    app.state.web_audits = WebAuditService(settings, file_store, job_store)
    app.state.domain_audits = DomainAuditService(settings, file_store, job_store)
    app.state.subdomain_inventory_audits = SubdomainInventoryAuditService(settings, file_store, job_store)
    app.state.recovered_queued_jobs = resume_queued_project_jobs(app)
    app.state.recovered_queued_active_jobs = resume_queued_active_jobs(app)
    app.state.active_recurrence_stop = asyncio.Event()
    app.state.active_recurrence_task = (
        asyncio.create_task(run_active_recurrence_loop(app), name="inspectra-active-recurrence")
        if settings.active_recurrence_enabled
        else None
    )
    try:
        yield
    finally:
        app.state.active_recurrence_stop.set()
        recurrence_task = app.state.active_recurrence_task
        if recurrence_task is not None:
            recurrence_task.cancel()
            with suppress(asyncio.CancelledError):
                await recurrence_task
        await stop_tracked_audits(app)
        app.state.shutdown_interrupted_jobs = job_store.recover_interrupted_jobs(
            preserve_queued_project_jobs=True,
            preserve_queued_active_jobs=True,
            termination_reason="application_shutdown",
            public_error="Audit interrupted during application shutdown. Run it again.",
        )
        app.state.shutdown_workspaces_cleaned = execution_workspaces.cleanup_orphans()


app = FastAPI(
    title="Inspectra",
    summary="Lightweight defensive security audit API.",
    version=PRODUCT_VERSION,
    lifespan=lifespan,
)

PUBLIC_ANONYMOUS_PATHS = {
    "/client-capabilities",
    "/health",
    "/ready",
    "/auth/status",
    "/auth/login",
    "/auth/invitations/accept",
}
CSRF_REQUIRED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
TEAM_READER_READ_POST_PATHS = frozenset({
    "/projects/search",
    "/projects/portfolio/search",
    "/projects/trends",
    "/projects/trends/refresh",
    "/projects/trends/report",
    "/remediation/search",
    "/remediation/report",
    "/remediation/plans",
    "/active/operations/weekly-review-receipts/verify",
})
AUTH_REQUIRED_DETAIL = "Authentication required."
CSRF_REQUIRED_DETAIL = "CSRF validation failed."
INVALID_CREDENTIALS_DETAIL = "Invalid credentials."
RATE_LIMITED_DETAIL = "Too many attempts. Try again later."
AUTOMATION_TOKEN_INVALID_DETAIL = "Automation credential is invalid or expired."
REQUEST_VALIDATION_DETAIL = "Request validation failed. Review the required fields and try again."
CORS_EXPOSED_RESPONSE_HEADERS = ("X-Inspectra-Snapshot-SHA256",)
PROJECT_FLOW_MUTATION_ROUTE_CONTRACT = frozenset(
    {
        ("POST", "/projects"),
        ("POST", "/projects/import/sbom"),
        ("POST", "/projects/import/sbom/preflight"),
        ("POST", "/projects/{project_id}/baseline"),
        ("POST", "/projects/{project_id}/analyses"),
        ("POST", "/projects/{project_id}/analyses/search"),
        ("POST", "/projects/{project_id}/analyses/{analysis_id}/cancel"),
        ("POST", "/projects/{project_id}/analyses/{analysis_id}/report/{report_format}"),
        ("POST", "/projects/{project_id}/analyses/{analysis_id}/dependency-graphs/go"),
        ("POST", "/projects/{project_id}/analyses/{analysis_id}/dependency-graphs/cargo"),
        ("POST", "/projects/{project_id}/analyses/{analysis_id}/dependency-graphs/composer"),
        ("POST", "/projects/{project_id}/analyses/{analysis_id}/dependency-graphs/gradle"),
        ("POST", "/projects/{project_id}/analyses/{analysis_id}/dependency-graphs/nuget"),
        ("POST", "/projects/{project_id}/analyses/{analysis_id}/vulnerability-intelligence/osv"),
        ("POST", "/projects/{project_id}/analyses/{analysis_id}/vulnerability-intelligence/github"),
        ("POST", "/projects/{project_id}/analyses/{analysis_id}/vulnerability-intelligence/nvd"),
        ("POST", "/projects/{project_id}/analyses/{analysis_id}/vulnerability-intelligence/cisa-kev"),
        ("POST", "/projects/{project_id}/findings/{finding_id}/decisions"),
        ("POST", "/projects/search"),
        ("POST", "/projects/portfolio/search"),
        ("POST", "/projects/actions/rebuild"),
        ("PUT", "/projects/actions/{action_id}/read"),
        ("POST", "/projects/trends"),
        ("POST", "/projects/trends/refresh"),
        ("POST", "/projects/trends/report"),
        ("POST", "/projects/{project_id}/snapshots"),
        ("PUT", "/projects/{project_id}/responsibility"),
        ("POST", "/projects/{project_id}/ci/snapshots"),
        ("POST", "/projects/{project_id}/sbom-revisions"),
        ("DELETE", "/projects/{project_id}"),
        ("DELETE", "/projects/{project_id}/baseline"),
        # Removing a retained source changes a project's snapshot availability.
        ("DELETE", "/files/{file_id}"),
    }
)
cors_settings = load_settings()


async def run_bounded_audit(app: FastAPI, audit_task: Any, *args: Any) -> None:
    job_id = args[0] if args and isinstance(args[0], str) else None
    events = getattr(app.state, "audit_cancellation_events", None)
    if not isinstance(events, dict):
        events = {}
        app.state.audit_cancellation_events = events
    cancellation_event = events.setdefault(job_id, asyncio.Event()) if job_id else asyncio.Event()
    acquired = False
    acquire_task = asyncio.create_task(app.state.audit_semaphore.acquire())
    cancellation_task = asyncio.create_task(cancellation_event.wait())
    work_task: asyncio.Task | None = None
    try:
        done, _pending = await asyncio.wait({acquire_task, cancellation_task}, return_when=asyncio.FIRST_COMPLETED)
        if cancellation_task in done:
            acquire_task.cancel()
            with suppress(asyncio.CancelledError):
                await acquire_task
            if job_id:
                _finish_cancelled_audit(app, job_id)
            return

        acquired = True
        cancellation_task.cancel()
        with suppress(asyncio.CancelledError):
            await cancellation_task
        if cancellation_event.is_set():
            if job_id:
                _finish_cancelled_audit(app, job_id)
            return

        work_task = asyncio.create_task(audit_task(*args))
        cancellation_task = asyncio.create_task(cancellation_event.wait())
        done, _pending = await asyncio.wait({work_task, cancellation_task}, return_when=asyncio.FIRST_COMPLETED)
        if cancellation_task in done and not work_task.done():
            work_task.cancel()
            with suppress(asyncio.CancelledError):
                await work_task
            if job_id:
                _finish_cancelled_audit(app, job_id)
            return
        cancellation_task.cancel()
        with suppress(asyncio.CancelledError):
            await cancellation_task
        await work_task
    except asyncio.CancelledError:
        if work_task is not None:
            work_task.cancel()
            with suppress(asyncio.CancelledError):
                await work_task
        raise
    except Exception:
        if job_id:
            try:
                record = app.state.jobs.get(job_id)
                if record.status in {"queued", "running", "cancelling"}:
                    app.state.jobs.update(
                        job_id,
                        status="failed",
                        error="The analysis stopped because of an internal execution error. Retry after reviewing service health.",
                        termination_reason="internal_error",
                    )
            except Exception:
                pass
    finally:
        for task in (acquire_task, cancellation_task):
            if not task.done():
                task.cancel()
        if acquired:
            app.state.audit_semaphore.release()
        if job_id and events.get(job_id) is cancellation_event:
            events.pop(job_id, None)


def _finish_cancelled_audit(app: FastAPI, job_id: str) -> None:
    workspaces = getattr(app.state, "execution_workspaces", None)
    if workspaces is not None:
        workspaces.cleanup(job_id)
    record = app.state.jobs.mark_cancelled(job_id)
    log_audit_event(
        "project.analysis.cancelled",
        correlation_id=f"job:{record.id}",
        job_id=record.id,
        project_id=record.project_id,
        owner_id=record.owner_id,
        termination_reason=record.termination_reason,
    )


def schedule_bounded_audit(background_tasks: BackgroundTasks, app: FastAPI, audit_task: Any, *args: Any) -> None:
    background_tasks.add_task(run_tracked_bounded_audit, app, audit_task, *args)


def schedule_project_archive_once(background_tasks: BackgroundTasks, app: FastAPI, job_id: str) -> bool:
    """Register one process-local dispatch for an idempotent snapshot job."""

    scheduled = getattr(app.state, "scheduled_project_audit_job_ids", None)
    if not isinstance(scheduled, set):
        scheduled = set()
        app.state.scheduled_project_audit_job_ids = scheduled
    if job_id in scheduled:
        return False
    scheduled.add(job_id)
    background_tasks.add_task(run_scheduled_project_archive, app, job_id)
    return True


async def run_scheduled_project_archive(app: FastAPI, job_id: str) -> None:
    try:
        await run_tracked_bounded_audit(app, app.state.project_archive_audits.run_project_archive_analysis, job_id)
    finally:
        app.state.scheduled_project_audit_job_ids.discard(job_id)


def schedule_active_execution_once(background_tasks: BackgroundTasks, app: FastAPI, job_id: str) -> bool:
    """Register one process-local dispatch; the store claim guards all workers."""

    scheduled = getattr(app.state, "scheduled_active_execution_job_ids", None)
    if not isinstance(scheduled, set):
        scheduled = set()
        app.state.scheduled_active_execution_job_ids = scheduled
    if job_id in scheduled:
        return False
    scheduled.add(job_id)
    background_tasks.add_task(run_scheduled_active_execution, app, job_id)
    return True


async def run_scheduled_active_execution(app: FastAPI, job_id: str) -> None:
    current = asyncio.current_task()
    tasks = getattr(app.state, "durable_audit_tasks", None)
    if not isinstance(tasks, set):
        tasks = set()
        app.state.durable_audit_tasks = tasks
    if current is not None:
        tasks.add(current)
    try:
        await run_durable_active_execution(app, job_id)
    finally:
        app.state.scheduled_active_execution_job_ids.discard(job_id)
        if current is not None:
            tasks.discard(current)


def schedule_remediation_plan_once(
    background_tasks: BackgroundTasks,
    app: FastAPI,
    organization_id: str,
    job_id: str,
) -> bool:
    scheduled = getattr(app.state, "scheduled_remediation_plan_job_ids", None)
    if not isinstance(scheduled, set):
        scheduled = set()
        app.state.scheduled_remediation_plan_job_ids = scheduled
    if job_id in scheduled:
        return False
    scheduled.add(job_id)
    background_tasks.add_task(run_scheduled_remediation_plan, app, organization_id, job_id)
    return True


async def run_scheduled_remediation_plan(app: FastAPI, organization_id: str, job_id: str) -> None:
    current = asyncio.current_task()
    tasks = getattr(app.state, "durable_audit_tasks", None)
    if not isinstance(tasks, set):
        tasks = set()
        app.state.durable_audit_tasks = tasks
    if current is not None:
        tasks.add(current)
    try:
        async with app.state.remediation_plan_semaphore:
            await asyncio.to_thread(
                build_remediation_plan,
                store=app.state.remediation_plan_jobs,
                projects=app.state.projects,
                remediation_center=app.state.remediation_center,
                organization_id=organization_id,
                job_id=job_id,
            )
    finally:
        app.state.scheduled_remediation_plan_job_ids.discard(job_id)
        if current is not None:
            tasks.discard(current)


def schedule_risk_trend_refresh_once(
    background_tasks: BackgroundTasks,
    app: FastAPI,
    organization_id: str,
) -> bool:
    """Dispatch one owner rebuild; the durable SQLite claim coalesces retries."""

    scheduled = getattr(app.state, "scheduled_risk_trend_refresh_owner_ids", None)
    if not isinstance(scheduled, set):
        scheduled = set()
        app.state.scheduled_risk_trend_refresh_owner_ids = scheduled
    if organization_id in scheduled:
        return False
    scheduled.add(organization_id)
    background_tasks.add_task(
        run_scheduled_risk_trend_refresh, app, organization_id
    )
    return True


async def run_scheduled_risk_trend_refresh(
    app: FastAPI,
    organization_id: str,
    *,
    manage_current_task: bool = True,
) -> None:
    current = asyncio.current_task()
    tasks = getattr(app.state, "durable_audit_tasks", None)
    if not isinstance(tasks, set):
        tasks = set()
        app.state.durable_audit_tasks = tasks
    if current is not None and manage_current_task:
        tasks.add(current)
    semaphore = getattr(app.state, "risk_trend_refresh_semaphore", None)
    if semaphore is None:
        semaphore = asyncio.Semaphore(1)
        app.state.risk_trend_refresh_semaphore = semaphore
    try:
        async with semaphore:
            # One source change observed during the first pass is coalesced into
            # one additional pass. Continued churn remains queued for the next
            # bounded request/recovery cycle instead of monopolizing a worker.
            passes = 0
            needs_another = True
            while needs_another and passes < 2:
                passes += 1
                needs_another = await asyncio.to_thread(
                    app.state.project_risk_trends.refresh_once,
                    organization_id=organization_id,
                )
            status_value = app.state.project_risk_trends.trend_index.materialization_status(
                organization_id=organization_id,
                observed_at=datetime.now(timezone.utc),
            )
            log_audit_event(
                "project_risk_trends.refresh_finished",
                owner_id=organization_id,
                state=status_value.state,
                pass_count=passes,
            )
    except Exception as exc:
        log_audit_event(
            "project_risk_trends.refresh_failed",
            owner_id=organization_id,
            error_type=exc.__class__.__name__,
            result="failed",
        )
    finally:
        app.state.scheduled_risk_trend_refresh_owner_ids.discard(organization_id)
        if current is not None and manage_current_task:
            tasks.discard(current)


async def run_recovered_risk_trend_refreshes(
    app: FastAPI,
    organization_ids: list[str],
) -> None:
    """Recover queued owner work sequentially under the same global bound."""

    current = asyncio.current_task()
    tasks = getattr(app.state, "durable_audit_tasks", None)
    if not isinstance(tasks, set):
        tasks = set()
        app.state.durable_audit_tasks = tasks
    if current is not None:
        tasks.add(current)
    try:
        for organization_id in organization_ids:
            await run_scheduled_risk_trend_refresh(
                app, organization_id, manage_current_task=False
            )
    finally:
        if current is not None:
            tasks.discard(current)


async def run_active_recurrence_loop(app: FastAPI) -> None:
    """Poll bounded due policies; the persisted job claim remains the worker guard."""

    while not app.state.active_recurrence_stop.is_set():
        try:
            await process_due_active_recurrences(app)
        except Exception as exc:
            log_audit_event(
                "active_recurrence.tick_failed",
                correlation_id="active-recurrence:tick",
                reason_code="controlled_failure",
                error_type=exc.__class__.__name__,
            )
        try:
            await asyncio.wait_for(app.state.active_recurrence_stop.wait(), timeout=60.0)
        except asyncio.TimeoutError:
            pass


def suspend_due_active_recurrence(
    app: FastAPI,
    recurrence: ActiveRecurrenceRecord,
    reason_code: Literal[
        "authorization_unavailable",
        "authorization_revision_changed",
        "verification_unavailable",
        "capability_disabled",
    ],
) -> None:
    """Suspend one due policy and emit target-free operational telemetry."""

    try:
        updated = app.state.active_recurrences.suspend(recurrence, reason_code)
    except ActiveRecurrenceError:
        log_audit_event(
            "active_recurrence.state_conflict",
            correlation_id=f"active-recurrence:{recurrence.id}",
            reason_code="concurrent_mutation",
        )
        return
    log_audit_event(
        "active_recurrence.suspended",
        correlation_id=f"active-recurrence:{updated.id}",
        reason_code=updated.reason_code,
    )


def defer_due_active_recurrence(
    app: FastAPI,
    recurrence: ActiveRecurrenceRecord,
    outcome: Literal["runner_unavailable", "capacity_saturated", "dispatch_conflict"],
    *,
    now: datetime | None,
) -> None:
    """Persist bounded retry state and log only closed, target-free fields."""

    try:
        updated = app.state.active_recurrences.record_failure(recurrence, outcome, now=now)
    except ActiveRecurrenceError:
        log_audit_event(
            "active_recurrence.state_conflict",
            correlation_id=f"active-recurrence:{recurrence.id}",
            reason_code="concurrent_mutation",
        )
        return
    log_audit_event(
        "active_recurrence.deferred",
        correlation_id=f"active-recurrence:{updated.id}",
        reason_code=updated.last_outcome,
        failure_count=updated.failure_count,
        retry_state="authorization_ended" if updated.next_retry_at is None else "scheduled",
    )


async def process_due_active_recurrences(app: FastAPI, *, now: datetime | None = None) -> list[str]:
    """Admit at most one job per due policy without reconstructing target data."""

    scheduled_job_ids: list[str] = []
    for recurrence in app.state.active_recurrences.list_due(now=now):
        try:
            if not active_capability_enabled(app.state.settings, recurrence.capability):
                suspend_due_active_recurrence(app, recurrence, "capability_disabled")
                continue
            asset = app.state.active_assets.get(
                recurrence.asset_id, organization_id=recurrence.organization_id
            )
            revision = current_active_authorization_revision(asset)
            if revision is None:
                suspend_due_active_recurrence(app, recurrence, "authorization_unavailable")
                continue
            if (
                revision.id != recurrence.authorization_revision_id
                or revision.digest_sha256 != recurrence.authorization_revision_digest_sha256
                or revision.sequence != recurrence.authorization_revision_sequence
            ):
                suspend_due_active_recurrence(app, recurrence, "authorization_revision_changed")
                continue
            app.state.active_assets.assert_executable(
                asset.id,
                organization_id=recurrence.organization_id,
                capability=recurrence.capability,
                expected_authorization_revision_id=recurrence.authorization_revision_id,
            )
            verification = app.state.active_asset_verifications.get(
                recurrence.verification_id,
                asset_id=asset.id,
                organization_id=recurrence.organization_id,
            )
            latest_verification = app.state.active_asset_verifications.latest(
                asset.id, organization_id=recurrence.organization_id
            )
            if (
                verification.status != "verified"
                or latest_verification is None
                or latest_verification.id != verification.id
                or latest_verification.status != "verified"
            ):
                suspend_due_active_recurrence(app, recurrence, "verification_unavailable")
                continue
        except ActiveAssetVerificationError:
            suspend_due_active_recurrence(app, recurrence, "verification_unavailable")
            continue
        except ActiveAssetStoreError:
            suspend_due_active_recurrence(app, recurrence, "authorization_unavailable")
            continue

        checker = getattr(app.state, "active_tools_health_checker", check_active_tools_health)
        try:
            runner_health = await checker(
                app.state.settings.active_tools_url,
                timeout_seconds=min(app.state.settings.active_tools_health_timeout_seconds, 2.0),
            )
        except Exception:
            runner_health = {"available": False, "capabilities": {}, "error_code": "active_tools_unavailable"}
        readiness = build_active_capability_readiness(
            recurrence.capability,
            backend_enabled=True,
            runner_health=runner_health,
        )
        if readiness["readiness"] != "ready":
            defer_due_active_recurrence(app, recurrence, "runner_unavailable", now=now)
            continue

        try:
            job, replayed = app.state.jobs.create_active_asset_execution_job(
                recurrence.capability,
                owner_id=recurrence.organization_id,
                active_asset_id=recurrence.asset_id,
                active_authorization_contract=ACTIVE_ASSET_CONTRACT_VERSION,
                active_authorization_revision_id=recurrence.authorization_revision_id,
                active_authorization_revision_digest_sha256=recurrence.authorization_revision_digest_sha256,
                active_authorization_revision_sequence=recurrence.authorization_revision_sequence,
                active_execution_port=recurrence.port,
                idempotency_key_sha256=recurrence_occurrence_key(recurrence),
            )
            if not replayed:
                app.state.active_assets.admit_execution(
                    recurrence.asset_id,
                    organization_id=recurrence.organization_id,
                    actor_id=recurrence.actor_id,
                    capability=recurrence.capability,
                )
            app.state.active_recurrences.record_dispatch(recurrence, job_id=job.id, now=now)
        except HTTPException as exc:
            defer_due_active_recurrence(
                app,
                recurrence,
                "capacity_saturated" if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS else "dispatch_conflict",
                now=now,
            )
            continue
        except (ActiveAssetStoreError, ActiveRecurrenceError):
            defer_due_active_recurrence(app, recurrence, "dispatch_conflict", now=now)
            continue

        if job.status == "queued" and job.id not in app.state.scheduled_active_execution_job_ids:
            app.state.scheduled_active_execution_job_ids.add(job.id)
            task = asyncio.create_task(
                run_scheduled_active_execution(app, job.id),
                name=f"inspectra-active-recurring-execution-{job.id}",
            )
            app.state.durable_audit_tasks.add(task)
        try:
            app.state.product_audit.record(
                organization_id=recurrence.organization_id,
                actor_id=recurrence.actor_id,
                actor_role=recurrence.actor_role,
                action="active_recurrence.execution_scheduled",
                resource_type="active_recurrence",
                resource_id=recurrence.id,
                correlation_id=f"active-recurrence:{recurrence.id}",
                metadata={
                    "job_id": job.id,
                    "authorization_revision_id": recurrence.authorization_revision_id,
                    "authorization_revision_sequence": recurrence.authorization_revision_sequence,
                    "replayed": replayed,
                },
            )
        except ProductAuditError:
            log_audit_event(
                "active_recurrence.audit_failed",
                correlation_id="active-recurrence:audit",
                owner_id=recurrence.organization_id,
            )
        scheduled_job_ids.append(job.id)
    return scheduled_job_ids


async def run_tracked_bounded_audit(app: FastAPI, audit_task: Any, *args: Any) -> None:
    """Keep a strong process-local reference so shutdown can drain safely."""

    current = asyncio.current_task()
    tasks = getattr(app.state, "durable_audit_tasks", None)
    if not isinstance(tasks, set):
        tasks = set()
        app.state.durable_audit_tasks = tasks
    if current is not None:
        tasks.add(current)
    try:
        await run_bounded_audit(app, audit_task, *args)
    finally:
        if current is not None:
            tasks.discard(current)


def resume_queued_project_jobs(app: FastAPI) -> list[JobRecord]:
    """Validate and dispatch never-started project work after one restart."""

    resumed: list[JobRecord] = []
    for queued in app.state.jobs.list_queued_project_jobs():
        rejection = queued_project_recovery_rejection(app, queued)
        if rejection is not None:
            app.state.execution_workspaces.cleanup(queued.id)
            rejected = app.state.jobs.update(
                queued.id,
                status="failed",
                error=(
                    "The queued analysis could not be recovered because its retained source or execution contract "
                    "is no longer valid. Review the project source and start a new analysis."
                ),
                termination_reason="recovery_rejected",
            )
            log_audit_event(
                "project.analysis.recovery_rejected",
                correlation_id=f"job:{rejected.id}",
                job_id=rejected.id,
                project_id=rejected.project_id,
                owner_id=rejected.owner_id,
                reason_code=rejection,
            )
            continue
        recovered = app.state.jobs.record_restart_requeue(queued.id)
        app.state.scheduled_project_audit_job_ids.add(recovered.id)
        task = asyncio.create_task(
            run_scheduled_project_archive(app, recovered.id),
            name=f"inspectra-project-analysis-{recovered.id}",
        )
        app.state.durable_audit_tasks.add(task)
        resumed.append(recovered)
        log_audit_event(
            "project.analysis.requeued_after_restart",
            correlation_id=f"job:{recovered.id}",
            job_id=recovered.id,
            project_id=recovered.project_id,
            owner_id=recovered.owner_id,
            recovery_count=recovered.recovery_count,
            execution_contract=(
                recovered.execution_profile.contract_version if recovered.execution_profile is not None else None
            ),
        )
    return resumed


def resume_queued_active_jobs(app: FastAPI) -> list[JobRecord]:
    """Revalidate and dispatch source-free Active work that never started."""

    resumed: list[JobRecord] = []
    for queued in app.state.jobs.list_queued_active_jobs():
        rejection = queued_active_recovery_rejection(app, queued)
        if rejection is not None:
            rejected = app.state.jobs.update(
                queued.id,
                status="failed",
                error="The queued Active execution could not be recovered because its authorization or execution contract is no longer valid. Review the asset before retrying.",
                termination_reason="recovery_rejected",
                active_execution_phase="terminal",
            )
            log_audit_event(
                "active_asset.execution_recovery_rejected",
                correlation_id=f"job:{rejected.id}",
                job_id=rejected.id,
                owner_id=rejected.owner_id,
                reason_code=rejection,
            )
            continue
        recovered = app.state.jobs.record_restart_requeue(queued.id)
        app.state.scheduled_active_execution_job_ids.add(recovered.id)
        task = asyncio.create_task(
            run_scheduled_active_execution(app, recovered.id),
            name=f"inspectra-active-execution-{recovered.id}",
        )
        app.state.durable_audit_tasks.add(task)
        resumed.append(recovered)
        log_audit_event(
            "active_asset.execution_requeued_after_restart",
            correlation_id=f"job:{recovered.id}",
            job_id=recovered.id,
            owner_id=recovered.owner_id,
            audit_type=recovered.audit_type,
            recovery_count=recovered.recovery_count,
            execution_contract=(recovered.execution_profile.contract_version if recovered.execution_profile else None),
        )
    return resumed


def queued_active_recovery_rejection(app: FastAPI, job: JobRecord) -> str | None:
    """Return one closed recovery reason without reconstructing or exposing a target."""

    if (
        job.active_asset_id is None
        or job.owner_id is None
        or job.active_authorization_revision_id is None
        or job.active_authorization_revision_digest_sha256 is None
        or job.active_authorization_revision_sequence is None
        or job.audit_type not in ACTIVE_CAPABILITIES
    ):
        return "incomplete_binding"
    if not active_capability_enabled(app.state.settings, job.audit_type):
        return "capability_disabled"
    expected_profile = build_execution_profile(app.state.settings, audit_type=job.audit_type, analysis_profile=job.analysis_profile)
    if job.execution_profile != expected_profile:
        return "execution_contract_changed"
    if job.audit_type == "active_tls_basic":
        if job.active_execution_port is None:
            return "port_binding_missing"
    elif job.active_execution_port is not None:
        return "port_binding_invalid"
    if job.retry_of_job_id is not None:
        try:
            previous = app.state.jobs.get(job.retry_of_job_id)
        except HTTPException:
            return "retry_lineage_invalid"
        if (
            previous.owner_id != job.owner_id
            or previous.active_asset_id != job.active_asset_id
            or previous.audit_type != job.audit_type
            or previous.status not in {"failed", "cancelled"}
        ):
            return "retry_lineage_invalid"
    try:
        asset = app.state.active_assets.get(job.active_asset_id, organization_id=job.owner_id)
        revision = current_active_authorization_revision(asset)
        if (
            revision is None
            or revision.id != job.active_authorization_revision_id
            or revision.digest_sha256 != job.active_authorization_revision_digest_sha256
            or revision.sequence != job.active_authorization_revision_sequence
            or (job.active_execution_port is not None and job.active_execution_port not in asset.allowed_ports)
        ):
            return "authorization_revision_changed"
        app.state.active_assets.assert_executable(
            asset.id,
            organization_id=job.owner_id,
            capability=job.audit_type,
            expected_authorization_revision_id=revision.id,
        )
    except ActiveAssetStoreError:
        return "authorization_unavailable"
    return None


def queued_project_recovery_rejection(app: FastAPI, job: JobRecord) -> str | None:
    """Return one bounded reason code; never return path or source content."""

    if job.project_id is None or job.file_id is None or job.owner_id is None or job.source_sha256 is None:
        return "incomplete_binding"
    expected_profile = build_execution_profile(
        app.state.settings,
        audit_type=job.audit_type,
        analysis_profile=job.analysis_profile,
    )
    if job.execution_profile != expected_profile:
        return "execution_contract_changed"
    try:
        project = app.state.projects.get(job.project_id)
        stored_file = app.state.files.get(job.file_id)
    except HTTPException:
        return "retained_source_unavailable"
    if project.owner_id != job.owner_id or stored_file.owner_id != job.owner_id:
        return "owner_binding_mismatch"
    if project.latest_job_id != job.id:
        return "superseded_queue_record"
    matching_snapshots = [
        snapshot
        for snapshot in project.source_snapshots
        if snapshot.source_file_id == job.file_id and snapshot.source_sha256 == job.source_sha256
    ]
    if not matching_snapshots or all(snapshot.source_file_deleted_at is not None for snapshot in matching_snapshots):
        return "snapshot_binding_mismatch"
    if job.source_file_deleted_at is not None:
        return "retained_source_unavailable"
    if job.retry_of_job_id is not None:
        try:
            previous = app.state.jobs.get(job.retry_of_job_id)
        except HTTPException:
            return "retry_lineage_invalid"
        if (
            previous.owner_id != job.owner_id
            or previous.project_id != job.project_id
            or previous.source_sha256 != job.source_sha256
            or previous.status not in {"failed", "cancelled"}
        ):
            return "retry_lineage_invalid"
    try:
        app.state.execution_workspaces.validate_recovery_source(job, stored_file)
    except ExecutionWorkspaceError:
        return "retained_source_integrity_failed"
    return None


async def stop_tracked_audits(app: FastAPI) -> None:
    """Cancel and await process-local audit tasks before terminal recovery."""

    tasks = list(getattr(app.state, "durable_audit_tasks", set()))
    current = asyncio.current_task()
    tasks = [task for task in tasks if task is not current and not task.done()]
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(cors_settings.cors_origins),
    allow_credentials=True,
    allow_methods=list(cors_settings.cors_allowed_methods),
    allow_headers=list(cors_settings.cors_allowed_headers),
    expose_headers=list(CORS_EXPOSED_RESPONSE_HEADERS),
)


@app.exception_handler(RequestValidationError)
async def redact_request_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Return a stable validation response without echoing untrusted input values."""
    log_audit_event(
        "http.request.validation_failed",
        correlation_id=getattr(request.state, "request_id", None),
        method=request.method,
        error_count=len(exc.errors()),
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": REQUEST_VALIDATION_DETAIL},
    )


@app.middleware("http")
async def deny_anonymous_sensitive_routes(request: Request, call_next) -> Response:
    request_id = uuid4().hex
    request.state.request_id = request_id
    started_at = time.perf_counter()
    response: Response | None = None
    error_type: str | None = None
    try:
        if request.method == "OPTIONS" or request.url.path in PUBLIC_ANONYMOUS_PATHS:
            response = await call_next(request)
            return response

        settings = getattr(request.app.state, "settings", None) or load_settings()
        if not is_auth_required(settings):
            response = await call_next(request)
            return response

        authorization = request.headers.get("Authorization", "")
        if authorization:
            if not authorization.startswith("Bearer ") or authorization.count(" ") != 1:
                response = JSONResponse(status_code=401, content={"detail": AUTOMATION_TOKEN_INVALID_DETAIL})
                return response
            token_store = getattr(request.app.state, "automation_tokens", None)
            if not isinstance(token_store, AutomationTokenStore):
                response = JSONResponse(status_code=401, content={"detail": AUTOMATION_TOKEN_INVALID_DETAIL})
                return response
            try:
                principal = token_store.authenticate(authorization.removeprefix("Bearer "))
            except AutomationTokenError as exc:
                if exc.code == "rate_limited":
                    response = JSONResponse(
                        status_code=429,
                        content={"detail": RATE_LIMITED_DETAIL},
                        headers={"Retry-After": "60"},
                    )
                    return response
                response = JSONResponse(
                    status_code=503,
                    content={"detail": "Automation authentication is unavailable."},
                )
                return response
            if principal is None:
                response = JSONResponse(status_code=401, content={"detail": AUTOMATION_TOKEN_INVALID_DETAIL})
                return response
            if not automation_principal_authorizes_request(principal, request.method, request.url.path):
                response = JSONResponse(
                    status_code=403,
                    content={"detail": "Automation credential scope does not permit this action."},
                )
                return response
            request.state.automation_principal = principal
            request.state.current_operator_id = principal.organization_id
            response = await call_next(request)
            return response

        session = current_session_for_request(request)
        if session is None:
            response = JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": AUTH_REQUIRED_DETAIL},
            )
            return response

        if is_csrf_required_for_request(request) and not verify_csrf_token_for_request(request, session):
            response = JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": CSRF_REQUIRED_DETAIL},
            )
            return response

        if (
            get_auth_mode(settings) == "private_team_lightweight_users"
            and request.method.upper() in CSRF_REQUIRED_METHODS
            and request.url.path != "/auth/logout"
            and not team_role_allows(session.role, "project_mutate")
            and request.url.path not in TEAM_READER_READ_POST_PATHS
            and not (
                (request.method.upper() == "POST" and request.url.path == "/remediation/views")
                or (request.method.upper() == "PUT" and request.url.path == "/remediation/views/default")
                or (
                    request.method.upper() == "PUT"
                    and re.fullmatch(r"/projects/actions/[a-f0-9]{32}/read", request.url.path)
                )
                or (
                    request.method.upper() == "DELETE"
                    and re.fullmatch(r"/remediation/views/[a-f0-9]{32}", request.url.path)
                )
            )
        ):
            response = JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "This role cannot modify workspace data."},
            )
            return response

        response = await call_next(request)
        return response
    except Exception as exc:
        error_type = exc.__class__.__name__
        raise
    finally:
        if response is not None:
            response.headers["X-Request-ID"] = request_id
        matched_route = request.scope.get("route")
        route_template = getattr(matched_route, "path", None)
        duration_ms = round((time.perf_counter() - started_at) * 1000)
        log_audit_event(
            "http.request.completed",
            correlation_id=request_id,
            method=request.method,
            route=route_template if isinstance(route_template, str) else "unmatched_route",
            status_code=response.status_code if response is not None else 500,
            duration_ms=duration_ms,
            error_type=error_type,
        )
        adoption_metrics = getattr(request.app.state, "adoption_metrics", None)
        if isinstance(adoption_metrics, AdoptionMetricsStore) and isinstance(route_template, str):
            try:
                adoption_metrics.record_http(
                    method=request.method,
                    route_template=route_template,
                    status_code=response.status_code if response is not None else 500,
                    duration_ms=duration_ms,
                )
            except AdoptionMetricsError:
                log_audit_event("adoption_metrics.record_failed", result="failed")


def current_owner_id_for_request(request: Request) -> str:
    settings = getattr(request.app.state, "settings", None) or load_settings()
    automation_principal = automation_principal_for_request(request)
    if automation_principal is not None:
        return automation_principal.organization_id
    if get_auth_mode(settings) == "private_team_lightweight_users":
        session = current_session_for_request(request)
        if session is None or not session.organization_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=AUTH_REQUIRED_DETAIL)
        return session.organization_id

    session_operator_id = getattr(request.state, "current_operator_id", None)
    if isinstance(session_operator_id, str) and session_operator_id:
        return session_operator_id

    if is_auth_required(settings):
        session = current_session_for_request(request)
        if session is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=AUTH_REQUIRED_DETAIL)
        return session.operator_id

    return request.app.state.default_local_operator.id


def current_session_for_request(request: Request) -> AdminSession | None:
    existing_session = getattr(request.state, "current_session", None)
    if isinstance(existing_session, AdminSession):
        return existing_session

    session_id = request.cookies.get(ADMIN_SESSION_COOKIE_NAME)
    session = request.app.state.admin_sessions.get_session(session_id)
    settings = getattr(request.app.state, "settings", None) or load_settings()
    if session is not None and get_auth_mode(settings) == "private_team_lightweight_users":
        identity_store = getattr(request.app.state, "team_identity", None)
        if not isinstance(identity_store, TeamIdentityStore) or not session.organization_id:
            session = None
        else:
            try:
                principal = identity_store.get_principal(session.operator_id, session.organization_id)
            except TeamIdentityError:
                principal = None
            if principal is None or principal.role != session.role:
                request.app.state.admin_sessions.invalidate_session(session_id)
                session = None
    if session is not None:
        request.state.current_session = session
        request.state.current_operator_id = session.operator_id
    return session


def create_admin_session_store(settings) -> AdminSessionStore | SQLiteAdminSessionStore:
    if get_auth_mode(settings) in {"self_hosted_single_admin", "private_team_lightweight_users"} and settings.auth_state_store == "sqlite":
        return SQLiteAdminSessionStore(settings.resolved_auth_state_db_path, settings.session_ttl_seconds)
    return AdminSessionStore(settings.session_ttl_seconds)


def create_login_attempt_store(settings) -> LoginAttemptStore | SQLiteLoginAttemptStore:
    if get_auth_mode(settings) in {"self_hosted_single_admin", "private_team_lightweight_users"} and settings.auth_state_store == "sqlite":
        return SQLiteLoginAttemptStore(
            settings.resolved_auth_state_db_path,
            window_seconds=settings.login_attempt_window_seconds,
            max_failures=settings.login_attempt_max_failures,
            lockout_seconds=settings.login_lockout_seconds,
            max_keys=settings.login_attempt_max_keys,
        )
    return LoginAttemptStore(
        window_seconds=settings.login_attempt_window_seconds,
        max_failures=settings.login_attempt_max_failures,
        lockout_seconds=settings.login_lockout_seconds,
        max_keys=settings.login_attempt_max_keys,
    )


def is_login_available_for_settings(settings) -> bool:
    auth_mode = get_auth_mode(settings)
    if auth_mode == "self_hosted_single_admin":
        return is_supported_admin_password_hash(settings.admin_password_hash)
    return auth_mode == "private_team_lightweight_users" and is_auth_configured(settings)


def create_team_identity_store(settings) -> TeamIdentityStore | None:
    if get_auth_mode(settings) != "private_team_lightweight_users":
        return None
    if not settings.admin_password_hash:
        return None
    return TeamIdentityStore(
        settings.resolved_auth_state_db_path,
        organization_name=settings.team_organization_name,
        bootstrap_admin_password_hash=settings.admin_password_hash,
        invitation_ttl_seconds=settings.team_invitation_ttl_seconds,
    )


def create_automation_token_store(settings) -> AutomationTokenStore | None:
    if get_auth_mode(settings) not in {"self_hosted_single_admin", "private_team_lightweight_users"}:
        return None
    if settings.auth_state_store != "sqlite" or not is_auth_configured(settings):
        return None
    return AutomationTokenStore(settings.resolved_auth_state_db_path)


def automation_principal_for_request(request: Request) -> AutomationPrincipal | None:
    principal = getattr(request.state, "automation_principal", None)
    return principal if isinstance(principal, AutomationPrincipal) else None


def automation_principal_authorizes_request(principal: AutomationPrincipal, method: str, path: str) -> bool:
    """Closed route policy for bearer credentials; unknown routes fail closed."""

    method = method.upper()
    project_prefix = f"/projects/{principal.project_id}"
    if method == "POST" and path == "/files/archive":
        return "project:scan" in principal.scopes
    if path == project_prefix or path.startswith(f"{project_prefix}/"):
        if method in {"GET", "POST"} and "/report/" in path:
            return "report:read" in principal.scopes
        if method == "GET":
            return bool({"project:read", "project:scan", "report:read"}.intersection(principal.scopes))
        if method == "POST" and (
            path == f"{project_prefix}/snapshots"
            or path == f"{project_prefix}/ci/snapshots"
            or path == f"{project_prefix}/sbom-revisions"
            or path == f"{project_prefix}/analyses"
            or re.fullmatch(re.escape(project_prefix) + r"/analyses/[a-f0-9]{32}/cancel", path)
            or re.fullmatch(
                re.escape(project_prefix) + r"/analyses/[a-f0-9]{32}/dependency-graphs/(?:go|cargo|composer|gradle)",
                path,
            )
            or re.fullmatch(
                re.escape(project_prefix)
                + r"/analyses/[a-f0-9]{32}/vulnerability-intelligence/(?:osv|github|nvd|cisa-kev)",
                path,
            )
        ):
            return "project:scan" in principal.scopes
        return False
    if method == "GET" and re.fullmatch(r"/jobs/[a-f0-9]{32}", path):
        return bool({"project:read", "project:scan"}.intersection(principal.scopes))
    if method == "GET" and re.fullmatch(
        r"/jobs/[a-f0-9]{32}/(?:export/(?:markdown|html|xml|pdf)|sbom/(?:cyclonedx-json|spdx-json))",
        path,
    ):
        return "report:read" in principal.scopes
    return False


def current_team_principal(request: Request) -> TeamPrincipal:
    settings = getattr(request.app.state, "settings", None) or load_settings()
    if get_auth_mode(settings) != "private_team_lightweight_users":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found.")
    session = current_session_for_request(request)
    identity_store = getattr(request.app.state, "team_identity", None)
    if session is None or not session.organization_id or not isinstance(identity_store, TeamIdentityStore):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=AUTH_REQUIRED_DETAIL)
    try:
        principal = identity_store.get_principal(session.operator_id, session.organization_id)
    except TeamIdentityError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Identity service unavailable.") from exc
    if principal is None or principal.role != session.role:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=AUTH_REQUIRED_DETAIL)
    return principal


def require_team_administrator(request: Request) -> TeamPrincipal:
    principal = current_team_principal(request)
    if not team_role_allows(principal.role, "workspace_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator role required.")
    return principal


def require_team_maintainer(request: Request) -> TeamPrincipal:
    principal = current_team_principal(request)
    if not team_role_allows(principal.role, "project_mutate"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Maintainer role required.")
    return principal


def public_identity_attestation_response(
    attestation: PublicIdentityAttestation,
) -> PublicIdentityAttestationResponse:
    return PublicIdentityAttestationResponse(
        contract_version=PUBLIC_IDENTITY_ATTESTATION_CONTRACT_VERSION,
        id=attestation.attestation_id,
        ecosystem=attestation.ecosystem,
        package_name=attestation.package_name,
        status=attestation.status,
        revision=attestation.revision,
        requested_ttl_days=attestation.requested_ttl_days,
        proposed_at=attestation.proposed_at,
        approved_at=attestation.approved_at,
        expires_at=attestation.expires_at,
        revoked_at=attestation.revoked_at,
    )


def public_advisory_operations_response(request: Request) -> PublicAdvisoryOperationsResponse:
    client = request.app.state.public_advisory_egress_client
    summaries = client.cache.operational_summary() if client.cache is not None else ()
    by_provider = {item.provider: item for item in summaries}
    configured = {
        "osv": client.enabled,
        "github_advisories": client.enabled,
        "nvd": client.enabled and client.nvd_enabled,
        "cisa_kev": client.enabled,
    }
    providers = []
    for provider in ("osv", "github_advisories", "nvd", "cisa_kev"):
        item = by_provider.get(provider)
        providers.append(PublicAdvisoryProviderOperations(
            provider=provider,
            configured=configured[provider],
            cache_entries=item.entries if item else 0,
            fresh_entries=item.fresh_entries if item else 0,
            stale_entries=item.stale_entries if item else 0,
            invalid_entries=item.invalid_entries if item else 0,
            cache_bytes=item.total_bytes if item else 0,
            last_updated_at=item.last_updated_at if item else None,
            truncated=item.truncated if item else False,
        ))
    return PublicAdvisoryOperationsResponse(
        egress_enabled=client.enabled,
        offline_snapshot_active=client.has_active_offline_snapshot(),
        providers=providers,
    )


def _public_identity_attestation_http_error(exc: TeamIdentityError) -> HTTPException:
    if exc.code in {"invalid_public_identity", "invalid_attestation_ttl"}:
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Public package identity is invalid.")
    if exc.code in {"attestation_exists", "attestation_not_pending", "attestation_not_active"}:
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Public identity approval state changed. Refresh and retry.")
    if exc.code == "attestation_limit_reached":
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Public identity approval limit reached for this workspace.")
    if exc.code == "attestation_not_found":
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Public identity approval not found.")
    if exc.code == "administrator_required":
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator role required.")
    if exc.code == "maintainer_required":
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Maintainer role required.")
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Public identity approvals are unavailable.")


def public_advisory_policy_for_owner(
    request: Request,
    organization_id: str,
) -> tuple[PublicAdvisoryNamespacePolicy, Callable[[PublicComponentIdentity], bool] | None]:
    client = request.app.state.public_advisory_egress_client
    settings = getattr(request.app.state, "settings", None) or load_settings()
    if get_auth_mode(settings) != "private_team_lightweight_users":
        return client.namespace_policy, None
    store = getattr(request.app.state, "team_identity", None)
    if not isinstance(store, TeamIdentityStore):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Public identity approvals are unavailable.")
    try:
        policy = client.namespace_policy.with_organization_attestations(
            store.approved_public_identity_keys(organization_id)
        )
    except (TeamIdentityError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Public identity approvals are unavailable.") from exc

    def authorize(component: PublicComponentIdentity) -> bool:
        try:
            return store.is_public_identity_approved(
                organization_id,
                component.ecosystem,
                component.name,
            )
        except TeamIdentityError:
            return False

    return policy, authorize


def require_automation_token_administrator(request: Request) -> tuple[str, str, str]:
    if automation_principal_for_request(request) is not None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Interactive administrator session required.")
    settings = getattr(request.app.state, "settings", None) or load_settings()
    token_store = getattr(request.app.state, "automation_tokens", None)
    if not isinstance(token_store, AutomationTokenStore):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Automation credentials are unavailable.")
    if get_auth_mode(settings) == "private_team_lightweight_users":
        principal = require_team_administrator(request)
        return principal.organization_id, principal.user_id, principal.role
    session = current_session_for_request(request)
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=AUTH_REQUIRED_DETAIL)
    return session.operator_id, session.operator_id, "administrator"


def automation_token_response(record: AutomationTokenRecord) -> AutomationTokenResponse:
    return AutomationTokenResponse(
        id=record.token_id,
        name=record.name,
        project_id=record.project_id,
        scopes=list(record.scopes),
        created_at=record.created_at,
        expires_at=record.expires_at,
        revoked_at=record.revoked_at,
        last_used_at=record.last_used_at,
    )


def require_team_scope_identifier(value: str, *, bootstrap_value: str, detail: str) -> str:
    if value == bootstrap_value or re.fullmatch(r"[a-f0-9]{32}", value):
        return value
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)


def login_client_key_for_request(request: Request) -> str:
    client = request.client
    if client is None or not isinstance(client.host, str) or not client.host.strip():
        return "unknown"
    return client.host.strip()


def is_csrf_required_for_request(request: Request) -> bool:
    return request.method.upper() in CSRF_REQUIRED_METHODS


def csrf_token_for_session(request: Request, session: AdminSession | None) -> str | None:
    if session is None:
        return None
    token_provider = getattr(request.app.state.admin_sessions, "csrf_token_for_session", None)
    if callable(token_provider):
        return token_provider(session)
    return session.csrf_token


def verify_csrf_token_for_request(request: Request, session: AdminSession) -> bool:
    csrf_token = request.headers.get(ADMIN_CSRF_HEADER_NAME)
    verifier = getattr(request.app.state.admin_sessions, "verify_csrf_token", None)
    if callable(verifier):
        return verifier(session.session_id, csrf_token)
    return verify_admin_csrf_token(csrf_token, session)


def owned_by_current_request(request: Request, owner_id: str | None) -> bool:
    return owner_id == current_owner_id_for_request(request)


def require_file_owner(request: Request, stored_file: StoredFile) -> StoredFile:
    if not owned_by_current_request(request, stored_file.owner_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")
    return stored_file


def require_job_owner(request: Request, job: JobRecord) -> JobRecord:
    if not owned_by_current_request(request, job.owner_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found.")
    return job


def require_project_owner(request: Request, project: ProjectRecord) -> ProjectRecord:
    if not owned_by_current_request(request, project.owner_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
    return project


def get_file_for_current_owner(request: Request, file_id: str) -> StoredFile:
    return require_file_owner(request, request.app.state.files.get(file_id))


def get_job_for_current_owner(request: Request, job_id: str) -> JobRecord:
    job = require_job_owner(request, request.app.state.jobs.get(job_id))
    automation_principal = automation_principal_for_request(request)
    if automation_principal is not None and job.project_id != automation_principal.project_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found.")
    return job


def get_project_for_current_owner(request: Request, project_id: str) -> ProjectRecord:
    project = require_project_owner(request, request.app.state.projects.get(project_id))
    automation_principal = automation_principal_for_request(request)
    if automation_principal is not None and project.id != automation_principal.project_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
    return project


def owner_id_for_file_job(request: Request, stored_file: StoredFile) -> str:
    return stored_file.owner_id or current_owner_id_for_request(request)


def default_project_name(source_file_id: str) -> str:
    """Generate a useful label without deriving it from a private filename."""

    reference = opaque_source_reference(source_file_id)
    suffix = reference.removeprefix("snapshot-")[:8] if reference else "private"
    return f"Project {suffix}"


def finding_lifecycle_for_project(
    request: Request,
    project: ProjectRecord,
    findings: list[NormalizedFinding],
) -> dict[str, FindingLifecycleState]:
    organization_id = project.organization_id or project.owner_id
    if not organization_id:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Finding lifecycle is unavailable.")
    try:
        return request.app.state.finding_decisions.lifecycle_for_findings(
            organization_id,
            project.id,
            findings,
        )
    except FindingLifecycleError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Finding lifecycle is unavailable.") from exc


def finding_decision_actor(request: Request) -> tuple[str, str, str]:
    automation_principal = automation_principal_for_request(request)
    if automation_principal is not None:
        return automation_principal.token_id, "automation", "maintainer"
    settings = getattr(request.app.state, "settings", None) or load_settings()
    if get_auth_mode(settings) == "private_team_lightweight_users":
        principal = current_team_principal(request)
        return principal.user_id, principal.username, principal.role
    session = current_session_for_request(request)
    if session is not None:
        return session.operator_id, "admin", "administrator"
    operator = request.app.state.default_local_operator
    return operator.id, "local-admin", "administrator"


def finding_decision_assignee(request: Request, user_id: str | None) -> tuple[str | None, str | None]:
    if user_id is None:
        return None, None
    settings = getattr(request.app.state, "settings", None) or load_settings()
    if get_auth_mode(settings) == "private_team_lightweight_users":
        principal = current_team_principal(request)
        try:
            member = next(
                (item for item in request.app.state.team_identity.list_members(principal.organization_id) if item.user_id == user_id),
                None,
            )
        except TeamIdentityError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Identity service unavailable.") from exc
        if member is None:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Assignee must be an active workspace member.")
        return member.user_id, member.username
    actor_id, actor_username, _ = finding_decision_actor(request)
    if user_id != actor_id:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Assignee must be the current operator.")
    return actor_id, actor_username


def project_responsibility_for_report(
    request: Request, project: ProjectRecord
) -> tuple[str, str | None]:
    responsibility = current_project_responsibility(project)
    if responsibility.state != "assigned" or responsibility.responsible_user_id is None:
        return responsibility.state, None
    settings = getattr(request.app.state, "settings", None) or load_settings()
    if get_auth_mode(settings) != "private_team_lightweight_users":
        return "assigned", "local-admin"
    try:
        member = request.app.state.team_identity.get_principal(
            responsibility.responsible_user_id,
            project.organization_id or project.owner_id,
        )
    except TeamIdentityError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Project responsibility is temporarily unavailable.",
        ) from exc
    if member is None:
        return "unassigned_attention", None
    return "assigned", member.username


def record_product_action(
    request: Request,
    action: str,
    *,
    resource_type: str,
    resource_id: str,
    result: str = "succeeded",
    organization_id: str | None = None,
    actor_id: str | None = None,
    actor_role: str | None = None,
    correlation_id: str | None = None,
    metadata: dict[str, object] | None = None,
) -> None:
    """Persist only an allowlisted, source-free view of a user action."""

    try:
        resolved_organization_id = organization_id or current_owner_id_for_request(request)
        if actor_id is None or actor_role is None:
            resolved_actor_id, _actor_username, resolved_actor_role = finding_decision_actor(request)
        else:
            resolved_actor_id, resolved_actor_role = actor_id, actor_role
        request.app.state.product_audit.record(
            organization_id=resolved_organization_id,
            actor_id=resolved_actor_id,
            actor_role=resolved_actor_role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            result=result,
            correlation_id=correlation_id or getattr(request.state, "request_id", None) or uuid4().hex,
            metadata=metadata,
        )
    except (ProductAuditError, ValidationError, AttributeError):
        # The primary action has already reached its authoritative store. Keep
        # this signal deliberately content-free; a later integrity task can
        # introduce fail-closed transactional semantics where justified.
        log_audit_event("product_audit.persist_failed", result="failed")


def require_product_audit_reader(request: Request) -> tuple[str, str, str]:
    settings = getattr(request.app.state, "settings", None) or load_settings()
    if get_auth_mode(settings) == "private_team_lightweight_users":
        principal = current_team_principal(request)
        if principal.role != "administrator":
            record_product_action(
                request,
                "audit.events.read",
                resource_type="organization",
                resource_id=principal.organization_id,
                result="denied",
                organization_id=principal.organization_id,
                actor_id=principal.user_id,
                actor_role=principal.role,
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator role required.")
        return principal.organization_id, principal.user_id, principal.role
    actor_id, _actor_username, actor_role = finding_decision_actor(request)
    return current_owner_id_for_request(request), actor_id, actor_role


def retention_cleanup_allowed(request: Request) -> bool:
    settings = getattr(request.app.state, "settings", None) or load_settings()
    if get_auth_mode(settings) == "private_team_lightweight_users":
        return current_team_principal(request).role == "administrator"
    return True


def require_retention_administrator(request: Request) -> str:
    if not retention_cleanup_allowed(request):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator role required.")
    return current_owner_id_for_request(request)


def active_asset_actor(request: Request, *, write: bool = False) -> tuple[str, str, str]:
    """Resolve the organization and actor without granting automation tokens Active access."""

    if automation_principal_for_request(request) is not None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Interactive Active access required.")
    organization_id = current_owner_id_for_request(request)
    actor_id, _actor_username, actor_role = finding_decision_actor(request)
    if write and actor_role not in {"administrator", "maintainer"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Maintainer role required.")
    return organization_id, actor_id, actor_role


def active_change_approval_http_error(exc: ActiveChangeApprovalError) -> HTTPException:
    code = exc.code
    if code in {"approval_not_found", "invalid_scope"}:
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active change approval not found.")
    if code in {"administrator_required", "same_actor"}:
        detail = "A different current administrator must approve this change." if code == "same_actor" else "Administrator role required."
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)
    if code == "maintainer_required":
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Maintainer role required.")
    if code in {"approval_not_ready", "approval_state_changed", "approval_not_executing"}:
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Active change approval is no longer actionable. Refresh and request a new review.")
    if code in {"requester_required", "approval_mismatch"}:
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Active change approval does not match this requester and exact mutation.")
    if code == "capacity_reached":
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Active change approval capacity is reached for this workspace.")
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Active change approvals are unavailable.")


def active_weekly_review_receipt_http_error(
    exc: ActiveWeeklyReviewReceiptError,
) -> HTTPException:
    if exc.code in {"not_found", "invalid_scope"}:
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Active weekly review receipt not found.",
        )
    if exc.code in {"stale_revision", "idempotency_conflict"}:
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Weekly review receipt state changed. Refresh the history and prepare a new review.",
        )
    if exc.code in {"invalid_store", "store_unavailable"}:
        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Weekly review receipt storage is temporarily unavailable.",
        )
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="Weekly review receipt request is invalid.",
    )


def _active_four_eyes_available(request: Request) -> bool:
    settings = getattr(request.app.state, "settings", None) or load_settings()
    return bool(settings.active_four_eyes_enabled and get_auth_mode(settings) == "private_team_lightweight_users")


def _active_approval_view(
    request: Request,
    record: ActiveChangeApprovalRecord,
    *,
    organization_id: str,
    actor_id: str,
    actor_role: str,
) -> ActiveChangeApprovalView:
    return request.app.state.active_change_approvals.view(
        record, organization_id=organization_id, actor_id=actor_id, actor_role=actor_role
    )


def _claim_active_change(
    request: Request,
    *,
    organization_id: str,
    actor_id: str,
    kind: Literal["registration", "renewal", "revocation"],
    asset_id: str | None,
    payload: ActiveAssetCreateRequest | ActiveAssetRenewRequest | ActiveAssetRevokeRequest,
) -> str | None:
    if not request.app.state.settings.active_four_eyes_enabled:
        return None
    if not _active_four_eyes_available(request):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Four-eyes Active changes require private team mode with two current accounts.",
        )
    approval_id = request.headers.get("X-Inspectra-Active-Approval", "")
    digest = active_change_operation_digest(
        organization_id=organization_id, kind=kind, asset_id=asset_id, payload=payload
    )
    try:
        if re.fullmatch(r"[a-f0-9]{32}", approval_id):
            record = request.app.state.active_change_approvals.claim(
                organization_id, approval_id, actor_id,
                kind=kind, asset_id=asset_id, operation_digest_sha256=digest,
            )
        else:
            record = request.app.state.active_change_approvals.claim_matching(
                organization_id, actor_id,
                kind=kind, asset_id=asset_id, operation_digest_sha256=digest,
            )
    except ActiveChangeApprovalError as exc:
        raise active_change_approval_http_error(exc) from exc
    return record.id


def _finish_active_change(request: Request, organization_id: str, approval_id: str | None, *, succeeded: bool) -> None:
    if approval_id is None:
        return
    try:
        request.app.state.active_change_approvals.finish(
            organization_id, approval_id, succeeded=succeeded
        )
    except ActiveChangeApprovalError as exc:
        raise active_change_approval_http_error(exc) from exc


def run_with_validated_active_responsibles(
    request: Request,
    values: list[str],
    *,
    organization_id: str,
    actor_id: str,
    operation: Callable[[list[str]], Any],
) -> Any:
    """Serialize membership validation and an Active write without leaking IDs."""

    normalized = sorted(set(values))
    settings = getattr(request.app.state, "settings", None) or load_settings()
    if get_auth_mode(settings) == "private_team_lightweight_users":
        identity_store = getattr(request.app.state, "team_identity", None)
        if not isinstance(identity_store, TeamIdentityStore):
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Identity service unavailable.")
        try:
            return identity_store.run_with_active_members(
                organization_id=organization_id,
                user_ids=normalized,
                operation=lambda: operation(normalized),
            )
        except TeamIdentityError as exc:
            if exc.code == "member_not_active":
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="Responsible accounts must be active members of the current workspace.",
                ) from exc
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Identity service unavailable.") from exc
    if not set(normalized).issubset({actor_id}):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Responsible accounts must be active members of the current workspace.",
        )
    return operation(normalized)


def active_asset_http_error(exc: ActiveAssetStoreError) -> HTTPException:
    if str(exc) == "asset_not_found":
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active asset not found.")
    if str(exc) in {"asset_expired", "asset_revoked"}:
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Active asset authorization is not current.")
    if str(exc) == "capability_not_authorized":
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Capability is not authorized for this asset.")
    if str(exc) == "authorization_revision_required":
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Active asset authorization must be re-attested before execution.",
        )
    if str(exc) == "authorization_revision_changed":
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Active asset authorization changed during admission. Review the current revision and try again.",
        )
    if str(exc) == "asset_changed":
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Active asset changed while responsibilities were being reviewed. Reload and try again.",
        )
    if str(exc) == "asset_identity_conflict":
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An Active asset with this exact identity is already registered in the current workspace.",
        )
    if str(exc) == "asset_deletion_pending":
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An Active asset deletion is still being finalized. Retry after cleanup completes.",
        )
    if str(exc) == "scope_expansion_confirmation_required":
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Expanded capability, protocol, or port scope requires a specific confirmation.",
        )
    if str(exc) == "renewal_idempotency_conflict":
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Renewal idempotency key is already bound to another authorization revision.",
        )
    if str(exc) in {"authorization_revision_capacity_reached", "history_capacity_reached"}:
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Active asset history capacity has been reached.",
        )
    if str(exc) in {"asset_store_invalid", "asset_conflict"}:
        return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Active asset registry is unavailable.")
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Active asset request could not be applied.")


def active_asset_verification_http_error(exc: ActiveAssetVerificationError) -> HTTPException:
    code = str(exc)
    if code in {"verification_not_found"}:
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active asset verification not found.")
    if code in {"asset_not_current", "verification_expired", "verification_revoked", "verification_failed", "verification_verified"}:
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Active asset verification is not pending or the authorization is no longer current.")
    if code == "verification_rate_limited":
        return HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Active asset verification challenge limit reached. Retry later.")
    if code == "verification_store_invalid":
        return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Active asset verification store is unavailable.")
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Active asset verification request could not be applied.")


def active_capability_enabled(settings, capability: str) -> bool:
    return {
        "active_nmap_basic": settings.active_nmap_basic_enabled,
        "active_dns_inventory": settings.active_dns_inventory_enabled,
        "active_dns_osint": settings.active_dns_osint_enabled,
        "active_http_basic_header_review": (
            settings.active_http_basic_header_review_enabled
            and settings.active_http_basic_header_review_live_head_enabled
        ),
        "active_tls_basic": settings.active_tls_basic_enabled,
    }.get(capability, False)


def require_legacy_active_free_target_enabled(request: Request) -> None:
    if not request.app.state.settings.active_legacy_free_targets_enabled:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Free-target Active routes are retired. Register an authorized asset and start the capability from that asset.",
        )


def active_asset_result_metadata(asset_id: str, authorization_revision_id: str) -> dict[str, object]:
    return {
        "active_asset_id": asset_id,
        "authorization_contract": ACTIVE_ASSET_CONTRACT_VERSION,
        "authorization_revision_id": authorization_revision_id,
        "authorization_revalidated": True,
        "scope": "exact_registered_asset",
        "target_expansion_allowed": False,
        "interpretation": "bounded_observation_not_confirmed_vulnerability",
    }


def active_jobs_for_asset(request: Request, asset_id: str, organization_id: str) -> list[JobRecord]:
    return request.app.state.jobs.active_asset_history(
        owner_id=organization_id, asset_id=asset_id, limit=500
    )


def active_execution_for_asset(
    request: Request, asset_id: str, organization_id: str, execution_id: str
) -> JobRecord:
    """Resolve one execution without revealing a foreign owner or asset."""

    try:
        job = request.app.state.jobs.get(execution_id)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Active execution not found.",
            ) from exc
        raise
    if job.owner_id != organization_id or job.active_asset_id != asset_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Active execution not found.",
        )
    return job


def project_summary(project: ProjectRecord, jobs: JobStore) -> ProjectSummary:
    latest_job: JobListItem | None = None
    if project.latest_job_id:
        try:
            job = jobs.get(project.latest_job_id)
        except HTTPException as exc:
            if exc.status_code != status.HTTP_404_NOT_FOUND:
                raise
        else:
            if job.owner_id == project.owner_id and job.project_id == project.id:
                latest_job = jobs.get_list_item(job.id)
    return ProjectSummary(project=project, latest_job=latest_job)


def project_analysis_availability_state(
    analysis_status: str,
) -> Literal["analysis_pending", "analysis_failed", "analysis_cancelled"]:
    """Map a non-completed job to safe, exact product availability copy."""

    if analysis_status in {"queued", "running", "cancelling"}:
        return "analysis_pending"
    if analysis_status == "cancelled":
        return "analysis_cancelled"
    return "analysis_failed"


def project_findings_response(
    request: Request,
    project: ProjectRecord,
    analysis_id: str | None,
) -> ProjectFindingsResponse:
    jobs = request.app.state.jobs
    analysis: JobRecord | None = None
    if analysis_id:
        try:
            candidate = jobs.get(analysis_id)
        except HTTPException as exc:
            if exc.status_code in {status.HTTP_400_BAD_REQUEST, status.HTTP_404_NOT_FOUND}:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found for this project.") from exc
            raise
        if candidate.project_id != project.id or candidate.owner_id != project.owner_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found for this project.")
        analysis = candidate
    else:
        analysis = jobs.latest_completed_project_job(project.id, owner_id=project.owner_id)

    empty_summary = ProjectFindingSummary(
        total=0,
        by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        by_category={},
    )


    if analysis is None:
        return ProjectFindingsResponse(project=project, state="no_completed_analysis", summary=empty_summary)

    analysis_item = jobs.get_list_item(analysis.id)
    if analysis.status != "completed":
        return ProjectFindingsResponse(
            project=project,
            analysis=analysis_item,
            state=project_analysis_availability_state(analysis.status),
            summary=empty_summary,
        )

    coverage = build_project_analysis_coverage(analysis)
    findings = normalized_findings_for_analysis(analysis)
    if findings is None:
        return ProjectFindingsResponse(
            project=project,
            analysis=analysis_item,
            state="no_normalized_findings",
            summary=empty_summary,
            coverage=coverage,
        )

    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_category: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] += 1
        by_category[finding.category] = by_category.get(finding.category, 0) + 1
    lifecycle = finding_lifecycle_for_project(request, project, findings)
    by_status = {item: 0 for item in ("open", "in_review", "accepted", "false_positive", "resolved")}
    for item in lifecycle.values():
        by_status[item.current_status] += 1
    result = analysis.result if isinstance(analysis.result, dict) else {}
    result_summary = result.get("summary")
    result_truncated = bool(result_summary.get("truncated")) if isinstance(result_summary, dict) else False
    return ProjectFindingsResponse(
        project=project,
        analysis=analysis_item,
        state="ready",
        findings=findings,
        summary=ProjectFindingSummary(
            total=len(findings),
            by_severity=by_severity,
            by_category=dict(sorted(by_category.items())),
            by_status=by_status,
            needs_review=sum(item.needs_review for item in lifecycle.values()),
        ),
        result_truncated=result_truncated,
        coverage=coverage,
        lifecycle=lifecycle,
    )


def project_component_inventory_response(
    request: Request,
    project: ProjectRecord,
    analysis_id: str | None,
) -> ProjectComponentInventoryResponse:
    """Return only the persisted, safe component inventory for one project analysis."""

    jobs = request.app.state.jobs
    analysis: JobRecord | None = None
    if analysis_id:
        analysis = project_analysis_for_project(request, project, analysis_id)
    else:
        analysis = jobs.latest_completed_project_job(project.id, owner_id=project.owner_id)

    empty_summary = ProjectComponentInventorySummary(
        total_components=0,
        exact_registry_components=0,
        declared_range_components=0,
        not_correlatable_components=0,
        parsed_manifest_count=0,
        supported_manifest_count=0,
        skipped_manifest_count=0,
        result_truncated=False,
        resolution="declared_only",
    )
    if analysis is None:
        return ProjectComponentInventoryResponse(project=project, state="no_completed_analysis", summary=empty_summary)

    analysis_item = jobs.get_list_item(analysis.id)
    if analysis.status != "completed":
        return ProjectComponentInventoryResponse(
            project=project,
            analysis=analysis_item,
            state=project_analysis_availability_state(analysis.status),
            summary=empty_summary,
        )

    result = analysis.result if isinstance(analysis.result, dict) else {}
    raw_components = result.get("component_inventory")
    raw_summary = result.get("component_inventory_summary")
    contract_version = result.get("component_inventory_contract_version")
    if not isinstance(raw_components, list) or not isinstance(raw_summary, dict) or not isinstance(contract_version, str):
        return ProjectComponentInventoryResponse(
            project=project,
            analysis=analysis_item,
            state="no_component_inventory",
            summary=empty_summary,
        )

    components: list[ProjectComponent] = []
    seen_ids: set[str] = set()
    for raw_component in raw_components:
        if not isinstance(raw_component, dict):
            continue
        try:
            component = ProjectComponent.model_validate(raw_component)
        except ValidationError:
            continue
        safe_path = normalize_project_relative_path(component.manifest_path) if component.manifest_path else None
        if component.manifest_path and safe_path is None:
            component = component.model_copy(update={"manifest_path": None, "manifest_path_status": "withheld_unsafe_path"})
        elif safe_path:
            component = component.model_copy(update={"manifest_path": safe_path, "manifest_path_status": "reported"})
        if component.id in seen_ids:
            continue
        seen_ids.add(component.id)
        components.append(component)
    try:
        summary = ProjectComponentInventorySummary.model_validate(raw_summary)
    except ValidationError:
        return ProjectComponentInventoryResponse(
            project=project,
            analysis=analysis_item,
            state="no_component_inventory",
            summary=empty_summary,
        )
    coverage_matrix: list[ProjectComponentCoverage] = []
    raw_coverage_matrix = result.get("component_coverage_matrix")
    for raw_entry in raw_coverage_matrix if isinstance(raw_coverage_matrix, list) else []:
        try:
            coverage_matrix.append(ProjectComponentCoverage.model_validate(raw_entry))
        except ValidationError:
            continue
    if not coverage_matrix:
        for raw_entry in build_component_coverage_matrix(result, [component.model_dump() for component in components]):
            try:
                coverage_matrix.append(ProjectComponentCoverage.model_validate(raw_entry))
            except ValidationError:  # pragma: no cover - generated table remains defensive.
                continue
    dependency_graph = None
    raw_dependency_graph = result.get("dependency_graph_evidence")
    if isinstance(raw_dependency_graph, dict):
        try:
            dependency_graph = ProjectDependencyGraphEvidence.model_validate(raw_dependency_graph)
        except ValidationError:
            # Legacy or damaged optional evidence must not make the otherwise
            # valid retained inventory unreadable.
            dependency_graph = None
    cargo_dependency_graph = None
    raw_cargo_dependency_graph = result.get("cargo_dependency_graph_evidence")
    if isinstance(raw_cargo_dependency_graph, dict):
        try:
            cargo_dependency_graph = CargoProjectDependencyGraphEvidence.model_validate(raw_cargo_dependency_graph)
        except ValidationError:
            cargo_dependency_graph = None
    composer_dependency_graph = None
    raw_composer_dependency_graph = result.get("composer_dependency_graph_evidence")
    if isinstance(raw_composer_dependency_graph, dict):
        try:
            composer_dependency_graph = ComposerProjectDependencyGraphEvidence.model_validate(raw_composer_dependency_graph)
        except ValidationError:
            composer_dependency_graph = None
    gradle_dependency_graph = None
    raw_gradle_dependency_graph = result.get("gradle_dependency_graph_evidence")
    if isinstance(raw_gradle_dependency_graph, dict):
        try:
            gradle_dependency_graph = GradleProjectDependencyGraphEvidence.model_validate(raw_gradle_dependency_graph)
        except ValidationError:
            gradle_dependency_graph = None
    nuget_dependency_graph = None
    raw_nuget_dependency_graph = result.get("nuget_dependency_graph_evidence")
    if isinstance(raw_nuget_dependency_graph, dict):
        try:
            nuget_dependency_graph = NugetProjectDependencyGraphEvidence.model_validate(raw_nuget_dependency_graph)
        except ValidationError:
            nuget_dependency_graph = None
    return ProjectComponentInventoryResponse(
        project=project,
        analysis=analysis_item,
        state="ready",
        contract_version=contract_version,
        components=components,
        summary=summary,
        coverage_matrix=coverage_matrix,
        dependency_graph=dependency_graph,
        cargo_dependency_graph=cargo_dependency_graph,
        composer_dependency_graph=composer_dependency_graph,
        gradle_dependency_graph=gradle_dependency_graph,
        nuget_dependency_graph=nuget_dependency_graph,
    )


def _empty_project_vulnerability_summary() -> ProjectVulnerabilityIntelligenceSummary:
    return ProjectVulnerabilityIntelligenceSummary(
        inventory_components=0,
        correlation_eligible_components=0,
        queryable_components=0,
        queried_components=0,
        findings=0,
        fixed_version_available=0,
        excluded_components=0,
        unverified_advisories=0,
        withdrawn_advisories=0,
        failed_batches=0,
        fresh_cache_batches=0,
        stale_cache_batches=0,
    )


def project_vulnerability_intelligence_response(
    request: Request,
    project: ProjectRecord,
    analysis_id: str | None,
    *,
    snapshot_id: str | None = None,
) -> ProjectVulnerabilityIntelligenceResponse:
    """Read a separate, safe OSV snapshot for one owner-scoped analysis."""

    jobs = request.app.state.jobs
    analysis: JobRecord | None = None
    if analysis_id:
        analysis = project_analysis_for_project(request, project, analysis_id)
    else:
        analysis = jobs.latest_completed_project_job(project.id, owner_id=project.owner_id)

    settings = request.app.state.settings
    egress_client = request.app.state.public_advisory_egress_client
    offline_snapshot_id = egress_client.active_offline_snapshot_id()
    nvd_available = settings.public_advisory_nvd_enabled or egress_client.has_active_offline_provider("nvd")
    empty_summary = _empty_project_vulnerability_summary()
    if analysis is None:
        return ProjectVulnerabilityIntelligenceResponse(
            project=project,
            state="no_completed_analysis",
            egress_enabled=settings.public_advisory_egress_enabled,
            nvd_enabled=nvd_available,
            offline_snapshot_id=offline_snapshot_id,
            summary=empty_summary,
        )
    analysis_item = jobs.get_list_item(analysis.id)
    if analysis.status != "completed":
        return ProjectVulnerabilityIntelligenceResponse(
            project=project,
            analysis=analysis_item,
            state=project_analysis_availability_state(analysis.status),
            egress_enabled=settings.public_advisory_egress_enabled,
            nvd_enabled=nvd_available,
            offline_snapshot_id=offline_snapshot_id,
            summary=empty_summary,
        )
    source_result = analysis.result if isinstance(analysis.result, dict) else {}
    if not isinstance(source_result.get("component_inventory"), list):
        return ProjectVulnerabilityIntelligenceResponse(
            project=project,
            analysis=analysis_item,
            state="no_component_inventory",
            egress_enabled=settings.public_advisory_egress_enabled,
            nvd_enabled=nvd_available,
            offline_snapshot_id=offline_snapshot_id,
            summary=empty_summary,
        )
    store = request.app.state.project_vulnerability_intelligence_store
    try:
        latest_snapshot = store.get(analysis.id)
        snapshot = store.get(analysis.id, snapshot_id=snapshot_id) if snapshot_id is not None else latest_snapshot
        snapshot_history = store.list_history(analysis.id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability intelligence snapshot not found for this analysis.") from None
    if snapshot_id is not None and snapshot is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability intelligence snapshot not found for this analysis.")
    if snapshot is None:
        return ProjectVulnerabilityIntelligenceResponse(
            project=project,
            analysis=analysis_item,
            state="not_requested",
            egress_enabled=settings.public_advisory_egress_enabled,
            nvd_enabled=nvd_available,
            offline_snapshot_id=offline_snapshot_id,
            summary=empty_summary,
        )
    try:
        # Snapshots written before source freshness reasons were introduced
        # remain readable. This migration is in-memory: it neither trusts nor
        # exposes upstream diagnostics, and a later safe update rewrites it.
        snapshot = _public_vulnerability_snapshot_with_source_reasons(snapshot)
        latest_snapshot_id = latest_snapshot.get("snapshot_id") if isinstance(latest_snapshot, dict) else None
        selected_snapshot_id = snapshot.get("snapshot_id") if isinstance(snapshot.get("snapshot_id"), str) else None
        return ProjectVulnerabilityIntelligenceResponse.model_validate(
            {
                "project": project,
                "analysis": analysis_item,
                "egress_enabled": settings.public_advisory_egress_enabled,
                "nvd_enabled": nvd_available,
                "snapshot_id": selected_snapshot_id,
                "snapshot_recorded_at": snapshot.get("snapshot_recorded_at"),
                "latest_snapshot_id": latest_snapshot_id,
                "is_latest_snapshot": snapshot_id is None or selected_snapshot_id == latest_snapshot_id,
                "snapshot_history": snapshot_history,
                **snapshot,
            }
        )
    except ValidationError:
        return ProjectVulnerabilityIntelligenceResponse(
            project=project,
            analysis=analysis_item,
            state="degraded",
            egress_enabled=settings.public_advisory_egress_enabled,
            nvd_enabled=nvd_available,
            offline_snapshot_id=offline_snapshot_id,
            summary=empty_summary,
            errors=["stored_intelligence_invalid"],
        )


def _public_vulnerability_snapshot_with_source_reasons(snapshot: dict[str, Any]) -> dict[str, Any]:
    result = with_public_vulnerability_field_provenance(snapshot)
    sources = snapshot.get("sources")
    if not isinstance(sources, list):
        return result
    reasons = {
        "fresh": "network_refreshed",
        "stale": "stale_cache_fallback",
        "unavailable": "provider_unavailable",
        "not_requested": "not_requested",
    }
    result["sources"] = [
        {
            **source,
            "reason": source.get("reason")
            if source.get("reason") in {
                "not_requested",
                "network_refreshed",
                "fresh_cache",
                "stale_cache_fallback",
                "provider_unavailable",
                "provider_circuit_open",
                "provider_catalog_stale",
                "invalid_source_data",
            }
            else reasons.get(source.get("state"), "provider_unavailable"),
        }
        if isinstance(source, dict)
        else source
        for source in sources
    ]
    return result


def normalized_findings_for_analysis(analysis: JobRecord) -> list[NormalizedFinding] | None:
    """Read only the persisted, redacted normalized contract from one analysis."""

    result = analysis.result if isinstance(analysis.result, dict) else {}
    raw_findings = result.get("normalized_findings")
    if not isinstance(raw_findings, list):
        return None
    findings: list[NormalizedFinding] = []
    seen_ids: set[str] = set()
    for raw_finding in raw_findings:
        if not isinstance(raw_finding, dict):
            continue
        try:
            finding = safe_normalized_finding(NormalizedFinding.model_validate(raw_finding))
        except ValidationError:
            continue
        if finding.id in seen_ids:
            continue
        seen_ids.add(finding.id)
        findings.append(finding)
    return findings


def safe_normalized_finding(finding: NormalizedFinding) -> NormalizedFinding:
    """Apply the current location policy to persisted legacy contracts too."""

    if finding.location_status == "withheld_unsafe_path":
        return finding.model_copy(update={"location": None})
    location = finding.location
    raw_path = location.path if location else None
    safe_path = normalize_project_relative_path(raw_path) if raw_path else None
    if raw_path and safe_path is None:
        return finding.model_copy(update={"location": None, "location_status": "withheld_unsafe_path"})
    if safe_path:
        safe_location = FindingLocation(path=safe_path, line=location.line if location else None)
        return finding.model_copy(update={"location": safe_location, "location_status": "reported"})
    if location and location.line:
        return finding.model_copy(update={"location_status": "reported"})
    return finding.model_copy(update={"location": None, "location_status": "not_reported"})


def project_analysis_for_project(request: Request, project: ProjectRecord, analysis_id: str) -> JobRecord:
    """Resolve an analysis without turning IDs from another project into an oracle."""

    try:
        candidate = request.app.state.jobs.get(analysis_id)
    except HTTPException as exc:
        if exc.status_code in {status.HTTP_400_BAD_REQUEST, status.HTTP_404_NOT_FOUND}:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found for this project.") from exc
        raise
    if candidate.project_id != project.id or candidate.owner_id != project.owner_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found for this project.")
    return candidate


def comparison_limitations(base: JobRecord, target: JobRecord) -> list[str]:
    limitations: list[str] = []
    profile_limitation = execution_profile_comparison_limitation(base.execution_profile, target.execution_profile)
    if profile_limitation:
        limitations.append(profile_limitation)
    for analysis in (base, target):
        result = analysis.result if isinstance(analysis.result, dict) else {}
        summary = result.get("summary")
        if isinstance(summary, dict) and summary.get("truncated"):
            limitations.append("At least one selected analysis reached a configured limit; comparison counts may be incomplete.")
            break
    if base.source_file_deleted_at is not None or target.source_file_deleted_at is not None:
        limitations.append("At least one source archive is no longer retained; this comparison uses retained redacted results only.")
    return limitations


def coverage_comparison_limitation(coverage_comparison: ProjectAnalysisCoverageComparison) -> str:
    if coverage_comparison.status == "unknown":
        return "One or both selected analyses have no recorded coverage summary; findings cannot be classified as resolved or new."
    return "The selected analyses have different recorded coverage or analysis limits; findings cannot be classified as resolved or new."


def changed_finding_fields(base: NormalizedFinding, target: NormalizedFinding) -> list[str]:
    fields = (
        "severity",
        "confidence",
        "title",
        "category",
        "description",
        "evidence",
        "location",
        "recommendation",
        "references",
    )
    return [field for field in fields if getattr(base, field) != getattr(target, field)]


_PUBLIC_VULNERABILITY_SNAPSHOT_ID = re.compile(r"^[a-f0-9]{32}$")


def _empty_public_vulnerability_comparison_summary() -> ProjectPublicVulnerabilityComparisonSummary:
    return ProjectPublicVulnerabilityComparisonSummary(new=0, resolved=0, persistent=0)


def _safe_public_vulnerability_snapshot_id(snapshot: dict[str, Any] | None) -> str | None:
    if not isinstance(snapshot, dict):
        return None
    value = snapshot.get("snapshot_id")
    return value if isinstance(value, str) and _PUBLIC_VULNERABILITY_SNAPSHOT_ID.fullmatch(value) else None


def _public_vulnerability_snapshot_freshness_reason(snapshot: dict[str, Any], *, analysis_label: str) -> str | None:
    """Return a controlled reason when a retained OSV snapshot is not comparable.

    This intentionally consumes only the normalized snapshot state and source
    freshness.  It must not surface a provider diagnostic, a project locator,
    or any other persisted untrusted value in the comparison API.
    """

    state = snapshot.get("state")
    if state == "stale":
        return f"The {analysis_label} OSV snapshot is stale, so public advisories are not classified as resolved or new."
    if state == "degraded":
        return f"The {analysis_label} OSV snapshot is degraded, so public advisories are not classified as resolved or new."
    if state != "ready":
        return f"The {analysis_label} OSV snapshot is not a complete fresh result, so public advisories are not classified as resolved or new."
    sources = snapshot.get("sources")
    if not isinstance(sources, list):
        return f"The {analysis_label} OSV snapshot has no retained source freshness, so public advisories are not classified as resolved or new."
    for source in sources:
        if isinstance(source, dict) and source.get("provider") == "osv":
            if source.get("state") == "fresh":
                return None
            return f"The {analysis_label} OSV source is not fresh, so public advisories are not classified as resolved or new."
    return f"The {analysis_label} OSV source freshness is unavailable, so public advisories are not classified as resolved or new."


def _validated_public_vulnerability_findings(snapshot: dict[str, Any]) -> list[ProjectVulnerabilityFinding] | None:
    raw_findings = snapshot.get("findings")
    if not isinstance(raw_findings, list):
        return None
    findings: list[ProjectVulnerabilityFinding] = []
    seen_ids: set[str] = set()
    for raw_finding in raw_findings:
        try:
            finding = ProjectVulnerabilityFinding.model_validate(raw_finding)
        except ValidationError:
            return None
        if finding.fingerprint_version != PUBLIC_VULNERABILITY_FINDING_FINGERPRINT_VERSION or finding.id in seen_ids:
            return None
        seen_ids.add(finding.id)
        findings.append(finding)
    return findings


def changed_public_vulnerability_finding_fields(
    base: ProjectVulnerabilityFinding,
    target: ProjectVulnerabilityFinding,
) -> list[str]:
    """Expose only changed, normalized advisory properties for a stable ID."""

    fields = (
        "dependency_scope",
        "relationship_status",
        "fixed_versions",
        "severity",
        "cvss_base_score",
        "cvss_band",
        "cvss_score_status",
        "corroborations",
        "nvd_evidence",
        "source_consensus",
        "source_conflicts",
        "kev_signals",
        "vendor_bulletins",
        "references",
        "published_at",
        "updated_at",
        "recommendation",
    )
    return [field for field in fields if getattr(base, field) != getattr(target, field)]


def project_public_vulnerability_comparison(
    request: Request,
    base: JobRecord,
    target: JobRecord,
    *,
    analysis_comparable: bool,
) -> ProjectPublicVulnerabilityComparison:
    """Compare two independently retained public-advisory snapshots safely.

    Public intelligence is intentionally not copied into normalized local
    findings.  This keeps its provider freshness and evidence provenance
    visible rather than allowing an absent or stale provider response to be
    mistaken for a remediation in the generic findings comparison.
    """

    summary = _empty_public_vulnerability_comparison_summary()
    store = request.app.state.project_vulnerability_intelligence_store
    base_snapshot = store.get(base.id)
    target_snapshot = store.get(target.id)
    base_snapshot_id = _safe_public_vulnerability_snapshot_id(base_snapshot)
    target_snapshot_id = _safe_public_vulnerability_snapshot_id(target_snapshot)

    if not isinstance(base_snapshot, dict) or not isinstance(target_snapshot, dict):
        missing: list[str] = []
        if not isinstance(base_snapshot, dict):
            missing.append("baseline")
        if not isinstance(target_snapshot, dict):
            missing.append("comparison")
        return ProjectPublicVulnerabilityComparison(
            state="not_available",
            base_snapshot_id=base_snapshot_id,
            target_snapshot_id=target_snapshot_id,
            summary=summary,
            limitations=[f"No retained OSV snapshot is available for the {' and '.join(missing)} analysis."],
        )

    if not analysis_comparable:
        return ProjectPublicVulnerabilityComparison(
            state="not_comparable",
            base_snapshot_id=base_snapshot_id,
            target_snapshot_id=target_snapshot_id,
            summary=summary,
            limitations=["The selected analyses are not comparable under their recorded analyzer or coverage profile, so public advisories are not classified as resolved or new."],
        )

    freshness_limitations = [
        reason
        for reason in (
            _public_vulnerability_snapshot_freshness_reason(base_snapshot, analysis_label="baseline"),
            _public_vulnerability_snapshot_freshness_reason(target_snapshot, analysis_label="comparison"),
        )
        if reason is not None
    ]
    if freshness_limitations:
        return ProjectPublicVulnerabilityComparison(
            state="not_comparable",
            base_snapshot_id=base_snapshot_id,
            target_snapshot_id=target_snapshot_id,
            summary=summary,
            limitations=freshness_limitations,
        )

    base_findings = _validated_public_vulnerability_findings(base_snapshot)
    target_findings = _validated_public_vulnerability_findings(target_snapshot)
    if base_findings is None or target_findings is None:
        return ProjectPublicVulnerabilityComparison(
            state="not_available",
            base_snapshot_id=base_snapshot_id,
            target_snapshot_id=target_snapshot_id,
            summary=summary,
            limitations=["One or both retained OSV snapshots use an invalid or legacy public-finding identity and cannot be compared safely."],
        )

    base_by_id = {finding.id: finding for finding in base_findings}
    target_by_id = {finding.id: finding for finding in target_findings}
    comparisons: list[ProjectPublicVulnerabilityFindingComparison] = []
    for finding in target_findings:
        previous = base_by_id.get(finding.id)
        comparisons.append(
            ProjectPublicVulnerabilityFindingComparison(
                status="persistent" if previous else "new",
                finding=finding,
                previous_finding=previous,
                changed_fields=changed_public_vulnerability_finding_fields(previous, finding) if previous else [],
            )
        )
    for finding in base_findings:
        if finding.id not in target_by_id:
            comparisons.append(ProjectPublicVulnerabilityFindingComparison(status="resolved", finding=finding))

    return ProjectPublicVulnerabilityComparison(
        state="ready",
        base_snapshot_id=base_snapshot_id,
        target_snapshot_id=target_snapshot_id,
        summary=ProjectPublicVulnerabilityComparisonSummary(
            new=sum(comparison.status == "new" for comparison in comparisons),
            resolved=sum(comparison.status == "resolved" for comparison in comparisons),
            persistent=sum(comparison.status == "persistent" for comparison in comparisons),
        ),
        comparisons=comparisons,
    )


def project_analysis_comparison_response(
    request: Request,
    project: ProjectRecord,
    base_analysis_id: str,
    target_analysis_id: str,
) -> ProjectAnalysisComparisonResponse:
    if base_analysis_id == target_analysis_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Select two distinct project analyses to compare.")

    base = project_analysis_for_project(request, project, base_analysis_id)
    target = project_analysis_for_project(request, project, target_analysis_id)
    base_item = request.app.state.jobs.get_list_item(base.id)
    target_item = request.app.state.jobs.get_list_item(target.id)
    empty_summary = ProjectComparisonSummary(new=0, resolved=0, persistent=0)
    uses_saved_baseline = project.baseline_analysis_id == base.id

    if base.status != "completed" or target.status != "completed":
        return ProjectAnalysisComparisonResponse(
            project=project,
            base_analysis=base_item,
            target_analysis=target_item,
            state="analysis_pending",
            summary=empty_summary,
            limitations=["Both selected analyses must be completed before their findings can be compared."],
            uses_saved_baseline=uses_saved_baseline,
        )

    coverage_comparison = compare_project_analysis_coverage(base, target)
    analysis_profiles_compatible = (
        base.audit_type == target.audit_type
        and base.analysis_profile == target.analysis_profile
        and execution_profiles_are_compatible(base.execution_profile, target.execution_profile)
    )
    coverage_equivalent = coverage_comparison is None or coverage_comparison.status == "equivalent"
    public_vulnerability_comparison = project_public_vulnerability_comparison(
        request,
        base,
        target,
        analysis_comparable=analysis_profiles_compatible and coverage_equivalent,
    )

    if not analysis_profiles_compatible:
        limitations = comparison_limitations(base, target)
        if base.audit_type != target.audit_type or base.analysis_profile != target.analysis_profile:
            limitations.insert(0, "The selected analyses use different analyzer types or analysis profiles and are not comparable.")
        return ProjectAnalysisComparisonResponse(
            project=project,
            base_analysis=base_item,
            target_analysis=target_item,
            state="not_comparable",
            summary=empty_summary,
            limitations=limitations,
            uses_saved_baseline=uses_saved_baseline,
            coverage_comparison=coverage_comparison,
            public_vulnerability_comparison=public_vulnerability_comparison,
        )

    if coverage_comparison is not None and coverage_comparison.status != "equivalent":
        limitations = comparison_limitations(base, target)
        limitations.insert(0, coverage_comparison_limitation(coverage_comparison))
        return ProjectAnalysisComparisonResponse(
            project=project,
            base_analysis=base_item,
            target_analysis=target_item,
            state="not_comparable",
            summary=empty_summary,
            limitations=limitations,
            uses_saved_baseline=uses_saved_baseline,
            coverage_comparison=coverage_comparison,
            public_vulnerability_comparison=public_vulnerability_comparison,
        )

    base_findings = normalized_findings_for_analysis(base)
    target_findings = normalized_findings_for_analysis(target)
    if base_findings is None or target_findings is None:
        limitations = comparison_limitations(base, target)
        limitations.insert(0, "One or both selected analyses have no compatible normalized findings for comparison.")
        return ProjectAnalysisComparisonResponse(
            project=project,
            base_analysis=base_item,
            target_analysis=target_item,
            state="no_normalized_findings",
            summary=empty_summary,
            limitations=limitations,
            uses_saved_baseline=uses_saved_baseline,
            coverage_comparison=coverage_comparison,
            public_vulnerability_comparison=public_vulnerability_comparison,
        )

    base_by_id = {finding.id: finding for finding in base_findings}
    target_by_id = {finding.id: finding for finding in target_findings}
    lifecycle = finding_lifecycle_for_project(
        request,
        project,
        list({finding.id: finding for finding in [*base_findings, *target_findings]}.values()),
    )
    comparisons: list[ProjectFindingComparison] = []
    for finding in target_findings:
        previous = base_by_id.get(finding.id)
        comparisons.append(
            ProjectFindingComparison(
                status="persistent" if previous else "new",
                finding=finding,
                previous_finding=previous,
                changed_fields=changed_finding_fields(previous, finding) if previous else [],
                lifecycle=lifecycle.get(finding.id),
            )
        )
    for finding in base_findings:
        if finding.id not in target_by_id:
            comparisons.append(
                ProjectFindingComparison(
                    status="resolved",
                    finding=finding,
                    lifecycle=lifecycle.get(finding.id),
                )
            )

    return ProjectAnalysisComparisonResponse(
        project=project,
        base_analysis=base_item,
        target_analysis=target_item,
        state="ready",
        summary=ProjectComparisonSummary(
            new=sum(comparison.status == "new" for comparison in comparisons),
            resolved=sum(comparison.status == "resolved" for comparison in comparisons),
            persistent=sum(comparison.status == "persistent" for comparison in comparisons),
        ),
        comparisons=comparisons,
        limitations=comparison_limitations(base, target),
        uses_saved_baseline=uses_saved_baseline,
        coverage_comparison=coverage_comparison,
        public_vulnerability_comparison=public_vulnerability_comparison,
    )


def source_for_project_analysis(request: Request, project: ProjectRecord) -> StoredFile:
    missing_source_detail = (
        "Project source is no longer retained. Import a new SBOM snapshot to run another analysis."
        if project.source_filename == "sbom.json"
        else "Project source is no longer retained. Upload a new archive snapshot to run another analysis."
    )
    if project.source_file_deleted_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=missing_source_detail,
        )
    try:
        source = get_file_for_current_owner(request, project.source_file_id)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            request.app.state.projects.mark_source_file_deleted(project.source_file_id, owner_id=project.owner_id)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=missing_source_detail,
            ) from exc
        raise
    is_supported_source = source.kind == "archive" or (
        source.kind == "manifest" and source.original_filename == "sbom.json"
    )
    if not is_supported_source or source.sha256 != project.source_sha256:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Project source no longer matches its recorded snapshot.")
    return source


ACTIVE_NMAP_BASIC_MODE = "live_nmap_basic"
ACTIVE_NMAP_BASIC_PROFILE = "tcp_connect_small"
ACTIVE_NMAP_BASIC_MAX_PORTS_PER_TARGET = 32
ACTIVE_NMAP_BASIC_MAX_TOTAL_TARGET_PORT_CHECKS = 96
ACTIVE_NMAP_BASIC_ALLOWED_FIELDS = frozenset(
    {
        "mode",
        "profile",
        "targets",
        "ports",
        "authorization_confirmed",
        "local_private_scope_confirmed",
        "live_traffic_confirmed",
    }
)
ACTIVE_NMAP_BASIC_CONFIRMATION_FIELDS = (
    "authorization_confirmed",
    "local_private_scope_confirmed",
    "live_traffic_confirmed",
)
ACTIVE_NMAP_BASIC_CONTRACT_LIMITS = {
    "max_targets": ACTIVE_NMAP_BASIC_MAX_TARGETS,
    "max_ports_per_target": ACTIVE_NMAP_BASIC_MAX_PORTS_PER_TARGET,
    "max_total_target_port_checks": ACTIVE_NMAP_BASIC_MAX_TOTAL_TARGET_PORT_CHECKS,
}


def validate_active_nmap_basic_contract(payload: Any) -> dict[str, int]:
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_nmap_basic request body must be a JSON object.",
        )

    fields = set(payload)
    if fields - ACTIVE_NMAP_BASIC_ALLOWED_FIELDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported active_nmap_basic request field.",
        )
    if ACTIVE_NMAP_BASIC_ALLOWED_FIELDS - fields:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_nmap_basic request is missing required fields.",
        )

    if payload.get("mode") != ACTIVE_NMAP_BASIC_MODE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_nmap_basic mode must be live_nmap_basic.",
        )
    if payload.get("profile") != ACTIVE_NMAP_BASIC_PROFILE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_nmap_basic profile must be tcp_connect_small.",
        )

    for field_name in ACTIVE_NMAP_BASIC_CONFIRMATION_FIELDS:
        if payload.get(field_name) is not True:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{field_name} must be true.")

    targets = payload.get("targets")
    target_policy = validate_active_nmap_basic_target_policy(targets)

    ports = payload.get("ports")
    if not isinstance(ports, list) or not ports:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_nmap_basic ports must be a non-empty list.",
        )
    if len(ports) > ACTIVE_NMAP_BASIC_MAX_PORTS_PER_TARGET:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_nmap_basic port count exceeds the allowed limit.",
        )
    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="active_nmap_basic ports must be integer TCP ports.",
            )
        if port < 1 or port > 65535:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="active_nmap_basic ports must be between 1 and 65535.",
            )

    total_checks = target_policy.target_count * len(ports)
    if total_checks > ACTIVE_NMAP_BASIC_MAX_TOTAL_TARGET_PORT_CHECKS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_nmap_basic target-port count exceeds the allowed limit.",
        )

    return {"target_count": target_policy.target_count, "port_count": len(ports), "target_port_checks": total_checks}


def validate_active_nmap_basic_target_policy(targets: object) -> ActiveNmapTargetPolicyResult:
    try:
        return validate_active_nmap_basic_targets(targets)
    except ActiveNmapTargetPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"active_nmap_basic target policy rejected the request: {exc.reason_code}.",
        ) from exc


ACTIVE_TLS_BASIC_MODE = "live_tls_basic"
ACTIVE_TLS_BASIC_PROFILE = "tls_handshake_summary"
ACTIVE_TLS_BASIC_ALLOWED_PORTS = frozenset({443, 8443, 9443})
ACTIVE_TLS_BASIC_ALLOWED_FIELDS = frozenset(
    {
        "mode",
        "profile",
        "target",
        "port",
        "authorization_confirmed",
        "local_private_scope_confirmed",
        "live_traffic_confirmed",
    }
)
ACTIVE_TLS_BASIC_CONFIRMATION_FIELDS = (
    "authorization_confirmed",
    "local_private_scope_confirmed",
    "live_traffic_confirmed",
)
ACTIVE_TLS_BASIC_CONTRACT_LIMITS = {
    "max_targets": 1,
    "max_ports": 1,
    "allowed_ports": sorted(ACTIVE_TLS_BASIC_ALLOWED_PORTS),
    "handshake_timeout_seconds": int(ACTIVE_TLS_BASIC_DEFAULT_TIMEOUT_SECONDS),
}


def validate_active_tls_basic_contract(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_tls_basic request body must be a JSON object.",
        )

    fields = set(payload)
    if fields - ACTIVE_TLS_BASIC_ALLOWED_FIELDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported active_tls_basic request field.",
        )
    if ACTIVE_TLS_BASIC_ALLOWED_FIELDS - fields:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_tls_basic request is missing required fields.",
        )

    if payload.get("mode") != ACTIVE_TLS_BASIC_MODE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_tls_basic mode must be live_tls_basic.",
        )
    if payload.get("profile") != ACTIVE_TLS_BASIC_PROFILE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_tls_basic profile must be tls_handshake_summary.",
        )

    for field_name in ACTIVE_TLS_BASIC_CONFIRMATION_FIELDS:
        if payload.get(field_name) is not True:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{field_name} must be true.")

    target = payload.get("target")
    if not isinstance(target, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_tls_basic target must be a single explicit string.",
        )
    try:
        target_policy = validate_active_nmap_basic_targets([target])
    except ActiveNmapTargetPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"active_tls_basic target policy rejected the request: {exc.reason_code}.",
        ) from exc

    port = payload.get("port")
    if isinstance(port, bool) or not isinstance(port, int):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_tls_basic port must be an integer TCP port.",
        )
    if port < 1 or port > 65535:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_tls_basic port must be between 1 and 65535.",
        )
    if port not in ACTIVE_TLS_BASIC_ALLOWED_PORTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_tls_basic port is outside the allowed TLS basic port set.",
        )

    return {
        "target_count": target_policy.target_count,
        "target": target_policy.normalized_targets[0],
        "port": port,
    }


ACTIVE_DNS_INVENTORY_MODE = "live_dns_inventory"
ACTIVE_DNS_INVENTORY_PROFILE = "dns_inventory_authorized"
ACTIVE_DNS_INVENTORY_ALLOWED_FIELDS = frozenset(
    {
        "mode",
        "profile",
        "domain",
        "record_types",
        "include_security_records",
        "include_subdomain_discovery",
        "attempt_zone_transfer",
        "zone_transfer_authorized_confirmed",
        "authorization_confirmed",
        "local_private_or_owned_scope_confirmed",
        "live_dns_queries_confirmed",
    }
)
ACTIVE_DNS_INVENTORY_REQUIRED_FIELDS = ACTIVE_DNS_INVENTORY_ALLOWED_FIELDS - {
    "attempt_zone_transfer",
    "zone_transfer_authorized_confirmed",
}
ACTIVE_DNS_INVENTORY_CONFIRMATION_FIELDS = (
    "authorization_confirmed",
    "local_private_or_owned_scope_confirmed",
    "live_dns_queries_confirmed",
)
ACTIVE_DNS_INVENTORY_CONTRACT_LIMITS = {
    "max_domains": 1,
    "allowed_record_types": sorted(ACTIVE_DNS_INVENTORY_ALLOWED_RECORD_TYPES),
    "dns_queries_sent": 0,
    "subdomain_queries_sent": 0,
}


def validate_active_dns_inventory_contract(payload: Any) -> ActiveDnsInventoryContract:
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_dns_inventory request body must be a JSON object.",
        )

    fields = set(payload)
    if fields - ACTIVE_DNS_INVENTORY_ALLOWED_FIELDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported active_dns_inventory request field.",
        )
    if ACTIVE_DNS_INVENTORY_REQUIRED_FIELDS - fields:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_dns_inventory request is missing required fields.",
        )

    if payload.get("mode") != ACTIVE_DNS_INVENTORY_MODE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_dns_inventory mode must be live_dns_inventory.",
        )
    if payload.get("profile") != ACTIVE_DNS_INVENTORY_PROFILE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_dns_inventory profile must be dns_inventory_authorized.",
        )

    for field_name in ACTIVE_DNS_INVENTORY_CONFIRMATION_FIELDS:
        if payload.get(field_name) is not True:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{field_name} must be true.")

    include_security_records = payload.get("include_security_records")
    if not isinstance(include_security_records, bool):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_dns_inventory include_security_records must be boolean.",
        )
    include_subdomain_discovery = payload.get("include_subdomain_discovery")
    if not isinstance(include_subdomain_discovery, bool):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_dns_inventory include_subdomain_discovery must be boolean.",
        )
    attempt_zone_transfer = payload.get("attempt_zone_transfer", False)
    if not isinstance(attempt_zone_transfer, bool):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_dns_inventory attempt_zone_transfer must be boolean.",
        )
    zone_transfer_authorized_confirmed = payload.get("zone_transfer_authorized_confirmed", False)
    if not isinstance(zone_transfer_authorized_confirmed, bool):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_dns_inventory zone_transfer_authorized_confirmed must be boolean.",
        )
    if attempt_zone_transfer is True and zone_transfer_authorized_confirmed is not True:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="zone_transfer_authorized_confirmed must be true.",
        )

    try:
        domain = normalize_active_dns_inventory_domain(payload.get("domain"))
        record_types = normalize_active_dns_inventory_record_types(payload.get("record_types"))
    except ActiveDnsInventoryPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"active_dns_inventory policy rejected the request: {exc.reason_code}.",
        ) from exc

    return ActiveDnsInventoryContract(
        domain=domain,
        record_types=record_types,
        include_security_records=include_security_records,
        include_subdomain_discovery=include_subdomain_discovery,
        attempt_zone_transfer=attempt_zone_transfer,
        zone_transfer_authorized_confirmed=zone_transfer_authorized_confirmed,
    )


ACTIVE_DNS_OSINT_ALLOWED_FIELDS = frozenset(
    {
        "mode",
        "profile",
        "domain",
        "include_certificate_transparency",
        "include_passive_dns",
        "max_names",
        "authorization_confirmed",
        "owned_or_authorized_domain_confirmed",
        "public_osint_queries_confirmed",
    }
)
ACTIVE_DNS_OSINT_CONFIRMATION_FIELDS = (
    "authorization_confirmed",
    "owned_or_authorized_domain_confirmed",
    "public_osint_queries_confirmed",
)
ACTIVE_DNS_OSINT_CONTRACT_LIMITS = {
    "max_domains": 1,
    "min_names": ACTIVE_DNS_OSINT_MIN_NAMES,
    "max_names": ACTIVE_DNS_OSINT_MAX_NAMES,
    "default_max_names": ACTIVE_DNS_OSINT_DEFAULT_MAX_NAMES,
    "external_requests_sent": 0,
    "ct_queries_sent": 0,
    "passive_dns_queries_sent": 0,
}


def validate_active_dns_osint_contract(payload: Any) -> ActiveDnsOsintContract:
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_dns_osint request body must be a JSON object.",
        )

    fields = set(payload)
    if fields - ACTIVE_DNS_OSINT_ALLOWED_FIELDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported active_dns_osint request field.",
        )
    if ACTIVE_DNS_OSINT_ALLOWED_FIELDS - fields:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_dns_osint request is missing required fields.",
        )

    if payload.get("mode") != ACTIVE_DNS_OSINT_MODE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_dns_osint mode must be live_dns_osint.",
        )
    if payload.get("profile") != ACTIVE_DNS_OSINT_PROFILE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_dns_osint profile must be ct_subdomain_discovery_bounded.",
        )

    for field_name in ACTIVE_DNS_OSINT_CONFIRMATION_FIELDS:
        if payload.get(field_name) is not True:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{field_name} must be true.")

    include_certificate_transparency = payload.get("include_certificate_transparency")
    if not isinstance(include_certificate_transparency, bool):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_dns_osint include_certificate_transparency must be boolean.",
        )
    if include_certificate_transparency is not True:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_dns_osint include_certificate_transparency must be true for this contract gate.",
        )

    include_passive_dns = payload.get("include_passive_dns")
    if not isinstance(include_passive_dns, bool):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_dns_osint include_passive_dns must be boolean.",
        )
    if include_passive_dns is not False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_dns_osint passive DNS is not supported by this contract gate.",
        )

    try:
        domain = normalize_active_dns_osint_domain(payload.get("domain"))
        max_names = normalize_active_dns_osint_max_names(payload.get("max_names"))
    except ActiveDnsOsintPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"active_dns_osint policy rejected the request: {exc.reason_code}.",
        ) from exc

    return ActiveDnsOsintContract(
        domain=domain,
        include_certificate_transparency=include_certificate_transparency,
        include_passive_dns=include_passive_dns,
        max_names=max_names,
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "inspectra-backend"}


@app.get("/client-capabilities", response_model=ClientCapabilitiesResponse)
async def client_capabilities(request: Request) -> ClientCapabilitiesResponse:
    """Advertise only static client contracts; no auth or project data is accepted."""

    if request.query_params:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Client capabilities do not accept parameters.")
    if await request.body():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Client capabilities do not accept a body.")
    return build_client_capabilities()


@app.get("/ready")
async def readiness(request: Request) -> Response:
    if request.query_params:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Readiness does not accept query parameters.")
    if await request.body():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Readiness does not accept a request body.")
    result = await request.app.state.operational_readiness.check()
    return JSONResponse(
        status_code=status.HTTP_200_OK if result["status"] == "ready" else status.HTTP_503_SERVICE_UNAVAILABLE,
        content=result,
    )


@app.get("/project-analysis-preflight", response_model=ProjectArchivePreflightResponse)
async def project_analysis_preflight(request: Request) -> ProjectArchivePreflightResponse:
    """Return source-free passive coverage before an archive is uploaded."""

    if request.query_params:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Project coverage preview does not accept query parameters.",
        )
    if await request.body():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Project coverage preview does not accept a request body.",
        )
    return build_project_archive_preflight(request.app.state.settings)


@app.get("/health/active-tools")
async def active_tools_health(request: Request) -> dict[str, Any]:
    if request.query_params:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_tools health status does not accept query parameters.",
        )
    if await request.body():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="active_tools health status does not accept a request body.",
        )

    settings = request.app.state.settings
    checker = getattr(request.app.state, "active_tools_health_checker", check_active_tools_health)
    active_tools = await checker(
        settings.active_tools_url,
        timeout_seconds=settings.active_tools_health_timeout_seconds,
    )
    return {
        "status": "ok",
        "service": "inspectra-backend",
        "active_tools": active_tools,
    }


@app.get("/auth/status", response_model=AuthStatusResponse)
async def auth_status(request: Request) -> AuthStatusResponse:
    settings = request.app.state.settings
    operator = request.app.state.default_local_operator
    auth_mode = get_auth_mode(settings)
    auth_required = is_auth_required(settings)
    session = current_session_for_request(request) if auth_required else None
    principal: TeamPrincipal | None = None
    if session is not None and auth_mode == "private_team_lightweight_users":
        try:
            principal = request.app.state.team_identity.get_principal(
                session.operator_id,
                session.organization_id or "",
            )
        except TeamIdentityError:
            principal = None
    return AuthStatusResponse(
        auth_mode=auth_mode,
        auth_required=auth_required,
        configured=is_auth_configured(settings),
        trusted_local=auth_mode == "trusted_local_no_auth",
        default_operator_id=operator.id,
        login_available=is_login_available_for_settings(settings),
        authenticated=session is not None,
        operator_id=session.operator_id if session is not None else None,
        username=principal.username if principal is not None else None,
        organization_id=principal.organization_id if principal is not None else None,
        organization_name=principal.organization_name if principal is not None else None,
        role=principal.role if principal is not None else None,
        csrf_required=auth_required,
        csrf_token=csrf_token_for_session(request, session),
    )


@app.post("/auth/login", response_model=AuthSessionResponse)
async def auth_login(request: Request, response: Response, login_request: AuthLoginRequest = Body(...)) -> AuthSessionResponse:
    settings = request.app.state.settings
    auth_mode = get_auth_mode(settings)
    username = (login_request.username or "").strip()
    username_allowed = not username or username == "admin"
    password = login_request.password or ""
    login_attempts = request.app.state.login_attempts
    client_key = login_client_key_for_request(request)

    rate_limited_mode = auth_mode in {"self_hosted_single_admin", "private_team_lightweight_users"}
    if rate_limited_mode:
        login_attempts.purge_expired()
        if login_attempts.is_locked(client_key):
            retry_after = login_attempts.seconds_until_unlock(client_key)
            headers = {"Retry-After": str(retry_after)} if retry_after > 0 else None
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=RATE_LIMITED_DETAIL,
                headers=headers,
            )

    principal: TeamPrincipal | None = None
    credentials_valid = False
    if auth_mode == "self_hosted_single_admin":
        credentials_valid = username_allowed and verify_admin_password(password, settings.admin_password_hash)
    elif auth_mode == "private_team_lightweight_users":
        identity_store = getattr(request.app.state, "team_identity", None)
        if isinstance(identity_store, TeamIdentityStore):
            try:
                principal = identity_store.authenticate(username, password)
            except TeamIdentityError:
                principal = None
        credentials_valid = principal is not None
        if principal is None:
            # Keep the missing/disabled-user path computationally comparable
            # without exposing which usernames exist.
            verify_admin_password(password, settings.admin_password_hash)

    if not credentials_valid:
        if rate_limited_mode:
            login_attempts.record_failure(client_key)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=INVALID_CREDENTIALS_DETAIL)

    login_attempts.reset_success(client_key)
    if principal is not None:
        session = request.app.state.admin_sessions.create_admin_session(
            principal.user_id,
            auth_mode=auth_mode,
            organization_id=principal.organization_id,
            role=principal.role,
        )
    else:
        session = request.app.state.admin_sessions.create_admin_session(
            request.app.state.default_local_operator.id,
            auth_mode=auth_mode,
        )
    cookie_settings = request.app.state.session_cookie_settings
    response.set_cookie(
        key=cookie_settings.name,
        value=session.session_id,
        max_age=cookie_settings.max_age_seconds,
        httponly=cookie_settings.httponly,
        secure=cookie_settings.secure,
        samesite=cookie_settings.samesite,
        path=cookie_settings.path,
    )
    record_product_action(
        request,
        "auth.login",
        resource_type="account",
        resource_id=session.operator_id,
        organization_id=session.organization_id or session.operator_id,
        actor_id=session.operator_id,
        actor_role=session.role or "administrator",
    )
    return AuthSessionResponse(
        authenticated=True,
        operator_id=session.operator_id,
        auth_mode=auth_mode,
        organization_id=session.organization_id,
        role=session.role,
    )


@app.post("/auth/logout", response_model=AuthSessionResponse)
async def auth_logout(request: Request, response: Response) -> AuthSessionResponse:
    settings = request.app.state.settings
    auth_mode = get_auth_mode(settings)
    session = current_session_for_request(request)
    session_id = request.cookies.get(ADMIN_SESSION_COOKIE_NAME)
    request.app.state.admin_sessions.invalidate_session(session_id)
    cookie_settings = request.app.state.session_cookie_settings
    response.delete_cookie(
        key=cookie_settings.name,
        path=cookie_settings.path,
        secure=cookie_settings.secure,
        httponly=cookie_settings.httponly,
        samesite=cookie_settings.samesite,
    )
    if session is not None:
        record_product_action(
            request,
            "auth.logout",
            resource_type="account",
            resource_id=session.operator_id,
            organization_id=session.organization_id or session.operator_id,
            actor_id=session.operator_id,
            actor_role=session.role or "administrator",
        )
    return AuthSessionResponse(
        authenticated=False,
        operator_id=None,
        auth_mode=auth_mode,
        organization_id=None,
        role=None,
    )


def _dependency_graph_attachment_target(request: Request, project_id: str, analysis_id: str):
    """Resolve the shared owner/lifecycle/source boundary before reading graph bytes."""

    project = get_project_for_current_owner(request, project_id)
    analysis = project_analysis_for_project(request, project, analysis_id)
    if analysis.status != "completed" or analysis.audit_type != "project_archive_basic":
        raise HTTPException(status_code=409, detail="Dependency evidence requires a completed project analysis.")
    if request.app.state.project_vulnerability_intelligence_store.get(analysis.id) is not None:
        raise HTTPException(
            status_code=409,
            detail="Attach dependency evidence before requesting public vulnerability intelligence for this analysis.",
        )
    if not analysis.source_sha256:
        raise HTTPException(status_code=409, detail="The selected analysis has no verifiable source binding.")
    snapshots = [
        snapshot for snapshot in project.source_snapshots
        if snapshot.source_sha256 == analysis.source_sha256 and snapshot.source_commit_sha is not None
    ]
    if len(snapshots) != 1:
        raise HTTPException(status_code=409, detail="The selected analysis is not bound to one verifiable Git commit.")
    return project, analysis, snapshots[0].source_commit_sha or ""


@app.post(
    "/auth/invitations/accept",
    response_model=TeamInvitationAcceptedResponse,
)
async def accept_team_invitation(
    request: Request,
    payload: TeamInvitationAcceptRequest,
) -> TeamInvitationAcceptedResponse:
    settings = request.app.state.settings
    identity_store = getattr(request.app.state, "team_identity", None)
    if get_auth_mode(settings) != "private_team_lightweight_users" or not isinstance(identity_store, TeamIdentityStore):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invitation not found.")
    login_attempts = request.app.state.login_attempts
    client_key = login_client_key_for_request(request)
    login_attempts.purge_expired()
    if login_attempts.is_locked(client_key):
        retry_after = login_attempts.seconds_until_unlock(client_key)
        headers = {"Retry-After": str(retry_after)} if retry_after > 0 else None
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=RATE_LIMITED_DETAIL,
            headers=headers,
        )
    try:
        principal = identity_store.accept_invitation(token=payload.token, password=payload.password)
    except (TeamIdentityError, ValueError) as exc:
        login_attempts.record_failure(client_key)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invitation is invalid or expired.") from exc
    login_attempts.reset_success(client_key)
    record_product_action(
        request,
        "team.invitation_accepted",
        resource_type="account",
        resource_id=principal.user_id,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        actor_role=principal.role,
    )
    return TeamInvitationAcceptedResponse(accepted=True, username=principal.username)


@app.get("/organization", response_model=TeamOrganizationResponse)
async def get_team_organization(request: Request) -> TeamOrganizationResponse:
    principal = current_team_principal(request)
    return TeamOrganizationResponse(
        id=principal.organization_id,
        name=principal.organization_name,
        current_user_id=principal.user_id,
        current_username=principal.username,
        current_role=principal.role,
    )


@app.get("/organizations", response_model=list[TeamOrganizationListItem])
async def list_team_organizations(request: Request) -> list[TeamOrganizationListItem]:
    principal = current_team_principal(request)
    try:
        organizations = request.app.state.team_identity.list_organizations(principal.user_id)
    except TeamIdentityError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Identity service unavailable.") from exc
    return [
        TeamOrganizationListItem(
            id=item.organization_id,
            name=item.name,
            role=item.role,
            created_at=item.created_at,
        )
        for item in organizations
    ]


@app.post("/organizations", response_model=TeamOrganizationListItem, status_code=status.HTTP_201_CREATED)
async def create_team_organization(
    request: Request,
    payload: TeamOrganizationCreateRequest,
) -> TeamOrganizationListItem:
    principal = require_team_administrator(request)
    try:
        organization = request.app.state.team_identity.create_organization(
            principal=principal,
            name=payload.name,
        )
    except TeamIdentityError as exc:
        if exc.code == "invalid_organization_name":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Workspace name is invalid.") from exc
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Identity service unavailable.") from exc
    record_product_action(
        request,
        "team.organization_created",
        resource_type="organization",
        resource_id=organization.organization_id,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        actor_role=principal.role,
    )
    return TeamOrganizationListItem(
        id=organization.organization_id,
        name=organization.name,
        role=organization.role,
        created_at=organization.created_at,
    )


@app.post("/organizations/{organization_id}/select", response_model=AuthSessionResponse)
async def select_team_organization(
    request: Request,
    response: Response,
    organization_id: str,
) -> AuthSessionResponse:
    principal = current_team_principal(request)
    organization_id = require_team_scope_identifier(
        organization_id,
        bootstrap_value="local-admin",
        detail="Workspace not found.",
    )
    try:
        selected = request.app.state.team_identity.get_principal(principal.user_id, organization_id)
    except TeamIdentityError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Identity service unavailable.") from exc
    if selected is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found.")

    old_session_id = request.cookies.get(ADMIN_SESSION_COOKIE_NAME)
    request.app.state.admin_sessions.invalidate_session(old_session_id)
    new_session = request.app.state.admin_sessions.create_admin_session(
        selected.user_id,
        auth_mode="private_team_lightweight_users",
        organization_id=selected.organization_id,
        role=selected.role,
    )
    cookie_settings = request.app.state.session_cookie_settings
    response.set_cookie(
        key=cookie_settings.name,
        value=new_session.session_id,
        max_age=cookie_settings.max_age_seconds,
        httponly=cookie_settings.httponly,
        secure=cookie_settings.secure,
        samesite=cookie_settings.samesite,
        path=cookie_settings.path,
    )
    record_product_action(
        request,
        "team.organization_selected",
        resource_type="organization",
        resource_id=selected.organization_id,
        organization_id=selected.organization_id,
        actor_id=selected.user_id,
        actor_role=selected.role,
    )
    return AuthSessionResponse(
        authenticated=True,
        operator_id=selected.user_id,
        auth_mode="private_team_lightweight_users",
        organization_id=selected.organization_id,
        role=selected.role,
    )


@app.get("/organization/members", response_model=list[TeamMemberResponse])
async def list_team_members(request: Request) -> list[TeamMemberResponse]:
    principal = current_team_principal(request)
    try:
        members = request.app.state.team_identity.list_members(principal.organization_id)
    except TeamIdentityError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Identity service unavailable.") from exc
    return [
        TeamMemberResponse(
            user_id=member.user_id,
            username=member.username,
            role=member.role,
            joined_at=member.joined_at,
        )
        for member in members
    ]


@app.get(
    "/organization/public-identities",
    response_model=list[PublicIdentityAttestationResponse],
)
async def list_public_identity_attestations(
    request: Request,
    response: Response,
) -> list[PublicIdentityAttestationResponse]:
    principal = current_team_principal(request)
    try:
        items = request.app.state.team_identity.list_public_identities(principal.organization_id)
    except TeamIdentityError as exc:
        raise _public_identity_attestation_http_error(exc) from exc
    response.headers["Cache-Control"] = "private, no-store"
    return [public_identity_attestation_response(item) for item in items]


@app.post(
    "/organization/public-identities",
    response_model=PublicIdentityAttestationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def propose_public_identity_attestation(
    request: Request,
    response: Response,
    payload: PublicIdentityAttestationCreateRequest,
) -> PublicIdentityAttestationResponse:
    principal = require_team_maintainer(request)
    try:
        attestation = request.app.state.team_identity.propose_public_identity(
            principal=principal,
            ecosystem=payload.ecosystem,
            package_name=payload.package_name,
            requested_ttl_days=payload.requested_ttl_days,
        )
    except TeamIdentityError as exc:
        raise _public_identity_attestation_http_error(exc) from exc
    record_product_action(
        request,
        "public_identity.proposed",
        resource_type="public_identity_attestation",
        resource_id=attestation.attestation_id,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        actor_role=principal.role,
        metadata={"package_ecosystem": attestation.ecosystem, "policy_revision": attestation.revision},
    )
    response.headers["Cache-Control"] = "private, no-store"
    return public_identity_attestation_response(attestation)


@app.post(
    "/organization/public-identities/{attestation_id}/approve",
    response_model=PublicIdentityAttestationResponse,
)
async def approve_public_identity_attestation(
    request: Request,
    response: Response,
    attestation_id: str,
) -> PublicIdentityAttestationResponse:
    principal = require_team_administrator(request)
    try:
        attestation = request.app.state.team_identity.approve_public_identity(
            principal=principal,
            attestation_id=attestation_id,
        )
    except TeamIdentityError as exc:
        raise _public_identity_attestation_http_error(exc) from exc
    record_product_action(
        request,
        "public_identity.approved",
        resource_type="public_identity_attestation",
        resource_id=attestation.attestation_id,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        actor_role=principal.role,
        metadata={"package_ecosystem": attestation.ecosystem, "policy_revision": attestation.revision},
    )
    response.headers["Cache-Control"] = "private, no-store"
    return public_identity_attestation_response(attestation)


@app.delete(
    "/organization/public-identities/{attestation_id}",
    response_model=PublicIdentityAttestationResponse,
)
async def revoke_public_identity_attestation(
    request: Request,
    response: Response,
    attestation_id: str,
) -> PublicIdentityAttestationResponse:
    principal = require_team_administrator(request)
    try:
        attestation = request.app.state.team_identity.revoke_public_identity(
            principal=principal,
            attestation_id=attestation_id,
        )
    except TeamIdentityError as exc:
        raise _public_identity_attestation_http_error(exc) from exc
    record_product_action(
        request,
        "public_identity.revoked",
        resource_type="public_identity_attestation",
        resource_id=attestation.attestation_id,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        actor_role=principal.role,
        metadata={"package_ecosystem": attestation.ecosystem, "policy_revision": attestation.revision},
    )
    response.headers["Cache-Control"] = "private, no-store"
    return public_identity_attestation_response(attestation)


@app.get(
    "/organization/members/{user_id}/active-impact",
    response_model=ActiveMemberResponsibilityImpact,
    deprecated=True,
)
@app.get(
    "/organization/members/{user_id}/responsibility-impact",
    response_model=ActiveMemberResponsibilityImpact,
)
async def get_team_member_responsibility_impact(request: Request, user_id: str) -> ActiveMemberResponsibilityImpact:
    principal = require_team_administrator(request)
    user_id = require_team_scope_identifier(user_id, bootstrap_value="team-admin", detail="Member not found.")
    try:
        member = request.app.state.team_identity.get_principal(user_id, principal.organization_id)
    except TeamIdentityError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Identity service unavailable.") from exc
    if member is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found.")
    try:
        impact = request.app.state.active_assets.responsibility_impact(
            user_id,
            organization_id=principal.organization_id,
        )
    except ActiveAssetStoreError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Active responsibility impact is unavailable.") from exc
    project_count = request.app.state.projects.responsibility_impact(
        user_id,
        owner_id=principal.organization_id,
    )
    return impact.model_copy(
        update={
            "affected_project_count": project_count,
            "projects_requiring_reassignment_count": project_count,
        }
    )


@app.get("/audit/events", response_model=ProductAuditEventsResponse)
async def list_product_audit_events(
    request: Request,
    limit: int = Query(default=25, ge=1, le=PRODUCT_AUDIT_MAX_PAGE_SIZE),
    cursor: str | None = Query(default=None, min_length=32, max_length=32),
    action: str | None = Query(default=None, min_length=3, max_length=96),
) -> ProductAuditEventsResponse:
    """Return only minimal events for the administrator's active workspace."""

    organization_id, actor_id, actor_role = require_product_audit_reader(request)
    try:
        response = request.app.state.product_audit.list(
            organization_id,
            limit=limit,
            cursor=cursor,
            action=action,
        )
    except ProductAuditError as exc:
        if exc.code in {"invalid_cursor", "invalid_action", "invalid_page_size"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Audit query is invalid or expired.") from exc
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Product audit history is unavailable.") from exc
    record_product_action(
        request,
        "audit.events.read",
        resource_type="organization",
        resource_id=organization_id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={"event_count": len(response.items), "filter_applied": action is not None},
    )
    return response


@app.get("/audit/integrity", response_model=ProductAuditIntegrityResponse)
async def verify_product_audit_integrity(request: Request) -> ProductAuditIntegrityResponse:
    organization_id, actor_id, actor_role = require_product_audit_reader(request)
    response = request.app.state.product_audit.verify_integrity(organization_id)
    record_product_action(
        request,
        "audit.integrity_verified",
        resource_type="organization",
        resource_id=organization_id,
        result="failed" if response.state == "invalid" else "succeeded",
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={
            "event_count": response.retained_events,
            "verification_status": response.state,
        },
    )
    return response


def product_audit_export_selection(
    request: Request,
    *,
    organization_id: str,
    period: Literal["7d", "30d", "90d", "365d"],
    action_filter: str | None,
    state_at: datetime | None = None,
):
    try:
        return select_product_audit_export(
            request.app.state.product_audit,
            organization_id=organization_id,
            period=period,
            action_filter=action_filter,
            state_at=state_at,
        )
    except ProductAuditError as exc:
        if exc.code == "invalid_action":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Audit export filter is invalid.") from exc
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Product audit export is unavailable.") from exc
    except ProductAuditExportError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Audit export scope is invalid.") from exc


@app.get("/audit/export/preflight", response_model=ProductAuditExportPreflight)
async def preflight_product_audit_export(
    request: Request,
    period: Literal["7d", "30d", "90d", "365d"] = Query(default="30d"),
    action_filter: str | None = Query(default=None, min_length=3, max_length=96),
) -> ProductAuditExportPreflight:
    organization_id, _actor_id, _actor_role = require_product_audit_reader(request)
    return product_audit_export_selection(
        request,
        organization_id=organization_id,
        period=period,
        action_filter=action_filter,
    ).preflight


@app.post("/audit/export")
async def export_product_audit(request: Request, payload: ProductAuditExportRequest) -> Response:
    organization_id, actor_id, actor_role = require_product_audit_reader(request)
    selection = product_audit_export_selection(
        request,
        organization_id=organization_id,
        period=payload.period,
        action_filter=payload.action_filter,
        state_at=payload.state_at,
    )
    try:
        validate_product_audit_export_request(selection, payload)
        rendered = render_product_audit_export(selection, payload.export_format)
    except ProductAuditExportError as exc:
        if exc.code == "export_too_large":
            raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="The bounded audit export is too large.") from exc
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Audit export preflight expired or no longer matches. Prepare it again.",
        ) from exc
    record_product_action(
        request,
        "audit.events_exported",
        resource_type="organization",
        resource_id=organization_id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={
            "report_format": payload.export_format,
            "event_count": selection.preflight.included_events,
            "filter_applied": payload.action_filter is not None,
            "review_period": payload.period,
        },
    )
    media_type = "application/json" if payload.export_format == "json" else "text/csv; charset=utf-8"
    return Response(
        content=rendered,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="inspectra-product-audit.{payload.export_format}"',
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Inspectra-Snapshot-SHA256": selection.preflight.snapshot_digest,
        },
    )


def active_audit_export_selection(
    request: Request,
    *,
    organization_id: str,
    period: Literal["7d", "30d", "90d", "365d"],
    asset_id: str | None,
):
    job_ids: set[str] = set()
    if asset_id is not None:
        try:
            asset = request.app.state.active_assets.get(asset_id, organization_id=organization_id)
        except ActiveAssetStoreError as exc:
            raise active_asset_http_error(exc) from exc
        job_ids = {job.id for job in active_jobs_for_asset(request, asset.id, organization_id)}
    try:
        return select_active_audit_export(
            request.app.state.product_audit,
            organization_id=organization_id,
            period=period,
            asset_id=asset_id,
            job_ids=job_ids,
        )
    except (ActiveAuditExportError, ProductAuditError) as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Active audit export is unavailable.") from exc


@app.get("/audit/active-export/preflight", response_model=ActiveAuditExportPreflight)
async def preflight_active_audit_export(
    request: Request,
    period: Literal["7d", "30d", "90d", "365d"] = Query(default="30d"),
    asset_id: str | None = Query(default=None, min_length=32, max_length=32),
) -> ActiveAuditExportPreflight:
    organization_id, _actor_id, _actor_role = require_product_audit_reader(request)
    return active_audit_export_selection(
        request,
        organization_id=organization_id,
        period=period,
        asset_id=asset_id,
    ).preflight


@app.get("/audit/active-export")
async def export_active_audit(
    request: Request,
    period: Literal["7d", "30d", "90d", "365d"] = Query(default="30d"),
    export_format: Literal["json", "csv"] = Query(default="json", alias="format"),
    asset_id: str | None = Query(default=None, min_length=32, max_length=32),
) -> Response:
    organization_id, actor_id, actor_role = require_product_audit_reader(request)
    selection = active_audit_export_selection(
        request,
        organization_id=organization_id,
        period=period,
        asset_id=asset_id,
    )
    try:
        payload = render_active_audit_export(selection, export_format)
    except ActiveAuditExportError as exc:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="The bounded Active audit export is too large.") from exc
    record_product_action(
        request,
        "active_asset.audit_exported",
        resource_type="active_asset" if asset_id else "organization",
        resource_id=asset_id or organization_id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={
            "report_format": export_format,
            "event_count": selection.preflight.included_events,
            "filter_applied": asset_id is not None,
        },
    )
    media_type = "application/json" if export_format == "json" else "text/csv; charset=utf-8"
    return Response(
        content=payload,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="inspectra-active-audit.{export_format}"',
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/privacy/retention", response_model=RetentionPolicyResponse)
async def get_retention_policy(request: Request) -> RetentionPolicyResponse:
    """Return configured lifecycle values without storage paths or contents."""

    if request.query_params:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Retention policy does not accept query parameters.")
    return build_retention_policy(
        request.app.state.settings,
        manual_cleanup_allowed=retention_cleanup_allowed(request),
    )


@app.get("/operations/public-advisories", response_model=PublicAdvisoryOperationsResponse)
async def get_public_advisory_operations(request: Request, response: Response) -> PublicAdvisoryOperationsResponse:
    if request.query_params:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Public advisory operations do not accept query parameters.")
    require_retention_administrator(request)
    try:
        result = public_advisory_operations_response(request)
    except (OSError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Public advisory operations are unavailable.") from exc
    response.headers["Cache-Control"] = "private, no-store"
    return result


@app.post("/operations/public-advisories/cache/purge-expired", response_model=PublicAdvisoryCacheCleanupResponse)
async def purge_public_advisory_cache(request: Request, response: Response) -> PublicAdvisoryCacheCleanupResponse:
    if request.query_params or await request.body():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Public advisory cache cleanup does not accept request data.")
    organization_id = require_retention_administrator(request)
    client = request.app.state.public_advisory_egress_client
    try:
        removed = client.cache.purge_expired() if client.cache is not None else 0
        operations = public_advisory_operations_response(request)
    except (OSError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Public advisory cache cleanup is unavailable.") from exc
    actor_id, _username, actor_role = finding_decision_actor(request)
    record_product_action(
        request,
        "public_advisory.cache_expired_purged",
        resource_type="public_advisory_cache",
        resource_id=organization_id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={"event_count": removed},
    )
    response.headers["Cache-Control"] = "private, no-store"
    return PublicAdvisoryCacheCleanupResponse(removed_entries=removed, operations=operations)


@app.post("/privacy/retention/run", response_model=RetentionCleanupResponse)
async def run_manual_retention_cleanup(request: Request) -> RetentionCleanupResponse:
    """Run bounded maintenance for the active organization only."""

    if request.query_params or await request.body():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Retention cleanup does not accept request data.")
    organization_id = require_retention_administrator(request)
    correlation_id = getattr(request.state, "request_id", None) or uuid4().hex
    response = request.app.state.retention_maintenance.run(
        organization_id=organization_id,
        correlation_id=correlation_id,
    )
    record_product_action(
        request,
        "retention.cleanup_run",
        resource_type="organization",
        resource_id=organization_id,
        result="failed" if response.state == "failed" else "succeeded",
        correlation_id=correlation_id,
    )
    return response


@app.post(
    "/organization/invitations",
    response_model=TeamInvitationCreatedResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_team_invitation(
    request: Request,
    payload: TeamInvitationCreateRequest,
) -> TeamInvitationCreatedResponse:
    principal = require_team_administrator(request)
    try:
        invitation = request.app.state.team_identity.create_invitation(
            principal=principal,
            username=payload.username,
            role=payload.role,
        )
    except TeamIdentityError as exc:
        if exc.code == "member_exists":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A member already uses that username.") from exc
        if exc.code in {"invalid_username", "invalid_role"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invitation details are invalid.") from exc
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Identity service unavailable.") from exc
    record_product_action(
        request,
        "team.invitation_created",
        resource_type="invitation",
        resource_id=invitation.invitation_id,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        actor_role=principal.role,
        metadata={"target_role": invitation.role},
    )
    return TeamInvitationCreatedResponse(
        invitation_id=invitation.invitation_id,
        token=invitation.token,
        username=invitation.username,
        role=invitation.role,
        expires_at=invitation.expires_at,
    )


@app.post("/organization/members/{user_id}/role", response_model=TeamMemberResponse)
async def change_team_member_role(
    request: Request,
    user_id: str,
    payload: TeamMemberRoleUpdateRequest,
) -> TeamMemberResponse:
    principal = require_team_administrator(request)
    user_id = require_team_scope_identifier(user_id, bootstrap_value="team-admin", detail="Member not found.")
    try:
        member = request.app.state.team_identity.change_member_role(
            principal=principal,
            user_id=user_id,
            role=payload.role,
        )
    except TeamIdentityError as exc:
        if exc.code == "last_administrator":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The bootstrap administrator role cannot be removed.") from exc
        if exc.code == "member_not_found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found.") from exc
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Identity service unavailable.") from exc
    scoped_invalidator = getattr(
        request.app.state.admin_sessions,
        "invalidate_operator_organization_sessions",
        None,
    )
    invalidator = getattr(request.app.state.admin_sessions, "invalidate_operator_sessions", None)
    if user_id != principal.user_id:
        if callable(scoped_invalidator):
            scoped_invalidator(user_id, principal.organization_id)
        elif callable(invalidator):
            invalidator(user_id)
    record_product_action(
        request,
        "team.member_role_changed",
        resource_type="account",
        resource_id=member.user_id,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        actor_role=principal.role,
        metadata={"target_role": member.role},
    )
    return TeamMemberResponse(
        user_id=member.user_id,
        username=member.username,
        role=member.role,
        joined_at=member.joined_at,
    )


@app.delete("/organization/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_team_member(request: Request, user_id: str) -> Response:
    principal = require_team_administrator(request)
    user_id = require_team_scope_identifier(user_id, bootstrap_value="team-admin", detail="Member not found.")
    if user_id == "team-admin":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The bootstrap administrator cannot revoke itself.")
    try:
        target_member = request.app.state.team_identity.get_principal(user_id, principal.organization_id)
    except TeamIdentityError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Identity service unavailable.") from exc
    if target_member is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found.")
    scoped_invalidator = getattr(
        request.app.state.admin_sessions,
        "invalidate_operator_organization_sessions",
        None,
    )
    invalidator = getattr(request.app.state.admin_sessions, "invalidate_operator_sessions", None)
    if callable(scoped_invalidator):
        scoped_invalidator(user_id, principal.organization_id)
    elif callable(invalidator):
        invalidator(user_id)
    def reconcile_member_responsibility() -> ActiveMemberResponsibilityImpact:
        affected_projects = request.app.state.projects.unassign_member(
            user_id,
            owner_id=principal.organization_id,
            actor_id=principal.user_id,
        )
        active_impact = request.app.state.active_assets.unassign_member(
            user_id,
            organization_id=principal.organization_id,
            actor_id=principal.user_id,
        )
        request.app.state.remediation_saved_views.delete_user(
            principal.organization_id,
            user_id,
        )
        return active_impact.model_copy(
            update={
                "affected_project_count": affected_projects,
                "projects_requiring_reassignment_count": affected_projects,
            }
        )

    try:
        impact = request.app.state.team_identity.revoke_member(
            principal=principal,
            user_id=user_id,
            on_membership_revoked=reconcile_member_responsibility,
        )
    except TeamIdentityError as exc:
        if exc.code == "last_administrator":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The bootstrap administrator cannot revoke itself.") from exc
        if exc.code == "member_not_found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found.") from exc
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Identity service unavailable.") from exc
    except (ActiveAssetStoreError, RemediationSavedViewError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Member revocation could not be reconciled safely.",
        ) from exc
    assert isinstance(impact, ActiveMemberResponsibilityImpact)
    record_product_action(
        request,
        "team.member_revoked",
        resource_type="account",
        resource_id=user_id,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        actor_role=principal.role,
        metadata={
            "affected_asset_count": impact.affected_asset_count,
            "unassigned_asset_count": impact.will_become_unassigned_count,
            "affected_project_count": impact.affected_project_count,
            "unassigned_project_count": impact.projects_requiring_reassignment_count,
        },
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/automation/tokens", response_model=list[AutomationTokenResponse])
async def list_automation_tokens(request: Request) -> list[AutomationTokenResponse]:
    organization_id, _actor_id, _actor_role = require_automation_token_administrator(request)
    try:
        records = request.app.state.automation_tokens.list(organization_id)
    except AutomationTokenError as exc:
        raise HTTPException(status_code=503, detail="Automation credentials are unavailable.") from exc
    return [automation_token_response(record) for record in records]


@app.post(
    "/automation/tokens",
    response_model=AutomationTokenCreatedResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_automation_token(
    request: Request,
    payload: AutomationTokenCreateRequest,
) -> AutomationTokenCreatedResponse:
    organization_id, actor_id, actor_role = require_automation_token_administrator(request)
    project = get_project_for_current_owner(request, payload.project_id)
    try:
        record, plaintext = request.app.state.automation_tokens.create(
            name=payload.name,
            organization_id=organization_id,
            project_id=project.id,
            scopes=tuple(payload.scopes),
            created_by=actor_id,
            lifetime_seconds=payload.lifetime_seconds,
        )
    except AutomationTokenError as exc:
        if exc.code in {"invalid_name", "invalid_project", "invalid_scopes", "invalid_lifetime"}:
            raise HTTPException(status_code=400, detail="Automation credential request is invalid.") from exc
        if exc.code == "active_limit":
            raise HTTPException(status_code=409, detail="Revoke an active project credential before creating another one.") from exc
        raise HTTPException(status_code=503, detail="Automation credentials are unavailable.") from exc
    record_product_action(
        request,
        "automation_token.created",
        resource_type="automation_token",
        resource_id=record.token_id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={"project_id": project.id, "scopes": list(record.scopes)},
    )
    public = automation_token_response(record)
    return AutomationTokenCreatedResponse(**public.model_dump(), token=plaintext)


@app.get("/automation/tokens/{token_id}", response_model=AutomationTokenProbeResponse)
async def probe_automation_token(request: Request, token_id: str) -> AutomationTokenProbeResponse:
    """Validate retained credential metadata without receiving or using its secret."""

    organization_id, _actor_id, _actor_role = require_automation_token_administrator(request)
    token_id = require_team_scope_identifier(token_id, bootstrap_value="", detail="Automation credential not found.")
    try:
        record = request.app.state.automation_tokens.get(organization_id, token_id)
    except AutomationTokenError as exc:
        if exc.code == "not_found":
            raise HTTPException(status_code=404, detail="Automation credential not found.") from exc
        raise HTTPException(status_code=503, detail="Automation credentials are unavailable.") from exc
    now = datetime.now(timezone.utc)
    project_available = True
    try:
        get_project_for_current_owner(request, record.project_id)
    except HTTPException as exc:
        if exc.status_code != 404:
            raise
        project_available = False
    state: Literal["ready", "expired", "revoked", "project_unavailable"]
    if record.revoked_at is not None:
        state = "revoked"
    elif record.expires_at <= now:
        state = "expired"
    elif not project_available:
        state = "project_unavailable"
    else:
        state = "ready"
    required_scopes = {"project:read", "project:scan", "report:read"}
    return AutomationTokenProbeResponse(
        status=state,
        project_id=record.project_id,
        scopes=list(record.scopes),
        scopes_complete=required_scopes.issubset(record.scopes),
        expires_at=record.expires_at,
    )


@app.delete("/automation/tokens/{token_id}", response_model=AutomationTokenResponse)
async def revoke_automation_token(request: Request, token_id: str) -> AutomationTokenResponse:
    organization_id, actor_id, actor_role = require_automation_token_administrator(request)
    token_id = require_team_scope_identifier(token_id, bootstrap_value="", detail="Automation credential not found.")
    try:
        record = request.app.state.automation_tokens.revoke(organization_id, token_id)
    except AutomationTokenError as exc:
        if exc.code == "not_found":
            raise HTTPException(status_code=404, detail="Automation credential not found.") from exc
        raise HTTPException(status_code=503, detail="Automation credentials are unavailable.") from exc
    record_product_action(
        request,
        "automation_token.revoked",
        resource_type="automation_token",
        resource_id=record.token_id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={"project_id": record.project_id},
    )
    return automation_token_response(record)


@app.post("/projects", response_model=ProjectCreated, status_code=status.HTTP_201_CREATED)
async def create_project(
    request: Request,
    payload: ProjectCreateRequest,
    background_tasks: BackgroundTasks,
) -> ProjectCreated:
    """Create an archive-backed project and immediately queue its first review."""

    source = get_file_for_current_owner(request, payload.source_file_id)
    if source.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Project source must be an archive.")

    owner_id = owner_id_for_file_job(request, source)
    request.app.state.jobs.assert_admission_available(owner_id=owner_id)
    project = request.app.state.projects.create(
        name=payload.name or default_project_name(source.id),
        source=source,
        owner_id=owner_id,
        source_channel="archive_upload",
    )
    job = request.app.state.jobs.create_project_archive_job(
        source.id,
        owner_id=owner_id,
        project_id=project.id,
        source_sha256=source.sha256,
    )
    project = request.app.state.projects.attach_job(project.id, job.id)
    log_audit_event(
        "project.created",
        correlation_id=f"project:{project.id}",
        project_id=project.id,
        job_id=job.id,
        owner_id=project.owner_id,
    )
    record_product_action(
        request,
        "project.created",
        resource_type="project",
        resource_id=project.id,
        organization_id=owner_id,
        metadata={
            "job_id": job.id,
            "analysis_profile": job.analysis_profile,
            "execution_contract_version": job.execution_profile.contract_version if job.execution_profile else None,
        },
    )
    schedule_bounded_audit(background_tasks, request.app, request.app.state.project_archive_audits.run_project_archive_analysis, job.id)
    return ProjectCreated(project=project, job=request.app.state.jobs.get_list_item(job.id))


@app.post(
    "/projects/{project_id}/sbom-revisions",
    response_model=ProjectSbomRevisionCreated,
    status_code=status.HTTP_201_CREATED,
)
async def import_project_sbom_revision(
    request: Request,
    project_id: str,
    file: UploadFile = File(...),
    idempotency_key: str = Form(..., min_length=16, max_length=128),
    authorization_confirmed: bool = Form(...),
    public_registry_identities_confirmed: bool = Form(default=False),
) -> ProjectSbomRevisionCreated:
    """Append one normalized SBOM revision without moving state on failure."""

    if authorization_confirmed is not True:
        raise HTTPException(status_code=400, detail="Explicit SBOM authorization confirmation is required.")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{16,128}", idempotency_key):
        raise HTTPException(status_code=400, detail="SBOM revision idempotency key is invalid.")
    project = get_project_for_current_owner(request, project_id)
    current_source = source_for_project_analysis(request, project)
    if current_source.kind != "manifest" or current_source.original_filename != "sbom.json":
        raise HTTPException(status_code=409, detail="Only an SBOM project accepts SBOM revisions.")
    current_normalized = request.app.state.files.read_normalized_sbom(current_source.id, owner_id=project.owner_id)
    raw_payload = await file.read(request.app.state.settings.max_upload_bytes + 1)
    if len(raw_payload) > request.app.state.settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="SBOM exceeds the configured upload limit.")
    try:
        normalized = normalize_sbom(raw_payload, public_identities_confirmed=public_registry_identities_confirmed)
    except SbomImportError as exc:
        raise HTTPException(status_code=400, detail="SBOM format or component contract is invalid.") from exc
    if normalized["format"] != current_normalized.get("format"):
        raise HTTPException(
            status_code=409,
            detail="SBOM revision format must match the project's original CycloneDX or SPDX format.",
        )
    normalized_payload = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    source_digest = hashlib.sha256(normalized_payload).hexdigest()
    revision_key_sha256 = hashlib.sha256(idempotency_key.encode("ascii")).hexdigest()

    def existing_revision() -> tuple[JobRecord, Any] | None:
        refreshed = request.app.state.projects.get(project.id)
        jobs = [
            request.app.state.jobs.get(item.id)
            for item in request.app.state.jobs.list_for_project(project.id, owner_id=project.owner_id)
        ]
        keyed = [job for job in jobs if job.project_id == project.id and job.sbom_revision_key_sha256 == revision_key_sha256]
        if keyed:
            if keyed[0].source_sha256 != source_digest:
                raise HTTPException(status_code=409, detail="Idempotency key is already bound to a different SBOM revision.")
            snapshot = next((item for item in refreshed.source_snapshots if item.source_sha256 == source_digest), None)
            if keyed[0].status == "completed" and snapshot is not None:
                return keyed[0], snapshot
            return None
        if any(
            job.project_id == project.id and job.source_sha256 == source_digest and job.status == "completed"
            for job in jobs
        ):
            raise HTTPException(status_code=409, detail="This SBOM revision is already retained under another request.")
        return None

    replay = existing_revision()
    if replay is not None:
        replay_job, replay_snapshot = replay
        return ProjectSbomRevisionCreated(
            project=request.app.state.projects.get(project.id),
            job=request.app.state.jobs.get_list_item(replay_job.id),
            snapshot=replay_snapshot,
            replayed=True,
        )

    source = request.app.state.files.save_normalized_sbom(normalized_payload, owner_id=project.owner_id)
    job: JobRecord | None = None
    try:
        job = request.app.state.jobs.create_sbom_import_job(
            source.id,
            owner_id=project.owner_id,
            project_id=project.id,
            source_sha256=source.sha256,
            revision_key_sha256=revision_key_sha256,
        )
        request.app.state.jobs.update(job.id, status="running")
        job = request.app.state.jobs.update(
            job.id,
            status="completed",
            result=sbom_project_result(normalized),
            termination_reason="completed",
        )
        updated, snapshot = request.app.state.projects.attach_sbom_revision(project.id, source=source, job=job)
    except Exception:
        if job is not None:
            with suppress(HTTPException):
                request.app.state.jobs.delete(job.id, owner_id=project.owner_id)
        with suppress(HTTPException):
            request.app.state.files.delete(source.id, owner_id=project.owner_id)
        replay = existing_revision()
        if replay is not None:
            replay_job, replay_snapshot = replay
            return ProjectSbomRevisionCreated(
                project=request.app.state.projects.get(project.id),
                job=request.app.state.jobs.get_list_item(replay_job.id),
                snapshot=replay_snapshot,
                replayed=True,
            )
        raise
    record_product_action(
        request,
        "project.sbom_revision_imported",
        resource_type="analysis",
        resource_id=job.id,
        organization_id=project.owner_id,
        metadata={"project_id": project.id, "analysis_profile": "sbom_import", "replayed": False},
    )
    return ProjectSbomRevisionCreated(
        project=updated,
        job=request.app.state.jobs.get_list_item(job.id),
        snapshot=snapshot,
        replayed=False,
    )


@app.post("/projects/import/sbom/preflight", response_model=SbomImportPreflightResponse)
async def preflight_sbom_project_import(
    request: Request,
    file: UploadFile = File(...),
) -> SbomImportPreflightResponse:
    """Inspect one SBOM in memory and return only aggregate, expiring metadata."""

    raw_payload = await file.read(request.app.state.settings.max_upload_bytes + 1)
    if len(raw_payload) > request.app.state.settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="SBOM exceeds the configured upload limit.")
    try:
        normalized = normalize_sbom(raw_payload, public_identities_confirmed=False)
    except SbomImportError as exc:
        detail = (
            "CycloneDX version is not supported. Use JSON 1.4, 1.5 or 1.6."
            if exc.args and exc.args[0] == "unsupported_cyclonedx_version"
            else "SPDX version is not supported. Use JSON 2.2 or 2.3."
            if exc.args and exc.args[0] == "unsupported_spdx_version"
            else "SBOM format or component contract is invalid."
        )
        raise HTTPException(status_code=400, detail=detail) from exc
    admission = request.app.state.sbom_preflights.create(
        current_owner_id_for_request(request),
        raw_payload,
    )
    return SbomImportPreflightResponse(
        preflight_token=admission.token,
        expires_at=admission.expires_at,
        format=normalized["format"],
        spec_version=normalized["spec_version"],
        input_components=normalized["input_components"],
        retained_components=normalized["retained_components"],
        rejected_or_ambiguous_components=normalized["rejected_or_ambiguous_components"],
        potentially_correlatable_components=normalized["retained_components"],
        component_limit_reached=normalized["truncated"],
        relationship_graph_truncated=normalized["relationship_graph_truncated"],
    )


@app.post("/projects/import/sbom", response_model=ProjectCreated, status_code=status.HTTP_201_CREATED)
async def import_sbom_project(
    request: Request,
    file: UploadFile = File(...),
    name: str = Form(..., min_length=3, max_length=120),
    preflight_token: str = Form(..., min_length=32, max_length=128),
    authorization_confirmed: bool = Form(...),
    public_registry_identities_confirmed: bool = Form(default=False),
) -> ProjectCreated:
    """Create a completed, immutable offline project from a bounded JSON SBOM."""

    if authorization_confirmed is not True:
        raise HTTPException(status_code=400, detail="Explicit SBOM authorization confirmation is required.")
    normalized_name = name.strip()
    if not normalized_name or any(ord(character) < 32 or character in {"/", "\\"} for character in normalized_name):
        raise HTTPException(status_code=400, detail="Project name contains unsupported characters.")
    owner_id = current_owner_id_for_request(request)
    raw_payload = await file.read(request.app.state.settings.max_upload_bytes + 1)
    if len(raw_payload) > request.app.state.settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="SBOM exceeds the configured upload limit.")
    try:
        request.app.state.sbom_preflights.consume(owner_id, preflight_token, raw_payload)
    except SbomPreflightError as exc:
        detail = (
            "The selected SBOM changed after preflight. Run preflight again before importing."
            if exc.args and exc.args[0] == "content_changed"
            else "The SBOM preflight expired or is unavailable. Run it again before importing."
        )
        raise HTTPException(status_code=409, detail=detail) from exc
    try:
        normalized = normalize_sbom(
            raw_payload,
            public_identities_confirmed=public_registry_identities_confirmed,
        )
    except SbomImportError as exc:
        detail = (
            "CycloneDX version is not supported. Use JSON 1.4, 1.5 or 1.6."
            if exc.args and exc.args[0] == "unsupported_cyclonedx_version"
            else "SPDX version is not supported. Use JSON 2.2 or 2.3."
            if exc.args and exc.args[0] == "unsupported_spdx_version"
            else "SBOM format or component contract is invalid."
        )
        raise HTTPException(status_code=400, detail=detail) from exc
    normalized_payload = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    source = request.app.state.files.save_normalized_sbom(normalized_payload, owner_id=owner_id)
    project = request.app.state.projects.create(
        name=normalized_name,
        source=source,
        owner_id=owner_id,
        source_channel="sbom",
    )
    job = request.app.state.jobs.create_sbom_import_job(
        source.id,
        owner_id=owner_id,
        project_id=project.id,
        source_sha256=source.sha256,
    )
    request.app.state.jobs.update(job.id, status="running")
    job = request.app.state.jobs.update(
        job.id,
        status="completed",
        result=sbom_project_result(normalized),
        termination_reason="completed",
    )
    project = request.app.state.projects.attach_job(project.id, job.id)
    record_product_action(
        request,
        "project.sbom_imported",
        resource_type="project",
        resource_id=project.id,
        organization_id=owner_id,
        metadata={"project_id": project.id, "analysis_profile": "sbom_import"},
    )
    return ProjectCreated(project=project, job=request.app.state.jobs.get_list_item(job.id))


@app.get("/projects", response_model=list[ProjectSummary], deprecated=True)
async def list_projects(request: Request, response: Response) -> list[ProjectSummary]:
    """Legacy bounded first page; new clients use the body-only search route."""

    owner_id = current_owner_id_for_request(request)
    records, total, next_cursor = request.app.state.projects.page(
        owner_id=owner_id, page_size=100
    )
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Deprecation"] = "true"
    response.headers["X-Inspectra-Total-Count"] = str(total)
    response.headers["X-Inspectra-Truncated"] = "true" if next_cursor else "false"
    return [project_summary(project, request.app.state.jobs) for project in records]


@app.post("/projects/search", response_model=ProjectPage)
async def search_projects(
    request: Request, response: Response, payload: ProjectPageRequest
) -> ProjectPage:
    """Return a bounded, owner-scoped project page from the private index."""

    owner_id = current_owner_id_for_request(request)
    records, total, next_cursor = request.app.state.projects.page(
        owner_id=owner_id,
        page_size=payload.page_size,
        cursor=payload.cursor,
    )
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    items = [project_summary(project, request.app.state.jobs) for project in records]
    return ProjectPage(
        items=items,
        returned_count=len(items),
        total_count=total,
        has_more=next_cursor is not None,
        next_cursor=next_cursor,
    )


@app.put("/projects/{project_id}/responsibility", response_model=ProjectView)
async def update_project_responsibility(
    request: Request,
    response: Response,
    project_id: str,
    payload: ProjectResponsibilityUpdateRequest,
) -> ProjectView:
    """Assign one active accountable member without changing finding triage."""

    project = get_project_for_current_owner(request, project_id)
    organization_id, actor_id, _actor_role = active_asset_actor(request, write=True)
    if project.owner_id != organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
    values = [payload.responsible_user_id] if payload.responsible_user_id else []
    updated, changed = run_with_validated_active_responsibles(
        request,
        values,
        organization_id=organization_id,
        actor_id=actor_id,
        operation=lambda normalized: request.app.state.projects.set_responsibility(
            project.id,
            responsible_user_id=normalized[0] if normalized else None,
            actor_id=actor_id,
            expected_updated_at=payload.expected_updated_at,
        ),
    )
    responsibility = updated.responsibility_revisions[-1] if updated.responsibility_revisions else None
    record_product_action(
        request,
        "project.responsibility_updated",
        resource_type="project",
        resource_id=project.id,
        organization_id=organization_id,
        metadata={
            "changed": changed,
            "responsible_count": 1 if responsibility and responsibility.responsible_user_id else 0,
            "policy_revision": responsibility.sequence if responsibility else 0,
        },
    )
    response.headers["Cache-Control"] = "private, no-store"
    return ProjectView.model_validate(updated)


def project_action_inbox_error(exc: ProjectActionInboxError) -> HTTPException:
    if exc.code == "action_not_found":
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Passive project action not found.")
    if exc.code in {"invalid_request", "invalid_scope"}:
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Passive action inbox request is invalid.")
    if exc.code in {"reader_limit", "store_limit"}:
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Passive action inbox reached its safe limit.")
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Passive action inbox integrity is unavailable. An administrator may rebuild it from the project portfolio.",
    )


@app.get("/projects/actions", response_model=ProjectActionPage)
async def list_project_actions(
    request: Request,
    response: Response,
    unread_only: bool = False,
    limit: int = Query(default=100, ge=1, le=200),
) -> ProjectActionPage:
    organization_id = current_owner_id_for_request(request)
    actor_id, _actor_username, _actor_role = finding_decision_actor(request)
    try:
        result = request.app.state.project_action_inbox.list(
            organization_id, actor_id, unread_only=unread_only, limit=limit
        )
    except ProjectActionInboxError as exc:
        raise project_action_inbox_error(exc) from exc
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return result


@app.put("/projects/actions/{action_id}/read", response_model=ProjectActionPage)
async def mark_project_action_read(
    request: Request,
    response: Response,
    action_id: str,
    payload: ProjectActionReadRequest,
) -> ProjectActionPage:
    del payload
    organization_id = current_owner_id_for_request(request)
    actor_id, _actor_username, actor_role = finding_decision_actor(request)
    try:
        result = request.app.state.project_action_inbox.mark_read(
            organization_id, actor_id, action_id
        )
    except ProjectActionInboxError as exc:
        raise project_action_inbox_error(exc) from exc
    record_product_action(
        request,
        "project.action_read",
        resource_type="project_action",
        resource_id=action_id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
    )
    response.headers["Cache-Control"] = "private, no-store"
    return result


@app.post("/projects/actions/rebuild", response_model=ProjectActionPage)
async def rebuild_project_actions(
    request: Request,
    response: Response,
    payload: ProjectActionRebuildRequest,
) -> ProjectActionPage:
    del payload
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    try:
        result = request.app.state.project_action_inbox.list(
            organization_id, actor_id, rebuild=True
        )
    except ProjectActionInboxError as exc:
        raise project_action_inbox_error(exc) from exc
    record_product_action(
        request,
        "project.action_inbox_rebuilt",
        resource_type="organization",
        resource_id=organization_id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={"event_count": result.total},
    )
    response.headers["Cache-Control"] = "private, no-store"
    return result


@app.post("/projects/portfolio/search", response_model=ProjectPortfolioPage)
async def search_project_portfolio(
    request: Request,
    response: Response,
    payload: ProjectPortfolioSearchRequest,
) -> ProjectPortfolioPage:
    """Return a coherent owner-scoped page ranked by visible, closed signals."""

    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return request.app.state.project_portfolio.search(
        organization_id=current_owner_id_for_request(request),
        payload=payload,
    )


@app.post("/projects/trends", response_model=RiskTrendViewResponse)
async def get_project_risk_trends(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    payload: RiskTrendRequest,
) -> RiskTrendViewResponse:
    """Read the last projection and enqueue stale work outside the request."""

    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    organization_id = current_owner_id_for_request(request)
    result = request.app.state.project_risk_trends.read(
        organization_id=organization_id,
        payload=payload,
    )
    if result.materialization.refresh_in_progress:
        schedule_risk_trend_refresh_once(
            background_tasks, request.app, organization_id
        )
        response.headers["Retry-After"] = str(
            result.materialization.retry_after_seconds or 1
        )
        if result.trend is None:
            response.status_code = status.HTTP_202_ACCEPTED
    return result


@app.post("/projects/trends/refresh", response_model=RiskTrendViewResponse)
async def retry_project_risk_trends(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    payload: RiskTrendRequest,
) -> RiskTrendViewResponse:
    """Explicitly retry or revalidate one owner-scoped derived projection."""

    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    organization_id = current_owner_id_for_request(request)
    result = request.app.state.project_risk_trends.read(
        organization_id=organization_id,
        payload=payload,
        force_refresh=True,
    )
    schedule_risk_trend_refresh_once(
        background_tasks, request.app, organization_id
    )
    response.headers["Retry-After"] = "1"
    if result.trend is None:
        response.status_code = status.HTTP_202_ACCEPTED
    return result


@app.post("/projects/trends/report")
async def export_project_risk_trends(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: RiskTrendReportRequest,
) -> Response:
    """Export the same bounded facts after explicit project-name disclosure consent."""

    organization_id = current_owner_id_for_request(request)
    view = request.app.state.project_risk_trends.read(
        organization_id=organization_id,
        payload=payload.filters,
    )
    if view.materialization.refresh_in_progress:
        schedule_risk_trend_refresh_once(
            background_tasks, request.app, organization_id
        )
    if view.trend is None or view.materialization.data_state != "current":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Risk trends are refreshing. Review the materialization state before exporting.",
            headers={"Retry-After": "1"},
        )
    trend = view.trend
    content, media_type, filename, digest = render_risk_trend_report(
        trend,
        profile=payload.profile,
        report_format=payload.report_format,
    )
    record_product_action(
        request,
        "project_risk_trends.report_exported",
        resource_type="organization",
        resource_id=organization_id,
        organization_id=organization_id,
        metadata={
            "profile": payload.profile,
            "report_format": payload.report_format,
            "period_days": payload.filters.period_days,
            "bucket_days": payload.filters.bucket_days,
        },
    )
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Inspectra-Snapshot-SHA256": digest,
        },
    )


@app.post("/remediation/search", response_model=RemediationPage)
async def search_remediation_center(
    request: Request,
    response: Response,
    payload: RemediationSearchRequest,
) -> RemediationPage:
    """Return grouped current evidence without treating a workflow decision as a verified fix."""

    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return request.app.state.remediation_center.search(
        organization_id=current_owner_id_for_request(request),
        payload=payload,
    )


@app.post(
    "/remediation/actions",
    response_model=RemediationBulkActionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def apply_remediation_action(
    request: Request,
    payload: RemediationBulkActionRequest,
) -> RemediationBulkActionResponse:
    """Append one explicitly confirmed, bounded workflow action across current evidence."""

    organization_id = current_owner_id_for_request(request)
    actor_id, actor_username, actor_role = finding_decision_actor(request)
    try:
        operation_id, request_digest = request.app.state.finding_decisions.batch_binding(
            organization_id=organization_id,
            actor_id=actor_id,
            idempotency_key=payload.idempotency_key,
            request_payload=payload.model_dump(mode="json"),
        )
        replay = request.app.state.finding_decisions.replay_batch(
            operation_id,
            organization_id=organization_id,
            request_digest=request_digest,
        )
    except FindingLifecycleError as exc:
        if exc.code in {"idempotency_conflict", "batch_replay_unavailable"}:
            raise HTTPException(status_code=409, detail="Remediation idempotency key cannot be replayed for this request.") from exc
        if exc.code in {"batch_state_invalid", "batch_recovery_failed", "store_unavailable"}:
            raise HTTPException(status_code=503, detail="Remediation batch recovery is temporarily unavailable.") from exc
        raise HTTPException(status_code=422, detail="Remediation action is invalid.") from exc
    if replay is not None:
        return RemediationBulkActionResponse(
            group_id=payload.group_id,
            applied_count=len(replay),
            decisions=replay,
            replayed=True,
        )
    occurrences = request.app.state.remediation_center.validate_bulk_selection(
        organization_id=organization_id,
        group_id=payload.group_id,
        expected_revision=payload.expected_revision,
        selections=payload.selections,
    )
    assignee_user_id, assignee_username = finding_decision_assignee(request, payload.assignee_user_id)
    try:
        decisions, replayed = request.app.state.finding_decisions.record_many(
            organization_id=organization_id,
            operation_id=operation_id,
            request_digest=request_digest,
            group_id=payload.group_id,
            items=[
                (item.project.id, item.finding_id, item.rule_id)
                for item in occurrences
            ],
            status=payload.status,
            reason=payload.reason,
            comment=payload.comment,
            actor_id=actor_id,
            actor_username=actor_username,
            actor_role=actor_role,
            review_at=payload.review_at,
            assignee_user_id=assignee_user_id,
            assignee_username=assignee_username,
        )
    except FindingLifecycleError as exc:
        if exc.code == "invalid_transition":
            raise HTTPException(status_code=409, detail="One selected finding changed state. Refresh and review the batch.") from exc
        if exc.code in {"idempotency_conflict", "batch_replay_unavailable"}:
            raise HTTPException(status_code=409, detail="Remediation idempotency key cannot be replayed for this request.") from exc
        if exc.code in {"finding_decision_limit", "project_decision_limit", "store_limit"}:
            raise HTTPException(status_code=409, detail="Finding decision history reached its configured limit.") from exc
        if exc.code in {
            "reason_required", "invalid_text", "invalid_assignee", "review_date_required",
            "review_date_not_allowed", "review_date_not_future", "review_date_timezone_required",
            "review_date_too_far", "finding_not_supported", "invalid_batch",
        }:
            raise HTTPException(status_code=422, detail="Remediation action is invalid.") from exc
        if exc.code in {"batch_state_invalid", "batch_recovery_failed"}:
            raise HTTPException(status_code=503, detail="Remediation batch recovery is temporarily unavailable.") from exc
        raise HTTPException(status_code=503, detail="Remediation workflow is temporarily unavailable.") from exc
    if replayed:
        return RemediationBulkActionResponse(
            group_id=payload.group_id,
            applied_count=len(decisions),
            decisions=decisions,
            replayed=True,
        )
    correlation_id = f"remediation:{uuid4().hex}"
    record_product_action(
        request,
        "remediation.batch_recorded",
        resource_type="remediation_group",
        resource_id=payload.group_id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        correlation_id=correlation_id,
        metadata={"applied_count": len(decisions), "decision_status": payload.status},
    )
    log_audit_event(
        "remediation.batch_recorded",
        correlation_id=correlation_id,
        owner_id=organization_id,
        group_id=payload.group_id,
        applied_count=len(decisions),
        decision_status=payload.status,
        actor_id=actor_id,
        actor_role=actor_role,
    )
    return RemediationBulkActionResponse(
        group_id=payload.group_id,
        applied_count=len(decisions),
        decisions=decisions,
        replayed=False,
    )


@app.get("/remediation/views", response_model=RemediationSavedViewPage)
async def list_remediation_saved_views(request: Request, response: Response) -> RemediationSavedViewPage:
    if automation_principal_for_request(request) is not None:
        raise HTTPException(status_code=403, detail="Interactive user session required.")
    organization_id = current_owner_id_for_request(request)
    actor_id, _username, _role = finding_decision_actor(request)
    try:
        result = request.app.state.remediation_saved_views.list_visible(organization_id, actor_id)
    except RemediationSavedViewError as exc:
        raise _remediation_saved_view_http_error(exc) from exc
    response.headers["Cache-Control"] = "private, no-store"
    return result


@app.post(
    "/remediation/views",
    response_model=RemediationSavedViewRecord,
    status_code=status.HTTP_201_CREATED,
)
async def create_remediation_saved_view(
    request: Request,
    response: Response,
    payload: RemediationSavedViewCreateRequest,
) -> RemediationSavedViewRecord:
    if automation_principal_for_request(request) is not None:
        raise HTTPException(status_code=403, detail="Interactive user session required.")
    organization_id = current_owner_id_for_request(request)
    actor_id, _username, actor_role = finding_decision_actor(request)
    try:
        record = request.app.state.remediation_saved_views.create(
            organization_id,
            actor_id,
            payload,
            can_share=team_role_allows(actor_role, "project_mutate"),
        )
    except RemediationSavedViewError as exc:
        raise _remediation_saved_view_http_error(exc) from exc
    record_product_action(
        request,
        "remediation.view_created",
        resource_type="remediation_view",
        resource_id=record.id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={"filter_applied": True},
    )
    response.headers["Cache-Control"] = "private, no-store"
    return record


@app.put("/remediation/views/default", response_model=RemediationSavedViewPage)
async def set_default_remediation_saved_view(
    request: Request,
    response: Response,
    payload: RemediationSavedViewDefaultRequest,
) -> RemediationSavedViewPage:
    if automation_principal_for_request(request) is not None:
        raise HTTPException(status_code=403, detail="Interactive user session required.")
    organization_id = current_owner_id_for_request(request)
    actor_id, _username, actor_role = finding_decision_actor(request)
    try:
        result = request.app.state.remediation_saved_views.set_default(
            organization_id, actor_id, payload.view_id
        )
    except RemediationSavedViewError as exc:
        raise _remediation_saved_view_http_error(exc) from exc
    record_product_action(
        request,
        "remediation.view_default_changed",
        resource_type="remediation_view",
        resource_id=payload.view_id or "none",
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={"changed": True},
    )
    response.headers["Cache-Control"] = "private, no-store"
    return result


@app.delete("/remediation/views/{view_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_remediation_saved_view(request: Request, view_id: str) -> Response:
    if automation_principal_for_request(request) is not None:
        raise HTTPException(status_code=403, detail="Interactive user session required.")
    organization_id = current_owner_id_for_request(request)
    actor_id, _username, actor_role = finding_decision_actor(request)
    try:
        deleted = request.app.state.remediation_saved_views.delete(organization_id, actor_id, view_id)
    except RemediationSavedViewError as exc:
        raise _remediation_saved_view_http_error(exc) from exc
    record_product_action(
        request,
        "remediation.view_deleted",
        resource_type="remediation_view",
        resource_id=deleted.id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"Cache-Control": "private, no-store"})


def _remediation_saved_view_http_error(exc: RemediationSavedViewError) -> HTTPException:
    if exc.code == "share_forbidden":
        return HTTPException(status_code=403, detail="Maintainer role required to share a saved view.")
    if exc.code in {"view_not_found", "invalid_view"}:
        return HTTPException(status_code=404, detail="Saved remediation view not found.")
    if exc.code in {"view_limit", "name_conflict"}:
        return HTTPException(status_code=409, detail="Saved remediation view cannot be created in its current state.")
    if exc.code in {"store_invalid", "store_unavailable"}:
        return HTTPException(status_code=503, detail="Saved remediation views are temporarily unavailable.")
    return HTTPException(status_code=422, detail="Saved remediation view is invalid.")


@app.post("/remediation/report")
async def export_remediation_report(
    request: Request,
    payload: RemediationReportRequest,
) -> Response:
    """Export a bounded owner-scoped plan after explicit project-name disclosure consent."""

    organization_id = current_owner_id_for_request(request)
    query = payload.filters.model_copy(update={"page_size": 100, "cursor": None})
    first = request.app.state.remediation_center.search(
        organization_id=organization_id,
        payload=query,
    )
    groups = list(first.items)
    current = first
    while current.next_cursor and len(groups) < REMEDIATION_REPORT_MAX_GROUPS:
        current = request.app.state.remediation_center.search(
            organization_id=organization_id,
            payload=query.model_copy(update={"cursor": current.next_cursor}),
        )
        groups.extend(current.items[: REMEDIATION_REPORT_MAX_GROUPS - len(groups)])
    groups_truncated = bool(current.next_cursor)
    content, media_type, filename, digest = render_remediation_report(
        first,
        groups,
        report_format=payload.report_format,
        groups_truncated=groups_truncated,
    )
    actor_id, _actor_username, actor_role = finding_decision_actor(request)
    record_product_action(
        request,
        "remediation.report_exported",
        resource_type="organization",
        resource_id=organization_id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={
            "report_format": payload.report_format,
            "included_groups": len(groups),
            "groups_truncated": groups_truncated,
        },
    )
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Inspectra-Snapshot-SHA256": digest,
        },
    )


def _remediation_plan_http_error(exc: RemediationPlanJobError) -> HTTPException:
    if exc.code in {"not_found", "artifact_unavailable"}:
        return HTTPException(status_code=404, detail="Remediation plan not found or not ready.")
    if exc.code == "artifact_expired":
        return HTTPException(status_code=410, detail="Remediation plan artifact expired. Create a new plan.")
    if exc.code in {"idempotency_conflict", "invalid_transition", "job_limit"}:
        return HTTPException(status_code=409, detail="Remediation plan state changed. Refresh before retrying.")
    if exc.code == "capacity":
        return HTTPException(status_code=429, detail="Remediation plan capacity is temporarily full.", headers={"Retry-After": "5"})
    if exc.code == "invalid_request":
        return HTTPException(status_code=422, detail="Remediation plan request is invalid.")
    return HTTPException(status_code=503, detail="Remediation plan storage is temporarily unavailable.")


@app.post(
    "/remediation/plans",
    response_model=RemediationPlanJob,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_remediation_plan_job(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    payload: RemediationPlanCreateRequest,
) -> RemediationPlanJob:
    organization_id = current_owner_id_for_request(request)
    try:
        job = request.app.state.remediation_plan_jobs.create(organization_id, payload)
    except RemediationPlanJobError as exc:
        raise _remediation_plan_http_error(exc) from exc
    if job.status == "queued":
        schedule_remediation_plan_once(background_tasks, request.app, organization_id, job.id)
    actor_id, _actor_username, actor_role = finding_decision_actor(request)
    if not job.replayed:
        record_product_action(
            request,
            "remediation.plan_requested",
            resource_type="remediation_plan",
            resource_id=job.id,
            organization_id=organization_id,
            actor_id=actor_id,
            actor_role=actor_role,
            metadata={"filter_applied": True},
        )
    response.headers["Cache-Control"] = "private, no-store"
    return job


@app.get("/remediation/plans", response_model=RemediationPlanJobPage)
async def list_remediation_plan_jobs(request: Request, response: Response) -> RemediationPlanJobPage:
    try:
        result = request.app.state.remediation_plan_jobs.list(current_owner_id_for_request(request))
    except RemediationPlanJobError as exc:
        raise _remediation_plan_http_error(exc) from exc
    response.headers["Cache-Control"] = "private, no-store"
    return result


@app.get("/remediation/plans/{plan_id}", response_model=RemediationPlanJob)
async def get_remediation_plan_job(request: Request, response: Response, plan_id: str) -> RemediationPlanJob:
    try:
        result = request.app.state.remediation_plan_jobs.get(current_owner_id_for_request(request), plan_id)
    except RemediationPlanJobError as exc:
        raise _remediation_plan_http_error(exc) from exc
    response.headers["Cache-Control"] = "private, no-store"
    return result


@app.post("/remediation/plans/{plan_id}/cancel", response_model=RemediationPlanJob)
async def cancel_remediation_plan_job(request: Request, response: Response, plan_id: str) -> RemediationPlanJob:
    organization_id = current_owner_id_for_request(request)
    try:
        result = request.app.state.remediation_plan_jobs.cancel(organization_id, plan_id)
    except RemediationPlanJobError as exc:
        raise _remediation_plan_http_error(exc) from exc
    response.headers["Cache-Control"] = "private, no-store"
    return result


@app.post(
    "/remediation/plans/{plan_id}/retry",
    response_model=RemediationPlanJob,
    status_code=status.HTTP_202_ACCEPTED,
)
async def retry_remediation_plan_job(
    request: Request,
    response: Response,
    background_tasks: BackgroundTasks,
    plan_id: str,
    payload: RemediationPlanRetryRequest,
) -> RemediationPlanJob:
    organization_id = current_owner_id_for_request(request)
    try:
        result = request.app.state.remediation_plan_jobs.retry(organization_id, plan_id, payload)
    except RemediationPlanJobError as exc:
        raise _remediation_plan_http_error(exc) from exc
    if result.status == "queued":
        schedule_remediation_plan_once(background_tasks, request.app, organization_id, result.id)
    response.headers["Cache-Control"] = "private, no-store"
    return result


@app.get("/remediation/plans/{plan_id}/download")
async def download_remediation_plan(
    request: Request,
    plan_id: str,
    report_format: Literal["json", "csv"] = Query(alias="format"),
) -> Response:
    organization_id = current_owner_id_for_request(request)
    try:
        job, artifact = request.app.state.remediation_plan_jobs.artifact(organization_id, plan_id)
        content, media_type, filename = render_durable_remediation_plan(
            artifact, report_format=report_format
        )
    except RemediationPlanJobError as exc:
        raise _remediation_plan_http_error(exc) from exc
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="Remediation plan rendering is temporarily unavailable.") from exc
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Inspectra-Snapshot-SHA256": job.snapshot_sha256 or "",
        },
    )
@app.get("/projects/{project_id}", response_model=ProjectSummary)
async def get_project(request: Request, project_id: str) -> ProjectSummary:
    return project_summary(get_project_for_current_owner(request, project_id), request.app.state.jobs)


@app.get("/projects/{project_id}/deletion", response_model=ProjectDeletionPreview)
async def get_project_deletion_preview(request: Request, project_id: str) -> ProjectDeletionPreview:
    """Disclose the exact local cascade before requiring confirmation."""

    try:
        return request.app.state.project_deletions.preview(
            organization_id=current_owner_id_for_request(request),
            project_id=project_id,
        )
    except ProjectDeletionError as exc:
        if exc.code == "not_found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.") from exc
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Project deletion state is unavailable.") from exc


@app.delete("/projects/{project_id}", response_model=ProjectDeletionResponse)
async def delete_project(
    request: Request,
    project_id: str,
    payload: ProjectDeletionRequest,
) -> ProjectDeletionResponse:
    """Apply or resume an owner-scoped project cascade after explicit consent."""

    del payload  # Pydantic has already enforced the literal confirmation contract.
    organization_id = current_owner_id_for_request(request)
    try:
        result = request.app.state.project_deletions.delete(
            organization_id=organization_id,
            project_id=project_id,
        )
    except ProjectDeletionError as exc:
        if exc.code == "active_work":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cancel the active project analysis and wait for a terminal state before deleting this project.",
            ) from exc
        if exc.code == "not_found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.") from exc
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Project deletion did not complete. Its safe retry state was retained; try again after checking service health.",
        ) from exc
    record_product_action(
        request,
        "project.deleted" if result.state == "completed" else "project.delete_noop",
        resource_type="project",
        resource_id=project_id,
        organization_id=organization_id,
        metadata={"deletion_contract": result.contract_version, "deletion_state": result.state},
    )
    return result


@app.get("/projects/{project_id}/analyses", response_model=list[JobListItem], deprecated=True)
async def list_project_analyses(
    request: Request, project_id: str, response: Response
) -> list[JobListItem]:
    project = get_project_for_current_owner(request, project_id)
    response.headers.update(
        {
            "Deprecation": "true",
            "Sunset": "Tue, 01 Dec 2026 00:00:00 GMT",
            "Link": f'</projects/{project.id}/analyses/search>; rel="successor-version"',
            "Cache-Control": "no-store",
        }
    )
    items, _total, _next_cursor = request.app.state.jobs.page(
        owner_id=project.owner_id, project_id=project.id, page_size=100
    )
    return items


@app.post("/projects/{project_id}/analyses/search", response_model=JobPage)
async def page_project_analyses(
    request: Request, project_id: str, payload: JobPageRequest
) -> JobPage:
    project = get_project_for_current_owner(request, project_id)
    if payload.project_id is not None and payload.project_id != project.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Project analysis filter does not match the requested project.",
        )
    items, total, next_cursor = request.app.state.jobs.page(
        owner_id=project.owner_id,
        project_id=project.id,
        page_size=payload.page_size,
        cursor=payload.cursor,
        status_filter=payload.status,
        audit_type=payload.audit_type,
    )
    return JobPage(
        items=items,
        returned_count=len(items),
        total_count=total,
        has_more=next_cursor is not None,
        next_cursor=next_cursor,
    )


@app.get("/projects/{project_id}/analyses/{analysis_id}", response_model=JobListItem)
async def get_project_analysis_summary(
    request: Request, project_id: str, analysis_id: str
) -> JobListItem:
    """Resolve one retained analysis without exposing its full result payload."""

    project = get_project_for_current_owner(request, project_id)
    analysis = project_analysis_for_project(request, project, analysis_id)
    return request.app.state.jobs.get_list_item(analysis.id)


@app.post("/projects/{project_id}/baseline", response_model=ProjectView)
async def set_project_baseline(
    request: Request,
    project_id: str,
    payload: ProjectBaselineSetRequest,
) -> ProjectRecord:
    """Make one completed, profiled project analysis the explicit regression baseline."""

    project = get_project_for_current_owner(request, project_id)
    analysis = project_analysis_for_project(request, project, payload.analysis_id)
    if analysis.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Only a completed project analysis can become the saved baseline.",
        )
    if analysis.execution_profile is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This legacy analysis has no recorded execution profile. Run its retained snapshot again before setting a baseline.",
        )
    previous_baseline_id = project.baseline_analysis_id
    updated = request.app.state.projects.set_baseline(project.id, analysis.id)
    if updated.baseline_analysis_id != previous_baseline_id:
        log_audit_event(
            "project.baseline.set",
            correlation_id=f"project:{updated.id}:baseline:{updated.baseline_version}",
            project_id=updated.id,
            owner_id=updated.owner_id,
            baseline_analysis_id=analysis.id,
            baseline_version=updated.baseline_version,
            analysis_profile=analysis.execution_profile.profile_name,
        )
        record_product_action(
            request,
            "project.baseline_set",
            resource_type="project",
            resource_id=updated.id,
            organization_id=updated.owner_id,
            metadata={
                "analysis_id": analysis.id,
                "baseline_version": updated.baseline_version,
                "analysis_profile": analysis.execution_profile.profile_name,
            },
        )
    return updated


@app.delete("/projects/{project_id}/baseline", response_model=ProjectView)
async def clear_project_baseline(request: Request, project_id: str) -> ProjectRecord:
    """Remove the saved policy only; the retained analysis and its result remain unchanged."""

    project = get_project_for_current_owner(request, project_id)
    updated = request.app.state.projects.clear_baseline(project.id)
    log_audit_event(
        "project.baseline.cleared",
        correlation_id=f"project:{updated.id}:baseline:{updated.baseline_version}",
        project_id=updated.id,
        owner_id=updated.owner_id,
        baseline_version=updated.baseline_version,
        reason="operator_cleared",
    )
    record_product_action(
        request,
        "project.baseline_cleared",
        resource_type="project",
        resource_id=updated.id,
        organization_id=updated.owner_id,
        metadata={"baseline_version": updated.baseline_version},
    )
    return updated


@app.get("/projects/{project_id}/findings", response_model=ProjectFindingsResponse)
async def get_project_findings(
    request: Request,
    project_id: str,
    analysis_id: str | None = None,
) -> ProjectFindingsResponse:
    project = get_project_for_current_owner(request, project_id)
    return project_findings_response(request, project, analysis_id)


@app.post(
    "/projects/{project_id}/findings/{finding_id}/decisions",
    response_model=FindingDecisionRecord,
    status_code=status.HTTP_201_CREATED,
)
async def create_project_finding_decision(
    request: Request,
    project_id: str,
    finding_id: str,
    payload: FindingDecisionCreateRequest,
) -> FindingDecisionRecord:
    """Append one scoped triage decision without modifying analyzer evidence."""

    project = get_project_for_current_owner(request, project_id)
    analysis = project_analysis_for_project(request, project, payload.analysis_id)
    if analysis.status != "completed":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A finding can be reviewed after its analysis completes.")
    findings = normalized_findings_for_analysis(analysis)
    local_finding = next((item for item in findings or [] if item.id == finding_id), None)
    public_finding = None
    if local_finding is None:
        snapshot = request.app.state.project_vulnerability_intelligence_store.get(analysis.id)
        raw_public = snapshot.get("findings") if isinstance(snapshot, dict) else None
        if isinstance(raw_public, list) and len(raw_public) <= 10_000:
            try:
                public_finding = next(
                    (
                        item
                        for raw in raw_public
                        if (item := ProjectVulnerabilityFinding.model_validate(raw)).id == finding_id
                    ),
                    None,
                )
            except ValidationError as exc:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="This analysis has no compatible public findings to review.",
                ) from exc
    if local_finding is None and public_finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found for this project analysis.")
    resolved_finding_id = local_finding.id if local_finding is not None else public_finding.id
    resolved_rule_id = (
        local_finding.rule_id
        if local_finding is not None
        else public_vulnerability_rule_id(public_finding)
    )

    actor_id, actor_username, actor_role = finding_decision_actor(request)
    assignee_user_id, assignee_username = finding_decision_assignee(request, payload.assignee_user_id)
    organization_id = project.organization_id or project.owner_id
    if not organization_id:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Finding lifecycle is unavailable.")
    try:
        decision = request.app.state.finding_decisions.record(
            organization_id=organization_id,
            project_id=project.id,
            finding_id=resolved_finding_id,
            rule_id=resolved_rule_id,
            status=payload.status,
            reason=payload.reason,
            comment=payload.comment,
            actor_id=actor_id,
            actor_username=actor_username,
            actor_role=actor_role,
            review_at=payload.review_at,
            assignee_user_id=assignee_user_id,
            assignee_username=assignee_username,
        )
    except FindingLifecycleError as exc:
        if exc.code == "invalid_transition":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This lifecycle transition is not allowed. Reopen the finding before applying that decision.",
            ) from exc
        if exc.code in {"finding_decision_limit", "project_decision_limit", "store_limit"}:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Finding decision history reached its configured limit.") from exc
        if exc.code in {
            "reason_required",
            "invalid_text",
            "invalid_assignee",
            "review_date_required",
            "review_date_not_allowed",
            "review_date_not_future",
            "review_date_timezone_required",
            "review_date_too_far",
            "finding_not_supported",
        }:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Finding decision is invalid.") from exc
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Finding lifecycle is unavailable.") from exc
    log_audit_event(
        "project.finding.decision_recorded",
        correlation_id=f"decision:{decision.id}",
        project_id=project.id,
        owner_id=organization_id,
        finding_id=resolved_finding_id,
        rule_id=resolved_rule_id,
        decision_status=decision.status,
        actor_id=actor_id,
        actor_role=actor_role,
        assignee_set=assignee_user_id is not None,
        review_at=decision.review_at.isoformat() if decision.review_at else None,
    )
    record_product_action(
        request,
        "finding.decision_recorded",
        resource_type="finding",
        resource_id=resolved_finding_id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        correlation_id=f"decision:{decision.id}",
        metadata={"project_id": project.id, "decision_status": decision.status},
    )
    return decision


@app.get("/projects/{project_id}/components", response_model=ProjectComponentInventoryResponse)
async def get_project_component_inventory(
    request: Request,
    project_id: str,
    analysis_id: str | None = None,
) -> ProjectComponentInventoryResponse:
    project = get_project_for_current_owner(request, project_id)
    return project_component_inventory_response(request, project, analysis_id)


@app.get(
    "/projects/{project_id}/analyses/{analysis_id}/vulnerability-intelligence",
    response_model=ProjectVulnerabilityIntelligenceResponse,
)
async def get_project_vulnerability_intelligence(
    request: Request,
    project_id: str,
    analysis_id: str,
    snapshot_id: str | None = None,
) -> ProjectVulnerabilityIntelligenceResponse:
    project = get_project_for_current_owner(request, project_id)
    return project_vulnerability_intelligence_response(request, project, analysis_id, snapshot_id=snapshot_id)


@app.post(
    "/projects/{project_id}/analyses/{analysis_id}/vulnerability-intelligence/osv",
    response_model=ProjectVulnerabilityIntelligenceResponse,
)
async def run_project_osv_vulnerability_intelligence(
    request: Request,
    project_id: str,
    analysis_id: str,
) -> ProjectVulnerabilityIntelligenceResponse:
    """Run only the opt-in, bounded OSV correlation for an exact inventory."""

    project = get_project_for_current_owner(request, project_id)
    analysis = project_analysis_for_project(request, project, analysis_id)
    if analysis.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Vulnerability intelligence is available after the selected project analysis completes.",
        )
    source_result = analysis.result if isinstance(analysis.result, dict) else {}
    if not isinstance(source_result.get("component_inventory"), list):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This project analysis has no compatible component inventory. Run the retained snapshot again first.",
        )
    service = request.app.state.project_vulnerability_intelligence
    store = request.app.state.project_vulnerability_intelligence_store
    previous_snapshot = store.get(analysis.id)
    namespace_policy, organization_authorizer = public_advisory_policy_for_owner(
        request,
        project.owner_id,
    )
    try:
        snapshot = await asyncio.to_thread(
            service.correlate,
            analysis,
            namespace_policy=namespace_policy,
            organization_authorizer=organization_authorizer,
        )
        snapshot = service.retain_previous_on_degraded_refresh(previous_snapshot, snapshot)
        store.put(analysis.id, snapshot, organization_id=project.owner_id)
    except Exception:
        # A provider, cache, or storage exception must not leak through the API
        # and must never be represented as clean advisory coverage.
        snapshot = service.controlled_failure(analysis, namespace_policy=namespace_policy)
        snapshot = service.retain_previous_on_degraded_refresh(previous_snapshot, snapshot)
        try:
            store.put(analysis.id, snapshot, organization_id=project.owner_id)
        except OSError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Vulnerability intelligence could not be stored. Retry after reviewing service health.",
            ) from None
    log_audit_event(
        "public_advisory.snapshot",
        provider="osv",
        state=snapshot.get("state"),
        finding_count=snapshot.get("summary", {}).get("findings") if isinstance(snapshot.get("summary"), dict) else None,
    )
    record_product_action(
        request,
        "vulnerability_intelligence.refreshed",
        resource_type="analysis",
        resource_id=analysis.id,
        organization_id=project.owner_id,
        metadata={
            "project_id": project.id,
            "provider": "osv",
            "source_state": snapshot.get("state"),
            "finding_count": snapshot.get("summary", {}).get("findings") if isinstance(snapshot.get("summary"), dict) else None,
        },
    )
    return project_vulnerability_intelligence_response(request, project, analysis.id)


@app.post(
    "/projects/{project_id}/analyses/{analysis_id}/vulnerability-intelligence/github",
    response_model=ProjectVulnerabilityIntelligenceResponse,
)
async def run_project_github_vulnerability_intelligence(
    request: Request,
    project_id: str,
    analysis_id: str,
) -> ProjectVulnerabilityIntelligenceResponse:
    """Corroborate GHSA aliases already retained by an OSV snapshot only."""

    project = get_project_for_current_owner(request, project_id)
    analysis = project_analysis_for_project(request, project, analysis_id)
    if analysis.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="GitHub advisory corroboration is available after the selected project analysis completes.",
        )
    if (
        not request.app.state.public_advisory_egress_client.enabled
        and not request.app.state.public_advisory_egress_client.has_active_offline_provider("github_advisories")
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Public advisory egress is disabled for this deployment.",
        )
    store = request.app.state.project_vulnerability_intelligence_store
    snapshot = store.get(analysis.id)
    if not isinstance(snapshot, dict) or snapshot.get("state") not in {"ready", "stale", "degraded"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Run the OSV check for this completed analysis before corroborating GitHub advisories.",
        )
    service = request.app.state.project_vulnerability_intelligence
    try:
        updated_snapshot = await asyncio.to_thread(service.corroborate_github, snapshot)
        store.put(analysis.id, updated_snapshot, organization_id=project.owner_id)
    except Exception:
        updated_snapshot = service.controlled_github_failure(snapshot)
        try:
            store.put(analysis.id, updated_snapshot, organization_id=project.owner_id)
        except OSError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="GitHub advisory intelligence could not be stored. Retry after reviewing service health.",
            ) from None
    log_audit_event(
        "public_advisory.snapshot",
        provider="github_advisories",
        state=updated_snapshot.get("state"),
        finding_count=updated_snapshot.get("summary", {}).get("github_corroborated")
        if isinstance(updated_snapshot.get("summary"), dict)
        else None,
    )
    record_product_action(
        request,
        "vulnerability_intelligence.refreshed",
        resource_type="analysis",
        resource_id=analysis.id,
        organization_id=project.owner_id,
        metadata={
            "project_id": project.id,
            "provider": "github_advisories",
            "source_state": updated_snapshot.get("state"),
            "finding_count": updated_snapshot.get("summary", {}).get("github_corroborated")
            if isinstance(updated_snapshot.get("summary"), dict)
            else None,
        },
    )
    return project_vulnerability_intelligence_response(request, project, analysis.id)


@app.post(
    "/projects/{project_id}/analyses/{analysis_id}/vulnerability-intelligence/nvd",
    response_model=ProjectVulnerabilityIntelligenceResponse,
)
async def run_project_nvd_vulnerability_intelligence(
    request: Request,
    project_id: str,
    analysis_id: str,
) -> ProjectVulnerabilityIntelligenceResponse:
    """Enrich exact CVEs already retained; never infer package applicability from CPE."""

    project = get_project_for_current_owner(request, project_id)
    analysis = project_analysis_for_project(request, project, analysis_id)
    if analysis.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="NVD enrichment is available after the selected project analysis completes.",
        )
    client = request.app.state.public_advisory_egress_client
    if not (client.enabled and client.nvd_enabled) and not client.has_active_offline_provider("nvd"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="NVD enrichment is disabled for this deployment.",
        )
    store = request.app.state.project_vulnerability_intelligence_store
    snapshot = store.get(analysis.id)
    if not isinstance(snapshot, dict) or snapshot.get("state") not in {"ready", "stale", "degraded"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Run the OSV check for this completed analysis before enriching exact CVEs with NVD.",
        )
    service = request.app.state.project_vulnerability_intelligence
    try:
        updated_snapshot = await asyncio.to_thread(service.enrich_nvd, snapshot)
        store.put(analysis.id, updated_snapshot, organization_id=project.owner_id)
    except Exception:
        updated_snapshot = service.controlled_nvd_failure(snapshot)
        try:
            store.put(analysis.id, updated_snapshot, organization_id=project.owner_id)
        except OSError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="NVD intelligence could not be stored. Retry after reviewing service health.",
            ) from None
    log_audit_event(
        "public_advisory.snapshot",
        provider="nvd",
        state=updated_snapshot.get("state"),
        finding_count=updated_snapshot.get("summary", {}).get("nvd_enriched")
        if isinstance(updated_snapshot.get("summary"), dict) else None,
    )
    record_product_action(
        request,
        "vulnerability_intelligence.refreshed",
        resource_type="analysis",
        resource_id=analysis.id,
        organization_id=project.owner_id,
        metadata={
            "project_id": project.id,
            "provider": "nvd",
            "source_state": updated_snapshot.get("state"),
            "finding_count": updated_snapshot.get("summary", {}).get("nvd_enriched")
            if isinstance(updated_snapshot.get("summary"), dict) else None,
        },
    )
    return project_vulnerability_intelligence_response(request, project, analysis.id)


@app.post(
    "/projects/{project_id}/analyses/{analysis_id}/vulnerability-intelligence/cisa-kev",
    response_model=ProjectVulnerabilityIntelligenceResponse,
)
async def run_project_cisa_kev_vulnerability_intelligence(
    request: Request,
    project_id: str,
    analysis_id: str,
) -> ProjectVulnerabilityIntelligenceResponse:
    """Attach CISA KEV only to exact CVEs already in a stored OSV snapshot."""

    project = get_project_for_current_owner(request, project_id)
    analysis = project_analysis_for_project(request, project, analysis_id)
    if analysis.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="CISA KEV correlation is available after the selected project analysis completes.",
        )
    if (
        not request.app.state.public_advisory_egress_client.enabled
        and not request.app.state.public_advisory_egress_client.has_active_offline_provider("cisa_kev")
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Public advisory egress is disabled for this deployment.",
        )
    store = request.app.state.project_vulnerability_intelligence_store
    snapshot = store.get(analysis.id)
    if not isinstance(snapshot, dict) or snapshot.get("state") not in {"ready", "stale", "degraded"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Run the OSV check for this completed analysis before checking CISA KEV.",
        )
    service = request.app.state.project_vulnerability_intelligence
    try:
        updated_snapshot = await asyncio.to_thread(service.correlate_cisa_kev, snapshot)
        store.put(analysis.id, updated_snapshot, organization_id=project.owner_id)
    except Exception:
        updated_snapshot = service.controlled_cisa_kev_failure(snapshot)
        try:
            store.put(analysis.id, updated_snapshot, organization_id=project.owner_id)
        except OSError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="CISA KEV intelligence could not be stored. Retry after reviewing service health.",
            ) from None
    log_audit_event(
        "public_advisory.snapshot",
        provider="cisa_kev",
        state=updated_snapshot.get("state"),
        finding_count=updated_snapshot.get("summary", {}).get("cisa_kev_known_exploited")
        if isinstance(updated_snapshot.get("summary"), dict)
        else None,
    )
    record_product_action(
        request,
        "vulnerability_intelligence.refreshed",
        resource_type="analysis",
        resource_id=analysis.id,
        organization_id=project.owner_id,
        metadata={
            "project_id": project.id,
            "provider": "cisa_kev",
            "source_state": updated_snapshot.get("state"),
            "finding_count": updated_snapshot.get("summary", {}).get("cisa_kev_known_exploited")
            if isinstance(updated_snapshot.get("summary"), dict)
            else None,
        },
    )
    return project_vulnerability_intelligence_response(request, project, analysis.id)


@app.get("/projects/{project_id}/comparisons", response_model=ProjectAnalysisComparisonResponse)
async def get_project_analysis_comparison(
    request: Request,
    project_id: str,
    base_analysis_id: str,
    target_analysis_id: str,
) -> ProjectAnalysisComparisonResponse:
    project = get_project_for_current_owner(request, project_id)
    return project_analysis_comparison_response(request, project, base_analysis_id, target_analysis_id)


@app.get("/projects/{project_id}/analyses/{analysis_id}/report/{report_format}")
async def export_project_analysis_report(
    request: Request,
    project_id: str,
    analysis_id: str,
    report_format: Literal["markdown", "html", "pdf"],
    vulnerability_snapshot_id: str | None = None,
) -> Response:
    return await build_project_analysis_report_response(
        request,
        project_id,
        analysis_id,
        report_format,
        vulnerability_snapshot_id=vulnerability_snapshot_id,
        report_profile="minimal",
    )


async def build_project_analysis_report_response(
    request: Request,
    project_id: str,
    analysis_id: str,
    report_format: Literal["markdown", "html", "pdf"],
    *,
    vulnerability_snapshot_id: str | None,
    report_profile: Literal["minimal", "technical"],
) -> Response:
    project = get_project_for_current_owner(request, project_id)
    analysis = project_analysis_for_project(request, project, analysis_id)
    if analysis.status != "completed":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A project report is available after the selected analysis completes.")
    findings = normalized_findings_for_analysis(analysis)
    if findings is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This project analysis has no compatible normalized findings for a project report.",
        )
    result = analysis.result if isinstance(analysis.result, dict) else {}
    summary = result.get("summary")
    result_truncated = bool(summary.get("truncated")) if isinstance(summary, dict) else False
    vulnerability_intelligence = project_vulnerability_intelligence_response(
        request,
        project,
        analysis.id,
        snapshot_id=vulnerability_snapshot_id,
    )
    finding_lifecycle = finding_lifecycle_for_project(request, project, findings)
    responsibility_state, responsible_username = project_responsibility_for_report(
        request, project
    )
    if report_format == "markdown":
        response = export_response(
            render_project_markdown_report(
                project,
                analysis,
                findings,
                result_truncated=result_truncated,
                vulnerability_intelligence=vulnerability_intelligence,
                finding_lifecycle=finding_lifecycle,
                project_responsibility_state=responsibility_state,
                project_responsible_username=responsible_username,
                profile=report_profile,
            ),
            "text/markdown; charset=utf-8",
            "inspectra-project-report.md"
            if report_profile == "minimal"
            else build_project_report_filename(project, analysis, "md"),
        )
    elif report_format == "html":
        response = export_response(
            render_project_html_report(
                project,
                analysis,
                findings,
                result_truncated=result_truncated,
                vulnerability_intelligence=vulnerability_intelligence,
                finding_lifecycle=finding_lifecycle,
                project_responsibility_state=responsibility_state,
                project_responsible_username=responsible_username,
                profile=report_profile,
            ),
            "text/html; charset=utf-8",
            "inspectra-project-report.html"
            if report_profile == "minimal"
            else build_project_report_filename(project, analysis, "html"),
        )
    else:
        response = export_response(
            render_project_pdf_report(
                project,
                analysis,
                findings,
                result_truncated=result_truncated,
                vulnerability_intelligence=vulnerability_intelligence,
                finding_lifecycle=finding_lifecycle,
                project_responsibility_state=responsibility_state,
                project_responsible_username=responsible_username,
                profile=report_profile,
            ),
            "application/pdf",
            "inspectra-project-report.pdf"
            if report_profile == "minimal"
            else build_project_report_filename(project, analysis, "pdf"),
        )
    response.headers["Cache-Control"] = "private, no-store"
    record_product_action(
        request,
        "project.report_exported",
        resource_type="analysis",
        resource_id=analysis.id,
        organization_id=project.owner_id,
        metadata={
            "project_id": project.id,
            "report_format": report_format,
            "report_profile": report_profile,
        },
    )
    return response


@app.post("/projects/{project_id}/analyses/{analysis_id}/report/{report_format}")
async def export_project_analysis_technical_report(
    request: Request,
    project_id: str,
    analysis_id: str,
    report_format: Literal["markdown", "html", "pdf"],
    payload: ProjectTechnicalReportRequest,
) -> Response:
    """Export detail only through an explicit, CSRF-protected disclosure request."""

    return await build_project_analysis_report_response(
        request,
        project_id,
        analysis_id,
        report_format,
        vulnerability_snapshot_id=payload.vulnerability_snapshot_id,
        report_profile="technical",
    )


@app.post("/projects/{project_id}/analyses", response_model=JobListItem, status_code=status.HTTP_202_ACCEPTED)
async def launch_project_analysis(
    request: Request,
    project_id: str,
    background_tasks: BackgroundTasks,
    payload: ProjectAnalysisCreateRequest | None = Body(default=None),
) -> JobListItem:
    """Queue a repeat only for the project's currently retained source snapshot."""

    project = get_project_for_current_owner(request, project_id)
    source = source_for_project_analysis(request, project)
    if request.app.state.jobs.has_active_project_job(project.id, owner_id=project.owner_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Project already has an active analysis. Wait for it to finish before running the same snapshot again.",
        )
    retry_of_job_id: str | None = None
    if payload is not None and payload.retry_of_analysis_id is not None:
        previous = project_analysis_for_project(request, project, payload.retry_of_analysis_id)
        if previous.status not in {"failed", "cancelled"}:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Only a failed or cancelled analysis can be retried explicitly.",
            )
        if previous.source_sha256 != project.source_sha256:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The selected retry does not belong to the project's current retained snapshot.",
            )
        retry_of_job_id = previous.id
    is_sbom = source.kind == "manifest" and source.original_filename == "sbom.json"
    if is_sbom:
        normalized = request.app.state.files.read_normalized_sbom(source.id, owner_id=project.owner_id)
        try:
            result = sbom_project_result(normalized)
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Normalized SBOM contract is invalid.") from exc
        job = request.app.state.jobs.create_sbom_import_job(
            source.id,
            owner_id=project.owner_id,
            project_id=project.id,
            source_sha256=project.source_sha256,
            retry_of_job_id=retry_of_job_id,
        )
        request.app.state.jobs.update(job.id, status="running")
        job = request.app.state.jobs.update(
            job.id,
            status="completed",
            result=result,
            termination_reason="completed",
        )
    else:
        job = request.app.state.jobs.create_project_archive_job(
            source.id,
            owner_id=project.owner_id,
            project_id=project.id,
            source_sha256=project.source_sha256,
            retry_of_job_id=retry_of_job_id,
        )
    request.app.state.projects.attach_job(project.id, job.id)
    log_audit_event(
        "project.analysis.queued",
        correlation_id=f"job:{job.id}",
        project_id=project.id,
        job_id=job.id,
        owner_id=project.owner_id,
        analysis_profile=job.analysis_profile,
        retry_of_job_id=job.retry_of_job_id,
    )
    record_product_action(
        request,
        "project.analysis_queued",
        resource_type="analysis",
        resource_id=job.id,
        organization_id=project.owner_id,
        metadata={
            "project_id": project.id,
            "analysis_profile": job.analysis_profile,
            "execution_contract_version": job.execution_profile.contract_version if job.execution_profile else None,
            "retry": job.retry_of_job_id is not None,
        },
    )
    if not is_sbom:
        schedule_bounded_audit(background_tasks, request.app, request.app.state.project_archive_audits.run_project_archive_analysis, job.id)
    return request.app.state.jobs.get_list_item(job.id)


@app.post(
    "/projects/{project_id}/analyses/{analysis_id}/cancel",
    response_model=JobListItem,
    status_code=status.HTTP_202_ACCEPTED,
)
async def cancel_project_analysis(request: Request, project_id: str, analysis_id: str) -> JobListItem:
    """Cooperatively cancel one owner-scoped local project analysis."""

    project = get_project_for_current_owner(request, project_id)
    analysis = project_analysis_for_project(request, project, analysis_id)
    if analysis.audit_type != "project_archive_basic":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This analysis does not support project cancellation.")
    updated = request.app.state.jobs.request_cancellation(analysis.id, owner_id=project.owner_id)
    events = getattr(request.app.state, "audit_cancellation_events", None)
    cancellation_event = events.get(analysis.id) if isinstance(events, dict) else None
    if cancellation_event is not None:
        cancellation_event.set()
    elif updated.status == "cancelling":
        # No process-local task owns this record. Complete cancellation only
        # after cleaning any orphan workspace, preserving an honest terminal state.
        _finish_cancelled_audit(request.app, analysis.id)
        updated = request.app.state.jobs.get(analysis.id)
    log_audit_event(
        "project.analysis.cancellation_requested",
        correlation_id=f"job:{updated.id}",
        job_id=updated.id,
        project_id=updated.project_id,
        owner_id=updated.owner_id,
    )
    record_product_action(
        request,
        "project.analysis_cancellation_requested",
        resource_type="analysis",
        resource_id=updated.id,
        organization_id=project.owner_id,
        metadata={"project_id": project.id},
    )
    return request.app.state.jobs.get_list_item(updated.id)


@app.post(
    "/projects/{project_id}/ci/snapshots",
    response_model=CiProjectSnapshotCreated,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_ci_project_snapshot(
    request: Request,
    project_id: str,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    commit_sha: str = Form(..., min_length=40, max_length=64, pattern=r"^[a-f0-9]{40,64}$"),
    source_sha256: str = Form(..., min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$"),
    branch: str | None = Form(default=None, max_length=160),
    authorization_confirmed: bool = Form(...),
) -> CiProjectSnapshotCreated:
    """Atomically bind one verified CI archive identity to an existing project."""

    if authorization_confirmed is not True:
        raise HTTPException(status_code=400, detail="Explicit source authorization confirmation is required.")
    project = get_project_for_current_owner(request, project_id)
    normalized_branch: str | None = None
    if branch is not None:
        normalized_branch = branch.strip()
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,159}", normalized_branch)
            or ".." in normalized_branch
            or "//" in normalized_branch
            or normalized_branch.endswith(("/", ".lock"))
        ):
            raise HTTPException(status_code=400, detail="CI branch metadata is invalid.")

    uploaded = await request.app.state.files.save_archive(file, owner_id=project.owner_id)
    if uploaded.sha256 != source_sha256:
        request.app.state.files.delete(uploaded.id, owner_id=project.owner_id)
        raise HTTPException(status_code=409, detail="Uploaded snapshot digest does not match the declared source digest.")

    identity = hashlib.sha256(
        f"inspectra-ci-snapshot-v1\0{project.owner_id}\0{project.id}\0{commit_sha}\0{source_sha256}".encode("ascii")
    ).hexdigest()[:32]
    source_channel = "ci" if automation_principal_for_request(request) is not None else "git_cli"
    try:
        admitted = request.app.state.project_snapshot_admissions.admit(
            project_id=project.id,
            owner_id=project.owner_id,
            source_file_id=uploaded.id,
            idempotency_key=identity,
            source_commit_sha=commit_sha,
            source_branch=normalized_branch,
            equivalent_source_allowed=True,
            source_channel=source_channel,
        )
    except HTTPException as exc:
        # Client/admission conflicts happen before a recovery journal owns the
        # new source. Server failures may have persisted a pending journal, so
        # retain its source for startup recovery instead of corrupting it.
        if exc.status_code < 500:
            request.app.state.files.delete(uploaded.id, owner_id=project.owner_id)
        raise
    if admitted.job.file_id != uploaded.id:
        request.app.state.files.delete(uploaded.id, owner_id=project.owner_id)

    log_audit_event(
        "project.ci_snapshot.replayed" if admitted.replayed else "project.ci_snapshot.queued",
        correlation_id=f"job:{admitted.job.id}",
        project_id=project.id,
        job_id=admitted.job.id,
        owner_id=project.owner_id,
    )
    record_product_action(
        request,
        "project.ci_snapshot_replayed" if admitted.replayed else "project.ci_snapshot_queued",
        resource_type="analysis",
        resource_id=admitted.job.id,
        organization_id=project.owner_id,
        metadata={
            "project_id": project.id,
            "analysis_profile": admitted.job.analysis_profile,
            "source_channel": admitted.snapshot.source_channel or "legacy_unknown",
        },
    )
    if admitted.should_schedule and admitted.job.status == "queued":
        schedule_project_archive_once(background_tasks, request.app, admitted.job.id)
    return CiProjectSnapshotCreated(
        project=admitted.project,
        job=request.app.state.jobs.get_list_item(admitted.job.id),
        snapshot=admitted.snapshot,
        replayed=admitted.replayed,
        commit_sha=commit_sha,
        source_digest_verified=True,
    )


@app.post(
    "/projects/{project_id}/analyses/{analysis_id}/dependency-graphs/go",
    response_model=ProjectDependencyGraphEvidence,
    status_code=status.HTTP_200_OK,
)
async def attach_go_dependency_graph(
    request: Request,
    project_id: str,
    analysis_id: str,
    file: UploadFile = File(...),
    artifact_sha256: str = Form(..., min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$"),
) -> ProjectDependencyGraphEvidence:
    """Bind one bounded CI-produced Go graph to its completed source result."""

    if file.content_type not in {"application/json", "application/octet-stream"}:
        raise HTTPException(status_code=415, detail="Go dependency evidence must be a JSON artifact.")
    project, analysis, source_commit_sha = _dependency_graph_attachment_target(request, project_id, analysis_id)

    payload = await file.read(GO_DEPENDENCY_GRAPH_MAX_BYTES + 1)
    try:
        artifact, digest = parse_go_dependency_graph_artifact(
            payload,
            declared_sha256=artifact_sha256,
            expected_commit_sha=source_commit_sha,
            expected_source_sha256=analysis.source_sha256,
        )
    except GoDependencyGraphError as exc:
        if exc.code == "artifact_size_invalid":
            raise HTTPException(status_code=413, detail="Go dependency evidence exceeds its fixed size limit.") from exc
        if exc.code in {"artifact_digest_mismatch", "source_commit_mismatch", "source_digest_mismatch"}:
            raise HTTPException(status_code=409, detail="Go dependency evidence does not match the selected source.") from exc
        raise HTTPException(status_code=422, detail="Go dependency evidence does not match the supported contract.") from exc

    updated = request.app.state.jobs.attach_go_dependency_graph(
        analysis.id,
        owner_id=project.owner_id,
        project_id=project.id,
        artifact=artifact,
        artifact_sha256=digest,
    )
    receipt = updated.result.get("dependency_graph_evidence") if isinstance(updated.result, dict) else None
    try:
        response = ProjectDependencyGraphEvidence.model_validate(receipt)
    except ValidationError as exc:  # pragma: no cover - store contract is tested directly.
        raise HTTPException(status_code=500, detail="Dependency evidence could not be persisted safely.") from exc
    record_product_action(
        request,
        "project.dependency_graph_attached",
        resource_type="analysis",
        resource_id=analysis.id,
        organization_id=project.owner_id,
        metadata={
            "project_id": project.id,
            "ecosystem": "go",
            "state": response.state,
            "nodes_reported": response.nodes_reported,
            "edges_reported": response.edges_reported,
        },
    )
    log_audit_event(
        "project.dependency_graph.attached",
        correlation_id=f"job:{analysis.id}",
        project_id=project.id,
        job_id=analysis.id,
        owner_id=project.owner_id,
        ecosystem="go",
        graph_state=response.state,
        nodes_reported=response.nodes_reported,
        edges_reported=response.edges_reported,
    )
    return response


@app.post(
    "/projects/{project_id}/analyses/{analysis_id}/dependency-graphs/cargo",
    response_model=CargoProjectDependencyGraphEvidence,
    status_code=status.HTTP_200_OK,
)
async def attach_cargo_dependency_graph(
    request: Request,
    project_id: str,
    analysis_id: str,
    file: UploadFile = File(...),
    artifact_sha256: str = Form(..., min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$"),
) -> CargoProjectDependencyGraphEvidence:
    """Bind one bounded CI-produced Cargo graph to its completed source result."""

    if file.content_type not in {"application/json", "application/octet-stream"}:
        raise HTTPException(status_code=415, detail="Cargo dependency evidence must be a JSON artifact.")
    project, analysis, source_commit_sha = _dependency_graph_attachment_target(request, project_id, analysis_id)

    payload = await file.read(CARGO_DEPENDENCY_GRAPH_MAX_BYTES + 1)
    try:
        artifact, digest = parse_cargo_dependency_graph_artifact(
            payload,
            declared_sha256=artifact_sha256,
            expected_commit_sha=source_commit_sha,
            expected_source_sha256=analysis.source_sha256,
        )
    except CargoDependencyGraphError as exc:
        if exc.code == "artifact_size_invalid":
            raise HTTPException(status_code=413, detail="Cargo dependency evidence exceeds its fixed size limit.") from exc
        if exc.code in {"artifact_digest_mismatch", "source_commit_mismatch", "source_digest_mismatch"}:
            raise HTTPException(status_code=409, detail="Cargo dependency evidence does not match the selected source.") from exc
        raise HTTPException(status_code=422, detail="Cargo dependency evidence does not match the supported contract.") from exc

    updated = request.app.state.jobs.attach_cargo_dependency_graph(
        analysis.id,
        owner_id=project.owner_id,
        project_id=project.id,
        artifact=artifact,
        artifact_sha256=digest,
    )
    receipt = updated.result.get("cargo_dependency_graph_evidence") if isinstance(updated.result, dict) else None
    try:
        response = CargoProjectDependencyGraphEvidence.model_validate(receipt)
    except ValidationError as exc:  # pragma: no cover - store contract is tested directly.
        raise HTTPException(status_code=500, detail="Cargo dependency evidence could not be persisted safely.") from exc
    record_product_action(
        request,
        "project.dependency_graph_attached",
        resource_type="analysis",
        resource_id=analysis.id,
        organization_id=project.owner_id,
        metadata={
            "project_id": project.id,
            "ecosystem": "cargo",
            "state": response.state,
            "nodes_reported": response.nodes_reported,
            "edges_reported": response.edges_reported,
        },
    )
    log_audit_event(
        "project.dependency_graph.attached",
        correlation_id=f"job:{analysis.id}",
        project_id=project.id,
        job_id=analysis.id,
        owner_id=project.owner_id,
        ecosystem="cargo",
        graph_state=response.state,
        nodes_reported=response.nodes_reported,
        edges_reported=response.edges_reported,
    )
    return response


@app.post(
    "/projects/{project_id}/analyses/{analysis_id}/dependency-graphs/composer",
    response_model=ComposerProjectDependencyGraphEvidence,
)
async def attach_composer_dependency_graph(
    request: Request, project_id: str, analysis_id: str,
    file: UploadFile = File(...),
    artifact_sha256: str = Form(..., min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$"),
) -> ComposerProjectDependencyGraphEvidence:
    if file.content_type not in {"application/json", "application/octet-stream"}:
        raise HTTPException(status_code=415, detail="Composer dependency evidence must be a JSON artifact.")
    project, analysis, source_commit_sha = _dependency_graph_attachment_target(request, project_id, analysis_id)
    payload = await file.read(COMPOSER_DEPENDENCY_GRAPH_MAX_BYTES + 1)
    try:
        artifact, digest = parse_composer_dependency_graph_artifact(
            payload, declared_sha256=artifact_sha256,
            expected_commit_sha=source_commit_sha,
            expected_source_sha256=analysis.source_sha256,
        )
    except ComposerDependencyGraphError as exc:
        if exc.code == "artifact_size_invalid":
            raise HTTPException(status_code=413, detail="Composer dependency evidence exceeds its fixed size limit.") from exc
        if exc.code in {"artifact_digest_mismatch", "source_commit_mismatch", "source_digest_mismatch"}:
            raise HTTPException(status_code=409, detail="Composer dependency evidence does not match the selected source.") from exc
        raise HTTPException(status_code=422, detail="Composer dependency evidence does not match the supported contract.") from exc
    updated = request.app.state.jobs.attach_composer_dependency_graph(
        analysis.id, owner_id=project.owner_id, project_id=project.id,
        artifact=artifact, artifact_sha256=digest,
    )
    try:
        response = ComposerProjectDependencyGraphEvidence.model_validate(updated.result.get("composer_dependency_graph_evidence"))
    except (ValidationError, AttributeError) as exc:
        raise HTTPException(status_code=500, detail="Composer dependency evidence could not be persisted safely.") from exc
    record_product_action(
        request, "project.dependency_graph_attached", resource_type="analysis",
        resource_id=analysis.id, organization_id=project.owner_id,
        metadata={"project_id": project.id, "ecosystem": "composer", "state": response.state,
                  "nodes_reported": response.nodes_reported, "edges_reported": response.edges_reported},
    )
    log_audit_event(
        "project.dependency_graph.attached", correlation_id=f"job:{analysis.id}",
        project_id=project.id, job_id=analysis.id, owner_id=project.owner_id,
        ecosystem="composer", graph_state=response.state,
        nodes_reported=response.nodes_reported, edges_reported=response.edges_reported,
    )
    return response


@app.post(
    "/projects/{project_id}/analyses/{analysis_id}/dependency-graphs/gradle",
    response_model=GradleProjectDependencyGraphEvidence,
)
async def attach_gradle_dependency_graph(
    request: Request, project_id: str, analysis_id: str,
    file: UploadFile = File(...),
    artifact_sha256: str = Form(..., min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$"),
) -> GradleProjectDependencyGraphEvidence:
    """Bind one closed, source-bound Gradle graph without executing a build."""

    if file.content_type not in {"application/json", "application/octet-stream"}:
        raise HTTPException(status_code=415, detail="Gradle dependency evidence must be a JSON artifact.")
    project, analysis, source_commit_sha = _dependency_graph_attachment_target(request, project_id, analysis_id)
    payload = await file.read(GRADLE_DEPENDENCY_GRAPH_MAX_BYTES + 1)
    try:
        artifact, digest = parse_gradle_dependency_graph_artifact(
            payload, declared_sha256=artifact_sha256,
            expected_commit_sha=source_commit_sha,
            expected_source_sha256=analysis.source_sha256,
        )
    except GradleDependencyGraphError as exc:
        if exc.code == "artifact_size_invalid":
            raise HTTPException(status_code=413, detail="Gradle dependency evidence exceeds its fixed size limit.") from exc
        if exc.code in {"artifact_digest_mismatch", "source_commit_mismatch", "source_digest_mismatch"}:
            raise HTTPException(status_code=409, detail="Gradle dependency evidence does not match the selected source.") from exc
        raise HTTPException(status_code=422, detail="Gradle dependency evidence does not match the supported contract.") from exc
    updated = request.app.state.jobs.attach_gradle_dependency_graph(
        analysis.id, owner_id=project.owner_id, project_id=project.id,
        artifact=artifact, artifact_sha256=digest,
    )
    try:
        response = GradleProjectDependencyGraphEvidence.model_validate(updated.result.get("gradle_dependency_graph_evidence"))
    except (ValidationError, AttributeError) as exc:
        raise HTTPException(status_code=500, detail="Gradle dependency evidence could not be persisted safely.") from exc
    safe_metadata = {
        "project_id": project.id, "ecosystem": "maven", "producer": "gradle",
        "state": response.state, "nodes_reported": response.nodes_reported,
        "edges_reported": response.edges_reported,
    }
    record_product_action(
        request, "project.dependency_graph_attached", resource_type="analysis",
        resource_id=analysis.id, organization_id=project.owner_id, metadata=safe_metadata,
    )
    log_audit_event(
        "project.dependency_graph.attached", correlation_id=f"job:{analysis.id}",
        project_id=project.id, job_id=analysis.id, owner_id=project.owner_id,
        ecosystem="maven", producer="gradle", graph_state=response.state,
        nodes_reported=response.nodes_reported, edges_reported=response.edges_reported,
    )
    return response


@app.post(
    "/projects/{project_id}/analyses/{analysis_id}/dependency-graphs/nuget",
    response_model=NugetProjectDependencyGraphEvidence,
)
async def attach_nuget_dependency_graph(
    request: Request, project_id: str, analysis_id: str,
    file: UploadFile = File(...),
    artifact_sha256: str = Form(..., min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$"),
) -> NugetProjectDependencyGraphEvidence:
    """Bind one closed, source-bound NuGet graph without restore or MSBuild."""

    if file.content_type not in {"application/json", "application/octet-stream"}:
        raise HTTPException(status_code=415, detail="NuGet dependency evidence must be a JSON artifact.")
    project, analysis, source_commit_sha = _dependency_graph_attachment_target(request, project_id, analysis_id)
    payload = await file.read(NUGET_DEPENDENCY_GRAPH_MAX_BYTES + 1)
    try:
        artifact, digest = parse_nuget_dependency_graph_artifact(
            payload, declared_sha256=artifact_sha256,
            expected_commit_sha=source_commit_sha,
            expected_source_sha256=analysis.source_sha256,
        )
    except NugetDependencyGraphError as exc:
        if exc.code == "artifact_size_invalid":
            raise HTTPException(status_code=413, detail="NuGet dependency evidence exceeds its fixed size limit.") from exc
        if exc.code in {"artifact_digest_mismatch", "source_commit_mismatch", "source_digest_mismatch"}:
            raise HTTPException(status_code=409, detail="NuGet dependency evidence does not match the selected source.") from exc
        raise HTTPException(status_code=422, detail="NuGet dependency evidence does not match the supported contract.") from exc
    updated = request.app.state.jobs.attach_nuget_dependency_graph(
        analysis.id, owner_id=project.owner_id, project_id=project.id,
        artifact=artifact, artifact_sha256=digest,
    )
    try:
        response = NugetProjectDependencyGraphEvidence.model_validate(updated.result.get("nuget_dependency_graph_evidence"))
    except (ValidationError, AttributeError) as exc:
        raise HTTPException(status_code=500, detail="NuGet dependency evidence could not be persisted safely.") from exc
    safe_metadata = {
        "project_id": project.id, "ecosystem": "nuget", "producer": "nuget",
        "state": response.state, "nodes_reported": response.nodes_reported,
        "edges_reported": response.edges_reported, "targets_reported": response.targets_reported,
    }
    record_product_action(
        request, "project.dependency_graph_attached", resource_type="analysis",
        resource_id=analysis.id, organization_id=project.owner_id, metadata=safe_metadata,
    )
    log_audit_event(
        "project.dependency_graph.attached", correlation_id=f"job:{analysis.id}",
        project_id=project.id, job_id=analysis.id, owner_id=project.owner_id,
        ecosystem="nuget", producer="nuget", graph_state=response.state,
        nodes_reported=response.nodes_reported, edges_reported=response.edges_reported,
        targets_reported=response.targets_reported,
    )
    return response


@app.post("/projects/{project_id}/snapshots", response_model=ProjectSnapshotCreated, status_code=status.HTTP_202_ACCEPTED)
async def create_project_snapshot(
    request: Request,
    project_id: str,
    payload: ProjectSnapshotCreateRequest,
    background_tasks: BackgroundTasks,
) -> ProjectSnapshotCreated:
    """Append an authorized source snapshot and immediately analyze that input."""

    owned_project = get_project_for_current_owner(request, project_id)
    admitted = request.app.state.project_snapshot_admissions.admit(
        project_id=owned_project.id,
        owner_id=owned_project.owner_id,
        source_file_id=payload.source_file_id,
        idempotency_key=payload.idempotency_key,
        source_channel="archive_upload",
    )
    log_audit_event(
        "project.snapshot.replayed" if admitted.replayed else "project.snapshot.queued",
        correlation_id=f"job:{admitted.job.id}",
        project_id=admitted.project.id,
        job_id=admitted.job.id,
        owner_id=admitted.project.owner_id,
        analysis_profile=admitted.job.analysis_profile,
    )
    record_product_action(
        request,
        "project.snapshot_replayed" if admitted.replayed else "project.snapshot_queued",
        resource_type="analysis",
        resource_id=admitted.job.id,
        organization_id=admitted.project.owner_id,
        metadata={"project_id": admitted.project.id, "analysis_profile": admitted.job.analysis_profile},
    )
    if admitted.job.status == "queued":
        schedule_project_archive_once(background_tasks, request.app, admitted.job.id)
    return ProjectSnapshotCreated(
        project=admitted.project,
        job=request.app.state.jobs.get_list_item(admitted.job.id),
        snapshot=admitted.snapshot,
    )


@app.post("/files/pdf", response_model=StoredFileView, status_code=status.HTTP_201_CREATED)
async def upload_pdf(request: Request, file: UploadFile = File(...)) -> StoredFileView:
    return StoredFileView.model_validate(
        await request.app.state.files.save_pdf(file, owner_id=current_owner_id_for_request(request))
    )


@app.post("/files/image", response_model=StoredFileView, status_code=status.HTTP_201_CREATED)
async def upload_image(request: Request, file: UploadFile = File(...)) -> StoredFileView:
    return StoredFileView.model_validate(
        await request.app.state.files.save_image(file, owner_id=current_owner_id_for_request(request))
    )


@app.post("/files/manifest", response_model=StoredFileView, status_code=status.HTTP_201_CREATED)
async def upload_manifest(request: Request, file: UploadFile = File(...)) -> StoredFileView:
    return StoredFileView.model_validate(
        await request.app.state.files.save_manifest(file, owner_id=current_owner_id_for_request(request))
    )


@app.post("/files/archive", response_model=StoredFileView, status_code=status.HTTP_201_CREATED)
async def upload_archive(request: Request, file: UploadFile = File(...)) -> StoredFileView:
    return StoredFileView.model_validate(
        await request.app.state.files.save_archive(file, owner_id=current_owner_id_for_request(request))
    )


@app.get("/files", response_model=list[StoredFileView])
async def list_files(request: Request) -> list[StoredFileView]:
    return [
        StoredFileView.model_validate(item)
        for item in request.app.state.files.list(owner_id=current_owner_id_for_request(request))
    ]


@app.get("/files/{file_id}", response_model=StoredFileView)
async def get_file(request: Request, file_id: str) -> StoredFileView:
    return StoredFileView.model_validate(get_file_for_current_owner(request, file_id))


@app.delete("/files/{file_id}", response_model=DeletedFileResponse)
async def delete_file(request: Request, file_id: str) -> DeletedFileResponse:
    owner_id = current_owner_id_for_request(request)
    deleted_file = request.app.state.files.delete(file_id, owner_id=owner_id)
    associated_jobs_marked = request.app.state.jobs.mark_file_deleted(file_id, owner_id=owner_id)
    request.app.state.projects.mark_source_file_deleted(file_id, owner_id=owner_id)
    record_product_action(
        request,
        "source.deleted",
        resource_type="source",
        resource_id=deleted_file.id,
        organization_id=owner_id,
    )
    return DeletedFileResponse(deleted_file=deleted_file, associated_jobs_marked=associated_jobs_marked)


@app.post("/audits/pdf/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_pdf_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "pdf":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not a PDF.")
    job = request.app.state.jobs.create_pdf_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.pdf_audits.run_pdf_analysis, job.id)
    return job


@app.post("/audits/image/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_image_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "image":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an image.")
    job = request.app.state.jobs.create_image_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.image_audits.run_image_analysis, job.id)
    return job


@app.post("/audits/manifest/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_manifest_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "manifest":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not a manifest.")
    job = request.app.state.jobs.create_manifest_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.manifest_audits.run_manifest_analysis, job.id)
    return job


@app.post("/audits/archive/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_archive_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_archive_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.archive_audits.run_archive_analysis, job.id)
    return job


@app.post("/audits/project-archive/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_project_archive_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_project_archive_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.project_archive_audits.run_project_archive_analysis, job.id)
    return job


@app.post("/audits/django-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_django_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_django_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.django_config_audits.run_django_config_analysis, job.id)
    return job


@app.post("/audits/docker-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_docker_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_docker_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.docker_config_audits.run_docker_config_analysis, job.id)
    return job


@app.post("/audits/secrets-review/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_secrets_review_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_secrets_review_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.secrets_review_audits.run_secrets_review_analysis, job.id)
    return job


@app.post("/audits/node-package-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_node_package_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_node_package_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.node_package_config_audits.run_node_package_config_analysis, job.id)
    return job


@app.post("/audits/ci-cd-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_ci_cd_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_ci_cd_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.ci_cd_config_audits.run_ci_cd_config_analysis, job.id)
    return job


@app.post("/audits/k8s-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_k8s_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_k8s_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.k8s_config_audits.run_k8s_config_analysis, job.id)
    return job


@app.post("/audits/terraform-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_terraform_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_terraform_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.terraform_config_audits.run_terraform_config_analysis, job.id)
    return job


@app.post("/audits/nginx-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_nginx_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_nginx_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.nginx_config_audits.run_nginx_config_analysis, job.id)
    return job


@app.post("/audits/compose-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_compose_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_compose_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.compose_config_audits.run_compose_config_analysis, job.id)
    return job


@app.post("/audits/database-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_database_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_database_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.database_config_audits.run_database_config_analysis, job.id)
    return job


@app.post("/audits/sql-database-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_sql_database_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_sql_database_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.sql_database_config_audits.run_sql_database_config_analysis, job.id)
    return job


@app.post("/audits/redis-config/{file_id}", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_redis_config_audit(request: Request, file_id: str, background_tasks: BackgroundTasks) -> JobRecord:
    stored_file = get_file_for_current_owner(request, file_id)
    if stored_file.kind != "archive":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is not an archive.")
    job = request.app.state.jobs.create_redis_config_job(file_id, owner_id=owner_id_for_file_job(request, stored_file))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.redis_config_audits.run_redis_config_analysis, job.id)
    return job


@app.get("/active/change-approvals", response_model=ActiveChangeApprovalPage)
async def list_active_change_approvals(request: Request, response: Response) -> ActiveChangeApprovalPage:
    if request.query_params:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Active change approvals do not accept query parameters.")
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    response.headers["Cache-Control"] = "private, no-store"
    if not _active_four_eyes_available(request):
        return ActiveChangeApprovalPage(enabled=False, items=(), pending_count=0)
    try:
        records = request.app.state.active_change_approvals.list(organization_id)
        views = tuple(
            _active_approval_view(
                request, item, organization_id=organization_id,
                actor_id=actor_id, actor_role=actor_role,
            )
            for item in records
        )
    except ActiveChangeApprovalError as exc:
        raise active_change_approval_http_error(exc) from exc
    return ActiveChangeApprovalPage(
        enabled=True,
        items=views,
        pending_count=sum(item.status == "pending" for item in views),
    )


def _require_active_four_eyes_request(request: Request) -> tuple[str, str, str]:
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    if not _active_four_eyes_available(request):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Four-eyes Active changes are disabled by the operator.")
    return organization_id, actor_id, actor_role


@app.post("/active/change-approvals/registrations", response_model=ActiveChangeApprovalView, status_code=status.HTTP_202_ACCEPTED)
async def request_active_registration_approval(
    request: Request, response: Response, payload: ActiveAssetCreateRequest
) -> ActiveChangeApprovalView:
    organization_id, actor_id, actor_role = _require_active_four_eyes_request(request)
    run_with_validated_active_responsibles(
        request, payload.responsible_user_ids,
        organization_id=organization_id, actor_id=actor_id,
        operation=lambda _responsibles: None,
    )
    digest = active_change_operation_digest(
        organization_id=organization_id, kind="registration", asset_id=None, payload=payload
    )
    summary = ActiveChangeSummary(
        asset_type=payload.asset_type, review_target=payload.value,
        scope_change="new_registration", capabilities=tuple(sorted(payload.capabilities)),
        allowed_ports=tuple(sorted(payload.allowed_ports)),
        allowed_protocols=tuple(sorted(payload.allowed_protocols)),
        authorization_expires_at=payload.expires_at,
    )
    try:
        record = request.app.state.active_change_approvals.request(
            organization_id=organization_id, actor_id=actor_id, actor_role=actor_role,
            kind="registration", asset_id=None,
            operation_digest_sha256=digest, summary=summary,
        )
    except ActiveChangeApprovalError as exc:
        raise active_change_approval_http_error(exc) from exc
    record_product_action(
        request, "active_change.approval_requested", resource_type="active_change_approval",
        resource_id=record.id, organization_id=organization_id, actor_id=actor_id,
        actor_role=actor_role, metadata={"change_kind": "registration"},
    )
    response.headers["Cache-Control"] = "private, no-store"
    return _active_approval_view(request, record, organization_id=organization_id, actor_id=actor_id, actor_role=actor_role)


@app.post("/active/assets/{asset_id}/change-approvals/renewals", response_model=ActiveChangeApprovalView, status_code=status.HTTP_202_ACCEPTED)
async def request_active_renewal_approval(
    request: Request, response: Response, asset_id: str, payload: ActiveAssetRenewRequest
) -> ActiveChangeApprovalView:
    organization_id, actor_id, actor_role = _require_active_four_eyes_request(request)
    try:
        asset = request.app.state.active_assets.get(asset_id, organization_id=organization_id)
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    run_with_validated_active_responsibles(
        request, payload.responsible_user_ids,
        organization_id=organization_id, actor_id=actor_id,
        operation=lambda _responsibles: None,
    )
    old_scope = (set(asset.capabilities), set(asset.allowed_ports), set(asset.allowed_protocols))
    new_scope = (set(payload.capabilities), set(payload.allowed_ports), set(payload.allowed_protocols))
    expanded = any(not new.issubset(old) for old, new in zip(old_scope, new_scope))
    reduced = any(not old.issubset(new) for old, new in zip(old_scope, new_scope))
    scope_change = "expanded_scope" if expanded else "reduced_scope" if reduced else "same_scope"
    digest = active_change_operation_digest(
        organization_id=organization_id, kind="renewal", asset_id=asset.id, payload=payload
    )
    summary = ActiveChangeSummary(
        asset_type=asset.asset_type, scope_change=scope_change,
        capabilities=tuple(sorted(payload.capabilities)),
        allowed_ports=tuple(sorted(payload.allowed_ports)),
        allowed_protocols=tuple(sorted(payload.allowed_protocols)),
        authorization_expires_at=payload.expires_at,
    )
    try:
        record = request.app.state.active_change_approvals.request(
            organization_id=organization_id, actor_id=actor_id, actor_role=actor_role,
            kind="renewal", asset_id=asset.id,
            operation_digest_sha256=digest, summary=summary,
        )
    except ActiveChangeApprovalError as exc:
        raise active_change_approval_http_error(exc) from exc
    record_product_action(
        request, "active_change.approval_requested", resource_type="active_change_approval",
        resource_id=record.id, organization_id=organization_id, actor_id=actor_id,
        actor_role=actor_role, metadata={"change_kind": "renewal", "scope_change": scope_change},
    )
    response.headers["Cache-Control"] = "private, no-store"
    return _active_approval_view(request, record, organization_id=organization_id, actor_id=actor_id, actor_role=actor_role)


@app.post("/active/assets/{asset_id}/change-approvals/revocations", response_model=ActiveChangeApprovalView, status_code=status.HTTP_202_ACCEPTED)
async def request_active_revocation_approval(
    request: Request, response: Response, asset_id: str, payload: ActiveAssetRevokeRequest
) -> ActiveChangeApprovalView:
    organization_id, actor_id, actor_role = _require_active_four_eyes_request(request)
    try:
        asset = request.app.state.active_assets.get(asset_id, organization_id=organization_id)
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    digest = active_change_operation_digest(
        organization_id=organization_id, kind="revocation", asset_id=asset.id, payload=payload
    )
    try:
        record = request.app.state.active_change_approvals.request(
            organization_id=organization_id, actor_id=actor_id, actor_role=actor_role,
            kind="revocation", asset_id=asset.id,
            operation_digest_sha256=digest,
            summary=ActiveChangeSummary(
                asset_type=asset.asset_type, scope_change="revocation",
                reason_code=payload.reason_code,
            ),
        )
    except ActiveChangeApprovalError as exc:
        raise active_change_approval_http_error(exc) from exc
    record_product_action(
        request, "active_change.approval_requested", resource_type="active_change_approval",
        resource_id=record.id, organization_id=organization_id, actor_id=actor_id,
        actor_role=actor_role, metadata={"change_kind": "revocation", "reason_code": payload.reason_code},
    )
    response.headers["Cache-Control"] = "private, no-store"
    return _active_approval_view(request, record, organization_id=organization_id, actor_id=actor_id, actor_role=actor_role)


@app.post("/active/change-approvals/{approval_id}/approve", response_model=ActiveChangeApprovalView)
async def approve_active_change(request: Request, response: Response, approval_id: str) -> ActiveChangeApprovalView:
    if request.query_params or await request.body():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Approval decision does not accept request data.")
    organization_id, actor_id, actor_role = _require_active_four_eyes_request(request)
    try:
        record = request.app.state.active_change_approvals.approve(
            organization_id, approval_id, actor_id, actor_role
        )
    except ActiveChangeApprovalError as exc:
        raise active_change_approval_http_error(exc) from exc
    record_product_action(
        request, "active_change.approved", resource_type="active_change_approval",
        resource_id=record.id, organization_id=organization_id, actor_id=actor_id,
        actor_role=actor_role, metadata={"change_kind": record.kind},
    )
    response.headers["Cache-Control"] = "private, no-store"
    return _active_approval_view(request, record, organization_id=organization_id, actor_id=actor_id, actor_role=actor_role)


@app.post("/active/change-approvals/{approval_id}/reject", response_model=ActiveChangeApprovalView)
async def reject_active_change(request: Request, response: Response, approval_id: str) -> ActiveChangeApprovalView:
    if request.query_params or await request.body():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Approval decision does not accept request data.")
    organization_id, actor_id, actor_role = _require_active_four_eyes_request(request)
    try:
        record = request.app.state.active_change_approvals.reject(
            organization_id, approval_id, actor_id, actor_role
        )
    except ActiveChangeApprovalError as exc:
        raise active_change_approval_http_error(exc) from exc
    record_product_action(
        request, "active_change.rejected", resource_type="active_change_approval",
        resource_id=record.id, organization_id=organization_id, actor_id=actor_id,
        actor_role=actor_role, metadata={"change_kind": record.kind},
    )
    response.headers["Cache-Control"] = "private, no-store"
    return _active_approval_view(request, record, organization_id=organization_id, actor_id=actor_id, actor_role=actor_role)


@app.post("/active/assets", response_model=ActiveAssetRecord, status_code=status.HTTP_201_CREATED)
async def create_active_asset(request: Request, payload: ActiveAssetCreateRequest) -> ActiveAssetRecord:
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    approval_id = _claim_active_change(
        request, organization_id=organization_id, actor_id=actor_id,
        kind="registration", asset_id=None, payload=payload,
    )
    try:
        asset = run_with_validated_active_responsibles(
            request,
            payload.responsible_user_ids,
            organization_id=organization_id,
            actor_id=actor_id,
            operation=lambda responsible_user_ids: request.app.state.active_assets.create(
                payload.model_copy(update={"responsible_user_ids": responsible_user_ids}),
                organization_id=organization_id,
                actor_id=actor_id,
            ),
        )
    except ActiveAssetStoreError as exc:
        _finish_active_change(request, organization_id, approval_id, succeeded=False)
        raise active_asset_http_error(exc) from exc
    except BaseException:
        _finish_active_change(request, organization_id, approval_id, succeeded=False)
        raise
    _finish_active_change(request, organization_id, approval_id, succeeded=True)
    record_product_action(
        request,
        "active_asset.registered",
        resource_type="active_asset",
        resource_id=asset.id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={
            "authorization_revision_id": asset.authorization_revisions[0].id,
            "authorization_revision_sequence": asset.authorization_revisions[0].sequence,
        },
    )
    return asset


@app.post("/active/assets/batch/preflight", response_model=ActiveAssetBatchPreflightResponse)
async def preflight_active_asset_batch(
    request: Request,
    file: UploadFile = File(...),
) -> ActiveAssetBatchPreflightResponse:
    """Parse one bounded CSV/JSON inventory without retaining its source bytes."""

    if request.app.state.settings.active_four_eyes_enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Batch registration is unavailable while four-eyes approval is enabled. Review exact assets individually.",
        )

    organization_id, actor_id, _actor_role = active_asset_actor(request, write=True)
    source = await file.read(ACTIVE_ASSET_BATCH_MAX_BYTES + 1)
    if len(source) > ACTIVE_ASSET_BATCH_MAX_BYTES:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="Active asset batch exceeds 128 KiB.")
    try:
        parsed = parse_active_asset_batch(source, file.filename)
        parsed = mark_existing_active_asset_conflicts(
            parsed,
            request.app.state.active_assets.existing_registration_identities(organization_id=organization_id),
        )
    except ActiveAssetBatchError as exc:
        detail = {
            "unsupported_format": "Use a .json or .csv Active asset batch.",
            "item_limit": "Active asset batches must contain between 1 and 50 rows.",
            "too_large": "Active asset batch exceeds 128 KiB.",
        }.get(str(exc), "Active asset batch format is invalid.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc

    requests = [row.request for row in parsed.rows if row.request is not None]
    if requests:
        run_with_validated_active_responsibles(
            request,
            sorted({user_id for item in requests for user_id in item.responsible_user_ids}),
            organization_id=organization_id,
            actor_id=actor_id,
            operation=lambda _responsible_user_ids: None,
        )
    can_confirm = all(row.status == "ready" for row in parsed.rows)
    admission = (
        request.app.state.active_asset_batch_preflights.create(
            f"{organization_id}:{actor_id}",
            source,
            parsed.normalized_digest_sha256,
        )
        if can_confirm
        else None
    )
    return build_active_asset_batch_preflight(parsed, admission)


@app.post("/active/assets/batch", response_model=ActiveAssetBatchCommitResponse, status_code=status.HTTP_201_CREATED)
async def create_active_asset_batch(
    request: Request,
    file: UploadFile = File(...),
    preflight_token: str = Form(..., min_length=32, max_length=128),
    idempotency_key: str = Form(..., pattern=r"^[a-f0-9]{32}$"),
    batch_confirmed: bool = Form(...),
) -> ActiveAssetBatchCommitResponse:
    """Commit the exact preflighted batch as one idempotent store transaction."""

    if request.app.state.settings.active_four_eyes_enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Batch registration is unavailable while four-eyes approval is enabled. Review exact assets individually.",
        )

    if batch_confirmed is not True:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Explicit batch confirmation is required.")
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    source = await file.read(ACTIVE_ASSET_BATCH_MAX_BYTES + 1)
    if len(source) > ACTIVE_ASSET_BATCH_MAX_BYTES:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="Active asset batch exceeds 128 KiB.")
    try:
        parsed = parse_active_asset_batch(source, file.filename)
    except ActiveAssetBatchError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Active asset batch format is invalid.") from exc
    if any(row.status != "ready" for row in parsed.rows):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Active asset batch must pass preflight without corrections.")
    try:
        expected_digest = request.app.state.active_asset_batch_preflights.consume(
            f"{organization_id}:{actor_id}",
            preflight_token,
            source,
        )
    except ActiveAssetBatchError as exc:
        detail = (
            "The Active asset batch changed after preflight. Run preflight again."
            if str(exc) == "content_changed"
            else "The Active asset batch preflight expired or is unavailable. Run it again."
        )
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail) from exc
    if not secrets.compare_digest(expected_digest, parsed.normalized_digest_sha256):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The Active asset batch changed after preflight. Run preflight again.")

    requests = parsed.requests
    try:
        assets, replayed, batch_id = run_with_validated_active_responsibles(
            request,
            sorted({user_id for item in requests for user_id in item.responsible_user_ids}),
            organization_id=organization_id,
            actor_id=actor_id,
            operation=lambda _responsible_user_ids: request.app.state.active_assets.create_many(
                requests,
                organization_id=organization_id,
                actor_id=actor_id,
                normalized_digest_sha256=parsed.normalized_digest_sha256,
                idempotency_key=idempotency_key,
            ),
        )
    except ActiveAssetStoreError as exc:
        if str(exc) in {"batch_asset_conflict", "batch_duplicate_identity"}:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An Active asset identity changed or was registered after preflight. Review the batch again.") from exc
        if str(exc) == "batch_idempotency_conflict":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Batch idempotency key is already bound to different content.") from exc
        raise active_asset_http_error(exc) from exc
    record_product_action(
        request,
        "active_asset.batch_registered",
        resource_type="active_asset_batch",
        resource_id=batch_id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={"created_count": len(assets), "replayed": replayed},
    )
    return ActiveAssetBatchCommitResponse(
        batch_id=batch_id,
        created_count=len(assets),
        replayed=replayed,
        assets=assets,
    )


@app.post("/active/assets/{asset_id}/renew", response_model=ActiveAssetRenewalResponse)
async def renew_active_asset(
    request: Request,
    asset_id: str,
    payload: ActiveAssetRenewRequest,
) -> ActiveAssetRenewalResponse:
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    approval_id = _claim_active_change(
        request, organization_id=organization_id, actor_id=actor_id,
        kind="renewal", asset_id=asset_id, payload=payload,
    )
    try:
        asset, replayed, scope_expanded = run_with_validated_active_responsibles(
            request,
            payload.responsible_user_ids,
            organization_id=organization_id,
            actor_id=actor_id,
            operation=lambda responsible_user_ids: request.app.state.active_assets.renew(
                asset_id,
                payload.model_copy(update={"responsible_user_ids": responsible_user_ids}),
                organization_id=organization_id,
                actor_id=actor_id,
            ),
        )
    except ActiveAssetStoreError as exc:
        _finish_active_change(request, organization_id, approval_id, succeeded=False)
        raise active_asset_http_error(exc) from exc
    except BaseException:
        _finish_active_change(request, organization_id, approval_id, succeeded=False)
        raise
    _finish_active_change(request, organization_id, approval_id, succeeded=True)
    revision = current_active_authorization_revision(asset)
    if revision is None:  # Defensive: renew() must always materialize one.
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Active asset registry is unavailable.")
    if not replayed:
        request.app.state.active_recurrences.suspend_for_asset(
            asset.id,
            organization_id=organization_id,
            reason_code="authorization_revision_changed",
        )
    record_product_action(
        request,
        "active_asset.authorization_renewed",
        resource_type="active_asset",
        resource_id=asset.id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={
            "authorization_revision_id": revision.id,
            "authorization_revision_sequence": revision.sequence,
            "scope_expanded": scope_expanded,
            "replayed": replayed,
        },
    )
    return ActiveAssetRenewalResponse(asset=asset, replayed=replayed, scope_expanded=scope_expanded)


@app.post("/active/assets/{asset_id}/responsibles", response_model=ActiveAssetRecord)
async def update_active_asset_responsibles(
    request: Request,
    asset_id: str,
    payload: ActiveAssetResponsiblesUpdateRequest,
) -> ActiveAssetRecord:
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    try:
        asset, changed = run_with_validated_active_responsibles(
            request,
            payload.responsible_user_ids,
            organization_id=organization_id,
            actor_id=actor_id,
            operation=lambda _responsible_user_ids: request.app.state.active_assets.set_responsibles(
                asset_id,
                payload,
                organization_id=organization_id,
                actor_id=actor_id,
            ),
        )
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    record_product_action(
        request,
        "active_asset.responsibles_updated",
        resource_type="active_asset",
        resource_id=asset.id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={"responsible_count": len(asset.responsible_user_ids), "changed": changed},
    )
    return asset


@app.get("/active/operations/summary")
async def get_active_operations_summary(request: Request) -> dict[str, Any]:
    organization_id, _actor_id, _actor_role = active_asset_actor(request)
    try:
        failed_job_assets, degraded_job_assets = (
            request.app.state.jobs.active_attention_asset_ids(owner_id=organization_id)
        )
        verification_attention_assets = (
            request.app.state.active_asset_verifications.attention_asset_ids(
                organization_id=organization_id
            )
        )
        assets, asset_counts = request.app.state.active_assets.operations_snapshot(
            organization_id=organization_id,
            high_priority_asset_ids=failed_job_assets
            | verification_attention_assets,
            review_priority_asset_ids=degraded_job_assets,
        )
        jobs, total_active_jobs = request.app.state.jobs.active_operations_snapshot(
            owner_id=organization_id,
            asset_ids={asset.id for asset in assets},
        )
        verifications = request.app.state.active_asset_verifications.latest_many(
            {asset.id for asset in assets[:500]}, organization_id=organization_id
        )
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    except ActiveAssetVerificationError as exc:
        raise active_asset_verification_http_error(exc) from exc
    capabilities = {capability: active_capability_enabled(request.app.state.settings, capability) for capability in sorted(ACTIVE_CAPABILITIES)}
    checker = getattr(request.app.state, "active_tools_health_checker", check_active_tools_health)
    try:
        runner_health = await checker(
            request.app.state.settings.active_tools_url,
            timeout_seconds=min(request.app.state.settings.active_tools_health_timeout_seconds, 2.0),
        )
    except Exception:
        runner_health = {
            "available": False,
            "capabilities": {},
            "error_code": "active_tools_unavailable",
        }
    return build_active_operations_summary(
        assets,
        jobs,
        verifications,
        capability_configuration=capabilities,
        runner_health=runner_health,
        verification_enabled=request.app.state.settings.active_asset_verification_enabled,
        recurrence_enabled=request.app.state.settings.active_recurrence_enabled,
        four_eyes_enabled=_active_four_eyes_available(request),
        legacy_free_targets_enabled=request.app.state.settings.active_legacy_free_targets_enabled,
        admission_available=request.app.state.jobs.active_admission_available(owner_id=organization_id),
        asset_counts_override=asset_counts,
        total_jobs_override=total_active_jobs,
        priority_candidates_override=asset_counts.get("priority_candidates", 0),
    )


def build_active_weekly_snapshot_for_request(
    request: Request,
    *,
    organization_id: str,
    period: ActiveWeeklyReportPeriod,
    state_at: datetime,
):
    try:
        failed_job_assets, degraded_job_assets = (
            request.app.state.jobs.active_attention_asset_ids(owner_id=organization_id)
        )
        verification_attention_assets = (
            request.app.state.active_asset_verifications.attention_asset_ids(
                organization_id=organization_id
            )
        )
        assets, asset_counts = request.app.state.active_assets.operations_snapshot(
            organization_id=organization_id,
            high_priority_asset_ids=failed_job_assets | verification_attention_assets,
            review_priority_asset_ids=degraded_job_assets,
        )
        asset_ids = {asset.id for asset in assets}
        jobs, total_active_jobs = request.app.state.jobs.active_operations_snapshot(
            owner_id=organization_id, asset_ids=asset_ids
        )
        verifications = request.app.state.active_asset_verifications.latest_many(
            asset_ids, organization_id=organization_id
        )
        recurrences = request.app.state.active_recurrences.list_for_assets(
            asset_ids, organization_id=organization_id
        )
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    except ActiveAssetVerificationError as exc:
        raise active_asset_verification_http_error(exc) from exc
    except ActiveRecurrenceError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Active recurrence state is temporarily unavailable.",
        ) from exc
    capabilities = {
        capability: active_capability_enabled(request.app.state.settings, capability)
        for capability in sorted(ACTIVE_CAPABILITIES)
    }
    summary = build_active_operations_summary(
        assets,
        jobs,
        verifications,
        capability_configuration=capabilities,
        runner_health=None,
        verification_enabled=request.app.state.settings.active_asset_verification_enabled,
        recurrence_enabled=request.app.state.settings.active_recurrence_enabled,
        four_eyes_enabled=_active_four_eyes_available(request),
        legacy_free_targets_enabled=request.app.state.settings.active_legacy_free_targets_enabled,
        admission_available=request.app.state.jobs.active_admission_available(owner_id=organization_id),
        asset_counts_override=asset_counts,
        total_jobs_override=total_active_jobs,
        priority_candidates_override=asset_counts.get("priority_candidates", 0),
        now=state_at,
    )
    try:
        return build_active_weekly_report_snapshot(
            summary,
            assets,
            jobs,
            recurrences,
            organization_id=organization_id,
            period=period,
            state_at=state_at,
        )
    except ActiveWeeklyReportError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The Active portfolio changed. Generate a new report preflight.",
        ) from exc


@app.get(
    "/active/operations/weekly-report/preflight",
    response_model=ActiveWeeklyReportPreflight,
)
async def preflight_active_weekly_report(
    request: Request,
    response: Response,
    period: ActiveWeeklyReportPeriod = Query(default="7d"),
) -> ActiveWeeklyReportPreflight:
    organization_id, _actor_id, _actor_role = active_asset_actor(request)
    snapshot = build_active_weekly_snapshot_for_request(
        request,
        organization_id=organization_id,
        period=period,
        state_at=datetime.now(timezone.utc),
    )
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return snapshot.preflight


@app.get(
    "/active/operations/weekly-review-receipts",
    response_model=ActiveWeeklyReviewReceiptPage,
)
async def list_active_weekly_review_receipts(
    request: Request, response: Response
) -> ActiveWeeklyReviewReceiptPage:
    if request.query_params:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Active weekly review receipts do not accept query parameters.",
        )
    organization_id, _actor_id, _actor_role = active_asset_actor(request)
    try:
        page = request.app.state.active_weekly_review_receipts.list(organization_id)
    except ActiveWeeklyReviewReceiptError as exc:
        raise active_weekly_review_receipt_http_error(exc) from exc
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Weekly review receipt storage is temporarily unavailable.",
        ) from exc
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return page


@app.post(
    "/active/operations/weekly-review-receipts",
    response_model=ActiveWeeklyReviewReceiptMutation,
    status_code=status.HTTP_201_CREATED,
)
async def create_active_weekly_review_receipt(
    request: Request,
    response: Response,
    payload: ActiveWeeklyReviewReceiptCreateRequest,
) -> ActiveWeeklyReviewReceiptMutation:
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    observed = datetime.now(timezone.utc)
    if (
        payload.state_at > observed + timedelta(seconds=5)
        or payload.state_at < observed - timedelta(minutes=5)
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The Active report preflight expired. Generate a new preflight.",
        )
    try:
        # All Active stores use the shared lock. Keeping snapshot reconstruction
        # and receipt publication inside it rejects a concurrent portfolio
        # mutation instead of attesting stale state.
        with storage_lock(request.app.state.settings):
            snapshot = build_active_weekly_snapshot_for_request(
                request,
                organization_id=organization_id,
                period=payload.period,
                state_at=payload.state_at,
            )
            if snapshot.digest != payload.snapshot_digest:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="The Active portfolio changed. Generate a new report preflight.",
                )
            result = request.app.state.active_weekly_review_receipts.create_with_shared_lock_held(
                organization_id=organization_id,
                preflight=snapshot.preflight,
                outcome=payload.outcome,
                expected_revision=payload.expected_revision,
                idempotency_key=payload.idempotency_key,
            )
    except ActiveWeeklyReviewReceiptError as exc:
        raise active_weekly_review_receipt_http_error(exc) from exc
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Weekly review receipt storage is temporarily unavailable.",
        ) from exc
    record_product_action(
        request,
        "active_asset.weekly_review_recorded",
        resource_type="active_weekly_review_receipt",
        resource_id=result.receipt.id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={
            "decision_status": result.receipt.outcome,
            "review_period": result.receipt.period,
            "replayed": result.replayed,
        },
    )
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return result


@app.post(
    "/active/operations/weekly-review-receipts/verify",
    response_model=ActiveWeeklyReviewReceiptVerification,
)
async def verify_active_weekly_review_receipt(
    request: Request,
    response: Response,
    payload: ActiveWeeklyReviewReceiptVerifyRequest,
) -> ActiveWeeklyReviewReceiptVerification:
    organization_id, _actor_id, _actor_role = active_asset_actor(request)
    try:
        result = request.app.state.active_weekly_review_receipts.verify(
            organization_id,
            payload.receipt_id,
            payload.snapshot_digest,
        )
    except ActiveWeeklyReviewReceiptError as exc:
        raise active_weekly_review_receipt_http_error(exc) from exc
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Weekly review receipt storage is temporarily unavailable.",
        ) from exc
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return result


@app.post("/active/operations/weekly-report")
async def export_active_weekly_report(
    request: Request, payload: ActiveWeeklyReportExportRequest
) -> Response:
    organization_id, actor_id, actor_role = active_asset_actor(request)
    observed = datetime.now(timezone.utc)
    if (
        payload.state_at > observed + timedelta(seconds=5)
        or payload.state_at < observed - timedelta(minutes=5)
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The Active report preflight expired. Generate a new preflight.",
        )
    snapshot = build_active_weekly_snapshot_for_request(
        request,
        organization_id=organization_id,
        period=payload.period,
        state_at=payload.state_at,
    )
    if snapshot.digest != payload.snapshot_digest:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The Active portfolio changed. Generate a new report preflight.",
        )
    try:
        content = render_active_weekly_report(snapshot, payload.report_format)
    except ActiveWeeklyReportError as exc:
        raise HTTPException(
            status_code=(
                status.HTTP_413_CONTENT_TOO_LARGE
                if exc.code == "report_too_large"
                else status.HTTP_422_UNPROCESSABLE_ENTITY
            ),
            detail="The bounded Active weekly report could not be generated.",
        ) from exc
    extension = "md" if payload.report_format == "markdown" else "json"
    media_type = (
        "text/markdown; charset=utf-8"
        if payload.report_format == "markdown"
        else "application/json"
    )
    record_product_action(
        request,
        "active_asset.weekly_report_exported",
        resource_type="organization",
        resource_id=organization_id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={"report_format": payload.report_format, "review_period": payload.period},
    )
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="inspectra-active-weekly-{payload.period}.{extension}"',
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Inspectra-Snapshot-SHA256": snapshot.digest,
        },
    )


@app.get(
    "/active/assets",
    deprecated=True,
    status_code=status.HTTP_410_GONE,
    responses={status.HTTP_410_GONE: {"description": "Use the bounded POST /active/assets/search contract."}},
)
async def retired_active_asset_list(request: Request) -> JSONResponse:
    active_asset_actor(request)
    return JSONResponse(
        status_code=status.HTTP_410_GONE,
        content={
            "contract_version": "2026-09-08.1",
            "detail": "The unbounded Active asset list has been retired.",
            "successor": "/active/assets/search",
        },
        headers={
            "Deprecation": "true",
            "Sunset": "Tue, 01 Dec 2026 00:00:00 GMT",
            "Link": '</active/assets/search>; rel="successor-version"',
            "Cache-Control": "no-store",
        },
    )


@app.post("/active/assets/search", response_model=ActiveAssetPage)
async def page_active_assets(
    request: Request,
    payload: ActiveAssetPageRequest,
) -> ActiveAssetPage:
    organization_id, _actor_id, _actor_role = active_asset_actor(request)
    try:
        return request.app.state.active_assets.page(
            organization_id=organization_id,
            page_size=payload.page_size,
            cursor=payload.cursor,
            status=payload.status,
            query=payload.query,
            query_mode=payload.query_mode,
            capability=payload.capability,
            updated_within_days=payload.updated_within_days,
        )
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc


@app.get("/active/assets/{asset_id}/deletion", response_model=ActiveAssetDeletionPreview)
async def get_active_asset_deletion_preview(
    request: Request, asset_id: str
) -> ActiveAssetDeletionPreview:
    """Return a target-free manifest of the owner-scoped Active cascade."""

    organization_id, _actor_id, _actor_role = active_asset_actor(request)
    try:
        return request.app.state.active_asset_deletions.preview(
            organization_id=organization_id, asset_id=asset_id
        )
    except ActiveAssetDeletionError as exc:
        if exc.code == "not_found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active asset not found.") from exc
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Active asset deletion state is unavailable.",
        ) from exc


@app.delete("/active/assets/{asset_id}", response_model=ActiveAssetDeletionResponse)
async def delete_active_asset(
    request: Request,
    asset_id: str,
    payload: ActiveAssetDeletionRequest,
) -> ActiveAssetDeletionResponse:
    """Apply or resume the Active cascade after exact administrator consent."""

    del payload
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    try:
        result = request.app.state.active_asset_deletions.delete(
            organization_id=organization_id, asset_id=asset_id
        )
    except ActiveAssetDeletionError as exc:
        if exc.code == "active_work":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cancel Active executions and revoke pending verification challenges before deleting this asset.",
            ) from exc
        if exc.code == "not_found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active asset not found.") from exc
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Active asset deletion did not complete. Its safe retry state was retained.",
        ) from exc
    record_product_action(
        request,
        "active_asset.deleted" if result.state == "completed" else "active_asset.delete_noop",
        resource_type="deleted_active_asset",
        resource_id=result.deletion_receipt_id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={
            "deletion_contract": ACTIVE_ASSET_DELETION_CONTRACT_VERSION,
            "deletion_state": result.state,
        },
    )
    return result


@app.get("/active/assets/{asset_id}", response_model=ActiveAssetRecord)
async def get_active_asset(request: Request, asset_id: str) -> ActiveAssetRecord:
    organization_id, _actor_id, _actor_role = active_asset_actor(request)
    try:
        return request.app.state.active_assets.get(asset_id, organization_id=organization_id)
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc


async def active_verification_runner_ready(request: Request) -> bool:
    checker = getattr(request.app.state, "active_tools_health_checker", check_active_tools_health)
    try:
        health = await checker(
            request.app.state.settings.active_tools_url,
            timeout_seconds=min(request.app.state.settings.active_tools_health_timeout_seconds, 2.0),
        )
    except Exception:
        return False
    capabilities = health.get("capabilities") if isinstance(health, dict) else None
    verification = capabilities.get("active_asset_verification") if isinstance(capabilities, dict) else None
    return health.get("available") is True and isinstance(verification, dict) and verification.get("execution_enabled") is True


@app.get("/active/verification/configuration")
async def get_active_asset_verification_configuration(request: Request) -> dict[str, Any]:
    active_asset_actor(request)
    enabled = bool(request.app.state.settings.active_asset_verification_enabled)
    transport = request.app.state.active_asset_verification_transport
    remote_ready = await active_verification_runner_ready(request) if enabled else False
    return {
        "contract_version": ACTIVE_ASSET_VERIFICATION_CONTRACT_VERSION,
        "enabled": enabled,
        "methods": {
            "manual_attestation": enabled,
            "dns_txt": enabled and remote_ready,
            "http_well_known": enabled and remote_ready,
            "managed_private": enabled and getattr(transport, "managed_checker", None) is not None,
        },
        "remote_runner_ready": remote_ready,
        "challenge_ttl_seconds": ACTIVE_ASSET_VERIFICATION_CHALLENGE_TTL_SECONDS,
        "max_attempts_per_hour": ACTIVE_ASSET_VERIFICATION_MAX_ATTEMPTS_PER_HOUR,
        "legal_authorization_established": False,
        "target_expansion_allowed": False,
    }


@app.get("/active/assets/{asset_id}/verification", response_model=ActiveAssetVerificationView | None)
async def get_active_asset_verification(request: Request, asset_id: str) -> ActiveAssetVerificationView | None:
    organization_id, _actor_id, _actor_role = active_asset_actor(request)
    try:
        request.app.state.active_assets.get(asset_id, organization_id=organization_id)
        record = request.app.state.active_asset_verifications.latest(asset_id, organization_id=organization_id)
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    except ActiveAssetVerificationError as exc:
        raise active_asset_verification_http_error(exc) from exc
    return request.app.state.active_asset_verifications.view(record) if record is not None else None


@app.post("/active/assets/{asset_id}/verification/challenge", response_model=ActiveAssetVerificationChallengeResponse, status_code=status.HTTP_201_CREATED)
async def start_active_asset_verification(
    request: Request,
    asset_id: str,
    payload: ActiveAssetVerificationStartRequest,
) -> ActiveAssetVerificationChallengeResponse:
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    if not request.app.state.settings.active_asset_verification_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Active asset verification is disabled by the operator.")
    if payload.method in {"dns_txt", "http_well_known"} and not await active_verification_runner_ready(request):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Isolated Active verification is temporarily unavailable.")
    try:
        asset = request.app.state.active_assets.get(asset_id, organization_id=organization_id)
        record, token = request.app.state.active_asset_verifications.start(
            asset,
            payload,
            organization_id=organization_id,
            actor_id=actor_id,
        )
        request.app.state.active_assets.append_event(
            asset.id,
            organization_id=organization_id,
            actor_id=actor_id,
            kind="verification_started",
        )
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    except ActiveAssetVerificationError as exc:
        raise active_asset_verification_http_error(exc) from exc
    record_product_action(
        request,
        "active_asset.verification_started",
        resource_type="active_asset",
        resource_id=asset.id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={"verification_method": payload.method},
    )
    return ActiveAssetVerificationChallengeResponse(
        verification=request.app.state.active_asset_verifications.view(record),
        challenge_token=token,
        placement=verification_placement(asset, payload.method),
    )


@app.post("/active/assets/{asset_id}/verification/check", response_model=ActiveAssetVerificationView)
async def check_active_asset_verification(
    request: Request,
    asset_id: str,
    payload: ActiveAssetVerificationCheckRequest,
) -> ActiveAssetVerificationView:
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    if not request.app.state.settings.active_asset_verification_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Active asset verification is disabled by the operator.")
    try:
        asset = request.app.state.active_assets.get(asset_id, organization_id=organization_id)
        if asset.status != "active":
            raise ActiveAssetVerificationError("asset_not_current")
        pending = request.app.state.active_asset_verifications.validate_pending_challenge(
            payload.verification_id,
            asset_id=asset.id,
            organization_id=organization_id,
            challenge_token=payload.challenge_token,
        )
        if pending.method in {"dns_txt", "http_well_known"}:
            runner_task = asyncio.create_task(request.app.state.active_asset_verification_runner.verify(
                method=pending.method,
                target=verification_runner_target(asset, pending.method),
                challenge_token=payload.challenge_token,
            ))
            cancellation_event = asyncio.Event()
            stop_task = asyncio.create_task(wait_for_active_verification_stop(
                request.app,
                pending.id,
                asset.id,
                organization_id,
                cancellation_event,
            ))
            request.app.state.active_verification_cancellation_events[pending.id] = (asset.id, cancellation_event)
            try:
                done, _pending_tasks = await asyncio.wait({runner_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
                if stop_task in done:
                    runner_task.cancel()
                    with suppress(asyncio.CancelledError):
                        await runner_task
                    raise ActiveAssetVerificationError("verification_revoked")
                observation = await runner_task
            except ActiveVerificationRunnerError:
                observation = ActiveAssetVerificationObservation(False, "isolated_runner_unavailable")
            finally:
                stop_task.cancel()
                with suppress(asyncio.CancelledError):
                    await stop_task
                request.app.state.active_verification_cancellation_events.pop(pending.id, None)
        else:
            observation = await asyncio.to_thread(
                verify_observation,
                request.app.state.active_asset_verification_transport,
                asset=asset,
                method=pending.method,
                challenge_token=payload.challenge_token,
                manual_attestation_confirmed=payload.manual_attestation_confirmed,
            )
        completed = request.app.state.active_asset_verifications.complete(
            pending.id,
            asset=asset,
            organization_id=organization_id,
            challenge_token=payload.challenge_token,
            observation=observation,
        )
        request.app.state.active_assets.append_event(
            asset.id,
            organization_id=organization_id,
            actor_id=actor_id,
            kind="verified" if completed.status == "verified" else "verification_failed",
            reason_code=completed.reason_code,
        )
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    except ActiveAssetVerificationError as exc:
        raise active_asset_verification_http_error(exc) from exc
    record_product_action(
        request,
        "active_asset.verification_completed",
        resource_type="active_asset",
        resource_id=asset.id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={"verification_method": completed.method, "verification_status": completed.status},
    )
    return request.app.state.active_asset_verifications.view(completed)


async def wait_for_active_verification_stop(
    app: FastAPI,
    verification_id: str,
    asset_id: str,
    organization_id: str,
    local_event: asyncio.Event,
) -> None:
    """Observe revocation in this process or another backend worker."""

    while not local_event.is_set():
        try:
            record = app.state.active_asset_verifications.get(
                verification_id,
                asset_id=asset_id,
                organization_id=organization_id,
            )
            asset = app.state.active_assets.get(asset_id, organization_id=organization_id)
        except (ActiveAssetVerificationError, ActiveAssetStoreError):
            return
        if record.status != "pending" or asset.status != "active":
            return
        await asyncio.sleep(0.1)


@app.post("/active/assets/{asset_id}/verification/revoke", response_model=ActiveAssetVerificationView)
async def revoke_active_asset_verification(
    request: Request,
    asset_id: str,
    payload: ActiveAssetVerificationRevokeRequest,
) -> ActiveAssetVerificationView:
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    try:
        request.app.state.active_assets.get(asset_id, organization_id=organization_id)
        revoked = request.app.state.active_asset_verifications.revoke(
            payload.verification_id,
            asset_id=asset_id,
            organization_id=organization_id,
        )
        request.app.state.active_recurrences.suspend_for_asset(
            asset_id,
            organization_id=organization_id,
            reason_code="verification_unavailable",
        )
        verification_guard = request.app.state.active_verification_cancellation_events.get(payload.verification_id)
        if verification_guard is not None:
            verification_guard[1].set()
        request.app.state.active_assets.append_event(
            asset_id,
            organization_id=organization_id,
            actor_id=actor_id,
            kind="verification_failed",
            reason_code="operator_revoked",
        )
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    except ActiveAssetVerificationError as exc:
        raise active_asset_verification_http_error(exc) from exc
    record_product_action(
        request,
        "active_asset.verification_revoked",
        resource_type="active_asset",
        resource_id=asset_id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={"verification_method": revoked.method},
    )
    return request.app.state.active_asset_verifications.view(revoked)


@app.get("/active/assets/{asset_id}/posture")
async def get_active_asset_posture(
    request: Request,
    asset_id: str,
    capability: str | None = Query(default=None, max_length=64),
) -> dict[str, Any]:
    organization_id, _actor_id, _actor_role = active_asset_actor(request)
    try:
        asset = request.app.state.active_assets.get(asset_id, organization_id=organization_id)
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    if capability is not None and capability not in asset.capabilities:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Capability is outside the registered asset scope.")
    page_items, total, next_cursor = request.app.state.jobs.page(
        owner_id=organization_id,
        active_asset_id=asset.id,
        page_size=50,
    )
    jobs = active_jobs_for_asset(request, asset.id, organization_id)
    baseline_execution = None
    if asset.baseline_execution_id is not None:
        try:
            baseline_job = active_execution_for_asset(
                request, asset.id, organization_id, asset.baseline_execution_id
            )
        except HTTPException as exc:
            if exc.status_code != status.HTTP_404_NOT_FOUND:
                raise
        else:
            baseline_execution = request.app.state.jobs.get_list_item(baseline_job.id)
            if all(item.id != baseline_job.id for item in jobs):
                jobs.append(baseline_job)
    posture = build_active_posture(jobs, baseline_execution_id=asset.baseline_execution_id, capability=capability)
    return {
        "asset": asset,
        "executions": page_items,
        "baseline_execution": baseline_execution,
        "history": {
            "returned_count": len(page_items),
            "total_count": total,
            "has_more": next_cursor is not None,
            "next_cursor": next_cursor,
            "posture_records_considered": len(jobs),
            "posture_incomplete": total > 500,
        },
        "posture": posture,
    }


@app.post("/active/assets/{asset_id}/executions/search", response_model=JobPage)
async def page_active_asset_executions(
    request: Request, asset_id: str, payload: ActiveExecutionPageRequest
) -> JobPage:
    organization_id, _actor_id, _actor_role = active_asset_actor(request)
    try:
        asset = request.app.state.active_assets.get(asset_id, organization_id=organization_id)
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    items, total, next_cursor = request.app.state.jobs.page(
        owner_id=organization_id,
        active_asset_id=asset.id,
        page_size=payload.page_size,
        cursor=payload.cursor,
    )
    return JobPage(
        items=items,
        returned_count=len(items),
        total_count=total,
        has_more=next_cursor is not None,
        next_cursor=next_cursor,
    )


@app.get("/active/assets/{asset_id}/executions/{job_id}", response_model=JobListItem)
async def get_active_asset_execution_summary(
    request: Request, asset_id: str, job_id: str
) -> JobListItem:
    organization_id, _actor_id, _actor_role = active_asset_actor(request)
    try:
        asset = request.app.state.active_assets.get(asset_id, organization_id=organization_id)
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    job = active_execution_for_asset(request, asset.id, organization_id, job_id)
    return request.app.state.jobs.get_list_item(job.id)


@app.post("/active/assets/{asset_id}/baseline", response_model=ActiveAssetRecord)
async def set_active_asset_baseline(request: Request, asset_id: str, payload: ActiveAssetBaselineRequest) -> ActiveAssetRecord:
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    try:
        asset = request.app.state.active_assets.get(asset_id, organization_id=organization_id)
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    job = active_execution_for_asset(
        request, asset.id, organization_id, payload.execution_id
    )
    if job.status not in {"completed", "failed", "cancelled"}:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only a terminal Active execution can be a baseline.")
    try:
        updated = request.app.state.active_assets.set_baseline(
            asset.id,
            organization_id=organization_id,
            actor_id=actor_id,
            execution_id=job.id,
        )
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    record_product_action(request, "active_asset.baseline_selected", resource_type="active_asset", resource_id=asset.id, organization_id=organization_id, actor_id=actor_id, actor_role=actor_role, metadata={"job_id": job.id})
    return updated


@app.post("/active/assets/{asset_id}/triage", response_model=ActiveAssetRecord)
async def set_active_asset_triage(request: Request, asset_id: str, payload: ActiveAssetTriageRequest) -> ActiveAssetRecord:
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    try:
        updated = request.app.state.active_assets.set_triage(asset_id, organization_id=organization_id, actor_id=actor_id, request=payload)
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    record_product_action(request, "active_asset.triage_updated", resource_type="active_asset", resource_id=asset_id, organization_id=organization_id, actor_id=actor_id, actor_role=actor_role)
    return updated


@app.get("/active/assets/{asset_id}/report")
async def export_active_asset_report(request: Request, asset_id: str) -> Response:
    organization_id, actor_id, actor_role = active_asset_actor(request)
    try:
        asset = request.app.state.active_assets.get(asset_id, organization_id=organization_id)
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    jobs = request.app.state.jobs.active_asset_complete_history(
        owner_id=organization_id, asset_id=asset.id
    )
    content = build_active_asset_markdown_report(asset, jobs)
    record_product_action(request, "active_asset.report_exported", resource_type="active_asset", resource_id=asset.id, organization_id=organization_id, actor_id=actor_id, actor_role=actor_role)
    return Response(
        content=content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="inspectra-active-{asset.id[:12]}.md"'},
    )


@app.get("/active/assets/{asset_id}/evidence-bundle")
async def export_active_asset_evidence_bundle(
    request: Request,
    asset_id: str,
    period: Literal["30d", "90d", "365d", "all"] = Query(default="90d"),
) -> Response:
    organization_id, actor_id, actor_role = active_asset_actor(request)
    try:
        asset = request.app.state.active_assets.get(asset_id, organization_id=organization_id)
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    try:
        jobs = request.app.state.jobs.active_asset_complete_history(
            owner_id=organization_id, asset_id=asset.id
        )
        bundle = build_active_evidence_bundle(
            asset,
            jobs,
            period=period,
            source_selection_incomplete=False,
        )
    except ActiveEvidenceBundleError as exc:
        status_code = status.HTTP_413_CONTENT_TOO_LARGE if exc.code in {"entry_too_large", "bundle_too_large"} else status.HTTP_503_SERVICE_UNAVAILABLE
        raise HTTPException(status_code=status_code, detail="The bounded evidence bundle could not be generated.") from exc
    record_product_action(
        request,
        "active_asset.evidence_bundle_exported",
        resource_type="active_asset",
        resource_id=asset.id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={"report_format": "active_evidence_tar"},
    )
    return Response(
        content=bundle.payload,
        media_type="application/x-tar",
        headers={
            "Content-Disposition": f'attachment; filename="inspectra-active-evidence-{asset.id[:12]}.tar"',
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Inspectra-Evidence-SHA256": bundle.sha256,
        },
    )


@app.post("/active/assets/{asset_id}/revoke", response_model=ActiveAssetRecord)
async def revoke_active_asset(request: Request, asset_id: str, payload: ActiveAssetRevokeRequest) -> ActiveAssetRecord:
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    emergency_bypass = (
        _active_four_eyes_available(request)
        and payload.reason_code == "security_hold"
        and actor_role == "administrator"
    )
    approval_id = None if emergency_bypass else _claim_active_change(
        request, organization_id=organization_id, actor_id=actor_id,
        kind="revocation", asset_id=asset_id, payload=payload,
    )
    try:
        asset = request.app.state.active_assets.revoke(
            asset_id,
            organization_id=organization_id,
            actor_id=actor_id,
            reason_code=payload.reason_code,
        )
    except ActiveAssetStoreError as exc:
        _finish_active_change(request, organization_id, approval_id, succeeded=False)
        raise active_asset_http_error(exc) from exc
    except BaseException:
        _finish_active_change(request, organization_id, approval_id, succeeded=False)
        raise
    _finish_active_change(request, organization_id, approval_id, succeeded=True)
    request.app.state.active_recurrences.suspend_for_asset(
        asset.id, organization_id=organization_id
    )
    for job in request.app.state.jobs.active_asset_inflight_history(
        owner_id=organization_id, asset_id=asset.id
    ):
        if job.status not in {"queued", "running", "cancelling"}:
            continue
        request.app.state.jobs.request_active_authorization_revocation(
            job.id,
            owner_id=organization_id,
            active_asset_id=asset.id,
        )
    for cancellation_event in list(getattr(request.app.state, "active_asset_revocation_events", {}).get(asset.id, set())):
        cancellation_event.set()
    for guarded_asset_id, verification_event in list(
        getattr(request.app.state, "active_verification_cancellation_events", {}).values()
    ):
        if guarded_asset_id == asset.id:
            verification_event.set()
    record_product_action(
        request,
        "active_asset.revoked",
        resource_type="active_asset",
        resource_id=asset.id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={"four_eyes_emergency_bypass": emergency_bypass},
    )
    return asset


@app.get("/active/assets/{asset_id}/recurrences", response_model=ActiveRecurrenceListResponse)
async def list_active_asset_recurrences(request: Request, asset_id: str) -> ActiveRecurrenceListResponse:
    organization_id, _actor_id, _actor_role = active_asset_actor(request)
    try:
        request.app.state.active_assets.get(asset_id, organization_id=organization_id)
        records = request.app.state.active_recurrences.list_for_asset(
            asset_id, organization_id=organization_id
        )
    except (ActiveAssetStoreError, ActiveRecurrenceError) as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active asset not found.") from exc
    return ActiveRecurrenceListResponse(
        enabled=request.app.state.settings.active_recurrence_enabled,
        items=[request.app.state.active_recurrences.view(item) for item in records],
    )


@app.post(
    "/active/assets/{asset_id}/recurrences",
    response_model=ActiveRecurrenceView,
    status_code=status.HTTP_201_CREATED,
)
async def create_active_asset_recurrence(
    request: Request, asset_id: str, payload: ActiveRecurrenceCreateRequest
) -> ActiveRecurrenceView:
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    if not request.app.state.settings.active_recurrence_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Recurring Active reviews are disabled by the operator.")
    if not request.app.state.settings.active_asset_verification_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A current control verification is required before recurring review.")
    if not active_capability_enabled(request.app.state.settings, payload.capability):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This Active capability is disabled by the operator.")
    try:
        asset = request.app.state.active_assets.get(asset_id, organization_id=organization_id)
        revision = current_active_authorization_revision(asset)
        if revision is None:
            raise ActiveAssetStoreError("authorization_revision_required")
        request.app.state.active_assets.assert_executable(
            asset.id,
            organization_id=organization_id,
            capability=payload.capability,
            expected_authorization_revision_id=revision.id,
        )
        if payload.port is not None and payload.port not in asset.allowed_ports:
            raise ActiveAssetStoreError("capability_not_authorized")
        if payload.capability == "active_tls_basic" and payload.port is None:
            raise ActiveAssetStoreError("capability_not_authorized")
        verification = request.app.state.active_asset_verifications.latest(
            asset.id, organization_id=organization_id
        )
        if verification is None or verification.status != "verified":
            raise ActiveAssetVerificationError("verification_required")
        recurrence, replayed = request.app.state.active_recurrences.create(
            payload,
            organization_id=organization_id,
            asset_id=asset.id,
            actor_id=actor_id,
            actor_role=actor_role,
            authorization_revision_id=revision.id,
            authorization_revision_digest_sha256=revision.digest_sha256,
            authorization_revision_sequence=revision.sequence,
            authorization_expires_at=revision.expires_at,
            verification_id=verification.id,
        )
    except ActiveAssetVerificationError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A current control verification is required before recurring review.") from exc
    except ActiveRecurrenceError as exc:
        code = str(exc)
        if code in {"schedule_conflict", "idempotency_conflict", "state_changed"}:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The recurring review already exists or changed. Refresh before retrying.") from exc
        if code == "authorization_window_unavailable":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="No eligible recurring window remains inside the current authorization. Renew authorization or choose an earlier cadence/window.") from exc
        if code == "capacity_reached":
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Recurring review capacity is full.", headers={"Retry-After": "60"}) from exc
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active asset not found.") from exc
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    record_product_action(
        request,
        "active_recurrence.created",
        resource_type="active_recurrence",
        resource_id=recurrence.id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={
            "authorization_revision_id": recurrence.authorization_revision_id,
            "authorization_revision_sequence": recurrence.authorization_revision_sequence,
            "replayed": replayed,
        },
    )
    return request.app.state.active_recurrences.view(recurrence)


@app.post("/active/assets/{asset_id}/recurrences/{schedule_id}/pause", response_model=ActiveRecurrenceView)
async def pause_active_asset_recurrence(
    request: Request, asset_id: str, schedule_id: str, payload: ActiveRecurrenceMutationRequest
) -> ActiveRecurrenceView:
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    try:
        recurrence = request.app.state.active_recurrences.pause(
            schedule_id,
            organization_id=organization_id,
            asset_id=asset_id,
            expected_updated_at=payload.expected_updated_at,
        )
    except ActiveRecurrenceError as exc:
        if str(exc) == "state_changed":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The recurring review changed. Refresh before retrying.") from exc
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recurring review not found.") from exc
    record_product_action(request, "active_recurrence.paused", resource_type="active_recurrence", resource_id=recurrence.id, organization_id=organization_id, actor_id=actor_id, actor_role=actor_role)
    return request.app.state.active_recurrences.view(recurrence)


@app.post("/active/assets/{asset_id}/recurrences/{schedule_id}/resume", response_model=ActiveRecurrenceView)
async def resume_active_asset_recurrence(
    request: Request, asset_id: str, schedule_id: str, payload: ActiveRecurrenceMutationRequest
) -> ActiveRecurrenceView:
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    if not request.app.state.settings.active_recurrence_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Recurring Active reviews are disabled by the operator.")
    try:
        asset = request.app.state.active_assets.get(asset_id, organization_id=organization_id)
        current = request.app.state.active_recurrences.get(schedule_id, organization_id=organization_id, asset_id=asset_id)
        if not active_capability_enabled(request.app.state.settings, current.capability):
            raise ActiveAssetStoreError("capability_not_authorized")
        revision = current_active_authorization_revision(asset)
        if revision is None:
            raise ActiveAssetStoreError("authorization_revision_required")
        request.app.state.active_assets.assert_executable(asset.id, organization_id=organization_id, capability=current.capability, expected_authorization_revision_id=revision.id)
        verification = request.app.state.active_asset_verifications.latest(asset.id, organization_id=organization_id)
        if verification is None or verification.status != "verified":
            raise ActiveAssetVerificationError("verification_required")
        recurrence = request.app.state.active_recurrences.resume(
            schedule_id,
            organization_id=organization_id,
            asset_id=asset_id,
            expected_updated_at=payload.expected_updated_at,
            authorization_revision_id=revision.id,
            authorization_revision_digest_sha256=revision.digest_sha256,
            authorization_revision_sequence=revision.sequence,
            authorization_expires_at=revision.expires_at,
            verification_id=verification.id,
        )
    except ActiveAssetVerificationError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A current control verification is required before recurring review.") from exc
    except ActiveRecurrenceError as exc:
        if str(exc) == "state_changed":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The recurring review changed. Refresh before retrying.") from exc
        if str(exc) == "authorization_window_unavailable":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="No eligible recurring window remains inside the current authorization. Renew authorization or choose an earlier cadence/window.") from exc
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recurring review not found.") from exc
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    record_product_action(request, "active_recurrence.resumed", resource_type="active_recurrence", resource_id=recurrence.id, organization_id=organization_id, actor_id=actor_id, actor_role=actor_role)
    return request.app.state.active_recurrences.view(recurrence)


@app.delete("/active/assets/{asset_id}/recurrences/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_active_asset_recurrence(
    request: Request, asset_id: str, schedule_id: str, payload: ActiveRecurrenceDeleteRequest
) -> Response:
    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    try:
        request.app.state.active_recurrences.delete(schedule_id, organization_id=organization_id, asset_id=asset_id)
    except ActiveRecurrenceError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recurring review not found.") from exc
    record_product_action(request, "active_recurrence.deleted", resource_type="active_recurrence", resource_id=schedule_id, organization_id=organization_id, actor_id=actor_id, actor_role=actor_role)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post("/active/assets/{asset_id}/executions", response_model=JobDetailView, status_code=status.HTTP_202_ACCEPTED)
async def launch_active_asset_execution(
    request: Request,
    background_tasks: BackgroundTasks,
    asset_id: str,
    payload: ActiveAssetExecutionRequest,
) -> JobDetailView:
    """Persist and dispatch one immutable, idempotent Active execution."""

    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    if not active_capability_enabled(request.app.state.settings, payload.capability):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This Active capability is disabled by the operator.")

    checker = getattr(request.app.state, "active_tools_health_checker", check_active_tools_health)
    try:
        runner_health = await checker(
            request.app.state.settings.active_tools_url,
            timeout_seconds=min(request.app.state.settings.active_tools_health_timeout_seconds, 2.0),
        )
    except Exception:
        runner_health = {"available": False, "capabilities": {}, "error_code": "active_tools_unavailable"}
    readiness = build_active_capability_readiness(
        payload.capability,
        backend_enabled=True,
        runner_health=runner_health,
    )
    if readiness["readiness"] != "ready":
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="The isolated Active runner is not ready for this capability.")

    try:
        asset = request.app.state.active_assets.get(asset_id, organization_id=organization_id)
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    if payload.port is not None and payload.port not in asset.allowed_ports:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Selected port is outside the authorized asset scope.")
    authorization_revision = current_active_authorization_revision(asset)
    if authorization_revision is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Active asset authorization must be re-attested before execution.")
    try:
        request.app.state.active_assets.assert_executable(
            asset.id,
            organization_id=organization_id,
            capability=payload.capability,
            expected_authorization_revision_id=authorization_revision.id,
        )
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    selected_port = payload.port or (
        asset.allowed_ports[0]
        if payload.capability == "active_tls_basic" and asset.allowed_ports
        else None
    )
    if payload.capability == "active_tls_basic" and selected_port is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="An authorized TLS port is required.")

    job, replayed = request.app.state.jobs.create_active_asset_execution_job(
        payload.capability,
        owner_id=organization_id,
        active_asset_id=asset.id,
        active_authorization_contract=ACTIVE_ASSET_CONTRACT_VERSION,
        active_authorization_revision_id=authorization_revision.id,
        active_authorization_revision_digest_sha256=authorization_revision.digest_sha256,
        active_authorization_revision_sequence=authorization_revision.sequence,
        active_execution_port=selected_port,
        idempotency_key_sha256=hashlib.sha256(payload.idempotency_key.encode("ascii")).hexdigest(),
    )
    if not replayed:
        try:
            request.app.state.active_assets.admit_execution(
                asset.id,
                organization_id=organization_id,
                actor_id=actor_id,
                capability=payload.capability,
            )
            request.app.state.active_assets.assert_executable(
                asset.id,
                organization_id=organization_id,
                capability=payload.capability,
                expected_authorization_revision_id=authorization_revision.id,
            )
        except ActiveAssetStoreError as exc:
            request.app.state.jobs.update(
                job.id,
                status="failed",
                error="The Active execution was rejected because its authorization changed before dispatch.",
                termination_reason="recovery_rejected",
                active_execution_phase="terminal",
            )
            raise active_asset_http_error(exc) from exc

    if job.status == "queued":
        schedule_active_execution_once(background_tasks, request.app, job.id)

    record_product_action(
        request,
        "active_asset.execution_requested",
        resource_type="active_asset",
        resource_id=asset.id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={
            "job_id": job.id,
            "authorization_revision_id": authorization_revision.id,
            "authorization_revision_sequence": authorization_revision.sequence,
            "replayed": replayed,
        },
    )
    return JobDetailView.model_validate(job)


@app.post("/active/assets/{asset_id}/executions/{job_id}/cancel", response_model=JobDetailView)
async def cancel_active_asset_execution(
    request: Request,
    asset_id: str,
    job_id: str,
    payload: ActiveAssetExecutionCancelRequest,
) -> JobDetailView:
    """Persist a scoped cancellation request before signalling the runner."""

    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    try:
        request.app.state.active_assets.get(asset_id, organization_id=organization_id)
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    job = request.app.state.jobs.get(job_id)
    if job.owner_id != organization_id or job.active_asset_id != asset_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active execution not found.")
    cancelled = request.app.state.jobs.request_cancellation(job_id, owner_id=organization_id)
    cancellation_event = request.app.state.active_execution_cancellation_events.get(job_id)
    if cancellation_event is not None:
        cancellation_event.set()
    elif job.status == "queued" and cancelled.status == "cancelling":
        cancelled = request.app.state.jobs.mark_cancelled(job_id)
    record_product_action(
        request,
        "active_asset.execution_cancelled",
        resource_type="active_execution",
        resource_id=job_id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
    )
    return JobDetailView.model_validate(cancelled)


@app.post("/active/assets/{asset_id}/executions/{job_id}/retry", response_model=JobDetailView, status_code=status.HTTP_202_ACCEPTED)
async def retry_active_asset_execution(
    request: Request,
    background_tasks: BackgroundTasks,
    asset_id: str,
    job_id: str,
    payload: ActiveAssetExecutionRetryRequest,
) -> JobDetailView:
    """Create one linked attempt after fresh authorization and readiness checks."""

    organization_id, actor_id, actor_role = active_asset_actor(request, write=True)
    previous = request.app.state.jobs.get(job_id)
    if previous.owner_id != organization_id or previous.active_asset_id != asset_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active execution not found.")
    if previous.status not in {"failed", "cancelled"}:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only a failed or cancelled Active execution can be retried.")
    if not active_capability_enabled(request.app.state.settings, previous.audit_type):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This Active capability is disabled by the operator.")
    checker = getattr(request.app.state, "active_tools_health_checker", check_active_tools_health)
    try:
        runner_health = await checker(
            request.app.state.settings.active_tools_url,
            timeout_seconds=min(request.app.state.settings.active_tools_health_timeout_seconds, 2.0),
        )
    except Exception:
        runner_health = {"available": False, "capabilities": {}, "error_code": "active_tools_unavailable"}
    readiness = build_active_capability_readiness(previous.audit_type, backend_enabled=True, runner_health=runner_health)
    if readiness["readiness"] != "ready":
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="The isolated Active runner is not ready for this capability.")
    try:
        asset = request.app.state.active_assets.get(asset_id, organization_id=organization_id)
        revision = current_active_authorization_revision(asset)
        if revision is None:
            raise ActiveAssetStoreError("authorization_revision_required")
        if previous.active_execution_port is not None and previous.active_execution_port not in asset.allowed_ports:
            raise ActiveAssetStoreError("capability_not_authorized")
        request.app.state.active_assets.assert_executable(
            asset.id,
            organization_id=organization_id,
            capability=previous.audit_type,
            expected_authorization_revision_id=revision.id,
        )
        retried, replayed = request.app.state.jobs.create_active_asset_execution_job(
            previous.audit_type,
            owner_id=organization_id,
            active_asset_id=asset.id,
            active_authorization_contract=ACTIVE_ASSET_CONTRACT_VERSION,
            active_authorization_revision_id=revision.id,
            active_authorization_revision_digest_sha256=revision.digest_sha256,
            active_authorization_revision_sequence=revision.sequence,
            active_execution_port=previous.active_execution_port,
            idempotency_key_sha256=hashlib.sha256(payload.idempotency_key.encode("ascii")).hexdigest(),
            retry_of_job_id=previous.id,
        )
        if not replayed:
            try:
                request.app.state.active_assets.admit_execution(
                    asset.id,
                    organization_id=organization_id,
                    actor_id=actor_id,
                    capability=previous.audit_type,
                )
                request.app.state.active_assets.assert_executable(
                    asset.id,
                    organization_id=organization_id,
                    capability=previous.audit_type,
                    expected_authorization_revision_id=revision.id,
                )
            except ActiveAssetStoreError:
                request.app.state.jobs.update(
                    retried.id,
                    status="failed",
                    error="The Active retry was rejected because its authorization changed before dispatch.",
                    termination_reason="recovery_rejected",
                    active_execution_phase="terminal",
                )
                raise
    except ActiveAssetStoreError as exc:
        raise active_asset_http_error(exc) from exc
    if retried.status == "queued":
        schedule_active_execution_once(background_tasks, request.app, retried.id)
    record_product_action(
        request,
        "active_asset.execution_retried",
        resource_type="active_execution",
        resource_id=retried.id,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        metadata={"job_id": previous.id, "replayed": replayed, "retry": True},
    )
    return JobDetailView.model_validate(retried)


async def run_durable_active_execution(app: FastAPI, job_id: str) -> None:
    """Execute one claimed Active job and persist every terminal outcome."""

    claimed = app.state.jobs.claim_queued_active_execution(job_id)
    if claimed is None:
        return
    rejection = queued_active_recovery_rejection(app, claimed)
    if rejection is not None:
        app.state.jobs.update(
            job_id,
            status="failed",
            error="The Active execution could not start because its authorization or execution contract changed.",
            termination_reason="recovery_rejected",
            active_execution_phase="terminal",
        )
        log_audit_event(
            "active_asset.execution_rejected_before_runner",
            correlation_id=f"job:{job_id}",
            job_id=job_id,
            owner_id=claimed.owner_id,
            reason_code=rejection,
        )
        return

    try:
        asset = app.state.active_assets.get(claimed.active_asset_id, organization_id=claimed.owner_id)
        target = asset_target_for_capability(asset, claimed.audit_type, port=claimed.active_execution_port)
    except ActiveAssetStoreError:
        app.state.jobs.update(
            job_id,
            status="failed",
            error="The Active execution could not reconstruct its authorized asset boundary.",
            termination_reason="recovery_rejected",
            active_execution_phase="terminal",
        )
        return

    cancellation_event = asyncio.Event()
    app.state.active_execution_cancellation_events[job_id] = cancellation_event
    guards = app.state.active_asset_revocation_events.setdefault(asset.id, set())
    guards.add(cancellation_event)
    execution_task: asyncio.Task[Any] | None = None
    cancellation_task = asyncio.create_task(
        wait_for_active_execution_stop(app, claimed, cancellation_event)
    )
    try:
        if app.state.jobs.get(job_id).status != "running":
            return
        try:
            app.state.active_assets.assert_executable(
                asset.id,
                organization_id=claimed.owner_id,
                capability=claimed.audit_type,
                expected_authorization_revision_id=claimed.active_authorization_revision_id,
            )
        except ActiveAssetStoreError:
            app.state.jobs.update(
                job_id,
                status="failed",
                error="The Active execution was rejected because authorization changed before the runner boundary.",
                termination_reason="recovery_rejected",
                active_execution_phase="terminal",
            )
            return
        app.state.jobs.update(job_id, status="running", active_execution_phase="executing")
        if claimed.audit_type == "active_nmap_basic":
            nmap_payload = {
                "mode": ACTIVE_NMAP_BASIC_MODE,
                "profile": ACTIVE_NMAP_BASIC_PROFILE,
                "targets": [target],
                "ports": asset.allowed_ports,
                "authorization_confirmed": True,
                "local_private_scope_confirmed": True,
                "live_traffic_confirmed": True,
            }
            validate_active_nmap_basic_contract(nmap_payload)
            handoff_plan = build_active_nmap_basic_handoff_plan(nmap_payload)
            lifecycle_runner = getattr(app.state, "active_nmap_basic_lifecycle_runner", run_active_nmap_basic_lifecycle_skeleton)
            lifecycle_client = getattr(app.state, "active_nmap_basic_lifecycle_client", ActiveNmapBasicRouteActiveToolsClient())
            client_mode = getattr(lifecycle_client, "client_mode", None)
            execution_task = asyncio.create_task(
                lifecycle_runner(
                    app.state.settings,
                    handoff_plan,
                    client=lifecycle_client,
                    internal_approval_confirmed=True,
                    fake_client_approved=client_mode == ActiveNmapBasicRouteNoLiveClient.client_mode,
                    active_tools_real_client_approved=client_mode == ActiveNmapBasicRouteActiveToolsClient.client_mode,
                )
            )
        else:
            execution_task = asyncio.create_task(
                _run_active_capability_with_semaphore(
                    app.state.active_capability_semaphore,
                    app.state.active_capability_runner,
                    capability=claimed.audit_type,
                    target=target,
                    port=claimed.active_execution_port,
                )
            )

        done, _pending = await asyncio.wait({execution_task, cancellation_task}, return_when=asyncio.FIRST_COMPLETED)
        if cancellation_task in done:
            execution_task.cancel()
            with suppress(asyncio.CancelledError):
                await execution_task
            latest = app.state.jobs.get(job_id)
            owner_cancelled = latest.termination_reason != "authorization_revoked" and latest.cancellation_requested_at is not None
            app.state.jobs.update(
                job_id,
                status="cancelled",
                error=(
                    "Active execution cancelled by its owner. Partial observations were discarded."
                    if owner_cancelled
                    else "Active execution cancelled after authorization was revoked. Partial observations were discarded."
                ),
                termination_reason="cancelled_by_owner" if owner_cancelled else "authorization_revoked",
                active_execution_phase="terminal",
            )
            return

        raw_result = await execution_task
        app.state.jobs.update(job_id, status="running", active_execution_phase="normalizing")
        result, job_status, job_error = normalize_durable_active_result(claimed, asset, target, raw_result)
        app.state.jobs.update(
            job_id,
            status=job_status,
            result=result,
            error=job_error,
            termination_reason="completed" if job_status == "completed" else "runner_contract_invalid",
            active_execution_phase="terminal",
        )
    except asyncio.CancelledError:
        if execution_task is not None:
            execution_task.cancel()
            with suppress(asyncio.CancelledError):
                await execution_task
        raise
    except ActiveCapabilityRunnerError as exc:
        reason = "runner_timeout" if "timeout" in str(exc) else "runner_unavailable"
        app.state.jobs.update(
            job_id,
            status="failed",
            error="The isolated Active runner could not complete the bounded capability.",
            termination_reason=reason,
            active_execution_phase="terminal",
        )
    except (ValueError, TypeError, KeyError, ActiveHttpBasicHeaderReviewContractError):
        app.state.jobs.update(
            job_id,
            status="failed",
            error="The isolated Active runner returned an invalid bounded result.",
            termination_reason="runner_contract_invalid",
            active_execution_phase="terminal",
        )
    except Exception:
        app.state.jobs.update(
            job_id,
            status="failed",
            error="The Active execution stopped with a controlled internal error.",
            termination_reason="internal_error",
            active_execution_phase="terminal",
        )
    finally:
        cancellation_task.cancel()
        app.state.active_execution_cancellation_events.pop(job_id, None)
        guards.discard(cancellation_event)
        if not guards:
            app.state.active_asset_revocation_events.pop(asset.id, None)


async def wait_for_active_execution_stop(app: FastAPI, job: JobRecord, local_event: asyncio.Event) -> None:
    """Observe process-local signals and persisted cross-worker cancellation."""

    while not local_event.is_set():
        latest = app.state.jobs.get(job.id)
        if latest.status in {"cancelling", "cancelled"}:
            return
        try:
            app.state.active_assets.assert_executable(
                job.active_asset_id,
                organization_id=job.owner_id,
                capability=job.audit_type,
                expected_authorization_revision_id=job.active_authorization_revision_id,
            )
        except ActiveAssetStoreError:
            return
        await asyncio.sleep(0.1)


def normalize_durable_active_result(
    job: JobRecord,
    asset: ActiveAssetRecord,
    target: str,
    raw_result: dict[str, Any],
) -> tuple[dict[str, Any], Literal["completed", "failed"], str | None]:
    """Normalize a runner response without retaining the reconstructed target."""

    if job.audit_type == "active_http_basic_header_review":
        if not active_http_basic_header_review_is_persistable(raw_result):
            raise ActiveHttpBasicHeaderReviewContractError("result_not_persistable")
        result = build_active_http_basic_header_review_persisted_result(raw_result)
        return result, active_http_basic_header_review_job_status(result), None
    if job.audit_type == "active_dns_inventory":
        return raw_result, active_dns_inventory_job_status(raw_result), active_dns_inventory_job_error(raw_result)
    if job.audit_type == "active_dns_osint":
        return raw_result, active_dns_osint_job_status(raw_result), active_dns_osint_job_error(raw_result)
    if job.audit_type == "active_tls_basic":
        return raw_result, active_tls_basic_job_status(raw_result), active_tls_basic_job_error(raw_result)
    if job.audit_type != "active_nmap_basic":
        raise ValueError("unsupported_active_capability")

    nmap_payload = {
        "mode": ACTIVE_NMAP_BASIC_MODE,
        "profile": ACTIVE_NMAP_BASIC_PROFILE,
        "targets": [target],
        "ports": asset.allowed_ports,
        "authorization_confirmed": True,
        "local_private_scope_confirmed": True,
        "live_traffic_confirmed": True,
    }
    route_result = normalize_active_nmap_basic_lifecycle_route_result(raw_result)
    handoff_plan = build_active_nmap_basic_handoff_plan(nmap_payload)
    real = is_active_nmap_basic_real_lifecycle_result(route_result)
    result = (
        build_active_nmap_basic_real_job_result(route_result, nmap_payload, handoff_plan=handoff_plan)
        if real
        else build_active_nmap_basic_no_live_job_result(route_result, nmap_payload, handoff_plan=handoff_plan)
    )
    result["authorization"] = active_asset_result_metadata(asset.id, job.active_authorization_revision_id)
    return (
        result,
        active_nmap_basic_real_job_status(result) if real else active_nmap_basic_no_live_job_status(result),
        active_nmap_basic_real_job_error(result) if real else active_nmap_basic_no_live_job_error(result),
    )


async def _run_active_capability_with_semaphore(
    semaphore: asyncio.Semaphore,
    runner: Any,
    *,
    capability: str,
    target: str,
    port: int | None,
) -> dict[str, Any]:
    async with semaphore:
        return await runner.execute(capability=capability, target=target, port=port)


@app.post("/active/network/dry-run", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_active_network_dry_run(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: Any = Body(...),
) -> JobRecord:
    if not request.app.state.settings.active_dry_run_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Active dry-run checks are disabled in this environment.")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Active dry-run request body must be a JSON object.")
    if "target" not in payload or not str(payload.get("target", "")).strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Active dry-run target is required.")
    try:
        active_request = ActiveDryRunRequest.from_mapping(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid active dry-run request: {exc}") from exc

    target_display = redact_active_secret_text(str(payload.get("target", ""))) if payload.get("target") is not None else ""
    job = request.app.state.jobs.create_active_network_dry_run_job(target_display, owner_id=current_owner_id_for_request(request))
    schedule_bounded_audit(
        background_tasks,
        request.app,
        request.app.state.active_network_dry_runs.run_active_network_dry_run_analysis,
        job.id,
        active_request,
    )
    return job


@app.post("/active/network/http-header-probe", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_active_http_header_probe(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: Any = Body(...),
) -> JobRecord:
    require_legacy_active_free_target_enabled(request)
    if not request.app.state.settings.active_http_header_probe_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Active HTTP header probe is disabled in this environment.")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Active HTTP header probe request body must be a JSON object.")
    if "target" not in payload or not str(payload.get("target", "")).strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Active HTTP header probe target is required.")
    try:
        active_request = ActiveHttpHeaderProbeRequest.from_mapping(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid active HTTP header probe request: {exc}") from exc

    target_display = redact_active_secret_text(str(payload.get("target", ""))) if payload.get("target") is not None else ""
    job = request.app.state.jobs.create_active_http_header_probe_job(target_display, owner_id=current_owner_id_for_request(request))
    schedule_bounded_audit(
        background_tasks,
        request.app,
        request.app.state.active_http_header_probes.run_active_http_header_probe_analysis,
        job.id,
        active_request,
    )
    return job


@app.post("/active/web/http-basic-header-review")
async def launch_active_http_basic_header_review(
    request: Request,
    response: Response,
    payload: Any = Body(...),
) -> JobRecord | dict[str, Any]:
    require_legacy_active_free_target_enabled(request)
    try:
        result = build_active_http_basic_header_review_response(
            payload,
            enabled=request.app.state.settings.active_http_basic_header_review_enabled,
            live_head_enabled=request.app.state.settings.active_http_basic_header_review_live_head_enabled,
            resolver=getattr(request.app.state, "active_http_basic_header_review_resolver", None),
            head_transport=getattr(request.app.state, "active_http_basic_header_review_head_transport", None),
        )
    except ActiveHttpBasicHeaderReviewContractError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=exc.message,
        ) from exc

    if not active_http_basic_header_review_is_persistable(result):
        return result

    persisted_result = build_active_http_basic_header_review_persisted_result(result)
    response.status_code = status.HTTP_202_ACCEPTED
    return request.app.state.jobs.create_active_http_basic_header_review_job(
        persisted_result,
        status=active_http_basic_header_review_job_status(persisted_result),
        owner_id=current_owner_id_for_request(request),
    )


@app.post("/active/network/nmap-basic", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_active_nmap_basic(
    request: Request,
    payload: Any = Body(...),
) -> JobRecord:
    require_legacy_active_free_target_enabled(request)
    if not request.app.state.settings.active_nmap_basic_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="active_nmap_basic is disabled in this environment.",
        )

    owner_id = current_owner_id_for_request(request)
    validate_active_nmap_basic_contract(payload)
    handoff_plan = build_active_nmap_basic_handoff_plan(payload)
    lifecycle_runner = getattr(
        request.app.state,
        "active_nmap_basic_lifecycle_runner",
        run_active_nmap_basic_lifecycle_skeleton,
    )
    lifecycle_client = getattr(
        request.app.state,
        "active_nmap_basic_lifecycle_client",
        ActiveNmapBasicRouteActiveToolsClient(),
    )
    client_mode = getattr(lifecycle_client, "client_mode", None)
    lifecycle_result = await lifecycle_runner(
        request.app.state.settings,
        handoff_plan,
        client=lifecycle_client,
        internal_approval_confirmed=True,
        fake_client_approved=client_mode == ActiveNmapBasicRouteNoLiveClient.client_mode,
        active_tools_real_client_approved=client_mode == ActiveNmapBasicRouteActiveToolsClient.client_mode,
    )
    route_result = normalize_active_nmap_basic_lifecycle_route_result(lifecycle_result)
    if is_active_nmap_basic_real_lifecycle_result(route_result):
        try:
            job_result = build_active_nmap_basic_real_job_result(route_result, payload, handoff_plan=handoff_plan)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="active_nmap_basic real persistence result was unsafe.",
            ) from exc
        return request.app.state.jobs.create_active_nmap_basic_no_live_job(
            job_result,
            status=active_nmap_basic_real_job_status(job_result),
            error=active_nmap_basic_real_job_error(job_result),
            owner_id=owner_id,
        )

    try:
        job_result = build_active_nmap_basic_no_live_job_result(route_result, payload, handoff_plan=handoff_plan)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="active_nmap_basic no-live persistence result was unsafe.",
        ) from exc
    return request.app.state.jobs.create_active_nmap_basic_no_live_job(
        job_result,
        status=active_nmap_basic_no_live_job_status(job_result),
        error=active_nmap_basic_no_live_job_error(job_result),
        owner_id=owner_id,
    )


@app.post("/active/network/tls-basic", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_active_tls_basic(
    request: Request,
    payload: Any = Body(...),
) -> JobRecord:
    require_legacy_active_free_target_enabled(request)
    if not request.app.state.settings.active_tls_basic_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="active_tls_basic is disabled in this environment.",
        )

    owner_id = current_owner_id_for_request(request)
    contract = validate_active_tls_basic_contract(payload)
    connector = getattr(request.app.state, "active_tls_basic_connector", None)
    now = getattr(request.app.state, "active_tls_basic_now", None)
    result = run_active_tls_basic(
        ActiveTlsBasicRequest(
            target=contract["target"],
            port=contract["port"],
            timeout_seconds=ACTIVE_TLS_BASIC_DEFAULT_TIMEOUT_SECONDS,
        ),
        connector=connector,
        now=now,
    )
    return request.app.state.jobs.create_active_tls_basic_job(
        result,
        status=active_tls_basic_job_status(result),
        error=active_tls_basic_job_error(result),
        owner_id=owner_id,
    )


@app.post("/active/network/dns-inventory", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_active_dns_inventory(
    request: Request,
    payload: Any = Body(...),
) -> JobRecord:
    require_legacy_active_free_target_enabled(request)
    if not request.app.state.settings.active_dns_inventory_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="active_dns_inventory is disabled in this environment.",
        )

    owner_id = current_owner_id_for_request(request)
    contract = validate_active_dns_inventory_contract(payload)
    resolver = getattr(request.app.state, "active_dns_inventory_resolver", None)
    axfr_transport = getattr(request.app.state, "active_dns_inventory_axfr_transport", None)
    result = run_active_dns_inventory(contract, resolver=resolver, axfr_transport=axfr_transport)
    return request.app.state.jobs.create_active_dns_inventory_job(
        result,
        status=active_dns_inventory_job_status(result),
        error=active_dns_inventory_job_error(result),
        owner_id=owner_id,
    )


@app.post("/active/network/dns-osint", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_active_dns_osint(
    request: Request,
    payload: Any = Body(...),
) -> JobRecord:
    require_legacy_active_free_target_enabled(request)
    if not request.app.state.settings.active_dns_osint_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="active_dns_osint is disabled in this environment.",
        )

    owner_id = current_owner_id_for_request(request)
    contract = validate_active_dns_osint_contract(payload)
    ct_source = getattr(request.app.state, "active_dns_osint_ct_source", None)
    result = run_active_dns_osint(contract, ct_source=ct_source)
    return request.app.state.jobs.create_active_dns_osint_job(
        result,
        status=active_dns_osint_job_status(result),
        error=active_dns_osint_job_error(result),
        owner_id=owner_id,
    )


@app.post("/audits/web/basic", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_web_basic_audit(request: Request, payload: WebAuditRequest, background_tasks: BackgroundTasks) -> JobRecord:
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Authorization confirmation is required.")
    normalized_url = validate_web_target_url(
        payload.url,
        allow_private_targets=request.app.state.settings.web_allow_private_targets,
        allowed_ports=request.app.state.settings.web_allowed_ports,
    )
    job = request.app.state.jobs.create_web_job(redact_url_query(normalized_url), owner_id=current_owner_id_for_request(request))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.web_audits.run_web_analysis, job.id, normalized_url)
    return job


@app.post("/audits/domain/basic", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_domain_basic_audit(request: Request, payload: DomainAuditRequest, background_tasks: BackgroundTasks) -> JobRecord:
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Authorization confirmation is required.")
    normalized_domain = normalize_domain(payload.domain)
    job = request.app.state.jobs.create_domain_job(normalized_domain, owner_id=current_owner_id_for_request(request))
    schedule_bounded_audit(background_tasks, request.app, request.app.state.domain_audits.run_domain_analysis, job.id)
    return job


@app.post("/audits/subdomains/basic", response_model=JobRecord, status_code=status.HTTP_202_ACCEPTED)
async def launch_subdomain_inventory_basic_audit(
    request: Request,
    payload: SubdomainInventoryRequest,
    background_tasks: BackgroundTasks,
) -> JobRecord:
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Authorization confirmation is required.")
    normalized_root = normalize_domain(payload.root_domain)
    normalize_subdomain_candidates(
        normalized_root,
        payload.subdomains,
        request.app.state.settings.subdomain_max_candidates,
    )
    job = request.app.state.jobs.create_subdomain_inventory_job(normalized_root, owner_id=current_owner_id_for_request(request))
    schedule_bounded_audit(
        background_tasks,
        request.app,
        request.app.state.subdomain_inventory_audits.run_subdomain_inventory_analysis,
        job.id,
        payload.subdomains,
    )
    return job


@app.get("/jobs", response_model=list[JobListItem], deprecated=True)
async def list_jobs(request: Request, response: Response) -> list[JobListItem]:
    """Return only the first bounded page for legacy clients."""

    response.headers.update(
        {
            "Deprecation": "true",
            "Sunset": "Tue, 01 Dec 2026 00:00:00 GMT",
            "Link": '</jobs/search>; rel="successor-version"',
            "Cache-Control": "no-store",
        }
    )
    items, _total, _next_cursor = request.app.state.jobs.page(
        owner_id=current_owner_id_for_request(request), page_size=100
    )
    return items


@app.post("/jobs/search", response_model=JobPage)
async def page_jobs(request: Request, payload: JobPageRequest) -> JobPage:
    items, total, next_cursor = request.app.state.jobs.page(
        owner_id=current_owner_id_for_request(request),
        page_size=payload.page_size,
        cursor=payload.cursor,
        status_filter=payload.status,
        audit_type=payload.audit_type,
        project_id=payload.project_id,
    )
    return JobPage(
        items=items,
        returned_count=len(items),
        total_count=total,
        has_more=next_cursor is not None,
        next_cursor=next_cursor,
    )


def project_job_result_without_source_metadata(job: JobRecord) -> dict[str, Any] | None:
    """Remove source identity fields from a project result without mutating storage."""

    if job.result is None:
        return None
    result = dict(job.result)
    result.pop("file_id", None)
    result.pop("hashes", None)
    file_identification = result.get("file_identification")
    if isinstance(file_identification, dict):
        safe_identification = dict(file_identification)
        safe_identification.pop("original_filename", None)
        result["file_identification"] = safe_identification
    return result


@app.get("/jobs/{job_id}", response_model=JobDetailView)
async def get_job(request: Request, job_id: str) -> JobDetailView:
    job = get_job_for_current_owner(request, job_id)
    if job.audit_type in {
        "ci_cd_config_basic",
        "k8s_config_basic",
        "terraform_config_basic",
        "nginx_config_basic",
        "compose_config_basic",
        "database_config_basic",
        "sql_database_config_basic",
        "redis_config_basic",
        "active_network_dry_run",
        "active_http_header_probe",
        "active_http_basic_header_review",
        "active_nmap_basic",
        "active_tls_basic",
        "active_dns_inventory",
        "active_dns_osint",
    }:
        job = job.model_copy(
            update={
                "target_url": public_job_target_url(job) or None,
                "result": public_result_for_job(job, job.result or {}),
                "error": public_job_error(job) or None,
            }
        )
    if job.project_id is not None:
        job = job.model_copy(update={"result": project_job_result_without_source_metadata(job)})
    return JobDetailView.model_validate(job)


@app.delete("/jobs/{job_id}", response_model=DeletedJobResponse)
async def delete_job(request: Request, job_id: str) -> DeletedJobResponse:
    deleted_job = request.app.state.jobs.delete(job_id, owner_id=current_owner_id_for_request(request))
    request.app.state.projects.clear_baselines_for_analysis_ids(
        {deleted_job.id}, owner_id=deleted_job.owner_id
    )
    return DeletedJobResponse(job_id=deleted_job.id, deleted=True)


@app.get("/jobs/{job_id}/export/markdown")
async def export_job_markdown(request: Request, job_id: str) -> Response:
    job = get_job_for_current_owner(request, job_id)
    return export_response(render_markdown_report(job), "text/markdown; charset=utf-8", build_report_filename(job, "md"))


@app.get("/jobs/{job_id}/export/html")
async def export_job_html(request: Request, job_id: str) -> Response:
    job = get_job_for_current_owner(request, job_id)
    return export_response(render_html_report(job), "text/html; charset=utf-8", build_report_filename(job, "html"))


@app.get("/jobs/{job_id}/export/xml")
async def export_job_xml(request: Request, job_id: str) -> Response:
    job = get_job_for_current_owner(request, job_id)
    return export_response(render_xml_report(job), "application/xml; charset=utf-8", build_report_filename(job, "xml"))


@app.get("/jobs/{job_id}/export/pdf")
async def export_job_pdf(request: Request, job_id: str) -> Response:
    job = get_job_for_current_owner(request, job_id)
    return export_response(render_pdf_report(job), "application/pdf", build_report_filename(job, "pdf"))


@app.get("/jobs/{job_id}/sbom/cyclonedx-json")
async def export_job_cyclonedx_sbom(request: Request, job_id: str) -> Response:
    job = get_job_for_current_owner(request, job_id)
    return export_response(
        generate_cyclonedx_json(job),
        "application/vnd.cyclonedx+json; charset=utf-8",
        build_sbom_filename(job, "cyclonedx"),
    )


@app.get("/jobs/{job_id}/sbom/spdx-json")
async def export_job_spdx_sbom(request: Request, job_id: str) -> Response:
    job = get_job_for_current_owner(request, job_id)
    return export_response(
        generate_spdx_json(job),
        "application/spdx+json; charset=utf-8",
        build_sbom_filename(job, "spdx"),
    )


def export_response(content: str | bytes, media_type: str, filename: str) -> Response:
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
