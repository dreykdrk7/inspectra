"""Visible retention policy and isolated, retryable maintenance operations."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable

from app.automation_tokens import AutomationTokenStore
from app.active_change_approvals import (
    ACTIVE_CHANGE_APPROVAL_TERMINAL_RETENTION_DAYS,
    ActiveChangeApprovalStore,
)
from app.active_weekly_review_receipts import (
    ACTIVE_WEEKLY_REVIEW_RECEIPT_RETENTION_DAYS,
    ActiveWeeklyReviewReceiptStore,
)
from app.config import Settings
from app.models import (
    RetentionCleanupClassResult,
    RetentionCleanupResponse,
    RetentionPolicyClass,
    RetentionPolicyResponse,
    SourceMetadataPolicy,
)
from app.observability import log_audit_event
from app.product_audit import ProductAuditStore
from app.project_vulnerability_intelligence import ProjectVulnerabilityIntelligenceStore
from app.public_advisory_egress import PublicAdvisoryResponseCache
from app.remediation_plan_jobs import REMEDIATION_PLAN_ARTIFACT_TTL_DAYS
from app.storage import FileStore, JobStore, ProjectStore
from app.team_identity import TeamIdentityStore


RETENTION_POLICY_CONTRACT_VERSION = "2026-09-10.7"
RETENTION_POLICY_CLASS_COUNT = 25


def build_retention_policy(settings: Settings, *, manual_cleanup_allowed: bool) -> RetentionPolicyResponse:
    """Expose configured values and lifecycle semantics, never stored-data facts."""

    return RetentionPolicyResponse(
        manual_cleanup_allowed=manual_cleanup_allowed,
        source_metadata=[
            SourceMetadataPolicy(
                key="original_filename",
                label="Original source filename",
                retained_in=["source_upload", "project_record"],
                sensitivity="private_source_label",
                project_view_disclosure="withheld",
                report_disclosure="withheld",
                integration_disclosure="withheld",
                retention_relation="follows_each_parent_record",
                description="Retained for authorized file management and legacy recovery only; project views, reports and integration projections omit it.",
            ),
            SourceMetadataPolicy(
                key="content_sha256",
                label="Source content SHA-256",
                retained_in=["source_upload", "project_record", "analysis_record"],
                sensitivity="correlatable_content_digest",
                project_view_disclosure="withheld",
                report_disclosure="withheld",
                integration_disclosure="withheld",
                retention_relation="follows_each_parent_record",
                description="Retained server-side for integrity and reproducibility; it is not a presentation or export identifier.",
            ),
            SourceMetadataPolicy(
                key="source_file_id",
                label="Internal source identifier",
                retained_in=["source_upload", "project_record", "analysis_record"],
                sensitivity="opaque_internal_identifier",
                project_view_disclosure="withheld",
                report_disclosure="withheld",
                integration_disclosure="withheld",
                retention_relation="follows_each_parent_record",
                description="Used by authorized Files mutations and ownership checks, but omitted from project, analysis, report and integration projections.",
            ),
            SourceMetadataPolicy(
                key="source_reference",
                label="Safe source reference",
                retained_in=["derived_projection"],
                sensitivity="safe_presentation_reference",
                project_view_disclosure="shown",
                report_disclosure="shown",
                integration_disclosure="shown",
                retention_relation="derived_not_stored",
                description="A short domain-separated value derived from the internal source ID for project views, comparisons and reports; it is not a content hash.",
            ),
            SourceMetadataPolicy(
                key="source_channel",
                label="Attested source admission channel",
                retained_in=["project_record"],
                sensitivity="non_sensitive_provenance_enum",
                project_view_disclosure="shown",
                report_disclosure="shown",
                integration_disclosure="shown",
                retention_relation="follows_each_parent_record",
                description="A server-derived closed enum identifying archive upload, Git/CLI, CI or SBOM admission; legacy Git records remain explicitly ambiguous.",
            ),
        ],
        classes=[
            RetentionPolicyClass(
                key="source_uploads",
                label="Uploaded source archives",
                category="project_data",
                scope="organization",
                storage="durable_upload_store",
                sensitivity="project_content",
                retention_mode="bounded" if settings.upload_retention_days else "until_explicit_deletion",
                retention_days=settings.upload_retention_days,
                automatic_cleanup=bool(settings.upload_retention_days),
                manual_cleanup=True,
                deletion_triggers=["retention_expiry", "explicit_source_deletion"],
                backup_disposition="included_sensitive",
                restore_behavior="restored",
                description=(
                    "Expired source bytes are removed unless an active analysis still needs them. "
                    "The related project and result retain only a source-deleted marker."
                    if settings.upload_retention_days
                    else "Automatic source expiry is disabled; an authorized operator must delete uploads explicitly."
                ),
            ),
            RetentionPolicyClass(
                key="analysis_results",
                label="Terminal analysis results",
                category="project_data",
                scope="organization",
                storage="durable_analysis_store",
                sensitivity="project_security_metadata",
                retention_mode="bounded" if settings.job_retention_days else "until_explicit_deletion",
                retention_days=settings.job_retention_days,
                automatic_cleanup=bool(settings.job_retention_days),
                manual_cleanup=True,
                deletion_triggers=["retention_expiry", "explicit_analysis_deletion", "explicit_project_deletion"],
                backup_disposition="included_sensitive",
                restore_behavior="restored",
                description=(
                    "Completed, failed and cancelled analyses expire with their normalized public-vulnerability snapshots. "
                    "Queued or running analyses are never removed by retention."
                    if settings.job_retention_days
                    else "Automatic result expiry is disabled; terminal analyses remain until explicit deletion."
                ),
            ),
            RetentionPolicyClass(
                key="analysis_inventories",
                label="Inventories and normalized findings",
                category="project_data",
                scope="organization",
                storage="embedded_in_analysis_result",
                sensitivity="project_security_metadata",
                retention_mode="follows_parent",
                retention_days=settings.job_retention_days,
                automatic_cleanup=bool(settings.job_retention_days),
                manual_cleanup=True,
                follows_class="analysis_results",
                deletion_triggers=["retention_expiry", "explicit_analysis_deletion", "explicit_project_deletion"],
                backup_disposition="included_sensitive",
                restore_behavior="restored",
                description="Component inventory, coverage and local findings are embedded in the analysis result and cannot outlive or be restored separately from it.",
            ),
            RetentionPolicyClass(
                key="public_advisory_snapshots",
                label="Normalized vulnerability snapshots",
                category="public_intelligence",
                scope="organization",
                storage="durable_public_intelligence_store",
                sensitivity="project_security_metadata",
                retention_mode="follows_parent",
                retention_days=settings.job_retention_days,
                automatic_cleanup=bool(settings.job_retention_days),
                manual_cleanup=True,
                follows_class="analysis_results",
                deletion_triggers=["retention_expiry", "explicit_analysis_deletion", "explicit_project_deletion"],
                backup_disposition="included_sensitive",
                restore_behavior="restored",
                description="Safe normalized evidence follows the lifecycle of its analysis; raw provider responses are not stored here.",
            ),
            RetentionPolicyClass(
                key="public_advisory_cache",
                label="Public advisory response cache",
                category="public_intelligence",
                scope="shared_public_data",
                storage="durable_public_cache",
                sensitivity="public_provider_data",
                retention_mode="bounded",
                freshness_seconds=settings.public_advisory_cache_ttl_seconds,
                retention_seconds=settings.public_advisory_cache_retention_seconds,
                automatic_cleanup=True,
                manual_cleanup=True,
                deletion_triggers=["retention_expiry"],
                backup_disposition="included_regenerable",
                restore_behavior="regenerated",
                description="Provider responses are keyed by a one-way digest and expire independently from their shorter freshness window.",
            ),
            RetentionPolicyClass(
                key="report_exports",
                label="Generated reports",
                category="project_data",
                scope="request",
                storage="request_only",
                sensitivity="project_security_metadata",
                retention_mode="not_persisted",
                automatic_cleanup=False,
                manual_cleanup=False,
                deletion_triggers=["not_applicable"],
                backup_disposition="not_server_persisted",
                restore_behavior="not_applicable",
                description="Synchronous reports are rendered on demand and are not retained as server-side export artifacts. Downloaded copies are operator managed.",
            ),
            RetentionPolicyClass(
                key="remediation_plan_artifacts",
                label="Durable remediation plan artifacts",
                category="project_data",
                scope="organization",
                storage="durable_remediation_plan_store",
                sensitivity="project_security_metadata",
                retention_mode="bounded",
                retention_days=REMEDIATION_PLAN_ARTIFACT_TTL_DAYS,
                automatic_cleanup=True,
                manual_cleanup=False,
                deletion_triggers=["retention_expiry", "startup_recovery"],
                backup_disposition="included_sensitive",
                restore_behavior="restored",
                description="Owner-scoped remediation snapshots include project names but no paths, source content, decision comments or actors; artifacts expire after seven days and terminal job metadata after thirty.",
            ),
            RetentionPolicyClass(
                key="project_metadata",
                label="Project metadata",
                category="project_data",
                scope="organization",
                storage="durable_project_store",
                sensitivity="project_security_metadata",
                retention_mode="until_explicit_deletion",
                automatic_cleanup=False,
                manual_cleanup=True,
                deletion_triggers=["explicit_project_deletion"],
                backup_disposition="included_sensitive",
                restore_behavior="restored",
                description=(
                    "An authorized project deletion removes project metadata and its derived analysis records. "
                    "Uploaded sources remain under their independent upload lifecycle."
                ),
            ),
            RetentionPolicyClass(
                key="finding_decisions",
                label="Finding decisions",
                category="project_data",
                scope="organization",
                storage="durable_finding_decision_store",
                sensitivity="project_security_metadata",
                retention_mode="follows_parent",
                automatic_cleanup=False,
                manual_cleanup=True,
                follows_class="project_metadata",
                deletion_triggers=["explicit_project_deletion"],
                backup_disposition="included_sensitive",
                restore_behavior="restored",
                description="Project deletion removes its organization-scoped triage decisions; audit records retain only bounded action metadata.",
            ),
            RetentionPolicyClass(
                key="passive_project_actions",
                label="Passive project action inbox",
                category="project_data",
                scope="organization",
                storage="durable_project_action_store",
                sensitivity="project_security_metadata",
                retention_mode="follows_parent",
                automatic_cleanup=False,
                manual_cleanup=True,
                follows_class="project_metadata",
                deletion_triggers=["explicit_project_deletion"],
                backup_disposition="included_sensitive",
                restore_behavior="restored",
                description="Closed reason codes and hashed per-user read markers follow current projects; names and finding evidence are never stored in this inbox.",
            ),
            RetentionPolicyClass(
                key="active_asset_metadata",
                label="Active asset metadata and decisions",
                category="project_data",
                scope="organization",
                storage="durable_active_asset_store",
                sensitivity="project_security_metadata",
                retention_mode="until_explicit_deletion",
                automatic_cleanup=False,
                manual_cleanup=True,
                deletion_triggers=["explicit_active_asset_deletion"],
                backup_disposition="included_sensitive",
                restore_behavior="restored",
                description="The exact target, assignments, notes, baseline, observation triage and target-free batch replay receipts remain until an explicit owner-scoped Active deletion.",
            ),
            RetentionPolicyClass(
                key="active_authorization_revisions",
                label="Active authorization revisions",
                category="project_data",
                scope="organization",
                storage="durable_active_asset_store",
                sensitivity="project_security_metadata",
                retention_mode="follows_parent",
                automatic_cleanup=False,
                manual_cleanup=True,
                follows_class="active_asset_metadata",
                deletion_triggers=["explicit_active_asset_deletion"],
                backup_disposition="included_sensitive",
                restore_behavior="restored",
                description="Append-only authorization scopes, references and digests are embedded in and removed with their Active asset.",
            ),
            RetentionPolicyClass(
                key="active_verification_records",
                label="Active verification records",
                category="project_data",
                scope="organization",
                storage="durable_active_verification_store",
                sensitivity="credential_derived",
                retention_mode="follows_parent",
                automatic_cleanup=False,
                manual_cleanup=True,
                follows_class="active_asset_metadata",
                deletion_triggers=["explicit_active_asset_deletion"],
                backup_disposition="included_sensitive",
                restore_behavior="restored",
                description="Challenge digests and closed control-check outcomes are removed with the asset; plaintext challenge tokens are never durable.",
            ),
            RetentionPolicyClass(
                key="active_execution_records",
                label="Active execution records and observations",
                category="project_data",
                scope="organization",
                storage="durable_analysis_store",
                sensitivity="project_security_metadata",
                retention_mode="bounded" if settings.job_retention_days else "until_explicit_deletion",
                retention_days=settings.job_retention_days,
                automatic_cleanup=bool(settings.job_retention_days),
                manual_cleanup=True,
                deletion_triggers=["retention_expiry", "explicit_active_asset_deletion"],
                backup_disposition="included_sensitive",
                restore_behavior="restored",
                description="Terminal bounded observations follow job retention or the explicit Active cascade; in-flight jobs always block deletion.",
            ),
            RetentionPolicyClass(
                key="active_change_approvals",
                label="Active change approval records",
                category="identity_and_operations",
                scope="organization",
                storage="durable_active_change_approval_store",
                sensitivity="credential_derived",
                retention_mode="bounded",
                retention_days=ACTIVE_CHANGE_APPROVAL_TERMINAL_RETENTION_DAYS,
                automatic_cleanup=True,
                manual_cleanup=True,
                deletion_triggers=["retention_expiry", "explicit_active_asset_deletion"],
                backup_disposition="included_sensitive",
                restore_behavior="restored",
                description="Requests expire after 24 hours; registration targets are scrubbed at terminal state and remaining closed metadata is removed after 90 days or with its Active asset.",
            ),
            RetentionPolicyClass(
                key="active_weekly_review_receipts",
                label="Active weekly review receipts",
                category="identity_and_operations",
                scope="organization",
                storage="durable_active_weekly_review_receipt_store",
                sensitivity="credential_derived",
                retention_mode="bounded",
                retention_days=ACTIVE_WEEKLY_REVIEW_RECEIPT_RETENTION_DAYS,
                automatic_cleanup=True,
                manual_cleanup=True,
                deletion_triggers=["retention_expiry"],
                backup_disposition="included_sensitive",
                restore_behavior="restored",
                description="At most 52 target-free weekly acknowledgements are retained for 400 days. They contain a keyed digest and closed outcome, never the report digest, report body, target, actor, notes or runner results.",
            ),
            RetentionPolicyClass(
                key="execution_workspaces",
                label="Execution workspaces",
                category="identity_and_operations",
                scope="execution",
                storage="ephemeral_workspace",
                sensitivity="project_content",
                retention_mode="ephemeral",
                automatic_cleanup=True,
                manual_cleanup=False,
                deletion_triggers=["execution_completion", "startup_recovery"],
                backup_disposition="excluded_ephemeral",
                restore_behavior="discarded",
                description="Per-analysis source copies are removed after execution; orphan cleanup also runs during application startup.",
            ),
            RetentionPolicyClass(
                key="operation_journals",
                label="Recovery journals",
                category="identity_and_operations",
                scope="deployment",
                storage="recoverable_operation_journal",
                sensitivity="operational_metadata",
                retention_mode="ephemeral",
                automatic_cleanup=True,
                manual_cleanup=False,
                deletion_triggers=["startup_recovery", "explicit_project_deletion"],
                backup_disposition="excluded_ephemeral",
                restore_behavior="discarded",
                description="Content-free snapshot and deletion journals exist only until a recoverable operation completes; a backup is refused while one remains.",
            ),
            RetentionPolicyClass(
                key="product_audit",
                label="Administrative activity",
                category="identity_and_operations",
                scope="organization",
                storage="durable_product_audit_store",
                sensitivity="operational_metadata",
                retention_mode="bounded",
                retention_days=settings.product_audit_retention_days,
                automatic_cleanup=True,
                manual_cleanup=True,
                deletion_triggers=["retention_expiry"],
                backup_disposition="included_sensitive",
                restore_behavior="restored",
                description="Minimal high-value activity expires by organization and is additionally bounded by a global event capacity.",
            ),
            RetentionPolicyClass(
                key="adoption_metrics",
                label="Private local adoption metrics",
                category="identity_and_operations",
                scope="deployment",
                storage="durable_aggregate_metrics_store",
                sensitivity="operational_metadata",
                retention_mode="bounded",
                retention_days=90,
                automatic_cleanup=True,
                manual_cleanup=True,
                deletion_triggers=["retention_expiry", "operator_local_deletion"],
                backup_disposition="included_sensitive",
                restore_behavior="restored",
                description="Opt-in daily counters use only closed flow, phase, outcome and duration buckets; they contain no user, tenant, project, request, path or payload identity.",
            ),
            RetentionPolicyClass(
                key="auth_sessions",
                label="Sessions and login protection",
                category="identity_and_operations",
                scope="deployment",
                storage="durable_auth_state",
                sensitivity="credential_derived",
                retention_mode="bounded",
                retention_seconds=max(
                    settings.session_ttl_seconds,
                    settings.login_attempt_window_seconds,
                    settings.login_lockout_seconds,
                ),
                automatic_cleanup=True,
                manual_cleanup=True,
                deletion_triggers=["session_expiry_or_revocation", "operator_restore"],
                backup_disposition="included_sensitive",
                restore_behavior="discarded",
                description="Only hashed session, CSRF and client-key material is durable when SQLite is enabled. Restore discards sessions and login-attempt state.",
            ),
            RetentionPolicyClass(
                key="automation_credentials",
                label="Automation credential metadata",
                category="identity_and_operations",
                scope="organization",
                storage="durable_auth_state",
                sensitivity="credential_derived",
                retention_mode="bounded",
                retention_days=settings.automation_token_retention_days,
                automatic_cleanup=True,
                manual_cleanup=True,
                deletion_triggers=["retention_expiry"],
                backup_disposition="included_sensitive",
                restore_behavior="restored_sessions_revoked",
                description="Hashed credentials remain immediately revocable; expired or revoked metadata is purged per organization after the configured period. Product audit has an independent lifecycle.",
            ),
            RetentionPolicyClass(
                key="team_invitations",
                label="Team invitation records",
                category="identity_and_operations",
                scope="organization",
                storage="durable_auth_state",
                sensitivity="credential_derived",
                retention_mode="bounded",
                retention_days=settings.team_invitation_retention_days,
                automatic_cleanup=True,
                manual_cleanup=True,
                deletion_triggers=["retention_expiry", "operator_restore"],
                backup_disposition="included_sensitive",
                restore_behavior="discarded",
                description="Used, revoked and expired invitation hashes and metadata are removed per organization after the configured terminal-state window. Restore removes every invitation immediately.",
            ),
            RetentionPolicyClass(
                key="team_identity",
                label="Team identities and memberships",
                category="identity_and_operations",
                scope="deployment",
                storage="durable_auth_state",
                sensitivity="credential_derived",
                retention_mode="until_explicit_deletion",
                automatic_cleanup=False,
                manual_cleanup=True,
                deletion_triggers=["membership_revocation"],
                backup_disposition="included_sensitive",
                restore_behavior="restored_sessions_revoked",
                description="Membership revocation removes access and assignments. Accounts with no remaining membership are deactivated and pseudonymized while opaque references and revoked membership history remain for integrity. Restore preserves identities but removes invitation and session records.",
            ),
            RetentionPolicyClass(
                key="backup_bundles",
                label="Operator backup bundles",
                category="external_copies",
                scope="operator_external",
                storage="operator_external",
                sensitivity="project_content",
                retention_mode="external_policy",
                automatic_cleanup=False,
                manual_cleanup=False,
                deletion_triggers=["operator_external_policy"],
                backup_disposition="operator_managed",
                restore_behavior="operator_managed",
                description="Offline full backups contain source and credential-derived data, require external encryption and are never expired by application cleanup.",
            ),
        ],
    )


class RetentionMaintenanceService:
    """Run organization-scoped cleanup while reporting independent failures."""

    def __init__(
        self,
        settings: Settings,
        files: FileStore,
        jobs: JobStore,
        projects: ProjectStore,
        public_intelligence: ProjectVulnerabilityIntelligenceStore,
        public_cache: PublicAdvisoryResponseCache | None,
        product_audit: ProductAuditStore,
        automation_tokens: AutomationTokenStore | None,
        team_identity: TeamIdentityStore | None = None,
        active_change_approvals: ActiveChangeApprovalStore | None = None,
        active_weekly_review_receipts: ActiveWeeklyReviewReceiptStore | None = None,
    ) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs
        self.projects = projects
        self.public_intelligence = public_intelligence
        self.public_cache = public_cache
        self.product_audit = product_audit
        self.automation_tokens = automation_tokens
        self.team_identity = team_identity
        self.active_change_approvals = active_change_approvals
        self.active_weekly_review_receipts = active_weekly_review_receipts

    def run(
        self,
        *,
        organization_id: str,
        correlation_id: str,
        now: datetime | None = None,
    ) -> RetentionCleanupResponse:
        ran_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        results = [
            self._run_results(organization_id, ran_at, correlation_id),
            self._run_sources(organization_id, ran_at, correlation_id),
            self._run_cache(ran_at, correlation_id),
            self._run_automation_tokens(organization_id, ran_at, correlation_id),
            self._run_team_invitations(organization_id, ran_at, correlation_id),
            self._run_active_change_approvals(organization_id, ran_at, correlation_id),
            self._run_active_weekly_review_receipts(organization_id, ran_at, correlation_id),
            self._run_product_audit(organization_id, correlation_id),
        ]
        failed = sum(item.status == "failed" for item in results)
        completed = sum(item.status == "completed" for item in results)
        state = "failed" if failed and not completed else "partial" if failed else "completed"
        return RetentionCleanupResponse(state=state, ran_at=ran_at, results=results)

    def _run_results(
        self,
        organization_id: str,
        now: datetime,
        correlation_id: str,
    ) -> RetentionCleanupClassResult:
        if not self.settings.job_retention_days:
            return _disabled("analysis_results", "Automatic result expiry is disabled by operator configuration.")

        def operation() -> int:
            def before_delete(record) -> None:
                self.public_intelligence.delete_analysis(
                    record.id,
                    organization_id=organization_id,
                )
                self.projects.clear_baselines_for_analysis_ids(
                    {record.id}, owner_id=organization_id
                )

            records = self.jobs.purge_expired_terminal(
                now - timedelta(days=self.settings.job_retention_days),
                owner_id=organization_id,
                before_delete=before_delete,
            )
            return len(records)

        return self._run_class(
            "analysis_results",
            operation,
            correlation_id,
            "Expired terminal analyses and their vulnerability snapshots were evaluated.",
        )

    def _run_sources(
        self,
        organization_id: str,
        now: datetime,
        correlation_id: str,
    ) -> RetentionCleanupClassResult:
        if not self.settings.upload_retention_days:
            return _disabled("source_uploads", "Automatic source expiry is disabled by operator configuration.")

        def operation() -> int:
            def before_delete(record) -> None:
                self.jobs._mark_files_deleted_unlocked(
                    {record.id}, owner_id=organization_id
                )
                self.projects._mark_source_file_deleted_unlocked(
                    record.id, owner_id=organization_id
                )

            records = self.files.purge_expired(
                now - timedelta(days=self.settings.upload_retention_days),
                protected_file_ids=self.jobs.active_file_ids(),
                owner_id=organization_id,
                before_delete=before_delete,
                is_protected=self.jobs._source_file_is_active_unlocked,
            )
            return len(records)

        return self._run_class(
            "source_uploads",
            operation,
            correlation_id,
            "Expired sources were evaluated; active-analysis inputs remained protected.",
        )

    def _run_cache(self, now: datetime, correlation_id: str) -> RetentionCleanupClassResult:
        if self.public_cache is None:
            return self._run_class(
                "public_advisory_cache",
                lambda: (_ for _ in ()).throw(RuntimeError("cache_unavailable")),
                correlation_id,
                "Expired public advisory cache entries were evaluated.",
            )
        return self._run_class(
            "public_advisory_cache",
            lambda: self.public_cache.purge_expired(now=now),
            correlation_id,
            "Expired public advisory cache entries were evaluated.",
        )

    def _run_product_audit(self, organization_id: str, correlation_id: str) -> RetentionCleanupClassResult:
        return self._run_class(
            "product_audit",
            lambda: self.product_audit.purge_expired(organization_id=organization_id),
            correlation_id,
            "Expired administrative activity for the active organization was evaluated.",
        )

    def _run_automation_tokens(
        self,
        organization_id: str,
        now: datetime,
        correlation_id: str,
    ) -> RetentionCleanupClassResult:
        if self.automation_tokens is None:
            return _disabled("automation_credentials", "Automation credentials are not enabled in this deployment mode.")
        cutoff = now - timedelta(days=self.settings.automation_token_retention_days)
        return self._run_class(
            "automation_credentials",
            lambda: self.automation_tokens.purge_inactive(organization_id, cutoff=cutoff),
            correlation_id,
            "Expired or revoked automation credential metadata for the active organization was evaluated.",
        )

    def _run_team_invitations(
        self,
        organization_id: str,
        now: datetime,
        correlation_id: str,
    ) -> RetentionCleanupClassResult:
        if self.team_identity is None:
            return _disabled("team_invitations", "Team invitations are not enabled in this deployment mode.")
        cutoff = now - timedelta(days=self.settings.team_invitation_retention_days)
        return self._run_class(
            "team_invitations",
            lambda: self.team_identity.purge_terminal_invitations(
                cutoff=cutoff,
                organization_id=organization_id,
            ),
            correlation_id,
            "Used, revoked or expired invitation records for the active organization were evaluated.",
        )

    def _run_active_change_approvals(
        self,
        organization_id: str,
        now: datetime,
        correlation_id: str,
    ) -> RetentionCleanupClassResult:
        if self.active_change_approvals is None:
            return _disabled(
                "active_change_approvals",
                "Active change approvals are not enabled in this deployment mode.",
            )
        cutoff = now - timedelta(days=ACTIVE_CHANGE_APPROVAL_TERMINAL_RETENTION_DAYS)
        return self._run_class(
            "active_change_approvals",
            lambda: self.active_change_approvals.purge_terminal(
                organization_id=organization_id,
                cutoff=cutoff,
            ),
            correlation_id,
            "Expired terminal Active change approval metadata for the active organization was evaluated.",
        )

    def _run_active_weekly_review_receipts(
        self,
        organization_id: str,
        now: datetime,
        correlation_id: str,
    ) -> RetentionCleanupClassResult:
        if self.active_weekly_review_receipts is None:
            return _disabled(
                "active_weekly_review_receipts",
                "Active weekly review receipts are not enabled in this deployment mode.",
            )
        cutoff = now - timedelta(days=ACTIVE_WEEKLY_REVIEW_RECEIPT_RETENTION_DAYS)
        return self._run_class(
            "active_weekly_review_receipts",
            lambda: self.active_weekly_review_receipts.purge(
                organization_id=organization_id,
                cutoff=cutoff,
            ),
            correlation_id,
            "Expired target-free Active weekly review receipts for the active organization were evaluated.",
        )

    @staticmethod
    def _run_class(
        key: str,
        operation: Callable[[], int],
        correlation_id: str,
        success_detail: str,
    ) -> RetentionCleanupClassResult:
        try:
            removed = operation()
        except Exception as exc:  # A partial maintenance run must remain observable and retryable.
            log_audit_event(
                "retention.maintenance.class_failed",
                correlation_id=correlation_id,
                data_class=key,
                error_type=exc.__class__.__name__,
            )
            return RetentionCleanupClassResult(
                key=key,
                status="failed",
                removed_items=None,
                detail="This data class could not be cleaned. Review storage health and retry.",
            )
        return RetentionCleanupClassResult(
            key=key,
            status="completed",
            removed_items=removed,
            detail=success_detail,
        )


def _disabled(key: str, detail: str) -> RetentionCleanupClassResult:
    return RetentionCleanupClassResult(key=key, status="disabled", removed_items=0, detail=detail)
