"""Recoverable, organization-scoped deletion of projects and derived records."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Callable, Literal

from fastapi import HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.config import Settings
from app.finding_lifecycle import FindingDecisionStore
from app.models import ProjectDeletionPreview, ProjectDeletionResponse, ProjectDeletionScopeItem, ProjectRecord
from app.observability import log_audit_event
from app.project_action_inbox import ProjectActionInboxStore
from app.project_vulnerability_intelligence import ProjectVulnerabilityIntelligenceStore
from app.risk_trend_source_clock import RiskTrendSourceClock
from app.storage import (
    IDENTIFIER_PATTERN,
    ExecutionWorkspaceStore,
    JobStore,
    ProjectSnapshotAdmissionStore,
    ProjectStore,
    _atomic_write_json,
    project_deletion_marker_path,
    storage_lock,
)


PROJECT_DELETION_CONTRACT_VERSION = "2026-09-06.1"


class ProjectDeletionError(RuntimeError):
    """Controlled failure code; underlying storage details never reach clients."""

    def __init__(self, code: Literal["not_found", "active_work", "state_invalid", "cleanup_failed"]) -> None:
        self.code = code
        super().__init__(code)


class ProjectDeletionOperation(BaseModel):
    """Private write-ahead record containing opaque identifiers and counts only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-06.1"] = PROJECT_DELETION_CONTRACT_VERSION
    project_id: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    organization_id: str = Field(min_length=1, max_length=64)
    job_ids: list[str] = Field(max_length=10_000)
    source_upload_count: int = Field(ge=0)
    finding_decision_count: int = Field(ge=0)
    snapshot_admission_count: int = Field(ge=0)
    prepared_at: datetime


class _ProjectDeletionInspection(BaseModel):
    project: ProjectRecord
    job_ids: list[str]
    source_upload_count: int
    finding_decision_count: int
    snapshot_admission_count: int
    active_work: bool


class ProjectDeletionService:
    """Delete a project cascade without crossing its organization boundary.

    Uploaded source files have an independent lifecycle and are deliberately
    retained. Public provider cache and bounded product-audit events are shared
    or operational records and are also outside the cascade.
    """

    def __init__(
        self,
        settings: Settings,
        projects: ProjectStore,
        jobs: JobStore,
        finding_decisions: FindingDecisionStore,
        snapshot_admissions: ProjectSnapshotAdmissionStore,
        public_intelligence: ProjectVulnerabilityIntelligenceStore,
        execution_workspaces: ExecutionWorkspaceStore,
        project_action_inbox: ProjectActionInboxStore | None = None,
        *,
        now_func: Callable[[], datetime] | None = None,
        after_step: Callable[[str], None] | None = None,
    ) -> None:
        self.settings = settings
        self.projects = projects
        self.jobs = jobs
        self.finding_decisions = finding_decisions
        self.snapshot_admissions = snapshot_admissions
        self.public_intelligence = public_intelligence
        self.execution_workspaces = execution_workspaces
        self.project_action_inbox = project_action_inbox
        self.risk_trend_source_clock = RiskTrendSourceClock(settings)
        self._now_func = now_func or (lambda: datetime.now(timezone.utc))
        self._after_step = after_step

    def preview(self, *, organization_id: str, project_id: str) -> ProjectDeletionPreview:
        self._validate_project_id(project_id)
        with storage_lock(self.settings):
            marker = project_deletion_marker_path(self.settings, project_id)
            if marker.exists() or marker.is_symlink():
                operation = self._load_operation_unlocked(project_id)
                if operation.organization_id != organization_id:
                    raise ProjectDeletionError("not_found")
                return ProjectDeletionPreview(
                    project_id=project_id,
                    state="ready",
                    items=self._scope_items(operation),
                )
            inspection = self._inspect_unlocked(project_id, organization_id)
        return ProjectDeletionPreview(
            project_id=project_id,
            state="blocked_active_work" if inspection.active_work else "ready",
            items=self._scope_items_from_inspection(inspection),
        )

    def delete(self, *, organization_id: str, project_id: str) -> ProjectDeletionResponse:
        self._validate_project_id(project_id)
        operation = self._prepare(organization_id=organization_id, project_id=project_id)
        if operation is None:
            return ProjectDeletionResponse(
                project_id=project_id,
                state="already_absent",
                completed_at=self._now(),
                items=self._already_absent_scope(),
            )
        try:
            self._execute(operation)
        except ProjectDeletionError:
            raise
        except Exception as exc:
            log_audit_event(
                "project.deletion.failed",
                correlation_id=f"project:{project_id}:deletion",
                project_id=project_id,
                owner_id=organization_id,
                reason_code="cleanup_failed",
                error_type=exc.__class__.__name__,
            )
            raise ProjectDeletionError("cleanup_failed") from exc
        completed_at = self._now()
        log_audit_event(
            "project.deletion.completed",
            correlation_id=f"project:{project_id}:deletion",
            project_id=project_id,
            owner_id=organization_id,
            analysis_count=len(operation.job_ids),
            finding_decision_count=operation.finding_decision_count,
            snapshot_admission_count=operation.snapshot_admission_count,
            source_uploads_retained=operation.source_upload_count,
            contract_version=operation.contract_version,
        )
        return ProjectDeletionResponse(
            project_id=project_id,
            state="completed",
            completed_at=completed_at,
            items=self._scope_items(operation),
        )

    def recover_pending(self) -> int:
        """Finish valid pending cascades before snapshot/job startup recovery."""

        recovered = 0
        for path in sorted(self.settings.project_deletions_dir.glob("*.json")):
            if not IDENTIFIER_PATTERN.fullmatch(path.stem):
                log_audit_event(
                    "project.deletion.recovery_deferred",
                    correlation_id="project-deletion:invalid",
                    reason_code="state_invalid",
                )
                continue
            try:
                with storage_lock(self.settings):
                    operation = self._load_operation_unlocked(path.stem)
                self._execute(operation)
                recovered += 1
                log_audit_event(
                    "project.deletion.recovered",
                    correlation_id=f"project:{operation.project_id}:deletion",
                    project_id=operation.project_id,
                    owner_id=operation.organization_id,
                    contract_version=operation.contract_version,
                )
            except Exception as exc:
                log_audit_event(
                    "project.deletion.recovery_deferred",
                    correlation_id=f"project:{path.stem}:deletion",
                    project_id=path.stem,
                    reason_code="cleanup_failed",
                    error_type=exc.__class__.__name__,
                )
        return recovered

    def has_pending(self) -> bool:
        """Let readiness fail closed while any deletion receipt needs recovery."""

        return any(self.settings.project_deletions_dir.iterdir())

    def _prepare(self, *, organization_id: str, project_id: str) -> ProjectDeletionOperation | None:
        with storage_lock(self.settings):
            marker = project_deletion_marker_path(self.settings, project_id)
            if marker.exists() or marker.is_symlink():
                operation = self._load_operation_unlocked(project_id)
                return operation if operation.organization_id == organization_id else None
            try:
                inspection = self._inspect_unlocked(project_id, organization_id)
            except ProjectDeletionError as exc:
                if exc.code == "not_found":
                    return None
                raise
            if inspection.active_work:
                raise ProjectDeletionError("active_work")
            operation = ProjectDeletionOperation(
                project_id=project_id,
                organization_id=organization_id,
                job_ids=inspection.job_ids,
                source_upload_count=inspection.source_upload_count,
                finding_decision_count=inspection.finding_decision_count,
                snapshot_admission_count=inspection.snapshot_admission_count,
                prepared_at=self._now(),
            )
            source_revision = self.risk_trend_source_clock.raw_source_revision()
            _atomic_write_json(marker, operation.model_dump(mode="json"))
            # The durable marker closes admission and the rebuildable projection
            # must hide the project before any slower cascade step can fail.
            self.projects.reference_index.sync_after_delete(project_id)
            self.risk_trend_source_clock.record_mutation(
                organization_id,
                previous_source_revision=source_revision,
            )
            log_audit_event(
                "project.deletion.prepared",
                correlation_id=f"project:{project_id}:deletion",
                project_id=project_id,
                owner_id=organization_id,
                analysis_count=len(operation.job_ids),
                contract_version=operation.contract_version,
            )
            return operation

    def _inspect_unlocked(self, project_id: str, organization_id: str) -> _ProjectDeletionInspection:
        try:
            project = self.projects._get_for_deletion_unlocked(project_id)
        except HTTPException as exc:
            if exc.status_code == status.HTTP_404_NOT_FOUND:
                raise ProjectDeletionError("not_found") from exc
            raise ProjectDeletionError("state_invalid") from exc
        if project.owner_id != organization_id:
            raise ProjectDeletionError("not_found")
        if project.id != project_id:
            raise ProjectDeletionError("state_invalid")

        jobs = []
        for path in sorted(self.settings.jobs_dir.glob("*.json")):
            if not IDENTIFIER_PATTERN.fullmatch(path.stem):
                continue
            record = self.jobs._load_job_file(path)
            if record.project_id != project_id:
                continue
            if record.id != path.stem or not IDENTIFIER_PATTERN.fullmatch(record.id) or record.owner_id != organization_id:
                raise ProjectDeletionError("state_invalid")
            jobs.append(record)

        admission_records = []
        for path in sorted(self.settings.project_snapshot_admissions_dir.glob("*.json")):
            if not IDENTIFIER_PATTERN.fullmatch(path.stem):
                continue
            try:
                record = self.snapshot_admissions._load_unlocked(path)
            except (HTTPException, OSError) as exc:
                raise ProjectDeletionError("state_invalid") from exc
            if record.project_id != project_id:
                continue
            if record.id != path.stem or record.owner_id != organization_id:
                raise ProjectDeletionError("state_invalid")
            admission_records.append(record)

        try:
            decisions = self.finding_decisions._list_for_project_unlocked(organization_id, project_id)
        except Exception as exc:
            raise ProjectDeletionError("state_invalid") from exc

        source_file_ids = {snapshot.source_file_id for snapshot in project.source_snapshots}
        source_file_ids.add(project.source_file_id)
        return _ProjectDeletionInspection(
            project=project,
            job_ids=sorted(record.id for record in jobs),
            source_upload_count=len(source_file_ids),
            finding_decision_count=len(decisions),
            snapshot_admission_count=len(admission_records),
            active_work=(
                any(record.status in {"queued", "running", "cancelling"} for record in jobs)
                or any(record.status == "pending" for record in admission_records)
            ),
        )

    def _execute(self, operation: ProjectDeletionOperation) -> None:
        for job_id in operation.job_ids:
            self.public_intelligence.delete_analysis(
                job_id,
                organization_id=operation.organization_id,
            )
            self.execution_workspaces.cleanup(job_id)
            try:
                self.jobs.delete(job_id, owner_id=operation.organization_id)
            except HTTPException as exc:
                if exc.status_code != status.HTTP_404_NOT_FOUND:
                    raise
        self._step("analysis_results")

        self.finding_decisions.delete_project(operation.organization_id, operation.project_id)
        self._step("finding_decisions")

        self.snapshot_admissions.delete_for_project(operation.project_id, owner_id=operation.organization_id)
        self._step("snapshot_admissions")

        self.projects.delete_for_deletion(operation.project_id, owner_id=operation.organization_id)
        self._step("project_metadata")

        if self.project_action_inbox is not None:
            self.project_action_inbox.remove_project(operation.organization_id, operation.project_id)
        self._step("passive_project_actions")

        with storage_lock(self.settings):
            marker = project_deletion_marker_path(self.settings, operation.project_id)
            if marker.is_symlink():
                raise ProjectDeletionError("state_invalid")
            if marker.exists():
                current = self._load_operation_unlocked(operation.project_id)
                if current.organization_id != operation.organization_id:
                    raise ProjectDeletionError("state_invalid")
                source_revision = self.risk_trend_source_clock.raw_source_revision()
                marker.unlink()
                self.risk_trend_source_clock.record_mutation(
                    operation.organization_id,
                    previous_source_revision=source_revision,
                )

    def _load_operation_unlocked(self, project_id: str) -> ProjectDeletionOperation:
        path = project_deletion_marker_path(self.settings, project_id)
        if path.is_symlink() or not path.is_file():
            raise ProjectDeletionError("state_invalid")
        try:
            operation = ProjectDeletionOperation.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError, json.JSONDecodeError) as exc:
            raise ProjectDeletionError("state_invalid") from exc
        if operation.project_id != project_id:
            raise ProjectDeletionError("state_invalid")
        return operation

    def _step(self, name: str) -> None:
        if self._after_step is not None:
            self._after_step(name)

    def _now(self) -> datetime:
        value = self._now_func()
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

    @staticmethod
    def _validate_project_id(project_id: str) -> None:
        if not isinstance(project_id, str) or not IDENTIFIER_PATTERN.fullmatch(project_id):
            raise ProjectDeletionError("not_found")

    @classmethod
    def _scope_items_from_inspection(cls, inspection: _ProjectDeletionInspection) -> list[ProjectDeletionScopeItem]:
        operation = ProjectDeletionOperation(
            project_id=inspection.project.id,
            organization_id=inspection.project.owner_id or "local-admin",
            job_ids=inspection.job_ids,
            source_upload_count=inspection.source_upload_count,
            finding_decision_count=inspection.finding_decision_count,
            snapshot_admission_count=inspection.snapshot_admission_count,
            prepared_at=inspection.project.updated_at,
        )
        return cls._scope_items(operation)

    @staticmethod
    def _scope_items(operation: ProjectDeletionOperation) -> list[ProjectDeletionScopeItem]:
        analysis_count = len(operation.job_ids)
        return [
            ProjectDeletionScopeItem(
                key="project_metadata",
                disposition="delete",
                item_count=1,
                detail="The project name, source-history metadata and saved baseline are removed.",
            ),
            ProjectDeletionScopeItem(
                key="analysis_results",
                disposition="delete",
                item_count=analysis_count,
                detail="All terminal analysis records and normalized findings bound to this project are removed.",
            ),
            ProjectDeletionScopeItem(
                key="public_advisory_snapshots",
                disposition="delete",
                item_count=analysis_count,
                detail="Current and historical normalized vulnerability snapshots bound to these analyses are removed.",
            ),
            ProjectDeletionScopeItem(
                key="finding_decisions",
                disposition="delete",
                item_count=operation.finding_decision_count,
                detail="Project-scoped triage history, assignments and review dates are removed.",
            ),
            ProjectDeletionScopeItem(
                key="snapshot_admissions",
                disposition="delete",
                item_count=operation.snapshot_admission_count,
                detail="Private recovery journals for source-snapshot admission are removed.",
            ),
            ProjectDeletionScopeItem(
                key="execution_workspaces",
                disposition="delete",
                item_count=analysis_count,
                detail="Any remaining opaque execution workspace bound to these analyses is removed.",
            ),
            ProjectDeletionScopeItem(
                key="passive_project_actions",
                disposition="delete",
                detail="Closed passive reminders and per-user read markers for this project are removed.",
            ),
            ProjectDeletionScopeItem(
                key="source_uploads",
                disposition="retain",
                item_count=operation.source_upload_count,
                detail="Uploaded archives have an independent lifecycle and remain in Files until explicit deletion or configured expiry.",
            ),
            ProjectDeletionScopeItem(
                key="report_exports",
                disposition="not_persisted",
                item_count=0,
                detail="Reports are rendered on request; Inspectra has no server-side export artifact to purge.",
            ),
            ProjectDeletionScopeItem(
                key="public_advisory_cache",
                disposition="retain",
                detail="The shared, digest-keyed provider cache follows its own bounded retention policy and contains no project identity.",
            ),
            ProjectDeletionScopeItem(
                key="product_audit",
                disposition="retain",
                detail="Minimal action records remain until the configured audit-retention period expires.",
            ),
        ]

    @staticmethod
    def _already_absent_scope() -> list[ProjectDeletionScopeItem]:
        return [
            ProjectDeletionScopeItem(
                key="project_metadata",
                disposition="delete",
                item_count=0,
                detail="No project in the active organization remains at this identifier; the requested state is already satisfied.",
            ),
            ProjectDeletionScopeItem(
                key="source_uploads",
                disposition="retain",
                detail="Uploads keep their independent lifecycle and are never inferred from an absent project.",
            ),
            ProjectDeletionScopeItem(
                key="report_exports",
                disposition="not_persisted",
                item_count=0,
                detail="Inspectra retains no server-side report export artifacts.",
            ),
            ProjectDeletionScopeItem(
                key="public_advisory_cache",
                disposition="retain",
                detail="Shared public cache entries follow bounded cache retention.",
            ),
            ProjectDeletionScopeItem(
                key="product_audit",
                disposition="retain",
                detail="Minimal action records follow bounded audit retention.",
            ),
        ]
