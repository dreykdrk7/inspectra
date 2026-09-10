"""Recoverable, organization-scoped deletion of Active assets and derived data."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from typing import Callable, Literal
from uuid import uuid4

from fastapi import HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.active_asset_verification import ActiveAssetVerificationError, ActiveAssetVerificationStore
from app.active_assets import ActiveAssetRecord, ActiveAssetStore, ActiveAssetStoreError
from app.active_change_approvals import ActiveChangeApprovalStore
from app.active_recurrence import ActiveRecurrenceStore
from app.config import Settings
from app.observability import log_audit_event
from app.product_audit import ProductAuditError, ProductAuditStore
from app.storage import (
    IDENTIFIER_PATTERN,
    JobStore,
    _atomic_write_json,
    active_asset_deletion_marker_path,
    storage_lock,
)


ACTIVE_ASSET_DELETION_CONTRACT_VERSION = "2026-09-10.4"
_ACTIVE_JOB_STATES = frozenset({"queued", "running", "cancelling"})


class ActiveAssetDeletionError(RuntimeError):
    def __init__(self, code: Literal["not_found", "active_work", "state_invalid", "cleanup_failed"]):
        self.code = code
        super().__init__(code)


class ActiveAssetDeletionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmation: Literal["DELETE ACTIVE ASSET"]


class ActiveAssetDeletionScopeItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    key: Literal[
        "asset_metadata",
        "batch_replay_receipts",
        "recurrence_policies",
        "authorization_revisions",
        "verification_challenges",
        "execution_jobs",
        "execution_results",
        "report_exports",
        "product_audit",
        "change_approvals",
    ]
    disposition: Literal["delete", "anonymize", "not_persisted"]
    item_count: int | None = Field(default=None, ge=0)
    detail: str = Field(min_length=1, max_length=240)


class ActiveAssetDeletionPreview(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-10.4"] = ACTIVE_ASSET_DELETION_CONTRACT_VERSION
    asset_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    state: Literal["ready", "blocked_active_work"]
    items: list[ActiveAssetDeletionScopeItem] = Field(min_length=1, max_length=10)


class ActiveAssetDeletionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-10.4"] = ACTIVE_ASSET_DELETION_CONTRACT_VERSION
    asset_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    deletion_receipt_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    state: Literal["completed", "already_absent"]
    completed_at: datetime
    items: list[ActiveAssetDeletionScopeItem] = Field(min_length=1, max_length=10)


class ActiveAssetDeletionOperation(BaseModel):
    """Private write-ahead record containing opaque identifiers and counts only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-10.4"] = ACTIVE_ASSET_DELETION_CONTRACT_VERSION
    asset_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    organization_id: str = Field(min_length=1, max_length=64)
    deletion_receipt_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    job_ids: list[str] = Field(max_length=10_000)
    verification_ids: list[str] = Field(max_length=10_000)
    authorization_revision_count: int = Field(ge=0, le=64)
    batch_receipt_count: int = Field(default=0, ge=0, le=64)
    recurrence_count: int = Field(default=0, ge=0, le=500)
    change_approval_count: int = Field(default=0, ge=0, le=500)
    prepared_at: datetime


class _ActiveAssetDeletionInspection(BaseModel):
    asset: ActiveAssetRecord
    job_ids: list[str]
    verification_ids: list[str]
    batch_receipt_count: int
    recurrence_count: int
    change_approval_count: int
    active_work: bool


class ActiveAssetDeletionService:
    """Delete one Active aggregate without retaining its target or credentials."""

    def __init__(
        self,
        settings: Settings,
        assets: ActiveAssetStore,
        verifications: ActiveAssetVerificationStore,
        jobs: JobStore,
        product_audit: ProductAuditStore,
        recurrences: ActiveRecurrenceStore | None = None,
        approvals: ActiveChangeApprovalStore | None = None,
        *,
        now_func: Callable[[], datetime] | None = None,
        after_step: Callable[[str], None] | None = None,
    ) -> None:
        self.settings = settings
        self.assets = assets
        self.verifications = verifications
        self.jobs = jobs
        self.product_audit = product_audit
        self.recurrences = recurrences
        self.approvals = approvals
        self._now_func = now_func or (lambda: datetime.now(timezone.utc))
        self._after_step = after_step

    def preview(self, *, organization_id: str, asset_id: str) -> ActiveAssetDeletionPreview:
        self._validate_asset_id(asset_id)
        with storage_lock(self.settings):
            marker = active_asset_deletion_marker_path(self.settings, asset_id)
            if marker.exists() or marker.is_symlink():
                operation = self._load_operation_unlocked(asset_id)
                if operation.organization_id != organization_id:
                    raise ActiveAssetDeletionError("not_found")
                return ActiveAssetDeletionPreview(
                    asset_id=asset_id,
                    state="ready",
                    items=self._scope_items(operation),
                )
            inspection = self._inspect_unlocked(asset_id, organization_id)
        return ActiveAssetDeletionPreview(
            asset_id=asset_id,
            state="blocked_active_work" if inspection.active_work else "ready",
            items=self._scope_items_from_inspection(inspection),
        )

    def delete(self, *, organization_id: str, asset_id: str) -> ActiveAssetDeletionResponse:
        self._validate_asset_id(asset_id)
        operation = self._prepare(organization_id=organization_id, asset_id=asset_id)
        if operation is None:
            return ActiveAssetDeletionResponse(
                asset_id=asset_id,
                deletion_receipt_id=uuid4().hex,
                state="already_absent",
                completed_at=self._now(),
                items=self._already_absent_scope(),
            )
        try:
            self._execute(operation)
        except ActiveAssetDeletionError:
            raise
        except Exception as exc:
            log_audit_event(
                "active_asset.deletion.failed",
                correlation_id=f"active-deletion:{operation.deletion_receipt_id}",
                owner_id=organization_id,
                reason_code="cleanup_failed",
                error_type=exc.__class__.__name__,
            )
            raise ActiveAssetDeletionError("cleanup_failed") from exc
        return ActiveAssetDeletionResponse(
            asset_id=asset_id,
            deletion_receipt_id=operation.deletion_receipt_id,
            state="completed",
            completed_at=self._now(),
            items=self._scope_items(operation),
        )

    def recover_pending(self) -> int:
        recovered = 0
        for path in sorted(self.settings.active_asset_deletions_dir.glob("*.json")):
            if not IDENTIFIER_PATTERN.fullmatch(path.stem):
                log_audit_event(
                    "active_asset.deletion.recovery_deferred",
                    correlation_id="active-deletion:invalid",
                    reason_code="state_invalid",
                )
                continue
            try:
                with storage_lock(self.settings):
                    operation = self._load_operation_unlocked(path.stem)
                self._execute(operation)
                recovered += 1
                log_audit_event(
                    "active_asset.deletion.recovered",
                    correlation_id=f"active-deletion:{operation.deletion_receipt_id}",
                    owner_id=operation.organization_id,
                    contract_version=operation.contract_version,
                )
            except Exception as exc:
                log_audit_event(
                    "active_asset.deletion.recovery_deferred",
                    correlation_id="active-deletion:recovery",
                    reason_code="cleanup_failed",
                    error_type=exc.__class__.__name__,
                )
        return recovered

    def has_pending(self) -> bool:
        return any(self.settings.active_asset_deletions_dir.iterdir())

    def _prepare(self, *, organization_id: str, asset_id: str) -> ActiveAssetDeletionOperation | None:
        with storage_lock(self.settings):
            marker = active_asset_deletion_marker_path(self.settings, asset_id)
            if marker.exists() or marker.is_symlink():
                operation = self._load_operation_unlocked(asset_id)
                return operation if operation.organization_id == organization_id else None
            try:
                inspection = self._inspect_unlocked(asset_id, organization_id)
            except ActiveAssetDeletionError as exc:
                if exc.code == "not_found":
                    return None
                raise
            if inspection.active_work:
                raise ActiveAssetDeletionError("active_work")
            operation = ActiveAssetDeletionOperation(
                asset_id=asset_id,
                organization_id=organization_id,
                deletion_receipt_id=uuid4().hex,
                job_ids=inspection.job_ids,
                verification_ids=inspection.verification_ids,
                authorization_revision_count=len(inspection.asset.authorization_revisions),
                batch_receipt_count=inspection.batch_receipt_count,
                recurrence_count=inspection.recurrence_count,
                change_approval_count=inspection.change_approval_count,
                prepared_at=self._now(),
            )
            _atomic_write_json(marker, operation.model_dump(mode="json"))
            log_audit_event(
                "active_asset.deletion.prepared",
                correlation_id=f"active-deletion:{operation.deletion_receipt_id}",
                owner_id=organization_id,
                execution_count=len(operation.job_ids),
                verification_count=len(operation.verification_ids),
                contract_version=operation.contract_version,
            )
            return operation

    def _inspect_unlocked(self, asset_id: str, organization_id: str) -> _ActiveAssetDeletionInspection:
        try:
            asset = self.assets._get_for_deletion_unlocked(asset_id, organization_id=organization_id)
        except ActiveAssetStoreError as exc:
            if str(exc) == "asset_not_found":
                raise ActiveAssetDeletionError("not_found") from exc
            raise ActiveAssetDeletionError("state_invalid") from exc
        if asset.id != asset_id or asset.organization_id != organization_id:
            raise ActiveAssetDeletionError("not_found")

        try:
            jobs = self.jobs.active_asset_records_for_deletion_unlocked(
                owner_id=organization_id, asset_id=asset_id
            )
        except HTTPException as exc:
            raise ActiveAssetDeletionError("state_invalid") from exc
        try:
            verifications = self.verifications.list_for_deletion_unlocked(
                asset_id, organization_id=organization_id
            )
        except ActiveAssetVerificationError as exc:
            raise ActiveAssetDeletionError("state_invalid") from exc
        if any(record.organization_id != organization_id or record.asset_id != asset_id for record in verifications):
            raise ActiveAssetDeletionError("state_invalid")
        return _ActiveAssetDeletionInspection(
            asset=asset,
            job_ids=sorted(record.id for record in jobs),
            verification_ids=sorted(record.id for record in verifications),
            batch_receipt_count=self.assets.count_batch_receipts_for_asset_unlocked(
                asset_id, organization_id=organization_id
            ),
            recurrence_count=(
                self.recurrences.count_for_asset_unlocked(asset_id, organization_id=organization_id)
                if self.recurrences is not None
                else 0
            ),
            change_approval_count=(
                self.approvals.count_for_asset_unlocked(organization_id, asset_id)
                if self.approvals is not None else 0
            ),
            active_work=(
                any(record.status in _ACTIVE_JOB_STATES for record in jobs)
                or any(self.verifications._materialize(record).status == "pending" for record in verifications)
            ),
        )

    def _execute(self, operation: ActiveAssetDeletionOperation) -> None:
        self.verifications.delete_for_asset(
            operation.asset_id, organization_id=operation.organization_id
        )
        self._step("verification_challenges")

        for job_id in operation.job_ids:
            try:
                self.jobs.delete(job_id, owner_id=operation.organization_id)
            except HTTPException as exc:
                if exc.status_code != status.HTTP_404_NOT_FOUND:
                    raise
        self._step("execution_jobs")

        self.product_audit.anonymize_active_asset(
            organization_id=operation.organization_id,
            asset_id=operation.asset_id,
            job_ids=set(operation.job_ids),
            deletion_receipt_id=operation.deletion_receipt_id,
        )
        self._step("product_audit")

        if self.recurrences is not None:
            self.recurrences.delete_for_asset(
                operation.asset_id, organization_id=operation.organization_id
            )
        self._step("recurrence_policies")

        if self.approvals is not None:
            self.approvals.remove_asset(operation.organization_id, operation.asset_id)
        self._step("change_approvals")

        self.assets.delete_batch_receipts_for_asset(
            operation.asset_id, organization_id=operation.organization_id
        )

        try:
            self.assets.delete_for_deletion(
                operation.asset_id, organization_id=operation.organization_id
            )
        except ActiveAssetStoreError as exc:
            if str(exc) != "asset_not_found":
                raise
        self._step("asset_metadata")

        with storage_lock(self.settings):
            if self._orphans_exist_unlocked(operation):
                raise ActiveAssetDeletionError("cleanup_failed")
            marker = active_asset_deletion_marker_path(self.settings, operation.asset_id)
            if marker.is_symlink():
                raise ActiveAssetDeletionError("state_invalid")
            if marker.exists():
                current = self._load_operation_unlocked(operation.asset_id)
                if current != operation:
                    raise ActiveAssetDeletionError("state_invalid")
                marker.unlink()
        log_audit_event(
            "active_asset.deletion.completed",
            correlation_id=f"active-deletion:{operation.deletion_receipt_id}",
            owner_id=operation.organization_id,
            execution_count=len(operation.job_ids),
            verification_count=len(operation.verification_ids),
            contract_version=operation.contract_version,
        )

    def _orphans_exist_unlocked(self, operation: ActiveAssetDeletionOperation) -> bool:
        asset_path = self.assets._path(operation.organization_id, operation.asset_id)
        if asset_path.exists() or asset_path.is_symlink():
            return True
        try:
            if self.jobs.active_asset_records_for_deletion_unlocked(
                owner_id=operation.organization_id,
                asset_id=operation.asset_id,
            ):
                return True
        except HTTPException as exc:
            raise ActiveAssetDeletionError("state_invalid") from exc
        if self.recurrences is not None and self.recurrences.count_for_asset_unlocked(
            operation.asset_id, organization_id=operation.organization_id
        ):
            return True
        if self.approvals is not None and self.approvals.count_for_asset_unlocked(
            operation.organization_id, operation.asset_id
        ):
            return True
        return bool(
            self.verifications.list_for_deletion_unlocked(
                operation.asset_id, organization_id=operation.organization_id
            )
        )

    def _load_operation_unlocked(self, asset_id: str) -> ActiveAssetDeletionOperation:
        path = active_asset_deletion_marker_path(self.settings, asset_id)
        if path.is_symlink() or not path.is_file():
            raise ActiveAssetDeletionError("state_invalid")
        try:
            operation = ActiveAssetDeletionOperation.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError, json.JSONDecodeError) as exc:
            raise ActiveAssetDeletionError("state_invalid") from exc
        if operation.asset_id != asset_id:
            raise ActiveAssetDeletionError("state_invalid")
        return operation

    def _step(self, name: str) -> None:
        if self._after_step is not None:
            self._after_step(name)

    def _now(self) -> datetime:
        value = self._now_func()
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

    @staticmethod
    def _validate_asset_id(asset_id: str) -> None:
        if not isinstance(asset_id, str) or not IDENTIFIER_PATTERN.fullmatch(asset_id):
            raise ActiveAssetDeletionError("not_found")

    @classmethod
    def _scope_items_from_inspection(
        cls, inspection: _ActiveAssetDeletionInspection
    ) -> list[ActiveAssetDeletionScopeItem]:
        operation = ActiveAssetDeletionOperation(
            asset_id=inspection.asset.id,
            organization_id=inspection.asset.organization_id,
            deletion_receipt_id="0" * 32,
            job_ids=inspection.job_ids,
            verification_ids=inspection.verification_ids,
            authorization_revision_count=len(inspection.asset.authorization_revisions),
            batch_receipt_count=inspection.batch_receipt_count,
            recurrence_count=inspection.recurrence_count,
            change_approval_count=inspection.change_approval_count,
            prepared_at=inspection.asset.updated_at,
        )
        return cls._scope_items(operation)

    @staticmethod
    def _scope_items(operation: ActiveAssetDeletionOperation) -> list[ActiveAssetDeletionScopeItem]:
        return [
            ActiveAssetDeletionScopeItem(
                key="asset_metadata", disposition="delete", item_count=1,
                detail="The exact target, business notes, assignments and asset metadata are removed.",
            ),
            ActiveAssetDeletionScopeItem(
                key="authorization_revisions", disposition="delete",
                item_count=operation.authorization_revision_count,
                detail="Authorization references, immutable scopes and revision digests are removed with the asset.",
            ),
            ActiveAssetDeletionScopeItem(
                key="batch_replay_receipts", disposition="delete",
                item_count=operation.batch_receipt_count,
                detail="Any whole-batch replay receipt linked to this asset is invalidated and removed.",
            ),
            ActiveAssetDeletionScopeItem(
                key="recurrence_policies", disposition="delete",
                item_count=operation.recurrence_count,
                detail="Future recurring review policies are removed before the asset scope is deleted.",
            ),
            ActiveAssetDeletionScopeItem(
                key="change_approvals", disposition="delete",
                item_count=operation.change_approval_count,
                detail="Pending and retained four-eyes reviews linked to this asset are removed.",
            ),
            ActiveAssetDeletionScopeItem(
                key="verification_challenges", disposition="delete",
                item_count=len(operation.verification_ids),
                detail="Verification records and one-way challenge digests are removed.",
            ),
            ActiveAssetDeletionScopeItem(
                key="execution_jobs", disposition="delete", item_count=len(operation.job_ids),
                detail="All terminal job contracts, lifecycle records and links for this asset are removed.",
            ),
            ActiveAssetDeletionScopeItem(
                key="execution_results", disposition="delete", item_count=len(operation.job_ids),
                detail="Bounded observations, comparisons, baselines and triage stored with the asset or jobs are removed.",
            ),
            ActiveAssetDeletionScopeItem(
                key="report_exports", disposition="not_persisted", item_count=0,
                detail="Active reports are rendered on request; no server-side export file is retained.",
            ),
            ActiveAssetDeletionScopeItem(
                key="product_audit", disposition="anonymize",
                detail="Action, actor, result and time follow audit retention; target, job links, correlations and metadata are detached.",
            ),
        ]

    @staticmethod
    def _already_absent_scope() -> list[ActiveAssetDeletionScopeItem]:
        return [
            ActiveAssetDeletionScopeItem(
                key="asset_metadata", disposition="delete", item_count=0,
                detail="No asset in the active organization remains at this opaque identifier.",
            ),
            ActiveAssetDeletionScopeItem(
                key="report_exports", disposition="not_persisted", item_count=0,
                detail="Inspectra retains no server-side Active report export artifacts.",
            ),
            ActiveAssetDeletionScopeItem(
                key="product_audit", disposition="anonymize",
                detail="Any previously anonymized governance history continues its bounded audit retention.",
            ),
        ]
