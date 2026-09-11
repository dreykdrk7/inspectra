"""Offline, fail-closed backup and restore for Inspectra's local data store.

The backup bundle is deliberately a directory rather than an archive.  This
keeps extraction out of the restore path and makes every copied relative path
and digest explicit in the versioned manifest.  The caller remains responsible
for placing the bundle on encrypted storage.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
from typing import Iterator, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.auth_state_sqlite import AUTH_STATE_SCHEMA_VERSION, SQLiteAuthStateStore
from app.file_retention_index import (
    FILE_RETENTION_INDEX_MAX_BYTES,
    FILE_RETENTION_INDEX_SCHEMA_VERSION,
    file_retention_record_digest,
)
from app.active_job_index import (
    ACTIVE_JOB_INDEX_MAX_BYTES,
    ACTIVE_JOB_INDEX_SCHEMA_VERSION,
    active_job_record_digest,
    job_source_reference_digest,
)
from app.active_verification_index import (
    ACTIVE_VERIFICATION_INDEX_MAX_BYTES,
    ACTIVE_VERIFICATION_INDEX_SCHEMA_VERSION,
    active_verification_record_digest,
)
from app.active_assets import (
    ACTIVE_ASSET_INDEX_MAX_BYTES,
    ACTIVE_ASSET_INDEX_SCHEMA_VERSION,
    ActiveAssetBatchReceipt,
    ActiveAssetRecord,
    active_asset_record_digest,
)
from app.active_change_approvals import (
    ACTIVE_CHANGE_APPROVAL_MAX_BYTES,
    ActiveChangeApprovalCollection,
)
from app.active_weekly_review_receipts import (
    ACTIVE_WEEKLY_REVIEW_RECEIPT_KEY_BYTES,
    ACTIVE_WEEKLY_REVIEW_RECEIPT_KEY_NAME,
    ACTIVE_WEEKLY_REVIEW_RECEIPT_MAX_BYTES,
    ActiveWeeklyReviewReceiptCollection,
    validate_active_weekly_receipt_collection,
)
from app.active_recurrence import ActiveRecurrenceRecord
from app.active_recurrence_index import (
    ACTIVE_RECURRENCE_INDEX_MAX_BYTES,
    ACTIVE_RECURRENCE_INDEX_SCHEMA_VERSION,
    active_recurrence_record_digest,
)
from app.active_asset_verification import ActiveAssetVerificationRecord
from app.models import (
    FindingDecisionRecord,
    JobRecord,
    ProductAuditEvent,
    ProjectRecord,
    StoredFile,
    current_project_responsibility,
)
from app.finding_lifecycle import RemediationBatchReceipt, _decision_digest
from app.remediation_saved_views import RemediationSavedViewCollection
from app.remediation_plan_jobs import (
    REMEDIATION_PLAN_MAX_ARTIFACT_BYTES,
    REMEDIATION_PLAN_MAX_JOBS_PER_ORGANIZATION,
    RemediationPlanArtifact,
    RemediationPlanJob,
)
from app.product_audit import ProductAuditError, validate_product_audit_integrity_directory
from app.project_reference_index import (
    PROJECT_REFERENCE_INDEX_MAX_BYTES,
    PROJECT_REFERENCE_INDEX_SCHEMA_VERSION,
    project_baseline_reference_digest,
    project_reference_record_digest,
    project_responsible_reference_digest,
    project_source_reference_digest,
)
from app.project_risk_trend_index import (
    RISK_TREND_INDEX_COLUMNS,
    RISK_TREND_INDEX_MAX_ANALYSES,
    RISK_TREND_INDEX_MAX_BYTES,
    RISK_TREND_INDEX_SCHEMA_VERSION,
)
from app.risk_trend_source_clock import (
    RISK_TREND_SOURCE_CLOCK_COLUMNS,
    RISK_TREND_SOURCE_CLOCK_MAX_BYTES,
    RISK_TREND_SOURCE_CLOCK_MAX_OWNERS,
    RISK_TREND_SOURCE_CLOCK_SCHEMA_VERSION,
)
from app.adoption_metrics import (
    ADOPTION_METRICS_COLUMNS,
    ADOPTION_METRICS_DIMENSIONS,
    ADOPTION_METRICS_DURATION_BUCKETS,
    ADOPTION_METRICS_MAX_BYTES,
    ADOPTION_METRICS_MAX_ROWS,
    ADOPTION_METRICS_OUTCOMES,
    ADOPTION_METRICS_SCHEMA_VERSION,
)
from app.project_portfolio_priority_index import (
    PORTFOLIO_PRIORITY_INDEX_COLUMNS,
    PORTFOLIO_PRIORITY_INDEX_MAX_BYTES,
    PORTFOLIO_PRIORITY_INDEX_MAX_PROJECTS,
    PORTFOLIO_PRIORITY_INDEX_SCHEMA_VERSION,
)
from app.project_action_inbox import (
    PROJECT_ACTION_INBOX_MAX_BYTES,
    ProjectActionCollection,
)
from app.team_identity import TEAM_IDENTITY_SCHEMA_VERSION

try:
    import fcntl
except ImportError:  # pragma: no cover - production and CI use Linux.
    fcntl = None


BACKUP_CONTRACT_VERSION = "2026-09-06.1"
BACKUP_LAYOUT_VERSION = 1
DEFAULT_AUTH_STATE_RELATIVE_PATH = "runtime/auth_state.sqlite3"
DEFAULT_MAX_BACKUP_FILES = 100_000
DEFAULT_MAX_BACKUP_FILE_BYTES = 1024 * 1024 * 1024
DEFAULT_MAX_BACKUP_TOTAL_BYTES = 20 * 1024 * 1024 * 1024
COPY_CHUNK_BYTES = 1024 * 1024
_OPAQUE_ID = re.compile(r"^[a-f0-9]{32}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_ACTIVE_JOB_STATES = frozenset({"queued", "running", "cancelling"})
_IGNORED_MARKER = ".gitkeep"
_RUNTIME_OPERATION_DIRECTORIES = (
    "project_snapshot_admissions",
    "project_deletions",
    "active_asset_deletions",
    "remediation_batches",
)
_MANIFEST_NAME = "manifest.json"
_PAYLOAD_DIRECTORY = "payload"
_INTEGRATION_EVENT_OUTBOX_NAME = "integration_event_outbox.sqlite3"
BACKUP_EXCLUDED_CLASSES = (
    "storage_locks",
    "execution_workspaces",
    "pending_operation_journals",
    "external_configuration",
    "tls_private_keys",
    "proxy_logs",
    "browser_downloads",
    "operator_snapshots",
    "integration_event_outbox",
)


class BackupError(RuntimeError):
    """Controlled backup failure that never contains a host path or payload."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class BackupEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    relative_path: str = Field(min_length=1, max_length=512)
    size_bytes: int = Field(ge=0, le=DEFAULT_MAX_BACKUP_FILE_BYTES)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def path_is_safe(self):
        _safe_relative_path(self.relative_path)
        return self


class BackupManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-06.1"] = BACKUP_CONTRACT_VERSION
    layout_version: Literal[1] = BACKUP_LAYOUT_VERSION
    kind: Literal["inspectra_offline_full_backup"] = "inspectra_offline_full_backup"
    backup_id: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    created_at: datetime
    contains_sensitive_data: Literal[True] = True
    source_bytes_included: Literal[True] = True
    auth_state_included: bool
    auth_state_relative_path: str
    auth_schema_version: int | None = Field(default=None, ge=1)
    team_identity_schema_version: int | None = Field(default=None, ge=1)
    excluded_classes: tuple[
        Literal[
            "storage_locks",
            "execution_workspaces",
            "pending_operation_journals",
            "external_configuration",
            "tls_private_keys",
            "proxy_logs",
            "browser_downloads",
            "operator_snapshots",
            "integration_event_outbox",
        ],
        ...,
    ]
    file_count: int = Field(ge=0, le=DEFAULT_MAX_BACKUP_FILES)
    total_bytes: int = Field(ge=0, le=DEFAULT_MAX_BACKUP_TOTAL_BYTES)
    entries_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    entries: tuple[BackupEntry, ...]

    @model_validator(mode="after")
    def aggregate_is_consistent(self):
        _safe_relative_path(self.auth_state_relative_path)
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("Backup timestamp must include a timezone.")
        if tuple(sorted(item.relative_path for item in self.entries)) != tuple(item.relative_path for item in self.entries):
            raise ValueError("Backup entries must use stable path order.")
        if len({item.relative_path for item in self.entries}) != len(self.entries):
            raise ValueError("Backup entries must be unique.")
        if self.file_count != len(self.entries):
            raise ValueError("Backup file count is inconsistent.")
        if self.total_bytes != sum(item.size_bytes for item in self.entries):
            raise ValueError("Backup byte count is inconsistent.")
        if self.entries_digest != _entries_digest(self.entries):
            raise ValueError("Backup entry digest is inconsistent.")
        auth_present = self.auth_state_relative_path in {item.relative_path for item in self.entries}
        if auth_present != self.auth_state_included:
            raise ValueError("Backup authentication-state declaration is inconsistent.")
        if not self.auth_state_included and (self.auth_schema_version is not None or self.team_identity_schema_version is not None):
            raise ValueError("Backup declares schemas without authentication state.")
        if self.excluded_classes != BACKUP_EXCLUDED_CLASSES:
            raise ValueError("Backup exclusions do not match the contract.")
        return self


class BackupSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-06.1"] = BACKUP_CONTRACT_VERSION
    backup_id: str
    file_count: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    entries_digest: str
    contains_sensitive_data: Literal[True] = True
    auth_state_included: bool
    sessions_revoked: int = Field(default=0, ge=0)
    invitations_revoked: int = Field(default=0, ge=0)


def create_backup(
    data_dir: Path,
    destination: Path,
    *,
    offline_confirmed: bool,
    sensitive_data_confirmed: bool,
    encrypted_destination_confirmed: bool,
    auth_state_relative_path: str = DEFAULT_AUTH_STATE_RELATIVE_PATH,
    now: datetime | None = None,
    backup_id: str | None = None,
    max_files: int = DEFAULT_MAX_BACKUP_FILES,
    max_file_bytes: int = DEFAULT_MAX_BACKUP_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_BACKUP_TOTAL_BYTES,
) -> BackupSummary:
    """Create an immutable full backup bundle at a previously absent path."""

    if not offline_confirmed:
        raise BackupError("offline_confirmation_required")
    if not sensitive_data_confirmed:
        raise BackupError("sensitive_data_confirmation_required")
    if not encrypted_destination_confirmed:
        raise BackupError("encrypted_destination_confirmation_required")
    source = _existing_directory(data_dir, "invalid_source")
    target = _absent_target(destination, "invalid_destination")
    _require_separate_paths(source, target)
    auth_relative = _safe_relative_path(auth_state_relative_path)
    _validate_limits(max_files, max_file_bytes, max_total_bytes)
    identifier = backup_id or uuid4().hex
    if not _OPAQUE_ID.fullmatch(identifier):
        raise BackupError("invalid_backup_identifier")
    created_at = now or datetime.now(timezone.utc)
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise BackupError("invalid_clock")
    created_at = created_at.astimezone(timezone.utc)

    temporary = target.parent / f".{target.name}.tmp-{uuid4().hex}"
    try:
        with _offline_storage_locks(source):
            _require_quiescent(source, auth_relative)
            validation = validate_data_store(source, auth_state_relative_path=auth_relative.as_posix())
            source_files = _durable_source_files(source, auth_relative)
            if len(source_files) > max_files:
                raise BackupError("backup_file_limit_exceeded")
            temporary.mkdir(mode=0o700)
            payload = temporary / _PAYLOAD_DIRECTORY
            payload.mkdir(mode=0o700)
            entries: list[BackupEntry] = []
            total_bytes = 0
            for relative, source_path in source_files:
                size = source_path.stat(follow_symlinks=False).st_size
                if size > max_file_bytes:
                    raise BackupError("backup_file_size_limit_exceeded")
                total_bytes += size
                if total_bytes > max_total_bytes:
                    raise BackupError("backup_total_size_limit_exceeded")
                copied_path = payload.joinpath(*relative.parts)
                copied_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                digest = _copy_and_digest(source_path, copied_path, expected_size=size)
                entries.append(BackupEntry(relative_path=relative.as_posix(), size_bytes=size, sha256=digest))

            entries.sort(key=lambda item: item.relative_path)
            manifest = BackupManifest(
                backup_id=identifier,
                created_at=created_at,
                auth_state_included=validation.auth_state_included,
                auth_state_relative_path=auth_relative.as_posix(),
                auth_schema_version=validation.auth_schema_version,
                team_identity_schema_version=validation.team_identity_schema_version,
                excluded_classes=BACKUP_EXCLUDED_CLASSES,
                file_count=len(entries),
                total_bytes=total_bytes,
                entries_digest=_entries_digest(tuple(entries)),
                entries=tuple(entries),
            )
            validate_data_store(payload, auth_state_relative_path=auth_relative.as_posix())
            _write_private_json(temporary / _MANIFEST_NAME, manifest.model_dump(mode="json"))
            verified = _verify_backup_directory(temporary, max_files=max_files, max_total_bytes=max_total_bytes)
            os.replace(temporary, target)
            return _summary(verified)
    except BackupError:
        _remove_temporary_tree(temporary)
        raise
    except (OSError, ValueError) as exc:
        _remove_temporary_tree(temporary)
        raise BackupError("backup_write_failed") from exc


def verify_backup(
    backup_dir: Path,
    *,
    sensitive_data_confirmed: bool,
    max_files: int = DEFAULT_MAX_BACKUP_FILES,
    max_total_bytes: int = DEFAULT_MAX_BACKUP_TOTAL_BYTES,
) -> BackupSummary:
    """Verify the versioned manifest, exact file set, sizes and SHA-256 values."""

    if not sensitive_data_confirmed:
        raise BackupError("sensitive_data_confirmation_required")
    manifest = _verify_backup_directory(backup_dir, max_files=max_files, max_total_bytes=max_total_bytes)
    return _summary(manifest)


def restore_backup(
    backup_dir: Path,
    target_data_dir: Path,
    *,
    offline_confirmed: bool,
    sensitive_data_confirmed: bool,
    max_files: int = DEFAULT_MAX_BACKUP_FILES,
    max_total_bytes: int = DEFAULT_MAX_BACKUP_TOTAL_BYTES,
) -> BackupSummary:
    """Restore to a new directory, validate it, then publish it atomically."""

    if not offline_confirmed:
        raise BackupError("offline_confirmation_required")
    if not sensitive_data_confirmed:
        raise BackupError("sensitive_data_confirmation_required")
    bundle = _existing_directory(backup_dir, "invalid_backup")
    target = _absent_target(target_data_dir, "invalid_restore_target")
    _require_separate_paths(bundle, target)
    manifest = _verify_backup_directory(bundle, max_files=max_files, max_total_bytes=max_total_bytes)
    temporary = target.parent / f".{target.name}.restore-{uuid4().hex}"
    sessions_revoked = 0
    invitations_revoked = 0
    try:
        temporary.mkdir(mode=0o700)
        payload = bundle / _PAYLOAD_DIRECTORY
        for entry in manifest.entries:
            relative = _safe_relative_path(entry.relative_path)
            source_path = payload.joinpath(*relative.parts)
            copied_path = temporary.joinpath(*relative.parts)
            copied_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            digest = _copy_and_digest(source_path, copied_path, expected_size=entry.size_bytes)
            if digest != entry.sha256:
                raise BackupError("checksum_mismatch")
        if manifest.auth_state_included:
            auth_path = temporary.joinpath(*_safe_relative_path(manifest.auth_state_relative_path).parts)
            sessions_revoked, invitations_revoked = _migrate_and_revoke_auth_state(auth_path)
        validate_data_store(temporary, auth_state_relative_path=manifest.auth_state_relative_path)
        _make_tree_private(temporary)
        os.replace(temporary, target)
        return _summary(
            manifest,
            sessions_revoked=sessions_revoked,
            invitations_revoked=invitations_revoked,
        )
    except BackupError:
        _remove_temporary_tree(temporary)
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        _remove_temporary_tree(temporary)
        raise BackupError("restore_failed") from exc


class _DataValidation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    auth_state_included: bool
    auth_schema_version: int | None = None
    team_identity_schema_version: int | None = None


def validate_data_store(data_dir: Path, *, auth_state_relative_path: str = DEFAULT_AUTH_STATE_RELATIVE_PATH) -> _DataValidation:
    """Validate ownership boundaries and durable cross-references without writes."""

    root = _existing_directory(data_dir, "invalid_storage_data")
    auth_relative = _safe_relative_path(auth_state_relative_path)
    _validate_topology(root, auth_relative)

    files = _load_records(root / "uploads", StoredFile)
    projects = _load_records(root / "results" / "projects", ProjectRecord)
    jobs = _load_records(root / "results" / "jobs", JobRecord)
    decisions = _load_records(root / "results" / "finding_decisions", FindingDecisionRecord)
    _validate_remediation_batches(
        root / "results" / "remediation_batches", decisions
    )
    _validate_remediation_saved_views(root / "results" / "remediation_saved_views")
    _validate_project_action_inbox(
        root / "results" / "project_action_inbox", projects
    )
    _validate_remediation_plans(
        root / "results" / "remediation_plan_jobs",
        root / "results" / "remediation_plan_artifacts",
    )
    _validate_uploaded_payloads(root / "uploads", files)
    _validate_file_retention_index(
        root / "results" / "file_retention_index.sqlite3", files
    )

    for project in projects.values():
        project_scope = _record_scope(project)
        current_snapshots = [
            snapshot
            for snapshot in project.source_snapshots
            if snapshot.source_file_id == project.source_file_id and snapshot.source_sha256 == project.source_sha256
        ]
        if not current_snapshots:
            raise BackupError("invalid_storage_reference")
        if project.latest_job_id is not None:
            latest = jobs.get(project.latest_job_id)
            if latest is None or latest.project_id != project.id or _record_scope(latest) != project_scope:
                raise BackupError("invalid_ownership_boundary")
        if project.baseline_analysis_id is not None:
            baseline = jobs.get(project.baseline_analysis_id)
            if baseline is None or baseline.project_id != project.id or _record_scope(baseline) != project_scope:
                raise BackupError("invalid_ownership_boundary")
        for snapshot in project.source_snapshots:
            source = files.get(snapshot.source_file_id)
            if source is None:
                if snapshot.source_file_deleted_at is None:
                    raise BackupError("invalid_storage_reference")
                continue
            if _record_scope(source) != project_scope or source.sha256 != snapshot.source_sha256:
                raise BackupError("invalid_ownership_boundary")

    for job in jobs.values():
        job_scope = _record_scope(job)
        if job.project_id is not None:
            project = projects.get(job.project_id)
            if project is None or _record_scope(project) != job_scope:
                raise BackupError("invalid_ownership_boundary")
        if job.file_id is not None:
            source = files.get(job.file_id)
            if source is None:
                if job.source_file_deleted_at is None:
                    raise BackupError("invalid_storage_reference")
            elif _record_scope(source) != job_scope or (job.source_sha256 is not None and source.sha256 != job.source_sha256):
                raise BackupError("invalid_ownership_boundary")

    for decision in decisions.values():
        project = projects.get(decision.project_id)
        if project is None or _record_scope(project) != decision.organization_id:
            raise BackupError("invalid_ownership_boundary")

    _validate_active_aggregates(root / "results", jobs)
    _validate_active_job_index(root / "results" / "active_job_index.sqlite3", jobs)
    _validate_project_reference_index(
        root / "results" / "project_reference_index.sqlite3", projects
    )
    _validate_project_risk_trend_index(
        root / "results" / "project_risk_trend_index.sqlite3"
    )
    _validate_risk_trend_source_clock(
        root / "results" / "risk_trend_source_clock.sqlite3"
    )
    _validate_adoption_metrics(root / "results" / "adoption_metrics.sqlite3")
    _validate_project_portfolio_priority_index(
        root / "results" / "project_portfolio_priority_index.sqlite3"
    )

    _validate_product_audit(root / "results" / "product_audit")
    _validate_public_advisory_snapshots(root / "results" / "public_advisories", jobs)
    auth_path = root.joinpath(*auth_relative.parts)
    if not auth_path.exists():
        return _DataValidation(auth_state_included=False)
    if auth_path.is_symlink() or not auth_path.is_file():
        raise BackupError("invalid_auth_state")
    auth_schema, team_schema = _validate_sqlite_auth_state(auth_path)
    return _DataValidation(
        auth_state_included=True,
        auth_schema_version=auth_schema,
        team_identity_schema_version=team_schema,
    )


def _load_records(directory: Path, model_type):
    records = {}
    if not directory.exists():
        return records
    if directory.is_symlink() or not directory.is_dir():
        raise BackupError("invalid_storage_data")
    try:
        for path in directory.iterdir():
            if path.name == _IGNORED_MARKER:
                continue
            if path.is_symlink() or not path.is_file() or path.suffix != ".json" or not _OPAQUE_ID.fullmatch(path.stem):
                if model_type is StoredFile and path.is_file() and not path.is_symlink():
                    continue
                raise BackupError("invalid_storage_data")
            try:
                record = model_type.model_validate_json(path.read_text(encoding="utf-8"))
            except (OSError, ValidationError, ValueError) as exc:
                raise BackupError("invalid_storage_record") from exc
            if record.id != path.stem:
                raise BackupError("invalid_storage_record")
            records[record.id] = record
    except OSError as exc:
        raise BackupError("invalid_storage_data") from exc
    return records


def _validate_remediation_batches(
    directory: Path,
    decisions: dict[str, FindingDecisionRecord],
) -> None:
    """Validate committed batch receipts as the atomic visibility boundary."""

    receipts: dict[str, RemediationBatchReceipt] = {}
    if directory.exists():
        if directory.is_symlink() or not directory.is_dir():
            raise BackupError("invalid_storage_data")
        try:
            for path in directory.iterdir():
                if path.name == _IGNORED_MARKER:
                    continue
                if path.is_symlink() or not path.is_file() or path.suffix != ".json" or not _DIGEST.fullmatch(path.stem):
                    raise BackupError("invalid_storage_data")
                try:
                    receipt = RemediationBatchReceipt.model_validate_json(path.read_text(encoding="utf-8"))
                except (OSError, ValidationError, ValueError) as exc:
                    raise BackupError("invalid_storage_record") from exc
                if receipt.operation_id != path.stem or receipt.operation_id in receipts:
                    raise BackupError("invalid_storage_record")
                receipts[receipt.operation_id] = receipt
        except OSError as exc:
            raise BackupError("invalid_storage_data") from exc

    seen: dict[str, set[str]] = {}
    for decision in decisions.values():
        operation_id = decision.batch_operation_id
        if operation_id is None:
            continue
        receipt = receipts.get(operation_id)
        if (
            receipt is None
            or decision.organization_id != receipt.organization_id
            or decision.id not in receipt.decision_digests
            or _decision_digest(decision) != receipt.decision_digests[decision.id]
        ):
            raise BackupError("invalid_storage_reference")
        seen.setdefault(operation_id, set()).add(decision.id)
    for operation_id, receipt in receipts.items():
        if seen.get(operation_id, set()) != set(receipt.decision_ids):
            raise BackupError("invalid_storage_reference")


def _validate_remediation_saved_views(directory: Path) -> None:
    if not directory.exists():
        return
    if directory.is_symlink() or not directory.is_dir():
        raise BackupError("invalid_storage_data")
    try:
        for path in directory.iterdir():
            if path.name == _IGNORED_MARKER:
                continue
            if (
                path.is_symlink()
                or not path.is_file()
                or path.suffix != ".json"
                or (path.stem != "local-admin" and not _OPAQUE_ID.fullmatch(path.stem))
            ):
                raise BackupError("invalid_storage_data")
            try:
                collection = RemediationSavedViewCollection.model_validate_json(
                    path.read_text(encoding="utf-8")
                )
            except (OSError, ValidationError, ValueError) as exc:
                raise BackupError("invalid_storage_record") from exc
            if collection.organization_id != path.stem:
                raise BackupError("invalid_ownership_boundary")
    except OSError as exc:
        raise BackupError("invalid_storage_data") from exc


def _validate_project_action_inbox(
    directory: Path, projects: dict[str, ProjectRecord]
) -> None:
    """Validate private read markers and tenant/project boundaries before backup."""

    if not directory.exists():
        return
    if directory.is_symlink() or not directory.is_dir():
        raise BackupError("invalid_storage_data")
    try:
        for path in directory.iterdir():
            if path.name == _IGNORED_MARKER:
                continue
            if (
                path.is_symlink()
                or not path.is_file()
                or path.stat(follow_symlinks=False).st_nlink != 1
                or path.stat(follow_symlinks=False).st_size > PROJECT_ACTION_INBOX_MAX_BYTES
                or path.suffix != ".json"
                or (path.stem != "local-admin" and not _OPAQUE_ID.fullmatch(path.stem))
            ):
                raise BackupError("invalid_storage_data")
            try:
                collection = ProjectActionCollection.model_validate_json(
                    path.read_text(encoding="utf-8")
                )
            except (OSError, ValidationError, ValueError) as exc:
                raise BackupError("invalid_storage_record") from exc
            if collection.organization_id != path.stem:
                raise BackupError("invalid_ownership_boundary")
            for event in collection.events:
                project = projects.get(event.project_id)
                if project is None or _record_scope(project) != collection.organization_id:
                    raise BackupError("invalid_ownership_boundary")
    except OSError as exc:
        raise BackupError("invalid_storage_data") from exc


def _validate_remediation_plans(jobs_root: Path, artifacts_root: Path) -> None:
    jobs = _load_remediation_plan_jobs(jobs_root)
    expected_artifacts: set[tuple[str, str]] = set()
    for (owner, job_id), job in jobs.items():
        if job.status == "completed":
            if job.snapshot_sha256 is None:
                raise BackupError("invalid_storage_record")
            path = artifacts_root / owner / f"{job_id}.json"
            try:
                metadata = path.lstat()
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_size > REMEDIATION_PLAN_MAX_ARTIFACT_BYTES
                    or metadata.st_mode & 0o077
                ):
                    raise BackupError("invalid_storage_data")
                raw = path.read_bytes()
                artifact = RemediationPlanArtifact.model_validate_json(raw)
            except (OSError, ValidationError, ValueError) as exc:
                raise BackupError("invalid_storage_record") from exc
            if (
                len(raw) > REMEDIATION_PLAN_MAX_ARTIFACT_BYTES
                or hashlib.sha256(raw).hexdigest() != job.snapshot_sha256
                or artifact.job_id != job_id
                or artifact.organization_id != owner
                or artifact.project_revision != job.project_revision
            ):
                raise BackupError("invalid_storage_reference")
            expected_artifacts.add((owner, job_id))
    actual_artifacts: set[tuple[str, str]] = set()
    if artifacts_root.exists():
        if artifacts_root.is_symlink() or not artifacts_root.is_dir():
            raise BackupError("invalid_storage_data")
        for owner_dir in artifacts_root.iterdir():
            if owner_dir.is_symlink() or not owner_dir.is_dir() or not _valid_owner_directory(owner_dir.name):
                raise BackupError("invalid_storage_data")
            for path in owner_dir.iterdir():
                if path.is_symlink() or not path.is_file() or path.suffix != ".json" or not _OPAQUE_ID.fullmatch(path.stem):
                    raise BackupError("invalid_storage_data")
                actual_artifacts.add((owner_dir.name, path.stem))
    if actual_artifacts != expected_artifacts:
        raise BackupError("invalid_storage_reference")


def _load_remediation_plan_jobs(directory: Path) -> dict[tuple[str, str], RemediationPlanJob]:
    records: dict[tuple[str, str], RemediationPlanJob] = {}
    if not directory.exists():
        return records
    if directory.is_symlink() or not directory.is_dir():
        raise BackupError("invalid_storage_data")
    for owner_dir in directory.iterdir():
        if owner_dir.is_symlink() or not owner_dir.is_dir() or not _valid_owner_directory(owner_dir.name):
            raise BackupError("invalid_storage_data")
        paths = list(owner_dir.iterdir())
        if len(paths) > REMEDIATION_PLAN_MAX_JOBS_PER_ORGANIZATION:
            raise BackupError("invalid_storage_data")
        for path in paths:
            if path.is_symlink() or not path.is_file() or path.suffix != ".json" or not _OPAQUE_ID.fullmatch(path.stem):
                raise BackupError("invalid_storage_data")
            try:
                metadata = path.lstat()
                if metadata.st_nlink != 1 or metadata.st_size > 64 * 1024 or metadata.st_mode & 0o077:
                    raise BackupError("invalid_storage_data")
                record = RemediationPlanJob.model_validate_json(path.read_text(encoding="utf-8"))
            except (OSError, ValidationError, ValueError) as exc:
                raise BackupError("invalid_storage_record") from exc
            if record.id != path.stem or record.organization_id != owner_dir.name:
                raise BackupError("invalid_ownership_boundary")
            records[(owner_dir.name, path.stem)] = record
    return records


def _valid_owner_directory(value: str) -> bool:
    return value == "local-admin" or _OPAQUE_ID.fullmatch(value) is not None


def _validate_uploaded_payloads(directory: Path, records: dict[str, StoredFile]) -> None:
    expected: dict[str, StoredFile] = {}
    for record in records.values():
        if Path(record.stored_filename).name != record.stored_filename or record.stored_filename in {_MANIFEST_NAME, _IGNORED_MARKER}:
            raise BackupError("invalid_storage_record")
        if record.stored_filename in expected:
            raise BackupError("invalid_storage_record")
        expected[record.stored_filename] = record
    if not directory.exists():
        if records:
            raise BackupError("invalid_storage_reference")
        return
    for path in directory.iterdir():
        if path.name == _IGNORED_MARKER or (_OPAQUE_ID.fullmatch(path.stem) and path.suffix == ".json"):
            continue
        if path.is_symlink() or not path.is_file() or path.name not in expected:
            raise BackupError("invalid_storage_data")
        record = expected.pop(path.name)
        size, digest = _digest_file(path)
        if size != record.size_bytes or digest != record.sha256:
            raise BackupError("checksum_mismatch")
    if expected:
        raise BackupError("invalid_storage_reference")


def _validate_product_audit(directory: Path) -> None:
    if not directory.exists():
        return
    if directory.is_symlink() or not directory.is_dir():
        raise BackupError("invalid_storage_data")
    for organization_dir in directory.iterdir():
        if organization_dir.name == _IGNORED_MARKER:
            continue
        if (
            organization_dir.is_symlink()
            or not organization_dir.is_dir()
            or (organization_dir.name != "local-admin" and not _OPAQUE_ID.fullmatch(organization_dir.name))
        ):
            raise BackupError("invalid_storage_data")
        for path in organization_dir.iterdir():
            if path.name == ".integrity":
                continue
            if path.is_symlink() or not path.is_file() or path.suffix != ".json" or not _OPAQUE_ID.fullmatch(path.stem):
                raise BackupError("invalid_storage_data")
            try:
                event = ProductAuditEvent.model_validate_json(path.read_text(encoding="utf-8"))
            except (OSError, ValidationError, ValueError) as exc:
                raise BackupError("invalid_storage_record") from exc
            if event.id != path.stem or event.organization_id != organization_dir.name:
                raise BackupError("invalid_ownership_boundary")
        integrity_dir = organization_dir / ".integrity"
        if integrity_dir.exists() or integrity_dir.is_symlink():
            try:
                validate_product_audit_integrity_directory(
                    organization_dir,
                    organization_id=organization_dir.name,
                )
            except ProductAuditError as exc:
                raise BackupError("invalid_storage_record") from exc


def _validate_active_aggregates(results_dir: Path, jobs: dict[str, JobRecord]) -> None:
    """Validate nested Active stores and their owner-scoped cross-references."""

    assets = _load_organization_records(results_dir / "active_assets", ActiveAssetRecord)
    verifications = _load_organization_records(
        results_dir / "active_asset_verifications", ActiveAssetVerificationRecord
    )
    batch_receipts = _load_organization_records(
        results_dir / "active_asset_batches", ActiveAssetBatchReceipt
    )
    recurrences = _load_organization_records(
        results_dir / "active_recurrences", ActiveRecurrenceRecord
    )
    _validate_active_change_approvals(
        results_dir / "active_change_approvals", assets
    )
    _validate_active_weekly_review_receipts(
        results_dir / "active_weekly_review_receipts"
    )
    for organization_id, records in assets.items():
        for record in records.values():
            if record.organization_id != organization_id:
                raise BackupError("invalid_ownership_boundary")
    for organization_id, records in verifications.items():
        for record in records.values():
            asset = assets.get(organization_id, {}).get(record.asset_id)
            if record.organization_id != organization_id or asset is None:
                raise BackupError("invalid_ownership_boundary")
    for organization_id, records in batch_receipts.items():
        for record in records.values():
            if record.organization_id != organization_id or any(
                asset_id not in assets.get(organization_id, {}) for asset_id in record.record_ids
            ):
                raise BackupError("invalid_ownership_boundary")
    for organization_id, records in recurrences.items():
        for record in records.values():
            asset = assets.get(organization_id, {}).get(record.asset_id)
            if record.organization_id != organization_id or asset is None:
                raise BackupError("invalid_ownership_boundary")
            if record.last_job_id is not None:
                job = jobs.get(record.last_job_id)
                if (
                    job is None
                    or job.owner_id != organization_id
                    or job.active_asset_id != record.asset_id
                ):
                    raise BackupError("invalid_ownership_boundary")
    for job in jobs.values():
        if job.active_asset_id is None:
            continue
        owner = job.owner_id or "local-admin"
        if job.active_asset_id not in assets.get(owner, {}):
            raise BackupError("invalid_ownership_boundary")
    _validate_active_asset_index(results_dir / "active_asset_index.sqlite3", assets)
    _validate_active_verification_index(
        results_dir / "active_verification_index.sqlite3", verifications
    )
    _validate_active_recurrence_index(
        results_dir / "active_recurrence_index.sqlite3", recurrences
    )


def _validate_active_change_approvals(
    directory: Path, assets: dict[str, dict[str, object]]
) -> None:
    """Validate the flat tenant collections and every existing-asset reference."""

    if not directory.exists():
        return
    if directory.is_symlink() or not directory.is_dir():
        raise BackupError("invalid_storage_data")
    try:
        for path in directory.iterdir():
            if path.name == _IGNORED_MARKER:
                continue
            metadata = path.stat(follow_symlinks=False)
            if (
                path.is_symlink()
                or not path.is_file()
                or metadata.st_nlink != 1
                or metadata.st_size > ACTIVE_CHANGE_APPROVAL_MAX_BYTES
                or metadata.st_mode & 0o077
                or path.suffix != ".json"
                or (path.stem != "local-admin" and not _OPAQUE_ID.fullmatch(path.stem))
            ):
                raise BackupError("invalid_storage_data")
            try:
                collection = ActiveChangeApprovalCollection.model_validate_json(
                    path.read_text(encoding="utf-8")
                )
            except (OSError, ValidationError, ValueError) as exc:
                raise BackupError("invalid_storage_record") from exc
            if collection.organization_id != path.stem:
                raise BackupError("invalid_ownership_boundary")
            for record in collection.records:
                if (
                    record.organization_id != collection.organization_id
                    or (
                        record.asset_id is not None
                        and record.asset_id not in assets.get(collection.organization_id, {})
                    )
                ):
                    raise BackupError("invalid_ownership_boundary")
    except OSError as exc:
        raise BackupError("invalid_storage_data") from exc


def _validate_active_weekly_review_receipts(directory: Path) -> None:
    """Validate target-free receipt collections and their private HMAC key."""

    if not directory.exists():
        return
    if directory.is_symlink() or not directory.is_dir():
        raise BackupError("invalid_storage_data")
    try:
        key_path = directory / ACTIVE_WEEKLY_REVIEW_RECEIPT_KEY_NAME
        key: bytes | None = None
        if key_path.exists() or key_path.is_symlink():
            metadata = key_path.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size != ACTIVE_WEEKLY_REVIEW_RECEIPT_KEY_BYTES
                or metadata.st_mode & 0o077
            ):
                raise BackupError("invalid_storage_data")
            key = key_path.read_bytes()
        for path in directory.iterdir():
            if path.name in {_IGNORED_MARKER, ACTIVE_WEEKLY_REVIEW_RECEIPT_KEY_NAME}:
                continue
            metadata = path.stat(follow_symlinks=False)
            if (
                path.is_symlink()
                or not path.is_file()
                or metadata.st_nlink != 1
                or metadata.st_size > ACTIVE_WEEKLY_REVIEW_RECEIPT_MAX_BYTES
                or metadata.st_mode & 0o077
                or path.suffix != ".json"
                or (path.stem != "local-admin" and not _OPAQUE_ID.fullmatch(path.stem))
                or key is None
            ):
                raise BackupError("invalid_storage_data")
            try:
                collection = ActiveWeeklyReviewReceiptCollection.model_validate_json(
                    path.read_text(encoding="utf-8")
                )
            except (OSError, ValidationError, ValueError) as exc:
                raise BackupError("invalid_storage_record") from exc
            if (
                collection.organization_id != path.stem
                or not validate_active_weekly_receipt_collection(collection, key)
            ):
                raise BackupError("invalid_ownership_boundary")
    except OSError as exc:
        raise BackupError("invalid_storage_data") from exc


def _validate_active_asset_index(
    path: Path, assets: dict[str, dict[str, object]]
) -> None:
    """Verify the rebuildable index cannot carry stale or cross-owner data into backup."""

    for suffix in ("-wal", "-shm", "-journal"):
        companion = Path(f"{path}{suffix}")
        if companion.exists() or companion.is_symlink():
            raise BackupError("sqlite_not_quiescent")
    if not path.exists() and not path.is_symlink():
        return
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BackupError("invalid_storage_data") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > ACTIVE_ASSET_INDEX_MAX_BYTES
        or metadata.st_mode & 0o077
    ):
        raise BackupError("invalid_storage_data")
    expected = {
        (organization_id, asset_id): record
        for organization_id, records in assets.items()
        for asset_id, record in records.items()
    }
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            if integrity is None or integrity[0] != "ok":
                raise BackupError("invalid_storage_data")
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            if tables != {
                "active_asset_index_metadata",
                "active_asset_index",
                "active_asset_index_capabilities",
            }:
                raise BackupError("invalid_storage_data")
            version = connection.execute(
                "SELECT value FROM active_asset_index_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if version is None or version[0] != str(ACTIVE_ASSET_INDEX_SCHEMA_VERSION):
                raise BackupError("invalid_storage_data")
            rows = connection.execute(
                """
                SELECT organization_id, asset_id, asset_type, canonical_value,
                       updated_at_micros, expires_at_micros, revoked, record_digest
                FROM active_asset_index
                """
            ).fetchall()
            if len(rows) != len(expected):
                raise BackupError("invalid_storage_reference")
            for row in rows:
                key = (str(row["organization_id"]), str(row["asset_id"]))
                record = expected.get(key)
                if not isinstance(record, ActiveAssetRecord):
                    raise BackupError("invalid_ownership_boundary")
                if (
                    row["asset_type"] != record.asset_type
                    or row["canonical_value"] != record.canonical_value.casefold()
                    or row["updated_at_micros"]
                    != int(record.updated_at.timestamp()) * 1_000_000 + record.updated_at.microsecond
                    or row["expires_at_micros"]
                    != int(record.expires_at.timestamp()) * 1_000_000 + record.expires_at.microsecond
                    or row["revoked"] != int(record.revoked_at is not None)
                    or row["record_digest"] != active_asset_record_digest(record)
                ):
                    raise BackupError("invalid_storage_reference")
                capabilities = {
                    capability[0]
                    for capability in connection.execute(
                        """
                        SELECT capability FROM active_asset_index_capabilities
                        WHERE organization_id = ? AND asset_id = ?
                        """,
                        key,
                    )
                }
                if capabilities != set(record.capabilities):
                    raise BackupError("invalid_storage_reference")
        finally:
            connection.close()
    except BackupError:
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise BackupError("invalid_storage_data") from exc


def _validate_file_retention_index(
    path: Path, files: dict[str, StoredFile]
) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        companion = Path(f"{path}{suffix}")
        if companion.exists() or companion.is_symlink():
            raise BackupError("sqlite_not_quiescent")
    if not path.exists() and not path.is_symlink():
        return
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BackupError("invalid_storage_data") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > FILE_RETENTION_INDEX_MAX_BYTES
        or metadata.st_mode & 0o077
    ):
        raise BackupError("invalid_storage_data")
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            version = connection.execute(
                "SELECT value FROM file_retention_index_metadata WHERE key = 'schema_version'"
            ).fetchone()
            rows = connection.execute(
                """
                SELECT file_id, owner_id, created_at_micros, stored_filename,
                       record_digest
                FROM file_retention_index
                """
            ).fetchall()
            if (
                integrity is None
                or integrity[0] != "ok"
                or tables
                != {"file_retention_index_metadata", "file_retention_index"}
                or version is None
                or version[0] != str(FILE_RETENTION_INDEX_SCHEMA_VERSION)
                or len(rows) != len(files)
            ):
                raise BackupError("invalid_storage_reference")
            for row in rows:
                record = files.get(str(row["file_id"]))
                if record is None:
                    raise BackupError("invalid_ownership_boundary")
                owner_id = _record_scope(record)
                indexed_record = (
                    record
                    if record.owner_id is not None
                    else record.model_copy(
                        update={"owner_id": owner_id, "organization_id": owner_id}
                    )
                )
                created_at_micros = (
                    int(indexed_record.created_at.timestamp()) * 1_000_000
                    + indexed_record.created_at.microsecond
                )
                if (
                    row["owner_id"] != owner_id
                    or row["created_at_micros"] != created_at_micros
                    or row["stored_filename"] != indexed_record.stored_filename
                    or row["record_digest"]
                    != file_retention_record_digest(indexed_record)
                ):
                    raise BackupError("invalid_storage_reference")
        finally:
            connection.close()
    except BackupError:
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise BackupError("invalid_storage_data") from exc


def _validate_project_reference_index(
    path: Path, projects: dict[str, ProjectRecord]
) -> None:
    """Reject stale or disclosure-widened project relationship projections."""

    for suffix in ("-wal", "-shm", "-journal"):
        companion = Path(f"{path}{suffix}")
        if companion.exists() or companion.is_symlink():
            raise BackupError("sqlite_not_quiescent")
    if not path.exists() and not path.is_symlink():
        return
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BackupError("invalid_storage_data") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > PROJECT_REFERENCE_INDEX_MAX_BYTES
        or metadata.st_mode & 0o077
    ):
        raise BackupError("invalid_storage_data")
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            expected_tables = {
                "project_reference_index_metadata",
                "project_reference_index",
                "project_source_reference_index",
            }
            if tables != expected_tables:
                raise BackupError("invalid_storage_reference")
            columns = {
                table: {
                    str(row[1])
                    for row in connection.execute(f"PRAGMA table_info({table})")
                }
                for table in expected_tables
            }
            version = connection.execute(
                "SELECT value FROM project_reference_index_metadata WHERE key = 'schema_version'"
            ).fetchone()
            rows = connection.execute(
                """
                SELECT project_id, owner_id, updated_at_micros,
                       baseline_reference_digest, responsible_reference_digest,
                       record_digest
                FROM project_reference_index
                """
            ).fetchall()
            source_rows = connection.execute(
                """
                SELECT project_id, owner_id, source_reference_digest, source_deleted
                FROM project_source_reference_index
                """
            ).fetchall()
            if (
                integrity is None
                or integrity[0] != "ok"
                or columns.get("project_reference_index_metadata") != {"key", "value"}
                or columns.get("project_reference_index")
                != {
                    "project_id",
                    "owner_id",
                    "updated_at_micros",
                    "baseline_reference_digest",
                    "responsible_reference_digest",
                    "record_digest",
                }
                or columns.get("project_source_reference_index")
                != {
                    "project_id",
                    "owner_id",
                    "source_reference_digest",
                    "source_deleted",
                }
                or version is None
                or version[0] != str(PROJECT_REFERENCE_INDEX_SCHEMA_VERSION)
                or len(rows) != len(projects)
            ):
                raise BackupError("invalid_storage_reference")
            expected_sources: dict[tuple[str, str, str], int] = {}
            for row in rows:
                record = projects.get(str(row["project_id"]))
                if record is None:
                    raise BackupError("invalid_ownership_boundary")
                owner_id = _record_scope(record)
                indexed_record = (
                    record
                    if record.owner_id is not None
                    else record.model_copy(
                        update={"owner_id": owner_id, "organization_id": owner_id}
                    )
                )
                expected_baseline = (
                    project_baseline_reference_digest(indexed_record.baseline_analysis_id)
                    if indexed_record.baseline_analysis_id is not None
                    else None
                )
                responsibility = current_project_responsibility(indexed_record)
                expected_responsible = (
                    project_responsible_reference_digest(
                        responsibility.responsible_user_id
                    )
                    if responsibility.state == "assigned"
                    and responsibility.responsible_user_id is not None
                    else None
                )
                if (
                    row["owner_id"] != owner_id
                    or row["updated_at_micros"]
                    != int(indexed_record.updated_at.timestamp() * 1_000_000)
                    or row["baseline_reference_digest"] != expected_baseline
                    or row["responsible_reference_digest"] != expected_responsible
                    or row["record_digest"]
                    != project_reference_record_digest(indexed_record)
                ):
                    raise BackupError("invalid_storage_reference")
                grouped: dict[str, bool] = {}
                for snapshot in indexed_record.source_snapshots:
                    digest = project_source_reference_digest(snapshot.source_file_id)
                    grouped[digest] = (
                        grouped.get(digest, True)
                        and snapshot.source_file_deleted_at is not None
                    )
                expected_sources.update(
                    {
                        (indexed_record.id, owner_id, digest): int(deleted)
                        for digest, deleted in grouped.items()
                    }
                )
            actual_sources = {
                (
                    str(row["project_id"]),
                    str(row["owner_id"]),
                    str(row["source_reference_digest"]),
                ): int(row["source_deleted"])
                for row in source_rows
            }
            if actual_sources != expected_sources:
                raise BackupError("invalid_storage_reference")
        finally:
            connection.close()
    except BackupError:
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise BackupError("invalid_storage_data") from exc


def _validate_project_risk_trend_index(path: Path) -> None:
    """Validate the private derived projection without treating it as authority."""

    for suffix in ("-wal", "-shm", "-journal"):
        companion = Path(f"{path}{suffix}")
        if companion.exists() or companion.is_symlink():
            raise BackupError("sqlite_not_quiescent")
    if not path.exists() and not path.is_symlink():
        return
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > RISK_TREND_INDEX_MAX_BYTES
            or metadata.st_mode & 0o077
        ):
            raise BackupError("invalid_storage_data")
        connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            version = connection.execute(
                "SELECT value FROM risk_trend_metadata WHERE key = 'schema_version'"
            ).fetchone()
            columns = {
                table: {
                    str(row[1])
                    for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
                }
                for table in RISK_TREND_INDEX_COLUMNS
            }
            if (
                integrity is None
                or integrity[0] != "ok"
                or foreign_keys
                or tables != set(RISK_TREND_INDEX_COLUMNS)
                or version is None
                or version[0] != str(RISK_TREND_INDEX_SCHEMA_VERSION)
                or columns != RISK_TREND_INDEX_COLUMNS
            ):
                raise BackupError("invalid_storage_reference")
            states = connection.execute(
                "SELECT owner_id, source_revision, analysis_count FROM risk_trend_owner_state"
            ).fetchall()
            state_counts = {str(row["owner_id"]): int(row["analysis_count"]) for row in states}
            if (
                len(state_counts) != len(states)
                or any(not _valid_owner_directory(str(row["owner_id"])) for row in states)
                or any(not _DIGEST.fullmatch(str(row["source_revision"])) for row in states)
            ):
                raise BackupError("invalid_ownership_boundary")
            refresh_rows = connection.execute(
                "SELECT * FROM risk_trend_refresh_state"
            ).fetchall()
            for row in refresh_rows:
                owner_id = str(row["owner_id"])
                state = str(row["state"])
                desired = str(row["desired_revision"])
                built = row["built_revision"]
                failure = row["failure_code"]
                requested = int(row["requested_at_micros"])
                started = row["started_at_micros"]
                completed = row["completed_at_micros"]
                attempts = int(row["attempt_count"])
                if (
                    not _valid_owner_directory(owner_id)
                    or not _DIGEST.fullmatch(desired)
                    or (built is not None and not _DIGEST.fullmatch(str(built)))
                    or state not in {"queued", "rebuilding", "ready", "failed"}
                    or requested < 0
                    or attempts < 0
                    or attempts > 1_000_000
                    or (started is not None and int(started) < requested)
                    or (state == "queued" and started is not None)
                    or (state == "rebuilding" and started is None)
                    or (state == "failed" and failure not in {"limit", "source_changed", "rebuild_failed"})
                    or (state != "failed" and failure is not None)
                    or (
                        state == "ready"
                        and (
                            built is None
                            or not hmac.compare_digest(str(built), desired)
                            or completed is None
                            or owner_id not in state_counts
                        )
                    )
                ):
                    raise BackupError("invalid_storage_reference")
            fact_counts = {
                str(row["owner_id"]): int(row["amount"])
                for row in connection.execute(
                    "SELECT owner_id, COUNT(*) AS amount FROM risk_trend_analysis_fact GROUP BY owner_id"
                ).fetchall()
            }
            if (
                sum(fact_counts.values()) > RISK_TREND_INDEX_MAX_ANALYSES * max(len(state_counts), 1)
                or fact_counts != {owner: count for owner, count in state_counts.items() if count}
                or any(count < 0 or count > RISK_TREND_INDEX_MAX_ANALYSES for count in state_counts.values())
            ):
                raise BackupError("invalid_storage_reference")
            dangling_owner = connection.execute(
                """
                SELECT 1 FROM (
                    SELECT owner_id FROM risk_trend_analysis_fact
                    UNION ALL SELECT owner_id FROM risk_trend_ecosystem_fact
                    UNION ALL SELECT owner_id FROM risk_trend_duration_fact
                    UNION ALL SELECT owner_id FROM risk_trend_exception_fact
                ) facts LEFT JOIN risk_trend_owner_state owners USING (owner_id)
                WHERE owners.owner_id IS NULL LIMIT 1
                """
            ).fetchone()
            mismatched_ecosystem_owner = connection.execute(
                """
                SELECT 1 FROM risk_trend_ecosystem_fact ecosystem
                JOIN risk_trend_analysis_fact analysis USING (job_id)
                WHERE ecosystem.owner_id != analysis.owner_id
                   OR ecosystem.occurred_at_micros != analysis.occurred_at_micros
                LIMIT 1
                """
            ).fetchone()
            if dangling_owner is not None or mismatched_ecosystem_owner is not None:
                raise BackupError("invalid_ownership_boundary")
        finally:
            connection.close()
    except BackupError:
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise BackupError("invalid_storage_data") from exc


def _validate_adoption_metrics(path: Path) -> None:
    """Accept only the closed, aggregate and identity-free opt-in schema."""

    for suffix in ("-wal", "-shm", "-journal"):
        companion = Path(f"{path}{suffix}")
        if companion.exists() or companion.is_symlink():
            raise BackupError("sqlite_not_quiescent")
    if not path.exists() and not path.is_symlink():
        return
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > ADOPTION_METRICS_MAX_BYTES
            or metadata.st_mode & 0o077
        ):
            raise BackupError("invalid_storage_data")
        connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(adoption_metric)")
            }
            rows = connection.execute(
                "SELECT day, flow, phase, outcome, duration_bucket, event_count FROM adoption_metric"
            ).fetchall()
            if (
                integrity is None
                or integrity[0] != "ok"
                or int(connection.execute("PRAGMA user_version").fetchone()[0])
                != ADOPTION_METRICS_SCHEMA_VERSION
                or tables != {"adoption_metric"}
                or columns != ADOPTION_METRICS_COLUMNS
                or len(rows) > ADOPTION_METRICS_MAX_ROWS
                or any(
                    not _valid_adoption_metric_day(str(row["day"]))
                    or (str(row["flow"]), str(row["phase"]))
                    not in ADOPTION_METRICS_DIMENSIONS
                    or str(row["outcome"]) not in ADOPTION_METRICS_OUTCOMES
                    or str(row["duration_bucket"])
                    not in ADOPTION_METRICS_DURATION_BUCKETS
                    or not isinstance(row["event_count"], int)
                    or isinstance(row["event_count"], bool)
                    or int(row["event_count"]) < 1
                    for row in rows
                )
            ):
                raise BackupError("invalid_storage_reference")
        finally:
            connection.close()
    except BackupError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        raise BackupError("invalid_storage_data") from exc


def _valid_adoption_metric_day(value: str) -> bool:
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return False
    return True


def _validate_risk_trend_source_clock(path: Path) -> None:
    """Validate the rebuildable owner clock without trusting it as authority."""

    for suffix in ("-wal", "-shm", "-journal"):
        companion = Path(f"{path}{suffix}")
        if companion.exists() or companion.is_symlink():
            raise BackupError("sqlite_not_quiescent")
    if not path.exists() and not path.is_symlink():
        return
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > RISK_TREND_SOURCE_CLOCK_MAX_BYTES
            or metadata.st_mode & 0o077
        ):
            raise BackupError("invalid_storage_data")
        connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            columns = {
                table: {
                    str(row[1])
                    for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
                }
                for table in RISK_TREND_SOURCE_CLOCK_COLUMNS
            }
            metadata_rows = {
                str(row["key"]): str(row["value"])
                for row in connection.execute(
                    "SELECT key, value FROM risk_trend_source_clock_metadata"
                ).fetchall()
            }
            owner_rows = connection.execute(
                "SELECT owner_id, generation, updated_at_micros FROM risk_trend_source_owner_clock"
            ).fetchall()
            if (
                integrity is None
                or integrity[0] != "ok"
                or tables != set(RISK_TREND_SOURCE_CLOCK_COLUMNS)
                or columns != RISK_TREND_SOURCE_CLOCK_COLUMNS
                or set(metadata_rows) != {"schema_version", "epoch", "covered_source_revision"}
                or metadata_rows.get("schema_version") != str(RISK_TREND_SOURCE_CLOCK_SCHEMA_VERSION)
                or not _DIGEST.fullmatch(metadata_rows.get("epoch", ""))
                or not _DIGEST.fullmatch(metadata_rows.get("covered_source_revision", ""))
                or len(owner_rows) > RISK_TREND_SOURCE_CLOCK_MAX_OWNERS
                or any(
                    not _DIGEST.fullmatch(str(row["owner_id"]))
                    or int(row["generation"]) < 1
                    or int(row["updated_at_micros"]) < 0
                    for row in owner_rows
                )
            ):
                raise BackupError("invalid_storage_reference")
        finally:
            connection.close()
    except BackupError:
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise BackupError("invalid_storage_data") from exc


def _validate_project_portfolio_priority_index(path: Path) -> None:
    """Reject malformed or disclosure-widened derived portfolio facts."""

    for suffix in ("-wal", "-shm", "-journal"):
        companion = Path(f"{path}{suffix}")
        if companion.exists() or companion.is_symlink():
            raise BackupError("sqlite_not_quiescent")
    if not path.exists() and not path.is_symlink():
        return
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > PORTFOLIO_PRIORITY_INDEX_MAX_BYTES
            or metadata.st_mode & 0o077
        ):
            raise BackupError("invalid_storage_data")
        connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            columns = {
                table: {
                    str(row[1])
                    for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
                }
                for table in PORTFOLIO_PRIORITY_INDEX_COLUMNS
            }
            version = connection.execute(
                "SELECT value FROM portfolio_priority_metadata WHERE key = 'schema_version'"
            ).fetchone()
            owners = connection.execute(
                "SELECT owner_id, source_revision, key_marker, project_count, prefix_count, projection_digest, built_at_micros, valid_until_micros FROM portfolio_priority_owner_state"
            ).fetchall()
            facts = connection.execute(
                "SELECT owner_id, COUNT(*) AS amount FROM portfolio_priority_fact GROUP BY owner_id"
            ).fetchall()
            prefixes = connection.execute(
                "SELECT owner_id, COUNT(*) AS amount, COUNT(DISTINCT project_id) AS projects FROM portfolio_priority_name_prefix GROUP BY owner_id"
            ).fetchall()
            owner_counts = {str(row["owner_id"]): int(row["project_count"]) for row in owners}
            expected_prefix_counts = {str(row["owner_id"]): int(row["prefix_count"]) for row in owners}
            fact_counts = {str(row["owner_id"]): int(row["amount"]) for row in facts}
            prefix_counts = {str(row["owner_id"]): int(row["amount"]) for row in prefixes}
            prefix_projects = {str(row["owner_id"]): int(row["projects"]) for row in prefixes}
            if (
                integrity is None
                or integrity[0] != "ok"
                or foreign_keys
                or tables != set(PORTFOLIO_PRIORITY_INDEX_COLUMNS)
                or columns != PORTFOLIO_PRIORITY_INDEX_COLUMNS
                or version is None
                or version[0] != str(PORTFOLIO_PRIORITY_INDEX_SCHEMA_VERSION)
                or len(owner_counts) != len(owners)
                or any(not _valid_owner_directory(str(row["owner_id"])) for row in owners)
                or any(not _DIGEST.fullmatch(str(row["source_revision"])) for row in owners)
                or any(not _DIGEST.fullmatch(str(row["key_marker"])) for row in owners)
                or any(not _DIGEST.fullmatch(str(row["projection_digest"])) for row in owners)
                or any(
                    int(row["project_count"]) < 0
                    or int(row["project_count"]) > PORTFOLIO_PRIORITY_INDEX_MAX_PROJECTS
                    or int(row["prefix_count"]) < int(row["project_count"])
                    or int(row["valid_until_micros"]) <= int(row["built_at_micros"])
                    for row in owners
                )
                or fact_counts != {owner: count for owner, count in owner_counts.items() if count}
                or prefix_counts != {owner: count for owner, count in expected_prefix_counts.items() if count}
                or prefix_projects != {owner: count for owner, count in owner_counts.items() if count}
            ):
                raise BackupError("invalid_storage_reference")
        finally:
            connection.close()
    except BackupError:
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise BackupError("invalid_storage_data") from exc


def _validate_active_job_index(path: Path, jobs: dict[str, JobRecord]) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        companion = Path(f"{path}{suffix}")
        if companion.exists() or companion.is_symlink():
            raise BackupError("sqlite_not_quiescent")
    if not path.exists() and not path.is_symlink():
        return
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BackupError("invalid_storage_data") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > ACTIVE_JOB_INDEX_MAX_BYTES
        or metadata.st_mode & 0o077
    ):
        raise BackupError("invalid_storage_data")
    expected = dict(jobs)
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            version = connection.execute(
                "SELECT value FROM active_job_index_metadata WHERE key = 'schema_version'"
            ).fetchone()
            rows = connection.execute(
                """
                SELECT job_id, owner_id, active_asset_id, project_id, audit_type, status, degraded,
                       active_idempotency_key_sha256,
                       created_at_micros, updated_at_micros,
                       source_reference_digest, source_deleted, record_digest
                FROM active_job_index
                """
            ).fetchall()
            if (
                integrity is None
                or integrity[0] != "ok"
                or tables != {"active_job_index_metadata", "active_job_index"}
                or version is None
                or version[0] != str(ACTIVE_JOB_INDEX_SCHEMA_VERSION)
                or len(rows) != len(expected)
            ):
                raise BackupError("invalid_storage_reference")
            for row in rows:
                record = expected.get(str(row["job_id"]))
                if record is None:
                    raise BackupError("invalid_ownership_boundary")
                indexed_record = (
                    record
                    if record.owner_id is not None
                    else record.model_copy(update={"owner_id": "local-admin"})
                )
                if (
                    row["owner_id"] != indexed_record.owner_id
                    or row["active_asset_id"] != indexed_record.active_asset_id
                    or row["project_id"] != indexed_record.project_id
                    or row["audit_type"] != indexed_record.audit_type
                    or row["status"] != indexed_record.status
                    or row["degraded"] != int(_active_job_is_degraded(indexed_record))
                    or row["active_idempotency_key_sha256"]
                    != indexed_record.active_execution_idempotency_key_sha256
                    or row["created_at_micros"]
                    != int(indexed_record.created_at.timestamp()) * 1_000_000 + indexed_record.created_at.microsecond
                    or row["updated_at_micros"]
                    != int(indexed_record.updated_at.timestamp()) * 1_000_000 + indexed_record.updated_at.microsecond
                    or row["source_reference_digest"]
                    != (
                        job_source_reference_digest(indexed_record.file_id)
                        if indexed_record.file_id is not None
                        else None
                    )
                    or row["source_deleted"]
                    != int(indexed_record.source_file_deleted_at is not None)
                    or row["record_digest"] != active_job_record_digest(indexed_record)
                ):
                    raise BackupError("invalid_storage_reference")
        finally:
            connection.close()
    except BackupError:
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise BackupError("invalid_storage_data") from exc


def _validate_active_verification_index(
    path: Path, verifications: dict[str, dict[str, object]]
) -> None:
    """Reject stale, unexpected or cross-owner verification projections."""

    for suffix in ("-wal", "-shm", "-journal"):
        companion = Path(f"{path}{suffix}")
        if companion.exists() or companion.is_symlink():
            raise BackupError("sqlite_not_quiescent")
    if not path.exists() and not path.is_symlink():
        return
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BackupError("invalid_storage_data") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > ACTIVE_VERIFICATION_INDEX_MAX_BYTES
        or metadata.st_mode & 0o077
    ):
        raise BackupError("invalid_storage_data")
    expected = {
        verification_id: record
        for records in verifications.values()
        for verification_id, record in records.items()
    }
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            version = connection.execute(
                "SELECT value FROM active_verification_index_metadata WHERE key = 'schema_version'"
            ).fetchone()
            rows = connection.execute(
                """
                SELECT verification_id, organization_id, asset_id, status,
                       created_at_micros, challenge_expires_at_micros,
                       verification_expires_at_micros, record_digest
                FROM active_verification_index
                """
            ).fetchall()
            if (
                integrity is None
                or integrity[0] != "ok"
                or tables
                != {
                    "active_verification_index_metadata",
                    "active_verification_index",
                }
                or version is None
                or version[0] != str(ACTIVE_VERIFICATION_INDEX_SCHEMA_VERSION)
                or len(rows) != len(expected)
            ):
                raise BackupError("invalid_storage_reference")
            for row in rows:
                record = expected.get(str(row["verification_id"]))
                if not isinstance(record, ActiveAssetVerificationRecord):
                    raise BackupError("invalid_ownership_boundary")
                if (
                    row["organization_id"] != record.organization_id
                    or row["asset_id"] != record.asset_id
                    or row["status"] != record.status
                    or row["created_at_micros"]
                    != int(record.created_at.timestamp()) * 1_000_000
                    + record.created_at.microsecond
                    or row["challenge_expires_at_micros"]
                    != int(record.challenge_expires_at.timestamp()) * 1_000_000
                    + record.challenge_expires_at.microsecond
                    or row["verification_expires_at_micros"]
                    != (
                        int(record.verification_expires_at.timestamp()) * 1_000_000
                        + record.verification_expires_at.microsecond
                        if record.verification_expires_at is not None
                        else None
                    )
                    or row["record_digest"] != active_verification_record_digest(record)
                ):
                    raise BackupError("invalid_storage_reference")
        finally:
            connection.close()
    except BackupError:
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise BackupError("invalid_storage_data") from exc


def _validate_active_recurrence_index(
    path: Path, recurrences: dict[str, dict[str, object]]
) -> None:
    """Reject stale, unexpected or sensitive recurrence projections."""

    for suffix in ("-wal", "-shm", "-journal"):
        companion = Path(f"{path}{suffix}")
        if companion.exists() or companion.is_symlink():
            raise BackupError("sqlite_not_quiescent")
    if not path.exists() and not path.is_symlink():
        return
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BackupError("invalid_storage_data") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > ACTIVE_RECURRENCE_INDEX_MAX_BYTES
        or metadata.st_mode & 0o077
    ):
        raise BackupError("invalid_storage_data")
    expected = {
        schedule_id: record
        for records in recurrences.values()
        for schedule_id, record in records.items()
    }
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(active_recurrence_index)")
            }
            version = connection.execute(
                "SELECT value FROM active_recurrence_index_metadata WHERE key = 'schema_version'"
            ).fetchone()
            rows = connection.execute(
                """
                SELECT schedule_id, organization_id, asset_id, status,
                       next_run_at_micros, next_retry_at_micros, record_digest
                FROM active_recurrence_index
                """
            ).fetchall()
            if (
                integrity is None
                or integrity[0] != "ok"
                or tables
                != {"active_recurrence_index_metadata", "active_recurrence_index"}
                or columns
                != {
                    "schedule_id", "organization_id", "asset_id", "status",
                    "next_run_at_micros", "next_retry_at_micros", "record_digest",
                }
                or version is None
                or version[0] != str(ACTIVE_RECURRENCE_INDEX_SCHEMA_VERSION)
                or len(rows) != len(expected)
            ):
                raise BackupError("invalid_storage_reference")
            for row in rows:
                record = expected.get(str(row["schedule_id"]))
                if not isinstance(record, ActiveRecurrenceRecord):
                    raise BackupError("invalid_ownership_boundary")
                retry_micros = (
                    int(record.next_retry_at.timestamp()) * 1_000_000
                    + record.next_retry_at.microsecond
                    if record.next_retry_at is not None
                    else None
                )
                if (
                    row["organization_id"] != record.organization_id
                    or row["asset_id"] != record.asset_id
                    or row["status"] != record.status
                    or row["next_run_at_micros"]
                    != int(record.next_run_at.timestamp()) * 1_000_000
                    + record.next_run_at.microsecond
                    or row["next_retry_at_micros"] != retry_micros
                    or row["record_digest"] != active_recurrence_record_digest(record)
                ):
                    raise BackupError("invalid_storage_reference")
        finally:
            connection.close()
    except BackupError:
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise BackupError("invalid_storage_data") from exc


def _active_job_is_degraded(record: JobRecord) -> bool:
    if record.status != "completed" or not isinstance(record.result, dict):
        return False
    return record.result.get("status") in {
        "partial", "timed_out", "request_failed", "source_unavailable"
    } or record.result.get("coverage_level") in {
        "partial", "partial_inventory", "incomplete"
    }


def _load_organization_records(directory: Path, model_type) -> dict[str, dict[str, object]]:
    if not directory.exists():
        return {}
    if directory.is_symlink() or not directory.is_dir():
        raise BackupError("invalid_storage_data")
    result: dict[str, dict[str, object]] = {}
    for organization_dir in directory.iterdir():
        if organization_dir.name == _IGNORED_MARKER:
            continue
        if (
            organization_dir.is_symlink()
            or not organization_dir.is_dir()
            or (organization_dir.name != "local-admin" and not _OPAQUE_ID.fullmatch(organization_dir.name))
        ):
            raise BackupError("invalid_storage_data")
        records = _load_records(organization_dir, model_type)
        result[organization_dir.name] = records
    return result


def _validate_public_advisory_snapshots(directory: Path, jobs: dict[str, JobRecord]) -> None:
    if not directory.exists():
        return
    if directory.is_symlink() or not directory.is_dir():
        raise BackupError("invalid_storage_data")
    osv = directory / "osv"
    if not osv.exists():
        return
    if osv.is_symlink() or not osv.is_dir():
        raise BackupError("invalid_storage_data")
    for path in osv.iterdir():
        identifier = path.stem if path.is_file() else path.name
        if _OPAQUE_ID.fullmatch(identifier) and identifier not in jobs:
            raise BackupError("invalid_storage_reference")


def _validate_sqlite_auth_state(path: Path) -> tuple[int | None, int | None]:
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            quick_check = connection.execute("PRAGMA quick_check").fetchone()
            if quick_check is None or quick_check[0] != "ok":
                raise BackupError("invalid_auth_state")
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise BackupError("invalid_auth_state")
            auth_schema = _sqlite_metadata_version(connection, "auth_state_metadata")
            team_schema = _sqlite_metadata_version(connection, "team_identity_metadata")
        finally:
            connection.close()
    except BackupError:
        raise
    except sqlite3.Error as exc:
        raise BackupError("invalid_auth_state") from exc
    if auth_schema not in {None, 1, AUTH_STATE_SCHEMA_VERSION}:
        raise BackupError("unsupported_auth_schema")
    if team_schema is not None and team_schema not in range(1, TEAM_IDENTITY_SCHEMA_VERSION + 1):
        raise BackupError("unsupported_team_identity_schema")
    if auth_schema is None and team_schema is None:
        raise BackupError("invalid_auth_state")
    return auth_schema, team_schema


def _sqlite_metadata_version(connection: sqlite3.Connection, table: str) -> int | None:
    exists = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
    if exists is None:
        return None
    row = connection.execute(f"SELECT value FROM {table} WHERE key = 'schema_version'").fetchone()
    if row is None:
        raise BackupError("invalid_auth_state")
    try:
        return int(row[0])
    except (TypeError, ValueError) as exc:
        raise BackupError("invalid_auth_state") from exc


def _migrate_and_revoke_auth_state(path: Path) -> tuple[int, int]:
    auth_schema, _ = _validate_sqlite_auth_state(path)
    if auth_schema is not None:
        SQLiteAuthStateStore(path)
    try:
        connection = sqlite3.connect(path)
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("BEGIN IMMEDIATE")
            sessions = _delete_if_table_exists(connection, "auth_sessions")
            _delete_if_table_exists(connection, "auth_login_attempts")
            invitations = _delete_if_table_exists(connection, "team_invitations")
            connection.commit()
            return sessions, invitations
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise BackupError("auth_state_recovery_failed") from exc


def _delete_if_table_exists(connection: sqlite3.Connection, table: str) -> int:
    if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is None:
        return 0
    cursor = connection.execute(f"DELETE FROM {table}")
    return max(0, cursor.rowcount)


def _verify_backup_directory(backup_dir: Path, *, max_files: int, max_total_bytes: int) -> BackupManifest:
    _validate_limits(max_files, DEFAULT_MAX_BACKUP_FILE_BYTES, max_total_bytes)
    root = _existing_directory(backup_dir, "invalid_backup")
    manifest_path = root / _MANIFEST_NAME
    payload = root / _PAYLOAD_DIRECTORY
    if manifest_path.is_symlink() or not manifest_path.is_file() or payload.is_symlink() or not payload.is_dir():
        raise BackupError("invalid_backup")
    try:
        manifest = BackupManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError) as exc:
        raise BackupError("invalid_backup_manifest") from exc
    if manifest.file_count > max_files or manifest.total_bytes > max_total_bytes:
        raise BackupError("backup_limit_exceeded")
    expected = {entry.relative_path: entry for entry in manifest.entries}
    actual_paths: set[str] = set()
    for relative, path in _walk_regular_files(payload):
        relative_text = relative.as_posix()
        entry = expected.get(relative_text)
        if entry is None:
            raise BackupError("unexpected_backup_entry")
        size, digest = _digest_file(path)
        if size != entry.size_bytes or digest != entry.sha256:
            raise BackupError("checksum_mismatch")
        actual_paths.add(relative_text)
    if actual_paths != set(expected):
        raise BackupError("missing_backup_entry")
    extra_roots = {path.name for path in root.iterdir()} - {_MANIFEST_NAME, _PAYLOAD_DIRECTORY}
    if extra_roots:
        raise BackupError("unexpected_backup_entry")
    validation = validate_data_store(payload, auth_state_relative_path=manifest.auth_state_relative_path)
    if (
        validation.auth_state_included != manifest.auth_state_included
        or validation.auth_schema_version != manifest.auth_schema_version
        or validation.team_identity_schema_version != manifest.team_identity_schema_version
    ):
        raise BackupError("backup_schema_mismatch")
    return manifest


def _durable_source_files(root: Path, auth_relative: PurePosixPath) -> list[tuple[PurePosixPath, Path]]:
    files: list[tuple[PurePosixPath, Path]] = []
    for name in ("uploads", "results"):
        directory = root / name
        if directory.exists():
            for relative, path in _walk_regular_files(directory):
                if path.name != _IGNORED_MARKER:
                    files.append((PurePosixPath(name).joinpath(relative), path))
    auth_path = root.joinpath(*auth_relative.parts)
    if auth_path.exists():
        _require_regular_file(auth_path)
        files.append((auth_relative, auth_path))
    files.sort(key=lambda item: item[0].as_posix())
    return files


def _walk_regular_files(root: Path) -> Iterator[tuple[PurePosixPath, Path]]:
    if root.is_symlink() or not root.is_dir():
        raise BackupError("invalid_storage_data")
    pending = [(PurePosixPath(), root)]
    while pending:
        relative_root, directory = pending.pop()
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name, reverse=True)
        except OSError as exc:
            raise BackupError("invalid_storage_data") from exc
        for child in children:
            relative = relative_root / child.name
            metadata = child.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise BackupError("symlink_not_allowed")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append((relative, child))
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise BackupError("unsupported_storage_entry")
            if child.name.endswith(".tmp") or ".tmp-" in child.name:
                raise BackupError("temporary_storage_entry")
            yield relative, child


def _validate_topology(root: Path, auth_relative: PurePosixPath) -> None:
    if auth_relative.parts[0] != "runtime" or len(auth_relative.parts) < 2:
        raise BackupError("invalid_auth_state_path")
    allowed_roots = {"uploads", "results", "runtime", "workspaces", ".locks", _IGNORED_MARKER, auth_relative.parts[0]}
    for child in root.iterdir():
        if child.name not in allowed_roots:
            raise BackupError("unsupported_storage_entry")
        if child.is_symlink():
            raise BackupError("symlink_not_allowed")
    auth_path = root.joinpath(*auth_relative.parts)
    runtime = root / "runtime"
    if runtime.exists():
        if runtime.is_symlink() or not runtime.is_dir():
            raise BackupError("invalid_storage_data")
        allowed_runtime_roots = {
            *_RUNTIME_OPERATION_DIRECTORIES,
            auth_relative.parts[1],
            _INTEGRATION_EVENT_OUTBOX_NAME,
        }
        for child in runtime.iterdir():
            if child.name == _IGNORED_MARKER:
                continue
            if child.name not in allowed_runtime_roots:
                raise BackupError("unsupported_storage_entry")
        _validate_single_auth_branch(runtime, auth_relative.parts[1:])
        outbox = runtime / _INTEGRATION_EVENT_OUTBOX_NAME
        if outbox.exists() or outbox.is_symlink():
            _require_regular_file(outbox)
    if auth_path.exists():
        _require_regular_file(auth_path)


def _validate_single_auth_branch(parent: Path, parts: tuple[str, ...]) -> None:
    """Ensure a custom auth DB path cannot hide omitted sibling state."""

    if not parts:
        raise BackupError("invalid_auth_state_path")
    candidate = parent / parts[0]
    if len(parts) == 1:
        if candidate.exists() or candidate.is_symlink():
            _require_regular_file(candidate)
        return
    if not candidate.exists():
        return
    if candidate.is_symlink() or not candidate.is_dir():
        raise BackupError("invalid_auth_state_path")
    for child in candidate.iterdir():
        if child.name != parts[1]:
            raise BackupError("unsupported_storage_entry")
    _validate_single_auth_branch(candidate, parts[1:])


def _require_quiescent(root: Path, auth_relative: PurePosixPath) -> None:
    jobs = _load_records(root / "results" / "jobs", JobRecord)
    if any(job.status in _ACTIVE_JOB_STATES for job in jobs.values()):
        raise BackupError("active_jobs_present")
    remediation_plan_jobs = _load_remediation_plan_jobs(
        root / "results" / "remediation_plan_jobs"
    )
    if any(job.status in {"queued", "running", "cancelling"} for job in remediation_plan_jobs.values()):
        raise BackupError("active_jobs_present")
    workspaces = root / "workspaces"
    if workspaces.exists():
        if workspaces.is_symlink() or not workspaces.is_dir():
            raise BackupError("invalid_storage_data")
        if any(path.name != _IGNORED_MARKER for path in workspaces.iterdir()):
            raise BackupError("execution_workspaces_present")
    for name in _RUNTIME_OPERATION_DIRECTORIES:
        directory = root / "runtime" / name
        if directory.exists():
            if directory.is_symlink() or not directory.is_dir():
                raise BackupError("invalid_storage_data")
            if any(path.name != _IGNORED_MARKER for path in directory.iterdir()):
                raise BackupError("pending_operations_present")
    batch_directory = root / "results" / "active_asset_batches"
    if batch_directory.exists():
        for path in batch_directory.rglob(".pending-*.json"):
            if path.is_file() or path.is_symlink():
                raise BackupError("pending_operations_present")
    auth_path = root.joinpath(*auth_relative.parts)
    sqlite_paths = (auth_path, root / "runtime" / _INTEGRATION_EVENT_OUTBOX_NAME)
    for sqlite_path in sqlite_paths:
        for suffix in ("-wal", "-shm", "-journal"):
            companion = Path(f"{sqlite_path}{suffix}")
            if companion.exists() or companion.is_symlink():
                raise BackupError("sqlite_not_quiescent")
    _require_integration_outbox_safe_to_exclude(
        root / "runtime" / _INTEGRATION_EVENT_OUTBOX_NAME
    )


def _require_integration_outbox_safe_to_exclude(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    _require_regular_file(path)
    metadata = path.lstat()
    if metadata.st_mode & 0o077 or metadata.st_size > 64 * 1024 * 1024:
        raise BackupError("invalid_storage_data")
    expected_columns = {
        "event_id", "organization_id", "payload_json", "state", "attempts",
        "next_attempt_at", "lease_until", "last_result", "created_at", "delivered_at",
    }
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
        try:
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(integration_events)")
            }
            pending = int(
                connection.execute(
                    "SELECT COUNT(*) FROM integration_events WHERE state != 'delivered'"
                ).fetchone()[0]
            )
            if integrity is None or integrity[0] != "ok" or tables != {"integration_events"} or columns != expected_columns:
                raise BackupError("invalid_storage_data")
            if pending:
                raise BackupError("pending_integration_events_present")
        finally:
            connection.close()
    except BackupError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        raise BackupError("invalid_storage_data") from exc


@contextmanager
def _offline_storage_locks(root: Path) -> Iterator[None]:
    lock_directory = root / ".locks"
    lock_directory.mkdir(mode=0o700, exist_ok=True)
    lock_paths = [lock_directory / "storage.lock", lock_directory / "product-audit.lock"]
    handles = []
    try:
        for path in lock_paths:
            handle = path.open("a+", encoding="utf-8")
            handles.append(handle)
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        for handle in reversed(handles):
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()


def _safe_relative_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or "\\" in value or "\x00" in value:
        raise BackupError("invalid_relative_path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise BackupError("invalid_relative_path")
    if path.as_posix() != value or len(value) > 512:
        raise BackupError("invalid_relative_path")
    return path


def _existing_directory(path: Path, code: str) -> Path:
    candidate = Path(path)
    try:
        if candidate.is_symlink() or not candidate.is_dir():
            raise BackupError(code)
        return candidate.resolve(strict=True)
    except OSError as exc:
        raise BackupError(code) from exc


def _absent_target(path: Path, code: str) -> Path:
    candidate = Path(path).absolute()
    if os.path.lexists(candidate):
        raise BackupError("destination_exists")
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise BackupError(code) from exc
    if parent.is_symlink() or not parent.is_dir():
        raise BackupError(code)
    return parent / candidate.name


def _require_separate_paths(source: Path, target: Path) -> None:
    if source == target or source in target.parents or target in source.parents:
        raise BackupError("overlapping_paths")


def _require_regular_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BackupError("invalid_storage_data") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise BackupError("unsupported_storage_entry")


def _copy_and_digest(source: Path, target: Path, *, expected_size: int) -> str:
    _require_regular_file(source)
    digest = hashlib.sha256()
    copied = 0
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        with source.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
            while chunk := reader.read(COPY_CHUNK_BYTES):
                copied += len(chunk)
                if copied > expected_size:
                    raise BackupError("source_changed_during_backup")
                digest.update(chunk)
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
    except Exception:
        target.unlink(missing_ok=True)
        raise
    if copied != expected_size or source.stat(follow_symlinks=False).st_size != expected_size:
        target.unlink(missing_ok=True)
        raise BackupError("source_changed_during_backup")
    copied_digest = digest.hexdigest()
    source_size, source_digest = _digest_file(source)
    if source_size != expected_size or source_digest != copied_digest:
        target.unlink(missing_ok=True)
        raise BackupError("source_changed_during_backup")
    return copied_digest


def _digest_file(path: Path) -> tuple[int, str]:
    _require_regular_file(path)
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(COPY_CHUNK_BYTES):
                size += len(chunk)
                if size > DEFAULT_MAX_BACKUP_FILE_BYTES:
                    raise BackupError("backup_file_size_limit_exceeded")
                digest.update(chunk)
    except OSError as exc:
        raise BackupError("backup_read_failed") from exc
    return size, digest.hexdigest()


def _entries_digest(entries: tuple[BackupEntry, ...] | list[BackupEntry]) -> str:
    value = [entry.model_dump(mode="json") for entry in entries]
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_private_json(path: Path, value: dict) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, separators=(",", ":"))
        handle.flush()
        os.fsync(handle.fileno())


def _make_tree_private(root: Path) -> None:
    for directory, directories, files in os.walk(root):
        os.chmod(directory, 0o700)
        for name in directories:
            os.chmod(Path(directory) / name, 0o700)
        for name in files:
            os.chmod(Path(directory) / name, 0o600)


def _record_scope(record) -> str | None:
    organization_id = getattr(record, "organization_id", None)
    owner_id = getattr(record, "owner_id", None)
    if organization_id is not None and owner_id is not None and organization_id != owner_id:
        raise BackupError("invalid_ownership_boundary")
    return organization_id or owner_id


def _validate_limits(max_files: int, max_file_bytes: int, max_total_bytes: int) -> None:
    if not 1 <= max_files <= DEFAULT_MAX_BACKUP_FILES:
        raise BackupError("invalid_backup_limits")
    if not 1 <= max_file_bytes <= DEFAULT_MAX_BACKUP_FILE_BYTES:
        raise BackupError("invalid_backup_limits")
    if not 1 <= max_total_bytes <= DEFAULT_MAX_BACKUP_TOTAL_BYTES:
        raise BackupError("invalid_backup_limits")


def _summary(
    manifest: BackupManifest,
    *,
    sessions_revoked: int = 0,
    invitations_revoked: int = 0,
) -> BackupSummary:
    return BackupSummary(
        backup_id=manifest.backup_id,
        file_count=manifest.file_count,
        total_bytes=manifest.total_bytes,
        entries_digest=manifest.entries_digest,
        auth_state_included=manifest.auth_state_included,
        sessions_revoked=sessions_revoked,
        invitations_revoked=invitations_revoked,
    )


def _remove_temporary_tree(path: Path) -> None:
    if path.name.startswith(".") and (".tmp-" in path.name or ".restore-" in path.name):
        shutil.rmtree(path, ignore_errors=True)
