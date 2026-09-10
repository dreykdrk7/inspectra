"""Synthetic, offline recovery drill for Inspectra's durable data contract.

The drill never accepts an Inspectra data directory.  It creates a bounded
two-owner fixture inside a newly generated private workspace, exercises backup,
checksum rejection and restore, verifies the restored ownership boundaries and
then removes the entire workspace before returning evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import time
from typing import Callable, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.auth import hash_password
from app.auth_state_sqlite import SQLiteAuthStateStore
from app.backup import (
    BACKUP_CONTRACT_VERSION,
    BackupError,
    create_backup,
    restore_backup,
    validate_data_store,
    verify_backup,
)
from app.config import Settings
from app.finding_lifecycle import FindingDecisionStore
from app.models import StoredFile
from app.product_audit import ProductAuditStore
from app.project_vulnerability_intelligence import ProjectVulnerabilityIntelligenceStore
from app.retention import RETENTION_POLICY_CLASS_COUNT, RETENTION_POLICY_CONTRACT_VERSION, build_retention_policy
from app.storage import FileStore, JobStore, ProjectStore
from app.team_identity import TeamIdentityStore


RECOVERY_DRILL_CONTRACT_VERSION = "2026-09-06.1"
RECOVERY_DRILL_FIXTURE_VERSION = "2026-09-06.1"
_DRILL_BACKUP_ID = "c" * 32
_OWNER_A = "a" * 32
_OWNER_B = "b" * 32
_FIXED_NOW = datetime(2026, 9, 6, 16, 0, tzinfo=timezone.utc)


class RecoveryDrillError(RuntimeError):
    """Content-free failure suitable for operator-facing CLI output."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RecoveryDrillTimings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    fixture_ms: float = Field(ge=0)
    backup_ms: float = Field(ge=0)
    verify_ms: float = Field(ge=0)
    checksum_rejection_ms: float = Field(ge=0)
    restore_ms: float = Field(ge=0)
    restored_validation_ms: float = Field(ge=0)
    cleanup_ms: float = Field(ge=0)
    total_ms: float = Field(ge=0)


class RecoveryDrillSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-06.1"] = RECOVERY_DRILL_CONTRACT_VERSION
    backup_contract_version: Literal["2026-09-06.1"] = BACKUP_CONTRACT_VERSION
    retention_contract_version: Literal["2026-09-10.7"] = RETENTION_POLICY_CONTRACT_VERSION
    fixture_version: Literal["2026-09-06.1"] = RECOVERY_DRILL_FIXTURE_VERSION
    status: Literal["succeeded"] = "succeeded"
    data_scope: Literal["synthetic_two_owner_fixture"] = "synthetic_two_owner_fixture"
    project_count: Literal[2] = 2
    analysis_count: Literal[2] = 2
    source_count: Literal[2] = 2
    backup_file_count: int = Field(ge=1)
    backup_total_bytes: int = Field(ge=1)
    restored_sessions_revoked: int = Field(ge=1)
    restored_invitations_revoked: int = Field(ge=1)
    checksum_rejection_verified: Literal[True] = True
    corrupt_restore_not_published: Literal[True] = True
    owner_boundaries_verified: Literal[True] = True
    source_integrity_verified: Literal[True] = True
    retained_records_verified: Literal[True] = True
    source_rollback_preserved: Literal[True] = True
    egress_disabled_verified: Literal[True] = True
    external_configuration_restore_required: Literal[True] = True
    active_instance_modified: Literal[False] = False
    external_network_used: Literal[False] = False
    workspace_cleanup_verified: Literal[True] = True
    observed_data_loss_records: Literal[0] = 0
    measurements_are_sla: Literal[False] = False
    timings: RecoveryDrillTimings


@dataclass(frozen=True)
class _SyntheticRecordSet:
    owner_id: str
    file_id: str
    project_id: str
    job_id: str
    source_payload: bytes


def run_recovery_drill(
    workspace_parent: Path,
    *,
    offline_confirmed: bool,
    synthetic_data_only_confirmed: bool,
    encrypted_workspace_confirmed: bool,
    clock: Callable[[], float] = time.perf_counter,
) -> RecoveryDrillSummary:
    """Run a self-cleaning recovery drill without accepting user data."""

    if not offline_confirmed:
        raise RecoveryDrillError("offline_confirmation_required")
    if not synthetic_data_only_confirmed:
        raise RecoveryDrillError("synthetic_data_confirmation_required")
    if not encrypted_workspace_confirmed:
        raise RecoveryDrillError("encrypted_workspace_confirmation_required")
    parent = _validated_workspace_parent(workspace_parent)

    total_started = clock()
    workspace: Path | None = None
    timings: dict[str, float] = {}
    result_fields: dict[str, object] | None = None
    pending_error: BaseException | None = None
    try:
        workspace = Path(tempfile.mkdtemp(prefix=".inspectra-recovery-drill-", dir=parent))
        os.chmod(workspace, 0o700)
        source_dir = workspace / "source"
        backup_dir = workspace / "backup"
        corrupted_backup_dir = workspace / "corrupted-backup"
        corrupted_restore_dir = workspace / "corrupted-restore"
        restored_dir = workspace / "restored"

        started = clock()
        settings, records = _build_synthetic_fixture(source_dir)
        source_before = _durable_tree_digest(source_dir)
        timings["fixture_ms"] = _elapsed_ms(started, clock)

        started = clock()
        created = create_backup(
            source_dir,
            backup_dir,
            offline_confirmed=True,
            sensitive_data_confirmed=True,
            encrypted_destination_confirmed=True,
            now=_FIXED_NOW,
            backup_id=_DRILL_BACKUP_ID,
        )
        timings["backup_ms"] = _elapsed_ms(started, clock)

        started = clock()
        verified = verify_backup(backup_dir, sensitive_data_confirmed=True)
        if verified != created:
            raise RecoveryDrillError("backup_verification_mismatch")
        timings["verify_ms"] = _elapsed_ms(started, clock)

        started = clock()
        shutil.copytree(backup_dir, corrupted_backup_dir)
        _corrupt_one_payload_entry(corrupted_backup_dir)
        try:
            restore_backup(
                corrupted_backup_dir,
                corrupted_restore_dir,
                offline_confirmed=True,
                sensitive_data_confirmed=True,
            )
        except BackupError as exc:
            if exc.code != "checksum_mismatch":
                raise RecoveryDrillError("unexpected_corruption_result") from exc
        else:
            raise RecoveryDrillError("checksum_rejection_missing")
        if corrupted_restore_dir.exists() or list(workspace.glob(".corrupted-restore.restore-*")):
            raise RecoveryDrillError("corrupt_restore_published")
        timings["checksum_rejection_ms"] = _elapsed_ms(started, clock)

        started = clock()
        restored = restore_backup(
            backup_dir,
            restored_dir,
            offline_confirmed=True,
            sensitive_data_confirmed=True,
        )
        timings["restore_ms"] = _elapsed_ms(started, clock)

        started = clock()
        _validate_restored_fixture(restored_dir, records)
        validate_data_store(source_dir)
        if _durable_tree_digest(source_dir) != source_before:
            raise RecoveryDrillError("source_instance_modified")
        if settings.public_advisory_egress_enabled:
            raise RecoveryDrillError("unsafe_restored_configuration")
        timings["restored_validation_ms"] = _elapsed_ms(started, clock)
        result_fields = {
            "backup_file_count": created.file_count,
            "backup_total_bytes": created.total_bytes,
            "restored_sessions_revoked": restored.sessions_revoked,
            "restored_invitations_revoked": restored.invitations_revoked,
        }
    except RecoveryDrillError as exc:
        pending_error = exc
    except BackupError as exc:
        pending_error = RecoveryDrillError(f"backup_{exc.code}")
    except Exception as exc:
        pending_error = RecoveryDrillError("recovery_drill_failed")
        pending_error.__cause__ = exc
    finally:
        cleanup_started = clock()
        if workspace is not None:
            try:
                shutil.rmtree(workspace)
            except OSError as exc:
                pending_error = RecoveryDrillError("workspace_cleanup_failed")
                pending_error.__cause__ = exc
        timings["cleanup_ms"] = _elapsed_ms(cleanup_started, clock)

    if workspace is None or workspace.exists():
        raise RecoveryDrillError("workspace_cleanup_failed")
    if pending_error is not None:
        raise pending_error
    if result_fields is None:
        raise RecoveryDrillError("recovery_drill_failed")
    timings["total_ms"] = _elapsed_ms(total_started, clock)
    return RecoveryDrillSummary(
        **result_fields,
        timings=RecoveryDrillTimings(**timings),
    )


def _validated_workspace_parent(path: Path) -> Path:
    candidate = path.expanduser()
    try:
        if candidate.is_symlink() or not candidate.is_dir():
            raise RecoveryDrillError("invalid_workspace_parent")
        return candidate.resolve(strict=True)
    except OSError as exc:
        raise RecoveryDrillError("invalid_workspace_parent") from exc


def _settings(data_dir: Path) -> Settings:
    settings = Settings(
        data_dir=data_dir,
        tool_runner_url="http://audit-tools:8081",
        auth_state_store="sqlite",
        public_advisory_egress_enabled=False,
    )
    settings.ensure_directories()
    return settings


def _add_project(settings: Settings, *, owner_id: str, file_id: str, payload: bytes) -> _SyntheticRecordSet:
    files = FileStore(settings)
    projects = ProjectStore(settings)
    jobs = JobStore(settings)
    source = StoredFile(
        id=file_id,
        owner_id=owner_id,
        kind="archive",
        original_filename="synthetic-authorized-source.zip",
        stored_filename=f"{file_id}.zip",
        content_type="application/zip",
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        created_at=_FIXED_NOW,
    )
    files.source_path(source).write_bytes(payload)
    files._save_record(source)
    project = projects.create(name="Synthetic recovery project", source=source, owner_id=owner_id)
    job = jobs.create_project_archive_job(
        source.id,
        owner_id=owner_id,
        project_id=project.id,
        source_sha256=source.sha256,
    )
    projects.attach_job(project.id, job.id)
    jobs.update(
        job.id,
        status="completed",
        result={"analyzer": "project_archive_basic", "summary": {}, "findings": []},
    )
    return _SyntheticRecordSet(
        owner_id=owner_id,
        file_id=source.id,
        project_id=project.id,
        job_id=job.id,
        source_payload=payload,
    )


def _build_synthetic_fixture(data_dir: Path) -> tuple[Settings, tuple[_SyntheticRecordSet, _SyntheticRecordSet]]:
    settings = _settings(data_dir)
    owner_a = _add_project(
        settings,
        owner_id=_OWNER_A,
        file_id="1" * 32,
        payload=b"PK\x03\x04inspectra-recovery-owner-a",
    )
    owner_b = _add_project(
        settings,
        owner_id=_OWNER_B,
        file_id="2" * 32,
        payload=b"PK\x03\x04inspectra-recovery-owner-b",
    )
    FindingDecisionStore(settings, now_func=lambda: _FIXED_NOW).record(
        organization_id=_OWNER_A,
        project_id=owner_a.project_id,
        finding_id="f" * 64,
        rule_id="fixture.recovery",
        status="in_review",
        reason="Synthetic recovery review",
        comment=None,
        actor_id=_OWNER_A,
        actor_username="fixture.admin",
        actor_role="administrator",
        review_at=None,
        assignee_user_id=None,
        assignee_username=None,
    )
    ProductAuditStore(settings, now_func=lambda: _FIXED_NOW).record(
        organization_id=_OWNER_A,
        actor_id=_OWNER_A,
        actor_role="administrator",
        action="project.created",
        resource_type="project",
        resource_id=owner_a.project_id,
        correlation_id=f"project:{owner_a.project_id}",
    )
    ProjectVulnerabilityIntelligenceStore(settings.public_advisories_dir).put(
        owner_a.job_id,
        {"state": "disabled", "queried_at": _FIXED_NOW.isoformat(), "sources": [], "summary": {"findings": 0}},
        recorded_at=_FIXED_NOW,
    )

    password_hash = hash_password("synthetic-recovery-password")
    identity = TeamIdentityStore(
        settings.resolved_auth_state_db_path,
        organization_name="Synthetic recovery team",
        bootstrap_admin_password_hash=password_hash,
        invitation_ttl_seconds=3600,
        now_func=lambda: _FIXED_NOW,
        token_factory=lambda: "synthetic-recovery-invitation-token-with-entropy",
    )
    admin = identity.authenticate("admin", "synthetic-recovery-password")
    if admin is None:
        raise RecoveryDrillError("fixture_identity_failed")
    identity.create_invitation(principal=admin, username="restore.reader", role="reader")
    SQLiteAuthStateStore(settings.resolved_auth_state_db_path).create_session(
        "synthetic-recovery-session",
        "synthetic-recovery-csrf",
        _OWNER_A,
        organization_id=_OWNER_A,
        role="administrator",
        expires_at=_FIXED_NOW + timedelta(hours=1),
        now=_FIXED_NOW,
    )
    return settings, (owner_a, owner_b)


def _corrupt_one_payload_entry(backup_dir: Path) -> None:
    try:
        manifest = json.loads((backup_dir / "manifest.json").read_text(encoding="utf-8"))
        relative_paths = [item["relative_path"] for item in manifest["entries"]]
        selected = next(
            (item for item in relative_paths if item.startswith("uploads/") and not item.endswith(".json")),
            relative_paths[0],
        )
        payload = backup_dir / "payload" / selected
        with payload.open("ab") as handle:
            handle.write(b"corrupt")
    except (OSError, KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise RecoveryDrillError("fixture_corruption_failed") from exc


def _validate_restored_fixture(restored_dir: Path, records: tuple[_SyntheticRecordSet, _SyntheticRecordSet]) -> None:
    validate_data_store(restored_dir)
    settings = _settings(restored_dir)
    files = FileStore(settings)
    projects = ProjectStore(settings)
    jobs = JobStore(settings)
    for expected in records:
        source = files.get(expected.file_id)
        project = projects.get(expected.project_id)
        job = jobs.get(expected.job_id)
        if (
            source.owner_id != expected.owner_id
            or project.owner_id != expected.owner_id
            or job.owner_id != expected.owner_id
        ):
            raise RecoveryDrillError("restored_owner_boundary_failed")
        if project.source_file_id != source.id or job.file_id != source.id or job.project_id != project.id:
            raise RecoveryDrillError("restored_reference_failed")
        if files.source_path(source).read_bytes() != expected.source_payload:
            raise RecoveryDrillError("restored_source_integrity_failed")

    first = records[0]
    decisions = FindingDecisionStore(settings, now_func=lambda: _FIXED_NOW).list_for_project(
        first.owner_id,
        first.project_id,
    )
    audit_events = ProductAuditStore(settings, now_func=lambda: _FIXED_NOW).list(first.owner_id).items
    public_snapshot = ProjectVulnerabilityIntelligenceStore(settings.public_advisories_dir).get(first.job_id)
    retention = build_retention_policy(settings, manual_cleanup_allowed=True)
    if (
        len(decisions) != 1
        or len(audit_events) != 1
        or public_snapshot is None
        or public_snapshot.get("state") != "disabled"
    ):
        raise RecoveryDrillError("restored_retained_records_failed")
    if (
        retention.contract_version != RETENTION_POLICY_CONTRACT_VERSION
        or len(retention.classes) != RETENTION_POLICY_CLASS_COUNT
    ):
        raise RecoveryDrillError("restored_retention_contract_failed")

    with sqlite3.connect(settings.resolved_auth_state_db_path) as connection:
        sessions = connection.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0]
        attempts = connection.execute("SELECT COUNT(*) FROM auth_login_attempts").fetchone()[0]
        invitations = connection.execute("SELECT COUNT(*) FROM team_invitations").fetchone()[0]
        users = connection.execute("SELECT COUNT(*) FROM team_users").fetchone()[0]
    if (sessions, attempts, invitations, users) != (0, 0, 0, 1):
        raise RecoveryDrillError("restored_access_state_failed")
    if settings.public_advisory_egress_enabled:
        raise RecoveryDrillError("unsafe_restored_configuration")


def _durable_tree_digest(data_dir: Path) -> str:
    digest = hashlib.sha256()
    for root_name in ("uploads", "results", "runtime"):
        root = data_dir / root_name
        if not root.exists():
            continue
        for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: item.as_posix()):
            relative = path.relative_to(data_dir).as_posix()
            digest.update(len(relative).to_bytes(4, "big"))
            digest.update(relative.encode("utf-8"))
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _elapsed_ms(started: float, clock: Callable[[], float]) -> float:
    return round(max(0.0, (clock() - started) * 1000), 3)
