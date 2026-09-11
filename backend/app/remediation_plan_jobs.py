"""Durable, bounded remediation-plan jobs and private snapshot artifacts."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.config import Settings
from app.models import RemediationActionGroup, RemediationSearchRequest, RemediationSummary
from app.storage import storage_lock


REMEDIATION_PLAN_JOB_CONTRACT_VERSION = "2026-09-09.1"
REMEDIATION_PLAN_ARTIFACT_CONTRACT_VERSION = "2026-09-09.1"
REMEDIATION_PLAN_MAX_JOBS_PER_ORGANIZATION = 100
REMEDIATION_PLAN_MAX_INFLIGHT_PER_ORGANIZATION = 2
REMEDIATION_PLAN_MAX_PROJECTS = 100_000
REMEDIATION_PLAN_MAX_GROUPS = 2_000
REMEDIATION_PLAN_MAX_OCCURRENCES = 5_000
REMEDIATION_PLAN_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
REMEDIATION_PLAN_ARTIFACT_TTL_DAYS = 7
REMEDIATION_PLAN_PROGRESS_CHECKPOINT_PROJECTS = 1_000
_ID = re.compile(r"^[a-f0-9]{32}$")
_OWNER = re.compile(r"^(?:local-admin|[a-f0-9]{32})$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")


class RemediationPlanJobError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RemediationPlanCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filters: RemediationSearchRequest = Field(default_factory=RemediationSearchRequest)
    idempotency_key: str = Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    project_metadata_confirmed: Literal[True]

    def canonical_filters(self) -> RemediationSearchRequest:
        if self.filters.cursor is not None:
            raise RemediationPlanJobError("invalid_request")
        return self.filters.model_copy(update={"page_size": 100, "cursor": None})


class RemediationPlanRetryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    confirmation: Literal[True]


class RemediationPlanJob(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[REMEDIATION_PLAN_JOB_CONTRACT_VERSION] = REMEDIATION_PLAN_JOB_CONTRACT_VERSION
    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    organization_id: str = Field(pattern=r"^(?:local-admin|[a-f0-9]{32})$")
    status: Literal["queued", "running", "cancelling", "cancelled", "completed", "failed", "expired"]
    filters: RemediationSearchRequest
    request_digest: str = Field(pattern=r"^[a-f0-9]{64}$", exclude=True)
    idempotency_digest: str = Field(pattern=r"^[a-f0-9]{64}$", exclude=True)
    project_revision: str | None = Field(default=None, max_length=128, exclude=True)
    created_at: datetime
    updated_at: datetime
    cutoff_at: datetime
    expires_at: datetime | None = None
    processed_projects: int = Field(default=0, ge=0, le=REMEDIATION_PLAN_MAX_PROJECTS)
    total_projects: int = Field(default=0, ge=0, le=REMEDIATION_PLAN_MAX_PROJECTS)
    included_groups: int = Field(default=0, ge=0, le=REMEDIATION_PLAN_MAX_GROUPS)
    included_occurrences: int = Field(default=0, ge=0, le=REMEDIATION_PLAN_MAX_OCCURRENCES)
    groups_truncated: bool = False
    occurrences_truncated: bool = False
    snapshot_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    artifact_bytes: int = Field(default=0, ge=0, le=REMEDIATION_PLAN_MAX_ARTIFACT_BYTES)
    failure_reason: Literal[
        "portfolio_changed", "source_unavailable", "safe_limit_reached", "artifact_too_large", "internal_error"
    ] | None = None
    retry_of_job_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    recovery_count: int = Field(default=0, ge=0, le=3)
    replayed: bool = False
    privacy: Literal["owner_scoped_project_names_no_paths_content_comments_or_actors"] = (
        "owner_scoped_project_names_no_paths_content_comments_or_actors"
    )


class RemediationPlanJobPage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[REMEDIATION_PLAN_JOB_CONTRACT_VERSION] = REMEDIATION_PLAN_JOB_CONTRACT_VERSION
    items: list[RemediationPlanJob] = Field(max_length=100)
    max_retained_jobs: Literal[REMEDIATION_PLAN_MAX_JOBS_PER_ORGANIZATION] = REMEDIATION_PLAN_MAX_JOBS_PER_ORGANIZATION
    artifact_ttl_days: Literal[REMEDIATION_PLAN_ARTIFACT_TTL_DAYS] = REMEDIATION_PLAN_ARTIFACT_TTL_DAYS


class RemediationPlanArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[REMEDIATION_PLAN_ARTIFACT_CONTRACT_VERSION] = REMEDIATION_PLAN_ARTIFACT_CONTRACT_VERSION
    job_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    organization_id: str = Field(pattern=r"^(?:local-admin|[a-f0-9]{32})$", exclude=True)
    cutoff_at: datetime
    project_revision: str = Field(min_length=1, max_length=128, exclude=True)
    processed_projects: int = Field(ge=0, le=REMEDIATION_PLAN_MAX_PROJECTS)
    total_projects: int = Field(ge=0, le=REMEDIATION_PLAN_MAX_PROJECTS)
    included_groups: int = Field(ge=0, le=REMEDIATION_PLAN_MAX_GROUPS)
    included_occurrences: int = Field(ge=0, le=REMEDIATION_PLAN_MAX_OCCURRENCES)
    groups_truncated: bool
    occurrences_truncated: bool
    summary: RemediationSummary
    groups: list[RemediationActionGroup] = Field(max_length=REMEDIATION_PLAN_MAX_GROUPS)
    resolution_policy: Literal["comparable_reanalysis_required"] = "comparable_reanalysis_required"
    privacy: Literal["project_names_included_no_paths_content_comments_or_actors"] = (
        "project_names_included_no_paths_content_comments_or_actors"
    )
    limitations: list[str] = Field(max_length=12)


class RemediationPlanJobStore:
    def __init__(self, settings: Settings, *, now_func: Callable[[], datetime] | None = None) -> None:
        self.settings = settings
        self.jobs_root = settings.remediation_plan_jobs_dir
        self.artifacts_root = settings.remediation_plan_artifacts_dir
        self._now_func = now_func or (lambda: datetime.now(timezone.utc))

    def create(
        self,
        organization_id: str,
        payload: RemediationPlanCreateRequest,
        *,
        retry_of_job_id: str | None = None,
    ) -> RemediationPlanJob:
        self._validate_owner(organization_id)
        filters = payload.canonical_filters()
        canonical = json.dumps(filters.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        request_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        key_digest = _bound_digest(organization_id, "idempotency", payload.idempotency_key)
        now = self._now()
        with storage_lock(self.settings):
            records = self._purge_history_unlocked(
                organization_id, self._list_unlocked(organization_id)
            )
            for record in records:
                if record.idempotency_digest != key_digest:
                    continue
                if record.request_digest != request_digest:
                    raise RemediationPlanJobError("idempotency_conflict")
                return record.model_copy(update={"replayed": True})
            if len(records) >= REMEDIATION_PLAN_MAX_JOBS_PER_ORGANIZATION:
                raise RemediationPlanJobError("job_limit")
            if sum(item.status in {"queued", "running", "cancelling"} for item in records) >= REMEDIATION_PLAN_MAX_INFLIGHT_PER_ORGANIZATION:
                raise RemediationPlanJobError("capacity")
            record = RemediationPlanJob(
                id=uuid4().hex,
                organization_id=organization_id,
                status="queued",
                filters=filters,
                request_digest=request_digest,
                idempotency_digest=key_digest,
                created_at=now,
                updated_at=now,
                cutoff_at=now,
                retry_of_job_id=retry_of_job_id,
            )
            self._write_job_unlocked(record)
            return record

    def retry(self, organization_id: str, job_id: str, payload: RemediationPlanRetryRequest) -> RemediationPlanJob:
        previous = self.get(organization_id, job_id)
        if previous.status not in {"failed", "cancelled", "expired"}:
            raise RemediationPlanJobError("invalid_transition")
        return self.create(
            organization_id,
            RemediationPlanCreateRequest(
                filters=previous.filters,
                idempotency_key=payload.idempotency_key,
                project_metadata_confirmed=True,
            ),
            retry_of_job_id=previous.id,
        )

    def list(self, organization_id: str) -> RemediationPlanJobPage:
        self._validate_owner(organization_id)
        with storage_lock(self.settings):
            records = self._purge_history_unlocked(
                organization_id,
                [self._expire_unlocked(item) for item in self._list_unlocked(organization_id)],
            )
        records.sort(key=lambda item: (item.created_at, item.id), reverse=True)
        return RemediationPlanJobPage(items=records)

    def get(self, organization_id: str, job_id: str) -> RemediationPlanJob:
        self._validate_owner(organization_id)
        self._validate_id(job_id)
        with storage_lock(self.settings):
            return self._expire_unlocked(self._read_job_unlocked(organization_id, job_id))

    def claim(self, organization_id: str, job_id: str, *, project_revision: str, total_projects: int) -> RemediationPlanJob:
        if not 0 <= total_projects <= REMEDIATION_PLAN_MAX_PROJECTS:
            raise RemediationPlanJobError("safe_limit_reached")
        with storage_lock(self.settings):
            record = self._read_job_unlocked(organization_id, job_id)
            if record.status != "queued":
                raise RemediationPlanJobError("invalid_transition")
            updated = record.model_copy(update={
                "status": "running", "project_revision": project_revision,
                "total_projects": total_projects, "updated_at": self._now(), "replayed": False,
            })
            self._write_job_unlocked(updated)
            return updated

    def progress(self, organization_id: str, job_id: str, processed_projects: int) -> RemediationPlanJob:
        with storage_lock(self.settings):
            record = self._read_job_unlocked(organization_id, job_id)
            if record.status == "cancelling":
                raise RemediationPlanJobError("cancelled")
            if record.status != "running" or not record.processed_projects <= processed_projects <= record.total_projects:
                raise RemediationPlanJobError("invalid_transition")
            updated = record.model_copy(update={"processed_projects": processed_projects, "updated_at": self._now()})
            self._write_job_unlocked(updated)
            return updated

    def assert_running(self, organization_id: str, job_id: str, processed_projects: int) -> RemediationPlanJob:
        """Check cancellation and bounds without forcing a durable progress write."""

        with storage_lock(self.settings):
            record = self._read_job_unlocked(organization_id, job_id)
            if record.status == "cancelling":
                raise RemediationPlanJobError("cancelled")
            if record.status != "running" or not record.processed_projects <= processed_projects <= record.total_projects:
                raise RemediationPlanJobError("invalid_transition")
            return record

    def cancel(self, organization_id: str, job_id: str) -> RemediationPlanJob:
        with storage_lock(self.settings):
            record = self._read_job_unlocked(organization_id, job_id)
            if record.status == "queued":
                updated = record.model_copy(update={"status": "cancelled", "updated_at": self._now()})
            elif record.status == "running":
                updated = record.model_copy(update={"status": "cancelling", "updated_at": self._now()})
            elif record.status in {"cancelling", "cancelled"}:
                return record
            else:
                raise RemediationPlanJobError("invalid_transition")
            self._write_job_unlocked(updated)
            return updated

    def finish_cancel(self, organization_id: str, job_id: str) -> RemediationPlanJob:
        with storage_lock(self.settings):
            record = self._read_job_unlocked(organization_id, job_id)
            if record.status not in {"running", "cancelling"}:
                return record
            _durable_unlink(self._artifact_path(organization_id, job_id))
            updated = record.model_copy(update={"status": "cancelled", "updated_at": self._now()})
            self._write_job_unlocked(updated)
            return updated

    def complete(self, organization_id: str, job_id: str, artifact: RemediationPlanArtifact) -> RemediationPlanJob:
        encoded = _canonical_artifact_bytes(artifact)
        if len(encoded) > REMEDIATION_PLAN_MAX_ARTIFACT_BYTES:
            raise RemediationPlanJobError("artifact_too_large")
        digest = hashlib.sha256(encoded).hexdigest()
        occurrences = sum(min(item.occurrence_count, len(item.occurrences)) for item in artifact.groups)
        with storage_lock(self.settings):
            record = self._read_job_unlocked(organization_id, job_id)
            if record.status == "cancelling":
                raise RemediationPlanJobError("cancelled")
            if record.status != "running" or artifact.job_id != job_id or artifact.organization_id != organization_id:
                raise RemediationPlanJobError("invalid_transition")
            _durable_write_bytes(self._artifact_path(organization_id, job_id), encoded)
            now = self._now()
            updated = record.model_copy(update={
                "status": "completed", "updated_at": now,
                "expires_at": now + timedelta(days=REMEDIATION_PLAN_ARTIFACT_TTL_DAYS),
                "processed_projects": artifact.processed_projects,
                "included_groups": artifact.included_groups,
                "included_occurrences": occurrences,
                "groups_truncated": artifact.groups_truncated,
                "occurrences_truncated": artifact.occurrences_truncated,
                "snapshot_sha256": digest, "artifact_bytes": len(encoded), "failure_reason": None,
            })
            self._write_job_unlocked(updated)
            return updated

    def fail(self, organization_id: str, job_id: str, reason: str) -> RemediationPlanJob:
        allowed = {"portfolio_changed", "source_unavailable", "safe_limit_reached", "artifact_too_large", "internal_error"}
        safe_reason = reason if reason in allowed else "internal_error"
        with storage_lock(self.settings):
            record = self._read_job_unlocked(organization_id, job_id)
            if record.status not in {"queued", "running", "cancelling"}:
                return record
            _durable_unlink(self._artifact_path(organization_id, job_id))
            updated = record.model_copy(update={"status": "failed", "failure_reason": safe_reason, "updated_at": self._now()})
            self._write_job_unlocked(updated)
            return updated

    def artifact(self, organization_id: str, job_id: str) -> tuple[RemediationPlanJob, RemediationPlanArtifact]:
        with storage_lock(self.settings):
            record = self._expire_unlocked(self._read_job_unlocked(organization_id, job_id))
            if record.status == "expired":
                raise RemediationPlanJobError("artifact_expired")
            if record.status != "completed" or record.snapshot_sha256 is None:
                raise RemediationPlanJobError("artifact_unavailable")
            path = self._artifact_path(organization_id, job_id)
            raw = _read_private_file(path, REMEDIATION_PLAN_MAX_ARTIFACT_BYTES)
            if not hmac_compare(hashlib.sha256(raw).hexdigest(), record.snapshot_sha256):
                raise RemediationPlanJobError("artifact_invalid")
            try:
                artifact = RemediationPlanArtifact.model_validate_json(raw)
            except ValidationError as exc:
                raise RemediationPlanJobError("artifact_invalid") from exc
            if artifact.organization_id != organization_id or artifact.job_id != job_id:
                raise RemediationPlanJobError("artifact_invalid")
            return record, artifact

    def recover(self) -> list[RemediationPlanJob]:
        recovered: list[RemediationPlanJob] = []
        with storage_lock(self.settings):
            for organization_dir in self.jobs_root.iterdir() if self.jobs_root.exists() else ():
                if organization_dir.is_symlink() or not organization_dir.is_dir() or not _OWNER.fullmatch(organization_dir.name):
                    raise RemediationPlanJobError("store_invalid")
                for record in self._list_unlocked(organization_dir.name):
                    if record.status == "cancelling":
                        updated = record.model_copy(update={"status": "cancelled", "updated_at": self._now()})
                        _durable_unlink(self._artifact_path(record.organization_id, record.id))
                        self._write_job_unlocked(updated)
                    elif record.status == "running":
                        if record.recovery_count >= 3:
                            updated = record.model_copy(update={"status": "failed", "failure_reason": "internal_error", "updated_at": self._now()})
                        else:
                            updated = record.model_copy(update={
                                "status": "queued", "processed_projects": 0,
                                "project_revision": None, "recovery_count": record.recovery_count + 1,
                                "updated_at": self._now(),
                            })
                            recovered.append(updated)
                        _durable_unlink(self._artifact_path(record.organization_id, record.id))
                        self._write_job_unlocked(updated)
                    elif record.status == "completed":
                        raw = _read_private_file(
                            self._artifact_path(record.organization_id, record.id),
                            REMEDIATION_PLAN_MAX_ARTIFACT_BYTES,
                        )
                        if record.snapshot_sha256 is None or not hmac_compare(
                            hashlib.sha256(raw).hexdigest(), record.snapshot_sha256
                        ):
                            raise RemediationPlanJobError("artifact_invalid")
                        try:
                            artifact = RemediationPlanArtifact.model_validate_json(raw)
                        except ValidationError as exc:
                            raise RemediationPlanJobError("artifact_invalid") from exc
                        if artifact.organization_id != record.organization_id or artifact.job_id != record.id:
                            raise RemediationPlanJobError("artifact_invalid")
        return recovered

    def purge_expired(self) -> int:
        removed = 0
        with storage_lock(self.settings):
            for organization_dir in self.jobs_root.iterdir() if self.jobs_root.exists() else ():
                if not _OWNER.fullmatch(organization_dir.name):
                    continue
                for record in self._list_unlocked(organization_dir.name):
                    before = record.status
                    after = self._expire_unlocked(record)
                    if before != after.status:
                        removed += 1
        return removed

    def _expire_unlocked(self, record: RemediationPlanJob) -> RemediationPlanJob:
        if record.status == "completed" and record.expires_at is not None and record.expires_at <= self._now():
            _durable_unlink(self._artifact_path(record.organization_id, record.id))
            updated = record.model_copy(update={
                "status": "expired", "updated_at": self._now(), "snapshot_sha256": None,
                "artifact_bytes": 0,
            })
            self._write_job_unlocked(updated)
            return updated
        return record

    def _purge_history_unlocked(
        self, organization_id: str, records: list[RemediationPlanJob]
    ) -> list[RemediationPlanJob]:
        cutoff = self._now() - timedelta(days=30)
        retained: list[RemediationPlanJob] = []
        for record in records:
            if record.status in {"cancelled", "failed", "expired"} and record.updated_at < cutoff:
                _durable_unlink(self._job_path(organization_id, record.id))
                _durable_unlink(self._artifact_path(organization_id, record.id))
                continue
            retained.append(record)
        return retained

    def _list_unlocked(self, organization_id: str) -> list[RemediationPlanJob]:
        directory = self._organization_dir(self.jobs_root, organization_id)
        if not directory.exists():
            return []
        paths = list(directory.iterdir())
        if len(paths) > REMEDIATION_PLAN_MAX_JOBS_PER_ORGANIZATION:
            raise RemediationPlanJobError("store_invalid")
        records: list[RemediationPlanJob] = []
        for path in paths:
            if not _ID.fullmatch(path.stem) or path.suffix != ".json":
                raise RemediationPlanJobError("store_invalid")
            records.append(self._read_job_unlocked(organization_id, path.stem))
        return records

    def _read_job_unlocked(self, organization_id: str, job_id: str) -> RemediationPlanJob:
        try:
            raw = _read_private_file(self._job_path(organization_id, job_id), 64 * 1024)
            record = RemediationPlanJob.model_validate_json(raw)
        except FileNotFoundError as exc:
            raise RemediationPlanJobError("not_found") from exc
        except (OSError, ValidationError, ValueError) as exc:
            raise RemediationPlanJobError("store_invalid") from exc
        if record.id != job_id or record.organization_id != organization_id:
            raise RemediationPlanJobError("not_found")
        return record

    def _write_job_unlocked(self, record: RemediationPlanJob) -> None:
        document = record.model_dump(mode="json")
        document.update({
            "request_digest": record.request_digest,
            "idempotency_digest": record.idempotency_digest,
            "project_revision": record.project_revision,
        })
        _durable_write_bytes(
            self._job_path(record.organization_id, record.id),
            (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
        )

    def _job_path(self, organization_id: str, job_id: str) -> Path:
        self._validate_owner(organization_id)
        self._validate_id(job_id)
        return self._organization_dir(self.jobs_root, organization_id) / f"{job_id}.json"

    def _artifact_path(self, organization_id: str, job_id: str) -> Path:
        self._validate_owner(organization_id)
        self._validate_id(job_id)
        return self._organization_dir(self.artifacts_root, organization_id) / f"{job_id}.json"

    @staticmethod
    def _organization_dir(root: Path, organization_id: str) -> Path:
        return root / organization_id

    @staticmethod
    def _validate_owner(value: str) -> None:
        if not _OWNER.fullmatch(value):
            raise RemediationPlanJobError("invalid_owner")

    @staticmethod
    def _validate_id(value: str) -> None:
        if not _ID.fullmatch(value):
            raise RemediationPlanJobError("not_found")

    def _now(self) -> datetime:
        value = self._now_func()
        if value.tzinfo is None or value.utcoffset() is None:
            raise RemediationPlanJobError("store_invalid")
        return value.astimezone(timezone.utc)


def _canonical_artifact_bytes(artifact: RemediationPlanArtifact) -> bytes:
    document = artifact.model_dump(mode="json")
    document.update({
        "organization_id": artifact.organization_id,
        "project_revision": artifact.project_revision,
    })
    return (json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _bound_digest(owner: str, purpose: str, value: str) -> str:
    return hashlib.sha256(
        b"inspectra-remediation-plan-v1\0" + owner.encode("ascii") + b"\0" + purpose.encode("ascii") + b"\0" + value.encode("ascii")
    ).hexdigest()


def _read_private_file(path: Path, maximum: int) -> bytes:
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size > maximum
        or info.st_mode & 0o077
    ):
        raise RemediationPlanJobError("store_invalid")
    return path.read_bytes()


def _durable_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_info = path.parent.lstat()
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise RemediationPlanJobError("store_invalid")
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.tmp-{uuid4().hex}")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise RemediationPlanJobError("store_unavailable") from exc


def _durable_unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RemediationPlanJobError("store_unavailable") from exc
    try:
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise RemediationPlanJobError("store_unavailable") from exc


def hmac_compare(left: str, right: str) -> bool:
    import hmac
    return hmac.compare_digest(left, right)


def build_remediation_plan(
    *,
    store: RemediationPlanJobStore,
    projects,
    remediation_center,
    organization_id: str,
    job_id: str,
) -> RemediationPlanJob:
    """Build one bounded artifact from indexed project pages."""

    try:
        queued = store.get(organization_id, job_id)
        revision = projects.source_revision()
        first_page, total, cursor = projects.page(
            owner_id=organization_id, page_size=100, cursor=None
        )
        if total > REMEDIATION_PLAN_MAX_PROJECTS:
            return store.fail(organization_id, job_id, "safe_limit_reached")
        store.claim(
            organization_id, job_id,
            project_revision=revision,
            total_projects=total,
        )
        decisions_by_project = remediation_center.report_decision_snapshot(
            organization_id=organization_id,
            observed_at=queued.cutoff_at,
        )
        accumulators: dict[str, dict[str, object]] = {}
        processed = 0
        page = first_page
        while True:
            remediation_center.collect_report_projects(
                organization_id=organization_id,
                projects=page,
                observed_at=queued.cutoff_at,
                accumulators=accumulators,
                decisions_by_project=decisions_by_project,
            )
            processed += len(page)
            if (
                processed == total
                or processed % REMEDIATION_PLAN_PROGRESS_CHECKPOINT_PROJECTS == 0
            ):
                store.progress(organization_id, job_id, processed)
            else:
                store.assert_running(organization_id, job_id, processed)
            if cursor is None:
                break
            page, repeated_total, cursor = projects.page(
                owner_id=organization_id, page_size=100, cursor=cursor
            )
            if repeated_total != total:
                raise RuntimeError("remediation_snapshot_changed")
        if processed != total or not hmac_compare(revision, projects.source_revision()):
            raise RuntimeError("remediation_snapshot_changed")
        groups, summary = remediation_center.finalize_report_groups(
            organization_id=organization_id,
            payload=queued.filters,
            observed_at=queued.cutoff_at,
            accumulators=accumulators,
        )
        groups_truncated = len(groups) > REMEDIATION_PLAN_MAX_GROUPS
        groups = groups[:REMEDIATION_PLAN_MAX_GROUPS]
        retained_groups: list[RemediationActionGroup] = []
        remaining_occurrences = REMEDIATION_PLAN_MAX_OCCURRENCES
        occurrences_truncated = False
        for group in groups:
            retained = group.occurrences[:remaining_occurrences]
            if len(retained) < len(group.occurrences) or group.occurrence_count > len(retained):
                occurrences_truncated = True
            retained_groups.append(group.model_copy(update={
                "occurrences": retained,
                "occurrences_truncated": group.occurrence_count > len(retained),
            }))
            remaining_occurrences -= len(retained)
        artifact = RemediationPlanArtifact(
            job_id=job_id,
            organization_id=organization_id,
            cutoff_at=queued.cutoff_at,
            project_revision=revision,
            processed_projects=processed,
            total_projects=total,
            included_groups=len(retained_groups),
            included_occurrences=REMEDIATION_PLAN_MAX_OCCURRENCES - remaining_occurrences,
            groups_truncated=groups_truncated,
            occurrences_truncated=occurrences_truncated,
            summary=summary,
            groups=retained_groups,
            limitations=[
                "This artifact is a point-in-time remediation plan, not proof that a correction was applied.",
                "A finding is resolved only after a new comparable analysis no longer reports it.",
                "Project names and security metadata are included; source paths, content, comments and actor identities are excluded.",
            ],
        )
        return store.complete(organization_id, job_id, artifact)
    except RemediationPlanJobError as exc:
        if exc.code == "cancelled":
            return store.finish_cancel(organization_id, job_id)
        if exc.code in {"artifact_too_large", "safe_limit_reached"}:
            return store.fail(organization_id, job_id, exc.code)
        try:
            return store.fail(organization_id, job_id, "source_unavailable")
        except RemediationPlanJobError:
            raise
    except RuntimeError as exc:
        reason = str(exc)
        mapped = {
            "remediation_snapshot_changed": "portfolio_changed",
            "remediation_source_unavailable": "source_unavailable",
            "remediation_group_limit": "safe_limit_reached",
        }.get(reason, "internal_error")
        return store.fail(organization_id, job_id, mapped)
    except Exception:
        return store.fail(organization_id, job_id, "internal_error")
