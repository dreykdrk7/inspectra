from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import threading
from typing import Any, Callable, Iterator, Literal
from uuid import uuid4

from fastapi import HTTPException, UploadFile, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.active_http_basic_header_review import build_active_http_basic_header_review_persisted_result
from app.active_job_index import (
    JOB_RETENTION_BATCH_SIZE,
    JOB_SOURCE_REFERENCE_BATCH_SIZE,
    JOB_SOURCE_REFERENCE_MAX_REFERENCES,
    ActiveJobIndex,
    ActiveJobIndexError,
    active_job_record_digest,
)
from app.cargo_dependency_graph import CargoDependencyGraphArtifact
from app.composer_dependency_graph import ComposerDependencyGraphArtifact
from app.component_inventory import add_component_inventory, attach_dependency_graph_projection
from app.config import DEFAULT_LOCAL_OPERATOR, Settings
from app.execution_profile import build_execution_profile
from app.file_retention_index import (
    FILE_RETENTION_BATCH_SIZE,
    FileRetentionIndex,
    FileRetentionIndexError,
    file_retention_record_digest,
)
from app.finding_normalization import normalize_result_findings
from app.go_dependency_graph import GoDependencyGraphArtifact
from app.gradle_dependency_graph import GradleDependencyGraphArtifact
from app.nuget_dependency_graph import NugetDependencyGraphArtifact
from app.models import (
    AuditType,
    JobListItem,
    JobRecord,
    JobStatus,
    JobStatusDetail,
    JobTerminationReason,
    ProjectRecord,
    ProjectResponsibilityRevision,
    ProjectSourceChannel,
    ProjectSourceSnapshot,
    StoredProjectSourceChannel,
    StoredFile,
    effective_project_source_channel,
    current_project_responsibility,
    opaque_source_reference,
)
from app.observability import log_audit_event
from app.project_reference_index import (
    PROJECT_LIST_MAX_PAGE_SIZE,
    PROJECT_REFERENCE_QUERY_BATCH_SIZE,
    PROJECT_REFERENCE_QUERY_MAX_REFERENCES,
    ProjectReferenceIndex,
    ProjectReferenceIndexError,
)
from app.reporting import redact_active_secret_text
from app.risk_trend_source_clock import RiskTrendSourceClock
from app.web_security import redact_url_query

try:
    import fcntl
except ImportError:  # pragma: no cover - Linux/Docker path uses fcntl.
    fcntl = None


IDENTIFIER_PATTERN = re.compile(r"^[a-f0-9]{32}$")
PROJECT_ACTOR_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[a-f0-9]{32}$")
PROJECT_SNAPSHOT_ADMISSION_CONTRACT_VERSION = "2026-09-09.1"
PROJECT_SNAPSHOT_ADMISSION_IDENTITY_VERSION = "2026-09-06.1"
RESULT_INTEGRITY_CONTRACT_VERSION = "2026-09-09.1"
UPLOAD_CHUNK_SIZE = 1024 * 1024
IMAGE_SIGNATURES = (
    ("jpeg", ".jpg", "image/jpeg", lambda data: data.startswith(b"\xff\xd8\xff")),
    ("png", ".png", "image/png", lambda data: data.startswith(b"\x89PNG\r\n\x1a\n")),
    ("webp", ".webp", "image/webp", lambda data: len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP"),
)
_FALLBACK_LOCKS: dict[Path, threading.RLock] = {}
_FALLBACK_LOCKS_GUARD = threading.Lock()
_STORAGE_LOCK_STATE = threading.local()
MANIFEST_DEFINITIONS = {
    "package.json": ("package_json", "application/json"),
    "requirements.txt": ("requirements_txt", "text/plain"),
    "pyproject.toml": ("pyproject_toml", "application/toml"),
}
ARCHIVE_DEFINITIONS = (
    (".tar.gz", "tar_gz", ".tar.gz", "application/gzip", lambda data: data.startswith(b"\x1f\x8b")),
    (".tgz", "tar_gz", ".tgz", "application/gzip", lambda data: data.startswith(b"\x1f\x8b")),
    (".zip", "zip", ".zip", "application/zip", lambda data: data.startswith(b"PK")),
    (".tar", "tar", ".tar", "application/x-tar", lambda data: len(data) >= 262 and data[257:262] == b"ustar"),
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def resolve_record_owner_id(settings: Settings, owner_id: str | None) -> str | None:
    if owner_id:
        return owner_id
    if settings.auth_mode == "trusted_local_no_auth":
        return DEFAULT_LOCAL_OPERATOR.id
    return None


def _with_effective_file_owner(settings: Settings, record: StoredFile) -> StoredFile:
    owner_id = resolve_record_owner_id(settings, record.owner_id)
    if owner_id == record.owner_id:
        return record
    return record.model_copy(update={"owner_id": owner_id, "organization_id": owner_id})


def _with_effective_job_owner(settings: Settings, record: JobRecord) -> JobRecord:
    owner_id = resolve_record_owner_id(settings, record.owner_id)
    if owner_id == record.owner_id:
        return record
    return record.model_copy(update={"owner_id": owner_id, "organization_id": owner_id})


def _with_effective_project_owner(settings: Settings, record: ProjectRecord) -> ProjectRecord:
    owner_id = resolve_record_owner_id(settings, record.owner_id)
    if owner_id == record.owner_id:
        return record
    return record.model_copy(update={"owner_id": owner_id, "organization_id": owner_id})


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(f"{path.suffix}.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp_path.chmod(0o600)
    tmp_path.replace(path)


def project_deletion_marker_path(settings: Settings, project_id: str) -> Path:
    """Return the fixed local marker path used to close project admission."""

    _validate_identifier(project_id, "project_id")
    return settings.project_deletions_dir / f"{project_id}.json"


def project_deletion_is_pending(settings: Settings, project_id: str) -> bool:
    path = project_deletion_marker_path(settings, project_id)
    return path.exists() or path.is_symlink()


def active_asset_deletion_marker_path(settings: Settings, asset_id: str) -> Path:
    """Return the fixed local marker used to close every Active admission path."""

    _validate_identifier(asset_id, "asset_id")
    return settings.active_asset_deletions_dir / f"{asset_id}.json"


def active_asset_deletion_is_pending(settings: Settings, asset_id: str) -> bool:
    path = active_asset_deletion_marker_path(settings, asset_id)
    return path.exists() or path.is_symlink()


@contextmanager
def storage_lock(settings: Settings) -> Iterator[None]:
    lock_path = settings.data_dir / ".locks" / "storage.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory_metadata = lock_path.parent.lstat()
    if not stat.S_ISDIR(directory_metadata.st_mode) or lock_path.parent.is_symlink():
        raise OSError("Storage lock directory is invalid.")
    os.chmod(lock_path.parent, 0o700)
    with _fallback_lock(lock_path):
        lock_key = str(lock_path.resolve())
        depths = getattr(_STORAGE_LOCK_STATE, "depths", None)
        if depths is None:
            depths = {}
            _STORAGE_LOCK_STATE.depths = depths
        depth = depths.get(lock_key, 0)
        if depth:
            depths[lock_key] = depth + 1
            try:
                yield
            finally:
                depths[lock_key] -= 1
            return
        flags = os.O_CREAT | os.O_APPEND | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(lock_path, flags, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            os.close(descriptor)
            raise OSError("Storage lock file is invalid.")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "a+", encoding="utf-8") as handle:
            if fcntl is None:
                depths[lock_key] = 1
                try:
                    yield
                finally:
                    depths.pop(lock_key, None)
                return
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            depths[lock_key] = 1
            try:
                yield
            finally:
                depths.pop(lock_key, None)
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def _fallback_lock(lock_path: Path) -> Iterator[None]:
    resolved = lock_path.resolve()
    with _FALLBACK_LOCKS_GUARD:
        lock = _FALLBACK_LOCKS.setdefault(resolved, threading.RLock())
    with lock:
        yield


class FileStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.retention_index = FileRetentionIndex(settings, self._load_metadata_file)

    async def save_pdf(self, upload: UploadFile, *, owner_id: str | None = None) -> StoredFile:
        first_chunk = await upload.read(UPLOAD_CHUNK_SIZE)
        if not first_chunk:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty file.")
        if not first_chunk.startswith(b"%PDF-"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only PDF files are accepted.")

        file_id = uuid4().hex
        stored_filename = f"{file_id}.pdf"
        original_filename = Path(upload.filename or "uploaded.pdf").name
        target_path = self._safe_upload_path(stored_filename)
        sha256 = hashlib.sha256()
        size_bytes = 0

        try:
            with target_path.open("wb") as target:
                async for chunk in _iter_initial_and_remaining_chunks(first_chunk, upload):
                    size_bytes += len(chunk)
                    if size_bytes > self.settings.max_upload_bytes:
                        raise HTTPException(
                            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                            detail=f"File too large. Maximum allowed size is {self.settings.max_upload_bytes} bytes.",
                        )
                    sha256.update(chunk)
                    target.write(chunk)
        except Exception:
            target_path.unlink(missing_ok=True)
            raise

        record = StoredFile(
            id=file_id,
            owner_id=owner_id,
            kind="pdf",
            original_filename=original_filename,
            stored_filename=stored_filename,
            content_type=upload.content_type or "application/pdf",
            size_bytes=size_bytes,
            sha256=sha256.hexdigest(),
            created_at=utc_now(),
        )
        self._save_record(record)
        return record

    async def save_image(self, upload: UploadFile, *, owner_id: str | None = None) -> StoredFile:
        first_chunk = await upload.read(UPLOAD_CHUNK_SIZE)
        if not first_chunk:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty file.")
        detected = _detect_image_type(first_chunk)
        if detected is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only JPEG, PNG, and WebP images are accepted.")

        _, extension, content_type = detected
        file_id = uuid4().hex
        stored_filename = f"{file_id}{extension}"
        original_filename = Path(upload.filename or f"uploaded{extension}").name
        target_path = self._safe_upload_path(stored_filename)
        sha256 = hashlib.sha256()
        size_bytes = 0

        try:
            with target_path.open("wb") as target:
                async for chunk in _iter_initial_and_remaining_chunks(first_chunk, upload):
                    size_bytes += len(chunk)
                    if size_bytes > self.settings.max_upload_bytes:
                        raise HTTPException(
                            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                            detail=f"File too large. Maximum allowed size is {self.settings.max_upload_bytes} bytes.",
                        )
                    sha256.update(chunk)
                    target.write(chunk)
        except Exception:
            target_path.unlink(missing_ok=True)
            raise

        record = StoredFile(
            id=file_id,
            owner_id=owner_id,
            kind="image",
            original_filename=original_filename,
            stored_filename=stored_filename,
            content_type=content_type,
            size_bytes=size_bytes,
            sha256=sha256.hexdigest(),
            created_at=utc_now(),
        )
        self._save_record(record)
        return record

    async def save_manifest(self, upload: UploadFile, *, owner_id: str | None = None) -> StoredFile:
        original_filename = Path(upload.filename or "").name
        payload = await _read_limited_upload(upload, self.settings.max_upload_bytes)
        manifest_type, content_type = _validate_manifest_upload(original_filename, payload)

        file_id = uuid4().hex
        stored_filename = f"{file_id}-{original_filename.lower()}"
        target_path = self._safe_upload_path(stored_filename)
        target_path.write_bytes(payload)

        record = StoredFile(
            id=file_id,
            owner_id=owner_id,
            kind="manifest",
            original_filename=original_filename,
            stored_filename=stored_filename,
            content_type=content_type,
            size_bytes=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            created_at=utc_now(),
        )
        self._save_record(record)
        return record

    def save_normalized_sbom(self, payload: bytes, *, owner_id: str | None = None) -> StoredFile:
        """Persist only the normalized SBOM projection, never the source document."""

        if not payload or len(payload) > self.settings.max_upload_bytes:
            raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="Normalized SBOM exceeds the upload limit.")
        file_id = uuid4().hex
        stored_filename = f"{file_id}-sbom.json"
        self._safe_upload_path(stored_filename).write_bytes(payload)
        record = StoredFile(
            id=file_id,
            owner_id=owner_id,
            kind="manifest",
            original_filename="sbom.json",
            stored_filename=stored_filename,
            content_type="application/json",
            size_bytes=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            created_at=utc_now(),
        )
        self._save_record(record)
        return record

    def read_normalized_sbom(self, file_id: str, *, owner_id: str | None = None) -> dict[str, Any]:
        """Read only an internally normalized SBOM after checking its identity."""

        with storage_lock(self.settings):
            record = self._get_unlocked(file_id)
            if owner_id is not None and record.owner_id != owner_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")
            if (
                record.kind != "manifest"
                or record.original_filename != "sbom.json"
                or record.stored_filename != f"{record.id}-sbom.json"
            ):
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Project source is not a normalized SBOM.")
            payload = self._safe_upload_path(record.stored_filename).read_bytes()
        if len(payload) != record.size_bytes or hashlib.sha256(payload).hexdigest() != record.sha256:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Normalized SBOM integrity check failed.")
        try:
            normalized = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Normalized SBOM is invalid.") from exc
        if not isinstance(normalized, dict):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Normalized SBOM is invalid.")
        return normalized

    async def save_archive(self, upload: UploadFile, *, owner_id: str | None = None) -> StoredFile:
        original_filename = Path(upload.filename or "").name
        payload = await _read_limited_upload(upload, self.settings.max_upload_bytes)
        _, extension, content_type = _validate_archive_upload(original_filename, payload)

        file_id = uuid4().hex
        stored_filename = f"{file_id}{extension}"
        target_path = self._safe_upload_path(stored_filename)
        target_path.write_bytes(payload)

        record = StoredFile(
            id=file_id,
            owner_id=owner_id,
            kind="archive",
            original_filename=original_filename,
            stored_filename=stored_filename,
            content_type=content_type,
            size_bytes=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            created_at=utc_now(),
        )
        self._save_record(record)
        return record

    def list(self, *, owner_id: str | None = None) -> list[StoredFile]:
        records = [
            self._load_metadata_file(path)
            for path in self.settings.upload_dir.glob("*.json")
            if IDENTIFIER_PATTERN.fullmatch(path.stem)
        ]
        if owner_id is not None:
            records = [record for record in records if record.owner_id == owner_id]
        return sorted(records, key=lambda item: item.created_at, reverse=True)

    def get(self, file_id: str) -> StoredFile:
        return self._get_unlocked(file_id)

    def delete(self, file_id: str, *, owner_id: str | None = None) -> StoredFile:
        with storage_lock(self.settings):
            record = self._get_unlocked(file_id)
            if owner_id is not None and record.owner_id != owner_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")
            upload_path = self._safe_upload_path(record.stored_filename)
            metadata_path = self._metadata_path(file_id)
            upload_path.unlink(missing_ok=True)
            metadata_path.unlink(missing_ok=True)
            self.retention_index.sync_after_delete(record.id)
            log_audit_event(
                "file.deleted",
                correlation_id=f"file:{record.id}",
                file_id=record.id,
                owner_id=record.owner_id,
                kind=record.kind,
            )
            return record

    def purge_expired(
        self,
        cutoff: datetime,
        *,
        protected_file_ids: set[str],
        owner_id: str | None = None,
        before_delete: Callable[[StoredFile], None] | None = None,
        is_protected: Callable[[str], bool] | None = None,
    ) -> list[StoredFile]:
        deleted: list[StoredFile] = []
        excluded_file_ids = set(protected_file_ids)
        while True:
            with storage_lock(self.settings):
                try:
                    candidates = self.retention_index.expired_records(
                        cutoff=cutoff,
                        protected_file_ids=excluded_file_ids,
                        owner_id=owner_id,
                        limit=FILE_RETENTION_BATCH_SIZE,
                    )
                except FileRetentionIndexError as exc:
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Source retention state is temporarily unavailable.",
                    ) from exc
            if not candidates:
                break
            for candidate in candidates:
                # The final protection check, derived-record callback and source
                # deletion share one lock. Retention callbacks must therefore
                # use the lock-owned helpers supplied by JobStore/ProjectStore.
                with storage_lock(self.settings):
                    metadata_path = self._metadata_path(candidate.id)
                    if not metadata_path.exists():
                        continue
                    record = self._load_metadata_file(metadata_path)
                    if (
                        file_retention_record_digest(record)
                        != file_retention_record_digest(candidate)
                        or (owner_id is not None and record.owner_id != owner_id)
                        or record.id in excluded_file_ids
                        or record.created_at > cutoff
                        or record.stored_filename != candidate.stored_filename
                    ):
                        continue
                    if is_protected is not None and is_protected(record.id):
                        excluded_file_ids.add(record.id)
                        continue
                    if before_delete is not None:
                        before_delete(record)
                    post_callback = self._load_metadata_file(metadata_path)
                    if (
                        file_retention_record_digest(post_callback)
                        != file_retention_record_digest(record)
                    ):
                        continue
                    record = post_callback
                    self._safe_upload_path(record.stored_filename).unlink(missing_ok=True)
                    metadata_path.unlink(missing_ok=True)
                    self.retention_index.sync_after_delete(record.id)
                    deleted.append(record)
        return deleted

    def relative_upload_path(self, record: StoredFile) -> str:
        return f"uploads/{record.stored_filename}"

    def source_path(self, record: StoredFile) -> Path:
        """Resolve one stored source without exposing the host path to callers."""

        return self._safe_upload_path(record.stored_filename)

    def _metadata_path(self, file_id: str) -> Path:
        _validate_identifier(file_id, "file_id")
        return self.settings.upload_dir / f"{file_id}.json"

    def _save_record(self, record: StoredFile) -> None:
        with storage_lock(self.settings):
            _atomic_write_json(self._metadata_path(record.id), record.model_dump(mode="json"))
            self.retention_index.sync_after_save(record)
        log_audit_event(
            "file.persisted",
            correlation_id=f"file:{record.id}",
            file_id=record.id,
            owner_id=record.owner_id,
            kind=record.kind,
        )

    def _get_unlocked(self, file_id: str) -> StoredFile:
        path = self._metadata_path(file_id)
        if not path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")
        try:
            record = StoredFile.model_validate_json(path.read_text(encoding="utf-8"))
            return _with_effective_file_owner(self.settings, record)
        except (ValidationError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Stored file metadata is invalid.") from exc

    def _safe_upload_path(self, stored_filename: str) -> Path:
        candidate = (self.settings.upload_dir / stored_filename).resolve()
        upload_root = self.settings.upload_dir.resolve()
        if candidate != upload_root and upload_root not in candidate.parents:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Stored file path is invalid.")
        return candidate

    def _load_metadata_file(self, path: Path) -> StoredFile:
        try:
            record = StoredFile.model_validate_json(path.read_text(encoding="utf-8"))
            return _with_effective_file_owner(self.settings, record)
        except (ValidationError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Stored file metadata is invalid: {path.name}") from exc


class ExecutionWorkspaceError(RuntimeError):
    """Controlled workspace failure whose message must never reach public output."""


class ExecutionWorkspaceStore:
    """Create bounded, per-job source copies and remove them deterministically.

    The runner receives only ``<job id>/source.archive`` relative to the
    configured workspace root. Owner, project, original filename and host path
    are never encoded in the runner path or workspace name.
    """

    def __init__(self, settings: Settings, files: FileStore) -> None:
        self.settings = settings
        self.files = files

    def validate_recovery_source(self, job: JobRecord, stored_file: StoredFile) -> None:
        """Verify a queued source before startup dispatch without exposing it."""

        _validate_identifier(job.id, "job_id")
        if (
            job.audit_type != "project_archive_basic"
            or job.project_id is None
            or job.file_id != stored_file.id
            or job.owner_id != stored_file.owner_id
            or job.source_sha256 != stored_file.sha256
            or stored_file.kind != "archive"
            or stored_file.size_bytes > self.settings.execution_workspace_max_bytes
        ):
            raise ExecutionWorkspaceError("recovery source binding mismatch")
        try:
            digest = hashlib.sha256()
            observed_size = 0
            with self.files.source_path(stored_file).open("rb") as source:
                while chunk := source.read(UPLOAD_CHUNK_SIZE):
                    observed_size += len(chunk)
                    if observed_size > self.settings.execution_workspace_max_bytes:
                        raise ExecutionWorkspaceError("recovery source byte limit exceeded")
                    digest.update(chunk)
            if observed_size != stored_file.size_bytes or digest.hexdigest() != stored_file.sha256:
                raise ExecutionWorkspaceError("recovery source integrity mismatch")
        except Exception as exc:
            if isinstance(exc, ExecutionWorkspaceError):
                raise
            raise ExecutionWorkspaceError("recovery source unavailable") from exc

    def prepare(self, job: JobRecord, stored_file: StoredFile) -> str:
        _validate_identifier(job.id, "job_id")
        if job.file_id != stored_file.id or job.owner_id != stored_file.owner_id:
            raise ExecutionWorkspaceError("workspace ownership mismatch")
        if stored_file.size_bytes > self.settings.execution_workspace_max_bytes:
            raise ExecutionWorkspaceError("workspace byte limit exceeded")

        workspace = self._workspace_path(job.id)
        source_target = workspace / "source.archive"
        self.cleanup(job.id)
        try:
            workspace.mkdir(mode=0o700)
            digest = hashlib.sha256()
            copied = 0
            with self.files.source_path(stored_file).open("rb") as source, source_target.open("xb") as target:
                while chunk := source.read(UPLOAD_CHUNK_SIZE):
                    copied += len(chunk)
                    if copied > self.settings.execution_workspace_max_bytes:
                        raise ExecutionWorkspaceError("workspace byte limit exceeded")
                    digest.update(chunk)
                    target.write(chunk)
            source_target.chmod(0o400)
            if copied != stored_file.size_bytes or digest.hexdigest() != stored_file.sha256:
                raise ExecutionWorkspaceError("workspace source integrity mismatch")
        except Exception as exc:
            self.cleanup(job.id)
            if isinstance(exc, ExecutionWorkspaceError):
                raise
            raise ExecutionWorkspaceError("workspace preparation failed") from exc
        log_audit_event(
            "job.workspace.prepared",
            correlation_id=f"job:{job.id}",
            job_id=job.id,
            project_id=job.project_id,
            owner_id=job.owner_id,
            size_bytes=copied,
        )
        return f"workspaces/{job.id}/source.archive"

    def cleanup(self, job_id: str) -> bool:
        workspace = self._workspace_path(job_id)
        existed = workspace.exists() or workspace.is_symlink()
        if workspace.is_symlink() or workspace.is_file():
            workspace.unlink(missing_ok=True)
        elif workspace.exists():
            shutil.rmtree(workspace)
        if existed:
            log_audit_event(
                "job.workspace.cleaned",
                correlation_id=f"job:{job_id}",
                job_id=job_id,
            )
        return existed

    def cleanup_orphans(self) -> int:
        cleaned = 0
        for path in self.settings.execution_workspaces_dir.iterdir():
            if IDENTIFIER_PATTERN.fullmatch(path.name) and self.cleanup(path.name):
                cleaned += 1
        log_audit_event("job.workspace.orphans_cleaned", cleaned_count=cleaned)
        return cleaned

    def has_orphans(self, *, active_job_ids: set[str]) -> bool:
        """Report unexpected opaque workspaces without returning their names."""

        return any(
            IDENTIFIER_PATTERN.fullmatch(path.name) and path.name not in active_job_ids
            for path in self.settings.execution_workspaces_dir.iterdir()
        )

    def _workspace_path(self, job_id: str) -> Path:
        _validate_identifier(job_id, "job_id")
        root = self.settings.execution_workspaces_dir.resolve()
        candidate = (root / job_id).resolve()
        if candidate.parent != root:
            raise ExecutionWorkspaceError("workspace identifier is invalid")
        return candidate


class JobStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.active_index = ActiveJobIndex(settings, self._load_job_file)
        self.risk_trend_source_clock = RiskTrendSourceClock(settings)

    def create_pdf_job(self, file_id: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(file_id, "pdf_basic", owner_id=owner_id)

    def create_image_job(self, file_id: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(file_id, "image_basic", owner_id=owner_id)

    def create_manifest_job(self, file_id: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(file_id, "manifest_basic", owner_id=owner_id)

    def create_archive_job(self, file_id: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(file_id, "archive_basic", owner_id=owner_id)

    def create_project_archive_job(
        self,
        file_id: str,
        *,
        owner_id: str | None = None,
        project_id: str | None = None,
        source_sha256: str | None = None,
        retry_of_job_id: str | None = None,
    ) -> JobRecord:
        return self._create_job(
            file_id,
            "project_archive_basic",
            owner_id=owner_id,
            project_id=project_id,
            source_sha256=source_sha256,
            analysis_profile="project_archive_basic",
            retry_of_job_id=retry_of_job_id,
        )

    def create_sbom_import_job(
        self,
        file_id: str,
        *,
        owner_id: str | None = None,
        project_id: str | None = None,
        source_sha256: str | None = None,
        retry_of_job_id: str | None = None,
        revision_key_sha256: str | None = None,
    ) -> JobRecord:
        """Create an offline SBOM job with a comparison-incompatible profile."""

        return self._create_job(
            file_id,
            "project_archive_basic",
            owner_id=owner_id,
            project_id=project_id,
            source_sha256=source_sha256,
            analysis_profile="sbom_import",
            retry_of_job_id=retry_of_job_id,
            sbom_revision_key_sha256=revision_key_sha256,
        )

    def create_django_config_job(self, file_id: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(file_id, "django_config_basic", owner_id=owner_id)

    def create_docker_config_job(self, file_id: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(file_id, "docker_config_basic", owner_id=owner_id)

    def create_secrets_review_job(self, file_id: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(file_id, "secrets_review_basic", owner_id=owner_id)

    def create_node_package_config_job(self, file_id: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(file_id, "node_package_config_basic", owner_id=owner_id)

    def create_ci_cd_config_job(self, file_id: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(file_id, "ci_cd_config_basic", owner_id=owner_id)

    def create_k8s_config_job(self, file_id: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(file_id, "k8s_config_basic", owner_id=owner_id)

    def create_terraform_config_job(self, file_id: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(file_id, "terraform_config_basic", owner_id=owner_id)

    def create_nginx_config_job(self, file_id: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(file_id, "nginx_config_basic", owner_id=owner_id)

    def create_compose_config_job(self, file_id: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(file_id, "compose_config_basic", owner_id=owner_id)

    def create_database_config_job(self, file_id: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(file_id, "database_config_basic", owner_id=owner_id)

    def create_sql_database_config_job(self, file_id: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(file_id, "sql_database_config_basic", owner_id=owner_id)

    def create_redis_config_job(self, file_id: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(file_id, "redis_config_basic", owner_id=owner_id)

    def create_web_job(self, target_url: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(None, "web_basic", target_url=target_url, owner_id=owner_id)

    def create_domain_job(self, target_domain: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(None, "domain_basic", target_domain=target_domain, owner_id=owner_id)

    def create_subdomain_inventory_job(self, target_domain: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(None, "subdomain_inventory_basic", target_domain=target_domain, owner_id=owner_id)

    def create_active_network_dry_run_job(self, target_display: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(None, "active_network_dry_run", target_url=target_display, owner_id=owner_id)

    def create_active_http_header_probe_job(self, target_display: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(None, "active_http_header_probe", target_url=target_display, owner_id=owner_id)

    def create_active_http_basic_header_review_job(
        self,
        result: dict,
        *,
        status: JobStatus,
        error: str | None = None,
        owner_id: str | None = None,
        active_asset_id: str | None = None,
        active_authorization_contract: str | None = None,
        active_authorization_revision_id: str | None = None,
        active_authorization_revision_digest_sha256: str | None = None,
        active_authorization_revision_sequence: int | None = None,
    ) -> JobRecord:
        now = utc_now()
        persisted_result = build_active_http_basic_header_review_persisted_result(result)
        record = JobRecord(
            id=uuid4().hex,
            owner_id=owner_id,
            active_asset_id=active_asset_id,
            active_authorization_contract=active_authorization_contract,
            active_authorization_revision_id=active_authorization_revision_id,
            active_authorization_revision_digest_sha256=active_authorization_revision_digest_sha256,
            active_authorization_revision_sequence=active_authorization_revision_sequence,
            audit_type="active_http_basic_header_review",
            file_id=None,
            target_url="[REDACTED_TARGET]",
            target_domain=None,
            status=status,
            created_at=now,
            updated_at=now,
            result=persisted_result,
            error=error,
        )
        with storage_lock(self.settings):
            return self._save_unlocked(record)

    def create_active_nmap_basic_job(self, target_display: str, *, owner_id: str | None = None) -> JobRecord:
        return self._create_job(None, "active_nmap_basic", target_url=target_display, owner_id=owner_id)

    def create_active_nmap_basic_no_live_job(
        self,
        result: dict,
        *,
        status: JobStatus,
        error: str | None = None,
        owner_id: str | None = None,
        active_asset_id: str | None = None,
        active_authorization_contract: str | None = None,
        active_authorization_revision_id: str | None = None,
        active_authorization_revision_digest_sha256: str | None = None,
        active_authorization_revision_sequence: int | None = None,
    ) -> JobRecord:
        now = utc_now()
        record = JobRecord(
            id=uuid4().hex,
            owner_id=owner_id,
            active_asset_id=active_asset_id,
            active_authorization_contract=active_authorization_contract,
            active_authorization_revision_id=active_authorization_revision_id,
            active_authorization_revision_digest_sha256=active_authorization_revision_digest_sha256,
            active_authorization_revision_sequence=active_authorization_revision_sequence,
            audit_type="active_nmap_basic",
            file_id=None,
            target_url="[REDACTED_TARGET]",
            target_domain=None,
            status=status,
            created_at=now,
            updated_at=now,
            result=result,
            error=error,
        )
        with storage_lock(self.settings):
            return self._save_unlocked(record)

    def create_active_tls_basic_job(
        self,
        result: dict,
        *,
        status: JobStatus,
        error: str | None = None,
        owner_id: str | None = None,
        active_asset_id: str | None = None,
        active_authorization_contract: str | None = None,
        active_authorization_revision_id: str | None = None,
        active_authorization_revision_digest_sha256: str | None = None,
        active_authorization_revision_sequence: int | None = None,
    ) -> JobRecord:
        now = utc_now()
        record = JobRecord(
            id=uuid4().hex,
            owner_id=owner_id,
            active_asset_id=active_asset_id,
            active_authorization_contract=active_authorization_contract,
            active_authorization_revision_id=active_authorization_revision_id,
            active_authorization_revision_digest_sha256=active_authorization_revision_digest_sha256,
            active_authorization_revision_sequence=active_authorization_revision_sequence,
            audit_type="active_tls_basic",
            file_id=None,
            target_url="[REDACTED_TARGET]",
            target_domain=None,
            status=status,
            created_at=now,
            updated_at=now,
            result=result,
            error=error,
        )
        with storage_lock(self.settings):
            return self._save_unlocked(record)

    def create_active_dns_inventory_job(
        self,
        result: dict,
        *,
        status: JobStatus,
        error: str | None = None,
        owner_id: str | None = None,
        active_asset_id: str | None = None,
        active_authorization_contract: str | None = None,
        active_authorization_revision_id: str | None = None,
        active_authorization_revision_digest_sha256: str | None = None,
        active_authorization_revision_sequence: int | None = None,
    ) -> JobRecord:
        now = utc_now()
        record = JobRecord(
            id=uuid4().hex,
            owner_id=owner_id,
            active_asset_id=active_asset_id,
            active_authorization_contract=active_authorization_contract,
            active_authorization_revision_id=active_authorization_revision_id,
            active_authorization_revision_digest_sha256=active_authorization_revision_digest_sha256,
            active_authorization_revision_sequence=active_authorization_revision_sequence,
            audit_type="active_dns_inventory",
            file_id=None,
            target_url="[REDACTED_DOMAIN]",
            target_domain=None,
            status=status,
            created_at=now,
            updated_at=now,
            result=result,
            error=error,
        )
        with storage_lock(self.settings):
            return self._save_unlocked(record)

    def create_active_dns_osint_job(
        self,
        result: dict,
        *,
        status: JobStatus,
        error: str | None = None,
        owner_id: str | None = None,
        active_asset_id: str | None = None,
        active_authorization_contract: str | None = None,
        active_authorization_revision_id: str | None = None,
        active_authorization_revision_digest_sha256: str | None = None,
        active_authorization_revision_sequence: int | None = None,
    ) -> JobRecord:
        now = utc_now()
        record = JobRecord(
            id=uuid4().hex,
            owner_id=owner_id,
            active_asset_id=active_asset_id,
            active_authorization_contract=active_authorization_contract,
            active_authorization_revision_id=active_authorization_revision_id,
            active_authorization_revision_digest_sha256=active_authorization_revision_digest_sha256,
            active_authorization_revision_sequence=active_authorization_revision_sequence,
            audit_type="active_dns_osint",
            file_id=None,
            target_url="[REDACTED_DOMAIN]",
            target_domain=None,
            status=status,
            created_at=now,
            updated_at=now,
            result=result,
            error=error,
        )
        with storage_lock(self.settings):
            return self._save_unlocked(record)

    def create_active_asset_execution_job(
        self,
        audit_type: str,
        *,
        owner_id: str,
        active_asset_id: str,
        active_authorization_contract: str,
        active_authorization_revision_id: str,
        active_authorization_revision_digest_sha256: str,
        active_authorization_revision_sequence: int,
        active_execution_port: int | None,
        idempotency_key_sha256: str,
        retry_of_job_id: str | None = None,
    ) -> tuple[JobRecord, bool]:
        """Atomically admit or replay one source-free Active execution."""

        if not re.fullmatch(r"[a-f0-9]{64}", idempotency_key_sha256):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Active execution key is invalid.")
        now = utc_now()
        target_display = "[REDACTED_DOMAIN]" if audit_type in {"active_dns_inventory", "active_dns_osint"} else "[REDACTED_TARGET]"
        record = JobRecord(
            id=uuid4().hex,
            owner_id=owner_id,
            active_asset_id=active_asset_id,
            active_authorization_contract=active_authorization_contract,
            active_authorization_revision_id=active_authorization_revision_id,
            active_authorization_revision_digest_sha256=active_authorization_revision_digest_sha256,
            active_authorization_revision_sequence=active_authorization_revision_sequence,
            active_execution_port=active_execution_port,
            active_execution_phase="admitted",
            active_execution_idempotency_key_sha256=idempotency_key_sha256,
            audit_type=audit_type,
            execution_profile=build_execution_profile(self.settings, audit_type=audit_type, analysis_profile=None),
            file_id=None,
            target_url=target_display,
            target_domain=None,
            status="queued",
            created_at=now,
            updated_at=now,
            retry_of_job_id=retry_of_job_id,
        )
        with storage_lock(self.settings):
            try:
                existing = self.active_index.idempotent_record(
                    owner_id=owner_id,
                    idempotency_key_sha256=idempotency_key_sha256,
                )
            except ActiveJobIndexError as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Active execution admission is temporarily unavailable.",
                ) from exc
            if existing is not None:
                same_request = (
                    existing.active_asset_id == active_asset_id
                    and existing.audit_type == audit_type
                    and existing.active_authorization_revision_id == active_authorization_revision_id
                    and existing.active_authorization_revision_digest_sha256 == active_authorization_revision_digest_sha256
                    and existing.active_execution_port == active_execution_port
                    and existing.retry_of_job_id == retry_of_job_id
                )
                if not same_request:
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Active execution key was already used for different work.")
                return existing, True
            if active_asset_deletion_is_pending(self.settings, active_asset_id):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Active asset deletion is in progress. No new execution can be admitted.",
                )
            self._assert_admission_available_unlocked(owner_id)
            self._assert_active_admission_available_unlocked(
                owner_id=owner_id,
                active_asset_id=active_asset_id,
                audit_type=audit_type,
            )
            return self._save_unlocked(record), False

    def _create_job(
        self,
        file_id: str | None,
        audit_type: str,
        *,
        target_url: str | None = None,
        target_domain: str | None = None,
        owner_id: str | None = None,
        project_id: str | None = None,
        source_sha256: str | None = None,
        analysis_profile: str | None = None,
        retry_of_job_id: str | None = None,
        sbom_revision_key_sha256: str | None = None,
    ) -> JobRecord:
        now = utc_now()
        record = JobRecord(
            id=uuid4().hex,
            owner_id=owner_id,
            project_id=project_id,
            source_sha256=source_sha256,
            analysis_profile=analysis_profile,
            audit_type=audit_type,
            file_id=file_id,
            target_url=target_url,
            target_domain=target_domain,
            status="queued",
            created_at=now,
            updated_at=now,
            retry_of_job_id=retry_of_job_id,
            sbom_revision_key_sha256=sbom_revision_key_sha256,
        )
        with storage_lock(self.settings):
            if project_id is not None and project_deletion_is_pending(self.settings, project_id):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Project deletion is in progress. No new analysis can be admitted.",
                )
            self._assert_admission_available_unlocked(owner_id)
            return self._save_unlocked(record)

    def assert_admission_available(self, *, owner_id: str | None) -> None:
        """Check persisted in-flight work without exposing capacity counts."""

        with storage_lock(self.settings):
            self._assert_admission_available_unlocked(owner_id)

    def _assert_admission_available_unlocked(self, owner_id: str | None) -> None:
        effective_owner_id = resolve_record_owner_id(self.settings, owner_id)
        if effective_owner_id is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Analysis capacity is temporarily unavailable.",
            )
        try:
            global_count, owner_count = self.active_index.admission_counts(
                owner_id=effective_owner_id
            )
        except ActiveJobIndexError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Analysis capacity is temporarily unavailable.",
            ) from exc
        scope: str | None = None
        if global_count >= self.settings.audit_max_inflight_jobs:
            scope = "global"
        elif owner_count >= self.settings.audit_max_inflight_jobs_per_owner:
            scope = "owner"
        if scope is None:
            return
        log_audit_event(
            "job.admission.rejected",
            correlation_id="job-admission",
            owner_id=effective_owner_id,
            scope=scope,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Analysis capacity is temporarily full. Wait for an active analysis to finish, then retry.",
            headers={"Retry-After": "5"},
        )

    def active_admission_available(self, *, owner_id: str) -> bool:
        """Return only whether this organization may add Active work.

        Asset and capability limits still require an atomic check at creation;
        no count or competing tenant state crosses this read boundary.
        """

        with storage_lock(self.settings):
            try:
                global_count, owner_count, _asset_count, _capability_count = (
                    self.active_index.active_capacity_counts(
                        owner_id=owner_id,
                        active_asset_id="0" * 32,
                        audit_type="active_capacity_probe",
                    )
                )
            except ActiveJobIndexError:
                return False
            return (
                global_count < self.settings.active_max_inflight_jobs
                and owner_count < self.settings.active_max_inflight_jobs_per_organization
            )

    def _active_inflight_jobs_unlocked(self) -> list[JobRecord]:
        return [
            record
            for record in self._inflight_records_unlocked()
            if record.active_asset_id is not None
        ]

    def _assert_active_admission_available_unlocked(
        self,
        *,
        owner_id: str,
        active_asset_id: str,
        audit_type: str,
    ) -> None:
        try:
            global_count, owner_count, asset_count, capability_count = (
                self.active_index.active_capacity_counts(
                    owner_id=owner_id,
                    active_asset_id=active_asset_id,
                    audit_type=audit_type,
                )
            )
        except ActiveJobIndexError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Active execution admission is temporarily unavailable.",
            ) from exc
        saturated_scope: str | None = None
        if global_count >= self.settings.active_max_inflight_jobs:
            saturated_scope = "active_global"
        elif owner_count >= self.settings.active_max_inflight_jobs_per_organization:
            saturated_scope = "active_organization"
        elif asset_count >= self.settings.active_max_inflight_jobs_per_asset:
            saturated_scope = "active_asset"
        elif capability_count >= self.settings.active_max_inflight_jobs_per_capability:
            saturated_scope = "active_capability"
        if saturated_scope is None:
            return
        log_audit_event(
            "active_execution.admission.rejected",
            correlation_id="active-admission",
            owner_id=owner_id,
            scope=saturated_scope,
            capability=audit_type,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Active execution capacity is temporarily full. Wait for bounded work to finish, then retry.",
            headers={"Retry-After": "5"},
        )

    def get(self, job_id: str) -> JobRecord:
        return self._get_unlocked(job_id)

    def get_list_item(self, job_id: str) -> JobListItem:
        return self._to_list_item(self._get_unlocked(job_id))

    def update(
        self,
        job_id: str,
        *,
        status: JobStatus,
        result: dict | None = None,
        error: str | None = None,
        termination_reason: JobTerminationReason | None = None,
        active_execution_phase: Literal["admitted", "waiting_for_runner", "executing", "normalizing", "terminal"] | None = None,
    ) -> JobRecord:
        with storage_lock(self.settings):
            record = self._get_unlocked(job_id)
            if record.status == "cancelled" and status != "cancelled":
                return record
            now = utc_now()
            update: dict[str, Any] = {"status": status, "updated_at": now, "result": result, "error": error}
            if active_execution_phase is not None:
                update["active_execution_phase"] = active_execution_phase
            if status == "running":
                update["started_at"] = record.started_at or now
            if status in {"completed", "failed", "cancelled"}:
                update["finished_at"] = now
                update["termination_reason"] = termination_reason or (
                    "completed" if status == "completed" else "cancelled_by_owner" if status == "cancelled" else "runner_unavailable"
                )
            updated = record.model_copy(update=update)
            return self._save_unlocked(updated)

    def attach_go_dependency_graph(
        self,
        job_id: str,
        *,
        owner_id: str,
        project_id: str,
        artifact: GoDependencyGraphArtifact,
        artifact_sha256: str,
    ) -> JobRecord:
        """Atomically enrich one completed result without retaining raw graph JSON."""

        with storage_lock(self.settings):
            record, replay = self._dependency_graph_attachment_record_unlocked(
                job_id, owner_id=owner_id, project_id=project_id,
                evidence_key="dependency_graph_evidence", ecosystem="go",
                artifact_sha256=artifact_sha256,
                conflict_detail="This analysis is already bound to different dependency evidence.",
            )
            if replay:
                return record
            enriched = record.model_copy(update={"updated_at": utc_now()})
            return self._save_unlocked(
                enriched,
                go_dependency_graph=artifact,
                go_dependency_graph_sha256=artifact_sha256,
            )

    def attach_cargo_dependency_graph(
        self,
        job_id: str,
        *,
        owner_id: str,
        project_id: str,
        artifact: CargoDependencyGraphArtifact,
        artifact_sha256: str,
    ) -> JobRecord:
        """Atomically enrich one completed result without retaining raw Cargo data."""

        with storage_lock(self.settings):
            record, replay = self._dependency_graph_attachment_record_unlocked(
                job_id, owner_id=owner_id, project_id=project_id,
                evidence_key="cargo_dependency_graph_evidence", ecosystem="cargo",
                artifact_sha256=artifact_sha256,
                conflict_detail="This analysis is already bound to different Cargo dependency evidence.",
            )
            if replay:
                return record
            enriched = record.model_copy(update={"updated_at": utc_now()})
            return self._save_unlocked(
                enriched,
                cargo_dependency_graph=artifact,
                cargo_dependency_graph_sha256=artifact_sha256,
            )

    def attach_composer_dependency_graph(
        self, job_id: str, *, owner_id: str, project_id: str,
        artifact: ComposerDependencyGraphArtifact, artifact_sha256: str,
    ) -> JobRecord:
        """Atomically attach corroborated Composer relationships only."""

        with storage_lock(self.settings):
            record, replay = self._dependency_graph_attachment_record_unlocked(
                job_id, owner_id=owner_id, project_id=project_id,
                evidence_key="composer_dependency_graph_evidence", ecosystem="composer",
                artifact_sha256=artifact_sha256,
                conflict_detail="This analysis is already bound to different Composer dependency evidence.",
            )
            if replay:
                return record
            return self._save_unlocked(
                record.model_copy(update={"updated_at": utc_now()}),
                composer_dependency_graph=artifact,
                composer_dependency_graph_sha256=artifact_sha256,
            )

    def attach_gradle_dependency_graph(
        self, job_id: str, *, owner_id: str, project_id: str,
        artifact: GradleDependencyGraphArtifact, artifact_sha256: str,
    ) -> JobRecord:
        """Atomically attach CI-reported Gradle relationships only."""

        with storage_lock(self.settings):
            record, replay = self._dependency_graph_attachment_record_unlocked(
                job_id, owner_id=owner_id, project_id=project_id,
                evidence_key="gradle_dependency_graph_evidence", ecosystem="maven",
                artifact_sha256=artifact_sha256,
                conflict_detail="This analysis is already bound to different Gradle dependency evidence.",
            )
            if replay:
                return record
            return self._save_unlocked(
                record.model_copy(update={"updated_at": utc_now()}),
                gradle_dependency_graph=artifact,
                gradle_dependency_graph_sha256=artifact_sha256,
            )

    def attach_nuget_dependency_graph(
        self, job_id: str, *, owner_id: str, project_id: str,
        artifact: NugetDependencyGraphArtifact, artifact_sha256: str,
    ) -> JobRecord:
        """Atomically attach CI-reported NuGet target relationships only."""

        with storage_lock(self.settings):
            record, replay = self._dependency_graph_attachment_record_unlocked(
                job_id, owner_id=owner_id, project_id=project_id,
                evidence_key="nuget_dependency_graph_evidence", ecosystem="nuget",
                artifact_sha256=artifact_sha256,
                conflict_detail="This analysis is already bound to different NuGet dependency evidence.",
            )
            if replay:
                return record
            return self._save_unlocked(
                record.model_copy(update={"updated_at": utc_now()}),
                nuget_dependency_graph=artifact,
                nuget_dependency_graph_sha256=artifact_sha256,
            )

    def _dependency_graph_attachment_record_unlocked(
        self,
        job_id: str,
        *,
        owner_id: str,
        project_id: str,
        evidence_key: str,
        ecosystem: str,
        artifact_sha256: str,
        conflict_detail: str,
    ) -> tuple[JobRecord, bool]:
        """Apply the common tenant, lifecycle and immutable-replay boundary under the store lock."""

        record = self._get_unlocked(job_id)
        if record.owner_id != owner_id or record.project_id != project_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found for this project.")
        if record.status != "completed" or not isinstance(record.result, dict):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Dependency evidence requires a completed project analysis.",
            )
        existing = record.result.get(evidence_key)
        if isinstance(existing, dict):
            if existing.get("ecosystem") == ecosystem and existing.get("artifact_sha256") == artifact_sha256:
                return record, True
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=conflict_detail)
        return record, False

    def request_cancellation(self, job_id: str, *, owner_id: str) -> JobRecord:
        """Record an owner-scoped, idempotent request before signalling work."""

        with storage_lock(self.settings):
            record = self._get_unlocked(job_id)
            if record.owner_id != owner_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found.")
            if record.status in {"cancelling", "cancelled"}:
                return record
            if record.status not in {"queued", "running"}:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only a queued or running analysis can be cancelled.")
            now = utc_now()
            return self._save_unlocked(
                record.model_copy(
                    update={
                        "status": "cancelling",
                        "updated_at": now,
                        "cancellation_requested_at": now,
                        "result": None,
                        "error": None,
                    }
                )
            )

    def request_active_authorization_revocation(
        self,
        job_id: str,
        *,
        owner_id: str,
        active_asset_id: str,
    ) -> JobRecord:
        """Stop admitted Active work when its immutable authorization is revoked."""

        with storage_lock(self.settings):
            record = self._get_unlocked(job_id)
            if record.owner_id != owner_id or record.active_asset_id != active_asset_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active execution not found.")
            if record.status in {"completed", "failed", "cancelled"}:
                return record
            now = utc_now()
            if record.status == "queued":
                return self._save_unlocked(
                    record.model_copy(
                        update={
                            "status": "cancelled",
                            "updated_at": now,
                            "finished_at": now,
                            "active_execution_phase": "terminal",
                            "termination_reason": "authorization_revoked",
                            "result": None,
                            "error": "Active execution cancelled after authorization was revoked. Partial observations were discarded.",
                        }
                    )
                )
            return self._save_unlocked(
                record.model_copy(
                    update={
                        "status": "cancelling",
                        "updated_at": now,
                        "termination_reason": "authorization_revoked",
                        "result": None,
                        "error": None,
                    }
                )
            )

    def claim_queued_active_execution(self, job_id: str) -> JobRecord | None:
        """Atomically move one Active job from queued to running.

        The persisted compare-and-set is the cross-worker execution guard.  A
        second worker observing any other state must not contact a runner.
        """

        with storage_lock(self.settings):
            record = self._get_unlocked(job_id)
            if record.active_asset_id is None or record.status != "queued":
                return None
            now = utc_now()
            return self._save_unlocked(
                record.model_copy(
                    update={
                        "status": "running",
                        "active_execution_phase": "waiting_for_runner",
                        "started_at": record.started_at or now,
                        "updated_at": now,
                        "result": None,
                        "error": None,
                    }
                )
            )

    def mark_cancelled(self, job_id: str) -> JobRecord:
        return self.update(
            job_id,
            status="cancelled",
            result=None,
            error="Analysis cancelled by its owner. The execution workspace was removed.",
            termination_reason="cancelled_by_owner",
        )

    def recover_interrupted_jobs(
        self,
        *,
        preserve_queued_project_jobs: bool = False,
        preserve_queued_active_jobs: bool = False,
        termination_reason: JobTerminationReason = "application_restart",
        public_error: str = "Audit interrupted by application restart. Run it again.",
    ) -> list[JobRecord]:
        """Close work that cannot be resumed after a process lifecycle event.

        Only a never-started project analysis can be preserved for the durable
        startup dispatcher. Running/cancelling work and non-project background
        jobs cannot be resumed honestly, so partial results are discarded.
        """
        interrupted: list[JobRecord] = []
        recovered_at = utc_now()
        with storage_lock(self.settings):
            for record in self._inflight_records_unlocked():
                if (
                    preserve_queued_project_jobs
                    and record.status == "queued"
                    and record.audit_type == "project_archive_basic"
                    and record.project_id is not None
                ):
                    continue
                if preserve_queued_active_jobs and record.status == "queued" and record.active_asset_id is not None:
                    continue
                updated = record.model_copy(
                    update={
                        "status": "failed",
                        "updated_at": recovered_at,
                        "result": None,
                        "error": public_error,
                        "finished_at": recovered_at,
                        "termination_reason": termination_reason,
                        **({"active_execution_phase": "terminal"} if record.active_asset_id is not None else {}),
                    }
                )
                interrupted.append(self._save_unlocked(updated))
        for record in interrupted:
            log_audit_event(
                (
                    "job.interrupted_during_shutdown"
                    if termination_reason == "application_shutdown"
                    else "job.interrupted_after_restart"
                ),
                correlation_id=f"job:{record.id}",
                job_id=record.id,
                owner_id=record.owner_id,
                audit_type=record.audit_type,
                termination_reason=termination_reason,
            )
        return interrupted

    def list_queued_project_jobs(self) -> list[JobRecord]:
        """Return only persisted project analyses eligible for startup review."""

        with storage_lock(self.settings):
            return [
                record
                for record in self._inflight_records_unlocked()
                if record.status == "queued"
                and record.audit_type == "project_archive_basic"
                and record.project_id is not None
            ]

    def list_queued_active_jobs(self) -> list[JobRecord]:
        """Return source-free Active work that still requires admission revalidation."""

        with storage_lock(self.settings):
            return [
                record
                for record in self._inflight_records_unlocked()
                if record.status == "queued" and record.active_asset_id is not None
            ]

    def record_restart_requeue(self, job_id: str) -> JobRecord:
        """Persist one startup requeue without changing the admitted contract."""

        with storage_lock(self.settings):
            record = self._get_unlocked(job_id)
            project_recovery = record.audit_type == "project_archive_basic" and record.project_id is not None
            active_recovery = record.active_asset_id is not None
            if record.status != "queued" or not (project_recovery or active_recovery):
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Job is not eligible for restart recovery.")
            now = utc_now()
            return self._save_unlocked(
                record.model_copy(
                    update={
                        "updated_at": now,
                        "recovery_count": record.recovery_count + 1,
                        "last_recovered_at": now,
                    }
                )
            )

    def list(self, *, owner_id: str | None = None) -> list[JobListItem]:
        records = [self._load_job_file(path) for path in self.settings.jobs_dir.glob("*.json")]
        if owner_id is not None:
            records = [record for record in records if record.owner_id == owner_id]
        records.sort(key=lambda item: item.created_at, reverse=True)
        return [self._to_list_item(record) for record in records]

    def page(
        self,
        *,
        owner_id: str,
        page_size: int = 50,
        cursor: str | None = None,
        status_filter: JobStatus | None = None,
        audit_type: AuditType | None = None,
        project_id: str | None = None,
        active_asset_id: str | None = None,
    ) -> tuple[list[JobListItem], int, str | None]:
        """Return a bounded, index-backed history page or fail closed."""

        with storage_lock(self.settings):
            try:
                records, total, next_cursor = self.active_index.page(
                    owner_id=owner_id,
                    page_size=page_size,
                    cursor=cursor,
                    status=status_filter,
                    audit_type=audit_type,
                    project_id=project_id,
                    active_asset_id=active_asset_id,
                )
            except ActiveJobIndexError as exc:
                if str(exc) == "invalid_cursor":
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Job history cursor is invalid. Restart from the first page.",
                    ) from exc
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Job history is temporarily unavailable.",
                ) from exc
        return [self._to_list_item(record) for record in records], total, next_cursor

    def active_operations_snapshot(
        self, *, owner_id: str, asset_ids: set[str], limit: int = 2_000
    ) -> tuple[list[JobRecord], int]:
        """Return exact Active count plus only bounded owner/asset candidates."""

        with storage_lock(self.settings):
            try:
                return self.active_index.snapshot(
                    owner_id=owner_id, asset_ids=asset_ids, limit=limit
                )
            except ActiveJobIndexError as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Active operations index is temporarily unavailable.",
                ) from exc

    def active_asset_history(
        self, *, owner_id: str, asset_id: str, limit: int = 500
    ) -> list[JobRecord]:
        """Return only a bounded, validated history for one Active asset."""

        with storage_lock(self.settings):
            try:
                records, _total = self.active_index.snapshot(
                    owner_id=owner_id, asset_ids={asset_id}, limit=limit
                )
                return records
            except ActiveJobIndexError as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Active operations index is temporarily unavailable.",
                ) from exc

    def active_asset_records_for_deletion_unlocked(
        self, *, owner_id: str, asset_id: str
    ) -> list[JobRecord]:
        """Return an exhaustive asset aggregate while the caller owns the lock."""

        try:
            return self.active_index.records_for_active_asset(
                owner_id=owner_id, active_asset_id=asset_id
            )
        except ActiveJobIndexError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Active execution history is temporarily unavailable.",
            ) from exc

    def active_asset_complete_history(
        self, *, owner_id: str, asset_id: str
    ) -> list[JobRecord]:
        """Return the exhaustive validated aggregate for an explicit export."""

        with storage_lock(self.settings):
            try:
                return self.active_index.records_for_active_asset(
                    owner_id=owner_id, active_asset_id=asset_id
                )
            except ActiveJobIndexError as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Active execution history is temporarily unavailable.",
                ) from exc

    def active_asset_inflight_history(
        self, *, owner_id: str, asset_id: str
    ) -> list[JobRecord]:
        """Return all validated lifecycle work for one asset."""

        with storage_lock(self.settings):
            try:
                return self.active_index.inflight_records_for_active_asset(
                    owner_id=owner_id, active_asset_id=asset_id
                )
            except ActiveJobIndexError as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Active execution state is temporarily unavailable.",
                ) from exc

    def active_job_index_ready(self) -> bool:
        with storage_lock(self.settings):
            return self.active_index.ready()

    def active_attention_asset_ids(self, *, owner_id: str) -> tuple[set[str], set[str]]:
        with storage_lock(self.settings):
            try:
                return self.active_index.attention_asset_ids(owner_id=owner_id)
            except ActiveJobIndexError as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Active operations index is temporarily unavailable.",
                ) from exc

    def list_for_project(self, project_id: str, *, owner_id: str | None = None) -> list[JobListItem]:
        _validate_identifier(project_id, "project_id")
        records = []
        for path in self.settings.jobs_dir.glob("*.json"):
            record = self._load_job_file(path)
            if record.project_id == project_id:
                records.append(record)
        if owner_id is not None:
            records = [record for record in records if record.owner_id == owner_id]
        records.sort(key=lambda item: item.created_at, reverse=True)
        return [self._to_list_item(record) for record in records]

    def latest_completed_project_job(
        self, project_id: str, *, owner_id: str
    ) -> JobRecord | None:
        """Resolve the newest completed project job with one authoritative read."""

        _validate_identifier(project_id, "project_id")
        with storage_lock(self.settings):
            try:
                return self.active_index.latest_project_record(
                    owner_id=owner_id, project_id=project_id, status="completed"
                )
            except ActiveJobIndexError as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Analysis history is temporarily unavailable.",
                ) from exc

    def has_active_project_job(self, project_id: str, *, owner_id: str | None = None) -> bool:
        _validate_identifier(project_id, "project_id")
        if owner_id is not None:
            with storage_lock(self.settings):
                return self._has_active_project_job_unlocked(project_id, owner_id=owner_id)
        for path in self.settings.jobs_dir.glob("*.json"):
            record = self._load_job_file(path)
            if record.project_id != project_id or record.status not in {"queued", "running", "cancelling"}:
                continue
            if owner_id is None or record.owner_id == owner_id:
                return True
        return False

    def _has_active_project_job_unlocked(self, project_id: str, *, owner_id: str) -> bool:
        """Check project admission while the caller owns ``storage_lock``."""

        _validate_identifier(project_id, "project_id")
        try:
            return self.active_index.has_inflight_project(
                owner_id=owner_id, project_id=project_id
            )
        except ActiveJobIndexError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Analysis admission is temporarily unavailable.",
            ) from exc

    def has_global_admission_capacity(self) -> bool:
        """Return only aggregate admission state for readiness checks."""

        with storage_lock(self.settings):
            try:
                in_flight = self.active_index.global_inflight_count()
            except ActiveJobIndexError as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Analysis admission is temporarily unavailable.",
                ) from exc
        return in_flight < self.settings.audit_max_inflight_jobs

    def active_project_job_ids(self) -> set[str]:
        with storage_lock(self.settings):
            try:
                return self.active_index.inflight_project_job_ids()
            except ActiveJobIndexError as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Analysis recovery state is temporarily unavailable.",
                ) from exc

    def active_file_ids(self) -> set[str]:
        """Return source IDs referenced by validated in-flight jobs only."""

        with storage_lock(self.settings):
            return {
                record.file_id
                for record in self._inflight_records_unlocked()
                if record.file_id is not None
            }

    def _inflight_records_unlocked(self) -> list[JobRecord]:
        """Resolve recovery candidates while the caller owns ``storage_lock``."""

        try:
            return self.active_index.inflight_records()
        except ActiveJobIndexError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Analysis recovery state is temporarily unavailable.",
            ) from exc

    def purge_expired_terminal(
        self,
        cutoff: datetime,
        *,
        owner_id: str | None = None,
        before_delete: Callable[[JobRecord], None] | None = None,
        batch_size: int = JOB_RETENTION_BATCH_SIZE,
    ) -> list[JobRecord]:
        deleted: list[JobRecord] = []
        while True:
            with storage_lock(self.settings):
                try:
                    candidates = self.active_index.expired_terminal_records(
                        cutoff=cutoff,
                        owner_id=owner_id,
                        limit=batch_size,
                    )
                except ActiveJobIndexError as exc:
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Analysis retention state is temporarily unavailable.",
                    ) from exc
            if not candidates:
                break
            for candidate in candidates:
                # The index selection loaded and validated authoritative JSON
                # while holding the storage lock. Derived evidence is removed
                # without that lock so callbacks may update project baselines.
                # A failure leaves the job indexed and available for retry.
                if before_delete is not None:
                    before_delete(candidate)
                with storage_lock(self.settings):
                    path = self._job_path(candidate.id)
                    if not path.exists():
                        continue
                    record = self._load_job_file(path)
                    if (
                        active_job_record_digest(record) != active_job_record_digest(candidate)
                        or (owner_id is not None and record.owner_id != owner_id)
                        or record.status not in {"completed", "failed", "cancelled"}
                        or record.updated_at > cutoff
                    ):
                        continue
                    source_revision = self.risk_trend_source_clock.raw_source_revision()
                    path.unlink(missing_ok=True)
                    self.active_index.sync_after_delete(record)
                    effective_owner = resolve_record_owner_id(self.settings, record.owner_id)
                    if record.project_id is not None and effective_owner is not None:
                        self.risk_trend_source_clock.record_mutation(
                            effective_owner,
                            previous_source_revision=source_revision,
                        )
                    deleted.append(record)
        return deleted

    def mark_file_deleted(self, file_id: str, *, owner_id: str | None = None) -> int:
        return self.mark_files_deleted({file_id}, owner_id=owner_id)

    def mark_files_deleted(self, file_ids: set[str], *, owner_id: str | None = None) -> int:
        if not file_ids:
            return 0
        for file_id in file_ids:
            _validate_identifier(file_id, "file_id")
        with storage_lock(self.settings):
            return self._mark_files_deleted_unlocked(file_ids, owner_id=owner_id)

    def _mark_files_deleted_unlocked(
        self, file_ids: set[str], *, owner_id: str | None = None
    ) -> int:
        deleted_at = utc_now()
        marked = 0
        ordered_ids = sorted(file_ids)
        for offset in range(0, len(ordered_ids), JOB_SOURCE_REFERENCE_MAX_REFERENCES):
            source_batch = set(
                ordered_ids[offset : offset + JOB_SOURCE_REFERENCE_MAX_REFERENCES]
            )
            while True:
                try:
                    candidates = self.active_index.records_for_source_references(
                        file_ids=source_batch,
                        owner_id=owner_id,
                        limit=JOB_SOURCE_REFERENCE_BATCH_SIZE,
                    )
                except ActiveJobIndexError as exc:
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Analysis source state is temporarily unavailable.",
                    ) from exc
                if not candidates:
                    break
                for record in candidates:
                    updated = record.model_copy(
                        update={
                            "source_file_deleted_at": deleted_at,
                            "updated_at": deleted_at,
                        }
                    )
                    self._save_unlocked(updated)
                    marked += 1
        return marked

    def _source_file_is_active_unlocked(self, file_id: str) -> bool:
        _validate_identifier(file_id, "file_id")
        try:
            return self.active_index.inflight_source_reference_exists(file_id=file_id)
        except ActiveJobIndexError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Analysis source state is temporarily unavailable.",
            ) from exc

    def delete(self, job_id: str, *, owner_id: str | None = None) -> JobRecord:
        with storage_lock(self.settings):
            record = self._get_unlocked(job_id)
            if owner_id is not None and record.owner_id != owner_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found.")
            if record.status not in {"completed", "failed", "cancelled"}:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Job deletion is only available for completed, failed, or cancelled jobs.",
                )
            source_revision = self.risk_trend_source_clock.raw_source_revision()
            self._job_path(job_id).unlink(missing_ok=True)
            self.active_index.sync_after_delete(record)
            effective_owner = resolve_record_owner_id(self.settings, record.owner_id)
            if record.project_id is not None and effective_owner is not None:
                self.risk_trend_source_clock.record_mutation(
                    effective_owner,
                    previous_source_revision=source_revision,
                )
            log_audit_event(
                "job.deleted",
                correlation_id=f"job:{record.id}",
                job_id=record.id,
                owner_id=record.owner_id,
                audit_type=record.audit_type,
                status=record.status,
            )
            return record

    def save(self, record: JobRecord) -> None:
        with storage_lock(self.settings):
            self._save_unlocked(record)

    def _job_path(self, job_id: str) -> Path:
        _validate_identifier(job_id, "job_id")
        return self.settings.jobs_dir / f"{job_id}.json"

    def _get_unlocked(self, job_id: str) -> JobRecord:
        path = self._job_path(job_id)
        if not path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found.")
        return self._load_job_file(path)

    def _save_unlocked(
        self,
        record: JobRecord,
        *,
        go_dependency_graph: GoDependencyGraphArtifact | None = None,
        go_dependency_graph_sha256: str | None = None,
        cargo_dependency_graph: CargoDependencyGraphArtifact | None = None,
        cargo_dependency_graph_sha256: str | None = None,
        composer_dependency_graph: ComposerDependencyGraphArtifact | None = None,
        composer_dependency_graph_sha256: str | None = None,
        gradle_dependency_graph: GradleDependencyGraphArtifact | None = None,
        gradle_dependency_graph_sha256: str | None = None,
        nuget_dependency_graph: NugetDependencyGraphArtifact | None = None,
        nuget_dependency_graph_sha256: str | None = None,
    ) -> JobRecord:
        path = self._job_path(record.id)
        is_new_record = not path.exists()
        if is_new_record and record.execution_profile is None:
            record = record.model_copy(
                update={
                    "execution_profile": build_execution_profile(
                        self.settings,
                        audit_type=record.audit_type,
                        analysis_profile=record.analysis_profile,
                    )
                }
            )
        sanitized_record = sanitize_job_record_for_storage(
            record,
            go_dependency_graph=go_dependency_graph,
            go_dependency_graph_sha256=go_dependency_graph_sha256,
            cargo_dependency_graph=cargo_dependency_graph,
            cargo_dependency_graph_sha256=cargo_dependency_graph_sha256,
            composer_dependency_graph=composer_dependency_graph,
            composer_dependency_graph_sha256=composer_dependency_graph_sha256,
            gradle_dependency_graph=gradle_dependency_graph,
            gradle_dependency_graph_sha256=gradle_dependency_graph_sha256,
            nuget_dependency_graph=nuget_dependency_graph,
            nuget_dependency_graph_sha256=nuget_dependency_graph_sha256,
        )
        persisted_record = self._merge_existing_record(path, sanitized_record)
        integrity = _result_integrity_envelope(persisted_record)
        persisted_record = persisted_record.model_copy(
            update={"result_integrity_status": "valid" if integrity is not None else "unknown"}
        )
        payload = persisted_record.model_dump(mode="json")
        if integrity is not None:
            payload["_result_integrity"] = integrity
        effective_owner = resolve_record_owner_id(self.settings, persisted_record.owner_id)
        source_revision = (
            self.risk_trend_source_clock.raw_source_revision()
            if persisted_record.project_id is not None and effective_owner is not None
            else None
        )
        _atomic_write_json(path, payload)
        self.active_index.sync_after_save(persisted_record)
        if source_revision is not None and effective_owner is not None:
            self.risk_trend_source_clock.record_mutation(
                effective_owner,
                previous_source_revision=source_revision,
            )
        log_audit_event(
            "job.persisted",
            correlation_id=f"job:{persisted_record.id}",
            job_id=persisted_record.id,
            owner_id=persisted_record.owner_id,
            audit_type=persisted_record.audit_type,
            status=persisted_record.status,
        )
        return persisted_record

    def _merge_existing_record(self, path: Path, record: JobRecord) -> JobRecord:
        if not path.exists():
            return record
        existing = self._load_job_file(path)
        update: dict = {}
        if record.source_file_deleted_at is None and existing.source_file_deleted_at is not None:
            update["source_file_deleted_at"] = existing.source_file_deleted_at
        if record.owner_id is None and existing.owner_id is not None:
            update["owner_id"] = existing.owner_id
        if record.execution_profile != existing.execution_profile:
            # A profile describes the point at which the job was admitted. A
            # retry, terminal update, or later caller cannot retroactively
            # replace it; legacy records intentionally stay unprofiled.
            update["execution_profile"] = existing.execution_profile
        for field_name in (
            "active_asset_id",
            "active_authorization_contract",
            "active_authorization_revision_id",
            "active_authorization_revision_digest_sha256",
            "active_authorization_revision_sequence",
            "active_execution_port",
            "active_execution_idempotency_key_sha256",
        ):
            if getattr(record, field_name) != getattr(existing, field_name):
                # Authorization evidence belongs to the admission event.  A
                # terminal update, retry or caller must never rewrite it.
                update[field_name] = getattr(existing, field_name)
        if update:
            return record.model_copy(update=update)
        return record

    def _load_job_file(self, path: Path) -> JobRecord:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("job_not_object")
            integrity = payload.pop("_result_integrity", None)
            if integrity is not None and not _result_integrity_payload_matches(payload, integrity):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Stored result integrity check failed.",
                )
            record = JobRecord.model_validate(payload)
            if integrity is None:
                record = record.model_copy(update={"result_integrity_status": "unknown"})
            else:
                record = record.model_copy(update={"result_integrity_status": "valid"})
            return _with_effective_job_owner(self.settings, record)
        except HTTPException:
            raise
        except (ValidationError, ValueError) as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Stored job metadata is invalid.") from exc

    def _to_list_item(self, record: JobRecord) -> JobListItem:
        target_url = record.target_url
        if record.audit_type in {"active_network_dry_run", "active_http_header_probe"} and target_url:
            target_url = _redact_active_summary_text(target_url)
        if record.audit_type in {"active_http_basic_header_review", "active_nmap_basic", "active_tls_basic"} and target_url:
            target_url = "[REDACTED_TARGET]"
        if record.audit_type in {"active_dns_inventory", "active_dns_osint"} and target_url:
            target_url = "[REDACTED_DOMAIN]"
        return JobListItem(
            id=record.id,
            owner_id=record.owner_id,
            project_id=record.project_id,
            active_asset_id=record.active_asset_id,
            active_authorization_contract=record.active_authorization_contract,
            active_authorization_revision_id=record.active_authorization_revision_id,
            active_authorization_revision_digest_sha256=record.active_authorization_revision_digest_sha256,
            active_authorization_revision_sequence=record.active_authorization_revision_sequence,
            active_execution_port=record.active_execution_port,
            active_execution_phase=record.active_execution_phase,
            source_reference=opaque_source_reference(record.file_id) if record.project_id else None,
            analysis_profile=record.analysis_profile,
            execution_profile=record.execution_profile,
            audit_type=record.audit_type,
            file_id=None if record.project_id is not None else record.file_id,
            target_url=target_url,
            target_domain=record.target_domain,
            status=record.status,
            created_at=record.created_at,
            updated_at=record.updated_at,
            started_at=record.started_at,
            finished_at=record.finished_at,
            cancellation_requested_at=record.cancellation_requested_at,
            termination_reason=record.termination_reason,
            retry_of_job_id=record.retry_of_job_id,
            recovery_count=record.recovery_count,
            last_recovered_at=record.last_recovered_at,
            source_file_deleted_at=record.source_file_deleted_at,
            result_integrity_status=record.result_integrity_status,
            summary=_job_summary(record),
            status_detail=_job_status_detail(record),
        )


class ProjectStore:
    """Owner-scoped metadata for archive-backed projects.

    Source bytes remain in FileStore. This store intentionally keeps only a
    display name and immutable source metadata, never a host path, repository
    URL, or credential.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.reference_index = ProjectReferenceIndex(settings, self._load_project_file)
        self.risk_trend_source_clock = RiskTrendSourceClock(settings)

    def create(
        self,
        *,
        name: str,
        source: StoredFile,
        owner_id: str | None = None,
        source_channel: Literal["archive_upload", "sbom"] = "archive_upload",
    ) -> ProjectRecord:
        if (source_channel == "archive_upload" and source.kind != "archive") or (
            source_channel == "sbom" and (source.kind != "manifest" or source.original_filename != "sbom.json")
        ):
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Project source channel is invalid.")
        now = utc_now()
        snapshot = ProjectSourceSnapshot(
            id=uuid4().hex,
            source_file_id=source.id,
            source_filename=source.original_filename,
            source_sha256=source.sha256,
            source_channel=source_channel,
            created_at=now,
        )
        record = ProjectRecord(
            id=uuid4().hex,
            owner_id=owner_id,
            name=name,
            source_file_id=source.id,
            source_filename=source.original_filename,
            source_sha256=source.sha256,
            source_snapshots=[snapshot],
            created_at=now,
            updated_at=now,
        )
        with storage_lock(self.settings):
            return self._save_unlocked(record)

    def append_source_snapshot(self, project_id: str, source: StoredFile) -> tuple[ProjectRecord, ProjectSourceSnapshot]:
        """Move the current source pointer only by appending immutable metadata."""

        now = utc_now()
        with storage_lock(self.settings):
            record = self._get_unlocked(project_id)
            if any(snapshot.source_sha256 == source.sha256 for snapshot in record.source_snapshots):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="This archive snapshot is already retained for the project. Run that snapshot again instead.",
                )
            snapshot = ProjectSourceSnapshot(
                id=uuid4().hex,
                source_file_id=source.id,
                source_filename=source.original_filename,
                source_sha256=source.sha256,
                source_channel="archive_upload",
                created_at=now,
            )
            updated = record.model_copy(
                update={
                    "source_file_id": source.id,
                    "source_filename": source.original_filename,
                    "source_sha256": source.sha256,
                    "source_file_deleted_at": None,
                    "source_snapshots": [*record.source_snapshots, snapshot],
                    "updated_at": now,
                }
            )
            return self._save_unlocked(updated), snapshot

    def attach_sbom_revision(
        self,
        project_id: str,
        *,
        source: StoredFile,
        job: JobRecord,
    ) -> tuple[ProjectRecord, ProjectSourceSnapshot]:
        """Atomically advance an SBOM project only after its completed job exists."""

        with storage_lock(self.settings):
            record = self._get_unlocked(project_id)
            if record.owner_id != source.owner_id or record.owner_id != job.owner_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
            if record.source_filename != "sbom.json" or source.kind != "manifest" or source.original_filename != "sbom.json":
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only an SBOM project accepts SBOM revisions.")
            if (
                job.project_id != record.id
                or job.file_id != source.id
                or job.source_sha256 != source.sha256
                or job.analysis_profile != "sbom_import"
                or job.status != "completed"
                or job.sbom_revision_key_sha256 is None
            ):
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="SBOM revision state is invalid.")
            if len(record.source_snapshots) >= self.settings.project_max_source_snapshots:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Project snapshot limit reached.")
            for path in self.settings.jobs_dir.glob("*.json"):
                if not IDENTIFIER_PATTERN.fullmatch(path.stem) or path.stem == job.id:
                    continue
                candidate = JobRecord.model_validate_json(path.read_text(encoding="utf-8"))
                if candidate.project_id != record.id or candidate.sbom_revision_key_sha256 != job.sbom_revision_key_sha256:
                    continue
                if candidate.source_sha256 != source.sha256:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Idempotency key is already bound to a different SBOM revision.",
                    )
            if any(snapshot.source_sha256 == source.sha256 for snapshot in record.source_snapshots):
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This SBOM revision is already retained.")
            now = utc_now()
            snapshot = ProjectSourceSnapshot(
                id=uuid4().hex,
                source_file_id=source.id,
                source_filename=source.original_filename,
                source_sha256=source.sha256,
                source_channel="sbom",
                created_at=now,
            )
            updated = record.model_copy(
                update={
                    "source_file_id": source.id,
                    "source_filename": source.original_filename,
                    "source_sha256": source.sha256,
                    "source_file_deleted_at": None,
                    "latest_job_id": job.id,
                    "analysis_count": record.analysis_count + 1,
                    "source_snapshots": [*record.source_snapshots, snapshot],
                    "updated_at": now,
                }
            )
            return self._save_unlocked(updated), snapshot

    def get(self, project_id: str) -> ProjectRecord:
        return self._get_unlocked(project_id)

    def list(self, *, owner_id: str | None = None) -> list[ProjectRecord]:
        if owner_id is None:
            records = [self._load_project_file(path) for path in self.settings.projects_dir.glob("*.json")]
            records = [record for record in records if not project_deletion_is_pending(self.settings, record.id)]
            return sorted(records, key=lambda item: item.updated_at, reverse=True)
        records: list[ProjectRecord] = []
        cursor: str | None = None
        with storage_lock(self.settings):
            while True:
                page, _total, cursor = self._page_unlocked(
                    owner_id=owner_id,
                    page_size=PROJECT_LIST_MAX_PAGE_SIZE,
                    cursor=cursor,
                )
                records.extend(page)
                if cursor is None:
                    return records

    def page(
        self,
        *,
        owner_id: str,
        page_size: int = 50,
        cursor: str | None = None,
    ) -> tuple[list[ProjectRecord], int, str | None]:
        """Return one bounded project page without scanning the metadata directory."""

        with storage_lock(self.settings):
            return self._page_unlocked(
                owner_id=owner_id, page_size=page_size, cursor=cursor
            )

    def bounded_owner_snapshot(
        self, *, owner_id: str, limit: int
    ) -> list[ProjectRecord]:
        """Load at most ``limit + 1`` records for a bounded aggregate preflight."""

        if not 1 <= limit <= 100_000:
            raise ValueError("Project snapshot limit is invalid.")
        records: list[ProjectRecord] = []
        cursor: str | None = None
        with storage_lock(self.settings):
            while len(records) <= limit:
                remaining = limit + 1 - len(records)
                page, _total, cursor = self._page_unlocked(
                    owner_id=owner_id,
                    page_size=min(PROJECT_LIST_MAX_PAGE_SIZE, remaining),
                    cursor=cursor,
                )
                records.extend(page)
                if cursor is None or not page:
                    break
        return records

    def source_revision(self) -> str:
        """Return an opaque project-index revision for long-running snapshots."""

        with storage_lock(self.settings):
            try:
                return self.reference_index.source_revision()
            except ProjectReferenceIndexError as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Project list is temporarily unavailable.",
                ) from exc

    def _page_unlocked(
        self, *, owner_id: str, page_size: int, cursor: str | None
    ) -> tuple[list[ProjectRecord], int, str | None]:
        try:
            records, total, next_cursor = self.reference_index.page(
                owner_id=owner_id, page_size=page_size, cursor=cursor
            )
        except ProjectReferenceIndexError as exc:
            if str(exc) == "invalid_cursor":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Project list cursor is invalid. Restart from the first page.",
                ) from exc
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Project list is temporarily unavailable.",
            ) from exc
        if any(project_deletion_is_pending(self.settings, record.id) for record in records):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Project list is temporarily unavailable.",
            )
        return records, total, next_cursor

    def attach_job(self, project_id: str, job_id: str) -> ProjectRecord:
        _validate_identifier(job_id, "job_id")
        with storage_lock(self.settings):
            record = self._get_unlocked(project_id)
            updated = record.model_copy(
                update={
                    "latest_job_id": job_id,
                    "analysis_count": record.analysis_count + 1,
                    "updated_at": utc_now(),
                }
            )
            return self._save_unlocked(updated)

    def set_responsibility(
        self,
        project_id: str,
        *,
        responsible_user_id: str | None,
        actor_id: str,
        expected_updated_at: datetime,
    ) -> tuple[ProjectRecord, bool]:
        """Version one accountable owner without mixing it with finding triage."""

        if not PROJECT_ACTOR_PATTERN.fullmatch(actor_id) or (
            responsible_user_id is not None
            and not PROJECT_ACTOR_PATTERN.fullmatch(responsible_user_id)
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Project responsibility is invalid.",
            )
        if expected_updated_at.tzinfo is None or expected_updated_at.utcoffset() is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Project responsibility timestamp is invalid.",
            )
        with storage_lock(self.settings):
            record = self._get_unlocked(project_id)
            if record.updated_at != expected_updated_at.astimezone(timezone.utc):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Project changed. Refresh before assigning responsibility.",
                )
            current = current_project_responsibility(record)
            desired_state = "assigned" if responsible_user_id is not None else "manually_unassigned"
            if (
                current.responsible_user_id == responsible_user_id
                and current.state
                == ("assigned" if responsible_user_id is not None else "unassigned")
            ):
                return record, False
            if len(record.responsibility_revisions) >= 100:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Project responsibility history reached its safe limit.",
                )
            changed_at = utc_now()
            revision = ProjectResponsibilityRevision(
                sequence=len(record.responsibility_revisions) + 1,
                responsible_user_id=responsible_user_id,
                state=desired_state,
                changed_by_user_id=actor_id,
                changed_at=changed_at,
            )
            updated = record.model_copy(
                update={
                    "responsibility_revisions": [
                        *record.responsibility_revisions,
                        revision,
                    ],
                    "updated_at": changed_at,
                }
            )
            return self._save_unlocked(updated), True

    def responsibility_impact(self, user_id: str, *, owner_id: str) -> int:
        """Count current project assignments without listing project metadata."""

        try:
            return self.reference_index.responsible_count(
                user_id=user_id, owner_id=owner_id
            )
        except ProjectReferenceIndexError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Project responsibility impact is temporarily unavailable.",
            ) from exc

    def unassign_member(
        self,
        user_id: str,
        *,
        owner_id: str,
        actor_id: str,
    ) -> int:
        """Clear every current assignment after membership revocation is prepared."""

        if not PROJECT_ACTOR_PATTERN.fullmatch(actor_id):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Project responsibility reconciliation is unavailable.",
            )
        affected = 0
        with storage_lock(self.settings):
            while True:
                try:
                    records = self.reference_index.records_for_responsible(
                        user_id=user_id,
                        owner_id=owner_id,
                        limit=PROJECT_REFERENCE_QUERY_BATCH_SIZE,
                    )
                except ProjectReferenceIndexError as exc:
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Project responsibility reconciliation is unavailable.",
                    ) from exc
                if not records:
                    return affected
                if any(len(record.responsibility_revisions) >= 100 for record in records):
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Project responsibility history reached its safe limit.",
                    )
                changed_at = utc_now()
                for record in records:
                    revision = ProjectResponsibilityRevision(
                        sequence=len(record.responsibility_revisions) + 1,
                        responsible_user_id=None,
                        state="membership_revoked",
                        changed_by_user_id=actor_id,
                        changed_at=changed_at,
                    )
                    self._save_unlocked(
                        record.model_copy(
                            update={
                                "responsibility_revisions": [
                                    *record.responsibility_revisions,
                                    revision,
                                ],
                                "updated_at": changed_at,
                            }
                        )
                    )
                    affected += 1

    def set_baseline(self, project_id: str, analysis_id: str) -> ProjectRecord:
        """Persist a new explicit baseline without altering the selected result."""

        _validate_identifier(analysis_id, "analysis_id")
        with storage_lock(self.settings):
            record = self._get_unlocked(project_id)
            if record.baseline_analysis_id == analysis_id:
                return record
            changed_at = utc_now()
            updated = record.model_copy(
                update={
                    "baseline_analysis_id": analysis_id,
                    "baseline_version": record.baseline_version + 1,
                    "baseline_updated_at": changed_at,
                    "updated_at": changed_at,
                }
            )
            return self._save_unlocked(updated)

    def clear_baseline(self, project_id: str) -> ProjectRecord:
        """Clear an explicit baseline while preserving a monotonic policy version."""

        with storage_lock(self.settings):
            record = self._get_unlocked(project_id)
            if record.baseline_analysis_id is None:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This project has no saved baseline to clear.")
            changed_at = utc_now()
            updated = record.model_copy(
                update={
                    "baseline_analysis_id": None,
                    "baseline_version": record.baseline_version + 1,
                    "baseline_updated_at": changed_at,
                    "updated_at": changed_at,
                }
            )
            return self._save_unlocked(updated)

    def clear_baselines_for_analysis_ids(
        self, analysis_ids: set[str], *, owner_id: str | None = None
    ) -> int:
        """Avoid dangling project policy when a retained job is deleted or purged."""

        safe_analysis_ids = {analysis_id for analysis_id in analysis_ids if IDENTIFIER_PATTERN.fullmatch(analysis_id)}
        if not safe_analysis_ids:
            return 0
        cleared = 0
        ordered_ids = sorted(safe_analysis_ids)
        for offset in range(0, len(ordered_ids), PROJECT_REFERENCE_QUERY_MAX_REFERENCES):
            reference_batch = set(
                ordered_ids[offset : offset + PROJECT_REFERENCE_QUERY_MAX_REFERENCES]
            )
            while True:
                with storage_lock(self.settings):
                    try:
                        records = self.reference_index.records_for_baselines(
                            analysis_ids=reference_batch,
                            owner_id=owner_id,
                            limit=PROJECT_REFERENCE_QUERY_BATCH_SIZE,
                        )
                    except ProjectReferenceIndexError as exc:
                        raise HTTPException(
                            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Project retention state is temporarily unavailable.",
                        ) from exc
                    if not records:
                        break
                    for record in records:
                        changed_at = utc_now()
                        updated = record.model_copy(
                            update={
                                "baseline_analysis_id": None,
                                "baseline_version": record.baseline_version + 1,
                                "baseline_updated_at": changed_at,
                                "updated_at": changed_at,
                            }
                        )
                        self._save_unlocked(updated)
                        log_audit_event(
                            "project.baseline.cleared",
                            correlation_id=f"project:{record.id}:baseline:{updated.baseline_version}",
                            project_id=record.id,
                            owner_id=record.owner_id,
                            baseline_version=updated.baseline_version,
                            reason="analysis_deleted",
                        )
                        cleared += 1
        return cleared

    def mark_source_file_deleted(self, file_id: str, *, owner_id: str | None = None) -> int:
        _validate_identifier(file_id, "file_id")
        with storage_lock(self.settings):
            return self._mark_source_file_deleted_unlocked(
                file_id, owner_id=owner_id
            )

    def _mark_source_file_deleted_unlocked(
        self, file_id: str, *, owner_id: str | None = None
    ) -> int:
        deleted_at = utc_now()
        marked = 0
        while True:
            try:
                records = self.reference_index.records_for_sources(
                    file_ids={file_id},
                    owner_id=owner_id,
                    limit=PROJECT_REFERENCE_QUERY_BATCH_SIZE,
                )
            except ProjectReferenceIndexError as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Project source state is temporarily unavailable.",
                ) from exc
            if not records:
                break
            for record in records:
                snapshots = [
                    snapshot.model_copy(update={"source_file_deleted_at": deleted_at})
                    if snapshot.source_file_id == file_id
                    and snapshot.source_file_deleted_at is None
                    else snapshot
                    for snapshot in record.source_snapshots
                ]
                updated = record.model_copy(
                    update={
                        "source_file_deleted_at": (
                            deleted_at
                            if record.source_file_id == file_id
                            else record.source_file_deleted_at
                        ),
                        "source_snapshots": snapshots,
                        "updated_at": deleted_at,
                    }
                )
                self._save_unlocked(updated)
                marked += 1
        return marked

    def _project_path(self, project_id: str) -> Path:
        _validate_identifier(project_id, "project_id")
        return self.settings.projects_dir / f"{project_id}.json"

    def _get_unlocked(self, project_id: str) -> ProjectRecord:
        if project_deletion_is_pending(self.settings, project_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
        path = self._project_path(project_id)
        if not path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
        return self._load_project_file(path)

    def _get_for_deletion_unlocked(self, project_id: str) -> ProjectRecord:
        """Load authoritative metadata while a deletion marker hides the project."""

        path = self._project_path(project_id)
        if not path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
        return self._load_project_file(path)

    def delete_for_deletion(self, project_id: str, *, owner_id: str) -> bool:
        """Remove hidden metadata only after a deletion marker closes admission."""

        with storage_lock(self.settings):
            if not project_deletion_is_pending(self.settings, project_id):
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Project deletion is not prepared.")
            path = self._project_path(project_id)
            if not path.exists():
                return False
            record = self._load_project_file(path)
            if record.owner_id != owner_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
            source_revision = self.risk_trend_source_clock.raw_source_revision()
            path.unlink(missing_ok=True)
            self.reference_index.sync_after_delete(record.id)
            self.risk_trend_source_clock.record_mutation(
                owner_id,
                previous_source_revision=source_revision,
            )
            return True

    def _save_unlocked(self, record: ProjectRecord) -> ProjectRecord:
        effective_owner = resolve_record_owner_id(self.settings, record.owner_id)
        source_revision = (
            self.risk_trend_source_clock.raw_source_revision()
            if effective_owner is not None
            else None
        )
        _atomic_write_json(self._project_path(record.id), record.model_dump(mode="json"))
        self.reference_index.sync_after_save(record)
        if source_revision is not None and effective_owner is not None:
            self.risk_trend_source_clock.record_mutation(
                effective_owner,
                previous_source_revision=source_revision,
            )
        log_audit_event(
            "project.persisted",
            correlation_id=f"project:{record.id}",
            project_id=record.id,
            owner_id=record.owner_id,
            analysis_count=record.analysis_count,
        )
        return record

    def _load_project_file(self, path: Path) -> ProjectRecord:
        try:
            record = ProjectRecord.model_validate_json(path.read_text(encoding="utf-8"))
            record = _with_effective_project_owner(self.settings, record)
            if record.source_snapshots:
                return record
            legacy_snapshot = ProjectSourceSnapshot(
                id=hashlib.sha256(f"{record.id}:{record.source_file_id}".encode("utf-8")).hexdigest()[:32],
                source_file_id=record.source_file_id,
                source_filename=record.source_filename,
                source_sha256=record.source_sha256,
                source_file_deleted_at=record.source_file_deleted_at,
                created_at=record.created_at,
            )
            return record.model_copy(update={"source_snapshots": [legacy_snapshot]})
        except (ValidationError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Stored project metadata is invalid: {path.name}",
            ) from exc


class ProjectSnapshotAdmissionRecord(BaseModel):
    """Private recovery journal; never returned by the project API."""

    model_config = ConfigDict(extra="forbid")

    contract_version: Literal["2026-09-06.1", "2026-09-09.1"] = PROJECT_SNAPSHOT_ADMISSION_CONTRACT_VERSION
    id: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    idempotency_key_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    owner_id: str | None = None
    project_id: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    source_file_id: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    source_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    source_commit_sha: str | None = Field(default=None, pattern=r"^[a-f0-9]{40,64}$")
    source_branch: str | None = Field(default=None, min_length=1, max_length=160)
    source_channel: ProjectSourceChannel | None = None
    snapshot_id: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    job_id: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    status: Literal["pending", "completed"]
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def current_contract_has_attested_channel(self):
        if self.contract_version == PROJECT_SNAPSHOT_ADMISSION_CONTRACT_VERSION and self.source_channel is None:
            raise ValueError("Current snapshot admission records require a source channel.")
        return self


@dataclass(frozen=True)
class ProjectSnapshotAdmissionResult:
    project: ProjectRecord
    snapshot: ProjectSourceSnapshot
    job: JobRecord
    replayed: bool
    should_schedule: bool


class ProjectSnapshotAdmissionStore:
    """Admit a snapshot and job as one idempotent, recoverable operation.

    JSON files cannot provide a cross-file transaction. A private write-ahead
    record fixes every generated identifier before project/job persistence. A
    retry or startup recovery completes those same records and never replaces
    or deletes project history.
    """

    def __init__(self, settings: Settings, files: FileStore, projects: ProjectStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.projects = projects
        self.jobs = jobs

    def admit(
        self,
        *,
        project_id: str,
        owner_id: str | None,
        source_file_id: str,
        idempotency_key: str,
        source_commit_sha: str | None = None,
        source_branch: str | None = None,
        equivalent_source_allowed: bool = False,
        source_channel: StoredProjectSourceChannel = "archive_upload",
    ) -> ProjectSnapshotAdmissionResult:
        _validate_identifier(project_id, "project_id")
        _validate_identifier(source_file_id, "source_file_id")
        if source_channel == "sbom" or ((source_channel in {"git_cli", "ci"}) != (source_commit_sha is not None)):
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Snapshot source channel is invalid.")
        if not IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Idempotency key is invalid.")

        operation_id = self._operation_id(owner_id, project_id, idempotency_key)
        key_sha256 = hashlib.sha256(idempotency_key.encode("ascii")).hexdigest()
        with storage_lock(self.settings):
            project = self.projects._get_unlocked(project_id)
            if project.owner_id != resolve_record_owner_id(self.settings, owner_id):
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")

            existing = self._get_optional_unlocked(operation_id)
            if existing is not None:
                compatible_source_file_id = source_file_id
                if equivalent_source_allowed and existing.source_file_id != source_file_id:
                    submitted_source = self.files._get_unlocked(source_file_id)
                    self._assert_source(project, submitted_source)
                    if submitted_source.sha256 != existing.source_sha256:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail="Commit identity is already bound to different source content.",
                        )
                    compatible_source_file_id = existing.source_file_id
                self._assert_compatible(
                    existing,
                    project,
                    compatible_source_file_id,
                    key_sha256,
                    source_commit_sha,
                    source_branch,
                )
                if existing.status == "completed":
                    result = self._completed_result_unlocked(existing, project)
                    log_audit_event(
                        "project.snapshot.admission_replayed",
                        correlation_id=f"job:{result.job.id}",
                        project_id=project.id,
                        job_id=result.job.id,
                        owner_id=project.owner_id,
                    )
                    return result
                return self._recover_unlocked(existing, project)

            self._recover_project_pending_unlocked(project.id)
            project = self.projects._get_unlocked(project.id)
            if self.jobs._has_active_project_job_unlocked(project.id, owner_id=project.owner_id):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Project already has an active analysis. Wait for it to finish before adding a new snapshot.",
                )
            self.jobs._assert_admission_available_unlocked(project.owner_id)
            if len(project.source_snapshots) >= self.settings.project_max_source_snapshots:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Project snapshot limit reached. Preserve this history and create a new project for further snapshots.",
                )

            source = self.files._get_unlocked(source_file_id)
            self._assert_source(project, source)
            commit_snapshot = (
                next((snapshot for snapshot in project.source_snapshots if snapshot.source_commit_sha == source_commit_sha), None)
                if source_commit_sha is not None
                else None
            )
            if commit_snapshot is not None and commit_snapshot.source_sha256 != source.sha256:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Commit identity is already bound to different source content.",
                )
            content_snapshot = next(
                (snapshot for snapshot in project.source_snapshots if snapshot.source_sha256 == source.sha256),
                None,
            )
            if content_snapshot is not None and source_commit_sha is not None:
                if content_snapshot.source_commit_sha not in {None, source_commit_sha}:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Source content is already attributed to a different commit identity.",
                    )
                candidate_jobs = [
                    self.jobs._get_unlocked(item.id)
                    for item in self.jobs.list(owner_id=project.owner_id)
                    if item.project_id == project.id
                ]
                matching_jobs = [
                    job
                    for job in candidate_jobs
                    if job.source_sha256 == source.sha256 and job.file_id == content_snapshot.source_file_id
                ]
                if not matching_jobs:
                    raise HTTPException(status_code=500, detail="Snapshot admission state is invalid.")
                job = matching_jobs[0]
                if content_snapshot.source_commit_sha is None:
                    attributed_snapshot = content_snapshot.model_copy(
                        update={"source_commit_sha": source_commit_sha, "source_branch": source_branch}
                    )
                    project = project.model_copy(
                        update={
                            "source_snapshots": [
                                attributed_snapshot if item.id == content_snapshot.id else item
                                for item in project.source_snapshots
                            ],
                            "updated_at": utc_now(),
                        }
                    )
                    project = self.projects._save_unlocked(project)
                    content_snapshot = attributed_snapshot
                now = utc_now()
                operation = ProjectSnapshotAdmissionRecord(
                    id=operation_id,
                    idempotency_key_sha256=key_sha256,
                    owner_id=project.owner_id,
                    project_id=project.id,
                    source_file_id=content_snapshot.source_file_id,
                    source_sha256=content_snapshot.source_sha256,
                    source_commit_sha=source_commit_sha,
                    source_branch=content_snapshot.source_branch,
                    source_channel=effective_project_source_channel(content_snapshot),
                    snapshot_id=content_snapshot.id,
                    job_id=job.id,
                    status="completed",
                    created_at=now,
                    updated_at=now,
                )
                self._save_unlocked(operation)
                return ProjectSnapshotAdmissionResult(
                    project=project,
                    snapshot=content_snapshot,
                    job=job,
                    replayed=True,
                    should_schedule=False,
                )
            if content_snapshot is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="This archive snapshot is already retained for the project. Run that snapshot again instead.",
                )

            now = utc_now()
            operation = ProjectSnapshotAdmissionRecord(
                id=operation_id,
                idempotency_key_sha256=key_sha256,
                owner_id=project.owner_id,
                project_id=project.id,
                source_file_id=source.id,
                source_sha256=source.sha256,
                source_commit_sha=source_commit_sha,
                source_branch=source_branch,
                source_channel=source_channel,
                snapshot_id=uuid4().hex,
                job_id=uuid4().hex,
                status="pending",
                created_at=now,
                updated_at=now,
            )
            self._save_unlocked(operation)
            log_audit_event(
                "project.snapshot.admission_reserved",
                correlation_id=f"job:{operation.job_id}",
                project_id=project.id,
                job_id=operation.job_id,
                owner_id=project.owner_id,
                contract_version=operation.contract_version,
            )
            return self._recover_unlocked(operation, project, replayed=False)

    def recover_pending(self) -> list[JobRecord]:
        """Complete viable write-ahead operations before queued-job recovery."""

        recovered: list[JobRecord] = []
        with storage_lock(self.settings):
            for path in sorted(self.settings.project_snapshot_admissions_dir.glob("*.json")):
                if not IDENTIFIER_PATTERN.fullmatch(path.stem):
                    continue
                try:
                    operation = self._load_unlocked(path)
                    if operation.status != "pending":
                        continue
                    project = self.projects._get_unlocked(operation.project_id)
                    recovered.append(self._recover_unlocked(operation, project).job)
                except Exception:
                    # A corrupt/unavailable retained source must not prevent
                    # startup. Only a bounded reason code enters telemetry.
                    log_audit_event(
                        "project.snapshot.admission_recovery_deferred",
                        correlation_id=f"snapshot-admission:{path.stem}",
                        operation_id=path.stem,
                        reason_code="retained_state_unavailable",
                    )
        return recovered

    def has_pending(self) -> bool:
        """Fail readiness closed for pending or malformed recovery journals."""

        with storage_lock(self.settings):
            for path in self.settings.project_snapshot_admissions_dir.glob("*.json"):
                if not IDENTIFIER_PATTERN.fullmatch(path.stem):
                    continue
                try:
                    if self._load_unlocked(path).status == "pending":
                        return True
                except HTTPException:
                    return True
        return False

    def delete_for_project(self, project_id: str, *, owner_id: str) -> int:
        """Remove completed or pending admission journals bound to a deleting project."""

        _validate_identifier(project_id, "project_id")
        removed = 0
        with storage_lock(self.settings):
            for path in sorted(self.settings.project_snapshot_admissions_dir.glob("*.json")):
                if not IDENTIFIER_PATTERN.fullmatch(path.stem):
                    continue
                operation = self._load_unlocked(path)
                if operation.project_id != project_id:
                    continue
                if operation.owner_id != owner_id:
                    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Snapshot admission state is invalid.")
                path.unlink(missing_ok=True)
                removed += 1
        return removed

    def _recover_project_pending_unlocked(self, project_id: str) -> None:
        for path in sorted(self.settings.project_snapshot_admissions_dir.glob("*.json")):
            if not IDENTIFIER_PATTERN.fullmatch(path.stem):
                continue
            operation = self._load_unlocked(path)
            if operation.project_id == project_id and operation.status == "pending":
                project = self.projects._get_unlocked(project_id)
                self._recover_unlocked(operation, project)

    def _recover_unlocked(
        self,
        operation: ProjectSnapshotAdmissionRecord,
        project: ProjectRecord,
        *,
        replayed: bool = True,
    ) -> ProjectSnapshotAdmissionResult:
        if project_deletion_is_pending(self.settings, project.id):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Project deletion is in progress. No new snapshot can be admitted.",
            )
        if operation.owner_id != project.owner_id:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Snapshot admission state is invalid.")
        source = self.files._get_unlocked(operation.source_file_id)
        self._assert_source(project, source)
        if source.sha256 != operation.source_sha256:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Snapshot admission state is invalid.")

        snapshot = next((item for item in project.source_snapshots if item.id == operation.snapshot_id), None)
        if snapshot is None:
            if any(item.source_sha256 == source.sha256 for item in project.source_snapshots):
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Snapshot admission state is invalid.")
            snapshot = ProjectSourceSnapshot(
                id=operation.snapshot_id,
                source_file_id=source.id,
                source_filename=source.original_filename,
                source_sha256=source.sha256,
                source_commit_sha=operation.source_commit_sha,
                source_branch=operation.source_branch,
                source_channel=(
                    operation.source_channel
                    if operation.source_channel in {"archive_upload", "git_cli", "ci", "sbom"}
                    else None
                ),
                created_at=operation.created_at,
            )
            project = project.model_copy(
                update={
                    "source_file_id": source.id,
                    "source_filename": source.original_filename,
                    "source_sha256": source.sha256,
                    "source_file_deleted_at": None,
                    "latest_job_id": operation.job_id,
                    "analysis_count": project.analysis_count + 1,
                    "source_snapshots": [*project.source_snapshots, snapshot],
                    "updated_at": operation.created_at,
                }
            )
            project = self.projects._save_unlocked(project)
        elif (
            snapshot.source_file_id != operation.source_file_id
            or snapshot.source_sha256 != operation.source_sha256
            or project.latest_job_id != operation.job_id
            or (
                operation.source_channel is not None
                and snapshot.source_channel is not None
                and effective_project_source_channel(snapshot) != operation.source_channel
            )
        ):
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Snapshot admission state is invalid.")

        try:
            job = self.jobs._get_unlocked(operation.job_id)
        except HTTPException as exc:
            if exc.status_code != status.HTTP_404_NOT_FOUND:
                raise
            job = JobRecord(
                id=operation.job_id,
                owner_id=operation.owner_id,
                project_id=operation.project_id,
                source_sha256=operation.source_sha256,
                analysis_profile="project_archive_basic",
                audit_type="project_archive_basic",
                file_id=operation.source_file_id,
                status="queued",
                created_at=operation.created_at,
                updated_at=operation.created_at,
            )
            self.jobs._assert_admission_available_unlocked(operation.owner_id)
            job = self.jobs._save_unlocked(job)
        self._assert_job_binding(operation, job)
        self._save_unlocked(operation.model_copy(update={"status": "completed", "updated_at": utc_now()}))
        log_audit_event(
            "project.snapshot.admission_completed",
            correlation_id=f"job:{job.id}",
            project_id=project.id,
            job_id=job.id,
            owner_id=project.owner_id,
            recovered=replayed,
            contract_version=operation.contract_version,
        )
        return ProjectSnapshotAdmissionResult(
            project=project,
            snapshot=snapshot,
            job=job,
            replayed=replayed,
            should_schedule=True,
        )

    def _completed_result_unlocked(
        self,
        operation: ProjectSnapshotAdmissionRecord,
        project: ProjectRecord,
    ) -> ProjectSnapshotAdmissionResult:
        snapshot = next((item for item in project.source_snapshots if item.id == operation.snapshot_id), None)
        if snapshot is None:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Snapshot admission state is invalid.")
        job = self.jobs._get_unlocked(operation.job_id)
        self._assert_job_binding(operation, job)
        return ProjectSnapshotAdmissionResult(project=project, snapshot=snapshot, job=job, replayed=True, should_schedule=False)

    @staticmethod
    def _assert_compatible(
        operation: ProjectSnapshotAdmissionRecord,
        project: ProjectRecord,
        source_file_id: str,
        key_sha256: str,
        source_commit_sha: str | None,
        source_branch: str | None,
    ) -> None:
        if (
            operation.project_id != project.id
            or operation.owner_id != project.owner_id
            or operation.source_file_id != source_file_id
            or operation.idempotency_key_sha256 != key_sha256
            or operation.source_commit_sha != source_commit_sha
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Idempotency key is already bound to a different snapshot request.",
            )

    @staticmethod
    def _assert_source(project: ProjectRecord, source: StoredFile) -> None:
        if source.owner_id != project.owner_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")
        if source.kind != "archive":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Project snapshot source must be an archive.")

    @staticmethod
    def _assert_job_binding(operation: ProjectSnapshotAdmissionRecord, job: JobRecord) -> None:
        if (
            job.id != operation.job_id
            or job.owner_id != operation.owner_id
            or job.project_id != operation.project_id
            or job.file_id != operation.source_file_id
            or job.source_sha256 != operation.source_sha256
            or job.audit_type != "project_archive_basic"
            or job.analysis_profile != "project_archive_basic"
        ):
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Snapshot admission state is invalid.")

    def _operation_id(self, owner_id: str | None, project_id: str, idempotency_key: str) -> str:
        owner_scope = resolve_record_owner_id(self.settings, owner_id) or "anonymous"
        # Keep the original identity salt so an upgrade can replay journals
        # written before source-channel attestation without creating a second
        # operation for the same client key.
        material = f"{PROJECT_SNAPSHOT_ADMISSION_IDENTITY_VERSION}\0{owner_scope}\0{project_id}\0{idempotency_key}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]

    def _path(self, operation_id: str) -> Path:
        _validate_identifier(operation_id, "operation_id")
        return self.settings.project_snapshot_admissions_dir / f"{operation_id}.json"

    def _get_optional_unlocked(self, operation_id: str) -> ProjectSnapshotAdmissionRecord | None:
        path = self._path(operation_id)
        return self._load_unlocked(path) if path.exists() else None

    @staticmethod
    def _load_unlocked(path: Path) -> ProjectSnapshotAdmissionRecord:
        try:
            return ProjectSnapshotAdmissionRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except (ValidationError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Snapshot admission state is invalid.") from exc

    def _save_unlocked(self, operation: ProjectSnapshotAdmissionRecord) -> None:
        _atomic_write_json(self._path(operation.id), operation.model_dump(mode="json"))


def sanitize_job_record_for_storage(
    record: JobRecord,
    *,
    go_dependency_graph: GoDependencyGraphArtifact | None = None,
    go_dependency_graph_sha256: str | None = None,
    cargo_dependency_graph: CargoDependencyGraphArtifact | None = None,
    cargo_dependency_graph_sha256: str | None = None,
    composer_dependency_graph: ComposerDependencyGraphArtifact | None = None,
    composer_dependency_graph_sha256: str | None = None,
    gradle_dependency_graph: GradleDependencyGraphArtifact | None = None,
    gradle_dependency_graph_sha256: str | None = None,
    nuget_dependency_graph: NugetDependencyGraphArtifact | None = None,
    nuget_dependency_graph_sha256: str | None = None,
) -> JobRecord:
    target_url = record.target_url
    if target_url:
        target_url = redact_url_query(target_url)
    redacted_result = redact_job_value_for_storage(record.result) if record.result is not None else None
    result = normalize_result_findings(record.audit_type, redacted_result) if redacted_result is not None else None
    if result is not None:
        if (
            go_dependency_graph is not None
            or cargo_dependency_graph is not None
            or isinstance(result.get("dependency_graph_evidence"), dict)
            or isinstance(result.get("cargo_dependency_graph_evidence"), dict)
            or composer_dependency_graph is not None
            or isinstance(result.get("composer_dependency_graph_evidence"), dict)
            or gradle_dependency_graph is not None
            or isinstance(result.get("gradle_dependency_graph_evidence"), dict)
            or nuget_dependency_graph is not None
            or isinstance(result.get("nuget_dependency_graph_evidence"), dict)
        ):
            result = attach_dependency_graph_projection(
                record.audit_type,
                result,
                go_dependency_graph=go_dependency_graph,
                go_dependency_graph_sha256=go_dependency_graph_sha256,
                cargo_dependency_graph=cargo_dependency_graph,
                cargo_dependency_graph_sha256=cargo_dependency_graph_sha256,
                composer_dependency_graph=composer_dependency_graph,
                composer_dependency_graph_sha256=composer_dependency_graph_sha256,
                gradle_dependency_graph=gradle_dependency_graph,
                gradle_dependency_graph_sha256=gradle_dependency_graph_sha256,
                nuget_dependency_graph=nuget_dependency_graph,
                nuget_dependency_graph_sha256=nuget_dependency_graph_sha256,
            )
        else:
            result = add_component_inventory(record.audit_type, result)
    error = redact_active_secret_text(record.error) if record.error else None
    return record.model_copy(update={"target_url": target_url, "result": result, "error": error})


def _result_integrity_envelope(record: JobRecord) -> dict[str, str] | None:
    if record.result is None:
        return None
    return {
        "contract_version": RESULT_INTEGRITY_CONTRACT_VERSION,
        "sha256": _result_integrity_digest(record),
    }


def _result_integrity_payload_matches(payload: dict[str, Any], envelope: object) -> bool:
    return (
        isinstance(envelope, dict)
        and set(envelope) == {"contract_version", "sha256"}
        and envelope.get("contract_version") == RESULT_INTEGRITY_CONTRACT_VERSION
        and isinstance(envelope.get("sha256"), str)
        and bool(re.fullmatch(r"[a-f0-9]{64}", envelope["sha256"]))
        and payload.get("result") is not None
        and hashlib.sha256(_result_integrity_material_from_mapping(payload)).hexdigest() == envelope["sha256"]
    )


def _result_integrity_digest(record: JobRecord) -> str:
    return hashlib.sha256(_result_integrity_material(record)).hexdigest()


def _result_integrity_material(record: JobRecord) -> bytes:
    return _result_integrity_material_from_mapping({
        **record.model_dump(mode="json"),
        "execution_profile": record.execution_profile.model_dump(mode="json") if record.execution_profile else None,
    })


def _result_integrity_material_from_mapping(payload: dict[str, Any]) -> bytes:
    value = {
        "contract_version": RESULT_INTEGRITY_CONTRACT_VERSION,
        "job_id": payload.get("id"),
        "owner_id": payload.get("owner_id"),
        "organization_id": payload.get("organization_id"),
        "project_id": payload.get("project_id"),
        "audit_type": payload.get("audit_type"),
        "analysis_profile": payload.get("analysis_profile"),
        "execution_profile": payload.get("execution_profile"),
        "result": payload.get("result"),
    }
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Result integrity metadata could not be generated.",
        ) from exc


def redact_job_value_for_storage(value: Any, *, sensitive_context: bool = False) -> Any:
    if isinstance(value, str):
        return "[REDACTED]" if sensitive_context else redact_active_secret_text(value)
    if isinstance(value, list):
        return [redact_job_value_for_storage(item, sensitive_context=sensitive_context) for item in value]
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            normalized_key = str(key).lower().replace("-", "_")
            child_sensitive_context = sensitive_context or is_sensitive_storage_key(normalized_key)
            if is_safe_storage_metadata_key(normalized_key):
                child_sensitive_context = False
            redacted[key] = redact_job_value_for_storage(item, sensitive_context=child_sensitive_context)
        return redacted
    return value


def is_sensitive_storage_key(key: str) -> bool:
    return key in {
        "authorization",
        "authorization_header",
        "credential",
        "credentials",
        "cookie",
        "cookie_header",
        "password",
        "passwd",
        "pwd",
        "api_key",
        "api_key_header",
        "apikey",
        "private_key",
        "secret_key",
        "token",
        "x_api_key",
        "x_auth_token",
        "x_csrf_token",
        "set_cookie",
        "access_token",
        "refresh_token",
        "id_token",
        "auth_token",
        "response_body",
        "body_text",
        "raw_payload",
        "raw_response",
        "raw_request",
    }


def is_safe_storage_metadata_key(key: str) -> bool:
    return key == "scope" or key.endswith(("_count", "_detected", "_present", "_confirmed"))


def run_retention_cleanup(
    settings: Settings,
    files: FileStore,
    jobs: JobStore,
    projects: ProjectStore | None = None,
    public_intelligence: Any | None = None,
    *,
    now: datetime | None = None,
    owner_id: str | None = None,
) -> dict[str, int]:
    current_time = now or utc_now()
    deleted_jobs: list[JobRecord] = []
    if settings.job_retention_days:
        def cleanup_derived_result(record: JobRecord) -> None:
            if public_intelligence is not None:
                public_intelligence.delete_analysis(
                    record.id,
                    organization_id=resolve_record_owner_id(settings, record.owner_id),
                )
            if projects is not None:
                projects.clear_baselines_for_analysis_ids(
                    {record.id}, owner_id=record.owner_id if owner_id is not None else None
                )

        deleted_jobs = jobs.purge_expired_terminal(
            current_time - timedelta(days=settings.job_retention_days),
            owner_id=owner_id,
            before_delete=cleanup_derived_result if public_intelligence is not None or projects is not None else None,
        )

    deleted_files: list[StoredFile] = []
    marked_jobs = 0
    marked_projects = 0
    if settings.upload_retention_days:
        def mark_source_relations(record: StoredFile) -> None:
            nonlocal marked_jobs, marked_projects
            marked_jobs += jobs._mark_files_deleted_unlocked(
                {record.id}, owner_id=owner_id
            )
            if projects is not None:
                marked_projects += projects._mark_source_file_deleted_unlocked(
                    record.id, owner_id=owner_id
                )

        deleted_files = files.purge_expired(
            current_time - timedelta(days=settings.upload_retention_days),
            protected_file_ids=jobs.active_file_ids(),
            owner_id=owner_id,
            before_delete=mark_source_relations,
            is_protected=jobs._source_file_is_active_unlocked,
        )

    result: dict[str, int] = {
        "jobs_deleted": len(deleted_jobs),
        "files_deleted": len(deleted_files),
        "jobs_marked_source_deleted": marked_jobs,
    }
    if projects is not None:
        result["projects_marked_source_deleted"] = marked_projects
    log_audit_event(
        "retention.cleanup",
        correlation_id=f"retention:{current_time.date().isoformat()}",
        upload_retention_days=settings.upload_retention_days,
        job_retention_days=settings.job_retention_days,
        **result,
    )
    return result


async def _iter_initial_and_remaining_chunks(first_chunk: bytes, upload: UploadFile):
    yield first_chunk
    while chunk := await upload.read(UPLOAD_CHUNK_SIZE):
        yield chunk


async def _read_limited_upload(upload: UploadFile, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    size_bytes = 0
    while chunk := await upload.read(UPLOAD_CHUNK_SIZE):
        size_bytes += len(chunk)
        if size_bytes > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"File too large. Maximum allowed size is {max_bytes} bytes.",
            )
        chunks.append(chunk)
    if not chunks:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty file.")
    return b"".join(chunks)


def _validate_identifier(value: str, label: str) -> None:
    if not IDENTIFIER_PATTERN.fullmatch(value):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid {label}.")


def _detect_image_type(data: bytes) -> tuple[str, str, str] | None:
    for name, extension, content_type, matcher in IMAGE_SIGNATURES:
        if matcher(data):
            return name, extension, content_type
    return None


def _validate_manifest_upload(filename: str, payload: bytes) -> tuple[str, str]:
    normalized_name = filename.lower()
    definition = MANIFEST_DEFINITIONS.get(normalized_name)
    if definition is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only package.json, requirements.txt, and pyproject.toml manifests are accepted.",
        )
    if b"\x00" in payload:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Manifest must be a text file.")

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Manifest must be valid UTF-8 text.") from exc

    manifest_type, content_type = definition
    stripped = text.strip()
    if not stripped:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Manifest is empty.")
    if manifest_type == "package_json":
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="package.json must be valid JSON.") from exc
        if not isinstance(parsed, dict):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="package.json must contain a JSON object.")
    elif manifest_type == "requirements_txt":
        active_lines = [line for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
        if not active_lines:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="requirements.txt must contain at least one active line.")
    elif manifest_type == "pyproject_toml" and not re.search(r"^\s*\[(project|tool\.poetry)", text, flags=re.MULTILINE):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="pyproject.toml must include a [project] or [tool.poetry] section.",
        )

    return manifest_type, content_type


def _validate_archive_upload(filename: str, payload: bytes) -> tuple[str, str, str]:
    normalized_name = filename.lower()
    for suffix, archive_type, stored_extension, content_type, matcher in ARCHIVE_DEFINITIONS:
        if not normalized_name.endswith(suffix):
            continue
        if matcher(payload):
            return archive_type, stored_extension, content_type
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{suffix} archive content does not match the expected file signature.",
        )
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Only .zip, .tar, .tar.gz, and .tgz archives are accepted.",
    )


def _job_summary(record: JobRecord) -> dict | None:
    if record.result:
        validation = record.result.get("validation", {})
        hashes = record.result.get("hashes", {})
        manifest_summary = record.result.get("summary", {})
        if not isinstance(validation, dict):
            validation = {}
        if not isinstance(hashes, dict):
            hashes = {}
        if not isinstance(manifest_summary, dict):
            manifest_summary = {}
        summary = {
            "analyzer": record.result.get("analyzer"),
            "completed_at": record.result.get("completed_at"),
            "sha256": hashes.get("sha256"),
            "warnings": validation.get("warnings", []),
            "timed_out_tools": validation.get("timed_out_tools", []),
        }
        if record.audit_type == "pdf_basic":
            summary["qpdf_ok"] = validation.get("qpdf_ok")
        if record.audit_type == "image_basic":
            summary["mime_type"] = validation.get("mime_type")
            summary["privacy_indicators"] = record.result.get("privacy_indicators", {})
        if record.audit_type == "manifest_basic":
            summary["manifest_type"] = record.result.get("manifest_type")
            summary["total_dependencies"] = manifest_summary.get("total_dependencies")
            summary["informational_findings_count"] = manifest_summary.get("informational_findings_count")
        if record.audit_type == "archive_basic":
            summary["archive_type"] = record.result.get("archive_type")
            summary["total_entries"] = manifest_summary.get("total_entries")
            summary["findings_count"] = manifest_summary.get("findings_count")
            summary["truncated"] = manifest_summary.get("truncated")
        if record.audit_type == "project_archive_basic":
            summary["archive_type"] = record.result.get("archive_type")
            summary["total_entries_seen"] = manifest_summary.get("total_entries_seen")
            summary["supported_manifests_parsed"] = manifest_summary.get("supported_manifests_parsed")
            summary["total_dependencies"] = manifest_summary.get("total_dependencies")
            summary["findings_count"] = manifest_summary.get("findings_count")
            summary["truncated"] = manifest_summary.get("truncated")
        if record.audit_type == "web_basic":
            summary["status_code"] = (record.result.get("http") or {}).get("status_code")
            summary["final_url"] = (record.result.get("target") or {}).get("final_url")
            summary["findings_count"] = manifest_summary.get("findings_count")
            summary["redirects_count"] = manifest_summary.get("redirects_count")
            summary["tls_present"] = manifest_summary.get("tls_present")
        if record.audit_type == "domain_basic":
            summary["domain"] = (record.result.get("target") or {}).get("normalized_domain") or record.target_domain
            summary["records_found_count"] = manifest_summary.get("records_found_count")
            summary["findings_count"] = manifest_summary.get("findings_count")
            summary["spf_present"] = manifest_summary.get("spf_present")
            summary["dmarc_present"] = manifest_summary.get("dmarc_present")
            summary["dmarc_policy"] = manifest_summary.get("dmarc_policy")
        if record.audit_type == "subdomain_inventory_basic":
            summary["root_domain"] = (record.result.get("target") or {}).get("normalized_root_domain") or record.target_domain
            summary["candidates_accepted"] = manifest_summary.get("candidates_accepted")
            summary["candidates_rejected"] = manifest_summary.get("candidates_rejected")
            summary["resolved_count"] = manifest_summary.get("resolved_count")
            summary["unresolved_count"] = manifest_summary.get("unresolved_count")
            summary["private_ip_count"] = manifest_summary.get("private_ip_count")
            summary["findings_count"] = manifest_summary.get("findings_count")
            summary["wildcard_dns_possible"] = manifest_summary.get("wildcard_dns_possible")
            summary["truncated"] = manifest_summary.get("truncated")
            summary["deadline_reached"] = manifest_summary.get("deadline_reached")
        if record.audit_type == "django_config_basic":
            summary["archive_type"] = record.result.get("archive_type")
            summary["files_read"] = manifest_summary.get("files_read")
            summary["settings_files_detected"] = manifest_summary.get("settings_files_detected")
            summary["deployment_files_detected"] = manifest_summary.get("deployment_files_detected")
            summary["findings_count"] = manifest_summary.get("findings_count")
            summary["secrets_redacted_count"] = manifest_summary.get("secrets_redacted_count")
            summary["truncated"] = manifest_summary.get("truncated")
        if record.audit_type == "docker_config_basic":
            summary["archive_type"] = record.result.get("archive_type")
            summary["files_reviewed"] = manifest_summary.get("files_reviewed")
            summary["dockerfiles_detected"] = manifest_summary.get("dockerfiles_detected")
            summary["compose_files_detected"] = manifest_summary.get("compose_files_detected")
            summary["services_detected"] = manifest_summary.get("services_detected", len(record.result.get("compose_services") or []))
            summary["findings_count"] = manifest_summary.get("findings_count")
            summary["secrets_redacted_count"] = manifest_summary.get("secrets_redacted_count")
            summary["truncated"] = manifest_summary.get("truncated")
            summary["errors_count"] = len(record.result.get("errors") or [])
        if record.audit_type == "secrets_review_basic":
            summary["archive_type"] = record.result.get("archive_type")
            summary["files_considered"] = manifest_summary.get("files_considered")
            summary["files_reviewed"] = manifest_summary.get("files_reviewed")
            summary["sensitive_files_detected"] = manifest_summary.get("sensitive_files_detected")
            summary["findings_count"] = manifest_summary.get("findings_count")
            summary["high_confidence_count"] = manifest_summary.get("high_confidence_count")
            summary["redacted_values_count"] = manifest_summary.get("redacted_values_count")
            summary["truncated"] = manifest_summary.get("truncated")
            summary["errors_count"] = len(record.result.get("errors") or [])
        if record.audit_type == "node_package_config_basic":
            summary["archive_type"] = record.result.get("archive_type")
            summary["files_considered"] = manifest_summary.get("files_considered")
            summary["files_reviewed"] = manifest_summary.get("files_reviewed")
            summary["package_manifests_detected"] = manifest_summary.get("package_manifests_detected")
            summary["lockfiles_detected"] = manifest_summary.get("lockfiles_detected")
            summary["package_manager_configs_detected"] = manifest_summary.get("package_manager_configs_detected")
            summary["packages_detected"] = manifest_summary.get("packages_detected")
            summary["scripts_detected"] = manifest_summary.get("scripts_detected")
            summary["findings_count"] = manifest_summary.get("findings_count")
            summary["redacted_values_count"] = manifest_summary.get("redacted_values_count")
            summary["truncated"] = manifest_summary.get("truncated")
            summary["errors_count"] = len(record.result.get("errors") or [])
        if record.audit_type == "ci_cd_config_basic":
            summary["archive_type"] = record.result.get("archive_type")
            summary["files_considered"] = manifest_summary.get("files_considered")
            summary["files_reviewed"] = manifest_summary.get("files_reviewed")
            summary["workflow_files_detected"] = manifest_summary.get("workflow_files_detected")
            summary["jobs_detected"] = manifest_summary.get("jobs_detected")
            summary["steps_detected"] = manifest_summary.get("steps_detected")
            summary["triggers_detected"] = manifest_summary.get("triggers_detected")
            summary["findings_count"] = manifest_summary.get("findings_count")
            summary["redacted_values_count"] = manifest_summary.get("redacted_values_count")
            summary["truncated"] = manifest_summary.get("truncated")
            summary["errors_count"] = len(record.result.get("errors") or [])
        if record.audit_type == "k8s_config_basic":
            summary["archive_type"] = record.result.get("archive_type")
            summary["files_considered"] = manifest_summary.get("files_considered")
            summary["files_reviewed"] = manifest_summary.get("files_reviewed")
            summary["manifest_files_detected"] = manifest_summary.get("manifest_files_detected")
            summary["resources_detected"] = manifest_summary.get("resources_detected")
            summary["workloads_detected"] = manifest_summary.get("workloads_detected")
            summary["services_detected"] = manifest_summary.get("services_detected")
            summary["secrets_detected"] = manifest_summary.get("secrets_detected")
            summary["rbac_resources_detected"] = manifest_summary.get("rbac_resources_detected")
            summary["findings_count"] = manifest_summary.get("findings_count")
            summary["redacted_values_count"] = manifest_summary.get("redacted_values_count")
            summary["truncated"] = manifest_summary.get("truncated")
            summary["errors_count"] = len(record.result.get("errors") or [])
        if record.audit_type == "terraform_config_basic":
            summary["archive_type"] = record.result.get("archive_type")
            summary["files_considered"] = manifest_summary.get("files_considered")
            summary["files_reviewed"] = manifest_summary.get("files_reviewed")
            summary["terraform_files_detected"] = manifest_summary.get("terraform_files_detected")
            summary["tfvars_files_detected"] = manifest_summary.get("tfvars_files_detected")
            summary["state_files_detected"] = manifest_summary.get("state_files_detected")
            summary["providers_detected"] = manifest_summary.get("providers_detected")
            summary["backends_detected"] = manifest_summary.get("backends_detected")
            summary["modules_detected"] = manifest_summary.get("modules_detected")
            summary["resources_detected"] = manifest_summary.get("resources_detected")
            summary["findings_count"] = manifest_summary.get("findings_count")
            summary["redacted_values_count"] = manifest_summary.get("redacted_values_count")
            summary["truncated"] = manifest_summary.get("truncated")
            summary["errors_count"] = len(record.result.get("errors") or [])
        if record.audit_type == "nginx_config_basic":
            summary["archive_type"] = record.result.get("archive_type")
            summary["files_considered"] = manifest_summary.get("files_considered")
            summary["files_reviewed"] = manifest_summary.get("files_reviewed")
            summary["nginx_files_detected"] = manifest_summary.get("nginx_files_detected")
            summary["server_blocks_detected"] = manifest_summary.get("server_blocks_detected")
            summary["location_blocks_detected"] = manifest_summary.get("location_blocks_detected")
            summary["upstream_blocks_detected"] = manifest_summary.get("upstream_blocks_detected")
            summary["includes_detected"] = manifest_summary.get("includes_detected")
            summary["tls_servers_detected"] = manifest_summary.get("tls_servers_detected")
            summary["findings_count"] = manifest_summary.get("findings_count")
            summary["redacted_values_count"] = manifest_summary.get("redacted_values_count")
            summary["truncated"] = manifest_summary.get("truncated")
            summary["errors_count"] = len(record.result.get("errors") or [])
        if record.audit_type == "compose_config_basic":
            summary["archive_type"] = record.result.get("archive_type")
            summary["files_considered"] = manifest_summary.get("files_considered")
            summary["files_reviewed"] = manifest_summary.get("files_reviewed")
            summary["compose_files_detected"] = manifest_summary.get("compose_files_detected")
            summary["services_detected"] = manifest_summary.get("services_detected")
            summary["networks_detected"] = manifest_summary.get("networks_detected")
            summary["volumes_detected"] = manifest_summary.get("volumes_detected")
            summary["secrets_detected"] = manifest_summary.get("secrets_detected")
            summary["published_ports_detected"] = manifest_summary.get("published_ports_detected")
            summary["env_files_detected"] = manifest_summary.get("env_files_detected")
            summary["findings_count"] = manifest_summary.get("findings_count")
            summary["redacted_values_count"] = manifest_summary.get("redacted_values_count")
            summary["truncated"] = manifest_summary.get("truncated")
            summary["errors_count"] = len(record.result.get("errors") or [])
        if record.audit_type == "database_config_basic":
            summary["archive_type"] = record.result.get("archive_type")
            summary["files_considered"] = manifest_summary.get("files_considered")
            summary["files_reviewed"] = manifest_summary.get("files_reviewed")
            summary["database_files_detected"] = manifest_summary.get("database_files_detected")
            summary["postgres_files_detected"] = manifest_summary.get("postgres_files_detected")
            summary["mysql_files_detected"] = manifest_summary.get("mysql_files_detected")
            summary["mariadb_files_detected"] = manifest_summary.get("mariadb_files_detected")
            summary["pg_hba_files_detected"] = manifest_summary.get("pg_hba_files_detected")
            summary["dump_or_backup_files_detected"] = manifest_summary.get("dump_or_backup_files_detected")
            summary["engines_detected"] = manifest_summary.get("engines_detected")
            summary["findings_count"] = manifest_summary.get("findings_count")
            summary["redacted_values_count"] = manifest_summary.get("redacted_values_count")
            summary["truncated"] = manifest_summary.get("truncated")
            summary["errors_count"] = len(record.result.get("errors") or [])
        if record.audit_type == "sql_database_config_basic":
            errors = record.result.get("errors")
            summary["archive_type"] = record.result.get("archive_type")
            summary["files_considered"] = manifest_summary.get("files_considered")
            summary["files_reviewed"] = manifest_summary.get("files_reviewed")
            summary["postgres_configs_detected"] = manifest_summary.get("postgres_configs_detected")
            summary["postgres_hba_files_detected"] = manifest_summary.get("postgres_hba_files_detected")
            summary["mysql_configs_detected"] = manifest_summary.get("mysql_configs_detected")
            summary["mariadb_configs_detected"] = manifest_summary.get("mariadb_configs_detected")
            summary["dump_or_backup_files_detected"] = manifest_summary.get("dump_or_backup_files_detected")
            summary["data_files_detected"] = manifest_summary.get("data_files_detected")
            summary["findings_count"] = manifest_summary.get("findings_count")
            summary["redacted_values_count"] = manifest_summary.get("redacted_values_count")
            summary["truncated"] = manifest_summary.get("truncated")
            summary["errors_count"] = len(errors) if isinstance(errors, list) else 1 if errors else 0
        if record.audit_type == "redis_config_basic":
            summary["archive_type"] = record.result.get("archive_type")
            summary["files_considered"] = manifest_summary.get("files_considered")
            summary["files_reviewed"] = manifest_summary.get("files_reviewed")
            summary["redis_files_detected"] = manifest_summary.get("redis_files_detected")
            summary["sentinel_files_detected"] = manifest_summary.get("sentinel_files_detected")
            summary["acl_files_detected"] = manifest_summary.get("acl_files_detected")
            summary["dump_or_aof_files_detected"] = manifest_summary.get("dump_or_aof_files_detected")
            summary["configs_detected"] = manifest_summary.get("configs_detected")
            summary["findings_count"] = manifest_summary.get("findings_count")
            summary["redacted_values_count"] = manifest_summary.get("redacted_values_count")
            summary["truncated"] = manifest_summary.get("truncated")
            summary["errors_count"] = len(record.result.get("errors") or [])
        if record.audit_type in {"active_network_dry_run", "active_http_header_probe"}:
            target = record.result.get("target")
            policy = record.result.get("policy")
            blocked_reasons = record.result.get("blocked_reasons")
            if not isinstance(target, dict):
                target = {}
            if not isinstance(policy, dict):
                policy = {}
            if not isinstance(blocked_reasons, list):
                blocked_reasons = []
            target_display = target.get("normalized") or target.get("raw") or record.target_url
            summary["target_display"] = _redact_active_summary_text(str(target_display)) if target_display else None
            summary["mode"] = record.result.get("mode")
            summary["profile"] = record.result.get("profile")
            summary["allowed"] = policy.get("allowed", manifest_summary.get("allowed"))
            summary["planned_checks_count"] = manifest_summary.get("planned_checks_count")
            summary["blocked_reasons_count"] = manifest_summary.get("blocked_reasons_count")
            summary["network_requests_sent"] = manifest_summary.get("network_requests_sent")
            summary["redirects_followed"] = manifest_summary.get("redirects_followed")
            summary["body_bytes_read"] = manifest_summary.get("body_bytes_read")
            summary["headers_received_count"] = manifest_summary.get("headers_received_count")
            summary["redacted_headers_count"] = manifest_summary.get("redacted_headers_count")
            summary["truncated_headers_count"] = manifest_summary.get("truncated_headers_count")
            summary["errors_count"] = len(record.result.get("errors") or [])
            summary["blocked_reason_codes"] = [
                str(reason.get("code"))
                for reason in blocked_reasons
                if isinstance(reason, dict) and reason.get("code") is not None
            ]
            summary["policy_version"] = policy.get("policy_version")
        if record.audit_type == "active_http_basic_header_review":
            result_summary = record.result.get("summary")
            execution = record.result.get("execution")
            if not isinstance(result_summary, dict):
                result_summary = {}
            if not isinstance(execution, dict):
                execution = {}
            summary["capability"] = record.result.get("capability", "active_http_basic_header_review")
            summary["profile"] = record.result.get("profile")
            summary["result_status"] = record.result.get("result_status", record.result.get("status"))
            summary["lifecycle_state"] = record.result.get("lifecycle_state", "not_executed")
            summary["target_display"] = "[REDACTED_TARGET]"
            summary["method"] = record.result.get("method", "HEAD")
            summary["manual_validation_required"] = True
            summary["review_wording"] = result_summary.get("review_wording", "HTTP header review indicator")
            summary["job_status_meaning"] = result_summary.get(
                "job_status_meaning",
                "Completed job status means the no-live record was stored; no HTTP request was performed.",
            )
            summary["surface_interpretation"] = result_summary.get(
                "result_interpretation",
                "HTTP header review indicator",
            )
            summary["live_request_performed"] = execution.get("live_request_performed", False)
            summary["redirect_followed"] = execution.get("redirect_followed", False)
            summary["body_read"] = execution.get("body_read", False)
            summary["requests_sent"] = execution.get("requests_sent", 0)
            summary["network_requests_sent"] = execution.get("network_requests_sent", 0)
            summary["http_requests_sent"] = execution.get("http_requests_sent", 0)
            summary["storage_persisted"] = execution.get("storage_persisted", True)
        if record.audit_type == "active_nmap_basic":
            limits = record.result.get("limits")
            execution = record.result.get("execution")
            observations = record.result.get("port_observations")
            if not isinstance(limits, dict):
                limits = {}
            if not isinstance(execution, dict):
                execution = {}
            if not isinstance(observations, list):
                observations = []
            lifecycle_state = record.result.get("lifecycle_state")
            no_live_lifecycle_states = {
                "blocked_missing_approval",
                "blocked_unconfigured",
                "client_error_controlled",
                "completed_no_live",
                "not_executed",
                "unsafe_lifecycle_result",
            }
            if lifecycle_state in no_live_lifecycle_states:
                observations = []
            summary["capability"] = record.result.get("capability", "active_nmap_basic")
            summary["profile"] = record.result.get("profile")
            summary["result_status"] = record.result.get("status")
            summary["lifecycle_state"] = lifecycle_state
            summary["observation_count"] = manifest_summary.get("observation_count", record.result.get("observation_count", len(observations)))
            summary["open_tcp_observations_count"] = sum(
                1
                for observation in observations
                if isinstance(observation, dict)
                and str(observation.get("protocol", "")).lower() == "tcp"
                and str(observation.get("state", "")).lower() == "open"
            )
            summary["output_truncated"] = limits.get("output_truncated", record.result.get("output_truncated"))
            summary["stderr_truncated"] = limits.get("stderr_truncated", record.result.get("stderr_truncated"))
            summary["timed_out"] = limits.get("timed_out", record.result.get("timed_out"))
            if lifecycle_state in no_live_lifecycle_states:
                summary["manual_validation_required"] = True
                summary["no_live_lifecycle_record"] = True
                summary["surface_interpretation"] = "No-live lifecycle record, not a target finding"
                summary["nmap_executed"] = execution.get("nmap_executed", False)
                summary["network_requests_sent"] = execution.get("network_requests_sent", 0)
                summary["dns_queries_sent"] = execution.get("dns_queries_sent", 0)
                summary["evidence_collected"] = False
                summary["observations_available"] = False
            else:
                summary["manual_validation_required"] = True
                summary["no_live_lifecycle_record"] = False
                summary["surface_interpretation"] = "Observed TCP exposure / review indicator"
                summary["nmap_executed"] = execution.get("nmap_executed", False)
                summary["network_requests_sent"] = execution.get("network_requests_sent", 0)
                summary["dns_queries_sent"] = execution.get("dns_queries_sent", 0)
                summary["evidence_collected"] = execution.get("evidence_available", False)
                summary["observations_available"] = bool(observations)
        if record.audit_type == "active_tls_basic":
            tls_summary = record.result.get("summary")
            execution = record.result.get("execution")
            certificate = record.result.get("certificate")
            handshake = record.result.get("handshake")
            if not isinstance(tls_summary, dict):
                tls_summary = {}
            if not isinstance(execution, dict):
                execution = {}
            if not isinstance(certificate, dict):
                certificate = {}
            if not isinstance(handshake, dict):
                handshake = {}
            summary["capability"] = record.result.get("capability", "active_tls_basic")
            summary["profile"] = record.result.get("profile")
            summary["result_status"] = record.result.get("result_status", record.result.get("status"))
            summary["target_display"] = "[REDACTED_TARGET]"
            summary["port"] = record.result.get("port")
            summary["handshake_status"] = handshake.get("status")
            summary["protocol"] = handshake.get("protocol")
            summary["cipher"] = handshake.get("cipher")
            summary["certificate_available"] = certificate.get("available", tls_summary.get("certificate_available", False))
            summary["san_count"] = certificate.get("san_count", tls_summary.get("san_count", 0))
            summary["days_until_expiry"] = certificate.get("days_until_expiry")
            summary["manual_validation_required"] = True
            summary["surface_interpretation"] = "TLS configuration review indicator"
            summary["tls_handshake_attempted"] = execution.get("tls_handshake_attempted", True)
            summary["network_requests_sent"] = execution.get("network_requests_sent", 1)
            summary["http_requests_sent"] = execution.get("http_requests_sent", 0)
            summary["target_expansion_performed"] = execution.get("target_expansion_performed", False)
            summary["dns_expansion_performed"] = execution.get("dns_expansion_performed", False)
        if record.audit_type == "active_dns_inventory":
            records = record.result.get("records")
            security_records = record.result.get("security_records")
            subdomains = record.result.get("subdomains")
            zone_transfer = record.result.get("zone_transfer")
            execution = record.result.get("execution")
            if not isinstance(records, dict):
                records = {}
            if not isinstance(security_records, dict):
                security_records = {}
            if not isinstance(subdomains, dict):
                subdomains = {}
            if not isinstance(zone_transfer, dict):
                zone_transfer = {}
            if not isinstance(execution, dict):
                execution = {}
            summary["capability"] = record.result.get("capability", "active_dns_inventory")
            summary["profile"] = record.result.get("profile")
            summary["result_status"] = record.result.get("result_status", record.result.get("status"))
            summary["coverage_level"] = record.result.get("coverage_level")
            summary["target_display"] = "[REDACTED_DOMAIN]"
            summary["record_types"] = record.result.get("record_types")
            summary["record_count"] = sum(
                int(group.get("count", 0))
                for group in records.values()
                if isinstance(group, dict) and isinstance(group.get("count", 0), int)
            )
            summary["spf_present"] = bool((security_records.get("spf") or {}).get("present")) if isinstance(security_records.get("spf"), dict) else False
            summary["dmarc_present"] = bool((security_records.get("dmarc") or {}).get("present")) if isinstance(security_records.get("dmarc"), dict) else False
            summary["caa_present"] = bool((security_records.get("caa") or {}).get("present")) if isinstance(security_records.get("caa"), dict) else False
            summary["subdomain_candidates_checked"] = subdomains.get("candidates_checked", 0)
            summary["subdomain_observed_count"] = subdomains.get("count", 0)
            summary["zone_transfer_status"] = zone_transfer.get("status", "not_attempted")
            summary["zone_transfer_attempted"] = bool(zone_transfer.get("attempted", False))
            summary["zone_transfer_records_retained_count"] = zone_transfer.get("records_retained_count", 0)
            summary["dns_queries_sent"] = execution.get("dns_queries_sent", record.result.get("dns_queries_sent", 0))
            summary["subdomain_queries_sent"] = execution.get("subdomain_queries_sent", record.result.get("subdomain_queries_sent", 0))
            summary["manual_validation_required"] = True
            summary["surface_interpretation"] = "DNS configuration review indicator"
        if record.audit_type == "active_dns_osint":
            sources = record.result.get("sources")
            observed_names = record.result.get("observed_names")
            execution = record.result.get("execution")
            if not isinstance(sources, dict):
                sources = {}
            if not isinstance(observed_names, dict):
                observed_names = {}
            if not isinstance(execution, dict):
                execution = {}
            ct_source = sources.get("certificate_transparency")
            passive_dns = sources.get("passive_dns")
            if not isinstance(ct_source, dict):
                ct_source = {}
            if not isinstance(passive_dns, dict):
                passive_dns = {}
            summary["capability"] = record.result.get("capability", "active_dns_osint")
            summary["profile"] = record.result.get("profile")
            summary["result_status"] = record.result.get("result_status", record.result.get("status"))
            summary["coverage_level"] = record.result.get("coverage_level")
            summary["target_display"] = "[REDACTED_DOMAIN]"
            summary["observed_names_count"] = observed_names.get("count", 0)
            observed_count = observed_names.get("count", 0)
            if not isinstance(observed_count, int) or observed_count < 0:
                observed_count = 0
            summary["observed_names_sample"] = ["[REDACTED_DNS_NAME]" for _ in range(min(observed_count, 5))]
            summary["ct_source_status"] = ct_source.get("status", "not_attempted")
            summary["ct_names_observed_count"] = ct_source.get("names_observed_count", 0)
            summary["ct_names_retained_count"] = ct_source.get("names_retained_count", 0)
            summary["ct_truncated"] = bool(ct_source.get("truncated", False))
            summary["passive_dns_status"] = passive_dns.get("status", "not_attempted")
            summary["manual_validation_required"] = True
            summary["surface_interpretation"] = "DNS OSINT review indicator"
            summary["external_requests_sent"] = 0
            summary["ct_queries_sent"] = 0
            summary["passive_dns_queries_sent"] = 0
        return summary
    return None


def _job_status_detail(record: JobRecord) -> JobStatusDetail:
    if record.status == "queued":
        return JobStatusDetail(code="queued", message="Queued for a bounded review. Refresh to see its next state.", next_action="wait")
    if record.status == "running":
        return JobStatusDetail(code="running", message="The bounded review is running. Wait for a terminal result before starting it again.", next_action="wait")
    if record.status == "cancelling":
        return JobStatusDetail(
            code="cancelling",
            message="Cancellation is in progress. Inspectra is stopping the review and removing its execution workspace.",
            next_action="wait",
        )
    if record.status == "cancelled":
        return JobStatusDetail(
            code="cancelled",
            message="The review was cancelled and its execution workspace was removed. The retained source can be reviewed again.",
            next_action="review_and_retry",
        )
    if record.status == "completed":
        return JobStatusDetail(code="completed", message="The review completed. Open the retained result to assess coverage and findings.", next_action="view_results")
    if record.termination_reason == "application_restart" or (
        record.error and "interrupted by application restart" in record.error.lower()
    ):
        return JobStatusDetail(
            code="interrupted_after_restart",
            message="The review stopped when the application restarted. Review the retained record, then run the same snapshot again if appropriate.",
            next_action="review_and_retry",
        )
    if record.termination_reason == "application_shutdown":
        return JobStatusDetail(
            code="failed",
            message="The review stopped during an application shutdown. Confirm service health, then retry the retained snapshot.",
            next_action="review_and_retry",
        )
    if record.termination_reason == "recovery_rejected":
        return JobStatusDetail(
            code="failed",
            message="The queued review was not resumed because its retained source or execution contract no longer matched. Review the source before starting a new analysis.",
            next_action="review_and_retry",
        )
    return JobStatusDetail(
        code="failed",
        message="The review did not complete. Review the retained record, then run the same snapshot again if appropriate.",
        next_action="review_and_retry",
    )


def _redact_active_summary_text(value: str) -> str:
    redacted = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED]",
        value,
        flags=re.IGNORECASE | re.DOTALL,
    )
    redacted = re.sub(r"(?i)\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", "Authorization: [REDACTED]", redacted)
    redacted = re.sub(
        r"(?i)([?&](?:access_token|refresh_token|id_token|api_key|apikey|key|token|secret|password|passwd|pwd|session|sid|auth|authorization|jwt|bearer|sig|signature|client_secret|code|state)=)[^&#\s]+",
        lambda match: f"{match.group(1)}[REDACTED]",
        redacted,
    )
    redacted = re.sub(r"(?i)\b([a-z][a-z0-9+.-]*://)([^:\s/@;\"']+):([^@\s/;\"']+)@([^\s;\"']+)", r"\1[REDACTED]@\4", redacted)
    redacted = re.sub(
        r"(?i)\b([a-z0-9_.-]*(?:token|password|secret|api_key|apikey|client_secret)[a-z0-9_.-]*)(\s*[:=]\s*)[^\s,;]+",
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
        redacted,
    )
    return redacted.replace("PRIVATE KEY", "[REDACTED]")
