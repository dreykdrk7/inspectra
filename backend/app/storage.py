from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import threading
from typing import Iterator
from uuid import uuid4

from fastapi import HTTPException, UploadFile, status
from pydantic import ValidationError

from app.config import Settings
from app.models import JobListItem, JobRecord, JobStatus, StoredFile

try:
    import fcntl
except ImportError:  # pragma: no cover - Linux/Docker path uses fcntl.
    fcntl = None


IDENTIFIER_PATTERN = re.compile(r"^[a-f0-9]{32}$")
UPLOAD_CHUNK_SIZE = 1024 * 1024
IMAGE_SIGNATURES = (
    ("jpeg", ".jpg", "image/jpeg", lambda data: data.startswith(b"\xff\xd8\xff")),
    ("png", ".png", "image/png", lambda data: data.startswith(b"\x89PNG\r\n\x1a\n")),
    ("webp", ".webp", "image/webp", lambda data: len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP"),
)
_FALLBACK_LOCKS: dict[Path, threading.RLock] = {}
_FALLBACK_LOCKS_GUARD = threading.Lock()
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


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(f"{path.suffix}.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp_path.replace(path)


@contextmanager
def storage_lock(settings: Settings) -> Iterator[None]:
    lock_path = settings.data_dir / ".locks" / "storage.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with _fallback_lock(lock_path):
        if fcntl is None:
            yield
            return
        with lock_path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
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

    async def save_pdf(self, upload: UploadFile) -> StoredFile:
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

    async def save_image(self, upload: UploadFile) -> StoredFile:
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

    async def save_manifest(self, upload: UploadFile) -> StoredFile:
        original_filename = Path(upload.filename or "").name
        payload = await _read_limited_upload(upload, self.settings.max_upload_bytes)
        manifest_type, content_type = _validate_manifest_upload(original_filename, payload)

        file_id = uuid4().hex
        stored_filename = f"{file_id}-{original_filename.lower()}"
        target_path = self._safe_upload_path(stored_filename)
        target_path.write_bytes(payload)

        record = StoredFile(
            id=file_id,
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

    async def save_archive(self, upload: UploadFile) -> StoredFile:
        original_filename = Path(upload.filename or "").name
        payload = await _read_limited_upload(upload, self.settings.max_upload_bytes)
        _, extension, content_type = _validate_archive_upload(original_filename, payload)

        file_id = uuid4().hex
        stored_filename = f"{file_id}{extension}"
        target_path = self._safe_upload_path(stored_filename)
        target_path.write_bytes(payload)

        record = StoredFile(
            id=file_id,
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

    def list(self) -> list[StoredFile]:
        records = [self._load_metadata_file(path) for path in self.settings.upload_dir.glob("*.json")]
        return sorted(records, key=lambda item: item.created_at, reverse=True)

    def get(self, file_id: str) -> StoredFile:
        return self._get_unlocked(file_id)

    def delete(self, file_id: str) -> StoredFile:
        with storage_lock(self.settings):
            record = self._get_unlocked(file_id)
            upload_path = self._safe_upload_path(record.stored_filename)
            metadata_path = self._metadata_path(file_id)
            upload_path.unlink(missing_ok=True)
            metadata_path.unlink(missing_ok=True)
            return record

    def relative_upload_path(self, record: StoredFile) -> str:
        return f"uploads/{record.stored_filename}"

    def _metadata_path(self, file_id: str) -> Path:
        _validate_identifier(file_id, "file_id")
        return self.settings.upload_dir / f"{file_id}.json"

    def _save_record(self, record: StoredFile) -> None:
        with storage_lock(self.settings):
            _atomic_write_json(self._metadata_path(record.id), record.model_dump(mode="json"))

    def _get_unlocked(self, file_id: str) -> StoredFile:
        path = self._metadata_path(file_id)
        if not path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")
        try:
            return StoredFile.model_validate_json(path.read_text(encoding="utf-8"))
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
            return StoredFile.model_validate_json(path.read_text(encoding="utf-8"))
        except (ValidationError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Stored file metadata is invalid: {path.name}") from exc


class JobStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def create_pdf_job(self, file_id: str) -> JobRecord:
        return self._create_job(file_id, "pdf_basic")

    def create_image_job(self, file_id: str) -> JobRecord:
        return self._create_job(file_id, "image_basic")

    def create_manifest_job(self, file_id: str) -> JobRecord:
        return self._create_job(file_id, "manifest_basic")

    def create_archive_job(self, file_id: str) -> JobRecord:
        return self._create_job(file_id, "archive_basic")

    def create_project_archive_job(self, file_id: str) -> JobRecord:
        return self._create_job(file_id, "project_archive_basic")

    def create_django_config_job(self, file_id: str) -> JobRecord:
        return self._create_job(file_id, "django_config_basic")

    def create_docker_config_job(self, file_id: str) -> JobRecord:
        return self._create_job(file_id, "docker_config_basic")

    def create_web_job(self, target_url: str) -> JobRecord:
        return self._create_job(None, "web_basic", target_url=target_url)

    def create_domain_job(self, target_domain: str) -> JobRecord:
        return self._create_job(None, "domain_basic", target_domain=target_domain)

    def create_subdomain_inventory_job(self, target_domain: str) -> JobRecord:
        return self._create_job(None, "subdomain_inventory_basic", target_domain=target_domain)

    def _create_job(
        self,
        file_id: str | None,
        audit_type: str,
        *,
        target_url: str | None = None,
        target_domain: str | None = None,
    ) -> JobRecord:
        now = utc_now()
        record = JobRecord(
            id=uuid4().hex,
            audit_type=audit_type,
            file_id=file_id,
            target_url=target_url,
            target_domain=target_domain,
            status="queued",
            created_at=now,
            updated_at=now,
        )
        with storage_lock(self.settings):
            self._save_unlocked(record)
        return record

    def get(self, job_id: str) -> JobRecord:
        return self._get_unlocked(job_id)

    def update(self, job_id: str, *, status: JobStatus, result: dict | None = None, error: str | None = None) -> JobRecord:
        with storage_lock(self.settings):
            record = self._get_unlocked(job_id)
            updated = record.model_copy(update={"status": status, "updated_at": utc_now(), "result": result, "error": error})
            self._save_unlocked(updated)
            return updated

    def list(self) -> list[JobListItem]:
        records = [self._load_job_file(path) for path in self.settings.jobs_dir.glob("*.json")]
        records.sort(key=lambda item: item.created_at, reverse=True)
        return [self._to_list_item(record) for record in records]

    def mark_file_deleted(self, file_id: str) -> int:
        _validate_identifier(file_id, "file_id")
        deleted_at = utc_now()
        marked = 0
        with storage_lock(self.settings):
            for path in self.settings.jobs_dir.glob("*.json"):
                record = self._load_job_file(path)
                if record.file_id != file_id or record.source_file_deleted_at is not None:
                    continue
                updated = record.model_copy(update={"source_file_deleted_at": deleted_at, "updated_at": deleted_at})
                self._save_unlocked(updated)
                marked += 1
        return marked

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
        try:
            return JobRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except (ValidationError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Stored job metadata is invalid.") from exc

    def _save_unlocked(self, record: JobRecord) -> None:
        path = self._job_path(record.id)
        payload = self._merge_existing_record(path, record).model_dump(mode="json")
        _atomic_write_json(path, payload)

    def _merge_existing_record(self, path: Path, record: JobRecord) -> JobRecord:
        if not path.exists():
            return record
        existing = self._load_job_file(path)
        update: dict = {}
        if record.source_file_deleted_at is None and existing.source_file_deleted_at is not None:
            update["source_file_deleted_at"] = existing.source_file_deleted_at
        if update:
            return record.model_copy(update=update)
        return record

    def _load_job_file(self, path: Path) -> JobRecord:
        try:
            return JobRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except (ValidationError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Stored job metadata is invalid: {path.name}") from exc

    def _to_list_item(self, record: JobRecord) -> JobListItem:
        return JobListItem(
            id=record.id,
            audit_type=record.audit_type,
            file_id=record.file_id,
            target_url=record.target_url,
            target_domain=record.target_domain,
            status=record.status,
            created_at=record.created_at,
            updated_at=record.updated_at,
            source_file_deleted_at=record.source_file_deleted_at,
            summary=_job_summary(record),
        )


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
            summary["services_detected"] = len(record.result.get("compose_services") or [])
            summary["findings_count"] = manifest_summary.get("findings_count")
            summary["secrets_redacted_count"] = manifest_summary.get("secrets_redacted_count")
            summary["truncated"] = manifest_summary.get("truncated")
            summary["errors_count"] = len(record.result.get("errors") or [])
        return summary
    if record.error:
        return {"error": record.error}
    return None
