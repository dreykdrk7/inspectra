from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from uuid import uuid4

from fastapi import HTTPException, UploadFile, status
from pydantic import ValidationError

from app.config import Settings
from app.models import JobListItem, JobRecord, JobStatus, StoredFile


IDENTIFIER_PATTERN = re.compile(r"^[a-f0-9]{32}$")
UPLOAD_CHUNK_SIZE = 1024 * 1024
IMAGE_SIGNATURES = (
    ("jpeg", ".jpg", "image/jpeg", lambda data: data.startswith(b"\xff\xd8\xff")),
    ("png", ".png", "image/png", lambda data: data.startswith(b"\x89PNG\r\n\x1a\n")),
    ("webp", ".webp", "image/webp", lambda data: len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP"),
)
MANIFEST_DEFINITIONS = {
    "package.json": ("package_json", "application/json"),
    "requirements.txt": ("requirements_txt", "text/plain"),
    "pyproject.toml": ("pyproject_toml", "application/toml"),
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(f"{path.suffix}.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp_path.replace(path)


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
        _atomic_write_json(self._metadata_path(file_id), record.model_dump(mode="json"))
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
        _atomic_write_json(self._metadata_path(file_id), record.model_dump(mode="json"))
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
        _atomic_write_json(self._metadata_path(file_id), record.model_dump(mode="json"))
        return record

    def list(self) -> list[StoredFile]:
        records = [self._load_metadata_file(path) for path in self.settings.upload_dir.glob("*.json")]
        return sorted(records, key=lambda item: item.created_at, reverse=True)

    def get(self, file_id: str) -> StoredFile:
        path = self._metadata_path(file_id)
        if not path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")
        try:
            return StoredFile.model_validate_json(path.read_text(encoding="utf-8"))
        except (ValidationError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Stored file metadata is invalid.") from exc

    def delete(self, file_id: str) -> StoredFile:
        record = self.get(file_id)
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

    def _create_job(self, file_id: str, audit_type: str) -> JobRecord:
        now = utc_now()
        record = JobRecord(
            id=uuid4().hex,
            audit_type=audit_type,
            file_id=file_id,
            status="queued",
            created_at=now,
            updated_at=now,
        )
        self.save(record)
        return record

    def get(self, job_id: str) -> JobRecord:
        path = self._job_path(job_id)
        if not path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found.")
        try:
            return JobRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except (ValidationError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Stored job metadata is invalid.") from exc

    def update(self, job_id: str, *, status: JobStatus, result: dict | None = None, error: str | None = None) -> JobRecord:
        record = self.get(job_id)
        updated = record.model_copy(update={"status": status, "updated_at": utc_now(), "result": result, "error": error})
        self.save(updated)
        return updated

    def list(self) -> list[JobListItem]:
        records = [self._load_job_file(path) for path in self.settings.jobs_dir.glob("*.json")]
        records.sort(key=lambda item: item.created_at, reverse=True)
        return [self._to_list_item(record) for record in records]

    def mark_file_deleted(self, file_id: str) -> int:
        _validate_identifier(file_id, "file_id")
        deleted_at = utc_now()
        marked = 0
        for path in self.settings.jobs_dir.glob("*.json"):
            record = self._load_job_file(path)
            if record.file_id != file_id or record.source_file_deleted_at is not None:
                continue
            updated = record.model_copy(update={"source_file_deleted_at": deleted_at, "updated_at": deleted_at})
            self.save(updated)
            marked += 1
        return marked

    def save(self, record: JobRecord) -> None:
        _atomic_write_json(self._job_path(record.id), record.model_dump(mode="json"))

    def _job_path(self, job_id: str) -> Path:
        _validate_identifier(job_id, "job_id")
        return self.settings.jobs_dir / f"{job_id}.json"

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
        return summary
    if record.error:
        return {"error": record.error}
    return None
