from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


FileKind = Literal["pdf", "image", "manifest", "archive"]
AuditType = Literal[
    "pdf_basic",
    "image_basic",
    "manifest_basic",
    "archive_basic",
    "project_archive_basic",
    "web_basic",
    "domain_basic",
]
JobStatus = Literal["queued", "running", "completed", "failed"]


class StoredFile(BaseModel):
    id: str
    kind: FileKind = "pdf"
    original_filename: str
    stored_filename: str
    content_type: str
    size_bytes: int
    sha256: str
    created_at: datetime


class JobRecord(BaseModel):
    id: str
    audit_type: AuditType
    file_id: str | None = None
    target_url: str | None = None
    target_domain: str | None = None
    status: JobStatus
    created_at: datetime
    updated_at: datetime
    source_file_deleted_at: datetime | None = None
    result: dict[str, Any] | None = None
    error: str | None = None


class JobCreated(BaseModel):
    job: JobRecord = Field(description="Current job state.")


class JobListItem(BaseModel):
    id: str
    audit_type: AuditType
    file_id: str | None = None
    target_url: str | None = None
    target_domain: str | None = None
    status: JobStatus
    created_at: datetime
    updated_at: datetime
    source_file_deleted_at: datetime | None = None
    summary: dict[str, Any] | None = None


class DeletedFileResponse(BaseModel):
    deleted_file: StoredFile
    associated_jobs_marked: int


class WebAuditRequest(BaseModel):
    url: str
    authorization_confirmed: bool = False


class DomainAuditRequest(BaseModel):
    domain: str
    authorization_confirmed: bool = False
