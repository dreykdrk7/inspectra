from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


FileKind = Literal["pdf", "image", "manifest", "archive"]
AuditType = Literal[
    "pdf_basic",
    "image_basic",
    "manifest_basic",
    "archive_basic",
    "project_archive_basic",
    "web_basic",
    "domain_basic",
    "subdomain_inventory_basic",
    "django_config_basic",
    "docker_config_basic",
    "secrets_review_basic",
    "node_package_config_basic",
    "ci_cd_config_basic",
    "k8s_config_basic",
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


class SubdomainInventoryRequest(BaseModel):
    root_domain: str = Field(min_length=1, max_length=253)
    subdomains: list[str] = Field(min_length=1)
    authorization_confirmed: bool = False

    @field_validator("subdomains")
    @classmethod
    def subdomain_candidates_must_be_bounded(cls, value: list[str]) -> list[str]:
        for candidate in value:
            if len(candidate) > 253:
                raise ValueError("Subdomain candidates must be 253 characters or fewer.")
        return value
