from __future__ import annotations

from datetime import datetime
import hashlib
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_serializer, model_validator


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
    "terraform_config_basic",
    "nginx_config_basic",
    "compose_config_basic",
    "database_config_basic",
    "sql_database_config_basic",
    "redis_config_basic",
    "active_network_dry_run",
    "active_http_header_probe",
    "active_http_basic_header_review",
    "active_nmap_basic",
    "active_tls_basic",
    "active_dns_inventory",
    "active_dns_osint",
]
JobStatus = Literal["queued", "running", "cancelling", "cancelled", "completed", "failed"]
JobTerminationReason = Literal[
    "completed",
    "cancelled_by_owner",
    "authorization_revoked",
    "application_restart",
    "application_shutdown",
    "recovery_rejected",
    "runner_timeout",
    "runner_resource_limit",
    "runner_unavailable",
    "runner_contract_invalid",
    "workspace_error",
    "internal_error",
]
AuthMode = Literal[
    "trusted_local_no_auth",
    "self_hosted_single_admin",
    "private_team_lightweight_users",
    "public_community_limited_instance",
]
TeamRole = Literal["administrator", "maintainer", "reader"]
FindingDecisionStatus = Literal["open", "in_review", "accepted", "false_positive", "resolved"]


def _materialize_organization_boundary(record: BaseModel):
    """Keep the historical owner field and explicit organization scope aligned."""

    owner_id = getattr(record, "owner_id", None)
    organization_id = getattr(record, "organization_id", None)
    if owner_id is not None and organization_id is not None and owner_id != organization_id:
        raise ValueError("Organization boundary does not match the persisted owner boundary.")
    if organization_id is None and owner_id is not None:
        setattr(record, "organization_id", owner_id)
    revision_values = (
        getattr(record, "active_authorization_revision_id", None),
        getattr(record, "active_authorization_revision_digest_sha256", None),
        getattr(record, "active_authorization_revision_sequence", None),
    )
    if any(value is not None for value in revision_values) and not all(value is not None for value in revision_values):
        raise ValueError("Active authorization revision metadata must be complete.")
    if getattr(record, "active_asset_id", None) is None and any(value is not None for value in revision_values):
        raise ValueError("Active authorization revision metadata requires an active asset.")
    return record


class StoredFile(BaseModel):
    id: str
    owner_id: str | None = None
    organization_id: str | None = None
    kind: FileKind = "pdf"
    original_filename: str
    stored_filename: str
    content_type: str
    size_bytes: int
    sha256: str
    created_at: datetime

    @model_validator(mode="after")
    def organization_matches_owner_boundary(self):
        return _materialize_organization_boundary(self)


class JobExecutionProfile(BaseModel):
    """Safe, immutable execution context captured when a job is created."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    profile_name: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    ruleset_version: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    max_upload_bytes: int = Field(gt=0)
    audit_max_concurrency: int = Field(gt=0)
    audit_max_inflight_jobs: int | None = Field(default=None, gt=0)
    audit_max_inflight_jobs_per_owner: int | None = Field(default=None, gt=0)
    timeout_seconds: float | None = Field(default=None, gt=0)
    workspace_policy: Literal[
        "isolated_copy_cleanup_v1",
        "isolated_copy_stream_worker_v1",
        "isolated_stream_worker_v1",
        "shared_source_v1",
    ] | None = None
    workspace_max_bytes: int | None = Field(default=None, gt=0)
    worker_contract_version: str | None = Field(default=None, min_length=1, max_length=32, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    worker_source_transport: Literal["inline_base64_sha256_v1"] | None = None
    worker_lifecycle: Literal["ephemeral_subprocess"] | None = None
    worker_max_concurrency: int | None = Field(default=None, gt=0)
    worker_cpu_seconds: int | None = Field(default=None, gt=0)
    worker_memory_bytes: int | None = Field(default=None, gt=0)
    worker_max_result_bytes: int | None = Field(default=None, gt=0)
    worker_max_file_bytes: int | None = Field(default=None, gt=0)
    worker_max_open_files: int | None = Field(default=None, gt=0)
    worker_max_processes: int | None = Field(default=None, gt=0)
    max_total_uncompressed_bytes: int | None = Field(default=None, gt=0)
    max_archive_entries: int | None = Field(default=None, gt=0)
    max_manifests: int | None = Field(default=None, gt=0)
    max_manifest_bytes: int | None = Field(default=None, gt=0)
    max_total_manifest_bytes: int | None = Field(default=None, gt=0)
    max_lockfiles: int | None = Field(default=None, gt=0)
    max_lockfile_packages: int | None = Field(default=None, gt=0)
    max_lockfile_edges: int | None = Field(default=None, gt=0)
    license_policy_contract_version: str | None = Field(default=None, min_length=1, max_length=32, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    license_policy_denied_identifiers: tuple[str, ...] = Field(default_factory=tuple, max_length=64)


class JobRecord(BaseModel):
    id: str
    owner_id: str | None = None
    organization_id: str | None = None
    project_id: str | None = None
    active_asset_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    active_authorization_contract: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
    active_authorization_revision_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    active_authorization_revision_digest_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    active_authorization_revision_sequence: int | None = Field(default=None, ge=1, le=64)
    active_execution_port: int | None = Field(default=None, ge=1, le=65535)
    active_execution_phase: Literal["admitted", "waiting_for_runner", "executing", "normalizing", "terminal"] | None = None
    active_execution_idempotency_key_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    source_sha256: str | None = None
    sbom_revision_key_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    analysis_profile: str | None = None
    execution_profile: JobExecutionProfile | None = None
    audit_type: AuditType
    file_id: str | None = None
    target_url: str | None = None
    target_domain: str | None = None
    status: JobStatus
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    cancellation_requested_at: datetime | None = None
    termination_reason: JobTerminationReason | None = None
    retry_of_job_id: str | None = None
    recovery_count: int = Field(default=0, ge=0)
    last_recovered_at: datetime | None = None
    source_file_deleted_at: datetime | None = None
    result_integrity_status: Literal["valid", "unknown"] = "unknown"
    result: dict[str, Any] | None = None
    error: str | None = None

    @model_validator(mode="after")
    def organization_matches_owner_boundary(self):
        return _materialize_organization_boundary(self)


class JobDetailView(BaseModel):
    """Job projection that withholds source identity for project analyses."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    owner_id: str | None = None
    organization_id: str | None = None
    project_id: str | None = None
    active_asset_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    active_authorization_contract: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
    active_authorization_revision_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    active_authorization_revision_digest_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    active_authorization_revision_sequence: int | None = Field(default=None, ge=1, le=64)
    active_execution_port: int | None = Field(default=None, ge=1, le=65535)
    active_execution_phase: Literal["admitted", "waiting_for_runner", "executing", "normalizing", "terminal"] | None = None
    source_reference: str | None = Field(default=None, pattern=r"^snapshot-[a-f0-9]{16}$")
    analysis_profile: str | None = None
    execution_profile: JobExecutionProfile | None = None
    audit_type: AuditType
    file_id: str | None = None
    target_url: str | None = None
    target_domain: str | None = None
    status: JobStatus
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    cancellation_requested_at: datetime | None = None
    termination_reason: JobTerminationReason | None = None
    retry_of_job_id: str | None = None
    recovery_count: int = Field(default=0, ge=0)
    last_recovered_at: datetime | None = None
    source_file_deleted_at: datetime | None = None
    result_integrity_status: Literal["valid", "unknown"] = "unknown"
    result: dict[str, Any] | None = None
    error: str | None = None

    @model_validator(mode="before")
    @classmethod
    def from_stored_job(cls, value):
        if isinstance(value, JobRecord):
            projected = value.model_dump(exclude={"source_sha256", "sbom_revision_key_sha256", "active_execution_idempotency_key_sha256"})
            projected["source_reference"] = opaque_source_reference(value.file_id) if value.project_id else None
            if value.project_id is not None:
                projected["file_id"] = None
            return projected
        return value

    @model_validator(mode="after")
    def organization_matches_owner_boundary(self):
        return _materialize_organization_boundary(self)

    @model_serializer(mode="wrap")
    def withhold_project_source_id(self, handler):
        serialized = handler(self)
        if self.project_id is not None:
            serialized.pop("file_id", None)
        return serialized


class JobCreated(BaseModel):
    job: JobRecord = Field(description="Current job state.")


class JobStatusDetail(BaseModel):
    code: Literal["queued", "running", "cancelling", "cancelled", "completed", "interrupted_after_restart", "failed"]
    message: str
    next_action: Literal["wait", "view_results", "review_and_retry"]


class JobListItem(BaseModel):
    id: str
    owner_id: str | None = None
    organization_id: str | None = None
    project_id: str | None = None
    active_asset_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    active_authorization_contract: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
    active_authorization_revision_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    active_authorization_revision_digest_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    active_authorization_revision_sequence: int | None = Field(default=None, ge=1, le=64)
    active_execution_port: int | None = Field(default=None, ge=1, le=65535)
    active_execution_phase: Literal["admitted", "waiting_for_runner", "executing", "normalizing", "terminal"] | None = None
    source_reference: str | None = Field(default=None, pattern=r"^snapshot-[a-f0-9]{16}$")
    analysis_profile: str | None = None
    execution_profile: JobExecutionProfile | None = None
    audit_type: AuditType
    file_id: str | None = None
    target_url: str | None = None
    target_domain: str | None = None
    status: JobStatus
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    cancellation_requested_at: datetime | None = None
    termination_reason: JobTerminationReason | None = None
    retry_of_job_id: str | None = None
    recovery_count: int = Field(default=0, ge=0)
    last_recovered_at: datetime | None = None
    source_file_deleted_at: datetime | None = None
    result_integrity_status: Literal["valid", "unknown"] = "unknown"
    summary: dict[str, Any] | None = None
    status_detail: JobStatusDetail

    @model_validator(mode="after")
    def organization_matches_owner_boundary(self):
        return _materialize_organization_boundary(self)

    @model_serializer(mode="wrap")
    def withhold_project_source_id(self, handler):
        serialized = handler(self)
        if self.project_id is not None:
            serialized.pop("file_id", None)
        return serialized


class JobPageRequest(BaseModel):
    """Closed filters for a bounded, owner-scoped job history page."""

    model_config = ConfigDict(extra="forbid")

    page_size: int = Field(default=50, ge=1, le=100)
    cursor: str | None = Field(default=None, min_length=1, max_length=512)
    status: JobStatus | None = None
    audit_type: AuditType | None = None
    project_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")


class ActiveExecutionPageRequest(BaseModel):
    """Closed pagination input for one already-authorized Active asset."""

    model_config = ConfigDict(extra="forbid")

    page_size: int = Field(default=50, ge=1, le=100)
    cursor: str | None = Field(default=None, min_length=1, max_length=512)


class JobPage(BaseModel):
    """A bounded page; totals are exact for the supplied closed filters."""

    contract_version: Literal["2026-09-08.1"] = "2026-09-08.1"
    items: list[JobListItem] = Field(max_length=100)
    returned_count: int = Field(ge=0, le=100)
    total_count: int = Field(ge=0)
    has_more: bool
    next_cursor: str | None = Field(default=None, max_length=512)


class DeletedFileResponse(BaseModel):
    deleted_file: StoredFile
    associated_jobs_marked: int


class DeletedJobResponse(BaseModel):
    job_id: str
    deleted: bool


class ProjectCreateRequest(BaseModel):
    """Create a project only from a previously validated archive upload."""

    model_config = ConfigDict(extra="forbid")

    source_file_id: str = Field(min_length=1, max_length=64)
    authorization_confirmed: Literal[True]
    name: str | None = Field(default=None, max_length=120)

    @field_validator("name")
    @classmethod
    def project_name_must_be_safe_display_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("Project name must not be blank.")
        if any(ord(character) < 32 or character in {"/", "\\"} for character in normalized):
            raise ValueError("Project name contains unsupported characters.")
        return normalized


class ProjectSnapshotCreateRequest(BaseModel):
    """Attach one authorized archive as the next immutable project snapshot."""

    model_config = ConfigDict(extra="forbid")

    source_file_id: str = Field(min_length=1, max_length=64)
    idempotency_key: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    authorization_confirmed: Literal[True]


class ProjectAnalysisCreateRequest(BaseModel):
    """Repeat a retained snapshot, optionally linking a terminal failed attempt."""

    model_config = ConfigDict(extra="forbid")

    retry_of_analysis_id: str | None = Field(default=None, min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")


class ProjectBaselineSetRequest(BaseModel):
    """Explicitly select one retained execution as a project's regression baseline."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: str = Field(min_length=1, max_length=64)
    baseline_confirmed: Literal[True]


class ProjectArchivePreflightCapability(BaseModel):
    """One static passive capability without a source path or source content."""

    name: str = Field(min_length=1, max_length=80)
    ecosystem: str = Field(min_length=1, max_length=32)
    coverage: str = Field(min_length=1, max_length=240)


class PassiveAnalysisProfileRule(BaseModel):
    """One stable rule family exposed by the closed passive profile catalog."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_]*$")
    category: Literal["archive_safety", "dependency_hygiene", "package_execution", "coverage", "sensitive_data", "license"]
    applies_to: list[str] = Field(min_length=1, max_length=8)
    description: str = Field(min_length=1, max_length=240)


class PassiveAnalysisProfile(BaseModel):
    """Source-free declaration of one selectable project analysis profile."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    profile_name: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=120)
    ruleset_version: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    safe_default: bool
    selection_mode: Literal["manifest_driven_closed_catalog"]
    execution_mode: Literal["passive_no_project_execution"]
    network_access: Literal["disabled"]
    supported_stacks: list[str] = Field(min_length=1, max_length=8)
    rules: list[PassiveAnalysisProfileRule] = Field(min_length=1, max_length=16)
    exclusions: list[str] = Field(min_length=1, max_length=12)


class ProjectArchivePreflightResponse(BaseModel):
    """Safe, aggregate capabilities available before an archive upload."""

    contract_version: str = Field(min_length=1, max_length=32)
    status: Literal["available"]
    accepted_archive_formats: list[str] = Field(min_length=1, max_length=8)
    upload_limit_bytes: int = Field(gt=0)
    analysis_profile: PassiveAnalysisProfile
    execution_profile: JobExecutionProfile
    supported_manifests: list[ProjectArchivePreflightCapability] = Field(min_length=1, max_length=12)
    exact_resolution: list[ProjectArchivePreflightCapability] = Field(min_length=1, max_length=12)
    detected_not_resolved: list[str] = Field(max_length=8)
    limitations: list[str] = Field(min_length=1, max_length=8)
    boundaries: list[str] = Field(min_length=1, max_length=8)


StoredProjectSourceChannel = Literal["archive_upload", "git_cli", "ci", "sbom"]
ProjectSourceChannel = Literal["archive_upload", "git_cli", "ci", "sbom", "unknown_git_or_ci"]


class ProjectSourceSnapshot(BaseModel):
    id: str
    source_file_id: str
    source_filename: str
    source_sha256: str
    source_commit_sha: str | None = Field(default=None, pattern=r"^[a-f0-9]{40,64}$")
    source_branch: str | None = Field(default=None, min_length=1, max_length=160)
    # None is retained only for records written before source-channel attestation.
    # New writes always set a server-derived closed value.
    source_channel: StoredProjectSourceChannel | None = None
    source_file_deleted_at: datetime | None = None
    created_at: datetime


class ProjectResponsibilityRevision(BaseModel):
    """Private, versioned responsibility state without a copied username."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence: int = Field(ge=1, le=100)
    responsible_user_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    state: Literal["assigned", "manually_unassigned", "membership_revoked"]
    changed_by_user_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    changed_at: datetime

    @model_validator(mode="after")
    def assigned_state_has_one_identity(self):
        if (self.state == "assigned") != (self.responsible_user_id is not None):
            raise ValueError("Project responsibility state is inconsistent.")
        return self


def effective_project_source_channel(snapshot: ProjectSourceSnapshot) -> ProjectSourceChannel:
    """Return conservative provenance for new and pre-attestation snapshots."""

    if snapshot.source_channel is not None:
        return snapshot.source_channel
    if snapshot.source_commit_sha is not None:
        return "unknown_git_or_ci"
    if snapshot.source_filename == "sbom.json":
        return "sbom"
    return "archive_upload"


class ProjectRecord(BaseModel):
    id: str
    owner_id: str | None = None
    organization_id: str | None = None
    name: str
    source_file_id: str
    source_filename: str
    source_sha256: str
    source_file_deleted_at: datetime | None = None
    latest_job_id: str | None = None
    baseline_analysis_id: str | None = None
    baseline_version: int = Field(default=0, ge=0)
    baseline_updated_at: datetime | None = None
    analysis_count: int = Field(default=0, ge=0)
    source_snapshots: list[ProjectSourceSnapshot] = Field(default_factory=list)
    responsibility_revisions: list[ProjectResponsibilityRevision] = Field(
        default_factory=list,
        max_length=100,
    )
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def organization_matches_owner_boundary(self):
        for expected, revision in enumerate(self.responsibility_revisions, start=1):
            if revision.sequence != expected:
                raise ValueError("Project responsibility revision sequence is invalid.")
        return _materialize_organization_boundary(self)


class ProjectResponsibilityView(BaseModel):
    """Current responsibility exposed only inside the owner-scoped project view."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: Literal["assigned", "unassigned", "unassigned_attention"] = "unassigned"
    responsible_user_id: str | None = Field(default=None, max_length=128)
    revision: int = Field(default=0, ge=0, le=100)
    updated_at: datetime | None = None


def current_project_responsibility(record: ProjectRecord) -> ProjectResponsibilityView:
    if not record.responsibility_revisions:
        return ProjectResponsibilityView()
    latest = record.responsibility_revisions[-1]
    return ProjectResponsibilityView(
        state=(
            "assigned"
            if latest.state == "assigned"
            else "unassigned_attention"
            if latest.state == "membership_revoked"
            else "unassigned"
        ),
        responsible_user_id=latest.responsible_user_id,
        revision=latest.sequence,
        updated_at=latest.changed_at,
    )


def opaque_source_reference(source_file_id: str | None) -> str | None:
    """Derive a short stable presentation token without exposing an ID or content hash."""

    if not isinstance(source_file_id, str) or not re.fullmatch(r"[a-f0-9]{32}", source_file_id):
        return None
    digest = hashlib.sha256(f"inspectra-source-reference-v1:{source_file_id}".encode("ascii")).hexdigest()
    return f"snapshot-{digest[:16]}"


class StoredFileView(BaseModel):
    """Files-area projection that can map an upload to a safe project reference."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    owner_id: str | None = None
    organization_id: str | None = None
    source_reference: str = Field(pattern=r"^snapshot-[a-f0-9]{16}$")
    kind: FileKind = "pdf"
    original_filename: str
    stored_filename: str
    content_type: str
    size_bytes: int
    sha256: str
    created_at: datetime

    @model_validator(mode="before")
    @classmethod
    def from_stored_file(cls, value):
        if isinstance(value, StoredFile):
            reference = opaque_source_reference(value.id)
            if reference is None:
                raise ValueError("Source reference is unavailable.")
            return {**value.model_dump(), "source_reference": reference}
        return value

    @model_validator(mode="after")
    def organization_matches_owner_boundary(self):
        return _materialize_organization_boundary(self)


def _legacy_project_name_from_filename(source_filename: str) -> str:
    normalized = source_filename.replace("/", " ").replace("\\", " ")
    normalized = "".join(character if ord(character) >= 32 else " " for character in normalized).strip()
    for suffix in (".tar.gz", ".tgz", ".zip", ".tar"):
        if normalized.lower().endswith(suffix):
            normalized = normalized[: -len(suffix)]
            break
    return " ".join(normalized.split())[:120] or "Untitled project"


class ProjectSourceSnapshotView(BaseModel):
    """Owner-scoped snapshot metadata safe for product views and integrations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    source_reference: str
    source_commit_sha: str | None = None
    source_branch: str | None = None
    source_channel: ProjectSourceChannel
    source_file_deleted_at: datetime | None = None
    created_at: datetime

    @model_validator(mode="before")
    @classmethod
    def from_stored_snapshot(cls, value):
        if isinstance(value, ProjectSourceSnapshot):
            reference = opaque_source_reference(value.source_file_id)
            if reference is None:
                raise ValueError("Project source reference is unavailable.")
            return {
                "id": value.id,
                "source_reference": reference,
                "source_commit_sha": value.source_commit_sha,
                "source_branch": value.source_branch,
                "source_channel": effective_project_source_channel(value),
                "source_file_deleted_at": value.source_file_deleted_at,
                "created_at": value.created_at,
            }
        return value


class ProjectView(BaseModel):
    """Public project projection that withholds all internal source identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_metadata_contract_version: Literal["2026-09-06.1", "2026-09-09.2"] = "2026-09-09.2"
    source_name_disclosure: Literal["withheld_use_files_view"] = "withheld_use_files_view"
    source_digest_disclosure: Literal["retained_server_side"] = "retained_server_side"
    id: str
    owner_id: str | None = None
    organization_id: str | None = None
    name: str
    source_type: Literal["archive", "sbom"] = "archive"
    source_reference: str
    source_file_deleted_at: datetime | None = None
    latest_job_id: str | None = None
    baseline_analysis_id: str | None = None
    baseline_version: int = Field(default=0, ge=0)
    baseline_updated_at: datetime | None = None
    analysis_count: int = Field(default=0, ge=0)
    responsibility: ProjectResponsibilityView = Field(
        default_factory=ProjectResponsibilityView
    )
    source_snapshots: list[ProjectSourceSnapshotView] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="before")
    @classmethod
    def from_stored_project(cls, value):
        if isinstance(value, ProjectRecord):
            reference = opaque_source_reference(value.source_file_id)
            if reference is None:
                raise ValueError("Project source reference is unavailable.")
            name = value.name
            if name == _legacy_project_name_from_filename(value.source_filename):
                project_suffix = value.id[:8] if re.fullmatch(r"[a-f0-9]{32}", value.id) else "private"
                name = f"Project {project_suffix}"
            return {
                "id": value.id,
                "owner_id": value.owner_id,
                "organization_id": value.organization_id,
                "name": name,
                "source_type": "sbom" if value.source_filename == "sbom.json" else "archive",
                "source_reference": reference,
                "source_file_deleted_at": value.source_file_deleted_at,
                "latest_job_id": value.latest_job_id,
                "baseline_analysis_id": value.baseline_analysis_id,
                "baseline_version": value.baseline_version,
                "baseline_updated_at": value.baseline_updated_at,
                "analysis_count": value.analysis_count,
                "responsibility": current_project_responsibility(value),
                "source_snapshots": value.source_snapshots,
                "created_at": value.created_at,
                "updated_at": value.updated_at,
            }
        return value


class ProjectSummary(BaseModel):
    project: ProjectView
    latest_job: JobListItem | None = None


class ProjectPageRequest(BaseModel):
    """Closed input for the bounded owner-scoped project listing."""

    model_config = ConfigDict(extra="forbid")

    page_size: int = Field(default=50, ge=1, le=100)
    cursor: str | None = Field(default=None, min_length=1, max_length=512)


class ProjectResponsibilityUpdateRequest(BaseModel):
    """Optimistic, explicit update of the accountable project member."""

    model_config = ConfigDict(extra="forbid")

    responsible_user_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    expected_updated_at: datetime
    assignment_confirmed: Literal[True]


class ProjectPage(BaseModel):
    """A stable page backed only by opaque private index fields."""

    contract_version: Literal["2026-09-09.1"] = "2026-09-09.1"
    items: list[ProjectSummary] = Field(max_length=100)
    returned_count: int = Field(ge=0, le=100)
    total_count: int = Field(ge=0)
    has_more: bool
    next_cursor: str | None = Field(default=None, max_length=512)


ProjectPortfolioPriority = Literal["urgent", "high", "review", "monitor"]
ProjectPortfolioSourceType = Literal["archive", "git_or_ci", "sbom"]
ProjectPortfolioOperationalState = Literal[
    "no_analysis",
    "queued",
    "running",
    "cancelling",
    "cancelled",
    "failed",
    "completed",
]


class ProjectPortfolioSearchRequest(BaseModel):
    """Closed, body-only filters for one owner-scoped portfolio snapshot."""

    model_config = ConfigDict(extra="forbid")

    page_size: int = Field(default=24, ge=1, le=100)
    cursor: str | None = Field(default=None, min_length=1, max_length=512)
    search: str | None = Field(default=None, max_length=120)
    search_mode: Literal["prefix", "exact"] = "prefix"
    priority: ProjectPortfolioPriority | None = None
    severity: Literal["critical", "high", "medium", "low"] | None = None
    source_type: ProjectPortfolioSourceType | None = None
    operational_state: ProjectPortfolioOperationalState | None = None
    coverage: Literal["complete", "partial", "unknown", "lost"] | None = None
    public_intelligence: Literal[
        "fresh", "stale", "partial", "failed", "disabled", "not_requested"
    ] | None = None
    baseline: Literal["available", "missing"] | None = None
    responsibility: Literal["assigned", "multiple", "unassigned"] | None = None
    sort: Literal["priority", "name", "updated"] = "priority"

    @field_validator("search")
    @classmethod
    def portfolio_search_must_be_safe_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = " ".join(value.strip().split())
        if not normalized:
            return None
        if any(ord(character) < 32 or character in {"/", "\\"} for character in normalized):
            raise ValueError("Portfolio search contains unsupported characters.")
        return normalized


class ProjectPortfolioFindingCounts(BaseModel):
    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    informational: int = Field(default=0, ge=0)
    kev: int = Field(default=0, ge=0)
    local: int = Field(default=0, ge=0)
    public: int = Field(default=0, ge=0)


class ProjectPortfolioChangeCounts(BaseModel):
    state: Literal["ready", "baseline_is_latest", "missing_baseline", "not_comparable"]
    new: int = Field(default=0, ge=0)
    persistent: int = Field(default=0, ge=0)
    resolved: int = Field(default=0, ge=0)
    public_new: int = Field(default=0, ge=0)
    public_persistent: int = Field(default=0, ge=0)
    public_resolved: int = Field(default=0, ge=0)


class ProjectPortfolioCoverage(BaseModel):
    state: Literal["complete", "partial", "unknown", "lost"]
    current: ProjectAnalysisCoverage | None = None
    comparison: ProjectAnalysisCoverageComparison | None = None


class ProjectPortfolioResponsibility(BaseModel):
    state: Literal["assigned", "multiple", "unassigned"]
    active_assignees: list[str] = Field(default_factory=list, max_length=5)
    active_assignee_count: int = Field(default=0, ge=0)
    inactive_assignment_count: int = Field(default=0, ge=0)
    truncated: bool = False


class ProjectStableResponsibility(BaseModel):
    """Accountable project owner, deliberately separate from finding assignees."""

    state: Literal["assigned", "unassigned", "unassigned_attention"] = "unassigned"
    responsible_username: str | None = Field(default=None, max_length=64)
    revision: int = Field(default=0, ge=0, le=100)


class ProjectPortfolioItem(BaseModel):
    project: ProjectView
    latest_job: JobListItem | None = None
    latest_completed_analysis: JobListItem | None = None
    priority: ProjectPortfolioPriority
    priority_reasons: list[
        Literal[
            "known_exploited",
            "critical_findings",
            "latest_analysis_failed",
            "coverage_lost",
            "high_findings",
            "new_findings",
            "analysis_incomplete",
            "public_intelligence_stale",
            "public_intelligence_failed",
            "exception_review_due",
            "pending_triage",
            "no_baseline",
            "no_recent_analysis",
            "no_completed_analysis",
        ]
    ] = Field(default_factory=list)
    finding_counts: ProjectPortfolioFindingCounts
    changes: ProjectPortfolioChangeCounts
    coverage: ProjectPortfolioCoverage
    public_intelligence_state: Literal[
        "fresh", "stale", "partial", "failed", "disabled", "not_requested"
    ]
    public_sources: list[PublicVulnerabilitySourceFreshness] = Field(default_factory=list, max_length=4)
    source_type: ProjectPortfolioSourceType
    source_type_detail: Literal[
        "uploaded_archive",
        "normalized_sbom",
        "attested_git_cli",
        "attested_ci",
        "commit_attributed_channel_ambiguous",
    ]
    operational_state: ProjectPortfolioOperationalState
    pending_actions: int = Field(default=0, ge=0)
    exceptions_due: int = Field(default=0, ge=0)
    exceptions_overdue: int = Field(default=0, ge=0)
    responsibility: ProjectPortfolioResponsibility
    project_responsibility: ProjectStableResponsibility = Field(
        default_factory=ProjectStableResponsibility
    )
    last_comparable_analysis_at: datetime | None = None
    limitations: list[str] = Field(default_factory=list, max_length=12)


class ProjectPortfolioSummary(BaseModel):
    total_projects: int = Field(ge=0)
    filtered_projects: int = Field(ge=0)
    urgent_projects: int = Field(ge=0)
    high_priority_projects: int = Field(ge=0)
    projects_with_kev: int = Field(ge=0)
    projects_without_baseline: int = Field(ge=0)
    projects_with_partial_data: int = Field(ge=0)
    stale_or_failed_intelligence: int = Field(ge=0)
    pending_actions: int = Field(ge=0)


class ProjectPortfolioPage(BaseModel):
    contract_version: Literal["2026-09-10.2"] = "2026-09-10.2"
    snapshot_at: datetime
    items: list[ProjectPortfolioItem] = Field(max_length=100)
    returned_count: int = Field(ge=0, le=100)
    total_count: int = Field(ge=0)
    has_more: bool
    next_cursor: str | None = Field(default=None, max_length=512)
    summary: ProjectPortfolioSummary
    priority_model: Literal["closed_signals_no_opaque_score"] = "closed_signals_no_opaque_score"
    portfolio_complete: bool = True
    limitations: list[str] = Field(default_factory=list, max_length=8)


RemediationPriority = Literal["urgent", "high", "review"]
RemediationEvidenceKind = Literal["public_vulnerability", "local_finding"]


class RemediationSearchRequest(BaseModel):
    """Closed, owner-scoped filters for the cross-project remediation inbox."""

    model_config = ConfigDict(extra="forbid")

    page_size: int = Field(default=24, ge=1, le=100)
    cursor: str | None = Field(default=None, min_length=1, max_length=512)
    search: str | None = Field(default=None, max_length=120)
    search_mode: Literal["prefix", "exact"] = "prefix"
    priority: RemediationPriority | None = None
    evidence_kind: RemediationEvidenceKind | None = None
    ecosystem: Literal["npm", "pypi", "go", "cargo", "composer", "maven", "nuget"] | None = None
    dependency_scope: Literal["direct", "transitive", "optional", "unknown"] | None = None
    workflow_state: FindingDecisionStatus | Literal["awaiting_reanalysis", "still_detected"] | None = None
    sort: Literal["priority", "component", "projects"] = "priority"

    @field_validator("search")
    @classmethod
    def remediation_search_must_be_safe_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = " ".join(value.strip().split())
        if not normalized:
            return None
        if any(ord(character) < 32 or character in {"/", "\\"} for character in normalized):
            raise ValueError("Remediation search contains unsupported characters.")
        return normalized


class RemediationOccurrence(BaseModel):
    project: ProjectView
    analysis: JobListItem
    finding_id: str = Field(min_length=32, max_length=96)
    rule_id: str = Field(min_length=1, max_length=160)
    evidence_kind: RemediationEvidenceKind
    observed_version: str | None = Field(default=None, max_length=256)
    dependency_scope: Literal["direct", "transitive", "optional", "unknown"]
    relationship_status: Literal["reported", "not_reported", "truncated", "not_applicable"]
    workflow_state: FindingDecisionStatus | Literal["awaiting_reanalysis", "still_detected"]
    workflow_mutable: bool = True
    assignee_username: str | None = Field(default=None, max_length=64)
    review_at: datetime | None = None
    is_new: bool | None = None
    coverage_state: Literal["complete", "partial", "unknown", "lost"]


class RemediationWorkflowCounts(BaseModel):
    """Closed counters; clients must not infer states from arbitrary keys."""

    model_config = ConfigDict(extra="forbid")

    open: int = Field(default=0, ge=0)
    in_review: int = Field(default=0, ge=0)
    accepted: int = Field(default=0, ge=0)
    false_positive: int = Field(default=0, ge=0)
    resolved: int = Field(default=0, ge=0)
    awaiting_reanalysis: int = Field(default=0, ge=0)
    still_detected: int = Field(default=0, ge=0)


class RemediationActionGroup(BaseModel):
    id: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    evidence_kind: RemediationEvidenceKind
    title: str = Field(min_length=1, max_length=240)
    ecosystem: Literal["npm", "pypi", "go", "cargo", "composer", "maven", "nuget"] | None = None
    component_name: str | None = Field(default=None, max_length=256)
    advisory_ids: list[str] = Field(default_factory=list, max_length=32)
    observed_versions: list[str] = Field(default_factory=list, max_length=32)
    affected_ranges: list[PublicVulnerabilityAffectedRange] = Field(default_factory=list, max_length=64)
    fixed_versions: list[str] = Field(default_factory=list, max_length=32)
    recommended_fixed_version: str | None = Field(default=None, max_length=256)
    recommendation: str = Field(min_length=1, max_length=2_000)
    priority: RemediationPriority
    priority_reasons: list[
        Literal[
            "known_exploited",
            "critical",
            "high",
            "source_conflict",
            "new_finding",
            "direct_dependency",
            "coverage_incomplete",
            "exception_review_due",
            "awaiting_reanalysis",
        ]
    ] = Field(default_factory=list, max_length=9)
    highest_severity: Literal["none", "low", "medium", "high", "critical", "unknown"]
    known_exploited: bool = False
    source_conflict: bool = False
    exposure_state: Literal["not_assessed"] = "not_assessed"
    dependency_scopes: list[Literal["direct", "transitive", "optional", "unknown"]] = Field(
        default_factory=list, max_length=4
    )
    affected_project_count: int = Field(ge=1)
    occurrence_count: int = Field(ge=1)
    occurrences: list[RemediationOccurrence] = Field(max_length=100)
    occurrences_truncated: bool = False
    workflow_counts: RemediationWorkflowCounts = Field(default_factory=RemediationWorkflowCounts)
    limitations: list[str] = Field(default_factory=list, max_length=12)


class RemediationSummary(BaseModel):
    total_groups: int = Field(ge=0)
    filtered_groups: int = Field(ge=0)
    urgent_groups: int = Field(ge=0)
    high_groups: int = Field(ge=0)
    projects_affected: int = Field(ge=0)
    known_exploited_groups: int = Field(ge=0)
    conflicting_groups: int = Field(ge=0)
    awaiting_reanalysis: int = Field(ge=0)


class RemediationPage(BaseModel):
    contract_version: Literal["2026-09-09.1"] = "2026-09-09.1"
    snapshot_at: datetime
    items: list[RemediationActionGroup] = Field(max_length=100)
    returned_count: int = Field(ge=0, le=100)
    total_count: int = Field(ge=0)
    has_more: bool
    next_cursor: str | None = Field(default=None, max_length=512)
    summary: RemediationSummary
    resolution_policy: Literal["comparable_reanalysis_required"] = "comparable_reanalysis_required"
    portfolio_complete: bool = True
    limitations: list[str] = Field(default_factory=list, max_length=12)


class RemediationBulkSelection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    analysis_id: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    finding_id: str = Field(
        min_length=64,
        max_length=68,
        pattern=r"^(?:[a-f0-9]{64}|pvf_[a-f0-9]{64})$",
    )


class RemediationBulkActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group_id: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    idempotency_key: str = Field(
        min_length=16,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    expected_revision: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    selections: list[RemediationBulkSelection] = Field(min_length=1, max_length=25)
    status: FindingDecisionStatus
    reason: str = Field(min_length=3, max_length=240)
    comment: str | None = Field(default=None, max_length=1_000)
    assignee_user_id: str | None = Field(default=None, min_length=1, max_length=64)
    review_at: datetime | None = None
    confirmation: Literal[True]


class RemediationReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filters: RemediationSearchRequest = Field(default_factory=RemediationSearchRequest)
    report_format: Literal["json", "csv"]
    project_metadata_confirmed: Literal[True]

    @model_validator(mode="after")
    def report_starts_from_a_fresh_projection(self):
        if self.filters.cursor is not None:
            raise ValueError("A remediation report cannot start from a paging cursor.")
        return self


RiskTrendProfile = Literal["developer", "security", "executive"]


class RiskTrendRequest(BaseModel):
    """Closed request for one bounded, owner-scoped historical projection."""

    model_config = ConfigDict(extra="forbid")

    period_days: Literal[30, 90, 180] = 90
    bucket_days: Literal[7, 30] = 7

    @model_validator(mode="after")
    def bucket_fits_period(self):
        if self.bucket_days > self.period_days:
            raise ValueError("Trend bucket cannot exceed the selected period.")
        return self


class RiskTrendChangeCounts(BaseModel):
    local_new: int = Field(default=0, ge=0)
    local_persistent: int = Field(default=0, ge=0)
    local_resolved: int = Field(default=0, ge=0)
    public_new: int = Field(default=0, ge=0)
    public_persistent: int = Field(default=0, ge=0)
    public_resolved: int = Field(default=0, ge=0)
    critical_or_high_new: int = Field(default=0, ge=0)


class RiskTrendBucket(BaseModel):
    starts_at: datetime
    ends_at: datetime
    completed_analyses: int = Field(default=0, ge=0)
    projects_analyzed: int = Field(default=0, ge=0)
    comparable_local_transitions: int = Field(default=0, ge=0)
    comparable_public_transitions: int = Field(default=0, ge=0)
    excluded_transitions: int = Field(default=0, ge=0)
    coverage_gained: int = Field(default=0, ge=0)
    coverage_lost: int = Field(default=0, ge=0)
    changes: RiskTrendChangeCounts = Field(default_factory=RiskTrendChangeCounts)


class RiskTrendDuration(BaseModel):
    cohort: Literal["first_retained_observation_in_period"] = "first_retained_observation_in_period"
    sample_count: int = Field(default=0, ge=0)
    median_hours: float | None = Field(default=None, ge=0)
    p90_hours: float | None = Field(default=None, ge=0)


class RiskTrendDimension(BaseModel):
    key: str = Field(min_length=1, max_length=40, pattern=r"^[a-z0-9_]+$")
    current_findings: int = Field(default=0, ge=0)
    completed_analyses: int = Field(default=0, ge=0)
    comparable_transitions: int = Field(default=0, ge=0)
    new_findings: int = Field(default=0, ge=0)
    resolved_findings: int = Field(default=0, ge=0)


class RiskTrendExclusion(BaseModel):
    reason: Literal[
        "no_previous_analysis",
        "missing_execution_profile",
        "profile_changed",
        "coverage_changed",
        "invalid_local_findings",
        "public_snapshot_unavailable",
        "invalid_public_findings",
    ]
    count: int = Field(ge=1)


class RiskTrendPriorityProject(BaseModel):
    project: ProjectView
    priority: ProjectPortfolioPriority
    reasons: list[str] = Field(default_factory=list, max_length=12)
    pending_actions: int = Field(default=0, ge=0)


class RiskTrendSummary(BaseModel):
    projects_in_scope: int = Field(ge=0)
    projects_analyzed_in_period: int = Field(ge=0)
    projects_without_recent_analysis: int = Field(ge=0)
    retained_completed_analyses: int = Field(ge=0)
    completed_analyses_in_period: int = Field(ge=0)
    comparable_local_transitions: int = Field(ge=0)
    comparable_public_transitions: int = Field(ge=0)
    excluded_transitions: int = Field(ge=0)
    pending_actions: int = Field(ge=0)
    overdue_exceptions: int = Field(ge=0)
    current_known_exploited_findings: int = Field(ge=0)
    current_critical_or_high_findings: int = Field(ge=0)


class RiskTrendResponse(BaseModel):
    contract_version: Literal["2026-09-10.1"] = "2026-09-10.1"
    generated_at: datetime
    period_starts_at: datetime
    period_ends_at: datetime
    bucket_days: Literal[7, 30]
    summary: RiskTrendSummary
    changes: RiskTrendChangeCounts
    buckets: list[RiskTrendBucket] = Field(max_length=27)
    ecosystems: list[RiskTrendDimension] = Field(max_length=8)
    source_types: list[RiskTrendDimension] = Field(max_length=4)
    time_to_first_review: RiskTrendDuration
    time_to_verified_resolution: RiskTrendDuration
    priority_projects: list[RiskTrendPriorityProject] = Field(max_length=8)
    exclusions: list[RiskTrendExclusion] = Field(max_length=8)
    denominators: dict[str, int]
    limitations: list[str] = Field(max_length=12)


class RiskTrendMaterialization(BaseModel):
    """Content-free operational state for the private trend projection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: Literal["ready", "rebuilding", "stale", "failed"]
    data_state: Literal["current", "stale", "unavailable"]
    refresh_in_progress: bool
    retryable: bool
    requested_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    failure_code: Literal["limit", "source_changed", "rebuild_failed"] | None = None
    retry_after_seconds: Literal[1] | None = None


class RiskTrendViewResponse(BaseModel):
    """Non-blocking trend response; facts are absent instead of fabricated."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-10.2"] = "2026-09-10.2"
    materialization: RiskTrendMaterialization
    trend: RiskTrendResponse | None = None


class RiskTrendReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filters: RiskTrendRequest = Field(default_factory=RiskTrendRequest)
    profile: RiskTrendProfile
    report_format: Literal["json", "csv"]
    project_metadata_confirmed: Literal[True]


class ProjectTechnicalReportRequest(BaseModel):
    """Explicit disclosure gate for the non-default project report profile."""

    model_config = ConfigDict(extra="forbid")

    profile: Literal["technical"]
    technical_detail_confirmed: Literal[True]
    vulnerability_snapshot_id: str | None = Field(
        default=None,
        min_length=32,
        max_length=32,
        pattern=r"^[a-f0-9]{32}$",
    )


class ProjectCreated(BaseModel):
    project: ProjectView
    job: JobListItem


class ProjectSbomRevisionCreated(ProjectCreated):
    snapshot: ProjectSourceSnapshotView
    replayed: bool


class SbomImportPreflightResponse(BaseModel):
    contract_version: Literal["2026-09-08.1"] = "2026-09-08.1"
    status: Literal["ready"] = "ready"
    preflight_token: str = Field(min_length=32, max_length=128)
    expires_at: datetime
    format: Literal["cyclonedx", "spdx"]
    spec_version: str
    input_components: int = Field(ge=0)
    retained_components: int = Field(ge=0)
    rejected_or_ambiguous_components: int = Field(ge=0)
    potentially_correlatable_components: int = Field(ge=0)
    component_limit_reached: bool
    relationship_graph_truncated: bool


class ProjectSnapshotCreated(BaseModel):
    project: ProjectView
    job: JobListItem
    snapshot: ProjectSourceSnapshotView


class CiProjectSnapshotCreated(ProjectSnapshotCreated):
    contract_version: Literal["2026-09-07.1"] = "2026-09-07.1"
    replayed: bool
    commit_sha: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    source_digest_verified: Literal[True] = True


class ProjectDeletionRequest(BaseModel):
    """Require an explicit acknowledgement for the irreversible project cascade."""

    model_config = ConfigDict(extra="forbid")

    deletion_confirmed: Literal[True]


class ProjectDeletionScopeItem(BaseModel):
    """Content-free disclosure of one class affected by project deletion."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: Literal[
        "project_metadata",
        "analysis_results",
        "public_advisory_snapshots",
        "finding_decisions",
        "snapshot_admissions",
        "execution_workspaces",
        "passive_project_actions",
        "source_uploads",
        "report_exports",
        "public_advisory_cache",
        "product_audit",
    ]
    disposition: Literal["delete", "retain", "not_persisted"]
    item_count: int | None = Field(default=None, ge=0)
    detail: str = Field(min_length=3, max_length=280)


class ProjectDeletionPreview(BaseModel):
    """Owner-scoped plan shown before an irreversible project deletion."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-06.1"] = "2026-09-06.1"
    project_id: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    state: Literal["ready", "blocked_active_work"]
    requires_confirmation: Literal[True] = True
    items: list[ProjectDeletionScopeItem] = Field(min_length=1, max_length=12)


class ProjectDeletionResponse(BaseModel):
    """Stable result for a completed or already-satisfied delete request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-06.1"] = "2026-09-06.1"
    project_id: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    state: Literal["completed", "already_absent"]
    completed_at: datetime
    items: list[ProjectDeletionScopeItem] = Field(min_length=1, max_length=12)


class FindingLocation(BaseModel):
    path: str | None = None
    line: int | None = Field(default=None, ge=1)


class FindingReference(BaseModel):
    type: Literal["cve", "ghsa", "owasp"]
    id: str
    url: str


class NormalizedFinding(BaseModel):
    id: str
    rule_id: str
    source_audit_type: str
    title: str
    category: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["high", "medium", "low", "unknown"]
    description: str = ""
    evidence: str = ""
    location: FindingLocation | None = None
    location_status: Literal["reported", "withheld_unsafe_path", "not_reported"] = "not_reported"
    recommendation: str = ""
    references: list[FindingReference] = Field(default_factory=list)


class ProjectFindingSummary(BaseModel):
    total: int = Field(ge=0)
    by_severity: dict[str, int]
    by_category: dict[str, int]
    by_status: dict[str, int] = Field(default_factory=dict)
    needs_review: int = Field(default=0, ge=0)


class FindingDecisionRecord(BaseModel):
    """One immutable, organization-scoped triage decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-06.1"] = "2026-09-06.1"
    id: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    organization_id: str = Field(min_length=1, max_length=64, pattern=r"^(?:local-admin|[a-f0-9]{32})$")
    project_id: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    finding_id: str = Field(
        min_length=64,
        max_length=68,
        pattern=r"^(?:[a-f0-9]{64}|pvf_[a-f0-9]{64})$",
    )
    rule_id: str = Field(min_length=1, max_length=160)
    status: FindingDecisionStatus
    reason: str = Field(min_length=3, max_length=240)
    comment: str | None = Field(default=None, max_length=1_000)
    assignee_user_id: str | None = Field(default=None, min_length=1, max_length=64)
    assignee_username: str | None = Field(default=None, min_length=3, max_length=64)
    actor_id: str = Field(min_length=1, max_length=64)
    actor_username: str = Field(min_length=1, max_length=64)
    actor_role: str = Field(min_length=1, max_length=32)
    review_at: datetime | None = None
    created_at: datetime
    previous_decision_id: str | None = Field(default=None, min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    batch_operation_id: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
        pattern=r"^[a-f0-9]{64}$",
    )

    @model_validator(mode="after")
    def validate_immutable_decision_contract(self):
        if bool(self.assignee_user_id) != bool(self.assignee_username):
            raise ValueError("Finding decision assignment is incomplete.")
        if self.review_at is not None and self.status not in {"accepted", "false_positive"}:
            raise ValueError("Only reviewable exceptions can carry a review date.")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("Finding decision timestamps must include a timezone.")
        if self.review_at is not None and (self.review_at.tzinfo is None or self.review_at.utcoffset() is None):
            raise ValueError("Finding decision review timestamps must include a timezone.")
        return self


class FindingLifecycleState(BaseModel):
    finding_id: str
    rule_id: str
    current_status: FindingDecisionStatus = "open"
    has_decision: bool = False
    needs_review: bool = False
    review_overdue: bool = False
    current_decision: FindingDecisionRecord | None = None
    history: list[FindingDecisionRecord] = Field(default_factory=list)


class FindingDecisionCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    status: FindingDecisionStatus
    reason: str = Field(min_length=3, max_length=240)
    comment: str | None = Field(default=None, max_length=1_000)
    assignee_user_id: str | None = Field(default=None, min_length=1, max_length=64)
    review_at: datetime | None = None


class RemediationBulkActionResponse(BaseModel):
    contract_version: Literal["2026-09-09.2"] = "2026-09-09.2"
    group_id: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]{64}$")
    applied_count: int = Field(ge=1, le=25)
    decisions: list[FindingDecisionRecord] = Field(min_length=1, max_length=25)
    replayed: bool = False
    history_mode: Literal["append_only_recoverable_batch"] = "append_only_recoverable_batch"


class ProjectAnalysisCoverage(BaseModel):
    coverage_status: Literal["complete", "partial", "unknown"]
    total_entries_seen: int = Field(default=0, ge=0)
    supported_manifests_found: int = Field(default=0, ge=0)
    supported_manifests_parsed: int = Field(default=0, ge=0)
    supported_manifests_skipped: int = Field(default=0, ge=0)
    unsupported_manifests_detected: int = Field(default=0, ge=0)
    lockfiles_detected: int = Field(default=0, ge=0)
    lockfiles_parsed: int = Field(default=0, ge=0)
    lockfiles_skipped: int = Field(default=0, ge=0)
    total_dependencies: int = Field(default=0, ge=0)
    source_retained: bool
    limitations: list[Literal["analysis_limit_reached", "supported_manifests_not_parsed", "lockfiles_not_parsed", "source_removed"]] = Field(default_factory=list)


class ProjectAnalysisCoverageComparison(BaseModel):
    """Safe coverage context used before classifying a project regression."""

    status: Literal["equivalent", "changed", "unknown"]
    base: ProjectAnalysisCoverage
    target: ProjectAnalysisCoverage
    changed_metrics: list[
        Literal[
            "coverage_summary",
            "analysis_limit_reached",
            "total_entries_seen",
            "supported_manifests_found",
            "supported_manifests_parsed",
            "unsupported_manifests_detected",
            "lockfiles_detected",
            "lockfiles_parsed",
            "total_dependencies",
        ]
    ] = Field(default_factory=list)


class ProjectFindingsResponse(BaseModel):
    project: ProjectView
    analysis: JobListItem | None = None
    state: Literal[
        "ready",
        "analysis_pending",
        "analysis_failed",
        "analysis_cancelled",
        "no_completed_analysis",
        "no_normalized_findings",
    ]
    findings: list[NormalizedFinding] = Field(default_factory=list)
    summary: ProjectFindingSummary
    result_truncated: bool = False
    coverage: ProjectAnalysisCoverage | None = None
    lifecycle: dict[str, FindingLifecycleState] = Field(default_factory=dict)


class ProjectComponent(BaseModel):
    id: str
    ecosystem: Literal["npm", "pypi", "go", "cargo", "composer", "maven", "nuget"]
    name: str
    manifest_path: str | None = None
    manifest_path_status: Literal["reported", "withheld_unsafe_path", "not_reported"] = "not_reported"
    dependency_group: str
    source_type: Literal["registry", "url", "vcs", "local", "editable", "workspace", "alias", "unknown"]
    declared_version: str | None = None
    exact_version: str | None = None
    package_url: str | None = None
    dependency_scope: Literal["direct", "transitive", "optional"] = "direct"
    relationship_status: Literal["reported", "not_reported", "truncated"] = "reported"
    version_status: Literal["exact_declared", "exact_resolved", "declared_range", "not_correlatable"]
    correlation_eligible: bool
    resolution: Literal["declared", "lockfile"]
    lockfile_match_status: Literal["matched", "not_matched", "ambiguous", "not_applicable"] = "not_applicable"
    manifest_type: Literal["package_json", "requirements_txt", "pyproject_toml", "pipfile", "go_mod", "cargo_toml", "composer_json", "gradle_build", "dotnet_project", "cyclonedx", "spdx"]
    lockfile_path: str | None = None
    lockfile_path_status: Literal["reported", "withheld_unsafe_path", "not_reported"] = "not_reported"
    lockfile_type: Literal["npm_package_lock", "pnpm_lock", "yarn_classic_lock", "poetry_lock", "pipfile_lock", "go_sum", "cargo_lock", "composer_lock", "gradle_lock", "nuget_packages_lock"] | None = None
    enabled_feature_count: int | None = Field(default=None, ge=0, le=64)
    target_variant_count: int | None = Field(default=None, ge=0, le=32)
    build_scope_count: int | None = Field(default=None, ge=1, le=3)


class ProjectDependencyGraphEvidence(BaseModel):
    """Safe aggregate receipt; raw CI nodes and edges are never persisted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-10.1"]
    ecosystem: Literal["go"]
    state: Literal["accepted", "truncated", "divergent"]
    reason: Literal[
        "none",
        "producer_truncated",
        "no_single_source_root",
        "identity_not_in_lockfile",
        "replaced_identity",
        "root_set_mismatch",
        "complete_graph_omits_manifest_requirement",
        "unreachable_node",
    ]
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_commit_sha: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    source_binding_verified: Literal[True]
    nodes_reported: int = Field(ge=0, le=2_000)
    edges_reported: int = Field(ge=0, le=4_000)
    components_matched: int = Field(ge=0, le=2_000)
    components_unmatched: int = Field(ge=0, le=2_000)
    cycles_detected: bool
    truncation_reason: Literal["node_limit", "edge_limit", "producer_limit"] | None


class CargoProjectDependencyGraphEvidence(BaseModel):
    """Safe Cargo aggregate; feature names, target IDs and edges are withheld."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-10.2"]
    ecosystem: Literal["cargo"]
    state: Literal["accepted", "truncated", "divergent"]
    reason: Literal[
        "none",
        "producer_truncated",
        "no_single_source_root",
        "identity_not_in_lockfile",
        "unresolved_manifest_root",
        "root_set_mismatch",
        "unreachable_node",
    ]
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_commit_sha: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    source_binding_verified: Literal[True]
    target_coverage: Literal["all_locked_targets"]
    nodes_reported: int = Field(ge=0, le=2_000)
    edges_reported: int = Field(ge=0, le=4_000)
    features_reported: int = Field(ge=0, le=128_000)
    targets_reported: int = Field(ge=1, le=32)
    components_matched: int = Field(ge=0, le=2_000)
    components_unmatched: int = Field(ge=0, le=2_000)
    cycles_detected: bool
    truncation_reason: Literal["node_limit", "edge_limit", "feature_limit", "target_limit", "producer_limit"] | None


class ComposerProjectDependencyGraphEvidence(BaseModel):
    """Safe relationship receipt that makes no Packagist-origin claim."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: Literal["2026-09-10.3"]
    ecosystem: Literal["composer"]
    state: Literal["accepted", "truncated", "divergent"]
    reason: Literal[
        "none", "producer_truncated", "no_single_source_root",
        "custom_repository_declared", "identity_not_in_lockfile",
        "unresolved_manifest_root", "root_set_mismatch", "unreachable_node",
    ]
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_commit_sha: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    source_binding_verified: Literal[True]
    nodes_reported: int = Field(ge=0, le=2_000)
    edges_reported: int = Field(ge=0, le=4_000)
    components_matched: int = Field(ge=0, le=2_000)
    components_unmatched: int = Field(ge=0, le=2_000)
    cycles_detected: bool
    truncation_reason: Literal["node_limit", "edge_limit", "producer_limit"] | None


class GradleProjectDependencyGraphEvidence(BaseModel):
    """Safe Gradle relationship receipt; coordinates and raw edges are withheld."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: Literal["2026-09-10.4"]
    ecosystem: Literal["maven"]
    producer: Literal["gradle"]
    state: Literal["accepted", "truncated", "divergent"]
    reason: Literal[
        "none", "producer_truncated", "no_single_source_root",
        "identity_not_in_lockfile", "unreachable_node",
    ]
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_commit_sha: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    source_binding_verified: Literal[True]
    relationship_origin: Literal["ci_reported"]
    scope_coverage: list[Literal["compile", "runtime", "test"]] = Field(min_length=1, max_length=3)
    nodes_reported: int = Field(ge=0, le=2_000)
    edges_reported: int = Field(ge=0, le=4_000)
    scope_assignments_reported: int = Field(ge=0, le=6_000)
    components_matched: int = Field(ge=0, le=2_000)
    components_unmatched: int = Field(ge=0, le=2_000)
    cycles_detected: bool
    truncation_reason: Literal["node_limit", "edge_limit", "producer_limit"] | None


class NugetProjectDependencyGraphEvidence(BaseModel):
    """Safe NuGet receipt; target IDs and raw topology are withheld."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    contract_version: Literal["2026-09-10.5"]
    ecosystem: Literal["nuget"]
    producer: Literal["nuget"]
    state: Literal["accepted", "truncated", "divergent"]
    reason: Literal[
        "none", "producer_truncated", "no_single_source_root",
        "target_count_mismatch", "identity_not_in_lockfile", "unreachable_node",
    ]
    artifact_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_commit_sha: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    source_binding_verified: Literal[True]
    relationship_origin: Literal["ci_reported"]
    target_coverage: Literal["all_locked_targets"]
    targets_reported: int = Field(ge=1, le=32)
    target_assignments_reported: int = Field(ge=1, le=64_000)
    nodes_reported: int = Field(ge=1, le=2_000)
    edges_reported: int = Field(ge=0, le=4_000)
    components_matched: int = Field(ge=0, le=2_000)
    components_unmatched: int = Field(ge=0, le=2_000)
    cycles_detected: bool
    truncation_reason: Literal["node_limit", "edge_limit", "target_limit", "producer_limit"] | None


class ProjectComponentInventorySummary(BaseModel):
    total_components: int = Field(ge=0)
    exact_registry_components: int = Field(ge=0)
    resolved_registry_components: int = Field(default=0, ge=0)
    unverified_lockfile_components: int = Field(default=0, ge=0)
    transitive_registry_components: int = Field(default=0, ge=0)
    relationship_reported_components: int = Field(default=0, ge=0)
    relationship_not_reported_components: int = Field(default=0, ge=0)
    relationship_truncated_components: int = Field(default=0, ge=0)
    optional_registry_components: int = Field(default=0, ge=0)
    matched_lockfile_components: int = Field(default=0, ge=0)
    unmatched_lockfile_components: int = Field(default=0, ge=0)
    ambiguous_lockfile_components: int = Field(default=0, ge=0)
    declared_range_components: int = Field(ge=0)
    not_correlatable_components: int = Field(ge=0)
    parsed_manifest_count: int = Field(ge=0)
    supported_manifest_count: int = Field(ge=0)
    skipped_manifest_count: int = Field(ge=0)
    result_truncated: bool = False
    parsed_lockfile_count: int = Field(default=0, ge=0)
    skipped_lockfile_count: int = Field(default=0, ge=0)
    skipped_lockfile_reasons: list[str] = Field(default_factory=list)
    lockfile_graph_truncated: bool = False
    resolution: Literal["declared_only", "declared_and_lockfile"]


class ProjectComponentCoverage(BaseModel):
    """A safe, aggregate support row for a known package-manager workflow."""

    id: Literal[
        "npm-package-lock",
        "npm-pnpm-lock",
        "npm-yarn-lock",
        "pypi-requirements",
        "pypi-pyproject",
        "pypi-poetry-lock",
        "pypi-pipfile-lock",
        "go-mod-sum",
        "cargo-lock",
        "composer-lock",
        "gradle-lock",
        "nuget-packages-lock",
    ]
    coverage_contract_version: str = Field(min_length=1, max_length=32)
    ecosystem: Literal["npm", "pypi", "go", "cargo", "composer", "maven", "nuget"]
    manager: Literal["npm", "pnpm", "yarn", "pip", "python-packaging", "poetry", "pipenv", "go-modules", "cargo", "composer", "gradle", "nuget"]
    manifest: Literal["package.json", "requirements.txt", "pyproject.toml", "Pipfile", "go.mod", "Cargo.toml", "composer.json", "build.gradle", "*.csproj"]
    lockfile: Literal["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "Pipfile.lock", "go.sum", "Cargo.lock", "composer.lock", "gradle.lockfile", "packages.lock.json", "not_applicable"]
    parser_version: Literal[
        "package-lock-json-v2-v3",
        "pnpm-lock-yaml-v9",
        "yarn-classic-lock-v1",
        "poetry-lock-toml-v2.1",
        "pipfile-lock-json-v6",
        "requirements-lines-v2-hash-summary",
        "pyproject-toml-v1",
        "go-mod-sum-v1",
        "cargo-lock-toml-v3-v4",
        "composer-lock-json-v1",
        "gradle-lockfile-v1",
        "nuget-packages-lock-json-v1",
        "not_available",
    ]
    direct_coverage: Literal["exact_same_root_when_matched", "exact_same_root_local_only", "exact_ci_graph", "declared_manifest_only", "not_available"]
    transitive_coverage: Literal["bounded_registry_graph", "bounded_ci_graph", "not_available"]
    manifest_status: Literal["not_detected", "parsed", "detected_not_parsed"]
    lockfile_status: Literal["not_applicable", "not_detected", "parsed", "detected_not_parsed"]
    exclusion_reason: Literal[
        "none",
        "not_detected",
        "no_lockfile_contract",
        "unsupported_lockfile_parser",
        "defensive_limit_or_invalid_input",
        "no_same_root_match",
        "ambiguous_root_pair",
        "graph_truncated",
        "graph_divergent",
        "relationship_evidence_not_provided",
    ]


class ProjectComponentInventoryResponse(BaseModel):
    project: ProjectView
    analysis: JobListItem | None = None
    state: Literal[
        "ready",
        "analysis_pending",
        "analysis_failed",
        "analysis_cancelled",
        "no_completed_analysis",
        "no_component_inventory",
    ]
    contract_version: str | None = None
    components: list[ProjectComponent] = Field(default_factory=list)
    summary: ProjectComponentInventorySummary
    coverage_matrix: list[ProjectComponentCoverage] = Field(default_factory=list, max_length=12)
    dependency_graph: ProjectDependencyGraphEvidence | None = None
    cargo_dependency_graph: CargoProjectDependencyGraphEvidence | None = None
    composer_dependency_graph: ComposerProjectDependencyGraphEvidence | None = None
    gradle_dependency_graph: GradleProjectDependencyGraphEvidence | None = None
    nuget_dependency_graph: NugetProjectDependencyGraphEvidence | None = None


class PublicVulnerabilityReference(BaseModel):
    type: Literal["source", "reference"]
    url: str


class PublicVulnerabilityAffectedRange(BaseModel):
    type: Literal["SEMVER", "ECOSYSTEM", "GIT", "UNKNOWN"]
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    expression: str | None = None


class PublicVulnerabilitySeverity(BaseModel):
    type: str
    vector: str
    base_score: float | None = Field(default=None, ge=0, le=10)
    band: Literal["none", "low", "medium", "high", "critical", "unknown"] = "unknown"
    score_status: Literal["derived_from_vector", "source_provided", "not_available"] = "not_available"
    cvss_version: Literal["3.0", "3.1", "4.0"] | None = None


class PublicVulnerabilityCorroboration(BaseModel):
    provider: Literal["github_advisories"]
    advisory_id: str
    aliases: list[str] = Field(default_factory=list)
    affected_ranges: list[PublicVulnerabilityAffectedRange] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    severity: list[PublicVulnerabilitySeverity] = Field(default_factory=list)
    references: list[PublicVulnerabilityReference] = Field(default_factory=list)
    published_at: str | None = None
    updated_at: str | None = None
    withdrawn_at: str | None = None
    evidence_digest: str


class PublicVulnerabilityNvdEvidence(BaseModel):
    """CVE-level NVD evidence that never establishes package applicability."""

    provider: Literal["nvd"]
    contract_version: str
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    status: Literal["analyzed", "modified", "rejected", "under_analysis", "deferred", "unknown"]
    severity: list[PublicVulnerabilitySeverity] = Field(default_factory=list, max_length=16)
    cwes: list[str] = Field(default_factory=list, max_length=32)
    cpe_status: Literal["not_present", "present_unmapped", "identity_corroborated"]
    cpe_match_count: int = Field(ge=0, le=2000)
    cpe_corroborated_match_count: int = Field(default=0, ge=0, le=2000)
    cpe_mapping_ids: list[str] = Field(default_factory=list, max_length=8)
    cpe_mapping_policy_version: str = Field(default="legacy_unmapped", min_length=1, max_length=64)
    references: list[PublicVulnerabilityReference] = Field(default_factory=list, max_length=1)
    published_at: str | None = None
    updated_at: str | None = None
    evidence_digest: str = Field(pattern=r"^[a-f0-9]{64}$")

    @field_validator("cpe_mapping_ids")
    @classmethod
    def validate_cpe_mapping_ids(cls, value: list[str]) -> list[str]:
        if value != sorted(set(value)) or any(not re.fullmatch(r"cpe-map-[a-z0-9][a-z0-9-]{2,63}", item) for item in value):
            raise ValueError("invalid CPE mapping identifiers")
        return value

    @model_validator(mode="after")
    def validate_cpe_mapping_state(self):
        if self.cpe_corroborated_match_count > self.cpe_match_count:
            raise ValueError("corroborated CPE count exceeds observed matches")
        if self.cpe_status == "identity_corroborated":
            if self.cpe_corroborated_match_count < 1 or not self.cpe_mapping_ids:
                raise ValueError("corroborated CPE identity requires reviewed mapping evidence")
        elif self.cpe_corroborated_match_count or self.cpe_mapping_ids:
            raise ValueError("unmapped CPE evidence cannot retain mapping evidence")
        return self


class PublicAdvisoryProviderOperations(BaseModel):
    provider: Literal["osv", "github_advisories", "nvd", "cisa_kev"]
    configured: bool
    cache_entries: int = Field(ge=0, le=10000)
    fresh_entries: int = Field(ge=0, le=10000)
    stale_entries: int = Field(ge=0, le=10000)
    invalid_entries: int = Field(ge=0, le=10000)
    cache_bytes: int = Field(ge=0)
    last_updated_at: datetime | None = None
    truncated: bool = False


class PublicAdvisoryOperationsResponse(BaseModel):
    contract_version: Literal["2026-09-09.1"] = "2026-09-09.1"
    egress_enabled: bool
    offline_snapshot_active: bool
    providers: list[PublicAdvisoryProviderOperations] = Field(max_length=4)


class PublicAdvisoryCacheCleanupResponse(BaseModel):
    removed_entries: int = Field(ge=0, le=40000)
    operations: PublicAdvisoryOperationsResponse


class PublicVulnerabilitySourceConflict(BaseModel):
    """A source-scoped disagreement; its values never overwrite OSV evidence."""

    provider: Literal["github_advisories"]
    advisory_id: str
    type: Literal["fixed_version", "cvss_severity", "github_advisory_withdrawn"]
    observed_at: str | None = None
    evidence_digest: str


class PublicVulnerabilityKevSignal(BaseModel):
    """CISA KEV is an independent exploitation-prioritisation signal."""

    provider: Literal["cisa_kev"]
    status: Literal["known_exploited", "not_listed", "unavailable", "not_evaluated"]
    cve_id: str | None = None
    catalog_version: str | None = None
    date_released: str | None = None
    date_added: str | None = None
    due_date: str | None = None
    required_action: str | None = None
    known_ransomware_campaign_use: str | None = None
    source_url: str
    evidence_digest: str


class PublicVulnerabilityVendorBulletin(BaseModel):
    """A policy-bound vendor advisory link, never a fetched external page."""

    publisher: str = Field(min_length=1, max_length=80)
    advisory_id: str = Field(pattern=r"^GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$")
    url: str
    policy_version: str


class PublicVulnerabilityFieldSource(BaseModel):
    """One bounded source contribution to a decision-relevant field."""

    provider: Literal["osv", "github_advisories", "nvd", "cisa_kev", "vendor_bulletin"]
    evidence_id: str = Field(min_length=1, max_length=160)
    observed_at: str | None = None
    status: Literal["primary", "supporting", "conflicting", "withdrawn", "unmapped", "derived", "not_available"]
    evidence_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class PublicVulnerabilityFieldProvenance(BaseModel):
    """Closed, value-free provenance matrix; source values remain separate."""

    field: Literal[
        "advisory_identity",
        "affected_ranges",
        "fixed_versions",
        "severity",
        "lifecycle_dates",
        "references",
        "weaknesses",
        "cpe_applicability",
        "known_exploitation",
        "vendor_guidance",
        "recommendation",
    ]
    state: Literal[
        "primary_only",
        "corroborated",
        "conflicting",
        "secondary_withdrawn",
        "source_specific",
        "derived",
        "not_available",
        "not_applicable",
    ]
    sources: list[PublicVulnerabilityFieldSource] = Field(default_factory=list, max_length=12)


class ProjectVulnerabilityFinding(BaseModel):
    id: str
    # Snapshots created before PROD-102 used their evidence digest as `id`.
    # Keep them readable while new snapshots declare a versioned stable ID.
    fingerprint_version: str = "legacy_evidence_digest"
    provider: Literal["osv"]
    advisory_id: str
    aliases: list[str] = Field(default_factory=list)
    ecosystem: Literal["npm", "pypi", "go", "cargo", "composer", "maven", "nuget"]
    component_name: str
    component_version: str
    package_url: str
    component_identity_provenance: Literal[
        "npm_registry_lockfile",
        "operator_attested_public_pypi",
        "operator_attested_public_go",
        "cargo_crates_io_lockfile",
        "operator_attested_public_composer",
        "operator_attested_public_maven",
        "operator_attested_public_nuget",
        "not_applicable",
        "operator_attested_public_sbom",
    ] = "not_applicable"
    dependency_scope: Literal["direct", "transitive", "optional"]
    relationship_status: Literal["reported", "not_reported", "truncated"] = "reported"
    affected_ranges: list[PublicVulnerabilityAffectedRange] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    severity: list[PublicVulnerabilitySeverity] = Field(default_factory=list)
    corroborations: list[PublicVulnerabilityCorroboration] = Field(default_factory=list)
    nvd_evidence: list[PublicVulnerabilityNvdEvidence] = Field(default_factory=list, max_length=24)
    source_consensus: Literal["osv_only", "corroborated", "conflicting", "secondary_withdrawn"] = "osv_only"
    source_conflicts: list[PublicVulnerabilitySourceConflict] = Field(default_factory=list)
    kev_signals: list[PublicVulnerabilityKevSignal] = Field(default_factory=list)
    vendor_bulletins: list[PublicVulnerabilityVendorBulletin] = Field(default_factory=list)
    field_provenance: list[PublicVulnerabilityFieldProvenance] = Field(default_factory=list, max_length=11)
    cvss_base_score: float | None = Field(default=None, ge=0, le=10)
    cvss_band: Literal["none", "low", "medium", "high", "critical", "unknown"] = "unknown"
    cvss_score_status: Literal["derived_from_vector", "source_provided", "not_available"] = "not_available"
    references: list[PublicVulnerabilityReference] = Field(default_factory=list)
    published_at: str | None = None
    updated_at: str | None = None
    recommendation: str
    evidence_digest: str


class ProjectVulnerabilityIntelligenceSummary(BaseModel):
    inventory_components: int = Field(ge=0)
    correlation_eligible_components: int = Field(ge=0)
    queryable_components: int = Field(ge=0)
    queried_components: int = Field(ge=0)
    # Includes continuations completed locally for a Querybatch request. Older
    # retained snapshots omit it and remain readable as zero.
    osv_pages: int = Field(default=0, ge=0)
    findings: int = Field(ge=0)
    fixed_version_available: int = Field(ge=0)
    excluded_components: int = Field(ge=0)
    unverified_advisories: int = Field(ge=0)
    withdrawn_advisories: int = Field(ge=0)
    failed_batches: int = Field(ge=0)
    fresh_cache_batches: int = Field(ge=0)
    stale_cache_batches: int = Field(ge=0)
    github_queries: int = Field(default=0, ge=0)
    github_corroborated: int = Field(default=0, ge=0)
    github_not_correlated: int = Field(default=0, ge=0)
    github_failed: int = Field(default=0, ge=0)
    github_withdrawn: int = Field(default=0, ge=0)
    github_conflicts: int = Field(default=0, ge=0)
    affected_components: int = Field(default=0, ge=0)
    not_affected_components: int = Field(default=0, ge=0)
    not_correlatable_components: int = Field(default=0, ge=0)
    unavailable_components: int = Field(default=0, ge=0)
    cisa_kev_feed_queries: int = Field(default=0, ge=0)
    cisa_kev_known_exploited: int = Field(default=0, ge=0)
    cisa_kev_not_listed: int = Field(default=0, ge=0)
    cisa_kev_not_evaluated: int = Field(default=0, ge=0)
    cisa_kev_unavailable: int = Field(default=0, ge=0)
    nvd_queries: int = Field(default=0, ge=0)
    nvd_enriched: int = Field(default=0, ge=0)
    nvd_not_found: int = Field(default=0, ge=0)
    nvd_rejected: int = Field(default=0, ge=0)
    nvd_unavailable: int = Field(default=0, ge=0)


class PublicVulnerabilitySourceFreshness(BaseModel):
    provider: Literal["osv", "github_advisories", "nvd", "cisa_kev"]
    state: Literal["fresh", "stale", "unavailable", "not_requested"]
    # A small controlled vocabulary makes a degraded source useful without
    # surfacing an upstream diagnostic, URL, request identity or payload.
    reason: Literal[
        "not_requested",
        "network_refreshed",
        "fresh_cache",
        "stale_cache_fallback",
        "provider_unavailable",
        "provider_circuit_open",
        "provider_catalog_stale",
        "invalid_source_data",
    ]
    as_of: str | None = None
    expires_at: str | None = None
    evidence_count: int = Field(default=0, ge=0)
    evidence_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    offline_snapshot_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class PublicVulnerabilityComponentCorrelation(BaseModel):
    """One local component outcome; it is not an additional egress payload."""

    component_id: str
    ecosystem: Literal["npm", "pypi", "go", "cargo", "composer", "maven", "nuget"]
    component_name: str
    component_version: str | None = None
    dependency_scope: Literal["direct", "transitive", "optional"]
    relationship_status: Literal["reported", "not_reported", "truncated"] = "reported"
    identity_provenance: Literal[
        "npm_registry_lockfile",
        "operator_attested_public_pypi",
        "operator_attested_public_go",
        "cargo_crates_io_lockfile",
        "operator_attested_public_composer",
        "operator_attested_public_maven",
        "operator_attested_public_nuget",
        "not_applicable",
    ] = "not_applicable"
    provider: Literal["osv"] = "osv"
    state: Literal["affected", "not_affected", "not_correlatable", "unavailable"]
    reason: Literal[
        "affected_exact_version",
        "no_matching_advisory",
        "not_public_registry_component",
        "exact_version_unavailable",
        "identity_not_approved",
        "private_namespace",
        "public_pypi_identity_not_attested",
        "public_go_identity_not_attested",
        "public_composer_identity_not_attested",
        "public_maven_identity_not_attested",
        "public_nuget_identity_not_attested",
        "organization_identity_not_attested",
        "public_registry_provenance_unverified",
        "provider_unavailable",
        "invalid_source_data",
    ]


class ProjectVulnerabilityIntelligenceSnapshot(BaseModel):
    """Safe metadata for one immutable retained public-advisory refresh."""

    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    recorded_at: str
    state: Literal[
        "not_requested",
        "analysis_pending",
        "no_completed_analysis",
        "no_component_inventory",
        "disabled",
        "no_correlatable_components",
        "ready",
        "degraded",
        "stale",
    ]
    queried_at: str | None = None
    expires_at: str | None = None
    sources: list[PublicVulnerabilitySourceFreshness] = Field(default_factory=list)
    finding_count: int = Field(default=0, ge=0)
    snapshot_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    snapshot_integrity_status: Literal["valid", "unknown"] = "unknown"


class ProjectVulnerabilityIntelligenceResponse(BaseModel):
    project: ProjectView
    analysis: JobListItem | None = None
    state: Literal[
        "not_requested",
        "analysis_pending",
        "analysis_failed",
        "analysis_cancelled",
        "no_completed_analysis",
        "no_component_inventory",
        "disabled",
        "no_correlatable_components",
        "ready",
        "degraded",
        "stale",
    ]
    contract_version: str | None = None
    provider: Literal["osv"] = "osv"
    egress_enabled: bool
    nvd_enabled: bool = False
    offline_snapshot_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    snapshot_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    snapshot_recorded_at: str | None = None
    snapshot_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    snapshot_integrity_status: Literal["valid", "unknown"] = "unknown"
    latest_snapshot_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    is_latest_snapshot: bool = True
    snapshot_history: list[ProjectVulnerabilityIntelligenceSnapshot] = Field(default_factory=list)
    queried_at: str | None = None
    expires_at: str | None = None
    sources: list[PublicVulnerabilitySourceFreshness] = Field(default_factory=list)
    component_correlations: list[PublicVulnerabilityComponentCorrelation] = Field(default_factory=list)
    findings: list[ProjectVulnerabilityFinding] = Field(default_factory=list)
    summary: ProjectVulnerabilityIntelligenceSummary
    errors: list[str] = Field(default_factory=list)


class ProjectFindingComparison(BaseModel):
    """One safe, normalized finding as it relates to another snapshot."""

    status: Literal["new", "resolved", "persistent"]
    finding: NormalizedFinding
    previous_finding: NormalizedFinding | None = None
    changed_fields: list[str] = Field(default_factory=list)
    lifecycle: FindingLifecycleState | None = None


class ProjectComparisonSummary(BaseModel):
    new: int = Field(ge=0)
    resolved: int = Field(ge=0)
    persistent: int = Field(ge=0)


class ProjectPublicVulnerabilityFindingComparison(BaseModel):
    """One retained public-advisory finding compared without project source data."""

    status: Literal["new", "resolved", "persistent"]
    finding: ProjectVulnerabilityFinding
    previous_finding: ProjectVulnerabilityFinding | None = None
    changed_fields: list[str] = Field(default_factory=list)


class ProjectPublicVulnerabilityComparisonSummary(BaseModel):
    new: int = Field(ge=0)
    resolved: int = Field(ge=0)
    persistent: int = Field(ge=0)


class ProjectPublicVulnerabilityComparison(BaseModel):
    """Conservative cross-analysis view of separately retained OSV snapshots.

    A missing, stale, degraded, or legacy snapshot is deliberately not treated
    as evidence that an advisory was resolved.  It is surfaced with a bounded
    reason instead.
    """

    state: Literal["ready", "not_available", "not_comparable"]
    base_snapshot_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    target_snapshot_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    summary: ProjectPublicVulnerabilityComparisonSummary
    comparisons: list[ProjectPublicVulnerabilityFindingComparison] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ProjectAnalysisComparisonResponse(BaseModel):
    project: ProjectView
    base_analysis: JobListItem
    target_analysis: JobListItem
    state: Literal["ready", "analysis_pending", "not_comparable", "no_normalized_findings"]
    summary: ProjectComparisonSummary
    comparisons: list[ProjectFindingComparison] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    uses_saved_baseline: bool = False
    coverage_comparison: ProjectAnalysisCoverageComparison | None = None
    public_vulnerability_comparison: ProjectPublicVulnerabilityComparison | None = None


class AuthStatusResponse(BaseModel):
    auth_mode: AuthMode
    auth_required: bool
    configured: bool
    trusted_local: bool
    default_operator_id: str
    login_available: bool = False
    authenticated: bool = False
    operator_id: str | None = None
    username: str | None = None
    organization_id: str | None = None
    organization_name: str | None = None
    role: TeamRole | None = None
    csrf_required: bool = False
    csrf_token: str | None = None


class AuthLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str | None = Field(default=None, max_length=256)
    username: str | None = Field(default=None, max_length=64)


class AuthSessionResponse(BaseModel):
    authenticated: bool
    operator_id: str | None = None
    auth_mode: AuthMode
    organization_id: str | None = None
    role: TeamRole | None = None


class TeamOrganizationResponse(BaseModel):
    id: str
    name: str
    current_user_id: str
    current_username: str
    current_role: TeamRole


class TeamOrganizationListItem(BaseModel):
    id: str
    name: str
    role: TeamRole
    created_at: datetime


class TeamOrganizationCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=3, max_length=80)


class TeamMemberResponse(BaseModel):
    user_id: str
    username: str
    role: TeamRole
    joined_at: datetime


class TeamInvitationCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=64)
    role: TeamRole


class TeamInvitationCreatedResponse(BaseModel):
    invitation_id: str
    token: str
    username: str
    role: TeamRole
    expires_at: datetime


class TeamInvitationAcceptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=32, max_length=128)
    password: str = Field(min_length=12, max_length=256)


class TeamInvitationAcceptedResponse(BaseModel):
    accepted: Literal[True]
    username: str


PublicIdentityEcosystem = Literal["npm", "pypi", "go", "cargo", "composer", "maven", "nuget"]


class PublicIdentityAttestationCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ecosystem: PublicIdentityEcosystem
    package_name: str = Field(min_length=1, max_length=321)
    requested_ttl_days: int = Field(default=30, ge=1, le=90)


class PublicIdentityAttestationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-09.1"] = "2026-09-09.1"
    id: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    ecosystem: PublicIdentityEcosystem
    package_name: str
    status: Literal["pending", "approved", "expired", "revoked"]
    revision: int = Field(ge=1)
    requested_ttl_days: int = Field(ge=1, le=90)
    proposed_at: datetime
    approved_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None


class ProductAuditEvent(BaseModel):
    """One minimal, organization-scoped record of a product action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-06.1"] = "2026-09-06.1"
    id: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    organization_id: str = Field(min_length=1, max_length=64, pattern=r"^(?:local-admin|[a-f0-9]{32})$")
    actor_id: str = Field(min_length=1, max_length=64, pattern=r"^(?:local-admin|team-admin|[a-f0-9]{32})$")
    actor_role: Literal["administrator", "maintainer", "reader"]
    action: str = Field(min_length=3, max_length=96, pattern=r"^[a-z][a-z0-9_.-]+$")
    resource_type: str = Field(min_length=2, max_length=48, pattern=r"^[a-z][a-z0-9_-]+$")
    resource_id: str = Field(min_length=1, max_length=64, pattern=r"^(?:local-admin|team-admin|[a-f0-9]{32,64})$")
    result: Literal["succeeded", "denied", "failed"]
    correlation_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9:._-]*$")
    occurred_at: datetime
    metadata: dict[str, str | int | float | bool] = Field(default_factory=dict)

    @model_validator(mode="after")
    def timestamp_is_timezone_aware(self):
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("Product audit timestamps must include a timezone.")
        return self


class ProductAuditEventsResponse(BaseModel):
    items: list[ProductAuditEvent]
    next_cursor: str | None = None
    retention_days: int = Field(gt=0)


class RetentionPolicyClass(BaseModel):
    """One complete, value-only lifecycle declaration for a logical data class."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: Literal[
        "source_uploads",
        "analysis_results",
        "analysis_inventories",
        "public_advisory_snapshots",
        "public_advisory_cache",
        "report_exports",
        "remediation_plan_artifacts",
        "project_metadata",
        "finding_decisions",
        "passive_project_actions",
        "active_asset_metadata",
        "active_authorization_revisions",
        "active_verification_records",
        "active_execution_records",
        "active_change_approvals",
        "active_weekly_review_receipts",
        "execution_workspaces",
        "operation_journals",
        "product_audit",
        "auth_sessions",
        "automation_credentials",
        "team_invitations",
        "team_identity",
        "backup_bundles",
        "adoption_metrics",
    ]
    label: str = Field(min_length=3, max_length=80)
    category: Literal["project_data", "public_intelligence", "identity_and_operations", "external_copies"]
    scope: Literal["organization", "shared_public_data", "request", "execution", "deployment", "operator_external"]
    storage: Literal[
        "durable_upload_store",
        "durable_analysis_store",
        "embedded_in_analysis_result",
        "durable_public_intelligence_store",
        "durable_public_cache",
        "request_only",
        "durable_remediation_plan_store",
        "durable_project_store",
        "durable_finding_decision_store",
        "durable_project_action_store",
        "durable_active_asset_store",
        "durable_active_verification_store",
        "durable_active_change_approval_store",
        "durable_active_weekly_review_receipt_store",
        "ephemeral_workspace",
        "recoverable_operation_journal",
        "durable_product_audit_store",
        "durable_auth_state",
        "durable_aggregate_metrics_store",
        "operator_external",
    ]
    sensitivity: Literal[
        "project_content",
        "project_security_metadata",
        "public_provider_data",
        "credential_derived",
        "operational_metadata",
    ]
    retention_mode: Literal[
        "bounded",
        "until_explicit_deletion",
        "not_persisted",
        "ephemeral",
        "follows_parent",
        "external_policy",
    ]
    retention_days: int | None = Field(default=None, ge=0)
    freshness_seconds: int | None = Field(default=None, gt=0)
    retention_seconds: int | None = Field(default=None, gt=0)
    automatic_cleanup: bool
    manual_cleanup: bool
    follows_class: Literal["analysis_results", "project_metadata", "active_asset_metadata"] | None = None
    deletion_triggers: list[
        Literal[
            "retention_expiry",
            "explicit_source_deletion",
            "explicit_analysis_deletion",
            "explicit_project_deletion",
            "explicit_active_asset_deletion",
            "execution_completion",
            "startup_recovery",
            "session_expiry_or_revocation",
            "membership_revocation",
            "operator_restore",
            "operator_external_policy",
            "operator_local_deletion",
            "not_applicable",
        ]
    ] = Field(min_length=1, max_length=5)
    backup_disposition: Literal[
        "included_sensitive",
        "included_regenerable",
        "excluded_ephemeral",
        "not_server_persisted",
        "operator_managed",
    ]
    restore_behavior: Literal[
        "restored",
        "restored_sessions_revoked",
        "regenerated",
        "discarded",
        "not_applicable",
        "operator_managed",
    ]
    description: str = Field(min_length=3, max_length=320)

    @model_validator(mode="after")
    def lifecycle_relationship_is_consistent(self):
        if (self.retention_mode == "follows_parent") != (self.follows_class is not None):
            raise ValueError("Parent-linked retention must declare exactly one parent class.")
        if self.retention_mode == "not_persisted" and self.storage != "request_only":
            raise ValueError("Non-persisted data must be request-only.")
        if self.retention_mode == "ephemeral" and self.backup_disposition != "excluded_ephemeral":
            raise ValueError("Ephemeral data must remain outside backups.")
        return self


class SourceMetadataPolicy(BaseModel):
    """Disclosure and lifecycle rule for one source-identifying metadata field."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: Literal["original_filename", "content_sha256", "source_file_id", "source_reference", "source_channel"]
    label: str = Field(min_length=3, max_length=80)
    retained_in: list[Literal["source_upload", "project_record", "analysis_record", "derived_projection"]] = Field(
        min_length=1,
        max_length=4,
    )
    sensitivity: Literal[
        "private_source_label",
        "correlatable_content_digest",
        "opaque_internal_identifier",
        "safe_presentation_reference",
        "non_sensitive_provenance_enum",
    ]
    project_view_disclosure: Literal["withheld", "opaque_internal_only", "shown"]
    report_disclosure: Literal["withheld", "shown"]
    integration_disclosure: Literal["withheld", "shown"]
    retention_relation: Literal["follows_each_parent_record", "derived_not_stored"]
    description: str = Field(min_length=3, max_length=320)

    @model_validator(mode="after")
    def safe_reference_is_the_only_shared_presentation_value(self):
        shared = self.report_disclosure == "shown" or self.integration_disclosure == "shown"
        if shared != (self.key in {"source_reference", "source_channel"}):
            raise ValueError("Only safe source presentation metadata may be disclosed in reports or integrations.")
        if self.key == "source_reference" and self.retention_relation != "derived_not_stored":
            raise ValueError("The safe source reference must remain a derived value.")
        if self.key == "source_channel" and (
            self.sensitivity != "non_sensitive_provenance_enum"
            or self.retention_relation != "follows_each_parent_record"
        ):
            raise ValueError("The attested source channel must remain a retained closed enum.")
        return self


class RetentionPolicyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-10.7"] = "2026-09-10.7"
    cleanup_scope: Literal["active_organization_plus_shared_public_cache"] = "active_organization_plus_shared_public_cache"
    cleanup_runs_at_startup: bool = True
    manual_cleanup_allowed: bool
    application_encryption_at_rest: Literal["operator_managed"] = "operator_managed"
    backups: Literal["offline_bundle_operator_encrypted_not_automatically_purged"] = (
        "offline_bundle_operator_encrypted_not_automatically_purged"
    )
    data_classification_complete: Literal[True] = True
    backup_contract_version: Literal["2026-09-06.1"] = "2026-09-06.1"
    source_metadata_contract_version: Literal["2026-09-09.2"] = "2026-09-09.2"
    source_metadata: list["SourceMetadataPolicy"]
    classes: list[RetentionPolicyClass]

    @model_validator(mode="after")
    def data_classes_are_complete_and_unique(self):
        expected = {
            "source_uploads",
            "analysis_results",
            "analysis_inventories",
            "public_advisory_snapshots",
            "public_advisory_cache",
            "report_exports",
            "remediation_plan_artifacts",
            "project_metadata",
            "finding_decisions",
            "passive_project_actions",
            "active_asset_metadata",
            "active_authorization_revisions",
            "active_verification_records",
            "active_execution_records",
            "active_change_approvals",
            "active_weekly_review_receipts",
            "execution_workspaces",
            "operation_journals",
            "product_audit",
            "auth_sessions",
            "automation_credentials",
            "team_invitations",
            "team_identity",
            "backup_bundles",
            "adoption_metrics",
        }
        actual = [item.key for item in self.classes]
        if len(actual) != len(set(actual)) or set(actual) != expected:
            raise ValueError("Retention policy must classify every supported data class exactly once.")
        metadata_expected = {
            "original_filename",
            "content_sha256",
            "source_file_id",
            "source_reference",
            "source_channel",
        }
        metadata_actual = [item.key for item in self.source_metadata]
        if len(metadata_actual) != len(set(metadata_actual)) or set(metadata_actual) != metadata_expected:
            raise ValueError("Retention policy must classify every source metadata field exactly once.")
        return self


class RetentionCleanupClassResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    key: Literal[
        "source_uploads",
        "analysis_results",
        "public_advisory_cache",
        "automation_credentials",
        "team_invitations",
        "active_change_approvals",
        "active_weekly_review_receipts",
        "product_audit",
    ]
    status: Literal["completed", "failed", "disabled"]
    removed_items: int | None = Field(default=None, ge=0)
    detail: str = Field(min_length=3, max_length=200)


class RetentionCleanupResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-10.1"] = "2026-09-10.1"
    state: Literal["completed", "partial", "failed"]
    scope: Literal["active_organization_plus_shared_public_cache"] = "active_organization_plus_shared_public_cache"
    ran_at: datetime
    results: list[RetentionCleanupClassResult]


class TeamMemberRoleUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: TeamRole


AutomationTokenScope = Literal["project:read", "project:scan", "report:read"]


class AutomationTokenCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=3, max_length=80)
    project_id: str = Field(min_length=1, max_length=64)
    scopes: list[AutomationTokenScope] = Field(min_length=1, max_length=3)
    lifetime_seconds: int = Field(ge=300, le=7_776_000)


class AutomationTokenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    name: str
    project_id: str
    scopes: list[AutomationTokenScope]
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    last_used_at: datetime | None


class AutomationTokenCreatedResponse(AutomationTokenResponse):
    token: str = Field(min_length=70, max_length=96)


class AutomationTokenProbeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["ready", "expired", "revoked", "project_unavailable"]
    project_id: str
    scopes: list[AutomationTokenScope]
    scopes_complete: bool
    expires_at: datetime


class WebAuditRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    authorization_confirmed: bool = False


class DomainAuditRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
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
