from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
from typing import Callable, Literal
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.config import Settings
from app.storage import active_asset_deletion_is_pending, storage_lock


ACTIVE_ASSET_CONTRACT_VERSION = "2026-09-09.1"
ACTIVE_AUTHORIZATION_REVISION_CONTRACT_VERSION = "2026-09-10.1"
ACTIVE_AUTHORIZATION_MAX_REVISIONS = 64
ACTIVE_ASSET_PAGE_CONTRACT_VERSION = "2026-09-08.1"
ACTIVE_ASSET_DEFAULT_PAGE_SIZE = 24
ACTIVE_ASSET_MAX_PAGE_SIZE = 100
ACTIVE_ASSET_MAX_CURSOR_LENGTH = 512
ACTIVE_ASSET_BATCH_CONTRACT_VERSION = "2026-09-08.1"
ACTIVE_ASSET_BATCH_MAX_ITEMS = 50
ACTIVE_ASSET_INDEX_SCHEMA_VERSION = 1
ACTIVE_ASSET_INDEX_MAX_BYTES = 256 * 1024 * 1024
ACTIVE_CAPABILITIES = frozenset(
    {
        "active_nmap_basic",
        "active_dns_inventory",
        "active_dns_osint",
        "active_http_basic_header_review",
        "active_tls_basic",
    }
)
_ORGANIZATION_IDENTIFIER = re.compile(r"^(?:local-admin|[a-f0-9]{32})$")
_ACTOR_IDENTIFIER = re.compile(r"^(?:local-admin|team-admin|[a-f0-9]{32})$")
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,95}$")
_SENSITIVE_NOTE = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[_ -]?key|authorization|cookie|private[_ -]?key)\s*[:=]|"
    r"(?:https?|ssh)://[^\s/@:]+:[^\s/@]+@|-----BEGIN [A-Z ]+PRIVATE KEY-----"
)
_ACTIVE_ASSET_CURSOR_KEY = secrets.token_bytes(32)

ActiveAssetType = Literal["domain", "host", "ip", "http_origin"]
ActiveAssetStatus = Literal["active", "expired", "revoked"]
ActiveCapability = Literal[
    "active_nmap_basic",
    "active_dns_inventory",
    "active_dns_osint",
    "active_http_basic_header_review",
    "active_tls_basic",
]
ActiveProtocol = Literal["tcp", "dns", "http", "https", "tls"]
AuthorizationMethod = Literal["manual_attestation", "dns_txt", "http_well_known", "managed_private"]


class ActiveAssetNote(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["business_context", "scope_constraint", "operational_contact"]
    value: str = Field(min_length=1, max_length=200)

    @field_validator("value")
    @classmethod
    def reject_sensitive_note(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if _SENSITIVE_NOTE.search(normalized):
            raise ValueError("notes must not contain credentials or secrets")
        return normalized


class ActiveAssetCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_type: ActiveAssetType
    value: str = Field(min_length=1, max_length=253)
    responsible_user_ids: list[str] = Field(default_factory=list, max_length=20)
    capabilities: list[ActiveCapability] = Field(min_length=1, max_length=10)
    allowed_ports: list[int] = Field(default_factory=list, max_length=64)
    allowed_protocols: list[ActiveProtocol] = Field(min_length=1, max_length=5)
    authorization_method: AuthorizationMethod
    authorization_reference: str = Field(min_length=1, max_length=96)
    authorized_at: datetime
    expires_at: datetime
    notes: list[ActiveAssetNote] = Field(default_factory=list, max_length=10)

    @field_validator("responsible_user_ids")
    @classmethod
    def validate_responsible_ids(cls, values: list[str]) -> list[str]:
        if any(not _ACTOR_IDENTIFIER.fullmatch(value) for value in values):
            raise ValueError("responsible user identifiers are invalid")
        return sorted(set(values))

    @field_validator("capabilities", "allowed_protocols")
    @classmethod
    def deduplicate_scope(cls, values: list[str]) -> list[str]:
        if len(set(values)) != len(values):
            raise ValueError("scope values must be unique")
        return values

    @field_validator("allowed_ports")
    @classmethod
    def validate_ports(cls, values: list[int]) -> list[int]:
        if any(isinstance(value, bool) or value < 1 or value > 65535 for value in values):
            raise ValueError("ports must be integers between 1 and 65535")
        return sorted(set(values))

    @field_validator("authorization_reference")
    @classmethod
    def validate_reference(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if not _SAFE_REFERENCE.fullmatch(normalized) or _SENSITIVE_NOTE.search(normalized):
            raise ValueError("authorization reference must be a short non-sensitive label")
        return normalized

    @model_validator(mode="after")
    def validate_contract(self):
        self.value = canonicalize_active_asset(self.asset_type, self.value)
        self.authorized_at = _aware_utc(self.authorized_at)
        self.expires_at = _aware_utc(self.expires_at)
        _validate_authorization_window(self.authorized_at, self.expires_at, now=datetime.now(timezone.utc))
        _validate_active_scope(self.asset_type, self.capabilities, self.allowed_ports, self.allowed_protocols)
        return self


class ActiveAssetRenewRequest(BaseModel):
    """A re-attestation over the same exact asset with idempotent admission."""

    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(pattern=r"^[a-f0-9]{32}$")
    expected_revision_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    responsible_user_ids: list[str] = Field(max_length=20)
    capabilities: list[ActiveCapability] = Field(min_length=1, max_length=10)
    allowed_ports: list[int] = Field(default_factory=list, max_length=64)
    allowed_protocols: list[ActiveProtocol] = Field(min_length=1, max_length=5)
    authorization_method: AuthorizationMethod
    authorization_reference: str = Field(min_length=1, max_length=96)
    authorized_at: datetime
    expires_at: datetime
    renewal_confirmed: Literal[True]
    scope_expansion_confirmed: bool = False

    @field_validator("responsible_user_ids")
    @classmethod
    def validate_responsible_ids(cls, values: list[str]) -> list[str]:
        if any(not _ACTOR_IDENTIFIER.fullmatch(value) for value in values):
            raise ValueError("responsible user identifiers are invalid")
        return sorted(set(values))

    @field_validator("capabilities", "allowed_protocols")
    @classmethod
    def deduplicate_scope(cls, values: list[str]) -> list[str]:
        if len(set(values)) != len(values):
            raise ValueError("scope values must be unique")
        return values

    @field_validator("allowed_ports")
    @classmethod
    def validate_ports(cls, values: list[int]) -> list[int]:
        if any(isinstance(value, bool) or value < 1 or value > 65535 for value in values):
            raise ValueError("ports must be integers between 1 and 65535")
        return sorted(set(values))

    @field_validator("authorization_reference")
    @classmethod
    def validate_reference(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if not _SAFE_REFERENCE.fullmatch(normalized) or _SENSITIVE_NOTE.search(normalized):
            raise ValueError("authorization reference must be a short non-sensitive label")
        return normalized

    @model_validator(mode="after")
    def validate_window(self):
        self.authorized_at = _aware_utc(self.authorized_at)
        self.expires_at = _aware_utc(self.expires_at)
        _validate_authorization_window(self.authorized_at, self.expires_at, now=datetime.now(timezone.utc))
        return self


class ActiveAssetRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason_code: Literal["authorization_withdrawn", "asset_retired", "scope_changed", "security_hold"]


class ActiveAssetExecutionRequest(BaseModel):
    """An execution choice with no user-controlled target or scope expansion."""

    model_config = ConfigDict(extra="forbid")

    capability: ActiveCapability
    port: int | None = Field(default=None, ge=1, le=65535)
    authorization_reconfirmed: Literal[True]
    idempotency_key: str = Field(pattern=r"^[a-f0-9]{32}$")

    @model_validator(mode="after")
    def port_is_only_a_selector(self):
        if self.capability not in {"active_tls_basic"} and self.port is not None:
            raise ValueError("port selection is supported only for TLS basic")
        return self


class ActiveAssetExecutionCancelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cancellation_confirmed: Literal[True]


class ActiveAssetExecutionRetryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authorization_reconfirmed: Literal[True]
    idempotency_key: str = Field(pattern=r"^[a-f0-9]{32}$")


class ActiveAssetBaselineRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    baseline_confirmed: Literal[True]


class ActiveAssetTriageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observation_key: str = Field(pattern=r"^(?:tcp_port:[0-9]{1,5}|dns_(?:count|indicator):[A-Za-z0-9_-]{1,32}|dns_osint:[a-z_]{1,40}|http_header:[a-z0-9_]{1,64}|tls:[a-z_]{1,40})$")
    status: Literal["needs_review", "acknowledged", "expected_change", "dismissed"]
    comment_code: Literal["planned_change", "expected_service", "investigating", "needs_owner_review", "not_applicable"]


class ActiveAssetTriageEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    observation_key: str
    status: Literal["needs_review", "acknowledged", "expected_change", "dismissed"]
    comment_code: Literal["planned_change", "expected_service", "investigating", "needs_owner_review", "not_applicable"]
    actor_id: str = Field(pattern=r"^(?:local-admin|team-admin|[a-f0-9]{32})$")
    updated_at: datetime


class ActiveAssetEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    kind: Literal["registered", "renewed", "revoked", "responsibles_updated", "verification_started", "verified", "verification_failed", "execution_requested", "baseline_selected", "triage_updated"]
    occurred_at: datetime
    actor_id: str = Field(pattern=r"^(?:local-admin|team-admin|[a-f0-9]{32})$")
    reason_code: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{2,47}$")


class ActiveAuthorizationRevision(BaseModel):
    """Immutable, target-free public snapshot of one admitted authorization scope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[ACTIVE_AUTHORIZATION_REVISION_CONTRACT_VERSION] = ACTIVE_AUTHORIZATION_REVISION_CONTRACT_VERSION
    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    sequence: int = Field(ge=1, le=ACTIVE_AUTHORIZATION_MAX_REVISIONS)
    source: Literal["registration", "renewal"]
    scope_expanded: bool = False
    created_at: datetime
    authorized_at: datetime
    expires_at: datetime
    authorization_method: AuthorizationMethod
    capabilities: list[ActiveCapability] = Field(min_length=1, max_length=10)
    allowed_ports: list[int] = Field(default_factory=list, max_length=64)
    allowed_protocols: list[ActiveProtocol] = Field(min_length=1, max_length=5)
    digest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class ActiveAssetRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: Literal[ACTIVE_ASSET_CONTRACT_VERSION] = ACTIVE_ASSET_CONTRACT_VERSION
    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    organization_id: str = Field(pattern=r"^(?:local-admin|[a-f0-9]{32})$")
    owner_id: str = Field(pattern=r"^(?:local-admin|team-admin|[a-f0-9]{32})$")
    responsible_user_ids: list[str] = Field(max_length=20)
    asset_type: ActiveAssetType
    canonical_value: str
    capabilities: list[ActiveCapability]
    allowed_ports: list[int]
    allowed_protocols: list[ActiveProtocol]
    authorization_method: AuthorizationMethod
    authorization_reference: str
    authorized_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    status: ActiveAssetStatus
    notes: list[ActiveAssetNote]
    created_at: datetime
    updated_at: datetime
    baseline_execution_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    triage: list[ActiveAssetTriageEntry] = Field(default_factory=list, max_length=200)
    history: list[ActiveAssetEvent] = Field(max_length=500)
    authorization_revisions: list[ActiveAuthorizationRevision] = Field(
        default_factory=list,
        max_length=ACTIVE_AUTHORIZATION_MAX_REVISIONS,
    )

    @field_validator("responsible_user_ids")
    @classmethod
    def validate_persisted_responsible_ids(cls, values: list[str]) -> list[str]:
        if any(not _ACTOR_IDENTIFIER.fullmatch(value) for value in values):
            raise ValueError("responsible user identifiers are invalid")
        return sorted(set(values))

    @model_validator(mode="after")
    def validate_authorization_revision_chain(self):
        if not self.authorization_revisions:
            # Legacy records stay explicitly revision-unknown until re-attested.
            return self
        for expected_sequence, revision in enumerate(self.authorization_revisions, start=1):
            if revision.sequence != expected_sequence:
                raise ValueError("authorization revision sequence is invalid")
            expected_digest = active_authorization_revision_digest(
                asset_id=self.id,
                organization_id=self.organization_id,
                asset_type=self.asset_type,
                canonical_value=self.canonical_value,
                revision=revision,
            )
            if revision.digest_sha256 != expected_digest:
                raise ValueError("authorization revision digest is invalid")
        latest = self.authorization_revisions[-1]
        if (
            latest.authorized_at != _aware_utc(self.authorized_at)
            or latest.expires_at != _aware_utc(self.expires_at)
            or latest.authorization_method != self.authorization_method
            or latest.capabilities != sorted(self.capabilities)
            or latest.allowed_ports != sorted(self.allowed_ports)
            or latest.allowed_protocols != sorted(self.allowed_protocols)
        ):
            raise ValueError("current authorization scope does not match its latest revision")
        return self


class ActiveAssetPage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[ACTIVE_ASSET_PAGE_CONTRACT_VERSION] = ACTIVE_ASSET_PAGE_CONTRACT_VERSION
    items: list[ActiveAssetRecord] = Field(max_length=ACTIVE_ASSET_MAX_PAGE_SIZE)
    returned_count: int = Field(ge=0, le=ACTIVE_ASSET_MAX_PAGE_SIZE)
    page_size: int = Field(ge=1, le=ACTIVE_ASSET_MAX_PAGE_SIZE)
    has_more: bool
    next_cursor: str | None = Field(default=None, max_length=ACTIVE_ASSET_MAX_CURSOR_LENGTH)


class ActiveAssetPageRequest(BaseModel):
    """Closed search body so exact assets never enter access-log query strings."""

    model_config = ConfigDict(extra="forbid")

    page_size: int = Field(default=ACTIVE_ASSET_DEFAULT_PAGE_SIZE, ge=1, le=ACTIVE_ASSET_MAX_PAGE_SIZE)
    cursor: str | None = Field(default=None, min_length=1, max_length=ACTIVE_ASSET_MAX_CURSOR_LENGTH)
    status: ActiveAssetStatus | None = None
    query: str | None = Field(default=None, max_length=120)
    query_mode: Literal["prefix", "exact"] = "prefix"
    capability: ActiveCapability | None = None
    updated_within_days: Literal[7, 30] | None = None


class ActiveAssetRenewalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    asset: ActiveAssetRecord
    replayed: bool
    scope_expanded: bool


class ActiveAssetResponsiblesUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    responsible_user_ids: list[str] = Field(max_length=20)
    expected_updated_at: datetime
    assignment_confirmed: Literal[True]

    @field_validator("responsible_user_ids")
    @classmethod
    def validate_responsible_ids(cls, values: list[str]) -> list[str]:
        if any(not _ACTOR_IDENTIFIER.fullmatch(value) for value in values):
            raise ValueError("responsible user identifiers are invalid")
        return sorted(set(values))

    @field_validator("expected_updated_at")
    @classmethod
    def normalize_expected_updated_at(cls, value: datetime) -> datetime:
        return _aware_utc(value)


class ActiveMemberResponsibilityImpact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    affected_asset_count: int = Field(ge=0)
    will_become_unassigned_count: int = Field(ge=0)
    will_keep_other_responsibles_count: int = Field(ge=0)
    affected_project_count: int = Field(default=0, ge=0)
    projects_requiring_reassignment_count: int = Field(default=0, ge=0)


class ActiveAssetStoreError(RuntimeError):
    pass


class _ActiveAssetBatchJournal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[ACTIVE_ASSET_BATCH_CONTRACT_VERSION] = ACTIVE_ASSET_BATCH_CONTRACT_VERSION
    batch_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    organization_id: str = Field(pattern=r"^(?:local-admin|[a-f0-9]{32})$")
    actor_id: str = Field(pattern=r"^(?:local-admin|team-admin|[a-f0-9]{32})$")
    normalized_digest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    record_ids: list[str] = Field(min_length=1, max_length=ACTIVE_ASSET_BATCH_MAX_ITEMS)
    state: Literal["pending", "committed"]
    created_at: datetime


class ActiveAssetBatchReceipt(BaseModel):
    """Target-free durable proof used only to replay an exact committed batch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[ACTIVE_ASSET_BATCH_CONTRACT_VERSION] = ACTIVE_ASSET_BATCH_CONTRACT_VERSION
    batch_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    organization_id: str = Field(pattern=r"^(?:local-admin|[a-f0-9]{32})$")
    normalized_digest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    record_ids: list[str] = Field(min_length=1, max_length=ACTIVE_ASSET_BATCH_MAX_ITEMS)
    committed_at: datetime

    @property
    def id(self) -> str:
        """Expose the opaque storage identity to generic integrity validators."""

        return self.batch_id


class ActiveAssetStore:
    def __init__(self, settings: Settings, *, now_func: Callable[[], datetime] | None = None) -> None:
        self.settings = settings
        self.root = settings.data_dir / "results" / "active_assets"
        self.batch_root = settings.data_dir / "results" / "active_asset_batches"
        self.index_path = settings.data_dir / "results" / "active_asset_index.sqlite3"
        self._now_func = now_func or (lambda: datetime.now(timezone.utc))
        self._index_file_state: tuple[int, int, int, int, int] | None = None
        self._asset_root_state: tuple[int, int, int, int, int] | None = None
        self._organization_directory_states: dict[str, tuple[int, int, int, int, int] | None] = {}
        with storage_lock(self.settings):
            self._recover_batch_transactions_unlocked()

    def _rebuild_index_unlocked(self) -> None:
        """Recreate the derived index from validated JSON aggregate records."""

        records: list[ActiveAssetRecord] = []
        organization_states: dict[str, tuple[int, int, int, int, int] | None] = {}
        if self.root.exists():
            if self.root.is_symlink() or not self.root.is_dir():
                raise ActiveAssetStoreError("asset_store_invalid")
            try:
                organization_directories = sorted(self.root.iterdir(), key=lambda path: path.name)
            except OSError as exc:
                raise ActiveAssetStoreError("asset_store_invalid") from exc
            for directory in organization_directories:
                if directory.is_symlink() or not directory.is_dir():
                    raise ActiveAssetStoreError("asset_store_invalid")
                self._validate_organization_identity(directory.name)
                records.extend(self._load_all_unlocked(directory.name, include_deleting=True))
                organization_states[directory.name] = _safe_file_state(directory)

        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        self._remove_stale_index_artifacts_unlocked()
        if self.index_path.exists() or self.index_path.is_symlink():
            _validate_index_file(self.index_path)
        temporary = self.index_path.with_name(f".{self.index_path.name}.{uuid4().hex}.tmp")
        connection: sqlite3.Connection | None = None
        try:
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            connection = sqlite3.connect(temporary, timeout=30)
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            _create_active_asset_index_schema(connection)
            self._index_upsert_records_connection(connection, records)
            connection.execute(
                "INSERT INTO active_asset_index_metadata (key, value) VALUES ('schema_version', ?)",
                (str(ACTIVE_ASSET_INDEX_SCHEMA_VERSION),),
            )
            connection.commit()
            connection.close()
            connection = None
            os.chmod(temporary, 0o600)
            with temporary.open("rb") as handle:
                os.fsync(handle.fileno())
            temporary.replace(self.index_path)
            directory_descriptor = os.open(self.index_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                connection.close()
            temporary.unlink(missing_ok=True)
            raise ActiveAssetStoreError("asset_index_invalid") from exc
        _validate_index_file(self.index_path)
        self._index_file_state = _safe_file_state(self.index_path)
        self._asset_root_state = _optional_directory_state(self.root)
        self._organization_directory_states = organization_states

    def _remove_stale_index_artifacts_unlocked(self) -> None:
        exact_names = {
            f"{self.index_path.name}-journal",
            f"{self.index_path.name}-wal",
            f"{self.index_path.name}-shm",
        }
        temporary_pattern = re.compile(
            rf"^\.{re.escape(self.index_path.name)}\.[a-f0-9]{{32}}\.tmp(?:-(?:journal|wal|shm))?$"
        )
        try:
            candidates = list(self.index_path.parent.iterdir())
        except OSError as exc:
            raise ActiveAssetStoreError("asset_index_invalid") from exc
        for path in candidates:
            if path.name not in exact_names and not temporary_pattern.fullmatch(path.name):
                continue
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise ActiveAssetStoreError("asset_index_invalid") from exc
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ActiveAssetStoreError("asset_index_invalid")
            try:
                path.unlink()
            except OSError as exc:
                raise ActiveAssetStoreError("asset_index_invalid") from exc

    def _ensure_index_current_unlocked(self, organization_id: str) -> None:
        if self._index_file_state is None or (
            not self.index_path.exists() and not self.index_path.is_symlink()
        ):
            self._rebuild_index_unlocked()
            return
        try:
            index_state = _safe_file_state(self.index_path)
            organization_state = _optional_directory_state(self.root / organization_id)
        except ActiveAssetStoreError:
            raise
        if (
            index_state != self._index_file_state
            or organization_state != self._organization_directory_states.get(organization_id)
        ):
            self._rebuild_index_unlocked()

    def _connect_index_unlocked(self, *, query_only: bool = False) -> sqlite3.Connection:
        _validate_index_file(self.index_path)
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self.index_path, timeout=30)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 30000")
            if query_only:
                connection.execute("PRAGMA query_only = ON")
            version = connection.execute(
                "SELECT value FROM active_asset_index_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if version is None or version["value"] != str(ACTIVE_ASSET_INDEX_SCHEMA_VERSION):
                connection.close()
                raise ActiveAssetStoreError("asset_index_invalid")
            return connection
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise ActiveAssetStoreError("asset_index_invalid") from exc

    @staticmethod
    def _index_upsert_records_connection(
        connection: sqlite3.Connection, records: list[ActiveAssetRecord]
    ) -> None:
        for record in records:
            connection.execute(
                """
                INSERT INTO active_asset_index (
                    organization_id, asset_id, asset_type, canonical_value,
                    updated_at_micros, expires_at_micros, revoked, record_digest
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(organization_id, asset_id) DO UPDATE SET
                    asset_type = excluded.asset_type,
                    canonical_value = excluded.canonical_value,
                    updated_at_micros = excluded.updated_at_micros,
                    expires_at_micros = excluded.expires_at_micros,
                    revoked = excluded.revoked,
                    record_digest = excluded.record_digest
                """,
                (
                    record.organization_id,
                    record.id,
                    record.asset_type,
                    record.canonical_value.casefold(),
                    _datetime_micros(record.updated_at),
                    _datetime_micros(record.expires_at),
                    int(record.revoked_at is not None),
                    active_asset_record_digest(record),
                ),
            )
            connection.execute(
                "DELETE FROM active_asset_index_capabilities WHERE organization_id = ? AND asset_id = ?",
                (record.organization_id, record.id),
            )
            connection.executemany(
                """
                INSERT INTO active_asset_index_capabilities (organization_id, asset_id, capability)
                VALUES (?, ?, ?)
                """,
                [(record.organization_id, record.id, capability) for capability in record.capabilities],
            )

    def _index_upsert_records_unlocked(self, records: list[ActiveAssetRecord]) -> None:
        if self._index_file_state is None:
            self._rebuild_index_unlocked()
            return
        try:
            connection = self._connect_index_unlocked()
            try:
                self._index_upsert_records_connection(connection, records)
                connection.commit()
            finally:
                connection.close()
        except (ActiveAssetStoreError, sqlite3.Error):
            self._rebuild_index_unlocked()
            return
        _validate_index_file(self.index_path)
        self._index_file_state = _safe_file_state(self.index_path)
        self._asset_root_state = _optional_directory_state(self.root)
        for organization_id in {record.organization_id for record in records}:
            self._organization_directory_states[organization_id] = _optional_directory_state(
                self.root / organization_id
            )

    def _index_delete_records_unlocked(self, organization_id: str, asset_ids: list[str]) -> None:
        if not asset_ids:
            return
        if self._index_file_state is None:
            self._rebuild_index_unlocked()
            return
        try:
            connection = self._connect_index_unlocked()
            try:
                connection.executemany(
                    "DELETE FROM active_asset_index WHERE organization_id = ? AND asset_id = ?",
                    [(organization_id, asset_id) for asset_id in asset_ids],
                )
                connection.commit()
            finally:
                connection.close()
        except (ActiveAssetStoreError, sqlite3.Error):
            self._rebuild_index_unlocked()
            return
        _validate_index_file(self.index_path)
        self._index_file_state = _safe_file_state(self.index_path)
        self._asset_root_state = _optional_directory_state(self.root)
        self._organization_directory_states[organization_id] = _optional_directory_state(
            self.root / organization_id
        )

    def _write_record_unlocked(self, path: Path, record: ActiveAssetRecord) -> None:
        _atomic_write(path, record)
        self._index_upsert_records_unlocked([record])

    def _index_identity_exists_unlocked(
        self, organization_id: str, identities: set[tuple[str, str]]
    ) -> bool:
        if not identities:
            return False
        self._ensure_index_current_unlocked(organization_id)
        connection = self._connect_index_unlocked(query_only=True)
        try:
            return any(
                connection.execute(
                    """
                    SELECT 1 FROM active_asset_index
                    WHERE organization_id = ? AND asset_type = ? AND canonical_value = ?
                    LIMIT 1
                    """,
                    (organization_id, asset_type, canonical_value.casefold()),
                ).fetchone()
                is not None
                for asset_type, canonical_value in identities
            )
        except sqlite3.Error as exc:
            raise ActiveAssetStoreError("asset_index_invalid") from exc
        finally:
            connection.close()

    def index_ready(self) -> bool:
        """Return a target-free integrity signal for the generic storage readiness gate."""

        try:
            with storage_lock(self.settings):
                if self._index_file_state is None:
                    self._rebuild_index_unlocked()
                state_changed = (
                    _safe_file_state(self.index_path) != self._index_file_state
                    or _optional_directory_state(self.root) != self._asset_root_state
                    or any(
                        _optional_directory_state(self.root / organization_id) != expected
                        for organization_id, expected in self._organization_directory_states.items()
                    )
                )
                if state_changed:
                    self._rebuild_index_unlocked()
                connection = self._connect_index_unlocked(query_only=True)
                try:
                    result = connection.execute("PRAGMA quick_check").fetchone()
                    return result is not None and result[0] == "ok"
                finally:
                    connection.close()
        except (ActiveAssetStoreError, OSError, sqlite3.Error):
            return False

    def create(self, request: ActiveAssetCreateRequest, *, organization_id: str, actor_id: str) -> ActiveAssetRecord:
        self._validate_organization_identity(organization_id)
        self._validate_actor_identity(actor_id)
        now = _aware_utc(self._now_func())
        asset_id = uuid4().hex
        record = self._build_registration_record(
            request,
            organization_id=organization_id,
            actor_id=actor_id,
            asset_id=asset_id,
            now=now,
        )
        path = self._path(organization_id, asset_id)
        with storage_lock(self.settings):
            if self._organization_has_pending_deletion_unlocked(organization_id):
                raise ActiveAssetStoreError("asset_deletion_pending")
            if self._index_identity_exists_unlocked(
                organization_id, {(request.asset_type, request.value)}
            ):
                raise ActiveAssetStoreError("asset_identity_conflict")
            if path.exists() or path.is_symlink():
                raise ActiveAssetStoreError("asset_conflict")
            self._write_record_unlocked(path, record)
        return record

    def create_many(
        self,
        requests: list[ActiveAssetCreateRequest],
        *,
        organization_id: str,
        actor_id: str,
        normalized_digest_sha256: str,
        idempotency_key: str,
    ) -> tuple[list[ActiveAssetRecord], bool, str]:
        """Commit one bounded batch with rollback/recovery and deterministic replay."""

        self._validate_organization_identity(organization_id)
        self._validate_actor_identity(actor_id)
        if not 1 <= len(requests) <= ACTIVE_ASSET_BATCH_MAX_ITEMS:
            raise ActiveAssetStoreError("batch_item_limit")
        if not re.fullmatch(r"[a-f0-9]{64}", normalized_digest_sha256):
            raise ActiveAssetStoreError("batch_digest_invalid")
        if not re.fullmatch(r"[a-f0-9]{32}", idempotency_key):
            raise ActiveAssetStoreError("batch_idempotency_invalid")
        identities = [(request.asset_type, request.value) for request in requests]
        if len(set(identities)) != len(identities):
            raise ActiveAssetStoreError("batch_duplicate_identity")

        batch_id = hashlib.sha256(
            f"{ACTIVE_ASSET_BATCH_CONTRACT_VERSION}\0{organization_id}\0{actor_id}\0{idempotency_key}".encode("utf-8")
        ).hexdigest()[:32]
        now = _aware_utc(self._now_func())
        record_ids = [
            hashlib.sha256(f"{batch_id}\0{index}".encode("ascii")).hexdigest()[:32]
            for index in range(len(requests))
        ]
        records = [
            self._build_registration_record(
                request,
                organization_id=organization_id,
                actor_id=actor_id,
                asset_id=record_ids[index],
                now=now,
            )
            for index, request in enumerate(requests)
        ]
        journal = _ActiveAssetBatchJournal(
            batch_id=batch_id,
            organization_id=organization_id,
            actor_id=actor_id,
            normalized_digest_sha256=normalized_digest_sha256,
            record_ids=record_ids,
            state="pending",
            created_at=now,
        )
        receipt = ActiveAssetBatchReceipt(
            batch_id=batch_id,
            organization_id=organization_id,
            normalized_digest_sha256=normalized_digest_sha256,
            record_ids=record_ids,
            committed_at=now,
        )
        journal_path = self._batch_journal_path(organization_id, batch_id)
        receipt_path = self._batch_receipt_path(organization_id, batch_id)

        with storage_lock(self.settings):
            if receipt_path.exists():
                retained = self._read_batch_receipt(receipt_path, organization_id, batch_id)
                if retained.normalized_digest_sha256 != normalized_digest_sha256 or retained.record_ids != record_ids:
                    raise ActiveAssetStoreError("batch_idempotency_conflict")
                replayed = [self._read(self._path(organization_id, record_id), organization_id, record_id) for record_id in record_ids]
                if any(not _record_matches_registration(record, request) for record, request in zip(replayed, requests, strict=True)):
                    raise ActiveAssetStoreError("asset_store_invalid")
                return replayed, True, batch_id

            if self._organization_has_pending_deletion_unlocked(organization_id):
                raise ActiveAssetStoreError("asset_deletion_pending")
            if self._index_identity_exists_unlocked(organization_id, set(identities)):
                raise ActiveAssetStoreError("batch_asset_conflict")
            paths = [self._path(organization_id, record_id) for record_id in record_ids]
            if journal_path.exists() or any(path.exists() or path.is_symlink() for path in paths):
                raise ActiveAssetStoreError("asset_store_invalid")

            created_paths: list[Path] = []
            try:
                _atomic_write_json(journal_path, journal.model_dump(mode="json"))
                for path, record in zip(paths, records, strict=True):
                    _atomic_write(path, record)
                    created_paths.append(path)
                self._index_upsert_records_unlocked(records)
                committed_journal = journal.model_copy(update={"state": "committed"})
                _atomic_write_json(journal_path, committed_journal.model_dump(mode="json"))
                _atomic_write_json(receipt_path, receipt.model_dump(mode="json"))
                journal_path.unlink()
            except OSError as exc:
                for path in created_paths:
                    path.unlink(missing_ok=True)
                self._index_delete_records_unlocked(
                    organization_id, [path.stem for path in created_paths]
                )
                receipt_path.unlink(missing_ok=True)
                journal_path.unlink(missing_ok=True)
                raise ActiveAssetStoreError("asset_store_invalid") from exc
        return records, False, batch_id

    def _organization_has_pending_deletion_unlocked(self, organization_id: str) -> bool:
        return bool(self._pending_deletion_asset_ids_unlocked(organization_id))

    def _pending_deletion_asset_ids_unlocked(self, organization_id: str) -> set[str]:
        directory = self.settings.active_asset_deletions_dir
        if not directory.exists():
            return set()
        if directory.is_symlink() or not directory.is_dir():
            raise ActiveAssetStoreError("asset_store_invalid")
        pending: set[str] = set()
        for path in directory.glob("*.json"):
            if not re.fullmatch(r"[a-f0-9]{32}\.json", path.name):
                continue
            try:
                invalid_path = path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024
            except OSError as exc:
                raise ActiveAssetStoreError("asset_store_invalid") from exc
            if invalid_path:
                raise ActiveAssetStoreError("asset_store_invalid")
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise ActiveAssetStoreError("asset_store_invalid") from exc
            if isinstance(payload, dict) and payload.get("organization_id") == organization_id:
                pending.add(path.stem)
                if len(pending) > 500:
                    raise ActiveAssetStoreError("asset_store_invalid")
        return pending

    def _build_registration_record(
        self,
        request: ActiveAssetCreateRequest,
        *,
        organization_id: str,
        actor_id: str,
        asset_id: str,
        now: datetime,
    ) -> ActiveAssetRecord:
        event = ActiveAssetEvent(id=uuid4().hex, kind="registered", occurred_at=now, actor_id=actor_id)
        revision = build_active_authorization_revision(
            asset_id=asset_id,
            organization_id=organization_id,
            asset_type=request.asset_type,
            canonical_value=request.value,
            sequence=1,
            source="registration",
            created_at=now,
            authorized_at=request.authorized_at,
            expires_at=request.expires_at,
            authorization_method=request.authorization_method,
            capabilities=request.capabilities,
            allowed_ports=request.allowed_ports,
            allowed_protocols=request.allowed_protocols,
        )
        return ActiveAssetRecord(
            id=asset_id,
            organization_id=organization_id,
            owner_id=actor_id,
            responsible_user_ids=request.responsible_user_ids,
            asset_type=request.asset_type,
            canonical_value=request.value,
            capabilities=request.capabilities,
            allowed_ports=request.allowed_ports,
            allowed_protocols=request.allowed_protocols,
            authorization_method=request.authorization_method,
            authorization_reference=request.authorization_reference,
            authorized_at=request.authorized_at,
            expires_at=request.expires_at,
            status="active",
            notes=request.notes,
            created_at=now,
            updated_at=now,
            history=[event],
            authorization_revisions=[revision],
        )

    def list(self, *, organization_id: str, status: ActiveAssetStatus | None = None, query: str | None = None) -> list[ActiveAssetRecord]:
        self._validate_organization_identity(organization_id)
        normalized_query = (query or "").strip().casefold()
        if len(normalized_query) > 120:
            raise ActiveAssetStoreError("invalid_query")
        with storage_lock(self.settings):
            records = self._load_all_unlocked(organization_id)
        materialized = [self._materialize_status(record) for record in records]
        if status is not None:
            materialized = [record for record in materialized if record.status == status]
        if normalized_query:
            materialized = [record for record in materialized if normalized_query in record.canonical_value.casefold()]
        return sorted(materialized, key=lambda record: (record.updated_at, record.id), reverse=True)

    def existing_registration_identities(self, *, organization_id: str) -> set[tuple[str, str]]:
        """Return the owner-local uniqueness keys used by registration preflight."""

        self._validate_organization_identity(organization_id)
        with storage_lock(self.settings):
            if self._organization_has_pending_deletion_unlocked(organization_id):
                raise ActiveAssetStoreError("asset_deletion_pending")
            self._ensure_index_current_unlocked(organization_id)
            connection = self._connect_index_unlocked(query_only=True)
            try:
                rows = connection.execute(
                    """
                    SELECT asset_type, canonical_value FROM active_asset_index
                    WHERE organization_id = ?
                    """,
                    (organization_id,),
                ).fetchall()
            except sqlite3.Error as exc:
                raise ActiveAssetStoreError("asset_index_invalid") from exc
            finally:
                connection.close()
        return {(str(row["asset_type"]), str(row["canonical_value"])) for row in rows}

    def page(
        self,
        *,
        organization_id: str,
        page_size: int = ACTIVE_ASSET_DEFAULT_PAGE_SIZE,
        cursor: str | None = None,
        status: ActiveAssetStatus | None = None,
        query: str | None = None,
        query_mode: Literal["prefix", "exact"] = "prefix",
        capability: ActiveCapability | None = None,
        updated_within_days: Literal[7, 30] | None = None,
    ) -> ActiveAssetPage:
        """Return a bounded keyset page scoped to one organization.

        Cursors are process-local, authenticated capabilities over the owner,
        filter set and last sort key. Rotation on restart intentionally makes a
        stale cursor fail closed; callers restart from the first page.
        """

        self._validate_organization_identity(organization_id)
        if not 1 <= page_size <= ACTIVE_ASSET_MAX_PAGE_SIZE:
            raise ActiveAssetStoreError("invalid_page_size")
        normalized_query = (query or "").strip().casefold()
        if len(normalized_query) > 120 or query_mode not in {"prefix", "exact"}:
            raise ActiveAssetStoreError("invalid_query")
        if capability is not None and capability not in ACTIVE_CAPABILITIES:
            raise ActiveAssetStoreError("invalid_capability")
        if updated_within_days not in {None, 7, 30}:
            raise ActiveAssetStoreError("invalid_updated_window")
        filter_digest = _active_asset_filter_digest(
            organization_id=organization_id,
            status=status,
            query=normalized_query,
            query_mode=query_mode,
            capability=capability,
            updated_within_days=updated_within_days,
        )
        boundary: tuple[int, str] | None = None
        cutoff_micros = 0
        if cursor is not None:
            boundary, cutoff_micros = _decode_active_asset_cursor(
                cursor,
                organization_id=organization_id,
                filter_digest=filter_digest,
                updated_within_days=updated_within_days,
            )
        elif updated_within_days is not None:
            cutoff = _aware_utc(self._now_func()) - timedelta(days=updated_within_days)
            cutoff_micros = _datetime_micros(cutoff)

        with storage_lock(self.settings):
            self._ensure_index_current_unlocked(organization_id)
            try:
                selected = self._query_index_page_unlocked(
                    organization_id=organization_id,
                    page_size=page_size,
                    boundary=boundary,
                    status=status,
                    normalized_query=normalized_query,
                    query_mode=query_mode,
                    capability=capability,
                    cutoff_micros=cutoff_micros,
                )
            except ActiveAssetStoreError as exc:
                if str(exc) != "asset_index_invalid":
                    raise
                self._rebuild_index_unlocked()
                selected = self._query_index_page_unlocked(
                    organization_id=organization_id,
                    page_size=page_size,
                    boundary=boundary,
                    status=status,
                    normalized_query=normalized_query,
                    query_mode=query_mode,
                    capability=capability,
                    cutoff_micros=cutoff_micros,
                )
        items = selected[:page_size]
        has_more = len(selected) > page_size
        next_cursor = None
        if has_more and items:
            last = items[-1]
            next_cursor = _encode_active_asset_cursor(
                organization_id=organization_id,
                filter_digest=filter_digest,
                boundary=(_datetime_micros(last.updated_at), last.id),
                cutoff_micros=cutoff_micros,
            )
        return ActiveAssetPage(
            items=items,
            returned_count=len(items),
            page_size=page_size,
            has_more=has_more,
            next_cursor=next_cursor,
        )

    def operations_snapshot(
        self,
        *,
        organization_id: str,
        asset_limit: int = 500,
        high_priority_asset_ids: set[str] | None = None,
        review_priority_asset_ids: set[str] | None = None,
    ) -> tuple[list[ActiveAssetRecord], dict[str, int]]:
        """Return exact portfolio counters and only bounded action candidates."""

        self._validate_organization_identity(organization_id)
        if not 1 <= asset_limit <= 500:
            raise ActiveAssetStoreError("invalid_page_size")
        high_priority = set(high_priority_asset_ids or ())
        review_priority = set(review_priority_asset_ids or ()) - high_priority
        if len(high_priority) > 1_000 or len(review_priority) > 1_000:
            raise ActiveAssetStoreError("asset_index_invalid")
        for asset_id in high_priority | review_priority:
            self._validate_asset_id(asset_id)
        now = _aware_utc(self._now_func())
        now_micros = _datetime_micros(now)
        expiring_micros = _datetime_micros(now + timedelta(days=14))
        with storage_lock(self.settings):
            self._ensure_index_current_unlocked(organization_id)
            pending_ids = self._pending_deletion_asset_ids_unlocked(organization_id)
            exclusion = ""
            parameters: list[object] = [organization_id]
            if pending_ids:
                placeholders = ",".join("?" for _item in pending_ids)
                exclusion = f" AND asset_id NOT IN ({placeholders})"
                parameters.extend(sorted(pending_ids))
            connection = self._connect_index_unlocked(query_only=True)
            try:
                row = connection.execute(
                    f"""
                    SELECT
                        COUNT(*) AS total,
                        SUM(CASE WHEN revoked = 1 THEN 1 ELSE 0 END) AS revoked,
                        SUM(CASE WHEN revoked = 0 AND expires_at_micros <= ? THEN 1 ELSE 0 END) AS expired,
                        SUM(CASE WHEN revoked = 0 AND expires_at_micros > ? THEN 1 ELSE 0 END) AS active,
                        SUM(CASE WHEN revoked = 0 AND expires_at_micros > ?
                                      AND expires_at_micros <= ? THEN 1 ELSE 0 END) AS expiring
                    FROM active_asset_index
                    WHERE organization_id = ?{exclusion}
                    """,
                    (
                        now_micros,
                        now_micros,
                        now_micros,
                        expiring_micros,
                        *parameters,
                    ),
                ).fetchone()
                duplicate_rows = connection.execute(
                    f"""
                    SELECT COUNT(*) AS records
                    FROM active_asset_index
                    WHERE organization_id = ?{exclusion}
                    GROUP BY asset_type, canonical_value
                    HAVING COUNT(*) > 1
                    """,
                    tuple(parameters),
                ).fetchall()
                priority_clauses = [
                    "WHEN revoked = 0 AND expires_at_micros <= ? THEN 0"
                ]
                priority_parameters: list[object] = [now_micros]
                if high_priority:
                    placeholders = ",".join("?" for _item in high_priority)
                    priority_clauses.append(
                        f"WHEN revoked = 0 AND expires_at_micros > ? AND asset_id IN ({placeholders}) THEN 1"
                    )
                    priority_parameters.extend([now_micros, *sorted(high_priority)])
                priority_clauses.append(
                    "WHEN revoked = 0 AND expires_at_micros > ? AND expires_at_micros <= ? THEN 2"
                )
                priority_parameters.extend([now_micros, expiring_micros])
                if review_priority:
                    placeholders = ",".join("?" for _item in review_priority)
                    priority_clauses.append(
                        f"WHEN asset_id IN ({placeholders}) THEN 3"
                    )
                    priority_parameters.extend(sorted(review_priority))
                priority_expression = "CASE " + " ".join(priority_clauses) + " ELSE 4 END"
                candidate_rows = connection.execute(
                    f"""
                    SELECT asset_id, updated_at_micros, record_digest,
                           {priority_expression} AS priority_rank
                    FROM active_asset_index
                    WHERE organization_id = ?{exclusion}
                    ORDER BY priority_rank ASC,
                             CASE WHEN priority_rank IN (0, 2) THEN expires_at_micros END ASC,
                             updated_at_micros DESC, asset_id DESC
                    LIMIT ?
                    """,
                    (*priority_parameters, *parameters, asset_limit),
                ).fetchall()
            except sqlite3.Error as exc:
                raise ActiveAssetStoreError("asset_index_invalid") from exc
            finally:
                connection.close()
            assets: list[ActiveAssetRecord] = []
            priority_candidates = 0
            for candidate in candidate_rows:
                asset_id = str(candidate["asset_id"])
                persisted = self._read(
                    self._path(organization_id, asset_id), organization_id, asset_id
                )
                if (
                    _datetime_micros(persisted.updated_at)
                    != int(candidate["updated_at_micros"])
                    or active_asset_record_digest(persisted)
                    != str(candidate["record_digest"])
                ):
                    raise ActiveAssetStoreError("asset_index_invalid")
                assets.append(self._materialize_status(persisted))
                priority_candidates += int(candidate["priority_rank"] < 4)
        duplicate_counts = [int(item["records"]) for item in duplicate_rows]
        return assets, {
            "total": int(row["total"] or 0),
            "active": int(row["active"] or 0),
            "expired": int(row["expired"] or 0),
            "revoked": int(row["revoked"] or 0),
            "expiring_14_days": int(row["expiring"] or 0),
            "duplicate_identity_groups": len(duplicate_counts),
            "duplicate_identity_records": sum(duplicate_counts),
            "priority_candidates": priority_candidates,
        }

    def _query_index_page_unlocked(
        self,
        *,
        organization_id: str,
        page_size: int,
        boundary: tuple[int, str] | None,
        status: ActiveAssetStatus | None,
        normalized_query: str,
        query_mode: Literal["prefix", "exact"],
        capability: ActiveCapability | None,
        cutoff_micros: int,
    ) -> list[ActiveAssetRecord]:
        conditions = ["organization_id = ?"]
        parameters: list[object] = [organization_id]
        now_micros = _datetime_micros(_aware_utc(self._now_func()))
        if status == "active":
            conditions.extend(["revoked = 0", "expires_at_micros > ?"])
            parameters.append(now_micros)
        elif status == "expired":
            conditions.extend(["revoked = 0", "expires_at_micros <= ?"])
            parameters.append(now_micros)
        elif status == "revoked":
            conditions.append("revoked = 1")
        if normalized_query:
            if query_mode == "exact":
                conditions.append("canonical_value = ?")
                parameters.append(normalized_query)
            else:
                conditions.extend(["canonical_value >= ?", "canonical_value < ?"])
                parameters.extend([normalized_query, f"{normalized_query}\U0010ffff"])
        if capability is not None:
            conditions.append(
                """
                EXISTS (
                    SELECT 1 FROM active_asset_index_capabilities AS capabilities
                    WHERE capabilities.organization_id = active_asset_index.organization_id
                      AND capabilities.asset_id = active_asset_index.asset_id
                      AND capabilities.capability = ?
                )
                """
            )
            parameters.append(capability)
        if cutoff_micros:
            conditions.append("updated_at_micros >= ?")
            parameters.append(cutoff_micros)

        selected: list[ActiveAssetRecord] = []
        query_boundary = boundary
        connection = self._connect_index_unlocked(query_only=True)
        try:
            while len(selected) <= page_size:
                page_conditions = list(conditions)
                page_parameters = list(parameters)
                if query_boundary is not None:
                    page_conditions.append(
                        "(updated_at_micros < ? OR (updated_at_micros = ? AND asset_id < ?))"
                    )
                    page_parameters.extend(
                        [query_boundary[0], query_boundary[0], query_boundary[1]]
                    )
                page_parameters.append(page_size + 1)
                rows = connection.execute(
                    f"""
                    SELECT asset_id, updated_at_micros, record_digest
                    FROM active_asset_index
                    WHERE {' AND '.join(page_conditions)}
                    ORDER BY updated_at_micros DESC, asset_id DESC
                    LIMIT ?
                    """,
                    tuple(page_parameters),
                ).fetchall()
                if not rows:
                    break
                for row in rows:
                    asset_id = str(row["asset_id"])
                    query_boundary = (int(row["updated_at_micros"]), asset_id)
                    if active_asset_deletion_is_pending(self.settings, asset_id):
                        continue
                    persisted_record = self._read(
                        self._path(organization_id, asset_id), organization_id, asset_id
                    )
                    if (
                        _datetime_micros(persisted_record.updated_at) != int(row["updated_at_micros"])
                        or active_asset_record_digest(persisted_record) != str(row["record_digest"])
                    ):
                        raise ActiveAssetStoreError("asset_index_invalid")
                    record = self._materialize_status(persisted_record)
                    selected.append(record)
                    if len(selected) > page_size:
                        break
                if len(rows) < page_size + 1:
                    break
        except sqlite3.Error as exc:
            raise ActiveAssetStoreError("asset_index_invalid") from exc
        finally:
            connection.close()
        return selected

    def get(self, asset_id: str, *, organization_id: str) -> ActiveAssetRecord:
        self._validate_organization_identity(organization_id)
        self._validate_asset_id(asset_id)
        path = self._path(organization_id, asset_id)
        with storage_lock(self.settings):
            if active_asset_deletion_is_pending(self.settings, asset_id):
                raise ActiveAssetStoreError("asset_not_found")
            record = self._read(path, organization_id, asset_id)
        return self._materialize_status(record)

    def _get_for_deletion_unlocked(self, asset_id: str, *, organization_id: str) -> ActiveAssetRecord:
        """Read an asset after its deletion marker has intentionally hidden it."""

        return self._materialize_status(
            self._read(
                self._path(organization_id, asset_id),
                organization_id,
                asset_id,
                include_deleting=True,
            )
        )

    def delete_for_deletion(self, asset_id: str, *, organization_id: str) -> None:
        path = self._path(organization_id, asset_id)
        with storage_lock(self.settings):
            record = self._read(path, organization_id, asset_id, include_deleting=True)
            if record.organization_id != organization_id:
                raise ActiveAssetStoreError("asset_not_found")
            path.unlink(missing_ok=True)
            self._index_delete_records_unlocked(organization_id, [asset_id])

    def count_batch_receipts_for_asset_unlocked(self, asset_id: str, *, organization_id: str) -> int:
        """Count receipts linked to one asset while the caller owns the storage lock."""

        return sum(
            asset_id in receipt.record_ids
            for _path, receipt in self._iter_batch_receipts_unlocked(organization_id)
        )

    def delete_batch_receipts_for_asset(self, asset_id: str, *, organization_id: str) -> int:
        """Invalidate exact-batch replay after any member asset is explicitly deleted."""

        self._validate_asset_id(asset_id)
        self._validate_organization_identity(organization_id)
        removed = 0
        with storage_lock(self.settings):
            for path, receipt in self._iter_batch_receipts_unlocked(organization_id):
                if asset_id in receipt.record_ids:
                    path.unlink()
                    removed += 1
        return removed

    def assert_executable(
        self,
        asset_id: str,
        *,
        organization_id: str,
        capability: str,
        expected_authorization_revision_id: str | None = None,
    ) -> ActiveAssetRecord:
        record = self.get(asset_id, organization_id=organization_id)
        if record.status != "active":
            raise ActiveAssetStoreError(f"asset_{record.status}")
        if capability not in record.capabilities:
            raise ActiveAssetStoreError("capability_not_authorized")
        revision = current_active_authorization_revision(record)
        if revision is None:
            raise ActiveAssetStoreError("authorization_revision_required")
        if expected_authorization_revision_id is not None and revision.id != expected_authorization_revision_id:
            raise ActiveAssetStoreError("authorization_revision_changed")
        return record

    def admit_execution(self, asset_id: str, *, organization_id: str, actor_id: str, capability: str) -> ActiveAssetRecord:
        """Revalidate and append admission while sharing the revocation lock."""

        path = self._path(organization_id, asset_id)
        with storage_lock(self.settings):
            record = self._materialize_status(self._read(path, organization_id, asset_id))
            if record.status != "active":
                raise ActiveAssetStoreError(f"asset_{record.status}")
            if capability not in record.capabilities:
                raise ActiveAssetStoreError("capability_not_authorized")
            if current_active_authorization_revision(record) is None:
                raise ActiveAssetStoreError("authorization_revision_required")
            if len(record.history) >= 500:
                raise ActiveAssetStoreError("history_capacity_reached")
            now = _aware_utc(self._now_func())
            event = ActiveAssetEvent(id=uuid4().hex, kind="execution_requested", occurred_at=now, actor_id=actor_id)
            updated = record.model_copy(update={"updated_at": now, "history": [*record.history, event]})
            self._write_record_unlocked(path, updated)
        return updated

    def renew(
        self,
        asset_id: str,
        request: ActiveAssetRenewRequest,
        *,
        organization_id: str,
        actor_id: str,
    ) -> tuple[ActiveAssetRecord, bool, bool]:
        """Append one immutable revision; never edit or reactivate a revoked record."""

        self._validate_organization_identity(organization_id)
        self._validate_actor_identity(actor_id)
        path = self._path(organization_id, asset_id)
        revision_id = _renewal_revision_id(organization_id, asset_id, request.idempotency_key)
        with storage_lock(self.settings):
            record = self._materialize_status(self._read(path, organization_id, asset_id))
            if record.revoked_at is not None or record.status == "revoked":
                raise ActiveAssetStoreError("asset_revoked")
            current = current_active_authorization_revision(record)
            existing = next((item for item in record.authorization_revisions if item.id == revision_id), None)
            if existing is not None:
                if current is not None and current.id == existing.id and _renewal_matches(record, existing, request):
                    return record, True, existing.scope_expanded
                raise ActiveAssetStoreError("renewal_idempotency_conflict")
            expected_id = current.id if current is not None else None
            if request.expected_revision_id != expected_id:
                raise ActiveAssetStoreError("authorization_revision_changed")
            if len(record.authorization_revisions) >= ACTIVE_AUTHORIZATION_MAX_REVISIONS:
                raise ActiveAssetStoreError("authorization_revision_capacity_reached")
            if len(record.history) >= 500:
                raise ActiveAssetStoreError("history_capacity_reached")
            now = _aware_utc(self._now_func())
            try:
                _validate_authorization_window(request.authorized_at, request.expires_at, now=now)
                _validate_active_scope(record.asset_type, request.capabilities, request.allowed_ports, request.allowed_protocols)
            except ValueError as exc:
                raise ActiveAssetStoreError("invalid_renewal") from exc
            expanded = _scope_expanded(
                record.capabilities,
                record.allowed_ports,
                record.allowed_protocols,
                request.capabilities,
                request.allowed_ports,
                request.allowed_protocols,
            )
            if expanded and not request.scope_expansion_confirmed:
                raise ActiveAssetStoreError("scope_expansion_confirmation_required")
            sequence = (current.sequence + 1) if current is not None else 1
            revision = build_active_authorization_revision(
                asset_id=record.id,
                organization_id=record.organization_id,
                asset_type=record.asset_type,
                canonical_value=record.canonical_value,
                sequence=sequence,
                source="renewal",
                created_at=now,
                authorized_at=request.authorized_at,
                expires_at=request.expires_at,
                authorization_method=request.authorization_method,
                capabilities=request.capabilities,
                allowed_ports=request.allowed_ports,
                allowed_protocols=request.allowed_protocols,
                revision_id=revision_id,
                scope_expanded=expanded,
            )
            event = ActiveAssetEvent(
                id=uuid4().hex,
                kind="renewed",
                occurred_at=now,
                actor_id=actor_id,
                reason_code="scope_expanded" if expanded else "authorization_renewed",
            )
            updated = ActiveAssetRecord.model_validate(
                record.model_dump()
                | {
                    "capabilities": request.capabilities,
                    "responsible_user_ids": request.responsible_user_ids,
                    "allowed_ports": request.allowed_ports,
                    "allowed_protocols": request.allowed_protocols,
                    "authorization_method": request.authorization_method,
                    "authorization_reference": request.authorization_reference,
                    "authorized_at": request.authorized_at,
                    "expires_at": request.expires_at,
                    "revoked_at": None,
                    "status": "active",
                    "updated_at": now,
                    "history": [*record.history, event],
                    "authorization_revisions": [*record.authorization_revisions, revision],
                }
            )
            self._write_record_unlocked(path, updated)
        return updated, False, expanded

    def revoke(self, asset_id: str, *, organization_id: str, actor_id: str, reason_code: str) -> ActiveAssetRecord:
        if not re.fullmatch(r"[a-z][a-z0-9_]{2,47}", reason_code):
            raise ActiveAssetStoreError("invalid_reason")
        path = self._path(organization_id, asset_id)
        with storage_lock(self.settings):
            record = self._materialize_status(self._read(path, organization_id, asset_id))
            if record.revoked_at is not None:
                return record
            now = _aware_utc(self._now_func())
            event = ActiveAssetEvent(id=uuid4().hex, kind="revoked", occurred_at=now, actor_id=actor_id, reason_code=reason_code)
            updated = record.model_copy(update={"revoked_at": now, "status": "revoked", "updated_at": now, "history": [*record.history, event]})
            self._write_record_unlocked(path, updated)
        return updated

    def responsibility_impact(self, user_id: str, *, organization_id: str) -> ActiveMemberResponsibilityImpact:
        self._validate_organization_identity(organization_id)
        self._validate_actor_identity(user_id)
        with storage_lock(self.settings):
            affected = [record for record in self._load_all_unlocked(organization_id) if user_id in record.responsible_user_ids]
        becoming_unassigned = sum(1 for record in affected if len(record.responsible_user_ids) == 1)
        return ActiveMemberResponsibilityImpact(
            affected_asset_count=len(affected),
            will_become_unassigned_count=becoming_unassigned,
            will_keep_other_responsibles_count=len(affected) - becoming_unassigned,
        )

    def unassign_member(
        self,
        user_id: str,
        *,
        organization_id: str,
        actor_id: str,
    ) -> ActiveMemberResponsibilityImpact:
        """Remove a departing member under one asset lock without retaining their ID in history."""

        self._validate_organization_identity(organization_id)
        self._validate_actor_identity(user_id)
        self._validate_actor_identity(actor_id)
        with storage_lock(self.settings):
            affected = [record for record in self._load_all_unlocked(organization_id) if user_id in record.responsible_user_ids]
            if any(len(record.history) >= 500 for record in affected):
                raise ActiveAssetStoreError("history_capacity_reached")
            becoming_unassigned = sum(1 for record in affected if len(record.responsible_user_ids) == 1)
            now = _aware_utc(self._now_func())
            updates: list[tuple[Path, ActiveAssetRecord]] = []
            for record in affected:
                remaining = [value for value in record.responsible_user_ids if value != user_id]
                event = ActiveAssetEvent(
                    id=uuid4().hex,
                    kind="responsibles_updated",
                    occurred_at=now,
                    actor_id=actor_id,
                    reason_code="membership_revoked",
                )
                updated = record.model_copy(
                    update={
                        "responsible_user_ids": remaining,
                        "updated_at": now,
                        "history": [*record.history, event],
                    }
                )
                updates.append((self._path(organization_id, record.id), updated))
            for path, updated in updates:
                _atomic_write(path, updated)
            self._index_upsert_records_unlocked([updated for _path, updated in updates])
        return ActiveMemberResponsibilityImpact(
            affected_asset_count=len(affected),
            will_become_unassigned_count=becoming_unassigned,
            will_keep_other_responsibles_count=len(affected) - becoming_unassigned,
        )

    def set_responsibles(
        self,
        asset_id: str,
        request: ActiveAssetResponsiblesUpdateRequest,
        *,
        organization_id: str,
        actor_id: str,
    ) -> tuple[ActiveAssetRecord, bool]:
        self._validate_organization_identity(organization_id)
        self._validate_actor_identity(actor_id)
        path = self._path(organization_id, asset_id)
        with storage_lock(self.settings):
            record = self._materialize_status(self._read(path, organization_id, asset_id))
            if _aware_utc(record.updated_at) != request.expected_updated_at:
                raise ActiveAssetStoreError("asset_changed")
            if record.responsible_user_ids == request.responsible_user_ids:
                return record, False
            if len(record.history) >= 500:
                raise ActiveAssetStoreError("history_capacity_reached")
            now = _aware_utc(self._now_func())
            event = ActiveAssetEvent(
                id=uuid4().hex,
                kind="responsibles_updated",
                occurred_at=now,
                actor_id=actor_id,
                reason_code="responsibles_assigned" if request.responsible_user_ids else "responsibles_unassigned",
            )
            updated = record.model_copy(
                update={
                    "responsible_user_ids": request.responsible_user_ids,
                    "updated_at": now,
                    "history": [*record.history, event],
                }
            )
            self._write_record_unlocked(path, updated)
        return updated, True

    def append_event(
        self,
        asset_id: str,
        *,
        organization_id: str,
        actor_id: str,
        kind: ActiveAssetEvent.model_fields["kind"].annotation,
        reason_code: str | None = None,
    ) -> ActiveAssetRecord:
        path = self._path(organization_id, asset_id)
        with storage_lock(self.settings):
            record = self._materialize_status(self._read(path, organization_id, asset_id))
            if len(record.history) >= 500:
                raise ActiveAssetStoreError("history_capacity_reached")
            now = _aware_utc(self._now_func())
            event = ActiveAssetEvent(id=uuid4().hex, kind=kind, occurred_at=now, actor_id=actor_id, reason_code=reason_code)
            updated = record.model_copy(update={"updated_at": now, "history": [*record.history, event]})
            self._write_record_unlocked(path, updated)
        return updated

    def set_baseline(self, asset_id: str, *, organization_id: str, actor_id: str, execution_id: str) -> ActiveAssetRecord:
        path = self._path(organization_id, asset_id)
        with storage_lock(self.settings):
            record = self._materialize_status(self._read(path, organization_id, asset_id))
            now = _aware_utc(self._now_func())
            event = ActiveAssetEvent(id=uuid4().hex, kind="baseline_selected", occurred_at=now, actor_id=actor_id)
            updated = record.model_copy(update={"baseline_execution_id": execution_id, "updated_at": now, "history": [*record.history, event]})
            self._write_record_unlocked(path, updated)
        return updated

    def set_triage(
        self,
        asset_id: str,
        *,
        organization_id: str,
        actor_id: str,
        request: ActiveAssetTriageRequest,
    ) -> ActiveAssetRecord:
        path = self._path(organization_id, asset_id)
        with storage_lock(self.settings):
            record = self._materialize_status(self._read(path, organization_id, asset_id))
            now = _aware_utc(self._now_func())
            entry = ActiveAssetTriageEntry(
                observation_key=request.observation_key,
                status=request.status,
                comment_code=request.comment_code,
                actor_id=actor_id,
                updated_at=now,
            )
            triage = [item for item in record.triage if item.observation_key != entry.observation_key]
            triage.append(entry)
            if len(triage) > 200:
                raise ActiveAssetStoreError("triage_capacity_reached")
            event = ActiveAssetEvent(id=uuid4().hex, kind="triage_updated", occurred_at=now, actor_id=actor_id)
            updated = record.model_copy(update={"triage": triage, "updated_at": now, "history": [*record.history, event]})
            self._write_record_unlocked(path, updated)
        return updated

    def _load_all_unlocked(
        self, organization_id: str, *, include_deleting: bool = False
    ) -> list[ActiveAssetRecord]:
        directory = self.root / organization_id
        if not directory.exists():
            return []
        if directory.is_symlink() or not directory.is_dir():
            raise ActiveAssetStoreError("asset_store_invalid")
        records: list[ActiveAssetRecord] = []
        for path in directory.glob("*.json"):
            if re.fullmatch(r"[a-f0-9]{32}\.json", path.name):
                if not include_deleting and active_asset_deletion_is_pending(self.settings, path.stem):
                    continue
                records.append(
                    self._read(
                        path,
                        organization_id,
                        path.stem,
                        include_deleting=include_deleting,
                    )
                )
        return records

    def _read(
        self,
        path: Path,
        organization_id: str,
        asset_id: str,
        *,
        include_deleting: bool = False,
    ) -> ActiveAssetRecord:
        if not include_deleting and active_asset_deletion_is_pending(self.settings, asset_id):
            raise ActiveAssetStoreError("asset_not_found")
        if not path.exists():
            raise ActiveAssetStoreError("asset_not_found")
        if path.is_symlink() or not path.is_file():
            raise ActiveAssetStoreError("asset_store_invalid")
        try:
            record = ActiveAssetRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ActiveAssetStoreError("asset_store_invalid") from exc
        if record.id != asset_id or record.organization_id != organization_id:
            raise ActiveAssetStoreError("asset_store_invalid")
        return record

    def _materialize_status(self, record: ActiveAssetRecord) -> ActiveAssetRecord:
        status: ActiveAssetStatus = "revoked" if record.revoked_at else "expired" if record.expires_at <= _aware_utc(self._now_func()) else "active"
        return record if record.status == status else record.model_copy(update={"status": status})

    def _path(self, organization_id: str, asset_id: str) -> Path:
        self._validate_organization_identity(organization_id)
        self._validate_asset_id(asset_id)
        return self.root / organization_id / f"{asset_id}.json"

    def _batch_journal_path(self, organization_id: str, batch_id: str) -> Path:
        self._validate_organization_identity(organization_id)
        self._validate_asset_id(batch_id)
        return self.batch_root / organization_id / f".pending-{batch_id}.json"

    def _batch_receipt_path(self, organization_id: str, batch_id: str) -> Path:
        self._validate_organization_identity(organization_id)
        self._validate_asset_id(batch_id)
        return self.batch_root / organization_id / f"{batch_id}.json"

    def _read_batch_receipt(self, path: Path, organization_id: str, batch_id: str) -> ActiveAssetBatchReceipt:
        if path.is_symlink() or not path.is_file():
            raise ActiveAssetStoreError("asset_store_invalid")
        try:
            receipt = ActiveAssetBatchReceipt.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ActiveAssetStoreError("asset_store_invalid") from exc
        if receipt.organization_id != organization_id or receipt.batch_id != batch_id:
            raise ActiveAssetStoreError("asset_store_invalid")
        return receipt

    def _iter_batch_receipts_unlocked(
        self, organization_id: str
    ) -> list[tuple[Path, ActiveAssetBatchReceipt]]:
        directory = self.batch_root / organization_id
        if not directory.exists():
            return []
        if directory.is_symlink() or not directory.is_dir():
            raise ActiveAssetStoreError("asset_store_invalid")
        receipts: list[tuple[Path, ActiveAssetBatchReceipt]] = []
        for path in directory.iterdir():
            if path.name.startswith(".pending-"):
                continue
            if (
                path.is_symlink()
                or not path.is_file()
                or path.suffix != ".json"
                or not re.fullmatch(r"[a-f0-9]{32}", path.stem)
            ):
                raise ActiveAssetStoreError("asset_store_invalid")
            receipts.append((path, self._read_batch_receipt(path, organization_id, path.stem)))
        return receipts

    def _recover_batch_transactions_unlocked(self) -> None:
        if not self.batch_root.exists():
            return
        if self.batch_root.is_symlink() or not self.batch_root.is_dir():
            raise ActiveAssetStoreError("asset_store_invalid")
        for organization_dir in self.batch_root.iterdir():
            if organization_dir.is_symlink() or not organization_dir.is_dir():
                raise ActiveAssetStoreError("asset_store_invalid")
            self._validate_organization_identity(organization_dir.name)
            for journal_path in organization_dir.glob(".pending-*.json"):
                if journal_path.is_symlink() or not journal_path.is_file():
                    raise ActiveAssetStoreError("asset_store_invalid")
                try:
                    journal = _ActiveAssetBatchJournal.model_validate_json(journal_path.read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    raise ActiveAssetStoreError("asset_store_invalid") from exc
                if journal.organization_id != organization_dir.name or journal_path.name != f".pending-{journal.batch_id}.json":
                    raise ActiveAssetStoreError("asset_store_invalid")
                paths = [self._path(journal.organization_id, record_id) for record_id in journal.record_ids]
                receipt_path = self._batch_receipt_path(journal.organization_id, journal.batch_id)
                if journal.state == "committed" and all(path.exists() and path.is_file() and not path.is_symlink() for path in paths):
                    if not receipt_path.exists():
                        receipt = ActiveAssetBatchReceipt(
                            batch_id=journal.batch_id,
                            organization_id=journal.organization_id,
                            normalized_digest_sha256=journal.normalized_digest_sha256,
                            record_ids=journal.record_ids,
                            committed_at=journal.created_at,
                        )
                        _atomic_write_json(receipt_path, receipt.model_dump(mode="json"))
                else:
                    for path in paths:
                        path.unlink(missing_ok=True)
                    receipt_path.unlink(missing_ok=True)
                journal_path.unlink()

    @staticmethod
    def _validate_organization_identity(value: str) -> None:
        if not _ORGANIZATION_IDENTIFIER.fullmatch(value):
            raise ActiveAssetStoreError("invalid_identity")

    @staticmethod
    def _validate_actor_identity(value: str) -> None:
        if not _ACTOR_IDENTIFIER.fullmatch(value):
            raise ActiveAssetStoreError("invalid_identity")

    @staticmethod
    def _validate_asset_id(value: str) -> None:
        if not re.fullmatch(r"[a-f0-9]{32}", value):
            raise ActiveAssetStoreError("asset_not_found")


def _active_asset_filter_digest(
    *,
    organization_id: str,
    status: ActiveAssetStatus | None,
    query: str,
    query_mode: Literal["prefix", "exact"],
    capability: ActiveCapability | None,
    updated_within_days: Literal[7, 30] | None,
) -> str:
    payload = json.dumps(
        {
            "capability": capability or "",
            "query": query,
            "query_mode": query_mode,
            "status": status or "",
            "updated_within_days": updated_within_days or 0,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(
        _ACTIVE_ASSET_CURSOR_KEY,
        b"inspectra-active-assets-filter-v1\0" + organization_id.encode("ascii") + b"\0" + payload,
        hashlib.sha256,
    ).hexdigest()


def _encode_active_asset_cursor(
    *,
    organization_id: str,
    filter_digest: str,
    boundary: tuple[int, str],
    cutoff_micros: int,
) -> str:
    owner_digest = hmac.new(
        _ACTIVE_ASSET_CURSOR_KEY,
        b"inspectra-active-assets-owner-v1\0" + organization_id.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    payload = json.dumps(
        {
            "c": cutoff_micros,
            "f": filter_digest,
            "i": boundary[1],
            "o": owner_digest,
            "u": boundary[0],
            "v": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    signature = hmac.new(
        _ACTIVE_ASSET_CURSOR_KEY,
        b"inspectra-active-assets-cursor-v1\0" + payload,
        hashlib.sha256,
    ).digest()
    return f"{_urlsafe_encode(payload)}.{_urlsafe_encode(signature)}"


def _decode_active_asset_cursor(
    cursor: str,
    *,
    organization_id: str,
    filter_digest: str,
    updated_within_days: Literal[7, 30] | None,
) -> tuple[tuple[int, str], int]:
    if not 1 <= len(cursor) <= ACTIVE_ASSET_MAX_CURSOR_LENGTH or cursor.count(".") != 1:
        raise ActiveAssetStoreError("invalid_cursor")
    encoded_payload, encoded_signature = cursor.split(".", 1)
    try:
        payload = _urlsafe_decode(encoded_payload)
        signature = _urlsafe_decode(encoded_signature)
        document = json.loads(payload)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActiveAssetStoreError("invalid_cursor") from exc
    expected_signature = hmac.new(
        _ACTIVE_ASSET_CURSOR_KEY,
        b"inspectra-active-assets-cursor-v1\0" + payload,
        hashlib.sha256,
    ).digest()
    expected_owner = hmac.new(
        _ACTIVE_ASSET_CURSOR_KEY,
        b"inspectra-active-assets-owner-v1\0" + organization_id.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    if (
        len(signature) != hashlib.sha256().digest_size
        or not hmac.compare_digest(signature, expected_signature)
        or not isinstance(document, dict)
        or set(document) != {"c", "f", "i", "o", "u", "v"}
        or document.get("v") != 1
        or not isinstance(document.get("o"), str)
        or not hmac.compare_digest(document["o"], expected_owner)
        or not isinstance(document.get("f"), str)
        or not hmac.compare_digest(document["f"], filter_digest)
        or not isinstance(document.get("i"), str)
        or re.fullmatch(r"[a-f0-9]{32}", document["i"]) is None
        or isinstance(document.get("u"), bool)
        or not isinstance(document.get("u"), int)
        or not 0 <= document["u"] <= 10**18
        or isinstance(document.get("c"), bool)
        or not isinstance(document.get("c"), int)
        or not 0 <= document["c"] <= 10**18
        or (updated_within_days is None and document["c"] != 0)
        or (updated_within_days is not None and document["c"] == 0)
    ):
        raise ActiveAssetStoreError("invalid_cursor")
    return (document["u"], document["i"]), document["c"]


def _urlsafe_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _urlsafe_decode(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid base64url")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if _urlsafe_encode(decoded) != value:
        raise ValueError("non-canonical base64url")
    return decoded


def _datetime_micros(value: datetime) -> int:
    normalized = _aware_utc(value)
    return int(normalized.timestamp()) * 1_000_000 + normalized.microsecond


def canonicalize_active_asset(asset_type: ActiveAssetType, value: str) -> str:
    raw = value.strip()
    if not raw or "*" in raw or "/" in raw and asset_type != "http_origin":
        raise ValueError("asset must be one exact target without wildcard or range")
    if asset_type == "ip":
        try:
            return ipaddress.ip_address(raw).compressed
        except ValueError as exc:
            raise ValueError("invalid IP address") from exc
    if asset_type == "http_origin":
        try:
            parsed = urlsplit(raw)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("invalid HTTP origin") from exc
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("HTTP origin must use http/https without credentials")
        if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
            raise ValueError("HTTP origin must not include path, query, or fragment")
        host = _canonical_host(parsed.hostname)
        default_port = 443 if parsed.scheme == "https" else 80
        return f"{parsed.scheme}://{host}" + (f":{port}" if port and port != default_port else "")
    host = _canonical_host(raw)
    if asset_type == "domain" and _looks_like_ip(host):
        raise ValueError("domain asset cannot be an IP address")
    return host


def asset_target_for_capability(record: ActiveAssetRecord, capability: str, *, port: int | None = None) -> str:
    if capability == "active_http_basic_header_review":
        if record.asset_type == "http_origin":
            return record.canonical_value
        scheme = "https" if "https" in record.allowed_protocols else "http"
        selected_port = port or (443 if scheme == "https" else 80)
        suffix = "" if selected_port == (443 if scheme == "https" else 80) else f":{selected_port}"
        host = f"[{record.canonical_value}]" if ":" in record.canonical_value else record.canonical_value
        return f"{scheme}://{host}{suffix}"
    if record.asset_type == "http_origin":
        return urlsplit(record.canonical_value).hostname or record.canonical_value
    return record.canonical_value


def current_active_authorization_revision(record: ActiveAssetRecord) -> ActiveAuthorizationRevision | None:
    return record.authorization_revisions[-1] if record.authorization_revisions else None


def build_active_authorization_revision(
    *,
    asset_id: str,
    organization_id: str,
    asset_type: ActiveAssetType,
    canonical_value: str,
    sequence: int,
    source: Literal["registration", "renewal"],
    created_at: datetime,
    authorized_at: datetime,
    expires_at: datetime,
    authorization_method: AuthorizationMethod,
    capabilities: list[ActiveCapability],
    allowed_ports: list[int],
    allowed_protocols: list[ActiveProtocol],
    revision_id: str | None = None,
    scope_expanded: bool = False,
) -> ActiveAuthorizationRevision:
    provisional = ActiveAuthorizationRevision(
        id=revision_id or uuid4().hex,
        sequence=sequence,
        source=source,
        scope_expanded=scope_expanded,
        created_at=_aware_utc(created_at),
        authorized_at=_aware_utc(authorized_at),
        expires_at=_aware_utc(expires_at),
        authorization_method=authorization_method,
        capabilities=sorted(capabilities),
        allowed_ports=sorted(allowed_ports),
        allowed_protocols=sorted(allowed_protocols),
        digest_sha256="0" * 64,
    )
    digest = active_authorization_revision_digest(
        asset_id=asset_id,
        organization_id=organization_id,
        asset_type=asset_type,
        canonical_value=canonical_value,
        revision=provisional,
    )
    return provisional.model_copy(update={"digest_sha256": digest})


def active_authorization_revision_digest(
    *,
    asset_id: str,
    organization_id: str,
    asset_type: ActiveAssetType,
    canonical_value: str,
    revision: ActiveAuthorizationRevision,
) -> str:
    payload = {
        "contract_version": revision.contract_version,
        "revision_id": revision.id,
        "asset_id": asset_id,
        "organization_id": organization_id,
        "asset_type": asset_type,
        "canonical_value": canonical_value,
        "sequence": revision.sequence,
        "source": revision.source,
        "scope_expanded": revision.scope_expanded,
        "created_at": _aware_utc(revision.created_at).isoformat(),
        "authorized_at": _aware_utc(revision.authorized_at).isoformat(),
        "expires_at": _aware_utc(revision.expires_at).isoformat(),
        "authorization_method": revision.authorization_method,
        "capabilities": sorted(revision.capabilities),
        "allowed_ports": sorted(revision.allowed_ports),
        "allowed_protocols": sorted(revision.allowed_protocols),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _validate_authorization_window(authorized_at: datetime, expires_at: datetime, *, now: datetime) -> None:
    authorized_at = _aware_utc(authorized_at)
    expires_at = _aware_utc(expires_at)
    now = _aware_utc(now)
    if authorized_at > now + timedelta(minutes=5):
        raise ValueError("authorization date cannot be in the future")
    if expires_at <= now:
        raise ValueError("authorization must not already be expired")
    if expires_at <= authorized_at:
        raise ValueError("expiration must be after authorization")
    if expires_at - authorized_at > timedelta(days=366):
        raise ValueError("authorization lifetime exceeds 366 days")


def _validate_active_scope(
    asset_type: ActiveAssetType,
    capabilities: list[ActiveCapability],
    allowed_ports: list[int],
    allowed_protocols: list[ActiveProtocol],
) -> None:
    if "active_nmap_basic" in capabilities and ("tcp" not in allowed_protocols or not allowed_ports):
        raise ValueError("Nmap basic requires TCP and at least one explicit port")
    if "active_nmap_basic" in capabilities and len(allowed_ports) > 32:
        raise ValueError("Nmap basic accepts at most 32 explicit ports")
    if "active_tls_basic" in capabilities and ("tls" not in allowed_protocols or not allowed_ports):
        raise ValueError("TLS basic requires TLS and at least one explicit port")
    if "active_tls_basic" in capabilities and not set(allowed_ports).intersection({443, 8443, 9443}):
        raise ValueError("TLS basic requires at least one supported port: 443, 8443, or 9443")
    if any(capability.startswith("active_dns_") for capability in capabilities):
        if asset_type not in {"domain", "host"} or "dns" not in allowed_protocols:
            raise ValueError("DNS capabilities require an exact domain or host and DNS protocol")
    if "active_http_basic_header_review" in capabilities and not ({"http", "https"} & set(allowed_protocols)):
        raise ValueError("HTTP header review requires HTTP or HTTPS")


def _scope_expanded(
    old_capabilities: list[ActiveCapability],
    old_ports: list[int],
    old_protocols: list[ActiveProtocol],
    new_capabilities: list[ActiveCapability],
    new_ports: list[int],
    new_protocols: list[ActiveProtocol],
) -> bool:
    return bool(
        set(new_capabilities) - set(old_capabilities)
        or set(new_ports) - set(old_ports)
        or set(new_protocols) - set(old_protocols)
    )


def _renewal_revision_id(organization_id: str, asset_id: str, idempotency_key: str) -> str:
    material = (
        f"{ACTIVE_AUTHORIZATION_REVISION_CONTRACT_VERSION}\0{organization_id}\0{asset_id}\0{idempotency_key}"
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()[:32]


def _renewal_matches(
    record: ActiveAssetRecord,
    revision: ActiveAuthorizationRevision,
    request: ActiveAssetRenewRequest,
) -> bool:
    return bool(
        record.authorization_reference == request.authorization_reference
        and record.responsible_user_ids == request.responsible_user_ids
        and revision.authorized_at == request.authorized_at
        and revision.expires_at == request.expires_at
        and revision.authorization_method == request.authorization_method
        and revision.capabilities == sorted(request.capabilities)
        and revision.allowed_ports == sorted(request.allowed_ports)
        and revision.allowed_protocols == sorted(request.allowed_protocols)
    )


def _canonical_host(value: str) -> str:
    host = value.rstrip(".").casefold()
    if not host or len(host) > 253 or any(not _HOST_LABEL.fullmatch(label) for label in host.split(".")):
        raise ValueError("invalid exact host or domain")
    return host


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(timezone.utc)


def active_asset_record_digest(record: ActiveAssetRecord) -> str:
    payload = json.dumps(
        record.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _create_active_asset_index_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE active_asset_index_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE active_asset_index (
            organization_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            canonical_value TEXT NOT NULL,
            updated_at_micros INTEGER NOT NULL,
            expires_at_micros INTEGER NOT NULL,
            revoked INTEGER NOT NULL CHECK (revoked IN (0, 1)),
            record_digest TEXT NOT NULL,
            PRIMARY KEY (organization_id, asset_id)
        );
        CREATE TABLE active_asset_index_capabilities (
            organization_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            capability TEXT NOT NULL,
            PRIMARY KEY (organization_id, asset_id, capability),
            FOREIGN KEY (organization_id, asset_id)
                REFERENCES active_asset_index (organization_id, asset_id)
                ON DELETE CASCADE
        );
        CREATE INDEX active_asset_index_page
            ON active_asset_index (organization_id, updated_at_micros DESC, asset_id DESC);
        CREATE INDEX active_asset_index_identity
            ON active_asset_index (organization_id, asset_type, canonical_value);
        CREATE INDEX active_asset_index_status
            ON active_asset_index (organization_id, revoked, expires_at_micros, updated_at_micros DESC);
        CREATE INDEX active_asset_index_capability
            ON active_asset_index_capabilities (organization_id, capability, asset_id);
        """
    )


def _validate_index_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ActiveAssetStoreError("asset_index_invalid") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > ACTIVE_ASSET_INDEX_MAX_BYTES
        or metadata.st_mode & 0o077
    ):
        raise ActiveAssetStoreError("asset_index_invalid")


def _safe_file_state(path: Path) -> tuple[int, int, int, int, int]:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise ActiveAssetStoreError("asset_index_invalid") from exc
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _optional_directory_state(path: Path) -> tuple[int, int, int, int, int] | None:
    if not path.exists() and not path.is_symlink():
        return None
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ActiveAssetStoreError("asset_store_invalid") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ActiveAssetStoreError("asset_store_invalid")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _atomic_write(path: Path, record: ActiveAssetRecord) -> None:
    _atomic_write_json(path, record.model_dump(mode="json"))


def _atomic_write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    temporary.replace(path)


def _record_matches_registration(record: ActiveAssetRecord, request: ActiveAssetCreateRequest) -> bool:
    return (
        record.asset_type == request.asset_type
        and record.canonical_value == request.value
        and record.responsible_user_ids == request.responsible_user_ids
        and record.capabilities == request.capabilities
        and record.allowed_ports == request.allowed_ports
        and record.allowed_protocols == request.allowed_protocols
        and record.authorization_method == request.authorization_method
        and record.authorization_reference == request.authorization_reference
        and record.authorized_at == request.authorized_at
        and record.expires_at == request.expires_at
        and record.notes == request.notes
    )
