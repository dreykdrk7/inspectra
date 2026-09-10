"""Optional four-eyes gate for critical Active authorization changes.

The store never retains authorization references, notes, responsible identities
or a complete mutation payload.  A canonical digest binds the later mutation to
the reviewed closed scope.  Exact registration targets exist only while a
request is actionable and are scrubbed at every terminal transition.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.config import Settings
from app.storage import _atomic_write_json, storage_lock


ACTIVE_CHANGE_APPROVAL_CONTRACT_VERSION = "2026-09-10.1"
ACTIVE_CHANGE_APPROVAL_STORE_VERSION = 1
ACTIVE_CHANGE_APPROVAL_TTL_HOURS = 24
ACTIVE_CHANGE_APPROVAL_TERMINAL_RETENTION_DAYS = 90
ACTIVE_CHANGE_APPROVAL_MAX_RECORDS = 500
ACTIVE_CHANGE_APPROVAL_MAX_BYTES = 2 * 1024 * 1024

ActiveChangeKind = Literal["registration", "renewal", "revocation"]
ActiveChangeStatus = Literal[
    "pending", "approved", "executing", "consumed", "rejected", "expired", "interrupted"
]

_ORGANIZATION_ID = re.compile(r"^(?:local-admin|[a-f0-9]{32})$")
_OPAQUE_ID = re.compile(r"^[a-f0-9]{32}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")


class ActiveChangeApprovalError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ActiveChangeSummary(BaseModel):
    """Closed review material; never notes, references or account identities."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    asset_type: Literal["domain", "host", "ip", "http_origin"]
    review_target: str | None = Field(default=None, max_length=253)
    scope_change: Literal["new_registration", "same_scope", "expanded_scope", "reduced_scope", "revocation"]
    capabilities: tuple[str, ...] = Field(default=(), max_length=10)
    allowed_ports: tuple[int, ...] = Field(default=(), max_length=64)
    allowed_protocols: tuple[str, ...] = Field(default=(), max_length=5)
    authorization_expires_at: datetime | None = None
    reason_code: Literal[
        "authorization_withdrawn", "asset_retired", "scope_changed", "security_hold"
    ] | None = None


class ActiveChangeApprovalRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-10.1"] = ACTIVE_CHANGE_APPROVAL_CONTRACT_VERSION
    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    organization_id: str = Field(pattern=r"^(?:local-admin|[a-f0-9]{32})$")
    asset_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    kind: ActiveChangeKind
    status: ActiveChangeStatus
    operation_digest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    requester_digest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    requester_role: Literal["administrator", "maintainer"]
    approver_digest_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    requested_at: datetime
    expires_at: datetime
    decided_at: datetime | None = None
    consumed_at: datetime | None = None
    summary: ActiveChangeSummary

    @model_validator(mode="after")
    def validate_lifecycle(self):
        values = (self.requested_at, self.expires_at, self.decided_at, self.consumed_at)
        if any(value is not None and (value.tzinfo is None or value.utcoffset() is None) for value in values):
            raise ValueError("Approval timestamps must include a timezone.")
        if self.expires_at <= self.requested_at:
            raise ValueError("Approval expiry is invalid.")
        if self.kind == "registration" and self.asset_id is not None:
            raise ValueError("Registration approval must not bind a pre-existing asset.")
        if self.kind != "registration" and self.asset_id is None:
            raise ValueError("Existing-asset approval requires an asset identifier.")
        if self.status in {"pending", "approved", "executing"} and self.kind == "registration" and not self.summary.review_target:
            raise ValueError("Actionable registration approval requires its review target.")
        if self.status in {"consumed", "rejected", "expired", "interrupted"} and self.summary.review_target is not None:
            raise ValueError("Terminal approval must scrub its registration target.")
        return self


class ActiveChangeApprovalCollection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = ACTIVE_CHANGE_APPROVAL_STORE_VERSION
    organization_id: str = Field(pattern=r"^(?:local-admin|[a-f0-9]{32})$")
    revision: int = Field(default=0, ge=0)
    records: tuple[ActiveChangeApprovalRecord, ...] = Field(
        default=(), max_length=ACTIVE_CHANGE_APPROVAL_MAX_RECORDS
    )

    @model_validator(mode="after")
    def validate_scope(self):
        if len({item.id for item in self.records}) != len(self.records):
            raise ValueError("Approval identifiers are duplicated.")
        if any(item.organization_id != self.organization_id for item in self.records):
            raise ValueError("Approval crosses an organization boundary.")
        return self


class ActiveChangeApprovalView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-10.1"] = ACTIVE_CHANGE_APPROVAL_CONTRACT_VERSION
    id: str
    asset_id: str | None
    kind: ActiveChangeKind
    status: ActiveChangeStatus
    operation_digest_prefix: str = Field(min_length=12, max_length=12)
    requested_at: datetime
    expires_at: datetime
    decided_at: datetime | None
    consumed_at: datetime | None
    requested_by_current_user: bool
    can_approve: bool
    can_apply: bool
    summary: ActiveChangeSummary


class ActiveChangeApprovalPage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-10.1"] = ACTIVE_CHANGE_APPROVAL_CONTRACT_VERSION
    enabled: bool
    items: tuple[ActiveChangeApprovalView, ...] = Field(max_length=ACTIVE_CHANGE_APPROVAL_MAX_RECORDS)
    pending_count: int = Field(ge=0, le=ACTIVE_CHANGE_APPROVAL_MAX_RECORDS)
    privacy: Literal["no_notes_references_responsible_identities_or_complete_payload"] = (
        "no_notes_references_responsible_identities_or_complete_payload"
    )


class ActiveChangeApprovalStore:
    def __init__(self, settings: Settings, *, now_func=None, id_factory=None) -> None:
        self.settings = settings
        self.directory = settings.active_change_approvals_dir
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        self._now_func = now_func or (lambda: datetime.now(timezone.utc))
        self._id_factory = id_factory or (lambda: uuid4().hex)
        self.recover_interrupted()

    def request(
        self,
        *,
        organization_id: str,
        actor_id: str,
        actor_role: str,
        kind: ActiveChangeKind,
        asset_id: str | None,
        operation_digest_sha256: str,
        summary: ActiveChangeSummary,
    ) -> ActiveChangeApprovalRecord:
        self._validate_scope(organization_id, actor_id, actor_role)
        if not _DIGEST.fullmatch(operation_digest_sha256):
            raise ActiveChangeApprovalError("invalid_request")
        now = self._now()
        requester = _actor_digest(organization_id, actor_id)
        with storage_lock(self.settings):
            collection = self._normalize(self._load(organization_id), now)
            existing = next(
                (
                    item for item in collection.records
                    if item.operation_digest_sha256 == operation_digest_sha256
                    and item.requester_digest_sha256 == requester
                    and item.status in {"pending", "approved", "executing"}
                ),
                None,
            )
            if existing is not None:
                return existing
            if len(collection.records) >= ACTIVE_CHANGE_APPROVAL_MAX_RECORDS:
                raise ActiveChangeApprovalError("capacity_reached")
            record = ActiveChangeApprovalRecord(
                id=self._id_factory(), organization_id=organization_id, asset_id=asset_id,
                kind=kind, status="pending", operation_digest_sha256=operation_digest_sha256,
                requester_digest_sha256=requester, requester_role=actor_role,
                requested_at=now, expires_at=now + timedelta(hours=ACTIVE_CHANGE_APPROVAL_TTL_HOURS),
                summary=summary,
            )
            self._save(collection.model_copy(update={
                "revision": collection.revision + 1,
                "records": (*collection.records, record),
            }))
            return record

    def list(self, organization_id: str) -> tuple[ActiveChangeApprovalRecord, ...]:
        self._validate_organization(organization_id)
        now = self._now()
        with storage_lock(self.settings):
            current = self._load(organization_id)
            normalized = self._normalize(current, now)
            if normalized != current:
                self._save(normalized)
            return tuple(sorted(normalized.records, key=lambda item: (item.requested_at, item.id), reverse=True))

    def approve(self, organization_id: str, approval_id: str, actor_id: str, actor_role: str) -> ActiveChangeApprovalRecord:
        if actor_role != "administrator":
            raise ActiveChangeApprovalError("administrator_required")
        return self._decide(organization_id, approval_id, actor_id, approve=True)

    def reject(self, organization_id: str, approval_id: str, actor_id: str, actor_role: str) -> ActiveChangeApprovalRecord:
        if actor_role != "administrator":
            raise ActiveChangeApprovalError("administrator_required")
        return self._decide(organization_id, approval_id, actor_id, approve=False)

    def claim(
        self, organization_id: str, approval_id: str, actor_id: str,
        *, kind: ActiveChangeKind, asset_id: str | None, operation_digest_sha256: str,
    ) -> ActiveChangeApprovalRecord:
        self._validate_organization(organization_id)
        self._validate_approval_id(approval_id)
        now = self._now()
        actor = _actor_digest(organization_id, actor_id)
        with storage_lock(self.settings):
            collection = self._normalize(self._load(organization_id), now)
            record = self._find(collection, approval_id)
            if record.status != "approved":
                raise ActiveChangeApprovalError("approval_not_ready")
            if record.requester_digest_sha256 != actor:
                raise ActiveChangeApprovalError("requester_required")
            if (
                record.kind != kind or record.asset_id != asset_id
                or not _DIGEST.fullmatch(operation_digest_sha256)
                or record.operation_digest_sha256 != operation_digest_sha256
            ):
                raise ActiveChangeApprovalError("approval_mismatch")
            updated = record.model_copy(update={"status": "executing"})
            self._replace_and_save(collection, updated)
            return updated

    def claim_matching(
        self, organization_id: str, actor_id: str,
        *, kind: ActiveChangeKind, asset_id: str | None, operation_digest_sha256: str,
    ) -> ActiveChangeApprovalRecord:
        """Claim the one approved review matching the requester's closed change."""

        self._validate_organization(organization_id)
        now = self._now()
        actor = _actor_digest(organization_id, actor_id)
        with storage_lock(self.settings):
            collection = self._normalize(self._load(organization_id), now)
            matches = [
                item for item in collection.records
                if item.status == "approved"
                and item.requester_digest_sha256 == actor
                and item.kind == kind
                and item.asset_id == asset_id
                and item.operation_digest_sha256 == operation_digest_sha256
            ]
            if len(matches) != 1:
                raise ActiveChangeApprovalError("approval_not_ready")
            updated = matches[0].model_copy(update={"status": "executing"})
            self._replace_and_save(collection, updated)
            return updated

    def finish(self, organization_id: str, approval_id: str, *, succeeded: bool) -> ActiveChangeApprovalRecord:
        now = self._now()
        with storage_lock(self.settings):
            collection = self._load(organization_id)
            record = self._find(collection, approval_id)
            if record.status != "executing":
                raise ActiveChangeApprovalError("approval_not_executing")
            updated = record.model_copy(update={
                "status": "consumed" if succeeded else "approved",
                "consumed_at": now if succeeded else None,
                "summary": _scrub_summary(record.summary) if succeeded else record.summary,
            })
            self._replace_and_save(collection, updated)
            return updated

    def recover_interrupted(self) -> int:
        recovered = 0
        now = self._now()
        for path in self.directory.glob("*.json"):
            organization_id = path.stem
            if not _ORGANIZATION_ID.fullmatch(organization_id):
                continue
            with storage_lock(self.settings):
                collection = self._load(organization_id)
                changed = tuple(
                    item.model_copy(update={
                        "status": "interrupted",
                        "decided_at": now,
                        "summary": _scrub_summary(item.summary),
                    })
                    if item.status == "executing" else item
                    for item in collection.records
                )
                count = sum(item.status == "executing" for item in collection.records)
                recovered_collection = collection.model_copy(update={
                    "revision": collection.revision + (1 if count else 0),
                    "records": changed,
                })
                normalized = self._normalize(recovered_collection, now)
                if normalized != collection:
                    self._save(normalized)
                    recovered += count
        return recovered

    def count_for_asset_unlocked(self, organization_id: str, asset_id: str) -> int:
        """Count approvals while the caller owns the repository storage lock."""

        self._validate_organization(organization_id)
        self._validate_approval_id(asset_id)
        return sum(item.asset_id == asset_id for item in self._load(organization_id).records)

    def remove_asset(self, organization_id: str, asset_id: str) -> int:
        self._validate_organization(organization_id)
        self._validate_approval_id(asset_id)
        with storage_lock(self.settings):
            collection = self._load(organization_id)
            records = tuple(item for item in collection.records if item.asset_id != asset_id)
            removed = len(collection.records) - len(records)
            if removed:
                self._save(collection.model_copy(update={
                    "revision": collection.revision + 1, "records": records,
                }))
            return removed

    def purge_terminal(self, *, organization_id: str, cutoff: datetime) -> int:
        """Remove terminal review metadata for one tenant after its bounded window."""

        self._validate_organization(organization_id)
        if cutoff.tzinfo is None or cutoff.utcoffset() is None:
            raise ActiveChangeApprovalError("invalid_clock")
        with storage_lock(self.settings):
            current = self._load(organization_id)
            normalized = self._normalize_expired(current, self._now())
            records = tuple(
                item for item in normalized.records
                if not (
                    item.status in {"consumed", "rejected", "expired", "interrupted"}
                    and (item.consumed_at or item.decided_at or item.requested_at) < cutoff
                )
            )
            removed = len(normalized.records) - len(records)
            if removed or normalized != current:
                self._save(normalized.model_copy(update={
                    "revision": normalized.revision + (1 if removed else 0),
                    "records": records,
                }))
            return removed

    def view(self, record: ActiveChangeApprovalRecord, *, organization_id: str, actor_id: str, actor_role: str) -> ActiveChangeApprovalView:
        if record.organization_id != organization_id:
            raise ActiveChangeApprovalError("approval_not_found")
        actor = _actor_digest(organization_id, actor_id)
        own = record.requester_digest_sha256 == actor
        return ActiveChangeApprovalView(
            id=record.id, asset_id=record.asset_id, kind=record.kind, status=record.status,
            operation_digest_prefix=record.operation_digest_sha256[:12],
            requested_at=record.requested_at, expires_at=record.expires_at,
            decided_at=record.decided_at, consumed_at=record.consumed_at,
            requested_by_current_user=own,
            can_approve=record.status == "pending" and actor_role == "administrator" and not own,
            can_apply=record.status == "approved" and own,
            summary=record.summary,
        )

    def _decide(self, organization_id: str, approval_id: str, actor_id: str, *, approve: bool) -> ActiveChangeApprovalRecord:
        self._validate_organization(organization_id)
        self._validate_approval_id(approval_id)
        now = self._now()
        actor = _actor_digest(organization_id, actor_id)
        with storage_lock(self.settings):
            collection = self._normalize(self._load(organization_id), now)
            record = self._find(collection, approval_id)
            if record.status != "pending":
                raise ActiveChangeApprovalError("approval_state_changed")
            if record.requester_digest_sha256 == actor:
                raise ActiveChangeApprovalError("same_actor")
            updated = record.model_copy(update={
                "status": "approved" if approve else "rejected",
                "approver_digest_sha256": actor,
                "decided_at": now,
                "summary": record.summary if approve else _scrub_summary(record.summary),
            })
            self._replace_and_save(collection, updated)
            return updated

    def _normalize_expired(self, collection: ActiveChangeApprovalCollection, now: datetime) -> ActiveChangeApprovalCollection:
        records = tuple(
            item.model_copy(update={
                "status": "expired", "decided_at": now,
                "summary": _scrub_summary(item.summary),
            })
            if item.status in {"pending", "approved"} and item.expires_at <= now else item
            for item in collection.records
        )
        return collection if records == collection.records else collection.model_copy(
            update={"revision": collection.revision + 1, "records": records}
        )

    def _normalize(self, collection: ActiveChangeApprovalCollection, now: datetime) -> ActiveChangeApprovalCollection:
        normalized = self._normalize_expired(collection, now)
        cutoff = now - timedelta(days=ACTIVE_CHANGE_APPROVAL_TERMINAL_RETENTION_DAYS)
        records = tuple(
            item for item in normalized.records
            if not (
                item.status in {"consumed", "rejected", "expired", "interrupted"}
                and (item.consumed_at or item.decided_at or item.requested_at) < cutoff
            )
        )
        return normalized if records == normalized.records else normalized.model_copy(
            update={"revision": normalized.revision + 1, "records": records}
        )

    def _replace_and_save(self, collection: ActiveChangeApprovalCollection, updated: ActiveChangeApprovalRecord) -> None:
        records = tuple(updated if item.id == updated.id else item for item in collection.records)
        self._save(collection.model_copy(update={"revision": collection.revision + 1, "records": records}))

    @staticmethod
    def _find(collection: ActiveChangeApprovalCollection, approval_id: str) -> ActiveChangeApprovalRecord:
        record = next((item for item in collection.records if item.id == approval_id), None)
        if record is None:
            raise ActiveChangeApprovalError("approval_not_found")
        return record

    def _path(self, organization_id: str) -> Path:
        return self.directory / f"{organization_id}.json"

    def _load(self, organization_id: str) -> ActiveChangeApprovalCollection:
        path = self._path(organization_id)
        if not path.exists() and not path.is_symlink():
            return ActiveChangeApprovalCollection(organization_id=organization_id)
        try:
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > ACTIVE_CHANGE_APPROVAL_MAX_BYTES:
                raise ValueError("invalid file")
            collection = ActiveChangeApprovalCollection.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, ValidationError, json.JSONDecodeError) as exc:
            raise ActiveChangeApprovalError("invalid_store") from exc
        if collection.organization_id != organization_id:
            raise ActiveChangeApprovalError("invalid_store")
        return collection

    def _save(self, collection: ActiveChangeApprovalCollection) -> None:
        payload = collection.model_dump(mode="json")
        if len(json.dumps(payload, sort_keys=True).encode("utf-8")) > ACTIVE_CHANGE_APPROVAL_MAX_BYTES:
            raise ActiveChangeApprovalError("capacity_reached")
        try:
            _atomic_write_json(self._path(collection.organization_id), payload)
        except OSError as exc:
            raise ActiveChangeApprovalError("store_unavailable") from exc

    def _now(self) -> datetime:
        raw = self._now_func()
        if raw.tzinfo is None or raw.utcoffset() is None:
            raise ActiveChangeApprovalError("invalid_clock")
        return raw.astimezone(timezone.utc)

    @staticmethod
    def _validate_organization(organization_id: str) -> None:
        if not _ORGANIZATION_ID.fullmatch(organization_id):
            raise ActiveChangeApprovalError("invalid_scope")

    @classmethod
    def _validate_scope(cls, organization_id: str, actor_id: str, actor_role: str) -> None:
        cls._validate_organization(organization_id)
        if not re.fullmatch(r"(?:local-admin|team-admin|[a-f0-9]{32})", actor_id):
            raise ActiveChangeApprovalError("invalid_scope")
        if actor_role not in {"administrator", "maintainer"}:
            raise ActiveChangeApprovalError("maintainer_required")

    @staticmethod
    def _validate_approval_id(approval_id: str) -> None:
        if not _OPAQUE_ID.fullmatch(approval_id):
            raise ActiveChangeApprovalError("approval_not_found")


def active_change_operation_digest(
    *, organization_id: str, kind: ActiveChangeKind, asset_id: str | None, payload: BaseModel
) -> str:
    raw = payload.model_dump(mode="json")
    fields_by_kind = {
        "registration": (
            "asset_type", "value", "capabilities", "allowed_ports",
            "allowed_protocols", "authorization_method", "expires_at",
        ),
        "renewal": (
            "expected_revision_id", "capabilities", "allowed_ports",
            "allowed_protocols", "authorization_method", "expires_at",
            "scope_expansion_confirmed",
        ),
        "revocation": ("reason_code",),
    }
    review_contract = {key: raw[key] for key in fields_by_kind[kind] if key in raw}
    serialized = json.dumps(review_contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
    prefix = f"{ACTIVE_CHANGE_APPROVAL_CONTRACT_VERSION}\0{organization_id}\0{kind}\0{asset_id or 'new'}\0".encode("ascii")
    return hashlib.sha256(prefix + serialized).hexdigest()


def _actor_digest(organization_id: str, actor_id: str) -> str:
    return hashlib.sha256(f"inspectra-active-approver-v1\0{organization_id}\0{actor_id}".encode("ascii")).hexdigest()


def _scrub_summary(summary: ActiveChangeSummary) -> ActiveChangeSummary:
    return summary.model_copy(update={"review_target": None})
