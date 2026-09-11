from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import stat
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from app.config import Settings
from app.storage import _atomic_write_json, storage_lock


REMEDIATION_SAVED_VIEW_CONTRACT_VERSION = "2026-09-09.1"
REMEDIATION_SAVED_VIEW_STORE_VERSION = 1
MAX_SAVED_VIEWS_PER_USER = 20
MAX_SAVED_VIEWS_PER_ORGANIZATION = 1_000
MAX_SAVED_VIEW_STORE_BYTES = 2 * 1024 * 1024
_ORGANIZATION_ID = re.compile(r"^(?:local-admin|[a-f0-9]{32})$")
_VIEW_ID = re.compile(r"^[a-f0-9]{32}$")
_USER_ID = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
_VIEW_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{2,59}$")


class RemediationSavedViewError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RemediationSavedViewFilters(BaseModel):
    """Only non-sensitive, closed filters; never a search term or cursor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    priority: Literal["urgent", "high", "review"] | None = None
    evidence_kind: Literal["public_vulnerability", "local_finding"] | None = None
    ecosystem: Literal["npm", "pypi", "go", "cargo", "composer", "maven", "nuget"] | None = None
    dependency_scope: Literal["direct", "transitive", "optional", "unknown"] | None = None
    workflow_state: Literal[
        "open", "in_review", "accepted", "false_positive", "resolved",
        "awaiting_reanalysis", "still_detected",
    ] | None = None
    sort: Literal["priority", "component", "projects"] = "priority"


class RemediationSavedViewCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=3, max_length=60)
    filters: RemediationSavedViewFilters
    visibility: Literal["private", "organization"] = "private"
    make_default: bool = False

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        normalized = " ".join(value.strip().split())
        if not _VIEW_NAME.fullmatch(normalized):
            raise ValueError("Saved view name contains unsupported characters.")
        return normalized


class RemediationSavedViewDefaultRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    view_id: str | None = Field(default=None, min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    confirmation: Literal[True]


class RemediationSavedViewRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-09.1"] = REMEDIATION_SAVED_VIEW_CONTRACT_VERSION
    id: str = Field(min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    organization_id: str = Field(pattern=r"^(?:local-admin|[a-f0-9]{32})$")
    owner_user_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    name: str = Field(min_length=3, max_length=60, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]{2,59}$")
    filters: RemediationSavedViewFilters
    visibility: Literal["private", "organization"]
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def validate_timestamps(self):
        if (
            self.created_at.tzinfo is None
            or self.created_at.utcoffset() is None
            or self.updated_at.tzinfo is None
            or self.updated_at.utcoffset() is None
            or self.updated_at < self.created_at
        ):
            raise ValueError("Saved view timestamps are invalid.")
        return self


class RemediationSavedViewPage(BaseModel):
    contract_version: Literal["2026-09-09.1"] = REMEDIATION_SAVED_VIEW_CONTRACT_VERSION
    items: list[RemediationSavedViewRecord] = Field(max_length=1_000)
    default_view_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    owned_count: int = Field(ge=0, le=20)
    organization_count: int = Field(ge=0, le=1_000)
    privacy: Literal["closed_filters_only_no_search_cursor_or_resource_ids"] = (
        "closed_filters_only_no_search_cursor_or_resource_ids"
    )


class RemediationSavedViewCollection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = REMEDIATION_SAVED_VIEW_STORE_VERSION
    organization_id: str = Field(pattern=r"^(?:local-admin|[a-f0-9]{32})$")
    revision: int = Field(default=0, ge=0)
    views: list[RemediationSavedViewRecord] = Field(default_factory=list, max_length=MAX_SAVED_VIEWS_PER_ORGANIZATION)
    defaults: dict[str, str] = Field(default_factory=dict, max_length=1_000)

    @model_validator(mode="after")
    def validate_collection(self):
        ids = {item.id for item in self.views}
        if len(ids) != len(self.views):
            raise ValueError("Saved view identifiers are duplicated.")
        for item in self.views:
            if item.organization_id != self.organization_id:
                raise ValueError("Saved view crosses an organization boundary.")
        for user_id, view_id in self.defaults.items():
            if not _USER_ID.fullmatch(user_id) or view_id not in ids:
                raise ValueError("Saved view default is invalid.")
        counts: dict[str, int] = {}
        for item in self.views:
            counts[item.owner_user_id] = counts.get(item.owner_user_id, 0) + 1
        if any(value > MAX_SAVED_VIEWS_PER_USER for value in counts.values()):
            raise ValueError("Saved view per-user limit is exceeded.")
        return self


class RemediationSavedViewStore:
    def __init__(self, settings: Settings, *, now_func=None, id_factory=None) -> None:
        self.settings = settings
        self.directory = settings.remediation_saved_views_dir
        self._now_func = now_func or (lambda: datetime.now(timezone.utc))
        self._id_factory = id_factory or (lambda: uuid4().hex)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    def list_visible(self, organization_id: str, user_id: str) -> RemediationSavedViewPage:
        self._validate_scope(organization_id, user_id)
        with storage_lock(self.settings):
            collection = self._load(organization_id)
            visible = [
                item for item in collection.views
                if item.owner_user_id == user_id or item.visibility == "organization"
            ]
            visible.sort(key=lambda item: (item.name.casefold(), item.id))
            visible_ids = {item.id for item in visible}
            default_id = collection.defaults.get(user_id)
            return RemediationSavedViewPage(
                items=visible,
                default_view_id=default_id if default_id in visible_ids else None,
                owned_count=sum(item.owner_user_id == user_id for item in collection.views),
                organization_count=sum(item.visibility == "organization" for item in collection.views),
            )

    def create(
        self,
        organization_id: str,
        user_id: str,
        payload: RemediationSavedViewCreateRequest,
        *,
        can_share: bool,
    ) -> RemediationSavedViewRecord:
        self._validate_scope(organization_id, user_id)
        if payload.visibility == "organization" and not can_share:
            raise RemediationSavedViewError("share_forbidden")
        with storage_lock(self.settings):
            collection = self._load(organization_id)
            owned = [item for item in collection.views if item.owner_user_id == user_id]
            if len(owned) >= MAX_SAVED_VIEWS_PER_USER or len(collection.views) >= MAX_SAVED_VIEWS_PER_ORGANIZATION:
                raise RemediationSavedViewError("view_limit")
            if any(item.name.casefold() == payload.name.casefold() for item in owned):
                raise RemediationSavedViewError("name_conflict")
            view_id = self._new_id({item.id for item in collection.views})
            now = self._now()
            record = RemediationSavedViewRecord(
                id=view_id,
                organization_id=organization_id,
                owner_user_id=user_id,
                name=payload.name,
                filters=payload.filters,
                visibility=payload.visibility,
                created_at=now,
                updated_at=now,
            )
            defaults = dict(collection.defaults)
            if payload.make_default:
                defaults[user_id] = view_id
            updated = collection.model_copy(update={
                "revision": collection.revision + 1,
                "views": [*collection.views, record],
                "defaults": defaults,
            })
            self._save(updated)
            return record

    def set_default(self, organization_id: str, user_id: str, view_id: str | None) -> RemediationSavedViewPage:
        self._validate_scope(organization_id, user_id)
        if view_id is not None and not _VIEW_ID.fullmatch(view_id):
            raise RemediationSavedViewError("invalid_view")
        with storage_lock(self.settings):
            collection = self._load(organization_id)
            if view_id is not None:
                selected = next((item for item in collection.views if item.id == view_id), None)
                if selected is None or (selected.owner_user_id != user_id and selected.visibility != "organization"):
                    raise RemediationSavedViewError("view_not_found")
            defaults = dict(collection.defaults)
            if view_id is None:
                defaults.pop(user_id, None)
            else:
                defaults[user_id] = view_id
            self._save(collection.model_copy(update={"revision": collection.revision + 1, "defaults": defaults}))
        return self.list_visible(organization_id, user_id)

    def delete(self, organization_id: str, user_id: str, view_id: str) -> RemediationSavedViewRecord:
        self._validate_scope(organization_id, user_id)
        if not _VIEW_ID.fullmatch(view_id):
            raise RemediationSavedViewError("invalid_view")
        with storage_lock(self.settings):
            collection = self._load(organization_id)
            selected = next((item for item in collection.views if item.id == view_id), None)
            if selected is None or selected.owner_user_id != user_id:
                raise RemediationSavedViewError("view_not_found")
            defaults = {
                owner: selected_id for owner, selected_id in collection.defaults.items()
                if selected_id != view_id
            }
            self._save(collection.model_copy(update={
                "revision": collection.revision + 1,
                "views": [item for item in collection.views if item.id != view_id],
                "defaults": defaults,
            }))
            return selected

    def delete_user(self, organization_id: str, user_id: str) -> int:
        self._validate_scope(organization_id, user_id)
        with storage_lock(self.settings):
            collection = self._load(organization_id)
            removed_ids = {item.id for item in collection.views if item.owner_user_id == user_id}
            if not removed_ids and user_id not in collection.defaults:
                return 0
            defaults = {
                owner: view_id for owner, view_id in collection.defaults.items()
                if owner != user_id and view_id not in removed_ids
            }
            self._save(collection.model_copy(update={
                "revision": collection.revision + 1,
                "views": [item for item in collection.views if item.id not in removed_ids],
                "defaults": defaults,
            }))
            return len(removed_ids)

    def _load(self, organization_id: str) -> RemediationSavedViewCollection:
        path = self._path(organization_id)
        if not path.exists() and not path.is_symlink():
            return RemediationSavedViewCollection(organization_id=organization_id)
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise RemediationSavedViewError("store_invalid") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > MAX_SAVED_VIEW_STORE_BYTES
        ):
            raise RemediationSavedViewError("store_invalid")
        try:
            collection = RemediationSavedViewCollection.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError, ValueError) as exc:
            raise RemediationSavedViewError("store_invalid") from exc
        if collection.organization_id != organization_id:
            raise RemediationSavedViewError("store_invalid")
        return collection

    def _save(self, collection: RemediationSavedViewCollection) -> None:
        try:
            validated = RemediationSavedViewCollection.model_validate(collection.model_dump(mode="python"))
            _atomic_write_json(self._path(collection.organization_id), validated.model_dump(mode="json"))
        except (OSError, ValidationError, ValueError) as exc:
            raise RemediationSavedViewError("store_unavailable") from exc

    def _path(self, organization_id: str) -> Path:
        if not _ORGANIZATION_ID.fullmatch(organization_id):
            raise RemediationSavedViewError("invalid_scope")
        return self.directory / f"{organization_id}.json"

    def _new_id(self, existing: set[str]) -> str:
        for _ in range(3):
            candidate = self._id_factory()
            if isinstance(candidate, str) and _VIEW_ID.fullmatch(candidate) and candidate not in existing:
                return candidate
        raise RemediationSavedViewError("identifier_unavailable")

    @staticmethod
    def _validate_scope(organization_id: str, user_id: str) -> None:
        if not _ORGANIZATION_ID.fullmatch(organization_id) or not _USER_ID.fullmatch(user_id):
            raise RemediationSavedViewError("invalid_scope")

    def _now(self) -> datetime:
        value = self._now_func()
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
