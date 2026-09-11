"""Durable, source-free action inbox for passive project risk.

The portfolio is authoritative. This module persists only closed action
identifiers and per-user read markers, then reconciles them on every read.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import stat
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.models import ProjectPortfolioSearchRequest
from app.config import Settings
from app.storage import _atomic_write_json, storage_lock


PROJECT_ACTION_INBOX_CONTRACT_VERSION = "2026-09-10.1"
PROJECT_ACTION_INBOX_STORE_VERSION = 1
PROJECT_ACTION_INBOX_MAX_EVENTS = 2_000
PROJECT_ACTION_INBOX_MAX_READERS = 100
PROJECT_ACTION_INBOX_MAX_BYTES = 2 * 1024 * 1024
_ORGANIZATION_ID = re.compile(r"^(?:local-admin|[a-f0-9]{32})$")
_ACTOR_ID = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
_OPAQUE_ID = re.compile(r"^[a-f0-9]{32}$")
_REASON_ORDER = (
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
)
_REASON_RANK = {reason: index for index, reason in enumerate(_REASON_ORDER)}

ActionReason = Literal[
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
ActionPriority = Literal["urgent", "high", "review", "monitor"]
ActionDestination = Literal["analysis", "findings", "comparison", "public_intelligence"]


class ProjectActionInboxError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ProjectActionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    organization_id: str = Field(pattern=r"^(?:local-admin|[a-f0-9]{32})$")
    project_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    analysis_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    reason: ActionReason
    priority: ActionPriority
    destination: ActionDestination
    occurred_at: datetime
    read_by: tuple[str, ...] = Field(default=(), max_length=PROJECT_ACTION_INBOX_MAX_READERS)

    @model_validator(mode="after")
    def validate_closed_record(self):
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("Action timestamp must include a timezone.")
        if len(set(self.read_by)) != len(self.read_by) or any(
            re.fullmatch(r"[a-f0-9]{64}", value) is None for value in self.read_by
        ):
            raise ValueError("Action reader markers are invalid.")
        return self


class ProjectActionCollection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = PROJECT_ACTION_INBOX_STORE_VERSION
    organization_id: str = Field(pattern=r"^(?:local-admin|[a-f0-9]{32})$")
    revision: int = Field(default=0, ge=0)
    events: tuple[ProjectActionRecord, ...] = Field(default=(), max_length=PROJECT_ACTION_INBOX_MAX_EVENTS)

    @model_validator(mode="after")
    def validate_scope(self):
        if len({event.id for event in self.events}) != len(self.events):
            raise ValueError("Action identifiers are duplicated.")
        if any(event.organization_id != self.organization_id for event in self.events):
            raise ValueError("Action crosses an organization boundary.")
        return self


class ProjectActionItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    project_id: str
    project_name: str = Field(min_length=1, max_length=120)
    analysis_id: str | None = None
    reason: ActionReason
    priority: ActionPriority
    destination: ActionDestination
    occurred_at: datetime
    read: bool


class ProjectActionPage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-10.1"] = PROJECT_ACTION_INBOX_CONTRACT_VERSION
    items: tuple[ProjectActionItem, ...] = Field(max_length=200)
    total: int = Field(ge=0, le=PROJECT_ACTION_INBOX_MAX_EVENTS)
    unread: int = Field(ge=0, le=PROJECT_ACTION_INBOX_MAX_EVENTS)
    source_complete: bool
    retained_limit: Literal[2000] = PROJECT_ACTION_INBOX_MAX_EVENTS
    state_revision: int = Field(ge=0)
    privacy: Literal["closed_reasons_opaque_ids_no_evidence_or_free_text"] = (
        "closed_reasons_opaque_ids_no_evidence_or_free_text"
    )


class ProjectActionReadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    read: Literal[True]


class ProjectActionRebuildRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rebuild_confirmed: Literal[True]


class ProjectActionInboxStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.directory = settings.project_action_inbox_dir
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    def reconcile(
        self,
        organization_id: str,
        events: list[ProjectActionRecord],
        *,
        rebuild: bool = False,
    ) -> ProjectActionCollection:
        self._validate_organization(organization_id)
        with storage_lock(self.settings):
            current = ProjectActionCollection(organization_id=organization_id) if rebuild else self._load(organization_id)
            existing = {event.id: event for event in current.events}
            reconciled = tuple(
                event.model_copy(update={"read_by": existing.get(event.id, event).read_by})
                for event in events[:PROJECT_ACTION_INBOX_MAX_EVENTS]
            )
            if reconciled == current.events and not rebuild:
                return current
            updated = ProjectActionCollection(
                organization_id=organization_id,
                revision=current.revision + 1,
                events=reconciled,
            )
            self._save(updated)
            return updated

    def mark_read(self, organization_id: str, action_id: str, actor_id: str) -> ProjectActionCollection:
        self._validate_organization(organization_id)
        if not _OPAQUE_ID.fullmatch(action_id) or not _ACTOR_ID.fullmatch(actor_id):
            raise ProjectActionInboxError("action_not_found")
        reader = _reader_digest(organization_id, actor_id)
        with storage_lock(self.settings):
            current = self._load(organization_id)
            selected = next((event for event in current.events if event.id == action_id), None)
            if selected is None:
                raise ProjectActionInboxError("action_not_found")
            if reader in selected.read_by:
                return current
            if len(selected.read_by) >= PROJECT_ACTION_INBOX_MAX_READERS:
                raise ProjectActionInboxError("reader_limit")
            events = tuple(
                event.model_copy(update={"read_by": (*event.read_by, reader)})
                if event.id == action_id
                else event
                for event in current.events
            )
            updated = current.model_copy(update={"revision": current.revision + 1, "events": events})
            self._save(updated)
            return updated

    def remove_project(self, organization_id: str, project_id: str) -> int:
        """Remove read state for a deleted project without touching another tenant."""

        self._validate_organization(organization_id)
        if not _OPAQUE_ID.fullmatch(project_id):
            raise ProjectActionInboxError("invalid_scope")
        with storage_lock(self.settings):
            current = self._load(organization_id)
            events = tuple(event for event in current.events if event.project_id != project_id)
            removed = len(current.events) - len(events)
            if not removed:
                return 0
            self._save(current.model_copy(update={"revision": current.revision + 1, "events": events}))
            return removed

    def _path(self, organization_id: str) -> Path:
        return self.directory / f"{organization_id}.json"

    def _load(self, organization_id: str) -> ProjectActionCollection:
        path = self._path(organization_id)
        if not path.exists() and not path.is_symlink():
            return ProjectActionCollection(organization_id=organization_id)
        try:
            metadata = path.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > PROJECT_ACTION_INBOX_MAX_BYTES
            ):
                raise ValueError("invalid file")
            raw = json.loads(path.read_text(encoding="utf-8"))
            collection = ProjectActionCollection.model_validate(raw)
        except (OSError, ValueError, ValidationError, json.JSONDecodeError) as exc:
            raise ProjectActionInboxError("invalid_store") from exc
        if collection.organization_id != organization_id:
            raise ProjectActionInboxError("invalid_store")
        return collection

    def _save(self, collection: ProjectActionCollection) -> None:
        try:
            payload = ProjectActionCollection.model_validate(
                collection.model_dump(mode="python")
            ).model_dump(mode="json")
            if len(json.dumps(payload, sort_keys=True).encode("utf-8")) > PROJECT_ACTION_INBOX_MAX_BYTES:
                raise ProjectActionInboxError("store_limit")
            _atomic_write_json(self._path(collection.organization_id), payload)
        except ProjectActionInboxError:
            raise
        except (OSError, ValueError, ValidationError) as exc:
            raise ProjectActionInboxError("store_unavailable") from exc

    @staticmethod
    def _validate_organization(organization_id: str) -> None:
        if not _ORGANIZATION_ID.fullmatch(organization_id):
            raise ProjectActionInboxError("invalid_scope")


class ProjectActionInboxService:
    def __init__(self, portfolio, store: ProjectActionInboxStore) -> None:
        self.portfolio = portfolio
        self.store = store

    def list(
        self,
        organization_id: str,
        actor_id: str,
        *,
        unread_only: bool = False,
        limit: int = 100,
        rebuild: bool = False,
    ) -> ProjectActionPage:
        if not 1 <= limit <= 200 or not _ACTOR_ID.fullmatch(actor_id):
            raise ProjectActionInboxError("invalid_request")
        events, names, source_complete = self._project_events(organization_id)
        collection = self.store.reconcile(organization_id, events, rebuild=rebuild)
        reader = _reader_digest(organization_id, actor_id)
        ordered = sorted(
            collection.events,
            key=lambda event: (
                reader in event.read_by,
                {"urgent": 0, "high": 1, "review": 2, "monitor": 3}[event.priority],
                _REASON_RANK[event.reason],
                -event.occurred_at.timestamp(),
                event.id,
            ),
        )
        unread = sum(reader not in event.read_by for event in ordered)
        visible = [event for event in ordered if not unread_only or reader not in event.read_by]
        return ProjectActionPage(
            items=tuple(
                ProjectActionItem(
                    id=event.id,
                    project_id=event.project_id,
                    project_name=names.get(event.project_id, "Unavailable project"),
                    analysis_id=event.analysis_id,
                    reason=event.reason,
                    priority=event.priority,
                    destination=event.destination,
                    occurred_at=event.occurred_at,
                    read=reader in event.read_by,
                )
                for event in visible[:limit]
            ),
            total=len(ordered),
            unread=unread,
            source_complete=source_complete,
            state_revision=collection.revision,
        )

    def mark_read(self, organization_id: str, actor_id: str, action_id: str) -> ProjectActionPage:
        # Reconcile immediately before the mutation so a resolved/stale action
        # cannot be acknowledged through an old browser tab.
        self.list(organization_id, actor_id, limit=1)
        self.store.mark_read(organization_id, action_id, actor_id)
        return self.list(organization_id, actor_id)

    def _project_events(
        self, organization_id: str
    ) -> tuple[list[ProjectActionRecord], dict[str, str], bool]:
        cursor: str | None = None
        events: list[ProjectActionRecord] = []
        names: dict[str, str] = {}
        source_complete = True
        while True:
            page = self.portfolio.search(
                organization_id=organization_id,
                payload=ProjectPortfolioSearchRequest(page_size=100, cursor=cursor, sort="priority"),
            )
            for item in page.items:
                names[item.project.id] = item.project.name
                analysis_id = (
                    item.latest_completed_analysis.id
                    if item.latest_completed_analysis is not None
                    else item.latest_job.id
                    if item.latest_job is not None
                    else None
                )
                occurred_at = (
                    item.latest_job.updated_at if item.latest_job is not None else item.project.updated_at
                )
                for reason in item.priority_reasons:
                    if len(events) >= PROJECT_ACTION_INBOX_MAX_EVENTS:
                        source_complete = False
                        break
                    events.append(
                        ProjectActionRecord(
                            id=_event_id(organization_id, item.project.id, analysis_id, reason),
                            organization_id=organization_id,
                            project_id=item.project.id,
                            analysis_id=analysis_id,
                            reason=reason,
                            priority=item.priority,
                            destination=_destination(reason),
                            occurred_at=occurred_at,
                        )
                    )
                if not source_complete:
                    break
            if not source_complete or not page.next_cursor:
                break
            cursor = page.next_cursor
        return events, names, source_complete


def _event_id(organization_id: str, project_id: str, analysis_id: str | None, reason: str) -> str:
    value = "\0".join((PROJECT_ACTION_INBOX_CONTRACT_VERSION, organization_id, project_id, analysis_id or "none", reason))
    return hashlib.sha256(value.encode("ascii")).hexdigest()[:32]


def _reader_digest(organization_id: str, actor_id: str) -> str:
    return hashlib.sha256(f"{organization_id}\0{actor_id}".encode("utf-8")).hexdigest()


def _destination(reason: str) -> ActionDestination:
    if reason in {"public_intelligence_stale", "public_intelligence_failed", "known_exploited"}:
        return "public_intelligence"
    if reason in {"coverage_lost", "no_baseline"}:
        return "comparison"
    if reason in {"latest_analysis_failed", "analysis_incomplete", "no_recent_analysis", "no_completed_analysis"}:
        return "analysis"
    return "findings"
