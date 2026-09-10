"""Owner-scoped, target-free recurrence policies for authorized Active assets."""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Callable, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.active_assets import ActiveCapability
from app.active_recurrence_index import ActiveRecurrenceIndex, ActiveRecurrenceIndexError
from app.config import Settings
from app.storage import _atomic_write_json, active_asset_deletion_is_pending, storage_lock


ACTIVE_RECURRENCE_CONTRACT_VERSION = "2026-09-08.2"
ACTIVE_RECURRENCE_LEGACY_CONTRACT_VERSION = "2026-09-08.1"
ACTIVE_RECURRENCE_IDEMPOTENCY_DOMAIN_VERSION = "2026-09-08.1"
ACTIVE_RECURRENCE_INTERVAL_DAYS = (7, 14, 30)
ACTIVE_RECURRENCE_MAX_PER_ORGANIZATION = 500
ACTIVE_RECURRENCE_MAX_DUE_PER_TICK = 16
ACTIVE_RECURRENCE_MAX_JITTER_SECONDS = 900
ACTIVE_RECURRENCE_MAX_FAILURES = 8
ACTIVE_RECURRENCE_MAX_BACKOFF_SECONDS = 21_600
ACTIVE_RECURRENCE_WEEKDAYS = (
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"
)
ActiveRecurrenceWeekday = Literal[
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"
]
ActiveRecurrenceOutcome = Literal[
    "never", "scheduled", "runner_unavailable", "capacity_saturated", "dispatch_conflict"
]
_ID = re.compile(r"^[a-f0-9]{32}$")
_ORGANIZATION_ID = re.compile(r"^(?:local-admin|[a-f0-9]{32})$")
_ACTOR_ID = re.compile(r"^(?:local-admin|team-admin|[a-f0-9]{32})$")


class ActiveRecurrenceError(RuntimeError):
    pass


class ActiveRecurrenceCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capability: ActiveCapability
    port: int | None = Field(default=None, ge=1, le=65535)
    interval_days: Literal[7, 14, 30] = 7
    timezone_name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_+.-]+(?:/[A-Za-z0-9_+.-]+)*$")
    window_weekdays: list[ActiveRecurrenceWeekday] = Field(min_length=1, max_length=7)
    window_start_hour: int = Field(ge=0, le=23)
    window_duration_hours: int = Field(ge=1, le=12)
    recurrence_confirmed: Literal[True]
    idempotency_key: str = Field(pattern=r"^[a-f0-9]{32}$")

    @model_validator(mode="after")
    def validate_window(self):
        if len(set(self.window_weekdays)) != len(self.window_weekdays):
            raise ValueError("Window weekdays must be unique.")
        if self.window_start_hour + self.window_duration_hours > 24:
            raise ValueError("Recurring windows cannot cross local midnight.")
        try:
            _load_timezone(self.timezone_name)
        except ActiveRecurrenceError as exc:
            raise ValueError("Timezone must be an installed IANA identifier.") from exc
        self.window_weekdays = sorted(
            self.window_weekdays, key=ACTIVE_RECURRENCE_WEEKDAYS.index
        )
        return self


class ActiveRecurrenceMutationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_updated_at: datetime

    @model_validator(mode="after")
    def timestamp_is_aware(self):
        self.expected_updated_at = _utc(self.expected_updated_at)
        return self


class ActiveRecurrenceDeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmation: Literal["DELETE ACTIVE SCHEDULE"]


class ActiveRecurrenceRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[ACTIVE_RECURRENCE_LEGACY_CONTRACT_VERSION, ACTIVE_RECURRENCE_CONTRACT_VERSION] = ACTIVE_RECURRENCE_CONTRACT_VERSION
    idempotency_domain_version: Literal[ACTIVE_RECURRENCE_IDEMPOTENCY_DOMAIN_VERSION] = ACTIVE_RECURRENCE_IDEMPOTENCY_DOMAIN_VERSION
    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    organization_id: str = Field(pattern=r"^(?:local-admin|[a-f0-9]{32})$")
    asset_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    capability: ActiveCapability
    port: int | None = Field(default=None, ge=1, le=65535)
    interval_days: Literal[7, 14, 30]
    timezone_name: str = "UTC"
    window_weekdays: list[ActiveRecurrenceWeekday] = Field(default_factory=lambda: list(ACTIVE_RECURRENCE_WEEKDAYS), min_length=1, max_length=7)
    window_start_hour: int = Field(default=0, ge=0, le=23)
    window_duration_hours: int = Field(default=24, ge=1, le=24)
    authorization_revision_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    authorization_revision_digest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    authorization_revision_sequence: int = Field(ge=1, le=64)
    authorization_expires_at: datetime | None = None
    verification_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    status: Literal["active", "paused", "suspended"]
    reason_code: Literal[
        "scheduled",
        "operator_paused",
        "authorization_unavailable",
        "authorization_revision_changed",
        "verification_unavailable",
        "capability_disabled",
    ]
    next_run_at: datetime
    last_scheduled_at: datetime | None = None
    last_job_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    failure_count: int = Field(default=0, ge=0, le=ACTIVE_RECURRENCE_MAX_FAILURES)
    next_retry_at: datetime | None = None
    last_attempt_at: datetime | None = None
    last_outcome: ActiveRecurrenceOutcome = "never"
    created_at: datetime
    updated_at: datetime
    actor_id: str = Field(pattern=r"^(?:local-admin|team-admin|[a-f0-9]{32})$")
    actor_role: Literal["administrator", "maintainer"]

    @model_validator(mode="after")
    def timestamps_are_aware(self):
        for value in (self.authorization_expires_at, self.next_run_at, self.last_scheduled_at, self.next_retry_at, self.last_attempt_at, self.created_at, self.updated_at):
            if value is not None and (value.tzinfo is None or value.utcoffset() is None):
                raise ValueError("Recurrence timestamps require timezone information.")
        if self.capability == "active_tls_basic" and self.port is None:
            raise ValueError("TLS recurrence requires one authorized port.")
        if self.capability != "active_tls_basic" and self.port is not None:
            raise ValueError("Only TLS recurrence may retain a port selector.")
        if len(set(self.window_weekdays)) != len(self.window_weekdays):
            raise ValueError("Window weekdays must be unique.")
        if self.window_start_hour + self.window_duration_hours > 24:
            raise ValueError("Recurring windows cannot cross local midnight.")
        try:
            _load_timezone(self.timezone_name)
        except ActiveRecurrenceError as exc:
            raise ValueError("Timezone must be an installed IANA identifier.") from exc
        return self


class ActiveRecurrenceView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[ACTIVE_RECURRENCE_CONTRACT_VERSION] = ACTIVE_RECURRENCE_CONTRACT_VERSION
    id: str
    asset_id: str
    capability: ActiveCapability
    port: int | None
    interval_days: Literal[7, 14, 30]
    timezone_name: str
    window_weekdays: list[ActiveRecurrenceWeekday]
    window_start_hour: int
    window_duration_hours: int
    authorization_revision_id: str
    authorization_revision_sequence: int
    authorization_expires_at: datetime | None
    verification_id: str
    status: Literal["active", "paused", "suspended"]
    reason_code: str
    next_run_at: datetime
    last_scheduled_at: datetime | None
    last_job_id: str | None
    failure_count: int
    next_retry_at: datetime | None
    last_attempt_at: datetime | None
    last_outcome: ActiveRecurrenceOutcome
    created_at: datetime
    updated_at: datetime


class ActiveRecurrenceListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[ACTIVE_RECURRENCE_CONTRACT_VERSION] = ACTIVE_RECURRENCE_CONTRACT_VERSION
    enabled: bool
    items: list[ActiveRecurrenceView] = Field(max_length=ACTIVE_RECURRENCE_MAX_PER_ORGANIZATION)


class ActiveRecurrenceStore:
    def __init__(self, settings: Settings, *, now_func: Callable[[], datetime] | None = None) -> None:
        self.settings = settings
        self.root = settings.data_dir / "results" / "active_recurrences"
        self._now_func = now_func or (lambda: datetime.now(timezone.utc))
        self.index = ActiveRecurrenceIndex(settings, self._load_index_record)

    def create(
        self,
        request: ActiveRecurrenceCreateRequest,
        *,
        organization_id: str,
        asset_id: str,
        actor_id: str,
        actor_role: Literal["administrator", "maintainer"],
        authorization_revision_id: str,
        authorization_revision_digest_sha256: str,
        authorization_revision_sequence: int,
        authorization_expires_at: datetime,
        verification_id: str,
    ) -> tuple[ActiveRecurrenceRecord, bool]:
        self._validate_scope(organization_id, asset_id, actor_id)
        schedule_id = hashlib.sha256(
            f"{ACTIVE_RECURRENCE_IDEMPOTENCY_DOMAIN_VERSION}\0{organization_id}\0{actor_id}\0{request.idempotency_key}".encode("ascii")
        ).hexdigest()[:32]
        now = self._now()
        next_run_at = _next_run(
            now, request.interval_days, schedule_id,
            request.timezone_name, request.window_weekdays,
            request.window_start_hour, request.window_duration_hours,
        )
        if next_run_at >= _utc(authorization_expires_at):
            raise ActiveRecurrenceError("authorization_window_unavailable")
        record = ActiveRecurrenceRecord(
            id=schedule_id,
            organization_id=organization_id,
            asset_id=asset_id,
            capability=request.capability,
            port=request.port,
            interval_days=request.interval_days,
            timezone_name=request.timezone_name,
            window_weekdays=request.window_weekdays,
            window_start_hour=request.window_start_hour,
            window_duration_hours=request.window_duration_hours,
            authorization_revision_id=authorization_revision_id,
            authorization_revision_digest_sha256=authorization_revision_digest_sha256,
            authorization_revision_sequence=authorization_revision_sequence,
            authorization_expires_at=authorization_expires_at,
            verification_id=verification_id,
            status="active",
            reason_code="scheduled",
            next_run_at=next_run_at,
            created_at=now,
            updated_at=now,
            actor_id=actor_id,
            actor_role=actor_role,
        )
        path = self._path(organization_id, schedule_id)
        with storage_lock(self.settings):
            if path.exists():
                existing = self._read(path, organization_id, schedule_id)
                if self._same_creation(existing, record):
                    return existing, True
                raise ActiveRecurrenceError("idempotency_conflict")
            records = self._load_organization_unlocked(organization_id)
            if len(records) >= ACTIVE_RECURRENCE_MAX_PER_ORGANIZATION:
                raise ActiveRecurrenceError("capacity_reached")
            if any(
                item.asset_id == asset_id and item.capability == request.capability and item.port == request.port
                for item in records
            ):
                raise ActiveRecurrenceError("schedule_conflict")
            if active_asset_deletion_is_pending(self.settings, asset_id):
                raise ActiveRecurrenceError("asset_unavailable")
            _atomic_write_json(path, record.model_dump(mode="json"))
            self.index.sync_after_write(record)
        return record, False

    def list_for_asset(self, asset_id: str, *, organization_id: str) -> list[ActiveRecurrenceRecord]:
        self._validate_scope(organization_id, asset_id)
        with storage_lock(self.settings):
            try:
                records = self.index.records_for_asset(
                    organization_id=organization_id, asset_id=asset_id
                )
            except ActiveRecurrenceIndexError as exc:
                raise ActiveRecurrenceError("store_invalid") from exc
        return sorted(records, key=lambda item: (item.created_at, item.id))

    def count_for_asset_unlocked(self, asset_id: str, *, organization_id: str) -> int:
        self._validate_scope(organization_id, asset_id)
        try:
            return self.index.count_for_asset(
                organization_id=organization_id, asset_id=asset_id
            )
        except ActiveRecurrenceIndexError as exc:
            raise ActiveRecurrenceError("store_invalid") from exc

    def list_for_assets(
        self, asset_ids: set[str], *, organization_id: str
    ) -> list[ActiveRecurrenceRecord]:
        self._validate_organization(organization_id)
        with storage_lock(self.settings):
            try:
                return self.index.records_for_assets(
                    organization_id=organization_id, asset_ids=asset_ids
                )
            except ActiveRecurrenceIndexError as exc:
                raise ActiveRecurrenceError("store_invalid") from exc

    def delete_for_asset(self, asset_id: str, *, organization_id: str) -> int:
        self._validate_scope(organization_id, asset_id)
        removed = 0
        with storage_lock(self.settings):
            try:
                records = self.index.records_for_asset(
                    organization_id=organization_id, asset_id=asset_id
                )
            except ActiveRecurrenceIndexError as exc:
                raise ActiveRecurrenceError("store_invalid") from exc
            for record in records:
                self._path(organization_id, record.id).unlink()
                removed += 1
            self.index.sync_after_asset_delete(
                organization_id=organization_id, asset_id=asset_id
            )
        return removed

    def list_due(self, *, now: datetime | None = None, limit: int = ACTIVE_RECURRENCE_MAX_DUE_PER_TICK) -> list[ActiveRecurrenceRecord]:
        observed = _utc(now) if now is not None else self._now()
        if not 1 <= limit <= ACTIVE_RECURRENCE_MAX_DUE_PER_TICK:
            raise ActiveRecurrenceError("invalid_limit")
        with storage_lock(self.settings):
            try:
                return self.index.due_records(
                    now=observed,
                    limit=limit,
                    is_eligible=recurrence_is_within_window,
                )
            except ActiveRecurrenceIndexError as exc:
                raise ActiveRecurrenceError("store_invalid") from exc

    def pause(self, schedule_id: str, *, organization_id: str, asset_id: str, expected_updated_at: datetime) -> ActiveRecurrenceRecord:
        return self._mutate(
            schedule_id,
            organization_id=organization_id,
            asset_id=asset_id,
            expected_updated_at=expected_updated_at,
            status="paused",
            reason_code="operator_paused",
        )

    def resume(
        self,
        schedule_id: str,
        *,
        organization_id: str,
        asset_id: str,
        expected_updated_at: datetime,
        authorization_revision_id: str,
        authorization_revision_digest_sha256: str,
        authorization_revision_sequence: int,
        authorization_expires_at: datetime,
        verification_id: str,
    ) -> ActiveRecurrenceRecord:
        now = self._now()
        current = self.get(schedule_id, organization_id=organization_id, asset_id=asset_id)
        next_run = _next_run(
            now, current.interval_days, current.id, current.timezone_name,
            current.window_weekdays, current.window_start_hour,
            current.window_duration_hours,
        )
        if next_run >= _utc(authorization_expires_at):
            raise ActiveRecurrenceError("authorization_window_unavailable")
        return self._mutate(
            schedule_id,
            organization_id=organization_id,
            asset_id=asset_id,
            expected_updated_at=expected_updated_at,
            status="active",
            reason_code="scheduled",
            update={
                "authorization_revision_id": authorization_revision_id,
                "authorization_revision_digest_sha256": authorization_revision_digest_sha256,
                "authorization_revision_sequence": authorization_revision_sequence,
                "authorization_expires_at": authorization_expires_at,
                "verification_id": verification_id,
                "next_run_at": next_run,
                "failure_count": 0,
                "next_retry_at": None,
                "last_outcome": "never",
            },
        )

    def suspend(self, record: ActiveRecurrenceRecord, reason_code: str) -> ActiveRecurrenceRecord:
        if reason_code not in {
            "authorization_unavailable", "authorization_revision_changed", "verification_unavailable", "capability_disabled"
        }:
            raise ActiveRecurrenceError("invalid_reason")
        return self._mutate(
            record.id,
            organization_id=record.organization_id,
            asset_id=record.asset_id,
            expected_updated_at=record.updated_at,
            status="suspended",
            reason_code=reason_code,
        )

    def suspend_for_asset(
        self, asset_id: str, *, organization_id: str, reason_code: str = "authorization_unavailable"
    ) -> int:
        """Immediately close future dispatch when an asset authorization is revoked."""

        self._validate_scope(organization_id, asset_id)
        if reason_code not in {"authorization_unavailable", "authorization_revision_changed", "verification_unavailable"}:
            raise ActiveRecurrenceError("invalid_reason")
        changed = 0
        with storage_lock(self.settings):
            try:
                records = self.index.records_for_asset(
                    organization_id=organization_id, asset_id=asset_id
                )
            except ActiveRecurrenceIndexError as exc:
                raise ActiveRecurrenceError("store_invalid") from exc
            for current in records:
                if current.asset_id != asset_id or current.status != "active":
                    continue
                updated = current.model_copy(
                    update={
                        "status": "suspended",
                        "reason_code": reason_code,
                        "updated_at": self._now(),
                    }
                )
                _atomic_write_json(
                    self._path(organization_id, current.id), updated.model_dump(mode="json")
                )
                self.index.sync_after_write(updated)
                changed += 1
        return changed

    def record_dispatch(self, record: ActiveRecurrenceRecord, *, job_id: str, now: datetime | None = None) -> ActiveRecurrenceRecord:
        observed = _utc(now) if now is not None else self._now()
        next_run = _next_run(
            observed, record.interval_days, record.id, record.timezone_name,
            record.window_weekdays, record.window_start_hour,
            record.window_duration_hours,
        )
        authorization_ended = (
            record.authorization_expires_at is not None
            and next_run >= record.authorization_expires_at
        )
        return self._mutate(
            record.id,
            organization_id=record.organization_id,
            asset_id=record.asset_id,
            expected_updated_at=record.updated_at,
            status="suspended" if authorization_ended else "active",
            reason_code="authorization_unavailable" if authorization_ended else "scheduled",
            update={
                "last_scheduled_at": record.next_run_at,
                "last_job_id": job_id,
                "failure_count": 0,
                "next_retry_at": None,
                "last_attempt_at": observed,
                "last_outcome": "scheduled",
                # Missed occurrences are deliberately collapsed into one; no catch-up storm.
                "next_run_at": next_run,
            },
        )

    def record_failure(
        self,
        record: ActiveRecurrenceRecord,
        reason_code: Literal["runner_unavailable", "capacity_saturated", "dispatch_conflict"],
        *,
        now: datetime | None = None,
    ) -> ActiveRecurrenceRecord:
        observed = _utc(now) if now is not None else self._now()
        failure_count = min(record.failure_count + 1, ACTIVE_RECURRENCE_MAX_FAILURES)
        delay = min(300 * (2 ** (failure_count - 1)), ACTIVE_RECURRENCE_MAX_BACKOFF_SECONDS)
        retry_candidate = observed + timedelta(
            seconds=delay + recurrence_retry_jitter_seconds(record.id, failure_count)
        )
        next_retry = _next_window_time(
            retry_candidate, record.id, record.timezone_name, record.window_weekdays,
            record.window_start_hour, record.window_duration_hours,
        )
        authorization_ended = (
            record.authorization_expires_at is not None
            and next_retry >= record.authorization_expires_at
        )
        return self._mutate(
            record.id,
            organization_id=record.organization_id,
            asset_id=record.asset_id,
            expected_updated_at=record.updated_at,
            status="suspended" if authorization_ended else "active",
            reason_code="authorization_unavailable" if authorization_ended else "scheduled",
            update={
                "failure_count": failure_count,
                "next_retry_at": None if authorization_ended else next_retry,
                "last_attempt_at": observed,
                "last_outcome": reason_code,
            },
        )

    def get(self, schedule_id: str, *, organization_id: str, asset_id: str) -> ActiveRecurrenceRecord:
        self._validate_scope(organization_id, asset_id)
        self._validate_id(schedule_id)
        with storage_lock(self.settings):
            record = self._read(self._path(organization_id, schedule_id), organization_id, schedule_id)
        if record.asset_id != asset_id:
            raise ActiveRecurrenceError("not_found")
        return record

    def delete(self, schedule_id: str, *, organization_id: str, asset_id: str) -> None:
        self._validate_scope(organization_id, asset_id)
        self._validate_id(schedule_id)
        path = self._path(organization_id, schedule_id)
        with storage_lock(self.settings):
            record = self._read(path, organization_id, schedule_id)
            if record.asset_id != asset_id:
                raise ActiveRecurrenceError("not_found")
            path.unlink()
            self.index.sync_after_delete(
                organization_id=organization_id, schedule_id=schedule_id
            )

    def index_ready(self) -> bool:
        return self.index.ready()

    @staticmethod
    def view(record: ActiveRecurrenceRecord) -> ActiveRecurrenceView:
        return ActiveRecurrenceView.model_validate(
            record.model_dump(exclude={"organization_id", "authorization_revision_digest_sha256", "idempotency_domain_version", "actor_id", "actor_role"})
            | {"contract_version": ACTIVE_RECURRENCE_CONTRACT_VERSION}
        )

    def _mutate(self, schedule_id: str, *, organization_id: str, asset_id: str, expected_updated_at: datetime, status: str, reason_code: str, update: dict | None = None) -> ActiveRecurrenceRecord:
        self._validate_scope(organization_id, asset_id)
        self._validate_id(schedule_id)
        path = self._path(organization_id, schedule_id)
        with storage_lock(self.settings):
            current = self._read(path, organization_id, schedule_id)
            if current.asset_id != asset_id:
                raise ActiveRecurrenceError("not_found")
            if current.updated_at != _utc(expected_updated_at):
                raise ActiveRecurrenceError("state_changed")
            values = {"status": status, "reason_code": reason_code, "updated_at": self._now()}
            values.update(update or {})
            changed = ActiveRecurrenceRecord.model_validate(current.model_dump() | values)
            _atomic_write_json(path, changed.model_dump(mode="json"))
            self.index.sync_after_write(changed)
        return changed

    def _load_index_record(self, path: Path) -> ActiveRecurrenceRecord:
        return self._read(path, path.parent.name, path.stem)

    def _load_organization_unlocked(self, organization_id: str) -> list[ActiveRecurrenceRecord]:
        directory = self.root / organization_id
        if not directory.exists():
            return []
        if directory.is_symlink() or not directory.is_dir():
            raise ActiveRecurrenceError("store_invalid")
        records: list[ActiveRecurrenceRecord] = []
        for path in directory.iterdir():
            if path.is_symlink() or not path.is_file() or path.suffix != ".json" or not _ID.fullmatch(path.stem):
                raise ActiveRecurrenceError("store_invalid")
            records.append(self._read(path, organization_id, path.stem))
        return records

    def _read(self, path: Path, organization_id: str, schedule_id: str) -> ActiveRecurrenceRecord:
        if path.is_symlink() or not path.is_file():
            raise ActiveRecurrenceError("not_found")
        try:
            record = ActiveRecurrenceRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise ActiveRecurrenceError("store_invalid") from exc
        if record.id != schedule_id or record.organization_id != organization_id:
            raise ActiveRecurrenceError("store_invalid")
        migration = {"contract_version": ACTIVE_RECURRENCE_CONTRACT_VERSION}
        # The legacy contract did not persist the authorization expiry. Never
        # infer that boundary or leave an old active policy executable: an
        # explicit resume binds it to the current immutable revision instead.
        if record.authorization_expires_at is None and record.status == "active":
            migration.update(
                status="suspended",
                reason_code="authorization_unavailable",
                next_retry_at=None,
            )
        return record.model_copy(update=migration)

    def _path(self, organization_id: str, schedule_id: str) -> Path:
        self._validate_organization(organization_id)
        self._validate_id(schedule_id)
        return self.root / organization_id / f"{schedule_id}.json"

    def _now(self) -> datetime:
        return _utc(self._now_func())

    @staticmethod
    def _same_creation(left: ActiveRecurrenceRecord, right: ActiveRecurrenceRecord) -> bool:
        keys = (
            "organization_id", "asset_id", "capability", "port", "interval_days",
            "timezone_name", "window_weekdays", "window_start_hour", "window_duration_hours",
            "authorization_revision_id", "authorization_revision_digest_sha256",
            "authorization_revision_sequence", "authorization_expires_at",
            "verification_id", "actor_id", "actor_role",
        )
        return all(getattr(left, key) == getattr(right, key) for key in keys)

    @classmethod
    def _validate_scope(cls, organization_id: str, asset_id: str, actor_id: str | None = None) -> None:
        cls._validate_organization(organization_id)
        cls._validate_id(asset_id)
        if actor_id is not None and not _ACTOR_ID.fullmatch(actor_id):
            raise ActiveRecurrenceError("invalid_identity")

    @staticmethod
    def _validate_organization(value: str) -> None:
        if not _ORGANIZATION_ID.fullmatch(value):
            raise ActiveRecurrenceError("invalid_identity")

    @staticmethod
    def _validate_id(value: str) -> None:
        if not _ID.fullmatch(value):
            raise ActiveRecurrenceError("not_found")


def recurrence_occurrence_key(record: ActiveRecurrenceRecord) -> str:
    """Stable, non-secret key for exactly one due occurrence."""

    due = record.next_run_at.astimezone(timezone.utc).isoformat(timespec="seconds")
    return hashlib.sha256(
        f"{record.idempotency_domain_version}\0{record.organization_id}\0{record.id}\0{due}".encode("ascii")
    ).hexdigest()


def recurrence_jitter_seconds(schedule_id: str) -> int:
    """Stable 1..900 second spread without retaining another scheduling input."""

    if not _ID.fullmatch(schedule_id):
        raise ActiveRecurrenceError("not_found")
    digest = hashlib.sha256(
        f"{ACTIVE_RECURRENCE_IDEMPOTENCY_DOMAIN_VERSION}\0jitter\0{schedule_id}".encode("ascii")
    ).digest()
    return 1 + int.from_bytes(digest[:4], "big") % ACTIVE_RECURRENCE_MAX_JITTER_SECONDS


def recurrence_retry_jitter_seconds(schedule_id: str, failure_count: int) -> int:
    if not _ID.fullmatch(schedule_id) or not 1 <= failure_count <= ACTIVE_RECURRENCE_MAX_FAILURES:
        raise ActiveRecurrenceError("invalid_retry")
    digest = hashlib.sha256(
        f"{ACTIVE_RECURRENCE_IDEMPOTENCY_DOMAIN_VERSION}\0retry\0{schedule_id}\0{failure_count}".encode("ascii")
    ).digest()
    return int.from_bytes(digest[:2], "big") % 61


def _next_run(
    observed: datetime,
    interval_days: int,
    schedule_id: str,
    timezone_name: str,
    window_weekdays: list[ActiveRecurrenceWeekday],
    window_start_hour: int,
    window_duration_hours: int,
) -> datetime:
    candidate = _utc(observed) + timedelta(
        days=interval_days, seconds=recurrence_jitter_seconds(schedule_id)
    )
    return _next_window_time(
        candidate, schedule_id, timezone_name, window_weekdays,
        window_start_hour, window_duration_hours,
    )


def recurrence_is_within_window(record: ActiveRecurrenceRecord, observed: datetime) -> bool:
    value = _utc(observed)
    zone = _load_timezone(record.timezone_name)
    local_day = value.astimezone(zone).date()
    bounds = _window_bounds(
        local_day, zone, record.window_weekdays,
        record.window_start_hour, record.window_duration_hours,
    )
    return bounds is not None and bounds[0] <= value < bounds[1]


def _next_window_time(
    candidate: datetime,
    schedule_id: str,
    timezone_name: str,
    window_weekdays: list[ActiveRecurrenceWeekday],
    window_start_hour: int,
    window_duration_hours: int,
) -> datetime:
    value = _utc(candidate)
    zone = _load_timezone(timezone_name)
    first_day = value.astimezone(zone).date()
    for offset in range(0, 371):
        bounds = _window_bounds(
            first_day + timedelta(days=offset), zone, window_weekdays,
            window_start_hour, window_duration_hours,
        )
        if bounds is None:
            continue
        start, end = bounds
        if start <= value < end:
            return value
        if value < start:
            jittered = start + timedelta(seconds=recurrence_jitter_seconds(schedule_id))
            if jittered < end:
                return jittered
    raise ActiveRecurrenceError("window_unavailable")


def _window_bounds(
    local_day: date,
    zone: ZoneInfo,
    window_weekdays: list[ActiveRecurrenceWeekday],
    start_hour: int,
    duration_hours: int,
) -> tuple[datetime, datetime] | None:
    if ACTIVE_RECURRENCE_WEEKDAYS[local_day.weekday()] not in window_weekdays:
        return None
    start_naive = datetime.combine(local_day, time(hour=start_hour))
    end_naive = start_naive + timedelta(hours=duration_hours)
    starts = _valid_local_instants(start_naive, zone)
    ends = _valid_local_instants(end_naive, zone)
    # A nonexistent DST boundary skips the whole window. Ambiguous boundaries
    # use the earliest start and latest end, never an invented local instant.
    if not starts or not ends:
        return None
    return min(starts), max(ends)


def _valid_local_instants(value: datetime, zone: ZoneInfo) -> list[datetime]:
    instants: set[datetime] = set()
    for fold in (0, 1):
        candidate = value.replace(tzinfo=zone, fold=fold).astimezone(timezone.utc)
        roundtrip = candidate.astimezone(zone)
        if roundtrip.replace(tzinfo=None) == value and roundtrip.fold == fold:
            instants.add(candidate)
    return sorted(instants)


def _load_timezone(value: str) -> ZoneInfo:
    try:
        return ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ActiveRecurrenceError("invalid_timezone") from exc


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ActiveRecurrenceError("timezone_required")
    return value.astimezone(timezone.utc)
