from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import threading
from typing import Callable, Iterator, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.config import Settings
from app.models import ProductAuditEvent, ProductAuditEventsResponse

try:
    import fcntl
except ImportError:  # pragma: no cover - production images use Linux.
    fcntl = None


PRODUCT_AUDIT_CONTRACT_VERSION = "2026-09-06.1"
PRODUCT_AUDIT_MAX_PAGE_SIZE = 100
PRODUCT_AUDIT_INTEGRITY_CONTRACT_VERSION = "2026-09-10.1"
_CHAIN_ZERO = "0" * 64
_CHAIN_ENTRY_NAME = re.compile(r"^[0-9]{20}\.json$")
_ORGANIZATION_ID = re.compile(r"^(?:local-admin|[a-f0-9]{32})$")
_EVENT_ID = re.compile(r"^[a-f0-9]{32}$")
_ACTION = re.compile(r"^[a-z][a-z0-9_.-]{2,95}$")
_SAFE_METADATA_KEYS = frozenset(
    {
        "analysis_id",
        "analysis_profile",
        "affected_asset_count",
        "affected_project_count",
        "authorization_revision_id",
        "authorization_revision_sequence",
        "baseline_version",
        "decision_status",
        "changed",
        "deletion_contract",
        "deletion_state",
        "execution_contract_version",
        "event_count",
        "finding_count",
        "filter_applied",
        "job_id",
        "package_ecosystem",
        "policy_revision",
        "project_id",
        "provider",
        "responsible_count",
        "replayed",
        "report_format",
        "report_profile",
        "review_period",
        "retry",
        "source_state",
        "scope_expanded",
        "target_role",
        "unassigned_asset_count",
        "unassigned_project_count",
        "verification_method",
        "verification_status",
    }
)
_SAFE_METADATA_STRING = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,159}$")
_THREAD_LOCKS: dict[Path, threading.RLock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()


class ProductAuditError(RuntimeError):
    """Controlled product-audit failure without storage or input details."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ProductAuditIntegrityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[PRODUCT_AUDIT_INTEGRITY_CONTRACT_VERSION] = PRODUCT_AUDIT_INTEGRITY_CONTRACT_VERSION
    state: Literal["valid", "empty", "invalid"]
    checked_at: datetime
    bootstrap_performed: bool
    generation: int | None = Field(default=None, ge=1)
    retained_events: int | None = Field(default=None, ge=0)
    anchor_sequence: int | None = Field(default=None, ge=0)
    head_sequence: int | None = Field(default=None, ge=0)
    head_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    failure_reason: Literal["integrity_check_failed"] | None = None


class ProductAuditStore:
    """Append and query minimal product actions within one organization boundary."""

    def __init__(self, settings: Settings, *, now_func: Callable[[], datetime] | None = None) -> None:
        self.settings = settings
        self.root = settings.product_audit_dir
        self.retention_days = settings.product_audit_retention_days
        self.max_events = settings.product_audit_max_events
        self._now_func = now_func or (lambda: datetime.now(timezone.utc))

    def record(
        self,
        *,
        organization_id: str,
        actor_id: str,
        actor_role: str,
        action: str,
        resource_type: str,
        resource_id: str,
        result: str = "succeeded",
        correlation_id: str,
        metadata: dict[str, object] | None = None,
    ) -> ProductAuditEvent:
        now = self._aware_now()
        event = ProductAuditEvent(
            contract_version=PRODUCT_AUDIT_CONTRACT_VERSION,
            id=uuid4().hex,
            organization_id=organization_id,
            actor_id=actor_id,
            actor_role=actor_role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            result=result,
            correlation_id=correlation_id,
            occurred_at=now,
            metadata=_sanitize_metadata(metadata or {}),
        )
        path = self._event_path(event.organization_id, event.id)
        with self._lock():
            self._purge_expired_unlocked(now, organization_id=event.organization_id)
            if self._event_count_unlocked(now) >= self.max_events:
                raise ProductAuditError("audit_capacity_reached")
            state = self._ensure_integrity_unlocked(event.organization_id)[0]
            self._append_integrity_event_unlocked(event, state=state, path=path)
        return event

    def list(
        self,
        organization_id: str,
        *,
        limit: int = 25,
        cursor: str | None = None,
        action: str | None = None,
    ) -> ProductAuditEventsResponse:
        self._validate_organization_id(organization_id)
        if not 1 <= limit <= PRODUCT_AUDIT_MAX_PAGE_SIZE:
            raise ProductAuditError("invalid_page_size")
        if cursor is not None and not _EVENT_ID.fullmatch(cursor):
            raise ProductAuditError("invalid_cursor")
        if action is not None and not _ACTION.fullmatch(action):
            raise ProductAuditError("invalid_action")

        with self._lock():
            self._purge_expired_unlocked(self._aware_now(), organization_id=organization_id)
            self._verify_integrity_unlocked(organization_id)
            events = self._load_organization_unlocked(organization_id)
        if action is not None:
            events = [event for event in events if event.action == action]
        events.sort(key=lambda event: (event.occurred_at, event.id), reverse=True)
        start = 0
        if cursor is not None:
            try:
                start = next(index + 1 for index, event in enumerate(events) if event.id == cursor)
            except StopIteration as exc:
                raise ProductAuditError("invalid_cursor") from exc
        page = events[start : start + limit]
        next_cursor = page[-1].id if start + len(page) < len(events) and page else None
        return ProductAuditEventsResponse(items=page, next_cursor=next_cursor, retention_days=self.retention_days)

    def active_events_for_export(
        self,
        organization_id: str,
        *,
        starts_at: datetime,
        ends_at: datetime,
        asset_id: str | None = None,
        job_ids: set[str] | None = None,
        limit: int = 1_000,
    ) -> tuple[list[ProductAuditEvent], int]:
        """Return a bounded Active-only slice without weakening tenant scope."""

        self._validate_organization_id(organization_id)
        if (
            starts_at.tzinfo is None
            or starts_at.utcoffset() is None
            or ends_at.tzinfo is None
            or ends_at.utcoffset() is None
            or starts_at >= ends_at
            or ends_at - starts_at > timedelta(days=366)
            or not 1 <= limit <= 1_000
        ):
            raise ProductAuditError("invalid_export_range")
        linked_jobs = job_ids or set()
        if asset_id is not None and not _EVENT_ID.fullmatch(asset_id):
            raise ProductAuditError("invalid_resource")
        if any(not _EVENT_ID.fullmatch(job_id) for job_id in linked_jobs):
            raise ProductAuditError("invalid_resource")
        with self._lock():
            self._purge_expired_unlocked(self._aware_now(), organization_id=organization_id)
            self._verify_integrity_unlocked(organization_id)
            events = self._load_organization_unlocked(organization_id)
        matching = [
            event
            for event in events
            if event.action.startswith("active_asset.")
            and starts_at <= event.occurred_at <= ends_at
            and (
                asset_id is None
                or event.resource_id == asset_id
                or event.resource_id in linked_jobs
                or event.metadata.get("job_id") in linked_jobs
            )
        ]
        matching.sort(key=lambda event: (event.occurred_at, event.id))
        return matching[-limit:], len(matching)

    def events_for_export(
        self,
        organization_id: str,
        *,
        starts_at: datetime,
        ends_at: datetime,
        action: str | None = None,
        limit: int = 1_000,
    ) -> tuple[list[ProductAuditEvent], int]:
        """Return one bounded organization slice for a redacted export."""

        self._validate_organization_id(organization_id)
        if (
            starts_at.tzinfo is None
            or starts_at.utcoffset() is None
            or ends_at.tzinfo is None
            or ends_at.utcoffset() is None
            or starts_at >= ends_at
            or ends_at - starts_at > timedelta(days=366)
            or not 1 <= limit <= 1_000
        ):
            raise ProductAuditError("invalid_export_range")
        if action is not None and not _ACTION.fullmatch(action):
            raise ProductAuditError("invalid_action")
        with self._lock():
            self._purge_expired_unlocked(self._aware_now(), organization_id=organization_id)
            self._verify_integrity_unlocked(organization_id)
            events = self._load_organization_unlocked(organization_id)
        matching = [
            event
            for event in events
            if starts_at <= event.occurred_at <= ends_at
            and (action is None or event.action == action)
        ]
        matching.sort(key=lambda event: (event.occurred_at, event.id))
        return matching[-limit:], len(matching)

    def purge_expired(self, *, organization_id: str | None = None) -> int:
        if organization_id is not None:
            self._validate_organization_id(organization_id)
        with self._lock():
            return self._purge_expired_unlocked(self._aware_now(), organization_id=organization_id)

    def verify_integrity(self, organization_id: str) -> ProductAuditIntegrityResponse:
        self._validate_organization_id(organization_id)
        checked_at = self._aware_now()
        try:
            with self._lock():
                state, bootstrap_performed = self._ensure_integrity_unlocked(organization_id)
                self._verify_integrity_unlocked(organization_id, expected_state=state)
            retained_events = int(state["retained_event_count"])
            return ProductAuditIntegrityResponse(
                state="empty" if retained_events == 0 else "valid",
                checked_at=checked_at,
                bootstrap_performed=bootstrap_performed,
                generation=int(state["generation"]),
                retained_events=retained_events,
                anchor_sequence=int(state["anchor_sequence"]),
                head_sequence=int(state["head_sequence"]),
                head_digest=str(state["head_digest"]),
            )
        except ProductAuditError:
            return ProductAuditIntegrityResponse(
                state="invalid",
                checked_at=checked_at,
                bootstrap_performed=False,
                failure_reason="integrity_check_failed",
            )

    def anonymize_active_asset(
        self,
        *,
        organization_id: str,
        asset_id: str,
        job_ids: set[str],
        deletion_receipt_id: str,
    ) -> int:
        """Detach retained action history from a deleted Active target and its jobs.

        Action, actor, result and time remain useful for bounded governance. The
        target/job identifiers, correlations and all per-resource metadata do not.
        """

        self._validate_organization_id(organization_id)
        if not _EVENT_ID.fullmatch(asset_id) or not _EVENT_ID.fullmatch(deletion_receipt_id):
            raise ProductAuditError("invalid_resource")
        if any(not _EVENT_ID.fullmatch(job_id) for job_id in job_ids):
            raise ProductAuditError("invalid_resource")
        rewritten = 0
        with self._lock():
            state, _bootstrap = self._ensure_integrity_unlocked(organization_id)
            self._verify_integrity_unlocked(organization_id, expected_state=state)
            events = self._load_organization_unlocked(organization_id)
            for event in events:
                linked = event.resource_id == asset_id or event.resource_id in job_ids
                if not linked:
                    linked = event.metadata.get("job_id") in job_ids
                if not linked:
                    continue
                anonymized = event.model_copy(
                    update={
                        "resource_type": "deleted_active_asset",
                        "resource_id": deletion_receipt_id,
                        "correlation_id": f"active-deletion:{deletion_receipt_id}",
                        "metadata": {},
                    }
                )
                _atomic_write_json(
                    self._event_path(organization_id, event.id),
                    anonymized.model_dump(mode="json"),
                )
                rewritten += 1
            if rewritten:
                self._rotate_integrity_unlocked(organization_id, previous_state=state)
        return rewritten

    def _load_organization_unlocked(self, organization_id: str) -> list[ProductAuditEvent]:
        directory = self._organization_dir(organization_id)
        if not directory.exists():
            return []
        events: list[ProductAuditEvent] = []
        try:
            for path in directory.glob("*.json"):
                if not _EVENT_ID.fullmatch(path.stem):
                    continue
                if path.is_symlink() or not path.is_file():
                    raise ProductAuditError("audit_record_invalid")
                event = ProductAuditEvent.model_validate_json(path.read_text(encoding="utf-8"))
                if event.id != path.stem or event.organization_id != organization_id:
                    raise ProductAuditError("audit_record_invalid")
                events.append(event)
        except (OSError, ValueError, ValidationError) as exc:
            if isinstance(exc, ProductAuditError):
                raise
            raise ProductAuditError("audit_store_unavailable") from exc
        return events

    def _purge_expired_unlocked(self, now: datetime, *, organization_id: str | None = None) -> int:
        cutoff = now - timedelta(days=self.retention_days)
        removed = 0
        try:
            organization_ids = [organization_id] if organization_id is not None else self._organization_ids_unlocked()
            for current_organization_id in organization_ids:
                state, _bootstrap = self._ensure_integrity_unlocked(current_organization_id)
                entries = self._verify_integrity_unlocked(
                    current_organization_id,
                    expected_state=state,
                )
                events_by_id = {
                    event.id: event for event in self._load_organization_unlocked(current_organization_id)
                }
                expired_prefix: list[dict[str, object]] = []
                for entry in entries:
                    event = events_by_id[str(entry["event_id"])]
                    if event.occurred_at >= cutoff:
                        break
                    expired_prefix.append(entry)
                if not expired_prefix:
                    continue
                last_removed = expired_prefix[-1]
                updated_state = dict(state)
                updated_state["anchor_sequence"] = int(last_removed["sequence"])
                updated_state["anchor_digest"] = str(last_removed["chain_digest"])
                updated_state["retained_event_count"] = int(state["retained_event_count"]) - len(expired_prefix)
                _atomic_write_json(self._integrity_state_path(current_organization_id), updated_state)
                for entry in expired_prefix:
                    self._event_path(current_organization_id, str(entry["event_id"])).unlink(missing_ok=True)
                    self._integrity_entry_path(current_organization_id, int(entry["sequence"])).unlink(missing_ok=True)
                    removed += 1
        except OSError as exc:
            raise ProductAuditError("audit_store_unavailable") from exc
        return removed

    def _organization_ids_unlocked(self) -> list[str]:
        if not self.root.exists():
            return []
        organization_ids: list[str] = []
        root = self.root.resolve()
        for directory in self.root.iterdir():
            if (
                not directory.is_symlink()
                and directory.is_dir()
                and directory.resolve().parent == root
                and _ORGANIZATION_ID.fullmatch(directory.name)
            ):
                organization_ids.append(directory.name)
        return sorted(organization_ids)

    def _ensure_integrity_unlocked(self, organization_id: str) -> tuple[dict[str, object], bool]:
        integrity_dir = self._integrity_dir(organization_id)
        if integrity_dir.exists() or integrity_dir.is_symlink():
            return self._load_integrity_state_unlocked(organization_id), False
        organization_dir = self._organization_dir(organization_id)
        organization_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        events = sorted(
            self._load_organization_unlocked(organization_id),
            key=lambda event: (event.occurred_at, event.id),
        )
        temporary = organization_dir / f".integrity.{uuid4().hex}.tmp"
        try:
            state = self._build_integrity_tree(
                temporary,
                organization_id=organization_id,
                events=events,
                generation=1,
                generation_parent_digest=_CHAIN_ZERO,
                anchor_digest=_CHAIN_ZERO,
            )
            temporary.replace(integrity_dir)
            return state, bool(events)
        except (OSError, ValueError, ValidationError, ProductAuditError) as exc:
            if temporary.exists() and not temporary.is_symlink():
                shutil.rmtree(temporary, ignore_errors=True)
            if isinstance(exc, ProductAuditError):
                raise
            raise ProductAuditError("audit_integrity_invalid") from exc

    def _build_integrity_tree(
        self,
        directory: Path,
        *,
        organization_id: str,
        events: list[ProductAuditEvent],
        generation: int,
        generation_parent_digest: str,
        anchor_digest: str,
    ) -> dict[str, object]:
        entries_dir = directory / "entries"
        entries_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        previous_digest = anchor_digest
        for sequence, event in enumerate(events, start=1):
            entry = _build_chain_entry(
                organization_id=organization_id,
                generation=generation,
                sequence=sequence,
                event=event,
                previous_chain_digest=previous_digest,
            )
            _atomic_write_json(entries_dir / f"{sequence:020d}.json", entry)
            previous_digest = str(entry["chain_digest"])
        state: dict[str, object] = {
            "contract_version": PRODUCT_AUDIT_INTEGRITY_CONTRACT_VERSION,
            "organization_id": organization_id,
            "generation": generation,
            "generation_parent_digest": generation_parent_digest,
            "anchor_sequence": 0,
            "anchor_digest": anchor_digest,
            "head_sequence": len(events),
            "head_digest": previous_digest,
            "retained_event_count": len(events),
        }
        _atomic_write_json(directory / "state.json", state)
        return state

    def _append_integrity_event_unlocked(
        self,
        event: ProductAuditEvent,
        *,
        state: dict[str, object],
        path: Path,
    ) -> None:
        self._verify_integrity_unlocked(event.organization_id, expected_state=state)
        sequence = int(state["head_sequence"]) + 1
        entry = _build_chain_entry(
            organization_id=event.organization_id,
            generation=int(state["generation"]),
            sequence=sequence,
            event=event,
            previous_chain_digest=str(state["head_digest"]),
        )
        entry_path = self._integrity_entry_path(event.organization_id, sequence)
        updated_state = dict(state)
        updated_state["head_sequence"] = sequence
        updated_state["head_digest"] = entry["chain_digest"]
        updated_state["retained_event_count"] = int(state["retained_event_count"]) + 1
        try:
            _atomic_write_json(path, event.model_dump(mode="json"))
            _atomic_write_json(entry_path, entry)
            _atomic_write_json(self._integrity_state_path(event.organization_id), updated_state)
        except ProductAuditError:
            entry_path.unlink(missing_ok=True)
            path.unlink(missing_ok=True)
            raise

    def _load_integrity_state_unlocked(self, organization_id: str) -> dict[str, object]:
        integrity_dir = self._integrity_dir(organization_id)
        state_path = self._integrity_state_path(organization_id)
        entries_dir = integrity_dir / "entries"
        if (
            integrity_dir.is_symlink()
            or not integrity_dir.is_dir()
            or state_path.is_symlink()
            or not state_path.is_file()
            or entries_dir.is_symlink()
            or not entries_dir.is_dir()
        ):
            raise ProductAuditError("audit_integrity_invalid")
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise ProductAuditError("audit_integrity_invalid") from exc
        if not _valid_chain_state(state, organization_id=organization_id):
            raise ProductAuditError("audit_integrity_invalid")
        return state

    def _verify_integrity_unlocked(
        self,
        organization_id: str,
        *,
        expected_state: dict[str, object] | None = None,
    ) -> list[dict[str, object]]:
        state, entries = validate_product_audit_integrity_directory(
            self._organization_dir(organization_id),
            organization_id=organization_id,
        )
        if expected_state is not None and state != expected_state:
            raise ProductAuditError("audit_integrity_invalid")
        return entries

    def _rotate_integrity_unlocked(
        self,
        organization_id: str,
        *,
        previous_state: dict[str, object],
    ) -> None:
        organization_dir = self._organization_dir(organization_id)
        current = self._integrity_dir(organization_id)
        token = uuid4().hex
        temporary = organization_dir / f".integrity.{token}.tmp"
        backup = organization_dir / f".integrity.{token}.bak"
        seed = _rotation_seed(str(previous_state["head_digest"]))
        events = sorted(
            self._load_organization_unlocked(organization_id),
            key=lambda event: (event.occurred_at, event.id),
        )
        try:
            self._build_integrity_tree(
                temporary,
                organization_id=organization_id,
                events=events,
                generation=int(previous_state["generation"]) + 1,
                generation_parent_digest=str(previous_state["head_digest"]),
                anchor_digest=seed,
            )
            current.replace(backup)
            temporary.replace(current)
            shutil.rmtree(backup)
        except (OSError, ProductAuditError) as exc:
            if not current.exists() and backup.exists():
                backup.replace(current)
            if temporary.exists() and not temporary.is_symlink():
                shutil.rmtree(temporary, ignore_errors=True)
            raise ProductAuditError("audit_integrity_invalid") from exc

    def _integrity_dir(self, organization_id: str) -> Path:
        return self._organization_dir(organization_id) / ".integrity"

    def _integrity_state_path(self, organization_id: str) -> Path:
        return self._integrity_dir(organization_id) / "state.json"

    def _integrity_entry_path(self, organization_id: str, sequence: int) -> Path:
        return self._integrity_dir(organization_id) / "entries" / f"{sequence:020d}.json"

    def _event_count_unlocked(self, now: datetime) -> int:
        cutoff = now - timedelta(days=self.retention_days)
        try:
            count = 0
            for path in self._safe_event_paths_unlocked():
                try:
                    event = ProductAuditEvent.model_validate_json(path.read_text(encoding="utf-8"))
                except (OSError, ValueError, ValidationError):
                    # Unknown records consume capacity rather than allowing a
                    # corrupt store to bypass the hard bound.
                    count += 1
                    continue
                if event.occurred_at >= cutoff:
                    count += 1
            return count
        except OSError as exc:
            raise ProductAuditError("audit_store_unavailable") from exc

    def _safe_event_paths_unlocked(self) -> Iterator[Path]:
        if not self.root.exists():
            return
        root = self.root.resolve()
        for directory in self.root.iterdir():
            if (
                directory.is_symlink()
                or not _ORGANIZATION_ID.fullmatch(directory.name)
                or not directory.is_dir()
                or directory.resolve().parent != root
            ):
                continue
            for path in directory.glob("*.json"):
                if _EVENT_ID.fullmatch(path.stem) and path.is_file() and not path.is_symlink():
                    yield path

    def _event_path(self, organization_id: str, event_id: str) -> Path:
        return self._organization_dir(organization_id) / f"{event_id}.json"

    def _organization_dir(self, organization_id: str) -> Path:
        self._validate_organization_id(organization_id)
        candidate = (self.root / organization_id).resolve()
        if candidate.parent != self.root.resolve():
            raise ProductAuditError("invalid_organization")
        return candidate

    @staticmethod
    def _validate_organization_id(organization_id: str) -> None:
        if not isinstance(organization_id, str) or not _ORGANIZATION_ID.fullmatch(organization_id):
            raise ProductAuditError("invalid_organization")

    def _aware_now(self) -> datetime:
        now = self._now_func()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ProductAuditError("invalid_clock")
        return now.astimezone(timezone.utc)

    @contextmanager
    def _lock(self) -> Iterator[None]:
        lock_path = self.settings.data_dir / ".locks" / "product-audit.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with _thread_lock(lock_path):
            if fcntl is None:
                yield
                return
            with lock_path.open("a+", encoding="utf-8") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _sanitize_metadata(metadata: dict[str, object]) -> dict[str, str | int | float | bool]:
    sanitized: dict[str, str | int | float | bool] = {}
    for key, value in metadata.items():
        if key not in _SAFE_METADATA_KEYS or value is None:
            continue
        if isinstance(value, bool):
            sanitized[key] = value
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            sanitized[key] = value
        elif isinstance(value, str) and _SAFE_METADATA_STRING.fullmatch(value):
            sanitized[key] = value
    return sanitized


def _event_digest(event: ProductAuditEvent) -> str:
    payload = json.dumps(
        event.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(b"inspectra-product-audit-event-v1\0" + payload).hexdigest()


def _rotation_seed(previous_head_digest: str) -> str:
    return hashlib.sha256(
        b"inspectra-product-audit-rotation-v1\0" + previous_head_digest.encode("ascii")
    ).hexdigest()


def _build_chain_entry(
    *,
    organization_id: str,
    generation: int,
    sequence: int,
    event: ProductAuditEvent,
    previous_chain_digest: str,
) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "contract_version": PRODUCT_AUDIT_INTEGRITY_CONTRACT_VERSION,
        "organization_id": organization_id,
        "generation": generation,
        "sequence": sequence,
        "event_id": event.id,
        "event_digest": _event_digest(event),
        "previous_chain_digest": previous_chain_digest,
    }
    digest_input = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        **unsigned,
        "chain_digest": hashlib.sha256(
            b"inspectra-product-audit-chain-v1\0" + digest_input
        ).hexdigest(),
    }


def _valid_chain_state(value: object, *, organization_id: str) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "contract_version",
        "organization_id",
        "generation",
        "generation_parent_digest",
        "anchor_sequence",
        "anchor_digest",
        "head_sequence",
        "head_digest",
        "retained_event_count",
    }:
        return False
    generation = value.get("generation")
    anchor_sequence = value.get("anchor_sequence")
    head_sequence = value.get("head_sequence")
    retained_event_count = value.get("retained_event_count")
    digests = (
        value.get("generation_parent_digest"),
        value.get("anchor_digest"),
        value.get("head_digest"),
    )
    base_valid = bool(
        value.get("contract_version") == PRODUCT_AUDIT_INTEGRITY_CONTRACT_VERSION
        and value.get("organization_id") == organization_id
        and isinstance(generation, int)
        and not isinstance(generation, bool)
        and generation >= 1
        and isinstance(anchor_sequence, int)
        and not isinstance(anchor_sequence, bool)
        and anchor_sequence >= 0
        and isinstance(head_sequence, int)
        and not isinstance(head_sequence, bool)
        and head_sequence >= anchor_sequence
        and isinstance(retained_event_count, int)
        and not isinstance(retained_event_count, bool)
        and retained_event_count == head_sequence - anchor_sequence
        and all(isinstance(item, str) and re.fullmatch(r"[a-f0-9]{64}", item) for item in digests)
        and (retained_event_count > 0 or value.get("head_digest") == value.get("anchor_digest"))
    )
    if not base_valid:
        return False
    if anchor_sequence != 0:
        return True
    parent_digest = str(value["generation_parent_digest"])
    anchor_digest = str(value["anchor_digest"])
    return (
        generation == 1
        and parent_digest == _CHAIN_ZERO
        and anchor_digest == _CHAIN_ZERO
    ) or (
        generation > 1
        and parent_digest != _CHAIN_ZERO
        and anchor_digest == _rotation_seed(parent_digest)
    )


def _valid_chain_entry(
    value: object,
    *,
    organization_id: str,
    generation: int,
    sequence: int,
    event: ProductAuditEvent,
    previous_digest: str,
) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "contract_version",
        "organization_id",
        "generation",
        "sequence",
        "event_id",
        "event_digest",
        "previous_chain_digest",
        "chain_digest",
    }:
        return False
    expected = _build_chain_entry(
        organization_id=organization_id,
        generation=generation,
        sequence=sequence,
        event=event,
        previous_chain_digest=previous_digest,
    )
    return value == expected


def validate_product_audit_integrity_directory(
    organization_dir: Path,
    *,
    organization_id: str,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    """Validate one existing integrity tree without mutating or bootstrapping it."""

    integrity_dir = organization_dir / ".integrity"
    state_path = integrity_dir / "state.json"
    entries_dir = integrity_dir / "entries"
    if (
        organization_dir.is_symlink()
        or not organization_dir.is_dir()
        or integrity_dir.is_symlink()
        or not integrity_dir.is_dir()
        or state_path.is_symlink()
        or not state_path.is_file()
        or entries_dir.is_symlink()
        or not entries_dir.is_dir()
    ):
        raise ProductAuditError("audit_integrity_invalid")
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ProductAuditError("audit_integrity_invalid") from exc
    if not _valid_chain_state(state, organization_id=organization_id):
        raise ProductAuditError("audit_integrity_invalid")
    anchor_sequence = int(state["anchor_sequence"])
    head_sequence = int(state["head_sequence"])
    try:
        paths = sorted(entries_dir.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        raise ProductAuditError("audit_integrity_invalid") from exc
    if any(path.is_symlink() or not path.is_file() or not _CHAIN_ENTRY_NAME.fullmatch(path.name) for path in paths):
        raise ProductAuditError("audit_integrity_invalid")
    expected_names = {
        f"{sequence:020d}.json" for sequence in range(anchor_sequence + 1, head_sequence + 1)
    }
    if {path.name for path in paths} != expected_names:
        raise ProductAuditError("audit_integrity_invalid")
    events: list[ProductAuditEvent] = []
    try:
        for path in organization_dir.glob("*.json"):
            if path.is_symlink() or not path.is_file() or not _EVENT_ID.fullmatch(path.stem):
                raise ProductAuditError("audit_integrity_invalid")
            event = ProductAuditEvent.model_validate_json(path.read_text(encoding="utf-8"))
            if event.id != path.stem or event.organization_id != organization_id:
                raise ProductAuditError("audit_integrity_invalid")
            events.append(event)
    except (OSError, ValueError, ValidationError) as exc:
        if isinstance(exc, ProductAuditError):
            raise
        raise ProductAuditError("audit_integrity_invalid") from exc
    events_by_id = {event.id: event for event in events}
    if len(events_by_id) != len(events):
        raise ProductAuditError("audit_integrity_invalid")
    previous_digest = str(state["anchor_digest"])
    entries: list[dict[str, object]] = []
    referenced_event_ids: set[str] = set()
    for sequence in range(anchor_sequence + 1, head_sequence + 1):
        path = entries_dir / f"{sequence:020d}.json"
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise ProductAuditError("audit_integrity_invalid") from exc
        event_id = entry.get("event_id") if isinstance(entry, dict) else None
        event = events_by_id.get(event_id) if isinstance(event_id, str) else None
        if (
            event is None
            or not _valid_chain_entry(
                entry,
                organization_id=organization_id,
                generation=int(state["generation"]),
                sequence=sequence,
                event=event,
                previous_digest=previous_digest,
            )
        ):
            raise ProductAuditError("audit_integrity_invalid")
        referenced_event_ids.add(event.id)
        previous_digest = str(entry["chain_digest"])
        entries.append(entry)
    if referenced_event_ids != set(events_by_id):
        raise ProductAuditError("audit_integrity_invalid")
    if (
        len(entries) != int(state["retained_event_count"])
        or previous_digest != str(state["head_digest"])
        or head_sequence - anchor_sequence != len(entries)
    ):
        raise ProductAuditError("audit_integrity_invalid")
    return state, entries


def _atomic_write_json(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_suffix(".json.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise ProductAuditError("audit_store_unavailable") from exc


@contextmanager
def _thread_lock(path: Path) -> Iterator[None]:
    resolved = path.resolve()
    with _THREAD_LOCKS_GUARD:
        lock = _THREAD_LOCKS.setdefault(resolved, threading.RLock())
    with lock:
        yield
