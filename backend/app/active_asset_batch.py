"""Bounded, ephemeral preflight for atomic Active asset batch registration."""

from __future__ import annotations

import csv
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
from io import StringIO
import json
import secrets
import threading
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.active_assets import ActiveAssetCreateRequest, ActiveAssetRecord


ACTIVE_ASSET_BATCH_CONTRACT_VERSION = "2026-09-08.1"
ACTIVE_ASSET_BATCH_MAX_BYTES = 128 * 1024
ACTIVE_ASSET_BATCH_MAX_ITEMS = 50
ACTIVE_ASSET_BATCH_PREFLIGHT_TTL_SECONDS = 300
ACTIVE_ASSET_BATCH_PREFLIGHT_MAX_ENTRIES = 64

_CSV_REQUIRED_FIELDS = (
    "asset_type",
    "value",
    "responsible_user_ids",
    "capabilities",
    "allowed_ports",
    "allowed_protocols",
    "authorization_method",
    "authorization_reference",
    "authorized_at",
    "expires_at",
)
_CSV_ALLOWED_FIELDS = frozenset((*_CSV_REQUIRED_FIELDS, "notes"))


class ActiveAssetBatchError(ValueError):
    pass


class ActiveAssetBatchRow(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    row: int = Field(ge=1, le=ACTIVE_ASSET_BATCH_MAX_ITEMS)
    status: Literal["ready", "invalid", "duplicate_in_batch", "already_registered"]
    reason_code: Literal[
        "ready",
        "invalid_contract",
        "duplicate_identity",
        "identity_already_registered",
    ]
    asset_type: Literal["domain", "host", "ip", "http_origin"] | None = None
    canonical_value: str | None = Field(default=None, max_length=253)


class ActiveAssetBatchPreflightResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[ACTIVE_ASSET_BATCH_CONTRACT_VERSION] = ACTIVE_ASSET_BATCH_CONTRACT_VERSION
    state: Literal["ready", "needs_correction"]
    format: Literal["json", "csv"]
    input_count: int = Field(ge=1, le=ACTIVE_ASSET_BATCH_MAX_ITEMS)
    ready_count: int = Field(ge=0, le=ACTIVE_ASSET_BATCH_MAX_ITEMS)
    invalid_count: int = Field(ge=0, le=ACTIVE_ASSET_BATCH_MAX_ITEMS)
    duplicate_count: int = Field(ge=0, le=ACTIVE_ASSET_BATCH_MAX_ITEMS)
    conflict_count: int = Field(ge=0, le=ACTIVE_ASSET_BATCH_MAX_ITEMS)
    can_confirm: bool
    review_digest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    preflight_token: str | None = Field(default=None, min_length=32, max_length=128)
    expires_at: datetime | None = None
    rows: list[ActiveAssetBatchRow] = Field(max_length=ACTIVE_ASSET_BATCH_MAX_ITEMS)


class ActiveAssetBatchCommitResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[ACTIVE_ASSET_BATCH_CONTRACT_VERSION] = ACTIVE_ASSET_BATCH_CONTRACT_VERSION
    batch_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    created_count: int = Field(ge=1, le=ACTIVE_ASSET_BATCH_MAX_ITEMS)
    replayed: bool
    assets: list[ActiveAssetRecord] = Field(min_length=1, max_length=ACTIVE_ASSET_BATCH_MAX_ITEMS)


@dataclass(frozen=True)
class ParsedActiveAssetBatchRow:
    row: int
    status: str
    reason_code: str
    request: ActiveAssetCreateRequest | None


@dataclass(frozen=True)
class ParsedActiveAssetBatch:
    format: Literal["json", "csv"]
    rows: tuple[ParsedActiveAssetBatchRow, ...]
    normalized_digest_sha256: str

    @property
    def requests(self) -> list[ActiveAssetCreateRequest]:
        return [row.request for row in self.rows if row.status == "ready" and row.request is not None]


@dataclass(frozen=True)
class ActiveAssetBatchPreflightAdmission:
    token: str
    expires_at: datetime


@dataclass(frozen=True)
class _RetainedAdmission:
    owner_id: str
    source_digest_sha256: str
    normalized_digest_sha256: str
    expires_at: datetime


class ActiveAssetBatchPreflightStore:
    """Retain only owner-bound digests; uploaded inventories stay in memory."""

    def __init__(
        self,
        *,
        ttl_seconds: int = ACTIVE_ASSET_BATCH_PREFLIGHT_TTL_SECONDS,
        max_entries: int = ACTIVE_ASSET_BATCH_PREFLIGHT_MAX_ENTRIES,
    ) -> None:
        if ttl_seconds <= 0 or max_entries <= 0:
            raise ValueError("Active batch preflight limits must be positive.")
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._records: dict[str, _RetainedAdmission] = {}
        self._lock = threading.Lock()

    def create(
        self,
        owner_id: str,
        source: bytes,
        normalized_digest_sha256: str,
        *,
        now: datetime | None = None,
    ) -> ActiveAssetBatchPreflightAdmission:
        observed_at = _utc(now)
        token = secrets.token_urlsafe(32)
        record = _RetainedAdmission(
            owner_id=owner_id,
            source_digest_sha256=hashlib.sha256(source).hexdigest(),
            normalized_digest_sha256=normalized_digest_sha256,
            expires_at=observed_at + timedelta(seconds=self.ttl_seconds),
        )
        with self._lock:
            self._purge_unlocked(observed_at)
            if len(self._records) >= self.max_entries:
                del self._records[min(self._records, key=lambda key: self._records[key].expires_at)]
            self._records[_token_hash(token)] = record
        return ActiveAssetBatchPreflightAdmission(token=token, expires_at=record.expires_at)

    def consume(
        self,
        owner_id: str,
        token: str,
        source: bytes,
        *,
        now: datetime | None = None,
    ) -> str:
        observed_at = _utc(now)
        if not isinstance(token, str) or not 32 <= len(token) <= 128:
            raise ActiveAssetBatchError("invalid_or_expired")
        token_hash = _token_hash(token)
        source_digest = hashlib.sha256(source).hexdigest()
        with self._lock:
            record = self._records.get(token_hash)
            if record is None or record.expires_at <= observed_at or record.owner_id != owner_id:
                self._records.pop(token_hash, None)
                raise ActiveAssetBatchError("invalid_or_expired")
            if not secrets.compare_digest(record.source_digest_sha256, source_digest):
                raise ActiveAssetBatchError("content_changed")
        return record.normalized_digest_sha256

    def _purge_unlocked(self, now: datetime) -> None:
        for key in [key for key, record in self._records.items() if record.expires_at <= now]:
            del self._records[key]


def parse_active_asset_batch(source: bytes, filename: str | None) -> ParsedActiveAssetBatch:
    if not source:
        raise ActiveAssetBatchError("empty")
    if len(source) > ACTIVE_ASSET_BATCH_MAX_BYTES:
        raise ActiveAssetBatchError("too_large")
    suffix = (filename or "").lower().rsplit(".", 1)[-1]
    if suffix not in {"json", "csv"}:
        raise ActiveAssetBatchError("unsupported_format")
    try:
        text = source.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ActiveAssetBatchError("invalid_encoding") from exc
    raw_rows = _parse_json_rows(text) if suffix == "json" else _parse_csv_rows(text)
    if not 1 <= len(raw_rows) <= ACTIVE_ASSET_BATCH_MAX_ITEMS:
        raise ActiveAssetBatchError("item_limit")

    parsed_rows: list[ParsedActiveAssetBatchRow] = []
    seen: set[tuple[str, str]] = set()
    normalized_payload: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_rows, start=1):
        try:
            request = ActiveAssetCreateRequest.model_validate(raw)
        except (ValidationError, ValueError, TypeError):
            parsed_rows.append(ParsedActiveAssetBatchRow(index, "invalid", "invalid_contract", None))
            normalized_payload.append({"row": index, "status": "invalid"})
            continue
        identity = (request.asset_type, request.value)
        if identity in seen:
            parsed_rows.append(ParsedActiveAssetBatchRow(index, "duplicate_in_batch", "duplicate_identity", request))
            normalized_payload.append({"row": index, "status": "duplicate_in_batch", "request": request.model_dump(mode="json")})
            continue
        seen.add(identity)
        parsed_rows.append(ParsedActiveAssetBatchRow(index, "ready", "ready", request))
        normalized_payload.append({"row": index, "status": "ready", "request": request.model_dump(mode="json")})

    digest = hashlib.sha256(
        json.dumps(normalized_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return ParsedActiveAssetBatch(format=suffix, rows=tuple(parsed_rows), normalized_digest_sha256=digest)


def mark_existing_active_asset_conflicts(
    parsed: ParsedActiveAssetBatch,
    existing: list[ActiveAssetRecord] | set[tuple[str, str]],
) -> ParsedActiveAssetBatch:
    identities = existing if isinstance(existing, set) else {(record.asset_type, record.canonical_value) for record in existing}
    rows = tuple(
        replace(row, status="already_registered", reason_code="identity_already_registered")
        if row.status == "ready" and row.request is not None and (row.request.asset_type, row.request.value) in identities
        else row
        for row in parsed.rows
    )
    return replace(parsed, rows=rows)


def build_active_asset_batch_preflight(
    parsed: ParsedActiveAssetBatch,
    admission: ActiveAssetBatchPreflightAdmission | None,
) -> ActiveAssetBatchPreflightResponse:
    rows = [
        ActiveAssetBatchRow(
            row=row.row,
            status=row.status,
            reason_code=row.reason_code,
            asset_type=row.request.asset_type if row.request is not None else None,
            canonical_value=row.request.value if row.request is not None else None,
        )
        for row in parsed.rows
    ]
    ready = sum(row.status == "ready" for row in parsed.rows)
    invalid = sum(row.status == "invalid" for row in parsed.rows)
    duplicates = sum(row.status == "duplicate_in_batch" for row in parsed.rows)
    conflicts = sum(row.status == "already_registered" for row in parsed.rows)
    can_confirm = ready == len(parsed.rows)
    return ActiveAssetBatchPreflightResponse(
        state="ready" if can_confirm else "needs_correction",
        format=parsed.format,
        input_count=len(parsed.rows),
        ready_count=ready,
        invalid_count=invalid,
        duplicate_count=duplicates,
        conflict_count=conflicts,
        can_confirm=can_confirm,
        review_digest_sha256=parsed.normalized_digest_sha256,
        preflight_token=admission.token if admission is not None else None,
        expires_at=admission.expires_at if admission is not None else None,
        rows=rows,
    )


def _parse_json_rows(text: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ActiveAssetBatchError("invalid_format") from exc
    if not isinstance(payload, list) or any(not isinstance(row, dict) for row in payload):
        raise ActiveAssetBatchError("invalid_format")
    return payload


def _parse_csv_rows(text: str) -> list[dict[str, Any]]:
    try:
        reader = csv.DictReader(StringIO(text, newline=""), strict=True)
        fields = tuple(reader.fieldnames or ())
        if not set(_CSV_REQUIRED_FIELDS).issubset(fields) or not set(fields).issubset(_CSV_ALLOWED_FIELDS):
            raise ActiveAssetBatchError("invalid_header")
        rows: list[dict[str, Any]] = []
        for row in reader:
            if None in row:
                raise ActiveAssetBatchError("invalid_format")
            notes_raw = (row.get("notes") or "").strip()
            notes: Any = []
            if notes_raw:
                try:
                    notes = json.loads(notes_raw)
                except ValueError:
                    notes = "invalid"
            rows.append(
                {
                    "asset_type": row.get("asset_type", ""),
                    "value": row.get("value", ""),
                    "responsible_user_ids": _pipe_values(row.get("responsible_user_ids")),
                    "capabilities": _pipe_values(row.get("capabilities")),
                    "allowed_ports": _port_values(row.get("allowed_ports")),
                    "allowed_protocols": _pipe_values(row.get("allowed_protocols")),
                    "authorization_method": row.get("authorization_method", ""),
                    "authorization_reference": row.get("authorization_reference", ""),
                    "authorized_at": row.get("authorized_at", ""),
                    "expires_at": row.get("expires_at", ""),
                    "notes": notes,
                }
            )
        return rows
    except (csv.Error, UnicodeError) as exc:
        raise ActiveAssetBatchError("invalid_format") from exc


def _pipe_values(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split("|") if item.strip()]


def _port_values(value: str | None) -> list[int | str]:
    return [int(item) if item.isdigit() else item for item in _pipe_values(value)]


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _utc(value: datetime | None) -> datetime:
    observed = value or datetime.now(timezone.utc)
    return observed if observed.tzinfo is not None else observed.replace(tzinfo=timezone.utc)
