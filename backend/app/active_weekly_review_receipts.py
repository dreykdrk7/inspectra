"""Private, target-free receipts for Active weekly portfolio reviews.

Receipts prove that a bounded weekly snapshot digest was acknowledged with a
closed outcome.  They never retain the digest itself, report contents, targets,
notes, actor identities, runner results, or free-form text.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.active_weekly_report import (
    ACTIVE_WEEKLY_REPORT_CONTRACT_VERSION,
    ActiveWeeklyReportPeriod,
    ActiveWeeklyReportPreflight,
)
from app.config import Settings
from app.storage import _atomic_write_json, storage_lock


ACTIVE_WEEKLY_REVIEW_RECEIPT_CONTRACT_VERSION = "2026-09-10.1"
ACTIVE_WEEKLY_REVIEW_RECEIPT_STORE_VERSION = 1
ACTIVE_WEEKLY_REVIEW_RECEIPT_MAX_RECORDS = 52
ACTIVE_WEEKLY_REVIEW_RECEIPT_RETENTION_DAYS = 400
ACTIVE_WEEKLY_REVIEW_RECEIPT_MAX_BYTES = 256 * 1024
ACTIVE_WEEKLY_REVIEW_RECEIPT_KEY_BYTES = 32
ACTIVE_WEEKLY_REVIEW_RECEIPT_KEY_NAME = ".receipt-hmac.key"

ActiveWeeklyReviewOutcome = Literal["reviewed", "follow_up_required"]
_ORGANIZATION_ID = re.compile(r"^(?:local-admin|[a-f0-9]{32})$")
_OPAQUE_ID = re.compile(r"^[a-f0-9]{32}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")


class ActiveWeeklyReviewReceiptError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ActiveWeeklyReviewReceiptCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    period: ActiveWeeklyReportPeriod
    state_at: datetime
    snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    outcome: ActiveWeeklyReviewOutcome
    expected_revision: int = Field(ge=0)
    idempotency_key: str = Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    review_confirmed: Literal[True]

    @model_validator(mode="after")
    def normalize_state_at(self):
        if self.state_at.tzinfo is None or self.state_at.utcoffset() is None:
            raise ValueError("state_at requires timezone information")
        self.state_at = self.state_at.astimezone(timezone.utc)
        return self


class ActiveWeeklyReviewReceiptVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    receipt_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class ActiveWeeklyReviewReceiptRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-10.1"] = ACTIVE_WEEKLY_REVIEW_RECEIPT_CONTRACT_VERSION
    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    organization_id: str = Field(pattern=r"^(?:local-admin|[a-f0-9]{32})$")
    report_contract_version: Literal["2026-09-09.1"] = ACTIVE_WEEKLY_REPORT_CONTRACT_VERSION
    period: ActiveWeeklyReportPeriod
    starts_at: datetime
    state_at: datetime
    outcome: ActiveWeeklyReviewOutcome
    coverage_state: Literal["ready", "partial", "no_assets"]
    coverage_incomplete: bool
    snapshot_hmac_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    request_digest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    idempotency_digest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    reviewed_at: datetime

    @model_validator(mode="after")
    def validate_times(self):
        values = (self.starts_at, self.state_at, self.reviewed_at)
        if any(value.tzinfo is None or value.utcoffset() is None for value in values):
            raise ValueError("Receipt timestamps require timezone information.")
        if not self.starts_at < self.state_at <= self.reviewed_at + timedelta(seconds=5):
            raise ValueError("Receipt time window is invalid.")
        expected_days = 7 if self.period == "7d" else 30
        if self.state_at - self.starts_at != timedelta(days=expected_days):
            raise ValueError("Receipt period does not match its time window.")
        if self.coverage_state == "partial" and not self.coverage_incomplete:
            raise ValueError("Partial receipt must declare incomplete coverage.")
        if self.coverage_state == "ready" and self.coverage_incomplete:
            raise ValueError("Ready receipt cannot declare incomplete coverage.")
        return self


class ActiveWeeklyReviewReceiptCollection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = ACTIVE_WEEKLY_REVIEW_RECEIPT_STORE_VERSION
    organization_id: str = Field(pattern=r"^(?:local-admin|[a-f0-9]{32})$")
    revision: int = Field(default=0, ge=0)
    receipts: tuple[ActiveWeeklyReviewReceiptRecord, ...] = Field(
        default=(), max_length=ACTIVE_WEEKLY_REVIEW_RECEIPT_MAX_RECORDS
    )
    integrity_hmac_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def validate_scope(self):
        if len({item.id for item in self.receipts}) != len(self.receipts):
            raise ValueError("Receipt identifiers are duplicated.")
        if any(item.organization_id != self.organization_id for item in self.receipts):
            raise ValueError("Receipt crosses an organization boundary.")
        return self


class ActiveWeeklyReviewReceiptView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-10.1"] = ACTIVE_WEEKLY_REVIEW_RECEIPT_CONTRACT_VERSION
    id: str
    report_contract_version: Literal["2026-09-09.1"]
    period: ActiveWeeklyReportPeriod
    starts_at: datetime
    state_at: datetime
    outcome: ActiveWeeklyReviewOutcome
    coverage_state: Literal["ready", "partial", "no_assets"]
    coverage_incomplete: bool
    snapshot_hmac_sha256: str
    reviewed_at: datetime
    privacy: Literal["target_free_no_raw_digest_report_actor_notes_or_results"] = (
        "target_free_no_raw_digest_report_actor_notes_or_results"
    )


class ActiveWeeklyReviewReceiptPage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-10.1"] = ACTIVE_WEEKLY_REVIEW_RECEIPT_CONTRACT_VERSION
    revision: int = Field(ge=0)
    items: tuple[ActiveWeeklyReviewReceiptView, ...] = Field(
        max_length=ACTIVE_WEEKLY_REVIEW_RECEIPT_MAX_RECORDS
    )
    max_retained: Literal[52] = ACTIVE_WEEKLY_REVIEW_RECEIPT_MAX_RECORDS
    retention_days: Literal[400] = ACTIVE_WEEKLY_REVIEW_RECEIPT_RETENTION_DAYS


class ActiveWeeklyReviewReceiptMutation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-10.1"] = ACTIVE_WEEKLY_REVIEW_RECEIPT_CONTRACT_VERSION
    revision: int = Field(ge=1)
    receipt: ActiveWeeklyReviewReceiptView
    replayed: bool


class ActiveWeeklyReviewReceiptVerification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-10.1"] = ACTIVE_WEEKLY_REVIEW_RECEIPT_CONTRACT_VERSION
    receipt_id: str
    valid: bool
    verification: Literal["local_hmac_no_external_provider"] = "local_hmac_no_external_provider"


class ActiveWeeklyReviewReceiptStore:
    def __init__(self, settings: Settings, *, now_func=None, id_factory=None) -> None:
        self.settings = settings
        self.directory = settings.active_weekly_review_receipts_dir
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        self._now_func = now_func or (lambda: datetime.now(timezone.utc))
        self._id_factory = id_factory or (lambda: uuid4().hex)
        self._key = self._load_or_create_key()

    def list(self, organization_id: str) -> ActiveWeeklyReviewReceiptPage:
        self._validate_organization(organization_id)
        with storage_lock(self.settings):
            current = self._load(organization_id)
            normalized = self._normalize(current, self._now())
            if normalized != current:
                self._save(normalized)
        ordered = tuple(sorted(normalized.receipts, key=lambda item: (item.reviewed_at, item.id), reverse=True))
        return ActiveWeeklyReviewReceiptPage(
            revision=normalized.revision,
            items=tuple(_view(item) for item in ordered),
        )

    def create(
        self,
        *,
        organization_id: str,
        preflight: ActiveWeeklyReportPreflight,
        outcome: ActiveWeeklyReviewOutcome,
        expected_revision: int,
        idempotency_key: str,
    ) -> ActiveWeeklyReviewReceiptMutation:
        with storage_lock(self.settings):
            return self.create_with_shared_lock_held(
                organization_id=organization_id,
                preflight=preflight,
                outcome=outcome,
                expected_revision=expected_revision,
                idempotency_key=idempotency_key,
            )

    def create_with_shared_lock_held(
        self,
        *,
        organization_id: str,
        preflight: ActiveWeeklyReportPreflight,
        outcome: ActiveWeeklyReviewOutcome,
        expected_revision: int,
        idempotency_key: str,
    ) -> ActiveWeeklyReviewReceiptMutation:
        """Create while the caller holds the process-wide storage lock.

        The HTTP boundary uses this method to bind snapshot reconstruction and
        publication without releasing the lock between those two operations.
        Other callers should use ``create``.
        """
        self._validate_organization(organization_id)
        if expected_revision < 0 or not re.fullmatch(r"[A-Za-z0-9._:-]{16,128}", idempotency_key):
            raise ActiveWeeklyReviewReceiptError("invalid_request")
        now = self._now()
        snapshot_hmac = active_weekly_snapshot_hmac(self._key, organization_id, preflight)
        request_digest = _request_digest(self._key, organization_id, snapshot_hmac, outcome)
        idempotency_digest = _idempotency_digest(self._key, organization_id, idempotency_key)
        current = self._load(organization_id)
        normalized = self._normalize(current, now)
        for item in normalized.receipts:
            if item.idempotency_digest_sha256 != idempotency_digest:
                continue
            if item.request_digest_sha256 != request_digest:
                raise ActiveWeeklyReviewReceiptError("idempotency_conflict")
            if normalized != current:
                self._save(normalized)
            return ActiveWeeklyReviewReceiptMutation(
                revision=normalized.revision, receipt=_view(item), replayed=True
            )
        if normalized.revision != expected_revision:
            raise ActiveWeeklyReviewReceiptError("stale_revision")
        receipt = ActiveWeeklyReviewReceiptRecord(
            id=self._id_factory(),
            organization_id=organization_id,
            period=preflight.period,
            starts_at=preflight.starts_at,
            state_at=preflight.state_at,
            outcome=outcome,
            coverage_state=preflight.state,
            coverage_incomplete=preflight.incomplete,
            snapshot_hmac_sha256=snapshot_hmac,
            request_digest_sha256=request_digest,
            idempotency_digest_sha256=idempotency_digest,
            reviewed_at=now,
        )
        records = (*normalized.receipts, receipt)
        if len(records) > ACTIVE_WEEKLY_REVIEW_RECEIPT_MAX_RECORDS:
            records = tuple(sorted(records, key=lambda item: (item.reviewed_at, item.id))[-ACTIVE_WEEKLY_REVIEW_RECEIPT_MAX_RECORDS:])
        updated = normalized.model_copy(update={
            "revision": normalized.revision + 1,
            "receipts": records,
        })
        self._save(updated)
        return ActiveWeeklyReviewReceiptMutation(
            revision=updated.revision, receipt=_view(receipt), replayed=False
        )

    def verify(
        self, organization_id: str, receipt_id: str, snapshot_digest: str
    ) -> ActiveWeeklyReviewReceiptVerification:
        self._validate_organization(organization_id)
        if not _OPAQUE_ID.fullmatch(receipt_id):
            raise ActiveWeeklyReviewReceiptError("not_found")
        if not _DIGEST.fullmatch(snapshot_digest):
            raise ActiveWeeklyReviewReceiptError("invalid_request")
        with storage_lock(self.settings):
            current = self._load(organization_id)
            collection = self._normalize(current, self._now())
            if collection != current:
                self._save(collection)
            receipt = next((item for item in collection.receipts if item.id == receipt_id), None)
        if receipt is None:
            raise ActiveWeeklyReviewReceiptError("not_found")
        expected = active_weekly_snapshot_hmac_for_receipt(
            self._key, receipt, snapshot_digest
        )
        return ActiveWeeklyReviewReceiptVerification(
            receipt_id=receipt.id,
            valid=hmac.compare_digest(expected, receipt.snapshot_hmac_sha256),
        )

    def purge(self, *, organization_id: str, cutoff: datetime) -> int:
        self._validate_organization(organization_id)
        if cutoff.tzinfo is None or cutoff.utcoffset() is None:
            raise ActiveWeeklyReviewReceiptError("invalid_clock")
        cutoff = cutoff.astimezone(timezone.utc)
        with storage_lock(self.settings):
            current = self._load(organization_id)
            retained = tuple(item for item in current.receipts if item.reviewed_at >= cutoff)
            removed = len(current.receipts) - len(retained)
            if removed:
                self._save(current.model_copy(update={
                    "revision": current.revision + 1,
                    "receipts": retained,
                }))
            return removed

    def _normalize(
        self, collection: ActiveWeeklyReviewReceiptCollection, now: datetime
    ) -> ActiveWeeklyReviewReceiptCollection:
        cutoff = now - timedelta(days=ACTIVE_WEEKLY_REVIEW_RECEIPT_RETENTION_DAYS)
        retained = tuple(item for item in collection.receipts if item.reviewed_at >= cutoff)
        if len(retained) > ACTIVE_WEEKLY_REVIEW_RECEIPT_MAX_RECORDS:
            retained = tuple(sorted(retained, key=lambda item: (item.reviewed_at, item.id))[-ACTIVE_WEEKLY_REVIEW_RECEIPT_MAX_RECORDS:])
        if retained == collection.receipts:
            return collection
        return collection.model_copy(update={
            "revision": collection.revision + 1,
            "receipts": retained,
        })

    def _load_or_create_key(self) -> bytes:
        path = self.directory / ACTIVE_WEEKLY_REVIEW_RECEIPT_KEY_NAME
        with storage_lock(self.settings):
            if path.exists() or path.is_symlink():
                return _read_private_key(path)
            if any(item.suffix == ".json" for item in self.directory.iterdir()):
                raise ActiveWeeklyReviewReceiptError("invalid_store")
            key = os.urandom(ACTIVE_WEEKLY_REVIEW_RECEIPT_KEY_BYTES)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(path, flags, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(key)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(path, 0o600)
                directory_fd = os.open(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except FileExistsError:
                return _read_private_key(path)
            except OSError as exc:
                raise ActiveWeeklyReviewReceiptError("store_unavailable") from exc
            return key

    def _path(self, organization_id: str) -> Path:
        return self.directory / f"{organization_id}.json"

    def _load(self, organization_id: str) -> ActiveWeeklyReviewReceiptCollection:
        path = self._path(organization_id)
        if not path.exists() and not path.is_symlink():
            return _signed_collection(self._key, organization_id=organization_id)
        try:
            metadata = path.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > ACTIVE_WEEKLY_REVIEW_RECEIPT_MAX_BYTES
                or metadata.st_mode & 0o077
            ):
                raise ValueError("invalid receipt store")
            collection = ActiveWeeklyReviewReceiptCollection.model_validate_json(
                path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError, ValidationError, json.JSONDecodeError) as exc:
            raise ActiveWeeklyReviewReceiptError("invalid_store") from exc
        if collection.organization_id != organization_id or not validate_active_weekly_receipt_collection(collection, self._key):
            raise ActiveWeeklyReviewReceiptError("invalid_store")
        return collection

    def _save(self, collection: ActiveWeeklyReviewReceiptCollection) -> None:
        signed = _signed_collection(
            self._key,
            organization_id=collection.organization_id,
            revision=collection.revision,
            receipts=collection.receipts,
        )
        payload = signed.model_dump(mode="json")
        if len(json.dumps(payload, sort_keys=True).encode("utf-8")) > ACTIVE_WEEKLY_REVIEW_RECEIPT_MAX_BYTES:
            raise ActiveWeeklyReviewReceiptError("capacity_reached")
        try:
            _atomic_write_json(self._path(collection.organization_id), payload)
        except OSError as exc:
            raise ActiveWeeklyReviewReceiptError("store_unavailable") from exc

    def _now(self) -> datetime:
        raw = self._now_func()
        if raw.tzinfo is None or raw.utcoffset() is None:
            raise ActiveWeeklyReviewReceiptError("invalid_clock")
        return raw.astimezone(timezone.utc)

    @staticmethod
    def _validate_organization(organization_id: str) -> None:
        if not _ORGANIZATION_ID.fullmatch(organization_id):
            raise ActiveWeeklyReviewReceiptError("invalid_scope")


def active_weekly_snapshot_hmac(
    key: bytes, organization_id: str, preflight: ActiveWeeklyReportPreflight
) -> str:
    return _snapshot_hmac(
        key,
        organization_id=organization_id,
        report_contract_version=preflight.contract_version,
        period=preflight.period,
        starts_at=preflight.starts_at,
        state_at=preflight.state_at,
        snapshot_digest=preflight.snapshot_digest,
    )


def active_weekly_snapshot_hmac_for_receipt(
    key: bytes, receipt: ActiveWeeklyReviewReceiptRecord, snapshot_digest: str
) -> str:
    return _snapshot_hmac(
        key,
        organization_id=receipt.organization_id,
        report_contract_version=receipt.report_contract_version,
        period=receipt.period,
        starts_at=receipt.starts_at,
        state_at=receipt.state_at,
        snapshot_digest=snapshot_digest,
    )


def validate_active_weekly_receipt_collection(
    collection: ActiveWeeklyReviewReceiptCollection, key: bytes
) -> bool:
    expected = _collection_hmac(
        key,
        organization_id=collection.organization_id,
        revision=collection.revision,
        receipts=collection.receipts,
    )
    return hmac.compare_digest(expected, collection.integrity_hmac_sha256)


def _snapshot_hmac(
    key: bytes,
    *,
    organization_id: str,
    report_contract_version: str,
    period: str,
    starts_at: datetime,
    state_at: datetime,
    snapshot_digest: str,
) -> str:
    if len(key) != ACTIVE_WEEKLY_REVIEW_RECEIPT_KEY_BYTES or not _DIGEST.fullmatch(snapshot_digest):
        raise ActiveWeeklyReviewReceiptError("invalid_request")
    fields = (
        organization_id,
        report_contract_version,
        period,
        _utc_text(starts_at),
        _utc_text(state_at),
        snapshot_digest,
    )
    payload = b"inspectra-active-weekly-review-snapshot-v1\0" + b"\0".join(
        item.encode("ascii") for item in fields
    )
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _request_digest(key: bytes, organization_id: str, snapshot_hmac: str, outcome: str) -> str:
    payload = f"inspectra-active-weekly-review-request-v1\0{organization_id}\0{snapshot_hmac}\0{outcome}".encode("ascii")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _idempotency_digest(key: bytes, organization_id: str, value: str) -> str:
    payload = f"inspectra-active-weekly-review-idempotency-v1\0{organization_id}\0{value}".encode("ascii")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _signed_collection(
    key: bytes,
    *,
    organization_id: str,
    revision: int = 0,
    receipts: tuple[ActiveWeeklyReviewReceiptRecord, ...] = (),
) -> ActiveWeeklyReviewReceiptCollection:
    return ActiveWeeklyReviewReceiptCollection(
        organization_id=organization_id,
        revision=revision,
        receipts=receipts,
        integrity_hmac_sha256=_collection_hmac(
            key, organization_id=organization_id, revision=revision, receipts=receipts
        ),
    )


def _collection_hmac(
    key: bytes,
    *,
    organization_id: str,
    revision: int,
    receipts: tuple[ActiveWeeklyReviewReceiptRecord, ...],
) -> str:
    body = {
        "schema_version": ACTIVE_WEEKLY_REVIEW_RECEIPT_STORE_VERSION,
        "organization_id": organization_id,
        "revision": revision,
        "receipts": [item.model_dump(mode="json") for item in receipts],
    }
    payload = (
        b"inspectra-active-weekly-review-collection-v1\0"
        + json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _read_private_key(path: Path) -> bytes:
    try:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != ACTIVE_WEEKLY_REVIEW_RECEIPT_KEY_BYTES
            or metadata.st_mode & 0o077
        ):
            raise ValueError("invalid receipt key")
        key = path.read_bytes()
    except (OSError, ValueError) as exc:
        raise ActiveWeeklyReviewReceiptError("invalid_store") from exc
    return key


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ActiveWeeklyReviewReceiptError("invalid_request")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _view(record: ActiveWeeklyReviewReceiptRecord) -> ActiveWeeklyReviewReceiptView:
    return ActiveWeeklyReviewReceiptView(
        id=record.id,
        report_contract_version=record.report_contract_version,
        period=record.period,
        starts_at=record.starts_at,
        state_at=record.state_at,
        outcome=record.outcome,
        coverage_state=record.coverage_state,
        coverage_incomplete=record.coverage_incomplete,
        snapshot_hmac_sha256=record.snapshot_hmac_sha256,
        reviewed_at=record.reviewed_at,
    )
