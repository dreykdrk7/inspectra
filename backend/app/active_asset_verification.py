from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
from typing import Callable, Literal, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.active_assets import ActiveAssetRecord
from app.active_verification_index import (
    ActiveVerificationIndex,
    ActiveVerificationIndexError,
)
from app.config import Settings
from app.storage import active_asset_deletion_is_pending, storage_lock


ACTIVE_ASSET_VERIFICATION_CONTRACT_VERSION = "2026-09-09.1"
ACTIVE_ASSET_VERIFICATION_CHALLENGE_TTL_SECONDS = 900
ACTIVE_ASSET_VERIFICATION_MAX_ATTEMPTS_PER_HOUR = 5
ACTIVE_ASSET_VERIFICATION_MAX_BODY_BYTES = 512
ACTIVE_ASSET_VERIFICATION_TIMEOUT_SECONDS = 3.0
ACTIVE_ASSET_VERIFICATION_MAX_DNS_ANSWERS = 8
ACTIVE_ASSET_VERIFICATION_WELL_KNOWN_PATH = "/.well-known/inspectra-verification"

VerificationMethod = Literal["manual_attestation", "dns_txt", "http_well_known", "managed_private"]
VerificationStatus = Literal["pending", "verified", "failed", "expired", "revoked"]
_ID = re.compile(r"^[a-f0-9]{32}$")
_ORGANIZATION_ID = re.compile(r"^(?:local-admin|[a-f0-9]{32})$")
_ACTOR_ID = re.compile(r"^(?:local-admin|team-admin|[a-f0-9]{32})$")
_TOKEN = re.compile(r"^iv1_[A-Za-z0-9_-]{32}$")


class ActiveAssetVerificationStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: VerificationMethod
    valid_for_days: int = Field(default=30, ge=1, le=90)
    control_check_confirmed: Literal[True]


class ActiveAssetVerificationCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verification_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    challenge_token: str = Field(min_length=36, max_length=36, pattern=r"^iv1_[A-Za-z0-9_-]{32}$")
    manual_attestation_confirmed: bool = False


class ActiveAssetVerificationRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verification_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    revocation_confirmed: Literal[True]


class ActiveAssetVerificationRecord(BaseModel):
    """Internal record. The challenge digest is never projected by the API."""

    model_config = ConfigDict(extra="forbid")

    contract_version: Literal[ACTIVE_ASSET_VERIFICATION_CONTRACT_VERSION] = ACTIVE_ASSET_VERIFICATION_CONTRACT_VERSION
    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    asset_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    organization_id: str = Field(pattern=r"^(?:local-admin|[a-f0-9]{32})$")
    actor_id: str = Field(pattern=r"^(?:local-admin|team-admin|[a-f0-9]{32})$")
    method: VerificationMethod
    status: VerificationStatus
    challenge_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime
    challenge_expires_at: datetime
    requested_valid_days: int = Field(ge=1, le=90)
    attempts: int = Field(default=0, ge=0, le=1)
    last_attempt_at: datetime | None = None
    verified_at: datetime | None = None
    verification_expires_at: datetime | None = None
    revoked_at: datetime | None = None
    reason_code: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{2,47}$")


class ActiveAssetVerificationView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: Literal[ACTIVE_ASSET_VERIFICATION_CONTRACT_VERSION] = ACTIVE_ASSET_VERIFICATION_CONTRACT_VERSION
    id: str
    asset_id: str
    method: VerificationMethod
    status: VerificationStatus
    created_at: datetime
    challenge_expires_at: datetime
    attempts: int
    last_attempt_at: datetime | None
    verified_at: datetime | None
    verification_expires_at: datetime | None
    revoked_at: datetime | None
    reason_code: str | None


class ActiveAssetVerificationChallengeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verification: ActiveAssetVerificationView
    challenge_token: str
    placement: str
    one_time_display: Literal[True] = True
    legal_authorization_established: Literal[False] = False


@dataclass(frozen=True)
class ActiveAssetVerificationObservation:
    matched: bool
    reason_code: str


class ActiveAssetVerificationTransport(Protocol):
    def managed_private(self, *, asset: ActiveAssetRecord, expected_token: str) -> ActiveAssetVerificationObservation: ...


class ManagedActiveAssetVerificationTransport:
    """Optional deployment adapter; public DNS/HTTP egress belongs to active-tools."""

    def __init__(self, *, managed_checker: Callable[[ActiveAssetRecord, str], bool] | None = None) -> None:
        self.managed_checker = managed_checker

    def managed_private(self, *, asset: ActiveAssetRecord, expected_token: str) -> ActiveAssetVerificationObservation:
        if self.managed_checker is None:
            return ActiveAssetVerificationObservation(False, "managed_verifier_unavailable")
        try:
            matched = bool(self.managed_checker(asset, expected_token))
        except Exception:
            return ActiveAssetVerificationObservation(False, "managed_verifier_unavailable")
        return ActiveAssetVerificationObservation(matched, "matched" if matched else "token_not_observed")


class ActiveAssetVerificationError(RuntimeError):
    pass


class ActiveAssetVerificationStore:
    def __init__(self, settings: Settings, *, now_func: Callable[[], datetime] | None = None) -> None:
        self.settings = settings
        self.root = settings.data_dir / "results" / "active_asset_verifications"
        self._now_func = now_func or (lambda: datetime.now(timezone.utc))
        self.index = ActiveVerificationIndex(settings, self._read)

    def start(
        self,
        asset: ActiveAssetRecord,
        request: ActiveAssetVerificationStartRequest,
        *,
        organization_id: str,
        actor_id: str,
    ) -> tuple[ActiveAssetVerificationRecord, str]:
        self._validate_owner(asset, organization_id)
        self._validate_method(asset, request.method)
        self._validate_actor(actor_id)
        now = _utc(self._now_func())
        if asset.status != "active" or asset.expires_at <= now:
            raise ActiveAssetVerificationError("asset_not_current")
        with storage_lock(self.settings):
            if active_asset_deletion_is_pending(self.settings, asset.id):
                raise ActiveAssetVerificationError("verification_not_found")
            records = self._load_asset_unlocked(asset.id, organization_id)
            recent = [item for item in records if item.created_at > now - timedelta(hours=1)]
            if len(recent) >= ACTIVE_ASSET_VERIFICATION_MAX_ATTEMPTS_PER_HOUR:
                raise ActiveAssetVerificationError("verification_rate_limited")
            for previous in records:
                if self._materialize(previous).status == "pending":
                    self._write(previous.model_copy(update={"status": "revoked", "revoked_at": now, "reason_code": "superseded"}))
            token = "iv1_" + secrets.token_urlsafe(24)[:32]
            record = ActiveAssetVerificationRecord(
                id=uuid4().hex,
                asset_id=asset.id,
                organization_id=organization_id,
                actor_id=actor_id,
                method=request.method,
                status="pending",
                challenge_sha256=_digest(token),
                created_at=now,
                challenge_expires_at=now + timedelta(seconds=ACTIVE_ASSET_VERIFICATION_CHALLENGE_TTL_SECONDS),
                requested_valid_days=request.valid_for_days,
            )
            self._write(record)
        return record, token

    def latest(self, asset_id: str, *, organization_id: str) -> ActiveAssetVerificationRecord | None:
        self._validate_id(asset_id)
        return self.latest_many({asset_id}, organization_id=organization_id).get(asset_id)

    def latest_many(
        self, asset_ids: set[str], *, organization_id: str
    ) -> dict[str, ActiveAssetVerificationRecord]:
        """Return at most one validated record for each bounded asset identity."""

        with storage_lock(self.settings):
            try:
                records = self.index.latest(
                    organization_id=organization_id, asset_ids=asset_ids
                )
            except ActiveVerificationIndexError as exc:
                raise ActiveAssetVerificationError("verification_store_invalid") from exc
        return {asset_id: self._materialize(record) for asset_id, record in records.items()}

    def index_ready(self) -> bool:
        with storage_lock(self.settings):
            return self.index.ready()

    def attention_asset_ids(self, *, organization_id: str) -> set[str]:
        with storage_lock(self.settings):
            try:
                return self.index.attention_asset_ids(
                    organization_id=organization_id, now=_utc(self._now_func())
                )
            except ActiveVerificationIndexError as exc:
                raise ActiveAssetVerificationError("verification_store_invalid") from exc

    def get(self, verification_id: str, *, asset_id: str, organization_id: str) -> ActiveAssetVerificationRecord:
        self._validate_id(verification_id)
        path = self._path(organization_id, verification_id)
        with storage_lock(self.settings):
            record = self._read(path)
        if record.asset_id != asset_id or record.organization_id != organization_id:
            raise ActiveAssetVerificationError("verification_not_found")
        return self._materialize(record)

    def list_for_deletion_unlocked(
        self, asset_id: str, *, organization_id: str
    ) -> list[ActiveAssetVerificationRecord]:
        return self._load_asset_unlocked(asset_id, organization_id)

    def delete_for_asset(self, asset_id: str, *, organization_id: str) -> int:
        with storage_lock(self.settings):
            records = self._load_asset_unlocked(asset_id, organization_id)
            for record in records:
                self._path(organization_id, record.id).unlink(missing_ok=True)
            self.index.sync_after_asset_delete(
                organization_id=organization_id, asset_id=asset_id
            )
            return len(records)

    def validate_pending_challenge(
        self,
        verification_id: str,
        *,
        asset_id: str,
        organization_id: str,
        challenge_token: str,
    ) -> ActiveAssetVerificationRecord:
        record = self.get(verification_id, asset_id=asset_id, organization_id=organization_id)
        if record.status != "pending":
            raise ActiveAssetVerificationError(f"verification_{record.status}")
        if not _TOKEN.fullmatch(challenge_token) or not secrets.compare_digest(_digest(challenge_token), record.challenge_sha256):
            raise ActiveAssetVerificationError("challenge_mismatch")
        return record

    def complete(
        self,
        verification_id: str,
        *,
        asset: ActiveAssetRecord,
        organization_id: str,
        challenge_token: str,
        observation: ActiveAssetVerificationObservation,
    ) -> ActiveAssetVerificationRecord:
        path = self._path(organization_id, verification_id)
        now = _utc(self._now_func())
        with storage_lock(self.settings):
            record = self._materialize(self._read(path))
            if record.asset_id != asset.id or record.organization_id != organization_id:
                raise ActiveAssetVerificationError("verification_not_found")
            if record.status != "pending":
                raise ActiveAssetVerificationError(f"verification_{record.status}")
            if not _TOKEN.fullmatch(challenge_token) or not secrets.compare_digest(_digest(challenge_token), record.challenge_sha256):
                observation = ActiveAssetVerificationObservation(False, "challenge_mismatch")
            if observation.matched:
                expiry = min(asset.expires_at, now + timedelta(days=record.requested_valid_days))
                updated = record.model_copy(update={
                    "status": "verified", "attempts": 1, "last_attempt_at": now,
                    "verified_at": now, "verification_expires_at": expiry, "reason_code": "matched",
                })
            else:
                updated = record.model_copy(update={
                    "status": "failed", "attempts": 1, "last_attempt_at": now,
                    "reason_code": observation.reason_code,
                })
            self._write(updated)
        return updated

    def revoke(self, verification_id: str, *, asset_id: str, organization_id: str) -> ActiveAssetVerificationRecord:
        path = self._path(organization_id, verification_id)
        now = _utc(self._now_func())
        with storage_lock(self.settings):
            record = self._materialize(self._read(path))
            if record.asset_id != asset_id or record.organization_id != organization_id:
                raise ActiveAssetVerificationError("verification_not_found")
            if record.status == "revoked":
                return record
            updated = record.model_copy(update={"status": "revoked", "revoked_at": now, "reason_code": "operator_revoked"})
            self._write(updated)
        return updated

    @staticmethod
    def view(record: ActiveAssetVerificationRecord) -> ActiveAssetVerificationView:
        return ActiveAssetVerificationView.model_validate(record.model_dump(exclude={"organization_id", "actor_id", "challenge_sha256", "requested_valid_days"}))

    def _materialize(self, record: ActiveAssetVerificationRecord) -> ActiveAssetVerificationRecord:
        now = _utc(self._now_func())
        expired = (
            record.status == "pending" and record.challenge_expires_at <= now
        ) or (
            record.status == "verified" and record.verification_expires_at is not None and record.verification_expires_at <= now
        )
        return record.model_copy(update={"status": "expired", "reason_code": "expired"}) if expired else record

    def _load_asset_unlocked(self, asset_id: str, organization_id: str) -> list[ActiveAssetVerificationRecord]:
        self._validate_id(asset_id)
        try:
            return self.index.records_for_asset(
                organization_id=organization_id, asset_id=asset_id
            )
        except ActiveVerificationIndexError as exc:
            raise ActiveAssetVerificationError("verification_store_invalid") from exc

    def _read(self, path: Path) -> ActiveAssetVerificationRecord:
        if not path.exists():
            raise ActiveAssetVerificationError("verification_not_found")
        if path.is_symlink() or not path.is_file():
            raise ActiveAssetVerificationError("verification_store_invalid")
        try:
            return ActiveAssetVerificationRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ActiveAssetVerificationError("verification_store_invalid") from exc

    def _write(self, record: ActiveAssetVerificationRecord) -> None:
        path = self._path(record.organization_id, record.id)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":")), encoding="utf-8")
        temporary.replace(path)
        self.index.sync_after_write(record)

    def _path(self, organization_id: str, verification_id: str) -> Path:
        self._validate_organization(organization_id)
        self._validate_id(verification_id)
        return self.root / organization_id / f"{verification_id}.json"

    @staticmethod
    def _validate_owner(asset: ActiveAssetRecord, organization_id: str) -> None:
        if asset.organization_id != organization_id:
            raise ActiveAssetVerificationError("verification_not_found")

    @staticmethod
    def _validate_method(asset: ActiveAssetRecord, method: VerificationMethod) -> None:
        if method == "dns_txt" and asset.asset_type not in {"domain", "host"}:
            raise ActiveAssetVerificationError("verification_method_incompatible")
        if method == "http_well_known" and asset.asset_type == "ip":
            raise ActiveAssetVerificationError("verification_method_incompatible")

    @staticmethod
    def _validate_actor(value: str) -> None:
        if not _ACTOR_ID.fullmatch(value):
            raise ActiveAssetVerificationError("invalid_identity")

    @staticmethod
    def _validate_organization(value: str) -> None:
        if not _ORGANIZATION_ID.fullmatch(value):
            raise ActiveAssetVerificationError("invalid_identity")

    @staticmethod
    def _validate_id(value: str) -> None:
        if not _ID.fullmatch(value):
            raise ActiveAssetVerificationError("verification_not_found")


def verification_placement(asset: ActiveAssetRecord, method: VerificationMethod) -> str:
    if method == "dns_txt":
        return f"_inspectra-verification.{asset.canonical_value} TXT"
    if method == "http_well_known":
        origin = _verification_origin(asset)
        return origin + ACTIVE_ASSET_VERIFICATION_WELL_KNOWN_PATH
    if method == "managed_private":
        return "managed private verifier"
    return "Inspectra manual attestation"


def verify_observation(
    transport: ActiveAssetVerificationTransport,
    *,
    asset: ActiveAssetRecord,
    method: VerificationMethod,
    challenge_token: str,
    manual_attestation_confirmed: bool,
) -> ActiveAssetVerificationObservation:
    if method == "manual_attestation":
        return ActiveAssetVerificationObservation(manual_attestation_confirmed, "matched" if manual_attestation_confirmed else "manual_attestation_missing")
    if method in {"dns_txt", "http_well_known"}:
        raise ActiveAssetVerificationError("remote_verification_requires_isolated_runner")
    return transport.managed_private(asset=asset, expected_token=challenge_token)


def _verification_origin(asset: ActiveAssetRecord) -> str:
    if asset.asset_type == "http_origin":
        return asset.canonical_value
    scheme = "https" if "https" in asset.allowed_protocols else "http"
    return f"{scheme}://{asset.canonical_value}"


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ActiveAssetVerificationError("timezone_required")
    return value.astimezone(timezone.utc)
