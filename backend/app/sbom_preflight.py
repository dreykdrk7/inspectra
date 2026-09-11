"""Bounded, ephemeral binding between an SBOM preflight and its import."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import threading


SBOM_PREFLIGHT_TTL_SECONDS = 300
SBOM_PREFLIGHT_MAX_ENTRIES = 256


class SbomPreflightError(ValueError):
    pass


@dataclass(frozen=True)
class SbomPreflightAdmission:
    token: str
    expires_at: datetime


@dataclass(frozen=True)
class _RetainedAdmission:
    owner_id: str
    digest: str
    expires_at: datetime


class SbomPreflightStore:
    """Keep only a bounded digest binding in memory; never retain SBOM bytes."""

    def __init__(self, *, ttl_seconds: int = SBOM_PREFLIGHT_TTL_SECONDS, max_entries: int = SBOM_PREFLIGHT_MAX_ENTRIES):
        if ttl_seconds <= 0 or max_entries <= 0:
            raise ValueError("SBOM preflight limits must be positive.")
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._records: dict[str, _RetainedAdmission] = {}
        self._lock = threading.Lock()

    def create(self, owner_id: str, payload: bytes, *, now: datetime | None = None) -> SbomPreflightAdmission:
        observed_at = _utc(now)
        token = secrets.token_urlsafe(32)
        token_hash = _token_hash(token)
        record = _RetainedAdmission(
            owner_id=owner_id,
            digest=hashlib.sha256(payload).hexdigest(),
            expires_at=observed_at + timedelta(seconds=self.ttl_seconds),
        )
        with self._lock:
            self._purge_unlocked(observed_at)
            if len(self._records) >= self.max_entries:
                oldest = min(self._records, key=lambda key: self._records[key].expires_at)
                del self._records[oldest]
            self._records[token_hash] = record
        return SbomPreflightAdmission(token=token, expires_at=record.expires_at)

    def consume(self, owner_id: str, token: str, payload: bytes, *, now: datetime | None = None) -> None:
        observed_at = _utc(now)
        if not isinstance(token, str) or len(token) < 32 or len(token) > 128:
            raise SbomPreflightError("invalid_or_expired")
        token_hash = _token_hash(token)
        digest = hashlib.sha256(payload).hexdigest()
        with self._lock:
            record = self._records.get(token_hash)
            if record is None or record.expires_at <= observed_at or record.owner_id != owner_id:
                self._records.pop(token_hash, None)
                raise SbomPreflightError("invalid_or_expired")
            if not secrets.compare_digest(record.digest, digest):
                raise SbomPreflightError("content_changed")
            del self._records[token_hash]

    def active_count(self, *, now: datetime | None = None) -> int:
        with self._lock:
            self._purge_unlocked(_utc(now))
            return len(self._records)

    def _purge_unlocked(self, now: datetime) -> None:
        for key in [key for key, record in self._records.items() if record.expires_at <= now]:
            del self._records[key]


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _utc(value: datetime | None) -> datetime:
    observed = value or datetime.now(timezone.utc)
    return observed if observed.tzinfo is not None else observed.replace(tzinfo=timezone.utc)
