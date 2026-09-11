from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import socket
import sqlite3
import threading
from typing import Awaitable, Callable, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError


INTEGRATION_EVENT_CONTRACT_VERSION = "2026-09-11.1"
INTEGRATION_EVENT_SIGNATURE_VERSION = "v1"
INTEGRATION_EVENT_MAX_BODY_BYTES = 8_192
INTEGRATION_EVENT_MAX_RESPONSE_BYTES = 8_192
INTEGRATION_EVENT_MAX_ATTEMPTS = 5
INTEGRATION_EVENT_LEASE_SECONDS = 30
INTEGRATION_EVENT_MAX_RECORDS = 10_000
INTEGRATION_EVENT_DELIVERED_RETENTION_DAYS = 30
INTEGRATION_EVENT_DEAD_RETENTION_DAYS = 90
INTEGRATION_EVENT_REPLAY_CONTRACT_VERSION = "2026-09-11.1"
INTEGRATION_EVENT_REPLAY_MAX_EVENTS = 100
INTEGRATION_EVENT_REPLAY_TTL_SECONDS = 300
_OPAQUE_ID = re.compile(r"^[a-f0-9]{32}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
_HOST = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class IntegrationEventError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class IntegrationEventConfig:
    endpoint: str
    host: str
    signing_key: bytes
    signing_key_id: str
    timeout_seconds: float = 5.0
    max_concurrency: int = 2

    def __post_init__(self) -> None:
        parsed = urlsplit(self.endpoint)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.hostname.lower() != self.host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.port not in {None, 443}
            or not parsed.path.startswith("/")
            or "//" in parsed.path
            or any(part in {".", ".."} for part in parsed.path.split("/"))
        ):
            raise ValueError("Integration event endpoint must be one fixed allowlisted HTTPS URL.")
        if _HOST.fullmatch(self.host) is None or self.host != self.host.lower():
            raise ValueError("Integration event host must be one canonical DNS name.")
        if len(self.signing_key) < 32:
            raise ValueError("Integration event signing key must contain at least 32 bytes.")
        if _KEY_ID.fullmatch(self.signing_key_id) is None:
            raise ValueError("Integration event signing key id is invalid.")
        if not 0.5 <= self.timeout_seconds <= 10.0 or not 1 <= self.max_concurrency <= 4:
            raise ValueError("Integration event transport limits are invalid.")


class IntegrationEventPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[INTEGRATION_EVENT_CONTRACT_VERSION] = INTEGRATION_EVENT_CONTRACT_VERSION
    event_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    event_type: Literal["analysis.terminal"] = "analysis.terminal"
    occurred_at: datetime
    project_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    analysis_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    status: Literal["completed", "failed", "cancelled"]
    finding_count: int | None = Field(default=None, ge=0, le=100_000)


class IntegrationEventRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    payload: IntegrationEventPayload
    organization_id: str = Field(pattern=r"^(?:local-admin|[a-f0-9]{32})$")
    state: Literal["pending", "delivering", "delivered", "dead"]
    attempts: int = Field(ge=0, le=INTEGRATION_EVENT_MAX_ATTEMPTS)
    next_attempt_at: datetime
    lease_until: datetime | None = None
    last_result: Literal["accepted", "retryable_failure", "permanent_failure"] | None = None
    created_at: datetime
    delivered_at: datetime | None = None


class IntegrationEventStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[INTEGRATION_EVENT_CONTRACT_VERSION] = INTEGRATION_EVENT_CONTRACT_VERSION
    enabled: bool
    destination_configured: bool
    pending: int = Field(ge=0)
    delivering: int = Field(ge=0)
    delivered: int = Field(ge=0)
    dead: int = Field(ge=0)
    delivery_scope: Literal["project_analysis_terminal"] = "project_analysis_terminal"


class IntegrationEventReplayPreflight(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[INTEGRATION_EVENT_REPLAY_CONTRACT_VERSION] = INTEGRATION_EVENT_REPLAY_CONTRACT_VERSION
    observed_at: datetime
    expires_at: datetime
    total_dead: int = Field(ge=0)
    selected_events: int = Field(ge=0, le=INTEGRATION_EVENT_REPLAY_MAX_EVENTS)
    truncated: bool
    snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class IntegrationEventReplayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    observed_at: datetime
    snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirmation: Literal["replay_dead_integration_events"]


class IntegrationEventReplayResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[INTEGRATION_EVENT_REPLAY_CONTRACT_VERSION] = INTEGRATION_EVENT_REPLAY_CONTRACT_VERSION
    replayed_events: int = Field(ge=0, le=INTEGRATION_EVENT_REPLAY_MAX_EVENTS)
    remaining_dead: int = Field(ge=0)


class IntegrationEventStore:
    """Durable, content-minimal outbox. It never stores destination or secret."""

    def __init__(self, path: Path, *, now_func: Callable[[], datetime] | None = None) -> None:
        self.path = path
        self._now = now_func or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        self._initialize()

    def enqueue_terminal_analysis(
        self,
        *,
        organization_id: str,
        project_id: str,
        analysis_id: str,
        status: str,
        occurred_at: datetime,
        finding_count: int | None,
    ) -> IntegrationEventRecord:
        if not _OPAQUE_ID.fullmatch(project_id) or not _OPAQUE_ID.fullmatch(analysis_id):
            raise IntegrationEventError("invalid_identifier")
        event_id = hashlib.sha256(
            f"{INTEGRATION_EVENT_CONTRACT_VERSION}\0{organization_id}\0{analysis_id}".encode("ascii")
        ).hexdigest()
        try:
            payload = IntegrationEventPayload(
                event_id=event_id,
                occurred_at=occurred_at,
                project_id=project_id,
                analysis_id=analysis_id,
                status=status,
                finding_count=finding_count,
            )
        except ValidationError as exc:
            raise IntegrationEventError("invalid_terminal_event") from exc
        now = self._aware(self._now())
        record = IntegrationEventRecord(
            payload=payload,
            organization_id=organization_id,
            state="pending",
            attempts=0,
            next_attempt_at=now,
            created_at=now,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._purge_terminal_unlocked(connection, now)
            existing = connection.execute(
                "SELECT event_id FROM integration_events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if existing is not None:
                connection.commit()
                return self.get(event_id)
            count = connection.execute("SELECT COUNT(*) FROM integration_events").fetchone()[0]
            if count >= INTEGRATION_EVENT_MAX_RECORDS:
                raise IntegrationEventError("outbox_capacity_reached")
            connection.execute(
                """
                INSERT OR IGNORE INTO integration_events
                    (event_id, organization_id, payload_json, state, attempts,
                     next_attempt_at, lease_until, last_result, created_at, delivered_at)
                VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, NULL)
                """,
                (
                    event_id,
                    organization_id,
                    self._payload_json(payload),
                    record.state,
                    record.attempts,
                    self._micros(record.next_attempt_at),
                    self._micros(record.created_at),
                ),
            )
            connection.commit()
            return self.get(event_id)

    def purge_terminal(self) -> int:
        now = self._aware(self._now())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            removed = self._purge_terminal_unlocked(connection, now)
            connection.commit()
        return removed

    def claim_due(self) -> IntegrationEventRecord | None:
        now = self._aware(self._now())
        now_micros = self._micros(now)
        lease_micros = self._micros(now + timedelta(seconds=INTEGRATION_EVENT_LEASE_SECONDS))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                UPDATE integration_events SET state = 'pending', lease_until = NULL
                WHERE state = 'delivering' AND lease_until <= ?
                """,
                (now_micros,),
            )
            row = connection.execute(
                """
                SELECT * FROM integration_events
                WHERE state = 'pending' AND next_attempt_at <= ?
                ORDER BY next_attempt_at, event_id LIMIT 1
                """,
                (now_micros,),
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            updated = connection.execute(
                """
                UPDATE integration_events SET state = 'delivering', lease_until = ?
                WHERE event_id = ? AND state = 'pending'
                """,
                (lease_micros, row["event_id"]),
            )
            connection.commit()
            if updated.rowcount != 1:
                return None
        return self.get(row["event_id"])

    def record_result(self, event_id: str, *, accepted: bool, retryable: bool) -> IntegrationEventRecord:
        now = self._aware(self._now())
        with self._connect() as connection:
            row = connection.execute(
                "SELECT attempts, state FROM integration_events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if row is None or row["state"] != "delivering":
                raise IntegrationEventError("delivery_claim_lost")
            attempts = int(row["attempts"]) + 1
            if accepted:
                state, result, next_at, delivered_at = "delivered", "accepted", now, now
            elif retryable and attempts < INTEGRATION_EVENT_MAX_ATTEMPTS:
                state, result = "pending", "retryable_failure"
                next_at = now + timedelta(seconds=min(300, 2 ** attempts))
                delivered_at = None
            else:
                state, result, next_at, delivered_at = "dead", "permanent_failure", now, None
            connection.execute(
                """
                UPDATE integration_events SET state = ?, attempts = ?, next_attempt_at = ?,
                    lease_until = NULL, last_result = ?, delivered_at = ?
                WHERE event_id = ? AND state = 'delivering'
                """,
                (
                    state,
                    attempts,
                    self._micros(next_at),
                    result,
                    self._micros(delivered_at) if delivered_at else None,
                    event_id,
                ),
            )
            connection.commit()
        return self.get(event_id)

    def get(self, event_id: str) -> IntegrationEventRecord:
        if re.fullmatch(r"^[a-f0-9]{64}$", event_id) is None:
            raise IntegrationEventError("invalid_event_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM integration_events WHERE event_id = ?", (event_id,)
            ).fetchone()
        if row is None:
            raise IntegrationEventError("event_not_found")
        try:
            return IntegrationEventRecord(
                payload=IntegrationEventPayload.model_validate_json(row["payload_json"]),
                organization_id=row["organization_id"],
                state=row["state"],
                attempts=row["attempts"],
                next_attempt_at=self._datetime(row["next_attempt_at"]),
                lease_until=self._datetime(row["lease_until"]) if row["lease_until"] else None,
                last_result=row["last_result"],
                created_at=self._datetime(row["created_at"]),
                delivered_at=self._datetime(row["delivered_at"]) if row["delivered_at"] else None,
            )
        except (ValidationError, ValueError, TypeError) as exc:
            raise IntegrationEventError("outbox_record_invalid") from exc

    def summary(self, organization_id: str) -> dict[str, int]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT state, COUNT(*) AS count FROM integration_events WHERE organization_id = ? GROUP BY state",
                (organization_id,),
            ).fetchall()
        counts = {state: 0 for state in ("pending", "delivering", "delivered", "dead")}
        counts.update({row["state"]: int(row["count"]) for row in rows})
        return counts

    def replay_preflight(self, organization_id: str) -> IntegrationEventReplayPreflight:
        now = self._aware(self._now())
        with self._connect() as connection:
            rows, total = self._dead_selection_unlocked(connection, organization_id)
        return IntegrationEventReplayPreflight(
            observed_at=now,
            expires_at=now + timedelta(seconds=INTEGRATION_EVENT_REPLAY_TTL_SECONDS),
            total_dead=total,
            selected_events=len(rows),
            truncated=total > len(rows),
            snapshot_digest=self._replay_digest(organization_id, rows),
        )

    def replay_dead(
        self,
        organization_id: str,
        request: IntegrationEventReplayRequest,
    ) -> IntegrationEventReplayResult:
        now = self._aware(self._now())
        observed = self._aware(request.observed_at)
        if observed > now or now - observed > timedelta(seconds=INTEGRATION_EVENT_REPLAY_TTL_SECONDS):
            raise IntegrationEventError("replay_preflight_expired")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows, total = self._dead_selection_unlocked(connection, organization_id)
            expected = self._replay_digest(organization_id, rows)
            if not rows:
                raise IntegrationEventError("no_dead_events")
            if not hmac.compare_digest(expected, request.snapshot_digest):
                raise IntegrationEventError("replay_snapshot_changed")
            event_ids = [row["event_id"] for row in rows]
            placeholders = ",".join("?" for _ in event_ids)
            updated = connection.execute(
                f"""
                UPDATE integration_events
                SET state = 'pending', attempts = 0, next_attempt_at = ?,
                    lease_until = NULL, last_result = NULL, delivered_at = NULL
                WHERE organization_id = ? AND state = 'dead'
                  AND event_id IN ({placeholders})
                """,
                (self._micros(now), organization_id, *event_ids),
            )
            if updated.rowcount != len(event_ids):
                connection.rollback()
                raise IntegrationEventError("replay_snapshot_changed")
            remaining = total - len(event_ids)
            connection.commit()
        return IntegrationEventReplayResult(
            replayed_events=len(event_ids),
            remaining_dead=remaining,
        )

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = DELETE;
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS integration_events (
                    event_id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('pending','delivering','delivered','dead')),
                    attempts INTEGER NOT NULL CHECK (attempts BETWEEN 0 AND 5),
                    next_attempt_at INTEGER NOT NULL,
                    lease_until INTEGER,
                    last_result TEXT CHECK (last_result IS NULL OR last_result IN ('accepted','retryable_failure','permanent_failure')),
                    created_at INTEGER NOT NULL,
                    delivered_at INTEGER
                );
                CREATE INDEX IF NOT EXISTS integration_events_due ON integration_events(state, next_attempt_at, event_id);
                CREATE INDEX IF NOT EXISTS integration_events_owner ON integration_events(organization_id, state);
                """
            )
        os.chmod(self.path, 0o600)

    @staticmethod
    def _purge_terminal_unlocked(connection: sqlite3.Connection, now: datetime) -> int:
        delivered_cutoff = int(
            (now - timedelta(days=INTEGRATION_EVENT_DELIVERED_RETENTION_DAYS)).timestamp() * 1_000_000
        )
        dead_cutoff = int(
            (now - timedelta(days=INTEGRATION_EVENT_DEAD_RETENTION_DAYS)).timestamp() * 1_000_000
        )
        result = connection.execute(
            """
            DELETE FROM integration_events
            WHERE (state = 'delivered' AND delivered_at < ?)
               OR (state = 'dead' AND created_at < ?)
            """,
            (delivered_cutoff, dead_cutoff),
        )
        return result.rowcount

    @staticmethod
    def _dead_selection_unlocked(
        connection: sqlite3.Connection, organization_id: str
    ) -> tuple[list[sqlite3.Row], int]:
        if re.fullmatch(r"^(?:local-admin|[a-f0-9]{32})$", organization_id) is None:
            raise IntegrationEventError("invalid_organization")
        total = int(
            connection.execute(
                "SELECT COUNT(*) FROM integration_events WHERE organization_id = ? AND state = 'dead'",
                (organization_id,),
            ).fetchone()[0]
        )
        rows = connection.execute(
            """
            SELECT event_id, payload_json FROM integration_events
            WHERE organization_id = ? AND state = 'dead'
            ORDER BY created_at, event_id LIMIT ?
            """,
            (organization_id, INTEGRATION_EVENT_REPLAY_MAX_EVENTS),
        ).fetchall()
        return rows, total

    @staticmethod
    def _replay_digest(organization_id: str, rows: list[sqlite3.Row]) -> str:
        digest = hashlib.sha256()
        digest.update(b"inspectra-integration-replay-v1\0")
        digest.update(organization_id.encode("ascii"))
        for row in rows:
            digest.update(b"\0")
            digest.update(row["event_id"].encode("ascii"))
            digest.update(b"\0")
            digest.update(hashlib.sha256(row["payload_json"].encode("utf-8")).digest())
        return digest.hexdigest()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _payload_json(payload: IntegrationEventPayload) -> str:
        encoded = json.dumps(payload.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > INTEGRATION_EVENT_MAX_BODY_BYTES:
            raise IntegrationEventError("payload_too_large")
        return encoded

    @staticmethod
    def _aware(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise IntegrationEventError("invalid_time")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _micros(value: datetime) -> int:
        return int(value.timestamp() * 1_000_000)

    @staticmethod
    def _datetime(value: int) -> datetime:
        return datetime.fromtimestamp(value / 1_000_000, tz=timezone.utc)


class IntegrationEventTransport:
    def __init__(
        self,
        config: IntegrationEventConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver: Callable[[str], Awaitable[list[str]]] | None = None,
    ) -> None:
        self.config = config
        self.transport = transport
        self.resolver = resolver or _resolve_public_addresses

    async def deliver(self, record: IntegrationEventRecord) -> tuple[bool, bool]:
        if self.transport is None:
            try:
                addresses = await self.resolver(self.config.host)
            except (OSError, asyncio.TimeoutError):
                return False, True
            if not addresses or any(not _is_public_address(value) for value in addresses):
                raise IntegrationEventError("destination_resolution_denied")
        body = IntegrationEventStore._payload_json(record.payload).encode("utf-8")
        timestamp = str(int(datetime.now(timezone.utc).timestamp()))
        signature = hmac.new(
            self.config.signing_key,
            timestamp.encode("ascii") + b"." + body,
            hashlib.sha256,
        ).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Inspectra-Integration-Events/1",
            "X-Inspectra-Event-ID": record.payload.event_id,
            "X-Inspectra-Key-ID": self.config.signing_key_id,
            "X-Inspectra-Timestamp": timestamp,
            "X-Inspectra-Signature": f"{INTEGRATION_EVENT_SIGNATURE_VERSION}={signature}",
        }
        try:
            async with httpx.AsyncClient(
                transport=self.transport,
                timeout=self.config.timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream("POST", self.config.endpoint, content=body, headers=headers) as response:
                    received = 0
                    async for chunk in response.aiter_bytes():
                        received += len(chunk)
                        if received > INTEGRATION_EVENT_MAX_RESPONSE_BYTES:
                            return False, False
                    if 200 <= response.status_code < 300:
                        return True, False
                    return False, response.status_code == 429 or 500 <= response.status_code < 600
        except (httpx.TimeoutException, httpx.NetworkError):
            return False, True
        except httpx.HTTPError:
            return False, False


class IntegrationEventDispatcher:
    def __init__(self, store: IntegrationEventStore, transport: IntegrationEventTransport, *, concurrency: int) -> None:
        self.store = store
        self.transport = transport
        self.concurrency = concurrency

    async def drain_once(self) -> int:
        records: list[IntegrationEventRecord] = []
        for _ in range(self.concurrency):
            claimed = self.store.claim_due()
            if claimed is None:
                break
            records.append(claimed)
        if not records:
            return 0

        async def deliver(record: IntegrationEventRecord) -> None:
            try:
                accepted, retryable = await self.transport.deliver(record)
            except IntegrationEventError:
                accepted, retryable = False, False
            except Exception:
                accepted, retryable = False, True
            self.store.record_result(record.payload.event_id, accepted=accepted, retryable=retryable)

        await asyncio.gather(*(deliver(record) for record in records))
        return len(records)


async def _resolve_public_addresses(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    results = await loop.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return sorted({item[4][0] for item in results})


def _is_public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global
