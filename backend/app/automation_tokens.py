from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from pathlib import Path
import re
import secrets
import sqlite3
from typing import Literal


AutomationScope = Literal["project:read", "project:scan", "report:read"]
AUTOMATION_SCOPES: frozenset[str] = frozenset({"project:read", "project:scan", "report:read"})
AUTOMATION_TOKEN_PREFIX = "inspectra_at_"
AUTOMATION_TOKEN_MAX_LIFETIME_SECONDS = 90 * 24 * 60 * 60
AUTOMATION_TOKEN_RATE_WINDOW_SECONDS = 60 * 60
AUTOMATION_TOKEN_MAX_REQUESTS_PER_WINDOW = 600
AUTOMATION_TOKEN_MAX_ACTIVE_PER_PROJECT = 2
AUTOMATION_TOKEN_LAST_USED_BUCKET_SECONDS = 60 * 60
_TOKEN_PATTERN = re.compile(r"^inspectra_at_([a-f0-9]{32})_([A-Za-z0-9_-]{43})$")


class AutomationTokenError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class AutomationPrincipal:
    token_id: str
    organization_id: str
    project_id: str
    scopes: tuple[str, ...]
    expires_at: datetime


@dataclass(frozen=True)
class AutomationTokenRecord:
    token_id: str
    name: str
    organization_id: str
    project_id: str
    scopes: tuple[str, ...]
    created_by: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    last_used_at: datetime | None


class AutomationTokenStore:
    """Hashed, project-bound credentials for non-interactive clients.

    The identifier is deliberately separate from the secret so authentication
    performs one bounded lookup. Only a domain-separated SHA-256 digest is
    persisted; the bearer value is returned by ``create`` exactly once.
    """

    def __init__(self, db_path: str | Path, *, now_func=None, token_bytes_func=None) -> None:
        self.db_path = Path(db_path)
        self._now_func = now_func or (lambda: datetime.now(timezone.utc))
        self._token_bytes_func = token_bytes_func or (lambda: secrets.token_urlsafe(32))
        self._initialize_schema()

    def create(
        self,
        *,
        name: str,
        organization_id: str,
        project_id: str,
        scopes: tuple[str, ...],
        created_by: str,
        lifetime_seconds: int,
    ) -> tuple[AutomationTokenRecord, str]:
        normalized_name = name.strip()
        if not (3 <= len(normalized_name) <= 80):
            raise AutomationTokenError("invalid_name")
        if not re.fullmatch(r"[a-f0-9]{32}|local-admin", project_id):
            raise AutomationTokenError("invalid_project")
        normalized_scopes = tuple(sorted(set(scopes)))
        if not normalized_scopes or any(scope not in AUTOMATION_SCOPES for scope in normalized_scopes):
            raise AutomationTokenError("invalid_scopes")
        if not 300 <= lifetime_seconds <= AUTOMATION_TOKEN_MAX_LIFETIME_SECONDS:
            raise AutomationTokenError("invalid_lifetime")

        now = self._now()
        token_id = secrets.token_hex(16)
        expires_at = now + timedelta(seconds=lifetime_seconds)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                active_count = connection.execute(
                    """SELECT COUNT(*) FROM automation_tokens
                       WHERE organization_id = ? AND project_id = ?
                       AND revoked_at IS NULL AND expires_at > ?""",
                    (organization_id, project_id, now.timestamp()),
                ).fetchone()[0]
                if int(active_count) >= AUTOMATION_TOKEN_MAX_ACTIVE_PER_PROJECT:
                    raise AutomationTokenError("active_limit")
                secret = self._token_bytes_func()
                if not re.fullmatch(r"[A-Za-z0-9_-]{43}", secret):
                    raise AutomationTokenError("token_generation_failed")
                plaintext = f"{AUTOMATION_TOKEN_PREFIX}{token_id}_{secret}"
                connection.execute(
                    """
                    INSERT INTO automation_tokens (
                        id, token_hash, name, organization_id, project_id, scopes,
                        created_by, created_at, expires_at, revoked_at, last_used_at,
                        rate_window_started_at, rate_window_requests
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, 0)
                    """,
                    (
                        token_id,
                        _token_hash(plaintext),
                        normalized_name,
                        organization_id,
                        project_id,
                        ",".join(normalized_scopes),
                        created_by,
                        now.timestamp(),
                        expires_at.timestamp(),
                        now.timestamp(),
                    ),
                )
        except AutomationTokenError:
            raise
        except sqlite3.Error as exc:
            raise AutomationTokenError("store_unavailable") from exc
        return self.get(organization_id, token_id), plaintext

    def authenticate(self, plaintext: str) -> AutomationPrincipal | None:
        match = _TOKEN_PATTERN.fullmatch(plaintext)
        if match is None:
            return None
        token_id = match.group(1)
        now = self._now()
        try:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT * FROM automation_tokens WHERE id = ?", (token_id,)).fetchone()
                if row is None or not hmac.compare_digest(str(row["token_hash"]), _token_hash(plaintext)):
                    connection.rollback()
                    return None
                if row["revoked_at"] is not None or float(row["expires_at"]) <= now.timestamp():
                    connection.rollback()
                    return None
                window_started = float(row["rate_window_started_at"])
                count = int(row["rate_window_requests"])
                if now.timestamp() - window_started >= AUTOMATION_TOKEN_RATE_WINDOW_SECONDS:
                    window_started = now.timestamp()
                    count = 0
                if count >= AUTOMATION_TOKEN_MAX_REQUESTS_PER_WINDOW:
                    connection.rollback()
                    raise AutomationTokenError("rate_limited")
                last_used_bucket = (
                    int(now.timestamp()) // AUTOMATION_TOKEN_LAST_USED_BUCKET_SECONDS
                ) * AUTOMATION_TOKEN_LAST_USED_BUCKET_SECONDS
                connection.execute(
                    """UPDATE automation_tokens
                       SET last_used_at = CASE
                             WHEN last_used_at IS NULL OR last_used_at < ? THEN ?
                             ELSE last_used_at
                           END,
                           rate_window_started_at = ?, rate_window_requests = ?
                       WHERE id = ?""",
                    (last_used_bucket, last_used_bucket, window_started, count + 1, token_id),
                )
                connection.commit()
            finally:
                connection.close()
        except AutomationTokenError:
            raise
        except sqlite3.Error as exc:
            raise AutomationTokenError("store_unavailable") from exc
        return AutomationPrincipal(
            token_id=token_id,
            organization_id=str(row["organization_id"]),
            project_id=str(row["project_id"]),
            scopes=tuple(filter(None, str(row["scopes"]).split(","))),
            expires_at=_datetime(float(row["expires_at"])),
        )

    def list(self, organization_id: str) -> list[AutomationTokenRecord]:
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT * FROM automation_tokens WHERE organization_id = ? ORDER BY created_at DESC, id DESC",
                    (organization_id,),
                ).fetchall()
        except sqlite3.Error as exc:
            raise AutomationTokenError("store_unavailable") from exc
        return [_record(row) for row in rows]

    def get(self, organization_id: str, token_id: str) -> AutomationTokenRecord:
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM automation_tokens WHERE organization_id = ? AND id = ?",
                    (organization_id, token_id),
                ).fetchone()
        except sqlite3.Error as exc:
            raise AutomationTokenError("store_unavailable") from exc
        if row is None:
            raise AutomationTokenError("not_found")
        return _record(row)

    def revoke(self, organization_id: str, token_id: str) -> AutomationTokenRecord:
        now = self._now()
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    """UPDATE automation_tokens SET revoked_at = COALESCE(revoked_at, ?)
                       WHERE organization_id = ? AND id = ?""",
                    (now.timestamp(), organization_id, token_id),
                )
                if cursor.rowcount != 1:
                    raise AutomationTokenError("not_found")
        except AutomationTokenError:
            raise
        except sqlite3.Error as exc:
            raise AutomationTokenError("store_unavailable") from exc
        return self.get(organization_id, token_id)

    def purge_inactive(self, organization_id: str, *, cutoff: datetime) -> int:
        """Remove only this organization's inactive metadata older than cutoff."""

        threshold = cutoff if cutoff.tzinfo is not None else cutoff.replace(tzinfo=timezone.utc)
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    """DELETE FROM automation_tokens
                       WHERE organization_id = ?
                       AND ((revoked_at IS NOT NULL AND revoked_at < ?)
                            OR (expires_at < ?))""",
                    (organization_id, threshold.timestamp(), threshold.timestamp()),
                )
        except sqlite3.Error as exc:
            raise AutomationTokenError("store_unavailable") from exc
        return max(0, cursor.rowcount)

    def _initialize_schema(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS automation_tokens (
                        id TEXT PRIMARY KEY,
                        token_hash TEXT NOT NULL,
                        name TEXT NOT NULL,
                        organization_id TEXT NOT NULL,
                        project_id TEXT NOT NULL,
                        scopes TEXT NOT NULL,
                        created_by TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        expires_at REAL NOT NULL,
                        revoked_at REAL,
                        last_used_at REAL,
                        rate_window_started_at REAL NOT NULL,
                        rate_window_requests INTEGER NOT NULL
                    )
                    """
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_automation_tokens_organization ON automation_tokens(organization_id, created_at)"
                )
        except sqlite3.Error as exc:
            raise AutomationTokenError("store_unavailable") from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _now(self) -> datetime:
        value = self._now_func()
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _token_hash(plaintext: str) -> str:
    return hashlib.sha256(b"inspectra-automation-token-v1\0" + plaintext.encode("ascii")).hexdigest()


def _datetime(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def _record(row: sqlite3.Row) -> AutomationTokenRecord:
    return AutomationTokenRecord(
        token_id=str(row["id"]),
        name=str(row["name"]),
        organization_id=str(row["organization_id"]),
        project_id=str(row["project_id"]),
        scopes=tuple(filter(None, str(row["scopes"]).split(","))),
        created_by=str(row["created_by"]),
        created_at=_datetime(float(row["created_at"])),
        expires_at=_datetime(float(row["expires_at"])),
        revoked_at=_datetime(float(row["revoked_at"])) if row["revoked_at"] is not None else None,
        last_used_at=_datetime(float(row["last_used_at"])) if row["last_used_at"] is not None else None,
    )
