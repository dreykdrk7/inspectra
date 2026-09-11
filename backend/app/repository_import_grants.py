from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from pathlib import Path
import re
import secrets
import sqlite3


REPOSITORY_IMPORT_GRANT_PREFIX = "inspectra_ri_"
REPOSITORY_IMPORT_GRANT_MIN_LIFETIME_SECONDS = 300
REPOSITORY_IMPORT_GRANT_MAX_LIFETIME_SECONDS = 1800
REPOSITORY_IMPORT_GRANT_MAX_ACTIVE_PER_ORGANIZATION = 3
_GRANT_PATTERN = re.compile(r"^inspectra_ri_([a-f0-9]{32})_([A-Za-z0-9_-]{43})$")


class RepositoryImportGrantError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class RepositoryImportPrincipal:
    grant_id: str
    organization_id: str
    created_by: str
    expires_at: datetime


@dataclass(frozen=True)
class RepositoryImportGrantRecord:
    grant_id: str
    organization_id: str
    created_by: str
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None


class RepositoryImportGrantStore:
    """Hashed, short-lived and single-use authority for one initial Git snapshot.

    A grant carries no repository URL, path, project name or Git credential. It
    only transfers the issuing operator's organization boundary to the closed
    initial snapshot route. The plaintext is returned exactly once.
    """

    def __init__(self, db_path: str | Path, *, now_func=None, token_bytes_func=None) -> None:
        self.db_path = Path(db_path)
        self._now_func = now_func or (lambda: datetime.now(timezone.utc))
        self._token_bytes_func = token_bytes_func or (lambda: secrets.token_urlsafe(32))
        self._initialize_schema()

    def create(
        self,
        *,
        organization_id: str,
        created_by: str,
        lifetime_seconds: int,
    ) -> tuple[RepositoryImportGrantRecord, str]:
        if not organization_id or len(organization_id) > 128 or not created_by or len(created_by) > 128:
            raise RepositoryImportGrantError("invalid_identity")
        if not REPOSITORY_IMPORT_GRANT_MIN_LIFETIME_SECONDS <= lifetime_seconds <= REPOSITORY_IMPORT_GRANT_MAX_LIFETIME_SECONDS:
            raise RepositoryImportGrantError("invalid_lifetime")
        now = self._now()
        grant_id = secrets.token_hex(16)
        expires_at = now + timedelta(seconds=lifetime_seconds)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """DELETE FROM repository_import_grants
                       WHERE organization_id = ? AND (expires_at <= ? OR consumed_at IS NOT NULL)""",
                    (organization_id, now.timestamp()),
                )
                active = connection.execute(
                    """SELECT COUNT(*) FROM repository_import_grants
                       WHERE organization_id = ? AND consumed_at IS NULL AND expires_at > ?""",
                    (organization_id, now.timestamp()),
                ).fetchone()[0]
                if int(active) >= REPOSITORY_IMPORT_GRANT_MAX_ACTIVE_PER_ORGANIZATION:
                    raise RepositoryImportGrantError("active_limit")
                secret = self._token_bytes_func()
                if not re.fullmatch(r"[A-Za-z0-9_-]{43}", secret):
                    raise RepositoryImportGrantError("token_generation_failed")
                plaintext = f"{REPOSITORY_IMPORT_GRANT_PREFIX}{grant_id}_{secret}"
                connection.execute(
                    """INSERT INTO repository_import_grants (
                           id, token_hash, organization_id, created_by,
                           created_at, expires_at, consumed_at
                       ) VALUES (?, ?, ?, ?, ?, ?, NULL)""",
                    (
                        grant_id,
                        _grant_hash(plaintext),
                        organization_id,
                        created_by,
                        now.timestamp(),
                        expires_at.timestamp(),
                    ),
                )
        except RepositoryImportGrantError:
            raise
        except sqlite3.Error as exc:
            raise RepositoryImportGrantError("store_unavailable") from exc
        return self.get(organization_id, grant_id), plaintext

    def authenticate(self, plaintext: str) -> RepositoryImportPrincipal | None:
        match = _GRANT_PATTERN.fullmatch(plaintext)
        if match is None:
            return None
        grant_id = match.group(1)
        now = self._now()
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM repository_import_grants WHERE id = ?", (grant_id,)
                ).fetchone()
        except sqlite3.Error as exc:
            raise RepositoryImportGrantError("store_unavailable") from exc
        if (
            row is None
            or row["consumed_at"] is not None
            or float(row["expires_at"]) <= now.timestamp()
            or not hmac.compare_digest(str(row["token_hash"]), _grant_hash(plaintext))
        ):
            return None
        return RepositoryImportPrincipal(
            grant_id=grant_id,
            organization_id=str(row["organization_id"]),
            created_by=str(row["created_by"]),
            expires_at=_datetime(float(row["expires_at"])),
        )

    def consume(self, principal: RepositoryImportPrincipal) -> RepositoryImportGrantRecord:
        """Atomically spend a grant before retaining any uploaded source bytes."""

        now = self._now()
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    """UPDATE repository_import_grants SET consumed_at = ?
                       WHERE id = ? AND organization_id = ? AND created_by = ?
                       AND consumed_at IS NULL AND expires_at > ?""",
                    (
                        now.timestamp(),
                        principal.grant_id,
                        principal.organization_id,
                        principal.created_by,
                        now.timestamp(),
                    ),
                )
                if cursor.rowcount != 1:
                    raise RepositoryImportGrantError("invalid_or_consumed")
        except RepositoryImportGrantError:
            raise
        except sqlite3.Error as exc:
            raise RepositoryImportGrantError("store_unavailable") from exc
        return self.get(principal.organization_id, principal.grant_id)

    def get(self, organization_id: str, grant_id: str) -> RepositoryImportGrantRecord:
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM repository_import_grants WHERE organization_id = ? AND id = ?",
                    (organization_id, grant_id),
                ).fetchone()
        except sqlite3.Error as exc:
            raise RepositoryImportGrantError("store_unavailable") from exc
        if row is None:
            raise RepositoryImportGrantError("not_found")
        return _record(row)

    def _initialize_schema(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS repository_import_grants (
                        id TEXT PRIMARY KEY,
                        token_hash TEXT NOT NULL,
                        organization_id TEXT NOT NULL,
                        created_by TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        expires_at REAL NOT NULL,
                        consumed_at REAL
                    )
                    """
                )
                connection.execute(
                    """CREATE INDEX IF NOT EXISTS idx_repository_import_grants_organization
                       ON repository_import_grants(organization_id, created_at)"""
                )
        except sqlite3.Error as exc:
            raise RepositoryImportGrantError("store_unavailable") from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _now(self) -> datetime:
        value = self._now_func()
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _grant_hash(plaintext: str) -> str:
    return hashlib.sha256(b"inspectra-repository-import-grant-v1\0" + plaintext.encode("ascii")).hexdigest()


def _datetime(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def _record(row: sqlite3.Row) -> RepositoryImportGrantRecord:
    return RepositoryImportGrantRecord(
        grant_id=str(row["id"]),
        organization_id=str(row["organization_id"]),
        created_by=str(row["created_by"]),
        created_at=_datetime(float(row["created_at"])),
        expires_at=_datetime(float(row["expires_at"])),
        consumed_at=_datetime(float(row["consumed_at"])) if row["consumed_at"] is not None else None,
    )
