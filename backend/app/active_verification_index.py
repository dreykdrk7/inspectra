"""Private, rebuildable projection for bounded Active verification lookups."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any, Callable
from uuid import uuid4

from app.config import Settings


ACTIVE_VERIFICATION_INDEX_SCHEMA_VERSION = 3
ACTIVE_VERIFICATION_INDEX_MAX_BYTES = 256 * 1024 * 1024
ACTIVE_VERIFICATION_INDEX_MAX_ASSETS = 500
_OWNER = re.compile(r"^(?:local-admin|[a-f0-9]{32})$")
_ID = re.compile(r"^[a-f0-9]{32}$")


class ActiveVerificationIndexError(RuntimeError):
    pass


class ActiveVerificationIndex:
    """Index redacted verification metadata while JSON remains authoritative."""

    def __init__(self, settings: Settings, loader: Callable[[Path], Any]) -> None:
        self.source = settings.data_dir / "results" / "active_asset_verifications"
        self.path = settings.data_dir / "results" / "active_verification_index.sqlite3"
        self.loader = loader
        self._file_state: tuple[int, int, int, int, int] | None = None
        self._source_state: tuple[tuple[str, int, int, int, int, int], ...] | None = None

    def latest(
        self, *, organization_id: str, asset_ids: set[str]
    ) -> dict[str, Any]:
        if (
            not _OWNER.fullmatch(organization_id)
            or not 0 <= len(asset_ids) <= ACTIVE_VERIFICATION_INDEX_MAX_ASSETS
            or any(not _ID.fullmatch(asset_id) for asset_id in asset_ids)
        ):
            raise ActiveVerificationIndexError("active_verification_index_invalid")
        if not asset_ids:
            return {}
        self._ensure_current()
        placeholders = ",".join("?" for _asset_id in asset_ids)
        connection = self._connect(query_only=True)
        try:
            rows = connection.execute(
                f"""
                SELECT verification_id, asset_id, record_digest
                FROM (
                    SELECT verification_id, asset_id, record_digest,
                           ROW_NUMBER() OVER (
                               PARTITION BY asset_id
                               ORDER BY created_at_micros DESC, verification_id DESC
                           ) AS position
                    FROM active_verification_index
                    WHERE organization_id = ? AND asset_id IN ({placeholders})
                )
                WHERE position = 1
                ORDER BY asset_id
                """,
                (organization_id, *sorted(asset_ids)),
            ).fetchall()
        except sqlite3.Error as exc:
            raise ActiveVerificationIndexError("active_verification_index_invalid") from exc
        finally:
            connection.close()
        records: dict[str, Any] = {}
        for row in rows:
            try:
                record = self.loader(
                    self.source / organization_id / f"{row['verification_id']}.json"
                )
            except Exception as exc:
                raise ActiveVerificationIndexError("active_verification_index_invalid") from exc
            if (
                record.organization_id != organization_id
                or record.asset_id != row["asset_id"]
                or record.asset_id not in asset_ids
                or active_verification_record_digest(record) != row["record_digest"]
            ):
                raise ActiveVerificationIndexError("active_verification_index_invalid")
            records[record.asset_id] = record
        return records

    def records_for_asset(self, *, organization_id: str, asset_id: str) -> list[Any]:
        """Load the complete validated verification history for one asset."""

        if not _OWNER.fullmatch(organization_id) or not _ID.fullmatch(asset_id):
            raise ActiveVerificationIndexError("active_verification_index_invalid")
        self._ensure_current()
        connection = self._connect(query_only=True)
        try:
            rows = connection.execute(
                """
                SELECT verification_id, record_digest
                FROM active_verification_index
                WHERE organization_id = ? AND asset_id = ?
                ORDER BY created_at_micros, verification_id
                """,
                (organization_id, asset_id),
            ).fetchall()
        except sqlite3.Error as exc:
            raise ActiveVerificationIndexError("active_verification_index_invalid") from exc
        finally:
            connection.close()
        records: list[Any] = []
        for row in rows:
            try:
                record = self.loader(
                    self.source / organization_id / f"{row['verification_id']}.json"
                )
            except Exception as exc:
                raise ActiveVerificationIndexError("active_verification_index_invalid") from exc
            if (
                record.organization_id != organization_id
                or record.asset_id != asset_id
                or active_verification_record_digest(record) != row["record_digest"]
            ):
                raise ActiveVerificationIndexError("active_verification_index_invalid")
            records.append(record)
        return records

    def sync_after_write(self, record: Any) -> None:
        if self._file_state is None:
            return
        try:
            source_state = _source_state(self.source)
            connection = self._connect()
            try:
                self._replace_record(connection, record)
                self._replace_source_state(connection, source_state)
                connection.commit()
            finally:
                connection.close()
            _validate_file(self.path)
            self._file_state = _file_state(self.path)
            self._source_state = source_state
        except (ActiveVerificationIndexError, OSError, sqlite3.Error):
            self._rebuild()

    def attention_asset_ids(
        self, *, organization_id: str, now: datetime, limit: int = ACTIVE_VERIFICATION_INDEX_MAX_ASSETS
    ) -> set[str]:
        """Return assets whose latest verification requires operator attention."""

        if not _OWNER.fullmatch(organization_id) or not 1 <= limit <= ACTIVE_VERIFICATION_INDEX_MAX_ASSETS:
            raise ActiveVerificationIndexError("active_verification_index_invalid")
        self._ensure_current()
        now_micros = _micros(now)
        connection = self._connect(query_only=True)
        try:
            rows = connection.execute(
                """
                SELECT asset_id
                FROM (
                    SELECT asset_id, status, challenge_expires_at_micros,
                           verification_expires_at_micros, created_at_micros,
                           verification_id,
                           ROW_NUMBER() OVER (
                               PARTITION BY asset_id
                               ORDER BY created_at_micros DESC, verification_id DESC
                           ) AS position
                    FROM active_verification_index
                    WHERE organization_id = ?
                )
                WHERE position = 1 AND (
                    status IN ('failed', 'expired')
                    OR (status = 'pending' AND challenge_expires_at_micros <= ?)
                    OR (
                        status = 'verified'
                        AND verification_expires_at_micros IS NOT NULL
                        AND verification_expires_at_micros <= ?
                    )
                )
                ORDER BY created_at_micros DESC, verification_id DESC
                LIMIT ?
                """,
                (organization_id, now_micros, now_micros, limit),
            ).fetchall()
        except sqlite3.Error as exc:
            raise ActiveVerificationIndexError("active_verification_index_invalid") from exc
        finally:
            connection.close()
        return {str(row["asset_id"]) for row in rows}

    def sync_after_asset_delete(self, *, organization_id: str, asset_id: str) -> None:
        if self._file_state is None:
            return
        try:
            source_state = _source_state(self.source)
            connection = self._connect()
            try:
                connection.execute(
                    "DELETE FROM active_verification_index WHERE organization_id = ? AND asset_id = ?",
                    (organization_id, asset_id),
                )
                self._replace_source_state(connection, source_state)
                connection.commit()
            finally:
                connection.close()
            self._file_state = _file_state(self.path)
            self._source_state = source_state
        except (ActiveVerificationIndexError, OSError, sqlite3.Error):
            self._rebuild()

    def ready(self) -> bool:
        if self._file_state is None and not self.path.exists() and not self.path.is_symlink():
            return True
        try:
            self._ensure_current()
            connection = self._connect(query_only=True)
            try:
                result = connection.execute("PRAGMA quick_check").fetchone()
                return result is not None and result[0] == "ok"
            finally:
                connection.close()
        except (ActiveVerificationIndexError, OSError, sqlite3.Error):
            return False

    def _ensure_current(self) -> None:
        if self._file_state is None and self.path.exists():
            try:
                self._adopt_existing()
                return
            except (ActiveVerificationIndexError, OSError, sqlite3.Error):
                self._rebuild()
                return
        if self._file_state is None or not self.path.exists():
            self._rebuild()
            return
        if _file_state(self.path) != self._file_state or _source_state(self.source) != self._source_state:
            self._rebuild()

    def _rebuild(self) -> None:
        records: list[Any] = []
        source_state = _source_state(self.source)
        if source_state:
            try:
                for organization_dir in sorted(self.source.iterdir(), key=lambda item: item.name):
                    if organization_dir.name == ".gitkeep":
                        continue
                    if not _OWNER.fullmatch(organization_dir.name):
                        raise ActiveVerificationIndexError("active_verification_index_invalid")
                    metadata = organization_dir.lstat()
                    if not stat.S_ISDIR(metadata.st_mode):
                        raise ActiveVerificationIndexError("active_verification_index_invalid")
                    for source_path in sorted(organization_dir.glob("*.json"), key=lambda item: item.name):
                        if not _ID.fullmatch(source_path.stem):
                            continue
                        records.append(self.loader(source_path))
            except ActiveVerificationIndexError:
                raise
            except Exception as exc:
                raise ActiveVerificationIndexError("active_verification_index_invalid") from exc
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._remove_stale_artifacts()
        if self.path.exists() or self.path.is_symlink():
            _validate_file(self.path)
        temporary = self.path.with_name(f".{self.path.name}.{uuid4().hex}.tmp")
        connection: sqlite3.Connection | None = None
        try:
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            connection = sqlite3.connect(temporary, timeout=30)
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE active_verification_index_metadata (
                    key TEXT PRIMARY KEY, value TEXT NOT NULL
                );
                CREATE TABLE active_verification_index (
                    verification_id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at_micros INTEGER NOT NULL,
                    challenge_expires_at_micros INTEGER NOT NULL,
                    verification_expires_at_micros INTEGER,
                    record_digest TEXT NOT NULL
                );
                CREATE INDEX active_verification_index_owner_asset_created
                    ON active_verification_index (
                        organization_id, asset_id, created_at_micros DESC, verification_id DESC
                    );
                """
            )
            for record in records:
                self._replace_record(connection, record)
            connection.execute(
                "INSERT INTO active_verification_index_metadata (key, value) VALUES ('schema_version', ?)",
                (str(ACTIVE_VERIFICATION_INDEX_SCHEMA_VERSION),),
            )
            connection.execute(
                "INSERT INTO active_verification_index_metadata (key, value) VALUES ('source_state', ?)",
                (_source_state_token(source_state),),
            )
            connection.commit()
            connection.close()
            connection = None
            with temporary.open("rb") as handle:
                os.fsync(handle.fileno())
            temporary.replace(self.path)
            directory_descriptor = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                connection.close()
            temporary.unlink(missing_ok=True)
            raise ActiveVerificationIndexError("active_verification_index_invalid") from exc
        _validate_file(self.path)
        self._file_state = _file_state(self.path)
        self._source_state = source_state

    def _adopt_existing(self) -> None:
        source_state = _source_state(self.source)
        connection = self._connect(query_only=True)
        try:
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            stored_state = connection.execute(
                "SELECT value FROM active_verification_index_metadata WHERE key = 'source_state'"
            ).fetchone()
            if (
                integrity is None
                or integrity[0] != "ok"
                or stored_state is None
                or stored_state[0] != _source_state_token(source_state)
            ):
                raise ActiveVerificationIndexError("active_verification_index_invalid")
        finally:
            connection.close()
        self._file_state = _file_state(self.path)
        self._source_state = source_state

    @staticmethod
    def _replace_record(connection: sqlite3.Connection, record: Any) -> None:
        if (
            not _ID.fullmatch(record.id)
            or not _ID.fullmatch(record.asset_id)
            or not _OWNER.fullmatch(record.organization_id)
        ):
            raise ActiveVerificationIndexError("active_verification_index_invalid")
        connection.execute(
            """
            INSERT INTO active_verification_index (
                verification_id, organization_id, asset_id, status,
                created_at_micros, challenge_expires_at_micros,
                verification_expires_at_micros, record_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(verification_id) DO UPDATE SET
                organization_id = excluded.organization_id,
                asset_id = excluded.asset_id,
                status = excluded.status,
                created_at_micros = excluded.created_at_micros,
                challenge_expires_at_micros = excluded.challenge_expires_at_micros,
                verification_expires_at_micros = excluded.verification_expires_at_micros,
                record_digest = excluded.record_digest
            """,
            (
                record.id,
                record.organization_id,
                record.asset_id,
                record.status,
                _micros(record.created_at),
                _micros(record.challenge_expires_at),
                _micros(record.verification_expires_at)
                if record.verification_expires_at is not None
                else None,
                active_verification_record_digest(record),
            ),
        )

    @staticmethod
    def _replace_source_state(
        connection: sqlite3.Connection,
        source_state: tuple[tuple[str, int, int, int, int, int], ...],
    ) -> None:
        connection.execute(
            """
            INSERT INTO active_verification_index_metadata (key, value) VALUES ('source_state', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (_source_state_token(source_state),),
        )

    def _connect(self, *, query_only: bool = False) -> sqlite3.Connection:
        _validate_file(self.path)
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self.path, timeout=30)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA busy_timeout = 30000")
            if query_only:
                connection.execute("PRAGMA query_only = ON")
            version = connection.execute(
                "SELECT value FROM active_verification_index_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if version is None or version[0] != str(ACTIVE_VERIFICATION_INDEX_SCHEMA_VERSION):
                connection.close()
                raise ActiveVerificationIndexError("active_verification_index_invalid")
            return connection
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise ActiveVerificationIndexError("active_verification_index_invalid") from exc

    def _remove_stale_artifacts(self) -> None:
        exact = {f"{self.path.name}-{suffix}" for suffix in ("journal", "wal", "shm")}
        temporary = re.compile(
            rf"^\.{re.escape(self.path.name)}\.[a-f0-9]{{32}}\.tmp(?:-(?:journal|wal|shm))?$"
        )
        try:
            candidates = list(self.path.parent.iterdir())
        except OSError as exc:
            raise ActiveVerificationIndexError("active_verification_index_invalid") from exc
        for candidate in candidates:
            if candidate.name not in exact and not temporary.fullmatch(candidate.name):
                continue
            metadata = candidate.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ActiveVerificationIndexError("active_verification_index_invalid")
            candidate.unlink()


def active_verification_record_digest(record: Any) -> str:
    payload = json.dumps(
        record.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _micros(value: datetime) -> int:
    normalized = value.astimezone(timezone.utc)
    return int(normalized.timestamp()) * 1_000_000 + normalized.microsecond


def _validate_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ActiveVerificationIndexError("active_verification_index_invalid") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > ACTIVE_VERIFICATION_INDEX_MAX_BYTES
        or metadata.st_mode & 0o077
    ):
        raise ActiveVerificationIndexError("active_verification_index_invalid")


def _file_state(path: Path) -> tuple[int, int, int, int, int]:
    metadata = path.lstat()
    return metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns


def _source_state(path: Path) -> tuple[tuple[str, int, int, int, int, int], ...]:
    if not path.exists() and not path.is_symlink():
        return ()
    root = path.lstat()
    if not stat.S_ISDIR(root.st_mode):
        raise ActiveVerificationIndexError("active_verification_index_invalid")
    states = [("", root.st_dev, root.st_ino, root.st_size, root.st_mtime_ns, root.st_ctime_ns)]
    try:
        children = sorted(path.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise ActiveVerificationIndexError("active_verification_index_invalid") from exc
    for child in children:
        metadata = child.lstat()
        if child.name == ".gitkeep" and stat.S_ISREG(metadata.st_mode):
            continue
        if not _OWNER.fullmatch(child.name) or not stat.S_ISDIR(metadata.st_mode):
            raise ActiveVerificationIndexError("active_verification_index_invalid")
        states.append(
            (child.name, metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)
        )
    return tuple(states)


def _source_state_token(
    state: tuple[tuple[str, int, int, int, int, int], ...]
) -> str:
    return json.dumps(state, separators=(",", ":"))
