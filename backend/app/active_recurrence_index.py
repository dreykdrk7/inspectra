"""Private, rebuildable projection for bounded Active recurrence lookups."""

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


ACTIVE_RECURRENCE_INDEX_SCHEMA_VERSION = 1
ACTIVE_RECURRENCE_INDEX_MAX_BYTES = 64 * 1024 * 1024
ACTIVE_RECURRENCE_INDEX_QUERY_BATCH_SIZE = 100
ACTIVE_RECURRENCE_INDEX_MAX_ASSETS = 500
_OWNER = re.compile(r"^(?:local-admin|[a-f0-9]{32})$")
_ID = re.compile(r"^[a-f0-9]{32}$")


class ActiveRecurrenceIndexError(RuntimeError):
    pass


class ActiveRecurrenceIndex:
    """Index closed scheduling fields while recurrence JSON remains authoritative."""

    def __init__(self, settings: Settings, loader: Callable[[Path], Any]) -> None:
        self.source = settings.data_dir / "results" / "active_recurrences"
        self.path = settings.data_dir / "results" / "active_recurrence_index.sqlite3"
        self.loader = loader
        self._file_state: tuple[int, int, int, int, int] | None = None
        self._source_state: tuple[tuple[str, int, int, int, int, int], ...] | None = None

    def due_records(
        self,
        *,
        now: datetime,
        limit: int,
        is_eligible: Callable[[Any, datetime], bool],
    ) -> list[Any]:
        if now.tzinfo is None or now.utcoffset() is None or not 1 <= limit <= 16:
            raise ActiveRecurrenceIndexError("active_recurrence_index_invalid")
        self._ensure_current()
        observed_micros = _micros(now)
        cursor: tuple[int, str] | None = None
        records: list[Any] = []
        while len(records) < limit:
            clauses = [
                "status = 'active'",
                "next_run_at_micros <= ?",
                "(next_retry_at_micros IS NULL OR next_retry_at_micros <= ?)",
            ]
            parameters: list[object] = [observed_micros, observed_micros]
            if cursor is not None:
                clauses.append(
                    "(next_run_at_micros > ? OR (next_run_at_micros = ? AND schedule_id > ?))"
                )
                parameters.extend((cursor[0], cursor[0], cursor[1]))
            connection = self._connect(query_only=True)
            try:
                rows = connection.execute(
                    f"""
                    SELECT schedule_id, organization_id, asset_id, status,
                           next_run_at_micros, next_retry_at_micros, record_digest
                    FROM active_recurrence_index
                    WHERE {' AND '.join(clauses)}
                    ORDER BY next_run_at_micros, schedule_id
                    LIMIT ?
                    """,
                    (*parameters, ACTIVE_RECURRENCE_INDEX_QUERY_BATCH_SIZE),
                ).fetchall()
            except sqlite3.Error as exc:
                raise ActiveRecurrenceIndexError("active_recurrence_index_invalid") from exc
            finally:
                connection.close()
            if not rows:
                break
            for row in rows:
                record = self._load_validated(row)
                if is_eligible(record, now):
                    records.append(record)
                    if len(records) == limit:
                        break
            last = rows[-1]
            cursor = (int(last["next_run_at_micros"]), str(last["schedule_id"]))
            if len(rows) < ACTIVE_RECURRENCE_INDEX_QUERY_BATCH_SIZE:
                break
        return records

    def records_for_asset(self, *, organization_id: str, asset_id: str) -> list[Any]:
        self._validate_scope(organization_id, asset_id)
        self._ensure_current()
        connection = self._connect(query_only=True)
        try:
            rows = connection.execute(
                """
                SELECT schedule_id, organization_id, asset_id, status,
                       next_run_at_micros, next_retry_at_micros, record_digest
                FROM active_recurrence_index
                WHERE organization_id = ? AND asset_id = ?
                ORDER BY schedule_id
                """,
                (organization_id, asset_id),
            ).fetchall()
        except sqlite3.Error as exc:
            raise ActiveRecurrenceIndexError("active_recurrence_index_invalid") from exc
        finally:
            connection.close()
        return [self._load_validated(row) for row in rows]

    def records_for_assets(
        self, *, organization_id: str, asset_ids: set[str]
    ) -> list[Any]:
        if (
            not _OWNER.fullmatch(organization_id)
            or not 0 <= len(asset_ids) <= ACTIVE_RECURRENCE_INDEX_MAX_ASSETS
            or any(not _ID.fullmatch(asset_id) for asset_id in asset_ids)
        ):
            raise ActiveRecurrenceIndexError("active_recurrence_index_invalid")
        if not asset_ids:
            return []
        self._ensure_current()
        placeholders = ",".join("?" for _asset_id in asset_ids)
        connection = self._connect(query_only=True)
        try:
            rows = connection.execute(
                f"""
                SELECT schedule_id, organization_id, asset_id, status,
                       next_run_at_micros, next_retry_at_micros, record_digest
                FROM active_recurrence_index
                WHERE organization_id = ? AND asset_id IN ({placeholders})
                ORDER BY asset_id, schedule_id
                """,
                (organization_id, *sorted(asset_ids)),
            ).fetchall()
        except sqlite3.Error as exc:
            raise ActiveRecurrenceIndexError("active_recurrence_index_invalid") from exc
        finally:
            connection.close()
        return [self._load_validated(row) for row in rows]

    def count_for_asset(self, *, organization_id: str, asset_id: str) -> int:
        self._validate_scope(organization_id, asset_id)
        self._ensure_current()
        connection = self._connect(query_only=True)
        try:
            row = connection.execute(
                "SELECT COUNT(*) FROM active_recurrence_index WHERE organization_id = ? AND asset_id = ?",
                (organization_id, asset_id),
            ).fetchone()
        except sqlite3.Error as exc:
            raise ActiveRecurrenceIndexError("active_recurrence_index_invalid") from exc
        finally:
            connection.close()
        return int(row[0]) if row is not None else 0

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
            self._file_state = _file_state(self.path)
            self._source_state = source_state
        except (ActiveRecurrenceIndexError, OSError, sqlite3.Error):
            self._rebuild()

    def sync_after_delete(self, *, organization_id: str, schedule_id: str) -> None:
        if self._file_state is None:
            return
        self._sync_delete(
            "DELETE FROM active_recurrence_index WHERE organization_id = ? AND schedule_id = ?",
            (organization_id, schedule_id),
        )

    def sync_after_asset_delete(self, *, organization_id: str, asset_id: str) -> None:
        if self._file_state is None:
            return
        self._sync_delete(
            "DELETE FROM active_recurrence_index WHERE organization_id = ? AND asset_id = ?",
            (organization_id, asset_id),
        )

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
        except (ActiveRecurrenceIndexError, OSError, sqlite3.Error):
            return False

    def _sync_delete(self, statement: str, parameters: tuple[str, str]) -> None:
        try:
            source_state = _source_state(self.source)
            connection = self._connect()
            try:
                connection.execute(statement, parameters)
                self._replace_source_state(connection, source_state)
                connection.commit()
            finally:
                connection.close()
            self._file_state = _file_state(self.path)
            self._source_state = source_state
        except (ActiveRecurrenceIndexError, OSError, sqlite3.Error):
            self._rebuild()

    def _load_validated(self, row: sqlite3.Row) -> Any:
        try:
            record = self.loader(
                self.source / str(row["organization_id"]) / f"{row['schedule_id']}.json"
            )
        except Exception as exc:
            raise ActiveRecurrenceIndexError("active_recurrence_index_invalid") from exc
        if (
            record.id != row["schedule_id"]
            or record.organization_id != row["organization_id"]
            or record.asset_id != row["asset_id"]
            or record.status != row["status"]
            or _micros(record.next_run_at) != int(row["next_run_at_micros"])
            or _optional_micros(record.next_retry_at) != row["next_retry_at_micros"]
            or active_recurrence_record_digest(record) != row["record_digest"]
        ):
            raise ActiveRecurrenceIndexError("active_recurrence_index_invalid")
        return record

    def _ensure_current(self) -> None:
        if self._file_state is None and self.path.exists():
            try:
                self._adopt_existing()
                return
            except (ActiveRecurrenceIndexError, OSError, sqlite3.Error):
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
                    if not _OWNER.fullmatch(organization_dir.name) or not organization_dir.is_dir():
                        raise ActiveRecurrenceIndexError("active_recurrence_index_invalid")
                    for source_path in sorted(organization_dir.glob("*.json"), key=lambda item: item.name):
                        if _ID.fullmatch(source_path.stem):
                            records.append(self.loader(source_path))
            except ActiveRecurrenceIndexError:
                raise
            except Exception as exc:
                raise ActiveRecurrenceIndexError("active_recurrence_index_invalid") from exc
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
                CREATE TABLE active_recurrence_index_metadata (
                    key TEXT PRIMARY KEY, value TEXT NOT NULL
                );
                CREATE TABLE active_recurrence_index (
                    schedule_id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    next_run_at_micros INTEGER NOT NULL,
                    next_retry_at_micros INTEGER,
                    record_digest TEXT NOT NULL
                );
                CREATE INDEX active_recurrence_due
                    ON active_recurrence_index (
                        status, next_run_at_micros, next_retry_at_micros, schedule_id
                    );
                CREATE INDEX active_recurrence_owner_asset
                    ON active_recurrence_index (organization_id, asset_id, schedule_id);
                """
            )
            for record in records:
                self._replace_record(connection, record)
            connection.execute(
                "INSERT INTO active_recurrence_index_metadata (key, value) VALUES ('schema_version', ?)",
                (str(ACTIVE_RECURRENCE_INDEX_SCHEMA_VERSION),),
            )
            self._replace_source_state(connection, source_state)
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
            raise ActiveRecurrenceIndexError("active_recurrence_index_invalid") from exc
        _validate_file(self.path)
        self._file_state = _file_state(self.path)
        self._source_state = source_state

    def _adopt_existing(self) -> None:
        source_state = _source_state(self.source)
        connection = self._connect(query_only=True)
        try:
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            stored = connection.execute(
                "SELECT value FROM active_recurrence_index_metadata WHERE key = 'source_state'"
            ).fetchone()
            if integrity is None or integrity[0] != "ok" or stored is None or stored[0] != _source_state_token(source_state):
                raise ActiveRecurrenceIndexError("active_recurrence_index_invalid")
        finally:
            connection.close()
        self._file_state = _file_state(self.path)
        self._source_state = source_state

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
                "SELECT value FROM active_recurrence_index_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if version is None or version[0] != str(ACTIVE_RECURRENCE_INDEX_SCHEMA_VERSION):
                connection.close()
                raise ActiveRecurrenceIndexError("active_recurrence_index_invalid")
            return connection
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise ActiveRecurrenceIndexError("active_recurrence_index_invalid") from exc

    @staticmethod
    def _replace_record(connection: sqlite3.Connection, record: Any) -> None:
        if (
            not _ID.fullmatch(record.id)
            or not _ID.fullmatch(record.asset_id)
            or not _OWNER.fullmatch(record.organization_id)
            or record.status not in {"active", "paused", "suspended"}
        ):
            raise ActiveRecurrenceIndexError("active_recurrence_index_invalid")
        connection.execute(
            """
            INSERT INTO active_recurrence_index (
                schedule_id, organization_id, asset_id, status,
                next_run_at_micros, next_retry_at_micros, record_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(schedule_id) DO UPDATE SET
                organization_id = excluded.organization_id,
                asset_id = excluded.asset_id,
                status = excluded.status,
                next_run_at_micros = excluded.next_run_at_micros,
                next_retry_at_micros = excluded.next_retry_at_micros,
                record_digest = excluded.record_digest
            """,
            (
                record.id,
                record.organization_id,
                record.asset_id,
                record.status,
                _micros(record.next_run_at),
                _optional_micros(record.next_retry_at),
                active_recurrence_record_digest(record),
            ),
        )

    @staticmethod
    def _replace_source_state(
        connection: sqlite3.Connection,
        source_state: tuple[tuple[str, int, int, int, int, int], ...],
    ) -> None:
        connection.execute(
            """
            INSERT INTO active_recurrence_index_metadata (key, value)
            VALUES ('source_state', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (_source_state_token(source_state),),
        )

    @staticmethod
    def _validate_scope(organization_id: str, asset_id: str) -> None:
        if not _OWNER.fullmatch(organization_id) or not _ID.fullmatch(asset_id):
            raise ActiveRecurrenceIndexError("active_recurrence_index_invalid")

    def _remove_stale_artifacts(self) -> None:
        exact = {f"{self.path.name}-{suffix}" for suffix in ("journal", "wal", "shm")}
        temporary = re.compile(
            rf"^\.{re.escape(self.path.name)}\.[a-f0-9]{{32}}\.tmp(?:-(?:journal|wal|shm))?$"
        )
        for candidate in self.path.parent.iterdir():
            if candidate.name not in exact and not temporary.fullmatch(candidate.name):
                continue
            metadata = candidate.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ActiveRecurrenceIndexError("active_recurrence_index_invalid")
            candidate.unlink()


def active_recurrence_record_digest(record: Any) -> str:
    return hashlib.sha256(
        json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _micros(value: datetime) -> int:
    normalized = value.astimezone(timezone.utc)
    return int(normalized.timestamp()) * 1_000_000 + normalized.microsecond


def _optional_micros(value: datetime | None) -> int | None:
    return None if value is None else _micros(value)


def _validate_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ActiveRecurrenceIndexError("active_recurrence_index_invalid") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > ACTIVE_RECURRENCE_INDEX_MAX_BYTES
        or metadata.st_mode & 0o077
    ):
        raise ActiveRecurrenceIndexError("active_recurrence_index_invalid")


def _file_state(path: Path) -> tuple[int, int, int, int, int]:
    metadata = path.lstat()
    return metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns


def _source_state(path: Path) -> tuple[tuple[str, int, int, int, int, int], ...]:
    if not path.exists() and not path.is_symlink():
        return ()
    root = path.lstat()
    if not stat.S_ISDIR(root.st_mode):
        raise ActiveRecurrenceIndexError("active_recurrence_index_invalid")
    states = [("", root.st_dev, root.st_ino, root.st_size, root.st_mtime_ns, root.st_ctime_ns)]
    for child in sorted(path.iterdir(), key=lambda item: item.name):
        metadata = child.lstat()
        if child.name == ".gitkeep" and stat.S_ISREG(metadata.st_mode):
            continue
        if not _OWNER.fullmatch(child.name) or not stat.S_ISDIR(metadata.st_mode):
            raise ActiveRecurrenceIndexError("active_recurrence_index_invalid")
        states.append((child.name, metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns))
    return tuple(states)


def _source_state_token(state: tuple[tuple[str, int, int, int, int, int], ...]) -> str:
    return json.dumps(state, separators=(",", ":"))
