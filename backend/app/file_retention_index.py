"""Private, rebuildable projection for bounded source-retention selection."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Callable
from uuid import uuid4

from app.config import MAX_AUDIT_MAX_INFLIGHT_JOBS, Settings
from app.models import StoredFile


FILE_RETENTION_INDEX_SCHEMA_VERSION = 1
FILE_RETENTION_INDEX_MAX_BYTES = 64 * 1024 * 1024
FILE_RETENTION_BATCH_SIZE = 100
FILE_RETENTION_MAX_PROTECTED_IDS = MAX_AUDIT_MAX_INFLIGHT_JOBS
_ID = re.compile(r"^[a-f0-9]{32}$")
_OWNER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class FileRetentionIndexError(RuntimeError):
    pass


class FileRetentionIndex:
    """Select metadata candidates while JSON and payload remain authoritative."""

    def __init__(self, settings: Settings, loader: Callable[[Path], StoredFile]) -> None:
        self.source = settings.upload_dir
        self.path = settings.data_dir / "results" / "file_retention_index.sqlite3"
        self.loader = loader
        self._file_state: tuple[int, int, int, int, int] | None = None
        self._source_state: tuple[int, int, int, int, int] | None = None

    def expired_records(
        self,
        *,
        cutoff: datetime,
        protected_file_ids: set[str],
        owner_id: str | None = None,
        limit: int = FILE_RETENTION_BATCH_SIZE,
    ) -> list[StoredFile]:
        if (
            cutoff.tzinfo is None
            or cutoff.utcoffset() is None
            or len(protected_file_ids) > FILE_RETENTION_MAX_PROTECTED_IDS
            or any(not _ID.fullmatch(file_id) for file_id in protected_file_ids)
            or (owner_id is not None and not _OWNER.fullmatch(owner_id))
            or not 1 <= limit <= FILE_RETENTION_BATCH_SIZE
        ):
            raise FileRetentionIndexError("file_retention_index_invalid")
        self._ensure_current()
        clauses = ["created_at_micros <= ?"]
        parameters: list[object] = [_micros(cutoff)]
        if owner_id is not None:
            clauses.append("owner_id = ?")
            parameters.append(owner_id)
        if protected_file_ids:
            placeholders = ",".join("?" for _file_id in protected_file_ids)
            clauses.append(f"file_id NOT IN ({placeholders})")
            parameters.extend(sorted(protected_file_ids))
        connection = self._connect(query_only=True)
        try:
            rows = connection.execute(
                f"""
                SELECT file_id, owner_id, created_at_micros, stored_filename,
                       record_digest
                FROM file_retention_index
                WHERE {' AND '.join(clauses)}
                ORDER BY created_at_micros, file_id
                LIMIT ?
                """,
                (*parameters, limit),
            ).fetchall()
        except sqlite3.Error as exc:
            raise FileRetentionIndexError("file_retention_index_invalid") from exc
        finally:
            connection.close()
        records: list[StoredFile] = []
        for row in rows:
            try:
                record = self.loader(self.source / f"{row['file_id']}.json")
            except Exception as exc:
                raise FileRetentionIndexError("file_retention_index_invalid") from exc
            if (
                record.owner_id != row["owner_id"]
                or (owner_id is not None and record.owner_id != owner_id)
                or record.id in protected_file_ids
                or _micros(record.created_at) != int(row["created_at_micros"])
                or record.created_at > cutoff
                or record.stored_filename != row["stored_filename"]
                or file_retention_record_digest(record) != row["record_digest"]
            ):
                raise FileRetentionIndexError("file_retention_index_invalid")
            records.append(record)
        return records

    def sync_after_save(self, record: StoredFile) -> None:
        if self._file_state is None:
            return
        try:
            source_state = _optional_directory_state(self.source)
            connection = self._connect()
            try:
                self._replace_record(connection, record)
                self._replace_source_state(connection, source_state)
                connection.commit()
            finally:
                connection.close()
            self._file_state = _file_state(self.path)
            self._source_state = source_state
        except (OSError, sqlite3.Error, FileRetentionIndexError):
            self._rebuild()

    def sync_after_delete(self, file_id: str) -> None:
        if self._file_state is None:
            return
        try:
            source_state = _optional_directory_state(self.source)
            connection = self._connect()
            try:
                connection.execute(
                    "DELETE FROM file_retention_index WHERE file_id = ?", (file_id,)
                )
                self._replace_source_state(connection, source_state)
                connection.commit()
            finally:
                connection.close()
            self._file_state = _file_state(self.path)
            self._source_state = source_state
        except (OSError, sqlite3.Error, FileRetentionIndexError):
            self._rebuild()

    def _ensure_current(self) -> None:
        if self._file_state is None and self.path.exists():
            try:
                self._adopt_existing()
                return
            except (OSError, sqlite3.Error, FileRetentionIndexError):
                self._rebuild()
                return
        if self._file_state is None or not self.path.exists():
            self._rebuild()
            return
        if (
            _file_state(self.path) != self._file_state
            or _optional_directory_state(self.source) != self._source_state
        ):
            self._rebuild()

    def _rebuild(self) -> None:
        records: list[StoredFile] = []
        if self.source.exists():
            if self.source.is_symlink() or not self.source.is_dir():
                raise FileRetentionIndexError("file_retention_index_invalid")
            try:
                for path in sorted(self.source.glob("*.json"), key=lambda item: item.name):
                    if _ID.fullmatch(path.stem):
                        records.append(self.loader(path))
            except Exception as exc:
                raise FileRetentionIndexError("file_retention_index_invalid") from exc
        source_state = _optional_directory_state(self.source)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{uuid4().hex}.tmp")
        if self.path.exists() or self.path.is_symlink():
            _validate_file(self.path)
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
                CREATE TABLE file_retention_index_metadata (
                    key TEXT PRIMARY KEY, value TEXT NOT NULL
                );
                CREATE TABLE file_retention_index (
                    file_id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    created_at_micros INTEGER NOT NULL,
                    stored_filename TEXT NOT NULL,
                    record_digest TEXT NOT NULL
                );
                CREATE INDEX file_retention_created
                    ON file_retention_index (created_at_micros, file_id);
                CREATE INDEX file_retention_owner_created
                    ON file_retention_index (owner_id, created_at_micros, file_id);
                """
            )
            for record in records:
                self._replace_record(connection, record)
            connection.execute(
                "INSERT INTO file_retention_index_metadata (key, value) VALUES ('schema_version', ?)",
                (str(FILE_RETENTION_INDEX_SCHEMA_VERSION),),
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
            raise FileRetentionIndexError("file_retention_index_invalid") from exc
        _validate_file(self.path)
        self._file_state = _file_state(self.path)
        self._source_state = source_state

    def _adopt_existing(self) -> None:
        source_state = _optional_directory_state(self.source)
        connection = self._connect(query_only=True)
        try:
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            stored = connection.execute(
                "SELECT value FROM file_retention_index_metadata WHERE key = 'source_state'"
            ).fetchone()
            if (
                integrity is None
                or integrity[0] != "ok"
                or stored is None
                or stored[0] != _directory_state_token(source_state)
            ):
                raise FileRetentionIndexError("file_retention_index_invalid")
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
            if query_only:
                connection.execute("PRAGMA query_only = ON")
            version = connection.execute(
                "SELECT value FROM file_retention_index_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if version is None or version[0] != str(FILE_RETENTION_INDEX_SCHEMA_VERSION):
                connection.close()
                raise FileRetentionIndexError("file_retention_index_invalid")
            return connection
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise FileRetentionIndexError("file_retention_index_invalid") from exc

    @staticmethod
    def _replace_record(connection: sqlite3.Connection, record: StoredFile) -> None:
        if record.owner_id is None or not _OWNER.fullmatch(record.owner_id):
            raise FileRetentionIndexError("file_retention_index_invalid")
        connection.execute(
            """
            INSERT INTO file_retention_index (
                file_id, owner_id, created_at_micros, stored_filename, record_digest
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(file_id) DO UPDATE SET
                owner_id = excluded.owner_id,
                created_at_micros = excluded.created_at_micros,
                stored_filename = excluded.stored_filename,
                record_digest = excluded.record_digest
            """,
            (
                record.id,
                record.owner_id,
                _micros(record.created_at),
                record.stored_filename,
                file_retention_record_digest(record),
            ),
        )

    @staticmethod
    def _replace_source_state(
        connection: sqlite3.Connection,
        state: tuple[int, int, int, int, int] | None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO file_retention_index_metadata (key, value)
            VALUES ('source_state', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (_directory_state_token(state),),
        )


def file_retention_record_digest(record: StoredFile) -> str:
    return hashlib.sha256(
        json.dumps(
            record.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()


def _micros(value: datetime) -> int:
    normalized = value.astimezone(timezone.utc)
    return int(normalized.timestamp()) * 1_000_000 + normalized.microsecond


def _validate_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise FileRetentionIndexError("file_retention_index_invalid") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > FILE_RETENTION_INDEX_MAX_BYTES
        or metadata.st_mode & 0o077
    ):
        raise FileRetentionIndexError("file_retention_index_invalid")


def _file_state(path: Path) -> tuple[int, int, int, int, int]:
    metadata = path.lstat()
    return metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns


def _optional_directory_state(path: Path) -> tuple[int, int, int, int, int] | None:
    if not path.exists() and not path.is_symlink():
        return None
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise FileRetentionIndexError("file_retention_index_invalid")
    return metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns


def _directory_state_token(state: tuple[int, int, int, int, int] | None) -> str:
    return "missing" if state is None else ":".join(str(value) for value in state)
