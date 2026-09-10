"""Private, rebuildable projection for project baseline and source relations."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
from typing import Callable, Literal
from uuid import uuid4

from app.config import Settings
from app.models import ProjectRecord, current_project_responsibility


PROJECT_REFERENCE_INDEX_SCHEMA_VERSION = 3
PROJECT_REFERENCE_INDEX_MAX_BYTES = 64 * 1024 * 1024
PROJECT_REFERENCE_QUERY_MAX_REFERENCES = 500
PROJECT_REFERENCE_QUERY_BATCH_SIZE = 100
PROJECT_LIST_DEFAULT_PAGE_SIZE = 50
PROJECT_LIST_MAX_PAGE_SIZE = 100
PROJECT_LIST_MAX_CURSOR_LENGTH = 512
_ID = re.compile(r"^[a-f0-9]{32}$")
_OWNER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PROJECT_CURSOR_KEY = secrets.token_bytes(32)


class ProjectReferenceIndexError(RuntimeError):
    pass


class ProjectReferenceIndex:
    """Select candidates only; authoritative project JSON remains decisive."""

    def __init__(self, settings: Settings, loader: Callable[[Path], ProjectRecord]) -> None:
        self.source = settings.projects_dir
        self.path = settings.data_dir / "results" / "project_reference_index.sqlite3"
        self.loader = loader
        self._file_state: tuple[int, int, int, int, int] | None = None
        self._source_state: tuple[int, int, int, int, int] | None = None

    def records_for_baselines(
        self,
        *,
        analysis_ids: set[str],
        owner_id: str | None = None,
        limit: int = PROJECT_REFERENCE_QUERY_BATCH_SIZE,
    ) -> list[ProjectRecord]:
        return self._records_for_references(
            reference_ids=analysis_ids,
            owner_id=owner_id,
            limit=limit,
            kind="baseline",
        )

    def records_for_sources(
        self,
        *,
        file_ids: set[str],
        owner_id: str | None = None,
        limit: int = PROJECT_REFERENCE_QUERY_BATCH_SIZE,
    ) -> list[ProjectRecord]:
        return self._records_for_references(
            reference_ids=file_ids,
            owner_id=owner_id,
            limit=limit,
            kind="source",
        )

    def records_for_responsible(
        self,
        *,
        user_id: str,
        owner_id: str,
        limit: int = PROJECT_REFERENCE_QUERY_BATCH_SIZE,
    ) -> list[ProjectRecord]:
        """Return a bounded authoritative batch currently assigned to one member."""

        if (
            not _OWNER.fullmatch(user_id)
            or not _OWNER.fullmatch(owner_id)
            or not 1 <= limit <= PROJECT_REFERENCE_QUERY_BATCH_SIZE
        ):
            raise ProjectReferenceIndexError("project_reference_index_invalid")
        digest = _reference_digest("responsible", user_id)
        self._ensure_current()
        connection = self._connect(query_only=True)
        try:
            rows = connection.execute(
                """
                SELECT project_id, owner_id, record_digest
                FROM project_reference_index
                WHERE owner_id = ? AND responsible_reference_digest = ?
                ORDER BY project_id
                LIMIT ?
                """,
                (owner_id, digest, limit),
            ).fetchall()
        except sqlite3.Error as exc:
            raise ProjectReferenceIndexError("project_reference_index_invalid") from exc
        finally:
            connection.close()
        records: list[ProjectRecord] = []
        for row in rows:
            try:
                record = self.loader(self.source / f"{row['project_id']}.json")
            except Exception as exc:
                raise ProjectReferenceIndexError("project_reference_index_invalid") from exc
            current = current_project_responsibility(record)
            if (
                record.owner_id != owner_id
                or row["owner_id"] != owner_id
                or current.state != "assigned"
                or current.responsible_user_id != user_id
                or project_reference_record_digest(record) != row["record_digest"]
            ):
                raise ProjectReferenceIndexError("project_reference_index_invalid")
            records.append(record)
        return records

    def responsible_count(self, *, user_id: str, owner_id: str) -> int:
        """Return the exact private-index count used by member-revocation preflight."""

        if not _OWNER.fullmatch(user_id) or not _OWNER.fullmatch(owner_id):
            raise ProjectReferenceIndexError("project_reference_index_invalid")
        self._ensure_current()
        connection = self._connect(query_only=True)
        try:
            return int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM project_reference_index
                    WHERE owner_id = ? AND responsible_reference_digest = ?
                    """,
                    (owner_id, _reference_digest("responsible", user_id)),
                ).fetchone()[0]
            )
        except sqlite3.Error as exc:
            raise ProjectReferenceIndexError("project_reference_index_invalid") from exc
        finally:
            connection.close()

    def page(
        self,
        *,
        owner_id: str,
        page_size: int = PROJECT_LIST_DEFAULT_PAGE_SIZE,
        cursor: str | None = None,
    ) -> tuple[list[ProjectRecord], int, str | None]:
        """Return a stable owner-scoped keyset page from opaque index fields."""

        if not _OWNER.fullmatch(owner_id) or not 1 <= page_size <= PROJECT_LIST_MAX_PAGE_SIZE:
            raise ProjectReferenceIndexError("project_reference_index_invalid")
        self._ensure_current()
        source_revision = _source_revision_digest(self._source_state)
        boundary = (
            _decode_project_cursor(cursor, owner_id=owner_id, source_revision=source_revision)
            if cursor is not None
            else None
        )
        clauses = ["owner_id = ?"]
        parameters: list[object] = [owner_id]
        if boundary is not None:
            clauses.append(
                "(updated_at_micros < ? OR (updated_at_micros = ? AND project_id < ?))"
            )
            parameters.extend((boundary[0], boundary[0], boundary[1]))
        connection = self._connect(query_only=True)
        try:
            total = int(
                connection.execute(
                    "SELECT COUNT(*) FROM project_reference_index WHERE owner_id = ?",
                    (owner_id,),
                ).fetchone()[0]
            )
            rows = connection.execute(
                f"""
                SELECT project_id, owner_id, updated_at_micros, record_digest
                FROM project_reference_index
                WHERE {' AND '.join(clauses)}
                ORDER BY updated_at_micros DESC, project_id DESC
                LIMIT ?
                """,
                (*parameters, page_size + 1),
            ).fetchall()
        except sqlite3.Error as exc:
            raise ProjectReferenceIndexError("project_reference_index_invalid") from exc
        finally:
            connection.close()
        selected = rows[:page_size]
        records: list[ProjectRecord] = []
        for row in selected:
            try:
                record = self.loader(self.source / f"{row['project_id']}.json")
            except Exception as exc:
                raise ProjectReferenceIndexError("project_reference_index_invalid") from exc
            if (
                record.owner_id != owner_id
                or row["owner_id"] != owner_id
                or _micros(record.updated_at) != row["updated_at_micros"]
                or project_reference_record_digest(record) != row["record_digest"]
            ):
                raise ProjectReferenceIndexError("project_reference_index_invalid")
            records.append(record)
        next_cursor = None
        if len(rows) > page_size and records:
            last = records[-1]
            next_cursor = _encode_project_cursor(
                owner_id=owner_id,
                source_revision=source_revision,
                boundary=(_micros(last.updated_at), last.id),
            )
        return records, total, next_cursor

    def source_revision(self) -> str:
        """Return the opaque revision currently binding project-list cursors."""

        self._ensure_current()
        return _source_revision_digest(self._source_state)

    def _records_for_references(
        self,
        *,
        reference_ids: set[str],
        owner_id: str | None,
        limit: int,
        kind: Literal["baseline", "source"],
    ) -> list[ProjectRecord]:
        if (
            not 1 <= len(reference_ids) <= PROJECT_REFERENCE_QUERY_MAX_REFERENCES
            or any(not _ID.fullmatch(reference_id) for reference_id in reference_ids)
            or (owner_id is not None and not _OWNER.fullmatch(owner_id))
            or not 1 <= limit <= PROJECT_REFERENCE_QUERY_BATCH_SIZE
        ):
            raise ProjectReferenceIndexError("project_reference_index_invalid")
        digests = sorted(_reference_digest(kind, value) for value in reference_ids)
        placeholders = ",".join("?" for _digest in digests)
        self._ensure_current()
        if kind == "baseline":
            table = "project_reference_index"
            digest_column = "baseline_reference_digest"
            extra = ""
        else:
            table = (
                "project_reference_index JOIN project_source_reference_index "
                "USING (project_id, owner_id)"
            )
            digest_column = "source_reference_digest"
            extra = " AND source_deleted = 0"
        owner_clause = " AND owner_id = ?" if owner_id is not None else ""
        parameters: list[object] = [*digests]
        if owner_id is not None:
            parameters.append(owner_id)
        connection = self._connect(query_only=True)
        try:
            rows = connection.execute(
                f"""
                SELECT DISTINCT project_id, owner_id, record_digest
                FROM {table}
                WHERE {digest_column} IN ({placeholders}){extra}{owner_clause}
                ORDER BY project_id
                LIMIT ?
                """,
                (*parameters, limit),
            ).fetchall()
        except sqlite3.Error as exc:
            raise ProjectReferenceIndexError("project_reference_index_invalid") from exc
        finally:
            connection.close()
        records: list[ProjectRecord] = []
        for row in rows:
            try:
                record = self.loader(self.source / f"{row['project_id']}.json")
            except Exception as exc:
                raise ProjectReferenceIndexError("project_reference_index_invalid") from exc
            if (
                record.owner_id != row["owner_id"]
                or (owner_id is not None and record.owner_id != owner_id)
                or project_reference_record_digest(record) != row["record_digest"]
            ):
                raise ProjectReferenceIndexError("project_reference_index_invalid")
            if kind == "baseline":
                matches = record.baseline_analysis_id in reference_ids
            else:
                matches = any(
                    snapshot.source_file_id in reference_ids
                    and snapshot.source_file_deleted_at is None
                    for snapshot in record.source_snapshots
                )
            if not matches:
                raise ProjectReferenceIndexError("project_reference_index_invalid")
            records.append(record)
        return records

    def sync_after_save(self, record: ProjectRecord) -> None:
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
        except (OSError, sqlite3.Error, ProjectReferenceIndexError):
            self._rebuild()

    def sync_after_delete(self, project_id: str) -> None:
        if self._file_state is None:
            self._ensure_current()
        try:
            source_state = _optional_directory_state(self.source)
            connection = self._connect()
            try:
                connection.execute(
                    "DELETE FROM project_reference_index WHERE project_id = ?",
                    (project_id,),
                )
                self._replace_source_state(connection, source_state)
                connection.commit()
            finally:
                connection.close()
            self._file_state = _file_state(self.path)
            self._source_state = source_state
        except (OSError, sqlite3.Error, ProjectReferenceIndexError):
            self._rebuild()

    def _ensure_current(self) -> None:
        if self._file_state is None and self.path.exists():
            try:
                self._adopt_existing()
                return
            except (OSError, sqlite3.Error, ProjectReferenceIndexError):
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
        records: list[ProjectRecord] = []
        if self.source.exists():
            if self.source.is_symlink() or not self.source.is_dir():
                raise ProjectReferenceIndexError("project_reference_index_invalid")
            try:
                for path in sorted(self.source.glob("*.json"), key=lambda item: item.name):
                    if _ID.fullmatch(path.stem):
                        records.append(self.loader(path))
            except Exception as exc:
                raise ProjectReferenceIndexError("project_reference_index_invalid") from exc
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
                CREATE TABLE project_reference_index_metadata (
                    key TEXT PRIMARY KEY, value TEXT NOT NULL
                );
                CREATE TABLE project_reference_index (
                    project_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    updated_at_micros INTEGER NOT NULL,
                    baseline_reference_digest TEXT,
                    responsible_reference_digest TEXT,
                    record_digest TEXT NOT NULL,
                    PRIMARY KEY (project_id, owner_id)
                );
                CREATE TABLE project_source_reference_index (
                    project_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    source_reference_digest TEXT NOT NULL,
                    source_deleted INTEGER NOT NULL CHECK (source_deleted IN (0, 1)),
                    PRIMARY KEY (project_id, owner_id, source_reference_digest),
                    FOREIGN KEY (project_id, owner_id)
                        REFERENCES project_reference_index (project_id, owner_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX project_reference_baseline
                    ON project_reference_index (owner_id, baseline_reference_digest, project_id);
                CREATE INDEX project_reference_owner_updated
                    ON project_reference_index (owner_id, updated_at_micros DESC, project_id DESC);
                CREATE INDEX project_reference_responsible
                    ON project_reference_index
                    (owner_id, responsible_reference_digest, project_id);
                CREATE INDEX project_reference_source
                    ON project_source_reference_index
                    (owner_id, source_reference_digest, source_deleted, project_id);
                """
            )
            connection.execute("PRAGMA foreign_keys = ON")
            for record in records:
                self._replace_record(connection, record)
            connection.execute(
                "INSERT INTO project_reference_index_metadata (key, value) VALUES ('schema_version', ?)",
                (str(PROJECT_REFERENCE_INDEX_SCHEMA_VERSION),),
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
            raise ProjectReferenceIndexError("project_reference_index_invalid") from exc
        _validate_file(self.path)
        self._file_state = _file_state(self.path)
        self._source_state = source_state

    def _adopt_existing(self) -> None:
        source_state = _optional_directory_state(self.source)
        connection = self._connect(query_only=True)
        try:
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            stored = connection.execute(
                "SELECT value FROM project_reference_index_metadata WHERE key = 'source_state'"
            ).fetchone()
            if (
                integrity is None
                or integrity[0] != "ok"
                or stored is None
                or stored[0] != _directory_state_token(source_state)
            ):
                raise ProjectReferenceIndexError("project_reference_index_invalid")
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
            connection.execute("PRAGMA foreign_keys = ON")
            if query_only:
                connection.execute("PRAGMA query_only = ON")
            version = connection.execute(
                "SELECT value FROM project_reference_index_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if version is None or version[0] != str(PROJECT_REFERENCE_INDEX_SCHEMA_VERSION):
                connection.close()
                raise ProjectReferenceIndexError("project_reference_index_invalid")
            return connection
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise ProjectReferenceIndexError("project_reference_index_invalid") from exc

    @staticmethod
    def _replace_record(connection: sqlite3.Connection, record: ProjectRecord) -> None:
        if record.owner_id is None or not _OWNER.fullmatch(record.owner_id):
            raise ProjectReferenceIndexError("project_reference_index_invalid")
        responsibility = current_project_responsibility(record)
        connection.execute(
            """
            INSERT INTO project_reference_index (
                project_id, owner_id, updated_at_micros,
                baseline_reference_digest, responsible_reference_digest,
                record_digest
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_id, owner_id) DO UPDATE SET
                updated_at_micros = excluded.updated_at_micros,
                baseline_reference_digest = excluded.baseline_reference_digest,
                responsible_reference_digest = excluded.responsible_reference_digest,
                record_digest = excluded.record_digest
            """,
            (
                record.id,
                record.owner_id,
                _micros(record.updated_at),
                _reference_digest("baseline", record.baseline_analysis_id)
                if record.baseline_analysis_id is not None
                else None,
                _reference_digest(
                    "responsible",
                    responsibility.responsible_user_id,
                )
                if responsibility.state == "assigned"
                and responsibility.responsible_user_id is not None
                else None,
                project_reference_record_digest(record),
            ),
        )
        connection.execute(
            "DELETE FROM project_source_reference_index WHERE project_id = ? AND owner_id = ?",
            (record.id, record.owner_id),
        )
        sources: dict[str, bool] = {}
        for snapshot in record.source_snapshots:
            digest = _reference_digest("source", snapshot.source_file_id)
            sources[digest] = sources.get(digest, True) and snapshot.source_file_deleted_at is not None
        connection.executemany(
            """
            INSERT INTO project_source_reference_index (
                project_id, owner_id, source_reference_digest, source_deleted
            ) VALUES (?, ?, ?, ?)
            """,
            [
                (record.id, record.owner_id, digest, int(deleted))
                for digest, deleted in sorted(sources.items())
            ],
        )

    @staticmethod
    def _replace_source_state(
        connection: sqlite3.Connection,
        state: tuple[int, int, int, int, int] | None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO project_reference_index_metadata (key, value)
            VALUES ('source_state', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (_directory_state_token(state),),
        )


def project_reference_record_digest(record: ProjectRecord) -> str:
    return hashlib.sha256(
        json.dumps(
            record.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def project_baseline_reference_digest(analysis_id: str) -> str:
    return _reference_digest("baseline", analysis_id)


def project_source_reference_digest(file_id: str) -> str:
    return _reference_digest("source", file_id)


def project_responsible_reference_digest(user_id: str) -> str:
    return _reference_digest("responsible", user_id)


def _reference_digest(
    kind: Literal["baseline", "source", "responsible"], value: str
) -> str:
    return hashlib.sha256(
        f"inspectra-project-{kind}-reference-v1\0{value}".encode("ascii")
    ).hexdigest()


def _validate_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProjectReferenceIndexError("project_reference_index_invalid") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > PROJECT_REFERENCE_INDEX_MAX_BYTES
        or metadata.st_mode & 0o077
    ):
        raise ProjectReferenceIndexError("project_reference_index_invalid")


def _file_state(path: Path) -> tuple[int, int, int, int, int]:
    metadata = path.lstat()
    return metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns


def _optional_directory_state(path: Path) -> tuple[int, int, int, int, int] | None:
    if not path.exists() and not path.is_symlink():
        return None
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise ProjectReferenceIndexError("project_reference_index_invalid")
    return metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns


def _directory_state_token(state: tuple[int, int, int, int, int] | None) -> str:
    return "missing" if state is None else ":".join(str(value) for value in state)


def _micros(value) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ProjectReferenceIndexError("project_reference_index_invalid")
    return int(value.timestamp() * 1_000_000)


def _source_revision_digest(state: tuple[int, int, int, int, int] | None) -> str:
    return hmac.new(
        _PROJECT_CURSOR_KEY,
        b"inspectra-project-source-revision-v1\0"
        + _directory_state_token(state).encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def _encode_project_cursor(
    *, owner_id: str, source_revision: str, boundary: tuple[int, str]
) -> str:
    owner_digest = hmac.new(
        _PROJECT_CURSOR_KEY,
        b"inspectra-project-owner-v1\0" + owner_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    payload = json.dumps(
        {"i": boundary[1], "o": owner_digest, "r": source_revision, "t": boundary[0], "v": 1},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    signature = hmac.new(
        _PROJECT_CURSOR_KEY,
        b"inspectra-project-cursor-v1\0" + payload,
        hashlib.sha256,
    ).digest()
    return f"{_urlsafe_encode(payload)}.{_urlsafe_encode(signature)}"


def _decode_project_cursor(
    cursor: str, *, owner_id: str, source_revision: str
) -> tuple[int, str]:
    if not 1 <= len(cursor) <= PROJECT_LIST_MAX_CURSOR_LENGTH or cursor.count(".") != 1:
        raise ProjectReferenceIndexError("invalid_cursor")
    encoded_payload, encoded_signature = cursor.split(".", 1)
    try:
        payload = _urlsafe_decode(encoded_payload)
        signature = _urlsafe_decode(encoded_signature)
        document = json.loads(payload)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProjectReferenceIndexError("invalid_cursor") from exc
    expected_signature = hmac.new(
        _PROJECT_CURSOR_KEY,
        b"inspectra-project-cursor-v1\0" + payload,
        hashlib.sha256,
    ).digest()
    expected_owner = hmac.new(
        _PROJECT_CURSOR_KEY,
        b"inspectra-project-owner-v1\0" + owner_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if (
        len(signature) != hashlib.sha256().digest_size
        or not hmac.compare_digest(signature, expected_signature)
        or not isinstance(document, dict)
        or set(document) != {"i", "o", "r", "t", "v"}
        or document.get("v") != 1
        or not isinstance(document.get("i"), str)
        or _ID.fullmatch(document["i"]) is None
        or not isinstance(document.get("t"), int)
        or document["t"] < 0
        or not isinstance(document.get("o"), str)
        or not hmac.compare_digest(document["o"], expected_owner)
        or not isinstance(document.get("r"), str)
        or not hmac.compare_digest(document["r"], source_revision)
    ):
        raise ProjectReferenceIndexError("invalid_cursor")
    return document["t"], document["i"]


def _urlsafe_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _urlsafe_decode(value: str) -> bytes:
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid cursor encoding") from exc
    if _urlsafe_encode(decoded) != value:
        raise ValueError("non-canonical base64url")
    return decoded
