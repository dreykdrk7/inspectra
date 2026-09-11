"""Private, rebuildable job projection for bounded summaries and admission."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import secrets
from typing import Callable
from uuid import uuid4

from app.config import Settings
from app.models import JobRecord


ACTIVE_JOB_INDEX_SCHEMA_VERSION = 7
ACTIVE_JOB_INDEX_MAX_BYTES = 256 * 1024 * 1024
ACTIVE_JOB_OPERATIONS_MAX_ASSETS = 500
ACTIVE_JOB_OPERATIONS_MAX_RECORDS = 2_000
JOB_HISTORY_DEFAULT_PAGE_SIZE = 50
JOB_HISTORY_MAX_PAGE_SIZE = 100
JOB_HISTORY_MAX_CURSOR_LENGTH = 512
JOB_RETENTION_BATCH_SIZE = 100
JOB_RETENTION_MAX_BATCH_SIZE = 500
JOB_SOURCE_REFERENCE_BATCH_SIZE = 100
JOB_SOURCE_REFERENCE_MAX_REFERENCES = 500
_OWNER = re.compile(r"^(?:local-admin|[a-f0-9]{32})$")
_GENERAL_OWNER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ID = re.compile(r"^[a-f0-9]{32}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_AUDIT_TYPE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_JOB_CURSOR_KEY = secrets.token_bytes(32)
_JOB_STATUSES = frozenset({"queued", "running", "cancelling", "cancelled", "completed", "failed"})


class ActiveJobIndexError(RuntimeError):
    pass


class ActiveJobIndex:
    """Index minimal job metadata while authoritative records remain in JSON."""

    def __init__(self, settings: Settings, loader: Callable[[Path], JobRecord]) -> None:
        self.settings = settings
        self.source = settings.jobs_dir
        self.path = settings.data_dir / "results" / "active_job_index.sqlite3"
        self.loader = loader
        self._file_state: tuple[int, int, int, int, int] | None = None
        self._source_state: tuple[int, int, int, int, int] | None = None

    def snapshot(
        self, *, owner_id: str, asset_ids: set[str], limit: int = ACTIVE_JOB_OPERATIONS_MAX_RECORDS
    ) -> tuple[list[JobRecord], int]:
        if not _OWNER.fullmatch(owner_id):
            raise ActiveJobIndexError("active_job_index_invalid")
        if (
            not 0 <= len(asset_ids) <= ACTIVE_JOB_OPERATIONS_MAX_ASSETS
            or any(not _ID.fullmatch(asset_id) for asset_id in asset_ids)
            or not 1 <= limit <= ACTIVE_JOB_OPERATIONS_MAX_RECORDS
        ):
            raise ActiveJobIndexError("active_job_index_invalid")
        self._ensure_current()
        connection = self._connect(query_only=True)
        try:
            total = int(
                connection.execute(
                    "SELECT COUNT(*) FROM active_job_index WHERE owner_id = ? AND active_asset_id IS NOT NULL",
                    (owner_id,),
                ).fetchone()[0]
            )
            if not asset_ids:
                return [], total
            placeholders = ",".join("?" for _asset_id in asset_ids)
            rows = connection.execute(
                f"""
                SELECT job_id, record_digest FROM active_job_index
                WHERE owner_id = ? AND active_asset_id IN ({placeholders})
                ORDER BY created_at_micros DESC, job_id DESC
                LIMIT ?
                """,
                (owner_id, *sorted(asset_ids), limit),
            ).fetchall()
        except sqlite3.Error as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        finally:
            connection.close()
        records: list[JobRecord] = []
        for row in rows:
            try:
                record = self.loader(self.source / f"{row['job_id']}.json")
            except Exception as exc:
                raise ActiveJobIndexError("active_job_index_invalid") from exc
            if (
                record.owner_id != owner_id
                or record.active_asset_id not in asset_ids
                or active_job_record_digest(record) != row["record_digest"]
            ):
                raise ActiveJobIndexError("active_job_index_invalid")
            records.append(record)
        return records, total

    def records_for_active_asset(
        self, *, owner_id: str, active_asset_id: str
    ) -> list[JobRecord]:
        """Load the complete validated job aggregate for one owned asset."""

        if not _OWNER.fullmatch(owner_id) or not _ID.fullmatch(active_asset_id):
            raise ActiveJobIndexError("active_job_index_invalid")
        self._ensure_current()
        connection = self._connect(query_only=True)
        try:
            rows = connection.execute(
                """
                SELECT job_id, owner_id, record_digest FROM active_job_index
                WHERE active_asset_id = ?
                ORDER BY created_at_micros, job_id
                """,
                (active_asset_id,),
            ).fetchall()
        except sqlite3.Error as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        finally:
            connection.close()
        records: list[JobRecord] = []
        for row in rows:
            try:
                record = self.loader(self.source / f"{row['job_id']}.json")
            except Exception as exc:
                raise ActiveJobIndexError("active_job_index_invalid") from exc
            if (
                row["owner_id"] != owner_id
                or record.owner_id != owner_id
                or record.active_asset_id != active_asset_id
                or active_job_record_digest(record) != row["record_digest"]
            ):
                raise ActiveJobIndexError("active_job_index_invalid")
            records.append(record)
        return records

    def inflight_records_for_active_asset(
        self, *, owner_id: str, active_asset_id: str
    ) -> list[JobRecord]:
        """Load every in-flight record for one asset without reading history."""

        if not _OWNER.fullmatch(owner_id) or not _ID.fullmatch(active_asset_id):
            raise ActiveJobIndexError("active_job_index_invalid")
        self._ensure_current()
        connection = self._connect(query_only=True)
        try:
            rows = connection.execute(
                """
                SELECT job_id, status, record_digest FROM active_job_index
                WHERE owner_id = ? AND active_asset_id = ?
                  AND status IN ('queued', 'running', 'cancelling')
                ORDER BY created_at_micros, job_id
                """,
                (owner_id, active_asset_id),
            ).fetchall()
        except sqlite3.Error as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        finally:
            connection.close()
        records: list[JobRecord] = []
        for row in rows:
            try:
                record = self.loader(self.source / f"{row['job_id']}.json")
            except Exception as exc:
                raise ActiveJobIndexError("active_job_index_invalid") from exc
            if (
                record.owner_id != owner_id
                or record.active_asset_id != active_asset_id
                or record.status != row["status"]
                or record.status not in {"queued", "running", "cancelling"}
                or active_job_record_digest(record) != row["record_digest"]
            ):
                raise ActiveJobIndexError("active_job_index_invalid")
            records.append(record)
        return records

    def admission_counts(self, *, owner_id: str) -> tuple[int, int]:
        """Return global and owner in-flight counts without loading JSON."""

        if not _GENERAL_OWNER.fullmatch(owner_id):
            raise ActiveJobIndexError("active_job_index_invalid")
        self._ensure_current()
        connection = self._connect(query_only=True)
        try:
            row = connection.execute(
                """
                SELECT
                    COUNT(*) AS global_count,
                    SUM(CASE WHEN owner_id = ? THEN 1 ELSE 0 END) AS owner_count
                FROM active_job_index
                WHERE status IN ('queued', 'running', 'cancelling')
                """,
                (owner_id,),
            ).fetchone()
            return int(row["global_count"] or 0), int(row["owner_count"] or 0)
        except sqlite3.Error as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        finally:
            connection.close()

    def global_inflight_count(self) -> int:
        """Return the exact global admission count without a synthetic owner."""

        self._ensure_current()
        connection = self._connect(query_only=True)
        try:
            return int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM active_job_index
                    WHERE status IN ('queued', 'running', 'cancelling')
                    """
                ).fetchone()[0]
            )
        except sqlite3.Error as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        finally:
            connection.close()

    def has_inflight_project(self, *, owner_id: str, project_id: str) -> bool:
        """Check one owner/project admission boundary without loading job JSON."""

        if not _GENERAL_OWNER.fullmatch(owner_id) or not _ID.fullmatch(project_id):
            raise ActiveJobIndexError("active_job_index_invalid")
        self._ensure_current()
        connection = self._connect(query_only=True)
        try:
            row = connection.execute(
                """
                SELECT 1 FROM active_job_index
                WHERE owner_id = ? AND project_id = ?
                  AND status IN ('queued', 'running', 'cancelling')
                LIMIT 1
                """,
                (owner_id, project_id),
            ).fetchone()
            return row is not None
        except sqlite3.Error as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        finally:
            connection.close()

    def inflight_project_job_ids(self) -> set[str]:
        """Return opaque IDs needed by recovery readiness without JSON reads."""

        self._ensure_current()
        connection = self._connect(query_only=True)
        try:
            rows = connection.execute(
                """
                SELECT job_id FROM active_job_index
                WHERE audit_type = 'project_archive_basic'
                  AND status IN ('queued', 'running', 'cancelling')
                """
            ).fetchall()
            return {str(row["job_id"]) for row in rows}
        except sqlite3.Error as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        finally:
            connection.close()

    def inflight_records(self) -> list[JobRecord]:
        """Load only authoritative records that require lifecycle recovery.

        The projection is used solely to select opaque candidates. Every
        selected JSON is then validated against its indexed status and digest
        before a recovery or source-retention decision can consume it.
        """

        self._ensure_current()
        connection = self._connect(query_only=True)
        try:
            rows = connection.execute(
                """
                SELECT job_id, status, record_digest FROM active_job_index
                WHERE status IN ('queued', 'running', 'cancelling')
                ORDER BY created_at_micros, job_id
                """
            ).fetchall()
        except sqlite3.Error as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        finally:
            connection.close()
        records: list[JobRecord] = []
        for row in rows:
            try:
                record = self.loader(self.source / f"{row['job_id']}.json")
            except Exception as exc:
                raise ActiveJobIndexError("active_job_index_invalid") from exc
            if (
                record.status != row["status"]
                or record.status not in {"queued", "running", "cancelling"}
                or active_job_record_digest(record) != row["record_digest"]
            ):
                raise ActiveJobIndexError("active_job_index_invalid")
            records.append(record)
        return records

    def inflight_source_reference_exists(self, *, file_id: str) -> bool:
        """Validate one indexed in-flight source reference under the store lock."""

        if not _ID.fullmatch(file_id):
            raise ActiveJobIndexError("active_job_index_invalid")
        self._ensure_current()
        reference_digest = job_source_reference_digest(file_id)
        connection = self._connect(query_only=True)
        try:
            row = connection.execute(
                """
                SELECT job_id, status, record_digest FROM active_job_index
                WHERE source_reference_digest = ? AND source_deleted = 0
                  AND status IN ('queued', 'running', 'cancelling')
                ORDER BY created_at_micros, job_id
                LIMIT 1
                """,
                (reference_digest,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        finally:
            connection.close()
        if row is None:
            return False
        try:
            record = self.loader(self.source / f"{row['job_id']}.json")
        except Exception as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        if (
            record.file_id != file_id
            or record.source_file_deleted_at is not None
            or record.status != row["status"]
            or record.status not in {"queued", "running", "cancelling"}
            or active_job_record_digest(record) != row["record_digest"]
        ):
            raise ActiveJobIndexError("active_job_index_invalid")
        return True

    def expired_terminal_records(
        self,
        *,
        cutoff: datetime,
        owner_id: str | None = None,
        limit: int = JOB_RETENTION_BATCH_SIZE,
    ) -> list[JobRecord]:
        """Load one stable, validated retention batch from the projection."""

        if (
            cutoff.tzinfo is None
            or cutoff.utcoffset() is None
            or (owner_id is not None and not _GENERAL_OWNER.fullmatch(owner_id))
            or not 1 <= limit <= JOB_RETENTION_MAX_BATCH_SIZE
        ):
            raise ActiveJobIndexError("active_job_index_invalid")
        self._ensure_current()
        cutoff_micros = _micros(cutoff)
        clauses = [
            "status IN ('completed', 'failed', 'cancelled')",
            "updated_at_micros <= ?",
        ]
        parameters: list[object] = [cutoff_micros]
        if owner_id is not None:
            clauses.append("owner_id = ?")
            parameters.append(owner_id)
        connection = self._connect(query_only=True)
        try:
            rows = connection.execute(
                f"""
                SELECT job_id, owner_id, status, updated_at_micros, record_digest
                FROM active_job_index
                WHERE {' AND '.join(clauses)}
                ORDER BY updated_at_micros, job_id
                LIMIT ?
                """,
                (*parameters, limit),
            ).fetchall()
        except sqlite3.Error as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        finally:
            connection.close()
        records: list[JobRecord] = []
        for row in rows:
            try:
                record = self.loader(self.source / f"{row['job_id']}.json")
            except Exception as exc:
                raise ActiveJobIndexError("active_job_index_invalid") from exc
            if (
                record.owner_id != row["owner_id"]
                or (owner_id is not None and record.owner_id != owner_id)
                or record.status != row["status"]
                or record.status not in {"completed", "failed", "cancelled"}
                or _micros(record.updated_at) != int(row["updated_at_micros"])
                or record.updated_at > cutoff
                or active_job_record_digest(record) != row["record_digest"]
            ):
                raise ActiveJobIndexError("active_job_index_invalid")
            records.append(record)
        return records

    def records_for_source_references(
        self,
        *,
        file_ids: set[str],
        owner_id: str | None = None,
        limit: int = JOB_SOURCE_REFERENCE_BATCH_SIZE,
    ) -> list[JobRecord]:
        """Load one unmarked source-reference batch without storing raw IDs."""

        if (
            not 1 <= len(file_ids) <= JOB_SOURCE_REFERENCE_MAX_REFERENCES
            or any(not _ID.fullmatch(file_id) for file_id in file_ids)
            or (owner_id is not None and not _GENERAL_OWNER.fullmatch(owner_id))
            or not 1 <= limit <= JOB_RETENTION_MAX_BATCH_SIZE
        ):
            raise ActiveJobIndexError("active_job_index_invalid")
        reference_digests = {
            job_source_reference_digest(file_id): file_id for file_id in file_ids
        }
        self._ensure_current()
        placeholders = ",".join("?" for _digest in reference_digests)
        clauses = [
            f"source_reference_digest IN ({placeholders})",
            "source_deleted = 0",
        ]
        parameters: list[object] = [*sorted(reference_digests)]
        if owner_id is not None:
            clauses.append("owner_id = ?")
            parameters.append(owner_id)
        connection = self._connect(query_only=True)
        try:
            rows = connection.execute(
                f"""
                SELECT job_id, owner_id, source_reference_digest, record_digest
                FROM active_job_index
                WHERE {' AND '.join(clauses)}
                ORDER BY source_reference_digest, created_at_micros, job_id
                LIMIT ?
                """,
                (*parameters, limit),
            ).fetchall()
        except sqlite3.Error as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        finally:
            connection.close()
        records: list[JobRecord] = []
        for row in rows:
            try:
                record = self.loader(self.source / f"{row['job_id']}.json")
            except Exception as exc:
                raise ActiveJobIndexError("active_job_index_invalid") from exc
            if (
                record.owner_id != row["owner_id"]
                or (owner_id is not None and record.owner_id != owner_id)
                or record.file_id not in file_ids
                or record.source_file_deleted_at is not None
                or job_source_reference_digest(record.file_id)
                != row["source_reference_digest"]
                or active_job_record_digest(record) != row["record_digest"]
            ):
                raise ActiveJobIndexError("active_job_index_invalid")
            records.append(record)
        return records

    def latest_project_record(
        self, *, owner_id: str, project_id: str, status: str = "completed"
    ) -> JobRecord | None:
        """Load and validate only the newest matching project job."""

        if (
            not _GENERAL_OWNER.fullmatch(owner_id)
            or not _ID.fullmatch(project_id)
            or status not in _JOB_STATUSES
        ):
            raise ActiveJobIndexError("active_job_index_invalid")
        self._ensure_current()
        connection = self._connect(query_only=True)
        try:
            row = connection.execute(
                """
                SELECT job_id, record_digest FROM active_job_index
                WHERE owner_id = ? AND project_id = ? AND status = ?
                ORDER BY created_at_micros DESC, job_id DESC
                LIMIT 1
                """,
                (owner_id, project_id, status),
            ).fetchone()
        except sqlite3.Error as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        finally:
            connection.close()
        if row is None:
            return None
        try:
            record = self.loader(self.source / f"{row['job_id']}.json")
        except Exception as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        if (
            record.owner_id != owner_id
            or record.project_id != project_id
            or record.status != status
            or active_job_record_digest(record) != row["record_digest"]
        ):
            raise ActiveJobIndexError("active_job_index_invalid")
        return record

    def active_capacity_counts(
        self, *, owner_id: str, active_asset_id: str, audit_type: str
    ) -> tuple[int, int, int, int]:
        """Return all four persisted Active quota dimensions."""

        if (
            not _GENERAL_OWNER.fullmatch(owner_id)
            or not _ID.fullmatch(active_asset_id)
            or not re.fullmatch(r"active_[a-z0-9_]{3,48}", audit_type)
        ):
            raise ActiveJobIndexError("active_job_index_invalid")
        self._ensure_current()
        connection = self._connect(query_only=True)
        try:
            row = connection.execute(
                """
                SELECT
                    COUNT(*) AS global_count,
                    SUM(CASE WHEN owner_id = ? THEN 1 ELSE 0 END) AS owner_count,
                    SUM(CASE WHEN owner_id = ? AND active_asset_id = ? THEN 1 ELSE 0 END) AS asset_count,
                    SUM(CASE WHEN audit_type = ? THEN 1 ELSE 0 END) AS capability_count
                FROM active_job_index
                WHERE active_asset_id IS NOT NULL
                  AND status IN ('queued', 'running', 'cancelling')
                """,
                (owner_id, owner_id, active_asset_id, audit_type),
            ).fetchone()
            return tuple(
                int(row[key] or 0)
                for key in (
                    "global_count", "owner_count", "asset_count", "capability_count"
                )
            )
        except sqlite3.Error as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        finally:
            connection.close()

    def idempotent_record(
        self, *, owner_id: str, idempotency_key_sha256: str
    ) -> JobRecord | None:
        """Resolve one owner-scoped replay and validate its authoritative JSON."""

        if (
            not _GENERAL_OWNER.fullmatch(owner_id)
            or not _DIGEST.fullmatch(idempotency_key_sha256)
        ):
            raise ActiveJobIndexError("active_job_index_invalid")
        self._ensure_current()
        connection = self._connect(query_only=True)
        try:
            row = connection.execute(
                """
                SELECT job_id, record_digest FROM active_job_index
                WHERE owner_id = ? AND active_idempotency_key_sha256 = ?
                """,
                (owner_id, idempotency_key_sha256),
            ).fetchone()
        except sqlite3.Error as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        finally:
            connection.close()
        if row is None:
            return None
        try:
            record = self.loader(self.source / f"{row['job_id']}.json")
        except Exception as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        if (
            record.owner_id != owner_id
            or record.active_execution_idempotency_key_sha256 != idempotency_key_sha256
            or active_job_record_digest(record) != row["record_digest"]
        ):
            raise ActiveJobIndexError("active_job_index_invalid")
        return record

    def page(
        self,
        *,
        owner_id: str,
        page_size: int = JOB_HISTORY_DEFAULT_PAGE_SIZE,
        cursor: str | None = None,
        status: str | None = None,
        audit_type: str | None = None,
        project_id: str | None = None,
        active_asset_id: str | None = None,
    ) -> tuple[list[JobRecord], int, str | None]:
        """Return an owner-scoped keyset page and exact filtered total."""

        if (
            not _GENERAL_OWNER.fullmatch(owner_id)
            or not 1 <= page_size <= JOB_HISTORY_MAX_PAGE_SIZE
            or status not in _JOB_STATUSES | {None}
            or (audit_type is not None and not _AUDIT_TYPE.fullmatch(audit_type))
            or (project_id is not None and not _ID.fullmatch(project_id))
            or (active_asset_id is not None and not _ID.fullmatch(active_asset_id))
        ):
            raise ActiveJobIndexError("active_job_index_invalid")
        filter_digest = _job_filter_digest(
            owner_id=owner_id,
            status=status,
            audit_type=audit_type,
            project_id=project_id,
            active_asset_id=active_asset_id,
        )
        cursor_state = (
            _decode_job_cursor(cursor, owner_id=owner_id, filter_digest=filter_digest)
            if cursor is not None
            else None
        )
        boundary = cursor_state[0] if cursor_state is not None else None
        cutoff = cursor_state[1] if cursor_state is not None else None
        self._ensure_current()
        clauses = ["owner_id = ?"]
        parameters: list[object] = [owner_id]
        if status is not None:
            clauses.append("status = ?")
            parameters.append(status)
        if audit_type is not None:
            clauses.append("audit_type = ?")
            parameters.append(audit_type)
        if project_id is not None:
            clauses.append("project_id = ?")
            parameters.append(project_id)
        if active_asset_id is not None:
            clauses.append("active_asset_id = ?")
            parameters.append(active_asset_id)
        if cutoff is not None:
            clauses.append("(created_at_micros < ? OR (created_at_micros = ? AND job_id <= ?))")
            parameters.extend((cutoff[0], cutoff[0], cutoff[1]))
        where = " AND ".join(clauses)
        page_clauses = list(clauses)
        page_parameters = list(parameters)
        if boundary is not None:
            page_clauses.append("(created_at_micros < ? OR (created_at_micros = ? AND job_id < ?))")
            page_parameters.extend((boundary[0], boundary[0], boundary[1]))
        connection = self._connect(query_only=True)
        try:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM active_job_index WHERE {where}", parameters
                ).fetchone()[0]
            )
            rows = connection.execute(
                f"""
                SELECT job_id, created_at_micros, record_digest FROM active_job_index
                WHERE {' AND '.join(page_clauses)}
                ORDER BY created_at_micros DESC, job_id DESC
                LIMIT ?
                """,
                (*page_parameters, page_size + 1),
            ).fetchall()
        except sqlite3.Error as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        finally:
            connection.close()
        selected = rows[:page_size]
        if cutoff is None and selected:
            cutoff = (int(selected[0]["created_at_micros"]), str(selected[0]["job_id"]))
        records: list[JobRecord] = []
        for row in selected:
            try:
                record = self.loader(self.source / f"{row['job_id']}.json")
            except Exception as exc:
                raise ActiveJobIndexError("active_job_index_invalid") from exc
            if (
                record.owner_id != owner_id
                or (status is not None and record.status != status)
                or (audit_type is not None and record.audit_type != audit_type)
                or (project_id is not None and record.project_id != project_id)
                or (active_asset_id is not None and record.active_asset_id != active_asset_id)
                or active_job_record_digest(record) != row["record_digest"]
            ):
                raise ActiveJobIndexError("active_job_index_invalid")
            records.append(record)
        next_cursor = None
        if len(rows) > page_size and records:
            last = records[-1]
            assert cutoff is not None
            next_cursor = _encode_job_cursor(
                owner_id=owner_id,
                filter_digest=filter_digest,
                boundary=(_micros(last.created_at), last.id),
                cutoff=cutoff,
            )
        return records, total, next_cursor

    def attention_asset_ids(
        self, *, owner_id: str, limit: int = ACTIVE_JOB_OPERATIONS_MAX_ASSETS
    ) -> tuple[set[str], set[str]]:
        """Return assets whose latest capability job failed or degraded."""

        if not _OWNER.fullmatch(owner_id) or not 1 <= limit <= ACTIVE_JOB_OPERATIONS_MAX_ASSETS:
            raise ActiveJobIndexError("active_job_index_invalid")
        self._ensure_current()
        connection = self._connect(query_only=True)
        try:
            rows = connection.execute(
                """
                SELECT active_asset_id, status, degraded
                FROM (
                    SELECT active_asset_id, status, degraded, updated_at_micros, job_id,
                           ROW_NUMBER() OVER (
                               PARTITION BY active_asset_id, audit_type
                               ORDER BY updated_at_micros DESC, job_id DESC
                           ) AS position
                    FROM active_job_index
                    WHERE owner_id = ? AND active_asset_id IS NOT NULL
                )
                WHERE position = 1 AND (status = 'failed' OR degraded = 1)
                ORDER BY CASE WHEN status = 'failed' THEN 0 ELSE 1 END,
                         updated_at_micros DESC, job_id DESC
                LIMIT ?
                """,
                (owner_id, limit),
            ).fetchall()
        except sqlite3.Error as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        finally:
            connection.close()
        failed = {str(row["active_asset_id"]) for row in rows if row["status"] == "failed"}
        degraded = {str(row["active_asset_id"]) for row in rows if int(row["degraded"]) == 1}
        return failed, degraded

    def sync_after_save(self, record: JobRecord) -> None:
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
            _validate_file(self.path)
            self._file_state = _file_state(self.path)
            self._source_state = source_state
        except (ActiveJobIndexError, OSError, sqlite3.Error):
            self._rebuild()

    def sync_after_delete(self, record: JobRecord) -> None:
        if self._file_state is None:
            return
        try:
            source_state = _optional_directory_state(self.source)
            connection = self._connect()
            try:
                connection.execute("DELETE FROM active_job_index WHERE job_id = ?", (record.id,))
                self._replace_source_state(connection, source_state)
                connection.commit()
            finally:
                connection.close()
            self._file_state = _file_state(self.path)
            self._source_state = source_state
        except (ActiveJobIndexError, OSError, sqlite3.Error):
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
        except (ActiveJobIndexError, OSError, sqlite3.Error):
            return False

    def _ensure_current(self) -> None:
        if self._file_state is None and self.path.exists():
            try:
                self._adopt_existing()
                return
            except (ActiveJobIndexError, OSError, sqlite3.Error):
                self._rebuild()
                return
        if self._file_state is None or not self.path.exists():
            self._rebuild()
            return
        if _file_state(self.path) != self._file_state or _optional_directory_state(self.source) != self._source_state:
            self._rebuild()

    def _rebuild(self) -> None:
        records: list[JobRecord] = []
        if self.source.exists():
            if self.source.is_symlink() or not self.source.is_dir():
                raise ActiveJobIndexError("active_job_index_invalid")
            try:
                paths = sorted(self.source.glob("*.json"), key=lambda item: item.name)
                for source_path in paths:
                    if not _ID.fullmatch(source_path.stem):
                        continue
                    records.append(self.loader(source_path))
            except Exception as exc:
                raise ActiveJobIndexError("active_job_index_invalid") from exc
        source_state = _optional_directory_state(self.source)
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
                CREATE TABLE active_job_index_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE active_job_index (
                    job_id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    active_asset_id TEXT,
                    project_id TEXT,
                    audit_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    degraded INTEGER NOT NULL CHECK (degraded IN (0, 1)),
                    active_idempotency_key_sha256 TEXT,
                    created_at_micros INTEGER NOT NULL,
                    updated_at_micros INTEGER NOT NULL,
                    source_reference_digest TEXT
                        CHECK (source_reference_digest IS NULL OR length(source_reference_digest) = 64),
                    source_deleted INTEGER NOT NULL CHECK (source_deleted IN (0, 1)),
                    record_digest TEXT NOT NULL
                );
                CREATE INDEX active_job_index_owner_created
                    ON active_job_index (owner_id, created_at_micros DESC, job_id DESC);
                CREATE INDEX active_job_index_owner_project_created
                    ON active_job_index (owner_id, project_id, created_at_micros DESC, job_id DESC);
                CREATE INDEX active_job_index_owner_asset
                    ON active_job_index (owner_id, active_asset_id, created_at_micros DESC);
                CREATE UNIQUE INDEX active_job_index_owner_idempotency
                    ON active_job_index (owner_id, active_idempotency_key_sha256)
                    WHERE active_idempotency_key_sha256 IS NOT NULL;
                CREATE INDEX active_job_index_terminal_retention
                    ON active_job_index (updated_at_micros, job_id)
                    WHERE status IN ('completed', 'failed', 'cancelled');
                CREATE INDEX active_job_index_owner_terminal_retention
                    ON active_job_index (owner_id, updated_at_micros, job_id)
                    WHERE status IN ('completed', 'failed', 'cancelled');
                CREATE INDEX active_job_index_source_reference
                    ON active_job_index (source_reference_digest, created_at_micros, job_id)
                    WHERE source_reference_digest IS NOT NULL AND source_deleted = 0;
                CREATE INDEX active_job_index_owner_source_reference
                    ON active_job_index (owner_id, source_reference_digest, created_at_micros, job_id)
                    WHERE source_reference_digest IS NOT NULL AND source_deleted = 0;
                """
            )
            for record in records:
                self._replace_record(connection, record)
            connection.execute(
                "INSERT INTO active_job_index_metadata (key, value) VALUES ('schema_version', ?)",
                (str(ACTIVE_JOB_INDEX_SCHEMA_VERSION),),
            )
            connection.execute(
                "INSERT INTO active_job_index_metadata (key, value) VALUES ('source_state', ?)",
                (_directory_state_token(source_state),),
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
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        _validate_file(self.path)
        self._file_state = _file_state(self.path)
        self._source_state = source_state

    def _adopt_existing(self) -> None:
        """Adopt a durable projection only when its source marker still matches."""

        source_state = _optional_directory_state(self.source)
        connection = self._connect(query_only=True)
        try:
            integrity = connection.execute("PRAGMA quick_check").fetchone()
            stored_state = connection.execute(
                "SELECT value FROM active_job_index_metadata WHERE key = 'source_state'"
            ).fetchone()
            if (
                integrity is None
                or integrity[0] != "ok"
                or stored_state is None
                or stored_state[0] != _directory_state_token(source_state)
            ):
                raise ActiveJobIndexError("active_job_index_invalid")
        finally:
            connection.close()
        self._file_state = _file_state(self.path)
        self._source_state = source_state

    @staticmethod
    def _replace_record(connection: sqlite3.Connection, record: JobRecord) -> None:
        if record.owner_id is None or not _GENERAL_OWNER.fullmatch(record.owner_id):
            raise ActiveJobIndexError("active_job_index_invalid")
        connection.execute(
            """
            INSERT INTO active_job_index (
                job_id, owner_id, active_asset_id, project_id, audit_type, status, degraded,
                active_idempotency_key_sha256, created_at_micros,
                updated_at_micros, source_reference_digest, source_deleted,
                record_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
                owner_id = excluded.owner_id,
                active_asset_id = excluded.active_asset_id,
                project_id = excluded.project_id,
                audit_type = excluded.audit_type,
                status = excluded.status,
                degraded = excluded.degraded,
                active_idempotency_key_sha256 = excluded.active_idempotency_key_sha256,
                created_at_micros = excluded.created_at_micros,
                updated_at_micros = excluded.updated_at_micros,
                source_reference_digest = excluded.source_reference_digest,
                source_deleted = excluded.source_deleted,
                record_digest = excluded.record_digest
            """,
            (
                record.id,
                record.owner_id,
                record.active_asset_id,
                record.project_id,
                record.audit_type,
                record.status,
                int(_record_is_degraded(record)),
                record.active_execution_idempotency_key_sha256,
                _micros(record.created_at),
                _micros(record.updated_at),
                (
                    job_source_reference_digest(record.file_id)
                    if record.file_id is not None
                    else None
                ),
                int(record.source_file_deleted_at is not None),
                active_job_record_digest(record),
            ),
        )

    @staticmethod
    def _replace_source_state(
        connection: sqlite3.Connection,
        source_state: tuple[int, int, int, int, int] | None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO active_job_index_metadata (key, value) VALUES ('source_state', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (_directory_state_token(source_state),),
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
                "SELECT value FROM active_job_index_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if version is None or version[0] != str(ACTIVE_JOB_INDEX_SCHEMA_VERSION):
                connection.close()
                raise ActiveJobIndexError("active_job_index_invalid")
            return connection
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise ActiveJobIndexError("active_job_index_invalid") from exc

    def _remove_stale_artifacts(self) -> None:
        exact = {f"{self.path.name}-{suffix}" for suffix in ("journal", "wal", "shm")}
        temporary = re.compile(
            rf"^\.{re.escape(self.path.name)}\.[a-f0-9]{{32}}\.tmp(?:-(?:journal|wal|shm))?$"
        )
        try:
            candidates = list(self.path.parent.iterdir())
        except OSError as exc:
            raise ActiveJobIndexError("active_job_index_invalid") from exc
        for candidate in candidates:
            if candidate.name not in exact and not temporary.fullmatch(candidate.name):
                continue
            metadata = candidate.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ActiveJobIndexError("active_job_index_invalid")
            candidate.unlink()


def active_job_record_digest(record: JobRecord) -> str:
    payload = json.dumps(
        record.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def job_source_reference_digest(file_id: str) -> str:
    """Derive a non-reversible index key for an opaque source identifier."""

    return hashlib.sha256(
        b"inspectra-job-source-reference-v1\0" + file_id.encode("utf-8")
    ).hexdigest()


def _record_is_degraded(record: JobRecord) -> bool:
    if record.status != "completed" or not isinstance(record.result, dict):
        return False
    return record.result.get("status") in {
        "partial", "timed_out", "request_failed", "source_unavailable"
    } or record.result.get("coverage_level") in {
        "partial", "partial_inventory", "incomplete"
    }


def _job_filter_digest(
    *,
    owner_id: str,
    status: str | None,
    audit_type: str | None,
    project_id: str | None,
    active_asset_id: str | None,
) -> str:
    payload = json.dumps(
        {
            "active_asset_id": active_asset_id or "",
            "audit_type": audit_type or "",
            "project_id": project_id or "",
            "status": status or "",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hmac.new(
        _JOB_CURSOR_KEY,
        b"inspectra-job-filter-v1\0" + owner_id.encode("utf-8") + b"\0" + payload,
        hashlib.sha256,
    ).hexdigest()


def _encode_job_cursor(
    *,
    owner_id: str,
    filter_digest: str,
    boundary: tuple[int, str],
    cutoff: tuple[int, str],
) -> str:
    owner_digest = hmac.new(
        _JOB_CURSOR_KEY,
        b"inspectra-job-owner-v1\0" + owner_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    payload = json.dumps(
        {
            "bi": boundary[1],
            "bt": boundary[0],
            "ci": cutoff[1],
            "ct": cutoff[0],
            "f": filter_digest,
            "o": owner_digest,
            "v": 2,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    signature = hmac.new(
        _JOB_CURSOR_KEY, b"inspectra-job-cursor-v1\0" + payload, hashlib.sha256
    ).digest()
    return f"{_urlsafe_encode(payload)}.{_urlsafe_encode(signature)}"


def _decode_job_cursor(
    cursor: str, *, owner_id: str, filter_digest: str
) -> tuple[tuple[int, str], tuple[int, str]]:
    if not 1 <= len(cursor) <= JOB_HISTORY_MAX_CURSOR_LENGTH or cursor.count(".") != 1:
        raise ActiveJobIndexError("invalid_cursor")
    encoded_payload, encoded_signature = cursor.split(".", 1)
    try:
        payload = _urlsafe_decode(encoded_payload)
        signature = _urlsafe_decode(encoded_signature)
        document = json.loads(payload)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActiveJobIndexError("invalid_cursor") from exc
    expected_signature = hmac.new(
        _JOB_CURSOR_KEY, b"inspectra-job-cursor-v1\0" + payload, hashlib.sha256
    ).digest()
    expected_owner = hmac.new(
        _JOB_CURSOR_KEY,
        b"inspectra-job-owner-v1\0" + owner_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if (
        len(signature) != hashlib.sha256().digest_size
        or not hmac.compare_digest(signature, expected_signature)
        or not isinstance(document, dict)
        or set(document) != {"bi", "bt", "ci", "ct", "f", "o", "v"}
        or document.get("v") != 2
        or not isinstance(document.get("o"), str)
        or not hmac.compare_digest(document["o"], expected_owner)
        or not isinstance(document.get("f"), str)
        or not hmac.compare_digest(document["f"], filter_digest)
        or not isinstance(document.get("bi"), str)
        or _ID.fullmatch(document["bi"]) is None
        or not isinstance(document.get("ci"), str)
        or _ID.fullmatch(document["ci"]) is None
        or any(isinstance(document.get(key), bool) for key in ("bt", "ct"))
        or any(not isinstance(document.get(key), int) for key in ("bt", "ct"))
        or any(not 0 <= document[key] <= 10**18 for key in ("bt", "ct"))
        or (document["bt"], document["bi"]) > (document["ct"], document["ci"])
    ):
        raise ActiveJobIndexError("invalid_cursor")
    return (
        (document["bt"], document["bi"]),
        (document["ct"], document["ci"]),
    )


def _urlsafe_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _urlsafe_decode(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid base64url")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if _urlsafe_encode(decoded) != value:
        raise ValueError("non-canonical base64url")
    return decoded


def _micros(value: datetime) -> int:
    normalized = value.astimezone(timezone.utc)
    return int(normalized.timestamp()) * 1_000_000 + normalized.microsecond


def _validate_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ActiveJobIndexError("active_job_index_invalid") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > ACTIVE_JOB_INDEX_MAX_BYTES
        or metadata.st_mode & 0o077
    ):
        raise ActiveJobIndexError("active_job_index_invalid")


def _file_state(path: Path) -> tuple[int, int, int, int, int]:
    metadata = path.lstat()
    return metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns


def _optional_directory_state(path: Path) -> tuple[int, int, int, int, int] | None:
    if not path.exists() and not path.is_symlink():
        return None
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise ActiveJobIndexError("active_job_index_invalid")
    return metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns


def _directory_state_token(state: tuple[int, int, int, int, int] | None) -> str:
    return json.dumps(state, separators=(",", ":"))
