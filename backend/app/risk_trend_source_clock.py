"""Durable owner-scoped invalidation clock for the risk-trend projection.

Authoritative JSON remains the source of truth.  This small SQLite journal only
records opaque owner revisions and a digest of source-directory metadata.  A
missed, corrupt, or out-of-band mutation rotates the epoch and therefore
invalidates every derived owner projection rather than risking stale data.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
from uuid import uuid4

from app.config import Settings


RISK_TREND_SOURCE_CLOCK_SCHEMA_VERSION = 1
RISK_TREND_SOURCE_CLOCK_MAX_BYTES = 16 * 1024 * 1024
RISK_TREND_SOURCE_CLOCK_MAX_OWNERS = 10_000
RISK_TREND_SOURCE_CLOCK_COLUMNS = {
    "risk_trend_source_clock_metadata": {"key", "value"},
    "risk_trend_source_owner_clock": {
        "owner_id", "generation", "updated_at_micros",
    },
}
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_METADATA_KEYS = frozenset({"schema_version", "epoch", "covered_source_revision"})


class RiskTrendSourceClockError(RuntimeError):
    """Closed failure that never includes a path, owner or source value."""


class RiskTrendSourceClock:
    """Bind relevant source mutations to monotonic per-owner generations."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.path = settings.results_dir / "risk_trend_source_clock.sqlite3"
        self._sources = (
            ("jobs", settings.jobs_dir),
            ("projects", settings.projects_dir),
            ("public_osv", settings.public_advisories_dir / "osv"),
            ("finding_decisions", settings.finding_decisions_dir),
            ("remediation_batches", settings.remediation_batches_dir),
            ("project_deletions", settings.project_deletions_dir),
        )

    def raw_source_revision(self) -> str:
        """Return a content-free fallback revision from relevant directory state."""

        states: list[tuple[str, tuple[int, int, int, int, int] | None]] = []
        for label, source in self._sources:
            if not source.exists() and not source.is_symlink():
                states.append((label, None))
                continue
            try:
                metadata = source.lstat()
            except OSError as exc:
                raise RiskTrendSourceClockError("risk_trend_source_clock_source_invalid") from exc
            if not stat.S_ISDIR(metadata.st_mode) or source.is_symlink():
                raise RiskTrendSourceClockError("risk_trend_source_clock_source_invalid")
            states.append((label, (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )))
        return hashlib.sha256(
            json.dumps(states, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()

    def recover(self) -> bool:
        """Repair a missing/divergent clock by rotating its epoch.

        Returning ``True`` means all previously materialized owner revisions are
        intentionally obsolete and will rebuild lazily from authority.
        """

        raw_revision = self.raw_source_revision()
        try:
            self._ensure_database()
            metadata = self._metadata()
        except (OSError, sqlite3.Error, RiskTrendSourceClockError):
            self._reset_database(raw_revision)
            return True
        if metadata["covered_source_revision"] != raw_revision:
            self._reset_database(raw_revision)
            return True
        return False

    def ready(self) -> bool:
        """Validate schema, topology and coverage without exposing owner counts."""

        try:
            self._ensure_database()
            return self._metadata()["covered_source_revision"] == self.raw_source_revision()
        except (OSError, sqlite3.Error, RiskTrendSourceClockError):
            return False

    def revision(self, organization_id: str) -> str:
        """Return an owner revision, falling back globally on any uncertainty."""

        owner_key = _owner_key(organization_id)
        raw_before = self.raw_source_revision()
        try:
            self._ensure_database()
            connection = self._connect(query_only=True)
            try:
                metadata = self._metadata(connection)
                row = connection.execute(
                    "SELECT generation FROM risk_trend_source_owner_clock WHERE owner_id = ?",
                    (owner_key,),
                ).fetchone()
            finally:
                connection.close()
        except (OSError, sqlite3.Error, RiskTrendSourceClockError):
            # Read paths never replace shared state. Startup recovery and
            # mutation writers run under the cross-process storage lock; until
            # either repairs the clock, every tenant receives the conservative
            # global fallback revision and readiness remains false.
            raw_after = self.raw_source_revision()
            return _fallback_revision(raw_after)
        raw_after = self.raw_source_revision()
        if (
            raw_before != raw_after
            or metadata["covered_source_revision"] != raw_after
        ):
            return _fallback_revision(raw_after)
        generation = int(row["generation"]) if row is not None else 0
        return _owner_revision(metadata["epoch"], owner_key, generation)

    def record_mutation(
        self,
        organization_id: str,
        *,
        previous_source_revision: str,
    ) -> str:
        """Cover one authoritative mutation made under the common storage lock.

        ``previous_source_revision`` must be captured immediately before the
        source write.  If it does not match the last covered state, the clock
        rotates its epoch and invalidates all owners.  That is the safe recovery
        path for crashes, manual edits and writers that predate this contract.
        """

        try:
            owner_key = _owner_key(organization_id)
        except RiskTrendSourceClockError:
            return "fallback_required"
        if not _DIGEST.fullmatch(previous_source_revision):
            raise RiskTrendSourceClockError("risk_trend_source_clock_invalid")
        current_source_revision = self.raw_source_revision()
        if current_source_revision == previous_source_revision:
            return "unchanged"
        try:
            self._ensure_database()
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                metadata = self._metadata(connection)
                if metadata["covered_source_revision"] != previous_source_revision:
                    connection.rollback()
                    connection.close()
                    connection = None
                    self._reset_database(current_source_revision)
                    return "all_invalidated"
                owner_count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM risk_trend_source_owner_clock"
                    ).fetchone()[0]
                )
                existing = connection.execute(
                    "SELECT generation FROM risk_trend_source_owner_clock WHERE owner_id = ?",
                    (owner_key,),
                ).fetchone()
                if existing is None and owner_count >= RISK_TREND_SOURCE_CLOCK_MAX_OWNERS:
                    raise RiskTrendSourceClockError("risk_trend_source_clock_limit")
                generation = (int(existing["generation"]) if existing is not None else 0) + 1
                connection.execute(
                    """
                    INSERT INTO risk_trend_source_owner_clock (
                        owner_id, generation, updated_at_micros
                    ) VALUES (?, ?, ?)
                    ON CONFLICT(owner_id) DO UPDATE SET
                        generation = excluded.generation,
                        updated_at_micros = excluded.updated_at_micros
                    """,
                    (owner_key, generation, _micros(datetime.now(timezone.utc))),
                )
                connection.execute(
                    "UPDATE risk_trend_source_clock_metadata SET value = ? WHERE key = 'covered_source_revision'",
                    (current_source_revision,),
                )
                connection.commit()
            except Exception:
                if connection is not None:
                    connection.rollback()
                raise
            finally:
                if connection is not None:
                    connection.close()
        except (OSError, sqlite3.Error, RiskTrendSourceClockError):
            # The authority has already changed.  A fresh epoch is safer than
            # propagating a write failure or preserving a potentially stale row.
            try:
                self._reset_database(current_source_revision)
                return "all_invalidated"
            except RiskTrendSourceClockError:
                # This projection clock is never allowed to roll back or make
                # an authoritative project mutation appear failed. The raw
                # mismatch keeps all trend reads on their global fallback and
                # readiness false until an operator/startup recovery succeeds.
                return "fallback_required"
        return "owner_invalidated"

    def _metadata(self, connection: sqlite3.Connection | None = None) -> dict[str, str]:
        owns_connection = connection is None
        current = connection or self._connect(query_only=True)
        try:
            rows = current.execute(
                "SELECT key, value FROM risk_trend_source_clock_metadata ORDER BY key"
            ).fetchall()
        finally:
            if owns_connection:
                current.close()
        values = {str(row["key"]): str(row["value"]) for row in rows}
        if (
            set(values) != _METADATA_KEYS
            or values["schema_version"] != str(RISK_TREND_SOURCE_CLOCK_SCHEMA_VERSION)
            or not _DIGEST.fullmatch(values["epoch"])
            or not _DIGEST.fullmatch(values["covered_source_revision"])
        ):
            raise RiskTrendSourceClockError("risk_trend_source_clock_invalid")
        return values

    def _ensure_database(self) -> None:
        self._validate_file()
        connection = self._connect(query_only=True)
        try:
            result = connection.execute("PRAGMA quick_check").fetchone()
            if result is None or result[0] != "ok":
                raise RiskTrendSourceClockError("risk_trend_source_clock_invalid")
            self._metadata(connection)
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM risk_trend_source_owner_clock"
                ).fetchone()[0]
            )
            if count > RISK_TREND_SOURCE_CLOCK_MAX_OWNERS:
                raise RiskTrendSourceClockError("risk_trend_source_clock_limit")
            invalid = connection.execute(
                """
                SELECT 1 FROM risk_trend_source_owner_clock
                WHERE generation < 1 OR updated_at_micros < 0
                LIMIT 1
                """
            ).fetchone()
            if invalid is not None:
                raise RiskTrendSourceClockError("risk_trend_source_clock_invalid")
            for row in connection.execute(
                "SELECT owner_id FROM risk_trend_source_owner_clock"
            ).fetchall():
                if not _DIGEST.fullmatch(str(row["owner_id"])):
                    raise RiskTrendSourceClockError("risk_trend_source_clock_invalid")
        finally:
            connection.close()

    def _connect(self, *, query_only: bool = False) -> sqlite3.Connection:
        self._validate_file()
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self.path, timeout=30)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema = OFF")
            if query_only:
                connection.execute("PRAGMA query_only = ON")
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            columns = {
                table: {
                    str(row[1])
                    for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
                }
                for table in RISK_TREND_SOURCE_CLOCK_COLUMNS
            }
            if tables != set(RISK_TREND_SOURCE_CLOCK_COLUMNS) or columns != RISK_TREND_SOURCE_CLOCK_COLUMNS:
                raise RiskTrendSourceClockError("risk_trend_source_clock_invalid")
            if not query_only:
                # This database is a rebuildable invalidation journal, never
                # authority. NORMAL removes one rollback-journal sync while
                # retaining transactional consistency. If the latest
                # transaction is lost, the independently persisted source
                # directory revision no longer matches and every read falls
                # back globally until startup recovery rotates the epoch.
                connection.execute("PRAGMA synchronous = NORMAL")
            return connection
        except Exception:
            if connection is not None:
                connection.close()
            raise

    def _reset_database(self, covered_source_revision: str) -> None:
        if not _DIGEST.fullmatch(covered_source_revision):
            raise RiskTrendSourceClockError("risk_trend_source_clock_invalid")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.parent.is_symlink() or not self.path.parent.is_dir():
            raise RiskTrendSourceClockError("risk_trend_source_clock_invalid")
        os.chmod(self.path.parent, 0o700)
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
                CREATE TABLE risk_trend_source_clock_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE risk_trend_source_owner_clock (
                    owner_id TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL CHECK (generation >= 1),
                    updated_at_micros INTEGER NOT NULL CHECK (updated_at_micros >= 0)
                );
                """
            )
            connection.executemany(
                "INSERT INTO risk_trend_source_clock_metadata (key, value) VALUES (?, ?)",
                (
                    ("schema_version", str(RISK_TREND_SOURCE_CLOCK_SCHEMA_VERSION)),
                    ("epoch", secrets.token_hex(32)),
                    ("covered_source_revision", covered_source_revision),
                ),
            )
            connection.commit()
            connection.close()
            connection = None
            with temporary.open("rb") as stream:
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory_descriptor = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                connection.close()
            temporary.unlink(missing_ok=True)
            raise RiskTrendSourceClockError("risk_trend_source_clock_invalid") from exc
        self._validate_file()

    def _validate_file(self) -> None:
        try:
            metadata = self.path.lstat()
        except OSError as exc:
            raise RiskTrendSourceClockError("risk_trend_source_clock_invalid") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or metadata.st_size > RISK_TREND_SOURCE_CLOCK_MAX_BYTES
        ):
            raise RiskTrendSourceClockError("risk_trend_source_clock_invalid")


def _owner_key(organization_id: str) -> str:
    """Derive a bounded opaque key without retaining a legacy tenant label."""

    if not isinstance(organization_id, str):
        raise RiskTrendSourceClockError("risk_trend_source_clock_invalid")
    encoded = organization_id.encode("utf-8")
    if not encoded or len(encoded) > 1024:
        raise RiskTrendSourceClockError("risk_trend_source_clock_invalid")
    return hashlib.sha256(
        b"inspectra-risk-trend-owner-key-v1\0" + encoded
    ).hexdigest()


def _owner_revision(epoch: str, owner_key: str, generation: int) -> str:
    return hashlib.sha256(
        b"inspectra-risk-trend-owner-source-clock-v1\0"
        + epoch.encode("ascii")
        + b"\0"
        + owner_key.encode("ascii")
        + b"\0"
        + str(generation).encode("ascii")
    ).hexdigest()


def _fallback_revision(raw_source_revision: str) -> str:
    return hashlib.sha256(
        b"inspectra-risk-trend-global-source-fallback-v1\0"
        + raw_source_revision.encode("ascii")
    ).hexdigest()


def _micros(value: datetime) -> int:
    return int(value.astimezone(timezone.utc).timestamp() * 1_000_000)
