"""Opt-in, local-only and low-cardinality product adoption counters."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Final

from app.config import Settings


ADOPTION_METRICS_CONTRACT_VERSION = "2026-09-10.1"
ADOPTION_METRICS_SCHEMA_VERSION = 1
ADOPTION_METRICS_RETENTION_DAYS = 90
ADOPTION_METRICS_MAX_ROWS = 8_192
ADOPTION_METRICS_MAX_BYTES = 16 * 1024 * 1024

_ROUTES: Final[dict[tuple[str, str], tuple[str, str]]] = {
    ("POST", "/projects"): ("archive_onboarding", "create"),
    ("POST", "/projects/import/sbom/preflight"): ("sbom_onboarding", "preflight"),
    ("POST", "/projects/import/sbom"): ("sbom_onboarding", "create"),
    ("POST", "/projects/{project_id}/analyses"): ("project_analysis", "enqueue"),
    ("POST", "/projects/{project_id}/ci/snapshots"): ("ci_analysis", "admit"),
    ("POST", "/projects/{project_id}/sbom-revisions"): ("sbom_revision", "admit"),
    (
        "POST",
        "/projects/{project_id}/analyses/{analysis_id}/vulnerability-intelligence/osv",
    ): ("public_vulnerability", "osv_query"),
    (
        "POST",
        "/projects/{project_id}/analyses/{analysis_id}/report/{report_format}",
    ): ("project_report", "export"),
    ("POST", "/projects/trends/report"): ("risk_trends", "export"),
    ("POST", "/remediation/report"): ("remediation", "export"),
}
_OUTCOMES = frozenset({"succeeded", "invalid", "denied", "throttled", "failed"})
_DURATION_BUCKETS = (
    (100, "lt_100ms"),
    (500, "lt_500ms"),
    (2_000, "lt_2s"),
    (10_000, "lt_10s"),
    (60_000, "lt_60s"),
)
_DIMENSIONS = frozenset(_ROUTES.values())
_BUCKETS = frozenset(label for _upper, label in _DURATION_BUCKETS) | {"gte_60s"}
ADOPTION_METRICS_DIMENSIONS = _DIMENSIONS
ADOPTION_METRICS_OUTCOMES = _OUTCOMES
ADOPTION_METRICS_DURATION_BUCKETS = _BUCKETS
ADOPTION_METRICS_COLUMNS = {
    "day", "flow", "phase", "outcome", "duration_bucket", "event_count",
}


class AdoptionMetricsError(RuntimeError):
    """Controlled local-store failure without filesystem or request details."""


class AdoptionMetricsStore:
    """Aggregate fixed route templates; never retain request or tenant identity."""

    def __init__(self, settings: Settings) -> None:
        self.enabled = settings.adoption_metrics_enabled
        self.path = settings.results_dir / "adoption_metrics.sqlite3"

    def record_http(
        self,
        *,
        method: str,
        route_template: str,
        status_code: int,
        duration_ms: int,
        observed_at: datetime | None = None,
    ) -> bool:
        if not self.enabled:
            return False
        dimension = _ROUTES.get((method.upper(), route_template))
        if dimension is None:
            return False
        outcome = _outcome(status_code)
        bucket = _duration_bucket(duration_ms)
        now = _utc(observed_at)
        day = now.date().isoformat()
        cutoff = (
            now.date() - timedelta(days=ADOPTION_METRICS_RETENTION_DAYS - 1)
        ).isoformat()
        try:
            self._ensure_database()
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("DELETE FROM adoption_metric WHERE day < ?", (cutoff,))
                exists = connection.execute(
                    """
                    SELECT 1 FROM adoption_metric
                    WHERE day = ? AND flow = ? AND phase = ? AND outcome = ? AND duration_bucket = ?
                    """,
                    (day, *dimension, outcome, bucket),
                ).fetchone()
                if exists is None:
                    count = int(connection.execute("SELECT COUNT(*) FROM adoption_metric").fetchone()[0])
                    if count >= ADOPTION_METRICS_MAX_ROWS:
                        raise AdoptionMetricsError("adoption_metrics_limit")
                connection.execute(
                    """
                    INSERT INTO adoption_metric (day, flow, phase, outcome, duration_bucket, event_count)
                    VALUES (?, ?, ?, ?, ?, 1)
                    ON CONFLICT(day, flow, phase, outcome, duration_bucket)
                    DO UPDATE SET event_count = event_count + 1
                    """,
                    (day, *dimension, outcome, bucket),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except (OSError, sqlite3.Error, AdoptionMetricsError) as exc:
            raise AdoptionMetricsError("adoption_metrics_unavailable") from exc
        return True

    def export(self, *, observed_at: datetime | None = None) -> bytes:
        """Render one canonical local snapshot containing aggregate rows only."""

        now = _utc(observed_at)
        rows: list[dict[str, object]] = []
        if self.enabled and self.path.exists():
            self._ensure_database()
            cutoff = (now.date() - timedelta(days=ADOPTION_METRICS_RETENTION_DAYS - 1)).isoformat()
            connection = self._connect(query_only=True)
            try:
                for row in connection.execute(
                    """
                    SELECT day, flow, phase, outcome, duration_bucket, event_count
                    FROM adoption_metric WHERE day >= ?
                    ORDER BY day, flow, phase, outcome, duration_bucket
                    """,
                    (cutoff,),
                ):
                    rows.append(dict(row))
            finally:
                connection.close()
        payload = {
            "contract_version": ADOPTION_METRICS_CONTRACT_VERSION,
            "enabled": self.enabled,
            "generated_day": now.date().isoformat(),
            "retention_days": ADOPTION_METRICS_RETENTION_DAYS,
            "privacy": {
                "external_transport": False,
                "user_identifier": False,
                "organization_identifier": False,
                "project_identifier": False,
                "request_identifier": False,
                "source_or_component_data": False,
                "exact_timestamp": False,
                "exact_duration": False,
            },
            "metrics": rows,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"

    def purge_expired(self, *, observed_at: datetime | None = None) -> int:
        if not self.enabled:
            return 0
        cutoff = (
            _utc(observed_at).date() - timedelta(days=ADOPTION_METRICS_RETENTION_DAYS - 1)
        ).isoformat()
        try:
            self._ensure_database()
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                removed = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM adoption_metric WHERE day < ?", (cutoff,)
                    ).fetchone()[0]
                )
                connection.execute("DELETE FROM adoption_metric WHERE day < ?", (cutoff,))
                connection.commit()
                return removed
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        except (OSError, sqlite3.Error, AdoptionMetricsError) as exc:
            raise AdoptionMetricsError("adoption_metrics_unavailable") from exc

    def ready(self) -> bool:
        if not self.enabled:
            return True
        try:
            self._ensure_database()
            connection = self._connect(query_only=True)
            try:
                result = connection.execute("PRAGMA quick_check").fetchone()
                return result is not None and result[0] == "ok"
            finally:
                connection.close()
        except (OSError, sqlite3.Error, AdoptionMetricsError):
            return False

    def _ensure_database(self) -> None:
        if not self.path.exists() and not self.path.is_symlink():
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            connection = sqlite3.connect(self.path)
            try:
                connection.execute("PRAGMA journal_mode = DELETE")
                connection.execute("PRAGMA synchronous = FULL")
                connection.executescript(
                    """
                    CREATE TABLE adoption_metric (
                        day TEXT NOT NULL,
                        flow TEXT NOT NULL,
                        phase TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        duration_bucket TEXT NOT NULL,
                        event_count INTEGER NOT NULL CHECK (event_count >= 1),
                        PRIMARY KEY (day, flow, phase, outcome, duration_bucket)
                    );
                    PRAGMA user_version = 1;
                    """
                )
                connection.commit()
            finally:
                connection.close()
        self._validate_file()
        connection = self._connect(query_only=True, validate_schema=False)
        try:
            columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(adoption_metric)")}
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            if (
                int(connection.execute("PRAGMA user_version").fetchone()[0]) != ADOPTION_METRICS_SCHEMA_VERSION
                or tables != {"adoption_metric"}
                or columns != ADOPTION_METRICS_COLUMNS
            ):
                raise AdoptionMetricsError("adoption_metrics_invalid")
            rows = connection.execute(
                "SELECT day, flow, phase, outcome, duration_bucket, event_count FROM adoption_metric"
            ).fetchall()
            if len(rows) > ADOPTION_METRICS_MAX_ROWS or any(
                not _valid_row(row) for row in rows
            ):
                raise AdoptionMetricsError("adoption_metrics_invalid")
        finally:
            connection.close()

    def _connect(self, *, query_only: bool = False, validate_schema: bool = True) -> sqlite3.Connection:
        self._validate_file()
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA trusted_schema = OFF")
        if query_only:
            connection.execute("PRAGMA query_only = ON")
        if validate_schema and int(connection.execute("PRAGMA user_version").fetchone()[0]) != ADOPTION_METRICS_SCHEMA_VERSION:
            connection.close()
            raise AdoptionMetricsError("adoption_metrics_invalid")
        return connection

    def _validate_file(self) -> None:
        metadata = self.path.lstat()
        if (
            self.path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or metadata.st_size > ADOPTION_METRICS_MAX_BYTES
        ):
            raise AdoptionMetricsError("adoption_metrics_invalid")


def _utc(value: datetime | None) -> datetime:
    resolved = value or datetime.now(timezone.utc)
    if resolved.tzinfo is None or resolved.utcoffset() is None:
        raise AdoptionMetricsError("adoption_metrics_invalid")
    return resolved.astimezone(timezone.utc)


def _outcome(status_code: int) -> str:
    if 200 <= status_code < 300:
        return "succeeded"
    if status_code in {401, 403}:
        return "denied"
    if status_code == 429:
        return "throttled"
    if 400 <= status_code < 500:
        return "invalid"
    return "failed"


def _duration_bucket(duration_ms: int) -> str:
    value = max(0, min(int(duration_ms), 3_600_000))
    for upper, label in _DURATION_BUCKETS:
        if value < upper:
            return label
    return "gte_60s"


def _valid_row(row: sqlite3.Row) -> bool:
    try:
        datetime.strptime(str(row["day"]), "%Y-%m-%d")
    except ValueError:
        return False
    count = row["event_count"]
    return (
        (str(row["flow"]), str(row["phase"])) in _DIMENSIONS
        and str(row["outcome"]) in _OUTCOMES
        and str(row["duration_bucket"]) in _BUCKETS
        and isinstance(count, int)
        and not isinstance(count, bool)
        and 1 <= count <= 9_223_372_036_854_775_807
    )
