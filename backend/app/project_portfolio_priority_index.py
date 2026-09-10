"""Private, rebuildable priority facts for large project portfolios.

The index is never authoritative. It stores opaque project identifiers, closed
signals, counters and keyed name lookup tokens. Project names, paths, evidence,
components and free text remain exclusively in their authoritative stores.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
from uuid import uuid4

from app.models import ProjectPortfolioItem, ProjectPortfolioSearchRequest, ProjectRecord
from app.project_reference_index import project_reference_record_digest


PORTFOLIO_PRIORITY_INDEX_SCHEMA_VERSION = 2
PORTFOLIO_PRIORITY_INDEX_MAX_BYTES = 256 * 1024 * 1024
PORTFOLIO_PRIORITY_INDEX_MAX_PROJECTS = 20_000
PORTFOLIO_PRIORITY_INDEX_MAX_NAME_LENGTH = 120
PORTFOLIO_PRIORITY_INDEX_COLUMNS = {
    "portfolio_priority_metadata": {"key", "value"},
    "portfolio_priority_owner_state": {
        "owner_id", "source_revision", "key_marker", "project_count",
        "prefix_count", "projection_digest", "built_at_micros", "valid_until_micros",
    },
    "portfolio_priority_fact": {
        "project_id", "owner_id", "project_record_digest", "fact_digest",
        "priority", "priority_rank", "kev", "critical", "high", "medium",
        "low", "new_findings", "source_type", "operational_state",
        "coverage_state", "public_state", "baseline_available",
        "responsibility_state", "updated_at_micros", "name_rank",
        "exact_name_token", "partial_data", "stale_or_failed",
        "pending_actions", "ambiguous_channel",
    },
    "portfolio_priority_name_prefix": {"owner_id", "token", "project_id"},
}
_OWNER = re.compile(r"^(?:local-admin|[a-f0-9]{32})$")
_ID = re.compile(r"^[a-f0-9]{32}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_PROCESS_KEY = secrets.token_bytes(32)
_PRIORITY_RANK = {"urgent": 0, "high": 1, "review": 2, "monitor": 3}


class ProjectPortfolioPriorityIndexError(RuntimeError):
    pass


@dataclass(frozen=True)
class PortfolioPriorityRow:
    project_id: str
    project_record_digest: str
    fact_digest: str
    priority: str
    kev: int
    critical: int
    high: int
    medium: int
    low: int
    new_findings: int
    source_type: str
    operational_state: str
    coverage_state: str
    public_state: str
    baseline_available: bool
    responsibility_state: str
    updated_at_micros: int
    name_rank: int
    partial_data: bool
    stale_or_failed: bool
    pending_actions: int
    ambiguous_channel: bool


@dataclass(frozen=True)
class PortfolioPrioritySearchResult:
    rows: list[PortfolioPriorityRow]
    total_projects: int
    filtered_projects: int
    summary: dict[str, int]
    ambiguous_channels: int
    projection_digest: str


class ProjectPortfolioPriorityIndex:
    def __init__(self, settings) -> None:
        self.settings = settings
        self.path = settings.results_dir / "project_portfolio_priority_index.sqlite3"
        configured_key = getattr(settings, "portfolio_index_hmac_key", None)
        if configured_key is not None and (
            not isinstance(configured_key, bytes) or len(configured_key) != 32
        ):
            raise ProjectPortfolioPriorityIndexError(
                "portfolio_priority_index_key_invalid"
            )
        self._key = configured_key if configured_key is not None else _PROCESS_KEY
        self._configured_key = configured_key is not None
        self._key_marker = hmac.new(
            self._key,
            b"inspectra-portfolio-priority-index-key-v1",
            hashlib.sha256,
        ).hexdigest()
        self._built_owners: set[str] = set()

    def source_revision(self) -> str:
        sources = (
            self.settings.projects_dir,
            self.settings.jobs_dir,
            self.settings.public_advisories_dir,
            self.settings.finding_decisions_dir,
            self.settings.resolved_auth_state_db_path,
        )
        states = [_path_state(path) for path in sources]
        return hashlib.sha256(
            json.dumps(states, separators=(",", ":")).encode("ascii")
        ).hexdigest()

    def is_current(self, *, owner_id: str, source_revision: str, observed_at_micros: int) -> bool:
        self._validate_owner(owner_id)
        try:
            self._ensure_database()
            connection = self._connect(query_only=True)
            try:
                row = connection.execute(
                    "SELECT source_revision, key_marker, built_at_micros, valid_until_micros FROM portfolio_priority_owner_state WHERE owner_id = ?",
                    (owner_id,),
                ).fetchone()
                configured_markers = connection.execute(
                    "SELECT DISTINCT key_marker FROM portfolio_priority_owner_state LIMIT 2"
                ).fetchall()
            finally:
                connection.close()
            if self._configured_key and any(
                not hmac.compare_digest(str(marker[0]), self._key_marker)
                for marker in configured_markers
            ):
                raise ProjectPortfolioPriorityIndexError(
                    "portfolio_priority_index_key_mismatch"
                )
            return (
                owner_id in self._built_owners
                and row is not None
                and hmac.compare_digest(str(row[0]), source_revision)
                and hmac.compare_digest(str(row[1]), self._key_marker)
                and int(row[2]) <= observed_at_micros < int(row[3])
            )
        except ProjectPortfolioPriorityIndexError as exc:
            if str(exc) == "portfolio_priority_index_key_mismatch":
                raise
            self._reset_database()
            return False
        except (OSError, sqlite3.Error):
            self._reset_database()
            return False

    def rebuild_owner(
        self,
        *,
        owner_id: str,
        source_revision: str,
        built_at_micros: int,
        valid_until_micros: int,
        projects: list[ProjectRecord],
        items: list[ProjectPortfolioItem],
    ) -> None:
        self._validate_owner(owner_id)
        if (
            len(projects) != len(items)
            or len(projects) > PORTFOLIO_PRIORITY_INDEX_MAX_PROJECTS
            or valid_until_micros <= built_at_micros
        ):
            raise ProjectPortfolioPriorityIndexError("portfolio_priority_index_limit")
        projects_by_id = {project.id: project for project in projects}
        items_by_id = {item.project.id: item for item in items}
        if (
            len(projects_by_id) != len(projects)
            or set(projects_by_id) != set(items_by_id)
            or any(project.owner_id != owner_id for project in projects)
        ):
            raise ProjectPortfolioPriorityIndexError("portfolio_priority_index_invalid")
        ordered_names = sorted(
            projects,
            key=lambda project: (_validated_name(project.name).casefold(), project.id),
        )
        name_ranks = {project.id: rank for rank, project in enumerate(ordered_names)}
        prefix_count = sum(len(_validated_name(project.name)) for project in projects)
        prepared = [
            (
                project,
                priority_row(
                    items_by_id[project.id],
                    project=project,
                    name_rank=name_ranks[project.id],
                ),
            )
            for project in sorted(projects, key=lambda value: value.id)
        ]
        projection_digest = hashlib.sha256(
            json.dumps(
                [(row.project_id, row.fact_digest) for _project, row in prepared],
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()
        self._ensure_database()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing_keys = connection.execute(
                "SELECT DISTINCT key_marker FROM portfolio_priority_owner_state LIMIT 2"
            ).fetchall()
            if self._configured_key and any(
                not hmac.compare_digest(str(existing_key[0]), self._key_marker)
                for existing_key in existing_keys
            ):
                raise ProjectPortfolioPriorityIndexError(
                    "portfolio_priority_index_key_mismatch"
                )
            connection.execute(
                """
                INSERT INTO portfolio_priority_owner_state
                    (owner_id, source_revision, key_marker, project_count, prefix_count, projection_digest,
                     built_at_micros, valid_until_micros)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(owner_id) DO UPDATE SET
                    source_revision = excluded.source_revision,
                    key_marker = excluded.key_marker,
                    project_count = excluded.project_count,
                    prefix_count = excluded.prefix_count,
                    projection_digest = excluded.projection_digest,
                    built_at_micros = excluded.built_at_micros,
                    valid_until_micros = excluded.valid_until_micros
                """,
                (
                    owner_id, source_revision, self._key_marker, len(projects), prefix_count,
                    projection_digest,
                    built_at_micros, valid_until_micros,
                ),
            )
            connection.execute(
                "DELETE FROM portfolio_priority_fact WHERE owner_id = ?", (owner_id,)
            )
            for project, row in prepared:
                connection.execute(
                    """
                    INSERT INTO portfolio_priority_fact (
                        project_id, owner_id, project_record_digest, fact_digest,
                        priority, priority_rank, kev, critical, high, medium, low,
                        new_findings, source_type, operational_state, coverage_state,
                        public_state, baseline_available, responsibility_state,
                        updated_at_micros, name_rank, exact_name_token, partial_data,
                        stale_or_failed, pending_actions, ambiguous_channel
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row.project_id, owner_id, row.project_record_digest, row.fact_digest,
                        row.priority, _PRIORITY_RANK[row.priority], row.kev, row.critical,
                        row.high, row.medium, row.low, row.new_findings, row.source_type,
                        row.operational_state, row.coverage_state, row.public_state,
                        int(row.baseline_available), row.responsibility_state,
                        row.updated_at_micros, row.name_rank,
                        _name_token(self._key, owner_id, "exact", project.name.casefold()),
                        int(row.partial_data), int(row.stale_or_failed), row.pending_actions,
                        int(row.ambiguous_channel),
                    ),
                )
                folded = project.name.casefold()
                connection.executemany(
                    "INSERT INTO portfolio_priority_name_prefix (owner_id, token, project_id) VALUES (?, ?, ?)",
                    [
                        (owner_id, _name_token(self._key, owner_id, "prefix", folded[:length]), project.id)
                        for length in range(1, len(folded) + 1)
                    ],
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        _validate_file(self.path)
        self._built_owners.add(owner_id)

    def search(
        self,
        *,
        owner_id: str,
        payload: ProjectPortfolioSearchRequest,
        offset: int,
    ) -> PortfolioPrioritySearchResult:
        self._validate_owner(owner_id)
        if offset < 0 or offset > PORTFOLIO_PRIORITY_INDEX_MAX_PROJECTS:
            raise ProjectPortfolioPriorityIndexError("portfolio_priority_index_invalid")
        self._ensure_database()
        connection = self._connect(query_only=True)
        try:
            connection.execute("BEGIN")
            clauses = ["owner_id = ?"]
            parameters: list[object] = [owner_id]
            if payload.search:
                mode = payload.search_mode
                token = _name_token(self._key, owner_id, mode, payload.search.casefold())
                if mode == "exact":
                    clauses.append("exact_name_token = ?")
                else:
                    clauses.append(
                        "EXISTS (SELECT 1 FROM portfolio_priority_name_prefix AS prefix "
                        "WHERE prefix.owner_id = portfolio_priority_fact.owner_id "
                        "AND prefix.project_id = portfolio_priority_fact.project_id AND prefix.token = ?)"
                    )
                parameters.append(token)
            field_filters = (
                ("priority", payload.priority),
                ("source_type", payload.source_type),
                ("operational_state", payload.operational_state),
                ("coverage_state", payload.coverage),
                ("public_state", payload.public_intelligence),
                ("responsibility_state", payload.responsibility),
            )
            for column, value in field_filters:
                if value is not None:
                    clauses.append(f"{column} = ?")
                    parameters.append(value)
            if payload.severity is not None:
                clauses.append(f"{payload.severity} > 0")
            if payload.baseline is not None:
                clauses.append("baseline_available = ?")
                parameters.append(int(payload.baseline == "available"))
            where = " AND ".join(clauses)
            state = connection.execute(
                "SELECT project_count, prefix_count, projection_digest FROM portfolio_priority_owner_state WHERE owner_id = ?",
                (owner_id,),
            ).fetchone()
            fact_count = int(connection.execute(
                "SELECT COUNT(*) FROM portfolio_priority_fact WHERE owner_id = ?", (owner_id,)
            ).fetchone()[0])
            prefix_state = connection.execute(
                "SELECT COUNT(*), COUNT(DISTINCT project_id) FROM portfolio_priority_name_prefix WHERE owner_id = ?",
                (owner_id,),
            ).fetchone()
            aggregates = connection.execute(
                f"""
                SELECT COUNT(*) AS filtered_projects,
                       COALESCE(SUM(priority = 'urgent'), 0) AS urgent_projects,
                       COALESCE(SUM(priority = 'high'), 0) AS high_priority_projects,
                       COALESCE(SUM(kev > 0), 0) AS projects_with_kev,
                       COALESCE(SUM(baseline_available = 0), 0) AS projects_without_baseline,
                       COALESCE(SUM(partial_data), 0) AS projects_with_partial_data,
                       COALESCE(SUM(stale_or_failed), 0) AS stale_or_failed_intelligence,
                       COALESCE(SUM(pending_actions), 0) AS pending_actions,
                       COALESCE(SUM(ambiguous_channel), 0) AS ambiguous_channels
                FROM portfolio_priority_fact WHERE {where}
                """,
                tuple(parameters),
            ).fetchone()
            order = {
                "name": "name_rank ASC, project_id ASC",
                "updated": "updated_at_micros DESC, project_id ASC",
                "priority": (
                    "priority_rank ASC, kev DESC, critical DESC, high DESC, "
                    "new_findings DESC, name_rank ASC, project_id ASC"
                ),
            }[payload.sort]
            raw = connection.execute(
                f"SELECT * FROM portfolio_priority_fact WHERE {where} ORDER BY {order} LIMIT ? OFFSET ?",
                (*parameters, payload.page_size, offset),
            ).fetchall()
        finally:
            connection.close()
        if (
            state is None
            or int(state[0]) != fact_count
            or prefix_state is None
            or int(prefix_state[0]) != int(state[1])
            or int(prefix_state[1]) != fact_count
            or _DIGEST.fullmatch(str(state[2])) is None
        ):
            raise ProjectPortfolioPriorityIndexError("portfolio_priority_index_invalid")
        rows = [_row_from_sql(row) for row in raw]
        assert aggregates is not None
        summary = {
            key: int(aggregates[key])
            for key in (
                "urgent_projects", "high_priority_projects", "projects_with_kev",
                "projects_without_baseline", "projects_with_partial_data",
                "stale_or_failed_intelligence", "pending_actions",
            )
        }
        return PortfolioPrioritySearchResult(
            rows=rows,
            total_projects=fact_count,
            filtered_projects=int(aggregates["filtered_projects"]),
            summary=summary,
            ambiguous_channels=int(aggregates["ambiguous_channels"]),
            projection_digest=str(state[2]),
        )

    def ready(self) -> bool:
        try:
            self._ensure_database()
            connection = self._connect(query_only=True)
            try:
                result = connection.execute("PRAGMA quick_check").fetchone()
                return result is not None and result[0] == "ok"
            finally:
                connection.close()
        except (OSError, sqlite3.Error, ProjectPortfolioPriorityIndexError):
            return False

    def _ensure_database(self) -> None:
        if self.path.exists() or self.path.is_symlink():
            _validate_file(self.path)
            connection = self._connect(query_only=True, validate_version=False)
            try:
                version = connection.execute(
                    "SELECT value FROM portfolio_priority_metadata WHERE key = 'schema_version'"
                ).fetchone()
                integrity = connection.execute("PRAGMA quick_check").fetchone()
                if version is None or version[0] != str(PORTFOLIO_PRIORITY_INDEX_SCHEMA_VERSION) or integrity is None or integrity[0] != "ok":
                    raise ProjectPortfolioPriorityIndexError("portfolio_priority_index_invalid")
            finally:
                connection.close()
            return
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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
                CREATE TABLE portfolio_priority_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE portfolio_priority_owner_state (
                    owner_id TEXT PRIMARY KEY, source_revision TEXT NOT NULL,
                    key_marker TEXT NOT NULL, project_count INTEGER NOT NULL,
                    prefix_count INTEGER NOT NULL, projection_digest TEXT NOT NULL,
                    built_at_micros INTEGER NOT NULL, valid_until_micros INTEGER NOT NULL
                );
                CREATE TABLE portfolio_priority_fact (
                    project_id TEXT NOT NULL, owner_id TEXT NOT NULL,
                    project_record_digest TEXT NOT NULL, fact_digest TEXT NOT NULL,
                    priority TEXT NOT NULL, priority_rank INTEGER NOT NULL,
                    kev INTEGER NOT NULL, critical INTEGER NOT NULL, high INTEGER NOT NULL,
                    medium INTEGER NOT NULL, low INTEGER NOT NULL, new_findings INTEGER NOT NULL,
                    source_type TEXT NOT NULL, operational_state TEXT NOT NULL,
                    coverage_state TEXT NOT NULL, public_state TEXT NOT NULL,
                    baseline_available INTEGER NOT NULL, responsibility_state TEXT NOT NULL,
                    updated_at_micros INTEGER NOT NULL, name_rank INTEGER NOT NULL,
                    exact_name_token BLOB NOT NULL, partial_data INTEGER NOT NULL,
                    stale_or_failed INTEGER NOT NULL, pending_actions INTEGER NOT NULL,
                    ambiguous_channel INTEGER NOT NULL,
                    PRIMARY KEY (project_id, owner_id),
                    FOREIGN KEY (owner_id) REFERENCES portfolio_priority_owner_state(owner_id) ON DELETE CASCADE
                );
                CREATE TABLE portfolio_priority_name_prefix (
                    owner_id TEXT NOT NULL, token BLOB NOT NULL, project_id TEXT NOT NULL,
                    PRIMARY KEY (owner_id, token, project_id),
                    FOREIGN KEY (project_id, owner_id)
                        REFERENCES portfolio_priority_fact(project_id, owner_id) ON DELETE CASCADE
                );
                CREATE INDEX portfolio_priority_owner_rank ON portfolio_priority_fact
                    (owner_id, priority_rank, kev DESC, critical DESC, high DESC, new_findings DESC, name_rank, project_id);
                CREATE INDEX portfolio_priority_owner_updated ON portfolio_priority_fact
                    (owner_id, updated_at_micros DESC, project_id);
                CREATE INDEX portfolio_priority_prefix ON portfolio_priority_name_prefix
                    (owner_id, token, project_id);
                """
            )
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(
                "INSERT INTO portfolio_priority_metadata (key, value) VALUES ('schema_version', ?)",
                (str(PORTFOLIO_PRIORITY_INDEX_SCHEMA_VERSION),),
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
        except Exception:
            if connection is not None:
                connection.close()
            temporary.unlink(missing_ok=True)
            raise
        _validate_file(self.path)

    def _connect(self, *, query_only: bool = False, validate_version: bool = True) -> sqlite3.Connection:
        _validate_file(self.path)
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA foreign_keys = ON")
        if query_only:
            connection.execute("PRAGMA query_only = ON")
        if validate_version:
            row = connection.execute(
                "SELECT value FROM portfolio_priority_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if row is None or row[0] != str(PORTFOLIO_PRIORITY_INDEX_SCHEMA_VERSION):
                connection.close()
                raise ProjectPortfolioPriorityIndexError("portfolio_priority_index_invalid")
        return connection

    def _reset_database(self) -> None:
        self._built_owners.clear()
        for candidate in (self.path, Path(f"{self.path}-wal"), Path(f"{self.path}-shm"), Path(f"{self.path}-journal")):
            try:
                candidate.unlink(missing_ok=True)
            except OSError:
                pass

    @staticmethod
    def _validate_owner(owner_id: str) -> None:
        if _OWNER.fullmatch(owner_id) is None:
            raise ProjectPortfolioPriorityIndexError("portfolio_priority_index_invalid")


def priority_row(
    item: ProjectPortfolioItem, *, project: ProjectRecord, name_rank: int
) -> PortfolioPriorityRow:
    if item.project.id != project.id or item.project.owner_id != project.owner_id:
        raise ProjectPortfolioPriorityIndexError("portfolio_priority_index_invalid")
    partial = (
        item.coverage.state in {"partial", "unknown", "lost"}
        or item.public_intelligence_state in {"stale", "partial", "failed"}
        or item.changes.state == "not_comparable"
    )
    values = {
        "project_id": project.id,
        "project_record_digest": project_reference_record_digest(project),
        "priority": item.priority,
        "kev": item.finding_counts.kev,
        "critical": item.finding_counts.critical,
        "high": item.finding_counts.high,
        "medium": item.finding_counts.medium,
        "low": item.finding_counts.low,
        "new_findings": item.changes.new + item.changes.public_new,
        "source_type": item.source_type,
        "operational_state": item.operational_state,
        "coverage_state": item.coverage.state,
        "public_state": item.public_intelligence_state,
        "baseline_available": item.project.baseline_analysis_id is not None,
        "responsibility_state": item.responsibility.state,
        "updated_at_micros": _micros(project.updated_at),
        "name_rank": name_rank,
        "partial_data": partial,
        "stale_or_failed": item.public_intelligence_state in {"stale", "partial", "failed"},
        "pending_actions": item.pending_actions,
        "ambiguous_channel": item.source_type_detail == "commit_attributed_channel_ambiguous",
    }
    digest = _fact_digest(values)
    return PortfolioPriorityRow(fact_digest=digest, **values)


def _matches_row(row: PortfolioPriorityRow, payload: ProjectPortfolioSearchRequest) -> bool:
    return not (
        (payload.priority is not None and row.priority != payload.priority)
        or (payload.severity is not None and getattr(row, payload.severity) == 0)
        or (payload.source_type is not None and row.source_type != payload.source_type)
        or (payload.operational_state is not None and row.operational_state != payload.operational_state)
        or (payload.coverage is not None and row.coverage_state != payload.coverage)
        or (payload.public_intelligence is not None and row.public_state != payload.public_intelligence)
        or (payload.baseline is not None and row.baseline_available != (payload.baseline == "available"))
        or (payload.responsibility is not None and row.responsibility_state != payload.responsibility)
    )


def _row_sort_key(row: PortfolioPriorityRow, sort: str) -> tuple[object, ...]:
    if sort == "name":
        return (row.name_rank, row.project_id)
    if sort == "updated":
        return (-row.updated_at_micros, row.project_id)
    return (
        _PRIORITY_RANK[row.priority], -row.kev, -row.critical, -row.high,
        -row.new_findings, row.name_rank, row.project_id,
    )


def _row_from_sql(row: sqlite3.Row) -> PortfolioPriorityRow:
    raw_booleans = (
        row["baseline_available"], row["partial_data"], row["stale_or_failed"],
        row["ambiguous_channel"],
    )
    result = PortfolioPriorityRow(
        project_id=str(row["project_id"]),
        project_record_digest=str(row["project_record_digest"]),
        fact_digest=str(row["fact_digest"]),
        priority=str(row["priority"]), kev=int(row["kev"]), critical=int(row["critical"]),
        high=int(row["high"]), medium=int(row["medium"]), low=int(row["low"]),
        new_findings=int(row["new_findings"]), source_type=str(row["source_type"]),
        operational_state=str(row["operational_state"]), coverage_state=str(row["coverage_state"]),
        public_state=str(row["public_state"]), baseline_available=bool(row["baseline_available"]),
        responsibility_state=str(row["responsibility_state"]),
        updated_at_micros=int(row["updated_at_micros"]), name_rank=int(row["name_rank"]),
        partial_data=bool(row["partial_data"]), stale_or_failed=bool(row["stale_or_failed"]),
        pending_actions=int(row["pending_actions"]), ambiguous_channel=bool(row["ambiguous_channel"]),
    )
    values = asdict(result)
    stored_digest = str(values.pop("fact_digest"))
    if (
        result.priority not in _PRIORITY_RANK
        or _ID.fullmatch(result.project_id) is None
        or _DIGEST.fullmatch(result.project_record_digest) is None
        or _DIGEST.fullmatch(stored_digest) is None
        or any(int(value) not in {0, 1} for value in raw_booleans)
        or int(row["priority_rank"]) != _PRIORITY_RANK.get(result.priority)
        or not isinstance(row["exact_name_token"], bytes)
        or len(row["exact_name_token"]) != hashlib.sha256().digest_size
        or result.source_type not in {"archive", "git_or_ci", "sbom"}
        or result.operational_state not in {
            "no_analysis", "queued", "running", "cancelling", "cancelled", "failed", "completed"
        }
        or result.coverage_state not in {"complete", "partial", "unknown", "lost"}
        or result.public_state not in {"fresh", "stale", "partial", "failed", "disabled", "not_requested"}
        or result.responsibility_state not in {"assigned", "multiple", "unassigned"}
        or any(
            value < 0
            for value in (
                result.kev, result.critical, result.high, result.medium, result.low,
                result.new_findings, result.updated_at_micros, result.name_rank,
                result.pending_actions,
            )
        )
        or not hmac.compare_digest(stored_digest, _fact_digest(values))
    ):
        raise ProjectPortfolioPriorityIndexError("portfolio_priority_index_invalid")
    return result


def _fact_digest(values: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(values, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _name_token(key: bytes, owner_id: str, mode: str, value: str) -> bytes:
    return hmac.new(
        key,
        b"inspectra-portfolio-name-v1\0" + owner_id.encode("ascii") + b"\0"
        + mode.encode("ascii") + b"\0" + value.encode("utf-8"),
        hashlib.sha256,
    ).digest()


def _validated_name(value: str) -> str:
    if not 1 <= len(value) <= PORTFOLIO_PRIORITY_INDEX_MAX_NAME_LENGTH or any(ord(char) < 32 for char in value):
        raise ProjectPortfolioPriorityIndexError("portfolio_priority_index_invalid")
    return value


def _micros(value) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ProjectPortfolioPriorityIndexError("portfolio_priority_index_invalid")
    return int(value.timestamp() * 1_000_000)


def _path_state(path: Path) -> list[int | str]:
    if not path.exists() and not path.is_symlink():
        return ["missing"]
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
        raise ProjectPortfolioPriorityIndexError("portfolio_priority_index_source_invalid")
    return [metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns]


def _validate_file(path: Path) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > PORTFOLIO_PRIORITY_INDEX_MAX_BYTES
        or metadata.st_mode & 0o077
    ):
        raise ProjectPortfolioPriorityIndexError("portfolio_priority_index_invalid")
