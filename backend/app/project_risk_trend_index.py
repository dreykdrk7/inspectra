"""Private, rebuildable materialization for organization risk trends.

The authoritative job, public-intelligence, project and lifecycle JSON records
remain the source of truth.  This index retains only opaque references,
digests, closed dimensions and aggregate counters needed by the trends API.
It deliberately excludes project names, source paths, package/component names,
finding text, evidence and decision text.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any, Iterator
from uuid import uuid4

from app.active_job_index import active_job_record_digest
from app.finding_lifecycle import FindingLifecycleError
from app.models import FindingDecisionRecord, JobRecord, ProjectRecord
from app.project_coverage import build_project_analysis_coverage
from app.project_portfolio import _current_decisions, _local_findings, _public_findings
from app.risk_trend_source_clock import RiskTrendSourceClock, RiskTrendSourceClockError


RISK_TREND_INDEX_SCHEMA_VERSION = 2
RISK_TREND_INDEX_MAX_BYTES = 256 * 1024 * 1024
RISK_TREND_INDEX_MAX_ANALYSES = 250_000
RISK_TREND_INDEX_SAMPLE_SIZE = 8
RISK_TREND_INDEX_COLUMNS = {
    "risk_trend_metadata": {"key", "value"},
    "risk_trend_owner_state": {
        "owner_id", "source_revision", "analysis_count", "rebuilt_at_micros",
    },
    "risk_trend_refresh_state": {
        "owner_id", "desired_revision", "built_revision", "state",
        "requested_at_micros", "started_at_micros", "completed_at_micros",
        "failure_code", "attempt_count",
    },
    "risk_trend_analysis_fact": {
        "job_id", "owner_id", "project_ref", "occurred_at_micros", "record_digest",
        "source_type", "is_current", "transition_state", "public_exclusion",
        "public_invalid", "local_new", "local_persistent", "local_resolved",
        "high_new", "public_new", "public_persistent", "public_resolved",
        "coverage_gained", "coverage_lost", "current_critical_high",
        "current_known_exploited",
    },
    "risk_trend_ecosystem_fact": {
        "job_id", "owner_id", "occurred_at_micros", "ecosystem", "current_findings",
        "comparable_transitions", "new_findings", "resolved_findings",
    },
    "risk_trend_duration_fact": {
        "id", "owner_id", "project_ref", "kind", "first_seen_at_micros",
        "completed_at_micros", "duration_hours",
    },
    "risk_trend_exception_fact": {
        "id", "owner_id", "project_ref", "review_at_micros",
    },
}
_OWNER = re.compile(r"^(?:local-admin|[a-f0-9]{32})$")
_ID = re.compile(r"^[a-f0-9]{32}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
class ProjectRiskTrendIndexError(RuntimeError):
    pass


@dataclass(frozen=True)
class _ProjectedFinding:
    severity: str
    ecosystem: str | None = None
    cvss_band: str | None = None
    known_exploited: bool = False


@dataclass(frozen=True)
class _ProjectedAnalysis:
    job_id: str
    project_ref: str
    occurred_at: datetime
    record_digest: str
    source_type: str
    analysis_profile: str | None
    profile_digest: str | None
    coverage: dict[str, Any] | None
    local_invalid: bool
    public_invalid: bool
    public_ready: bool
    local: dict[str, _ProjectedFinding]
    public: dict[str, _ProjectedFinding]


@dataclass(frozen=True)
class RiskTrendMaterializationStatus:
    state: str
    data_state: str
    refresh_in_progress: bool
    retryable: bool
    requested_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    failure_code: str | None


class ProjectRiskTrendIndex:
    """Materialize and query safe trend facts for one organization at a time."""

    def __init__(self, settings, projects, jobs, vulnerability_store, decisions) -> None:
        self.settings = settings
        self.projects = projects
        self.jobs = jobs
        self.vulnerability_store = vulnerability_store
        self.decisions = decisions
        self.path = settings.results_dir / "project_risk_trend_index.sqlite3"
        self._built_owners: set[str] = set()
        self.source_clock = RiskTrendSourceClock(settings)

    def query(
        self,
        *,
        organization_id: str,
        projects: list[ProjectRecord],
        cutoff: datetime,
        observed_at: datetime,
        bucket_days: int,
    ) -> dict[str, Any]:
        if (
            not _OWNER.fullmatch(organization_id)
            or cutoff.tzinfo is None
            or observed_at.tzinfo is None
            or bucket_days not in {7, 30}
        ):
            raise ProjectRiskTrendIndexError("risk_trend_index_invalid")
        for _attempt in range(2):
            self._ensure_owner(organization_id, projects)
            revision_before = self._source_revision(organization_id)
            index_state_before = _file_state(self.path)
            connection = self._connect(query_only=True)
            try:
                self._validate_sample(connection, organization_id)
                result = self._query(
                    connection, organization_id, projects, cutoff, observed_at, bucket_days
                )
                owner_state = connection.execute(
                    "SELECT source_revision FROM risk_trend_owner_state WHERE owner_id = ?",
                    (organization_id,),
                ).fetchone()
            finally:
                connection.close()
            if (
                owner_state is not None
                and owner_state[0] == revision_before
                and self._source_revision(organization_id) == revision_before
                and _file_state(self.path) == index_state_before
            ):
                return result
        raise ProjectRiskTrendIndexError("risk_trend_index_source_changed")

    def ready(self) -> bool:
        """Validate the materialization without leaking tenant counts."""

        try:
            self._ensure_database()
            connection = self._connect(query_only=True)
            try:
                result = connection.execute("PRAGMA quick_check").fetchone()
                return result is not None and result[0] == "ok"
            finally:
                connection.close()
        except (OSError, sqlite3.Error, ProjectRiskTrendIndexError):
            return False

    def request_refresh(
        self,
        *,
        organization_id: str,
        observed_at: datetime,
        force: bool = False,
    ) -> RiskTrendMaterializationStatus:
        """Durably coalesce one owner refresh without rebuilding in the caller."""

        if not _OWNER.fullmatch(organization_id) or observed_at.tzinfo is None:
            raise ProjectRiskTrendIndexError("risk_trend_index_invalid")
        for attempt in range(2):
            try:
                self._ensure_database()
                desired_revision = self._source_revision(organization_id)
                now_micros = _micros(observed_at)
                connection = self._connect()
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    owner_state = connection.execute(
                        "SELECT source_revision, rebuilt_at_micros FROM risk_trend_owner_state WHERE owner_id = ?",
                        (organization_id,),
                    ).fetchone()
                    refresh = connection.execute(
                        "SELECT * FROM risk_trend_refresh_state WHERE owner_id = ?",
                        (organization_id,),
                    ).fetchone()
                    owner_is_current = (
                        owner_state is not None
                        and hmac_compare(str(owner_state["source_revision"]), desired_revision)
                    )
                    if owner_is_current and not force:
                        requested = (
                            int(refresh["requested_at_micros"])
                            if refresh is not None else now_micros
                        )
                        connection.execute(
                            """
                            INSERT INTO risk_trend_refresh_state (
                                owner_id, desired_revision, built_revision, state,
                                requested_at_micros, started_at_micros,
                                completed_at_micros, failure_code, attempt_count
                            ) VALUES (?, ?, ?, 'ready', ?, NULL, ?, NULL, ?)
                            ON CONFLICT(owner_id) DO UPDATE SET
                                desired_revision = excluded.desired_revision,
                                built_revision = excluded.built_revision,
                                state = 'ready',
                                requested_at_micros = excluded.requested_at_micros,
                                started_at_micros = NULL,
                                completed_at_micros = excluded.completed_at_micros,
                                failure_code = NULL,
                                attempt_count = excluded.attempt_count
                            """,
                            (
                                organization_id,
                                desired_revision,
                                desired_revision,
                                requested,
                                int(owner_state["rebuilt_at_micros"]),
                                int(refresh["attempt_count"]) if refresh is not None else 0,
                            ),
                        )
                    elif (
                        refresh is not None
                        and hmac_compare(str(refresh["desired_revision"]), desired_revision)
                        and (
                            str(refresh["state"]) in {"queued", "rebuilding"}
                            or (str(refresh["state"]) == "failed" and not force)
                        )
                    ):
                        pass
                    else:
                        connection.execute(
                            """
                            INSERT INTO risk_trend_refresh_state (
                                owner_id, desired_revision, built_revision, state,
                                requested_at_micros, started_at_micros,
                                completed_at_micros, failure_code, attempt_count
                            ) VALUES (?, ?, NULL, 'queued', ?, NULL, NULL, NULL, 0)
                            ON CONFLICT(owner_id) DO UPDATE SET
                                desired_revision = excluded.desired_revision,
                                state = 'queued',
                                requested_at_micros = excluded.requested_at_micros,
                                started_at_micros = NULL,
                                failure_code = NULL
                            """,
                            (organization_id, desired_revision, now_micros),
                        )
                    refresh_after = connection.execute(
                        "SELECT * FROM risk_trend_refresh_state WHERE owner_id = ?",
                        (organization_id,),
                    ).fetchone()
                    status = self._materialization_status_from_rows(
                        owner_state=owner_state,
                        refresh=refresh_after,
                        revision=desired_revision,
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
                finally:
                    connection.close()
                return status
            except (OSError, sqlite3.Error, ProjectRiskTrendIndexError):
                if attempt:
                    raise ProjectRiskTrendIndexError("risk_trend_index_invalid")
                self._reset_database()
        raise ProjectRiskTrendIndexError("risk_trend_index_invalid")

    def materialization_status(
        self,
        *,
        organization_id: str,
        observed_at: datetime,
        desired_revision: str | None = None,
    ) -> RiskTrendMaterializationStatus:
        if not _OWNER.fullmatch(organization_id) or observed_at.tzinfo is None:
            raise ProjectRiskTrendIndexError("risk_trend_index_invalid")
        self._ensure_database()
        revision = desired_revision or self._source_revision(organization_id)
        connection = self._connect(query_only=True)
        try:
            owner_state = connection.execute(
                "SELECT source_revision FROM risk_trend_owner_state WHERE owner_id = ?",
                (organization_id,),
            ).fetchone()
            refresh = connection.execute(
                "SELECT * FROM risk_trend_refresh_state WHERE owner_id = ?",
                (organization_id,),
            ).fetchone()
        finally:
            connection.close()
        return self._materialization_status_from_rows(
            owner_state=owner_state,
            refresh=refresh,
            revision=revision,
        )

    @staticmethod
    def _materialization_status_from_rows(
        *,
        owner_state: sqlite3.Row | None,
        refresh: sqlite3.Row | None,
        revision: str,
    ) -> RiskTrendMaterializationStatus:
        """Render status from rows already validated in the current connection."""

        has_data = owner_state is not None
        data_is_current = has_data and hmac_compare(
            str(owner_state["source_revision"]), revision
        )
        refresh_state = str(refresh["state"]) if refresh is not None else "queued"
        refresh_matches = refresh is not None and hmac_compare(
            str(refresh["desired_revision"]), revision
        )
        in_progress = refresh_matches and refresh_state in {"queued", "rebuilding"}
        if data_is_current:
            state = "rebuilding" if in_progress else "ready"
            data_state = "current"
        elif refresh_matches and refresh_state == "failed":
            state = "failed"
            data_state = "stale" if has_data else "unavailable"
        elif has_data:
            state = "stale"
            data_state = "stale"
        else:
            state = "rebuilding"
            data_state = "unavailable"
        return RiskTrendMaterializationStatus(
            state=state,
            data_state=data_state,
            refresh_in_progress=in_progress,
            retryable=state == "failed",
            requested_at=_from_micros(refresh["requested_at_micros"] if refresh else None),
            started_at=_from_micros(refresh["started_at_micros"] if refresh else None),
            completed_at=_from_micros(refresh["completed_at_micros"] if refresh else None),
            failure_code=(
                str(refresh["failure_code"])
                if refresh is not None and refresh["failure_code"] is not None
                else None
            ),
        )

    def query_available(
        self,
        *,
        organization_id: str,
        projects: list[ProjectRecord],
        cutoff: datetime,
        observed_at: datetime,
        bucket_days: int,
    ) -> dict[str, Any] | None:
        """Read the last atomically published owner projection without rebuilding."""

        if not _OWNER.fullmatch(organization_id):
            raise ProjectRiskTrendIndexError("risk_trend_index_invalid")
        for _attempt in range(2):
            self._ensure_database()
            index_state_before = _file_state(self.path)
            connection = self._connect(query_only=True)
            try:
                owner_state = connection.execute(
                    "SELECT 1 FROM risk_trend_owner_state WHERE owner_id = ?",
                    (organization_id,),
                ).fetchone()
                if owner_state is None:
                    return None
                self._validate_sample(connection, organization_id)
                result = self._query(
                    connection, organization_id, projects, cutoff, observed_at, bucket_days
                )
            finally:
                connection.close()
            if _file_state(self.path) == index_state_before:
                return result
        raise ProjectRiskTrendIndexError("risk_trend_index_source_changed")

    def discard_owner_and_request_refresh(
        self,
        *,
        organization_id: str,
        observed_at: datetime,
    ) -> RiskTrendMaterializationStatus:
        """Fail closed on semantic corruption without deleting another tenant."""

        if not _OWNER.fullmatch(organization_id) or observed_at.tzinfo is None:
            raise ProjectRiskTrendIndexError("risk_trend_index_invalid")
        try:
            self._ensure_database()
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                for table in (
                    "risk_trend_ecosystem_fact",
                    "risk_trend_duration_fact",
                    "risk_trend_exception_fact",
                    "risk_trend_analysis_fact",
                ):
                    connection.execute(
                        f"DELETE FROM {table} WHERE owner_id = ?",
                        (organization_id,),
                    )
                connection.execute(
                    "DELETE FROM risk_trend_owner_state WHERE owner_id = ?",
                    (organization_id,),
                )
                connection.execute(
                    "DELETE FROM risk_trend_refresh_state WHERE owner_id = ?",
                    (organization_id,),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
            self._built_owners.discard(organization_id)
        except (OSError, sqlite3.Error, ProjectRiskTrendIndexError):
            self._reset_database()
        return self.request_refresh(
            organization_id=organization_id,
            observed_at=observed_at,
            force=True,
        )

    def claim_refresh(self, *, organization_id: str, started_at: datetime) -> str | None:
        if not _OWNER.fullmatch(organization_id) or started_at.tzinfo is None:
            raise ProjectRiskTrendIndexError("risk_trend_index_invalid")
        self._ensure_database()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT desired_revision, state FROM risk_trend_refresh_state WHERE owner_id = ?",
                (organization_id,),
            ).fetchone()
            if row is None or str(row["state"]) != "queued":
                connection.rollback()
                return None
            connection.execute(
                """
                UPDATE risk_trend_refresh_state
                SET state = 'rebuilding', started_at_micros = ?, failure_code = NULL,
                    attempt_count = attempt_count + 1
                WHERE owner_id = ? AND state = 'queued'
                """,
                (_micros(started_at), organization_id),
            )
            connection.commit()
            return str(row["desired_revision"])
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def complete_refresh(
        self,
        *,
        organization_id: str,
        claimed_revision: str,
        completed_at: datetime,
    ) -> bool:
        """Publish ready state or coalesce one source change for another pass."""

        current_revision = self._source_revision(organization_id)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT desired_revision, state FROM risk_trend_refresh_state WHERE owner_id = ?",
                (organization_id,),
            ).fetchone()
            if (
                row is None
                or str(row["state"]) != "rebuilding"
                or not hmac_compare(str(row["desired_revision"]), claimed_revision)
            ):
                raise ProjectRiskTrendIndexError("risk_trend_refresh_claim_lost")
            if not hmac_compare(current_revision, claimed_revision):
                connection.execute(
                    """
                    UPDATE risk_trend_refresh_state
                    SET desired_revision = ?, state = 'queued', requested_at_micros = ?,
                        started_at_micros = NULL, failure_code = NULL
                    WHERE owner_id = ?
                    """,
                    (current_revision, _micros(completed_at), organization_id),
                )
                connection.commit()
                return True
            connection.execute(
                """
                UPDATE risk_trend_refresh_state
                SET built_revision = ?, state = 'ready', started_at_micros = NULL,
                    completed_at_micros = ?, failure_code = NULL
                WHERE owner_id = ?
                """,
                (claimed_revision, _micros(completed_at), organization_id),
            )
            connection.commit()
            return False
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def fail_refresh(
        self,
        *,
        organization_id: str,
        claimed_revision: str,
        failed_at: datetime,
        failure_code: str,
    ) -> bool:
        if failure_code not in {"limit", "source_changed", "rebuild_failed"}:
            failure_code = "rebuild_failed"
        current_revision = self._source_revision(organization_id)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            if not hmac_compare(current_revision, claimed_revision):
                connection.execute(
                    """
                    UPDATE risk_trend_refresh_state
                    SET desired_revision = ?, state = 'queued', requested_at_micros = ?,
                        started_at_micros = NULL, failure_code = NULL
                    WHERE owner_id = ? AND state = 'rebuilding'
                    """,
                    (current_revision, _micros(failed_at), organization_id),
                )
                connection.commit()
                return True
            connection.execute(
                """
                UPDATE risk_trend_refresh_state
                SET state = 'failed', started_at_micros = NULL, failure_code = ?
                WHERE owner_id = ? AND state = 'rebuilding'
                """,
                (failure_code, organization_id),
            )
            connection.commit()
            return False
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def recover_pending_refreshes(self) -> list[str]:
        """Turn interrupted rebuild claims back into bounded queued work."""

        self._ensure_database()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE risk_trend_refresh_state SET state = 'queued', started_at_micros = NULL WHERE state = 'rebuilding'"
            )
            rows = connection.execute(
                "SELECT owner_id FROM risk_trend_refresh_state WHERE state = 'queued' ORDER BY owner_id LIMIT 1000"
            ).fetchall()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        owners = [str(row["owner_id"]) for row in rows]
        if any(not _OWNER.fullmatch(owner) for owner in owners):
            raise ProjectRiskTrendIndexError("risk_trend_index_invalid")
        return owners

    def rebuild_owner(self, *, organization_id: str, projects: list[ProjectRecord]) -> None:
        if not _OWNER.fullmatch(organization_id):
            raise ProjectRiskTrendIndexError("risk_trend_index_invalid")
        self._ensure_database()
        self._rebuild_owner(organization_id, projects)

    def _ensure_owner(self, organization_id: str, projects: list[ProjectRecord]) -> None:
        try:
            self._ensure_database()
            revision = self._source_revision(organization_id)
            connection = self._connect(query_only=True)
            try:
                row = connection.execute(
                    "SELECT source_revision FROM risk_trend_owner_state WHERE owner_id = ?",
                    (organization_id,),
                ).fetchone()
            finally:
                connection.close()
            if row is None or row[0] != revision:
                self._rebuild_owner(organization_id, projects)
            elif organization_id not in self._built_owners:
                # A fresh process never adopts aggregate facts blindly. Rebuild
                # this tenant from authority before serving it.
                self._rebuild_owner(organization_id, projects)
        except (OSError, sqlite3.Error, ProjectRiskTrendIndexError):
            self._reset_database()
            self._rebuild_owner(organization_id, projects)

    def _rebuild_owner(self, organization_id: str, projects: list[ProjectRecord]) -> None:
        project_by_id = {
            project.id: project
            for project in projects
            if project.owner_id == organization_id and _ID.fullmatch(project.id)
        }
        if len(project_by_id) != len(projects):
            raise ProjectRiskTrendIndexError("risk_trend_index_invalid")
        try:
            grouped_decisions = self.decisions.list_for_projects(
                organization_id, set(project_by_id)
            )
        except FindingLifecycleError as exc:
            raise ProjectRiskTrendIndexError("risk_trend_index_source_invalid") from exc

        revision_before = self._source_revision(organization_id)
        connection = self._connect()
        analyses_seen = 0
        try:
            connection.execute("BEGIN IMMEDIATE")
            for table in (
                "risk_trend_ecosystem_fact",
                "risk_trend_duration_fact",
                "risk_trend_exception_fact",
                "risk_trend_analysis_fact",
            ):
                connection.execute(f"DELETE FROM {table} WHERE owner_id = ?", (organization_id,))
            for project in sorted(project_by_id.values(), key=lambda item: item.id):
                count = self._materialize_project(
                    connection,
                    organization_id=organization_id,
                    project=project,
                    decisions=grouped_decisions.get(project.id, []),
                )
                analyses_seen += count
                if analyses_seen > RISK_TREND_INDEX_MAX_ANALYSES:
                    raise ProjectRiskTrendIndexError("risk_trend_index_limit")
            revision_after = self._source_revision(organization_id)
            if revision_after != revision_before:
                raise ProjectRiskTrendIndexError("risk_trend_index_source_changed")
            connection.execute(
                """
                INSERT INTO risk_trend_owner_state (owner_id, source_revision, analysis_count, rebuilt_at_micros)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(owner_id) DO UPDATE SET
                    source_revision = excluded.source_revision,
                    analysis_count = excluded.analysis_count,
                    rebuilt_at_micros = excluded.rebuilt_at_micros
                """,
                (organization_id, revision_after, analyses_seen, _micros(datetime.now(timezone.utc))),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        self._validate_index_file()
        self._built_owners.add(organization_id)

    def _materialize_project(
        self,
        connection: sqlite3.Connection,
        *,
        organization_id: str,
        project: ProjectRecord,
        decisions: list[FindingDecisionRecord],
    ) -> int:
        project_ref = _opaque_ref("project", organization_id, project.id)
        first_seen: dict[str, datetime] = {}
        first_resolution: dict[str, datetime] = {}
        newest: _ProjectedAnalysis | None = None
        newest_is_current = True
        latest_finding_refs: set[str] = set()
        count = 0

        for record in self._project_records(organization_id, project.id):
            projected = self._project_analysis(project, record)
            count += 1
            for finding_ref in (*projected.local.keys(), *projected.public.keys()):
                prior = first_seen.get(finding_ref)
                if prior is None or projected.occurred_at < prior:
                    first_seen[finding_ref] = projected.occurred_at
            if newest is None:
                newest = projected
                if not projected.local_invalid and not projected.public_invalid:
                    latest_finding_refs = set(projected.local) | set(projected.public)
                continue
            self._insert_transition(
                connection,
                organization_id=organization_id,
                base=projected,
                target=newest,
                current=newest_is_current,
                first_resolution=first_resolution,
            )
            newest = projected
            newest_is_current = False

        if newest is None:
            return 0
        self._insert_no_previous(
            connection,
            organization_id=organization_id,
            analysis=newest,
            current=newest_is_current,
        )
        for finding_ref, resolved_at in first_resolution.items():
            observed = first_seen.get(finding_ref)
            if observed is not None and resolved_at >= observed:
                self._insert_duration(
                    connection, organization_id, project_ref, "verified_resolution", observed, resolved_at
                )

        ordered_decisions = sorted(decisions, key=lambda item: (item.created_at, item.id))
        first_decision: dict[str, FindingDecisionRecord] = {}
        for decision in ordered_decisions:
            finding_ref = _opaque_ref("finding", project_ref, decision.finding_id)
            first_decision.setdefault(finding_ref, decision)
        for finding_ref, decision in first_decision.items():
            observed = first_seen.get(finding_ref)
            decided_at = _utc(decision.created_at)
            if observed is not None and decided_at >= observed:
                self._insert_duration(
                    connection, organization_id, project_ref, "first_review", observed, decided_at
                )
        for decision in _current_decisions(ordered_decisions).values():
            finding_ref = _opaque_ref("finding", project_ref, decision.finding_id)
            if (
                finding_ref in latest_finding_refs
                and decision.status in {"accepted", "false_positive"}
                and decision.review_at is not None
            ):
                connection.execute(
                    """
                    INSERT INTO risk_trend_exception_fact
                        (owner_id, project_ref, review_at_micros)
                    VALUES (?, ?, ?)
                    """,
                    (organization_id, project_ref, _micros(_utc(decision.review_at))),
                )
        return count

    def _project_records(self, organization_id: str, project_id: str) -> Iterator[JobRecord]:
        cursor: str | None = None
        while True:
            items, _total, cursor = self.jobs.page(
                owner_id=organization_id,
                page_size=100,
                cursor=cursor,
                status_filter="completed",
                audit_type="project_archive_basic",
                project_id=project_id,
            )
            for summary in items:
                record = self.jobs.get(summary.id)
                if (
                    record.owner_id != organization_id
                    or record.project_id != project_id
                    or record.status != "completed"
                    or record.audit_type != "project_archive_basic"
                ):
                    raise ProjectRiskTrendIndexError("risk_trend_index_source_invalid")
                yield record
            if cursor is None:
                return

    def _project_analysis(self, project: ProjectRecord, record: JobRecord) -> _ProjectedAnalysis:
        project_ref = _opaque_ref("project", str(record.owner_id), str(record.project_id))
        local, local_invalid = _local_findings(record)
        snapshot = self.vulnerability_store.get(record.id)
        public, public_invalid = _public_findings(snapshot)
        local_facts = {
            _opaque_ref("finding", project_ref, finding.id): _ProjectedFinding(
                severity=finding.severity
            )
            for finding in local
        }
        public_facts = {
            _opaque_ref("finding", project_ref, finding.id): _ProjectedFinding(
                severity=finding.cvss_band,
                ecosystem=finding.ecosystem,
                cvss_band=finding.cvss_band,
                known_exploited=any(signal.status == "known_exploited" for signal in finding.kev_signals),
            )
            for finding in public
        }
        profile_digest = None
        if record.execution_profile is not None:
            profile_digest = hashlib.sha256(
                json.dumps(
                    record.execution_profile.model_dump(mode="json"),
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
        coverage = _coverage_projection(record)
        snapshot_match = next(
            (item for item in project.source_snapshots if item.source_sha256 == record.source_sha256),
            None,
        )
        source_type = (
            "sbom"
            if project.source_filename == "sbom.json" or record.analysis_profile == "sbom_import"
            else "git_or_ci"
            if snapshot_match is not None and snapshot_match.source_commit_sha is not None
            else "archive"
        )
        return _ProjectedAnalysis(
            job_id=record.id,
            project_ref=project_ref,
            occurred_at=_utc(record.finished_at or record.updated_at),
            record_digest=active_job_record_digest(record),
            source_type=source_type,
            analysis_profile=record.analysis_profile,
            profile_digest=profile_digest,
            coverage=coverage,
            local_invalid=local_invalid,
            public_invalid=public_invalid,
            public_ready=isinstance(snapshot, dict) and snapshot.get("state") == "ready",
            local=local_facts,
            public=public_facts,
        )

    def _insert_transition(
        self,
        connection: sqlite3.Connection,
        *,
        organization_id: str,
        base: _ProjectedAnalysis,
        target: _ProjectedAnalysis,
        current: bool,
        first_resolution: dict[str, datetime],
    ) -> None:
        reason = _incomparability(base, target)
        local_new = local_persistent = local_resolved = high_new = 0
        public_new = public_persistent = public_resolved = 0
        coverage_gained = coverage_lost = 0
        public_exclusion: str | None = None
        ecosystem_changes: dict[str, Counter[str]] = {}
        if reason is None:
            local_new_refs = target.local.keys() - base.local.keys()
            local_resolved_refs = base.local.keys() - target.local.keys()
            local_new = len(local_new_refs)
            local_persistent = len(base.local.keys() & target.local.keys())
            local_resolved = len(local_resolved_refs)
            high_new = sum(target.local[value].severity in {"critical", "high"} for value in local_new_refs)
            for finding_ref in local_resolved_refs:
                first_resolution[finding_ref] = min(
                    first_resolution.get(finding_ref, target.occurred_at), target.occurred_at
                )
            coverage_lost, coverage_gained = _coverage_direction(base.coverage, target.coverage)
            if base.public_invalid or target.public_invalid:
                public_exclusion = "invalid_public_findings"
            elif not base.public_ready or not target.public_ready:
                public_exclusion = "public_snapshot_unavailable"
            else:
                public_new_refs = target.public.keys() - base.public.keys()
                public_resolved_refs = base.public.keys() - target.public.keys()
                public_new = len(public_new_refs)
                public_persistent = len(base.public.keys() & target.public.keys())
                public_resolved = len(public_resolved_refs)
                for finding_ref in public_resolved_refs:
                    first_resolution[finding_ref] = min(
                        first_resolution.get(finding_ref, target.occurred_at), target.occurred_at
                    )
                ecosystems = {
                    finding.ecosystem
                    for finding in (*base.public.values(), *target.public.values())
                    if finding.ecosystem is not None
                }
                ecosystem_changes = {ecosystem: Counter(comparable=1) for ecosystem in ecosystems}
                for finding_ref in public_new_refs:
                    ecosystem = target.public[finding_ref].ecosystem
                    if ecosystem is not None:
                        ecosystem_changes.setdefault(ecosystem, Counter())["new"] += 1
                for finding_ref in public_resolved_refs:
                    ecosystem = base.public[finding_ref].ecosystem
                    if ecosystem is not None:
                        ecosystem_changes.setdefault(ecosystem, Counter())["resolved"] += 1
        self._insert_analysis_fact(
            connection,
            organization_id=organization_id,
            analysis=target,
            current=current,
            transition_state=reason or "comparable",
            public_exclusion=public_exclusion,
            local_new=local_new,
            local_persistent=local_persistent,
            local_resolved=local_resolved,
            high_new=high_new,
            public_new=public_new,
            public_persistent=public_persistent,
            public_resolved=public_resolved,
            coverage_gained=coverage_gained,
            coverage_lost=coverage_lost,
        )
        self._insert_ecosystem_facts(connection, organization_id, target, current, ecosystem_changes)

    def _insert_no_previous(
        self,
        connection: sqlite3.Connection,
        *,
        organization_id: str,
        analysis: _ProjectedAnalysis,
        current: bool,
    ) -> None:
        self._insert_analysis_fact(
            connection,
            organization_id=organization_id,
            analysis=analysis,
            current=current,
            transition_state="no_previous_analysis",
            public_exclusion=None,
        )
        self._insert_ecosystem_facts(connection, organization_id, analysis, current, {})

    @staticmethod
    def _insert_analysis_fact(
        connection: sqlite3.Connection,
        *,
        organization_id: str,
        analysis: _ProjectedAnalysis,
        current: bool,
        transition_state: str,
        public_exclusion: str | None,
        local_new: int = 0,
        local_persistent: int = 0,
        local_resolved: int = 0,
        high_new: int = 0,
        public_new: int = 0,
        public_persistent: int = 0,
        public_resolved: int = 0,
        coverage_gained: int = 0,
        coverage_lost: int = 0,
    ) -> None:
        current_valid = current and not analysis.local_invalid and not analysis.public_invalid
        connection.execute(
            """
            INSERT INTO risk_trend_analysis_fact (
                job_id, owner_id, project_ref, occurred_at_micros, record_digest,
                source_type, is_current, transition_state, public_exclusion,
                public_invalid,
                local_new, local_persistent, local_resolved, high_new,
                public_new, public_persistent, public_resolved,
                coverage_gained, coverage_lost,
                current_critical_high, current_known_exploited
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                analysis.job_id,
                organization_id,
                analysis.project_ref,
                _micros(analysis.occurred_at),
                analysis.record_digest,
                analysis.source_type,
                int(current),
                transition_state,
                public_exclusion,
                int(analysis.public_invalid),
                local_new,
                local_persistent,
                local_resolved,
                high_new,
                public_new,
                public_persistent,
                public_resolved,
                coverage_gained,
                coverage_lost,
                (
                    sum(item.severity in {"critical", "high"} for item in analysis.local.values())
                    + sum(item.cvss_band in {"critical", "high"} for item in analysis.public.values())
                    if current_valid else 0
                ),
                (
                    sum(item.known_exploited for item in analysis.public.values())
                    if current_valid else 0
                ),
            ),
        )

    @staticmethod
    def _insert_ecosystem_facts(
        connection: sqlite3.Connection,
        organization_id: str,
        analysis: _ProjectedAnalysis,
        current: bool,
        changes: dict[str, Counter[str]],
    ) -> None:
        current_counts = Counter(
            finding.ecosystem
            for finding in analysis.public.values()
            if finding.ecosystem is not None
        ) if current and not analysis.local_invalid and not analysis.public_invalid else Counter()
        for ecosystem in sorted(set(current_counts) | set(changes)):
            if not re.fullmatch(r"[a-z0-9_]{1,40}", ecosystem):
                raise ProjectRiskTrendIndexError("risk_trend_index_source_invalid")
            change = changes.get(ecosystem, Counter())
            connection.execute(
                """
                INSERT INTO risk_trend_ecosystem_fact (
                    job_id, owner_id, occurred_at_micros, ecosystem,
                    current_findings, comparable_transitions, new_findings, resolved_findings
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    analysis.job_id,
                    organization_id,
                    _micros(analysis.occurred_at),
                    ecosystem,
                    current_counts[ecosystem],
                    change["comparable"],
                    change["new"],
                    change["resolved"],
                ),
            )

    @staticmethod
    def _insert_duration(
        connection: sqlite3.Connection,
        organization_id: str,
        project_ref: str,
        kind: str,
        first_seen: datetime,
        completed_at: datetime,
    ) -> None:
        connection.execute(
            """
            INSERT INTO risk_trend_duration_fact (
                owner_id, project_ref, kind, first_seen_at_micros,
                completed_at_micros, duration_hours
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                organization_id,
                project_ref,
                kind,
                _micros(first_seen),
                _micros(completed_at),
                max(0.0, (completed_at - first_seen).total_seconds() / 3600),
            ),
        )

    def _query(
        self,
        connection: sqlite3.Connection,
        organization_id: str,
        projects: list[ProjectRecord],
        cutoff: datetime,
        observed_at: datetime,
        bucket_days: int,
    ) -> dict[str, Any]:
        cutoff_us = _micros(cutoff)
        observed_us = _micros(observed_at)
        bucket_us = bucket_days * 86_400 * 1_000_000
        bucket_count = max(1, math.ceil((observed_us - cutoff_us) / bucket_us))
        buckets = [
            {
                "starts_at": cutoff + timedelta(days=bucket_days * index),
                "ends_at": min(cutoff + timedelta(days=bucket_days * (index + 1)), observed_at),
                "completed_analyses": 0,
                "projects_analyzed": 0,
                "comparable_local_transitions": 0,
                "comparable_public_transitions": 0,
                "excluded_transitions": 0,
                "coverage_gained": 0,
                "coverage_lost": 0,
                "changes": Counter(),
            }
            for index in range(bucket_count)
        ]
        rows = connection.execute(
            """
            SELECT
              MIN(CAST((occurred_at_micros - ?) / ? AS INTEGER), ?) AS bucket_index,
              COUNT(*) AS completed,
              COUNT(DISTINCT project_ref) AS projects,
              SUM(CASE WHEN transition_state = 'comparable' THEN 1 ELSE 0 END) AS local_comparable,
              SUM(CASE WHEN transition_state = 'comparable' AND public_exclusion IS NULL THEN 1 ELSE 0 END) AS public_comparable,
              SUM(CASE WHEN transition_state != 'comparable' THEN 1 ELSE 0 END) AS excluded,
              SUM(coverage_gained) AS coverage_gained,
              SUM(coverage_lost) AS coverage_lost,
              SUM(local_new) AS local_new,
              SUM(local_persistent) AS local_persistent,
              SUM(local_resolved) AS local_resolved,
              SUM(high_new) AS high_new,
              SUM(public_new) AS public_new,
              SUM(public_persistent) AS public_persistent,
              SUM(public_resolved) AS public_resolved
            FROM risk_trend_analysis_fact
            WHERE owner_id = ? AND occurred_at_micros >= ? AND occurred_at_micros <= ?
            GROUP BY bucket_index ORDER BY bucket_index
            """,
            (cutoff_us, bucket_us, bucket_count - 1, organization_id, cutoff_us, observed_us),
        ).fetchall()
        for row in rows:
            bucket = buckets[int(row["bucket_index"])]
            bucket.update({
                "completed_analyses": int(row["completed"] or 0),
                "projects_analyzed": int(row["projects"] or 0),
                "comparable_local_transitions": int(row["local_comparable"] or 0),
                "comparable_public_transitions": int(row["public_comparable"] or 0),
                "excluded_transitions": int(row["excluded"] or 0),
                "coverage_gained": int(row["coverage_gained"] or 0),
                "coverage_lost": int(row["coverage_lost"] or 0),
                "changes": Counter({
                    "local_new": int(row["local_new"] or 0),
                    "local_persistent": int(row["local_persistent"] or 0),
                    "local_resolved": int(row["local_resolved"] or 0),
                    "critical_or_high_new": int(row["high_new"] or 0),
                    "public_new": int(row["public_new"] or 0),
                    "public_persistent": int(row["public_persistent"] or 0),
                    "public_resolved": int(row["public_resolved"] or 0),
                }),
            })
        totals = connection.execute(
            """
            SELECT COUNT(*) AS retained,
              SUM(CASE WHEN occurred_at_micros >= ? AND occurred_at_micros <= ? THEN 1 ELSE 0 END) AS in_period,
              COUNT(DISTINCT CASE WHEN occurred_at_micros >= ? AND occurred_at_micros <= ? THEN project_ref END) AS projects_period,
              SUM(CASE WHEN is_current = 1 THEN current_critical_high ELSE 0 END) AS current_high,
              SUM(CASE WHEN is_current = 1 THEN current_known_exploited ELSE 0 END) AS current_kev,
              COUNT(DISTINCT CASE WHEN is_current = 1 AND occurred_at_micros >= ? THEN project_ref END) AS recent_projects
            FROM risk_trend_analysis_fact WHERE owner_id = ?
            """,
            (
                cutoff_us, observed_us, cutoff_us, observed_us,
                _micros(observed_at - timedelta(days=30)), organization_id,
            ),
        ).fetchone()
        change_totals = Counter()
        for bucket in buckets:
            change_totals.update(bucket["changes"])

        exclusion_rows = connection.execute(
            """
            SELECT reason, COUNT(*) AS amount FROM (
              SELECT transition_state AS reason FROM risk_trend_analysis_fact
              WHERE owner_id = ? AND occurred_at_micros >= ? AND occurred_at_micros <= ?
                AND transition_state != 'comparable'
              UNION ALL
              SELECT public_exclusion AS reason FROM risk_trend_analysis_fact
              WHERE owner_id = ? AND occurred_at_micros >= ? AND occurred_at_micros <= ?
                AND transition_state = 'comparable' AND public_exclusion IS NOT NULL
              UNION ALL
              SELECT 'invalid_public_findings' AS reason FROM risk_trend_analysis_fact
              WHERE owner_id = ? AND occurred_at_micros >= ? AND occurred_at_micros <= ?
                AND public_invalid = 1
            ) GROUP BY reason ORDER BY reason
            """,
            (
                organization_id, cutoff_us, observed_us,
                organization_id, cutoff_us, observed_us,
                organization_id, cutoff_us, observed_us,
            ),
        ).fetchall()
        source_rows = connection.execute(
            """
            SELECT source_type AS key, COUNT(*) AS completed_analyses,
              SUM(CASE WHEN transition_state = 'comparable' THEN 1 ELSE 0 END) AS comparable_transitions,
              SUM(local_new) AS new_findings, SUM(local_resolved) AS resolved_findings
            FROM risk_trend_analysis_fact
            WHERE owner_id = ? AND occurred_at_micros >= ? AND occurred_at_micros <= ?
            GROUP BY source_type ORDER BY source_type
            """,
            (organization_id, cutoff_us, observed_us),
        ).fetchall()
        ecosystem_rows = connection.execute(
            """
            SELECT ecosystem AS key,
              SUM(current_findings) AS current_findings,
              SUM(CASE WHEN occurred_at_micros >= ? AND occurred_at_micros <= ? THEN comparable_transitions ELSE 0 END) AS comparable_transitions,
              SUM(CASE WHEN occurred_at_micros >= ? AND occurred_at_micros <= ? THEN new_findings ELSE 0 END) AS new_findings,
              SUM(CASE WHEN occurred_at_micros >= ? AND occurred_at_micros <= ? THEN resolved_findings ELSE 0 END) AS resolved_findings
            FROM risk_trend_ecosystem_fact WHERE owner_id = ?
            GROUP BY ecosystem ORDER BY ecosystem
            """,
            (cutoff_us, observed_us, cutoff_us, observed_us, cutoff_us, observed_us, organization_id),
        ).fetchall()
        overdue = int(connection.execute(
            "SELECT COUNT(*) FROM risk_trend_exception_fact WHERE owner_id = ? AND review_at_micros <= ?",
            (organization_id, observed_us),
        ).fetchone()[0])
        return {
            "buckets": buckets,
            "changes": change_totals,
            "exclusions": [(str(row["reason"]), int(row["amount"])) for row in exclusion_rows],
            "source_types": [_dimension(row, include_completed=True) for row in source_rows],
            "ecosystems": [_dimension(row, include_completed=False) for row in ecosystem_rows],
            "time_to_first_review": self._duration(connection, organization_id, "first_review", cutoff_us),
            "time_to_verified_resolution": self._duration(connection, organization_id, "verified_resolution", cutoff_us),
            "retained": int(totals["retained"] or 0),
            "in_period": int(totals["in_period"] or 0),
            "projects_period": int(totals["projects_period"] or 0),
            "projects_without_recent": max(len(projects) - int(totals["recent_projects"] or 0), 0),
            "current_high": int(totals["current_high"] or 0),
            "current_kev": int(totals["current_kev"] or 0),
            "overdue_exceptions": overdue,
        }

    @staticmethod
    def _duration(connection, organization_id: str, kind: str, cutoff_us: int) -> dict[str, Any]:
        row = connection.execute(
            """
            SELECT COUNT(*) AS amount FROM risk_trend_duration_fact
            WHERE owner_id = ? AND kind = ? AND first_seen_at_micros >= ?
            """,
            (organization_id, kind, cutoff_us),
        ).fetchone()
        count = int(row["amount"] or 0)
        if count == 0:
            return {"sample_count": 0, "median_hours": None, "p90_hours": None}

        def value_at(offset: int) -> float:
            result = connection.execute(
                """
                SELECT duration_hours FROM risk_trend_duration_fact
                WHERE owner_id = ? AND kind = ? AND first_seen_at_micros >= ?
                ORDER BY duration_hours, completed_at_micros, project_ref LIMIT 1 OFFSET ?
                """,
                (organization_id, kind, cutoff_us, offset),
            ).fetchone()
            if result is None:
                raise ProjectRiskTrendIndexError("risk_trend_index_invalid")
            return float(result[0])

        middle = count // 2
        median = value_at(middle) if count % 2 else (value_at(middle - 1) + value_at(middle)) / 2
        p90 = value_at(max(0, math.ceil(count * 0.9) - 1))
        return {
            "sample_count": count,
            "median_hours": round(median, 2),
            "p90_hours": round(p90, 2),
        }

    def _validate_sample(self, connection: sqlite3.Connection, organization_id: str) -> None:
        rows = connection.execute(
            """
            SELECT job_id, project_ref, occurred_at_micros, record_digest
            FROM risk_trend_analysis_fact WHERE owner_id = ?
            ORDER BY job_id LIMIT ?
            """,
            (organization_id, RISK_TREND_INDEX_SAMPLE_SIZE),
        ).fetchall()
        for row in rows:
            try:
                record = self.jobs.get(str(row["job_id"]))
            except Exception as exc:
                raise ProjectRiskTrendIndexError("risk_trend_index_invalid") from exc
            if (
                record.owner_id != organization_id
                or record.project_id is None
                or _opaque_ref("project", organization_id, record.project_id) != row["project_ref"]
                or _micros(_utc(record.finished_at or record.updated_at)) != int(row["occurred_at_micros"])
                or active_job_record_digest(record) != row["record_digest"]
            ):
                raise ProjectRiskTrendIndexError("risk_trend_index_invalid")

    def _ensure_database(self) -> None:
        if not self.path.exists() and not self.path.is_symlink():
            self._reset_database()
            return
        self._validate_index_file()
        connection = self._connect(query_only=True)
        try:
            result = connection.execute("PRAGMA quick_check").fetchone()
            if result is None or result[0] != "ok":
                raise ProjectRiskTrendIndexError("risk_trend_index_invalid")
        finally:
            connection.close()

    def _reset_database(self) -> None:
        self._built_owners.clear()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.parent.is_symlink() or not self.path.parent.is_dir():
            raise ProjectRiskTrendIndexError("risk_trend_index_invalid")
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
                CREATE TABLE risk_trend_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE risk_trend_owner_state (
                    owner_id TEXT PRIMARY KEY,
                    source_revision TEXT NOT NULL,
                    analysis_count INTEGER NOT NULL CHECK (analysis_count >= 0),
                    rebuilt_at_micros INTEGER NOT NULL
                );
                CREATE TABLE risk_trend_refresh_state (
                    owner_id TEXT PRIMARY KEY,
                    desired_revision TEXT NOT NULL,
                    built_revision TEXT,
                    state TEXT NOT NULL CHECK (state IN ('queued','rebuilding','ready','failed')),
                    requested_at_micros INTEGER NOT NULL,
                    started_at_micros INTEGER,
                    completed_at_micros INTEGER,
                    failure_code TEXT CHECK (failure_code IS NULL OR failure_code IN (
                        'limit','source_changed','rebuild_failed'
                    )),
                    attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0)
                );
                CREATE TABLE risk_trend_analysis_fact (
                    job_id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    project_ref TEXT NOT NULL,
                    occurred_at_micros INTEGER NOT NULL,
                    record_digest TEXT NOT NULL,
                    source_type TEXT NOT NULL CHECK (source_type IN ('archive','git_or_ci','sbom')),
                    is_current INTEGER NOT NULL CHECK (is_current IN (0,1)),
                    transition_state TEXT NOT NULL CHECK (transition_state IN (
                        'no_previous_analysis','missing_execution_profile','profile_changed',
                        'coverage_changed','invalid_local_findings','comparable'
                    )),
                    public_exclusion TEXT CHECK (public_exclusion IS NULL OR public_exclusion IN (
                        'public_snapshot_unavailable','invalid_public_findings'
                    )),
                    public_invalid INTEGER NOT NULL CHECK (public_invalid IN (0,1)),
                    local_new INTEGER NOT NULL CHECK (local_new >= 0),
                    local_persistent INTEGER NOT NULL CHECK (local_persistent >= 0),
                    local_resolved INTEGER NOT NULL CHECK (local_resolved >= 0),
                    high_new INTEGER NOT NULL CHECK (high_new >= 0),
                    public_new INTEGER NOT NULL CHECK (public_new >= 0),
                    public_persistent INTEGER NOT NULL CHECK (public_persistent >= 0),
                    public_resolved INTEGER NOT NULL CHECK (public_resolved >= 0),
                    coverage_gained INTEGER NOT NULL CHECK (coverage_gained IN (0,1)),
                    coverage_lost INTEGER NOT NULL CHECK (coverage_lost IN (0,1)),
                    current_critical_high INTEGER NOT NULL CHECK (current_critical_high >= 0),
                    current_known_exploited INTEGER NOT NULL CHECK (current_known_exploited >= 0)
                );
                CREATE INDEX risk_trend_analysis_owner_time
                    ON risk_trend_analysis_fact (owner_id, occurred_at_micros, project_ref);
                CREATE INDEX risk_trend_analysis_owner_current
                    ON risk_trend_analysis_fact (owner_id, is_current, project_ref);
                CREATE TABLE risk_trend_ecosystem_fact (
                    job_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    occurred_at_micros INTEGER NOT NULL,
                    ecosystem TEXT NOT NULL,
                    current_findings INTEGER NOT NULL CHECK (current_findings >= 0),
                    comparable_transitions INTEGER NOT NULL CHECK (comparable_transitions >= 0),
                    new_findings INTEGER NOT NULL CHECK (new_findings >= 0),
                    resolved_findings INTEGER NOT NULL CHECK (resolved_findings >= 0),
                    PRIMARY KEY (job_id, ecosystem),
                    FOREIGN KEY (job_id) REFERENCES risk_trend_analysis_fact(job_id) ON DELETE CASCADE
                );
                CREATE INDEX risk_trend_ecosystem_owner_time
                    ON risk_trend_ecosystem_fact (owner_id, occurred_at_micros, ecosystem);
                CREATE TABLE risk_trend_duration_fact (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id TEXT NOT NULL,
                    project_ref TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK (kind IN ('first_review','verified_resolution')),
                    first_seen_at_micros INTEGER NOT NULL,
                    completed_at_micros INTEGER NOT NULL,
                    duration_hours REAL NOT NULL CHECK (duration_hours >= 0)
                );
                CREATE INDEX risk_trend_duration_owner_kind
                    ON risk_trend_duration_fact (owner_id, kind, first_seen_at_micros, duration_hours);
                CREATE TABLE risk_trend_exception_fact (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id TEXT NOT NULL,
                    project_ref TEXT NOT NULL,
                    review_at_micros INTEGER NOT NULL
                );
                CREATE INDEX risk_trend_exception_owner_review
                    ON risk_trend_exception_fact (owner_id, review_at_micros);
                """
            )
            connection.execute(
                "INSERT INTO risk_trend_metadata (key, value) VALUES ('schema_version', ?)",
                (str(RISK_TREND_INDEX_SCHEMA_VERSION),),
            )
            connection.commit()
            connection.close()
            connection = None
            with temporary.open("rb") as stream:
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                connection.close()
            temporary.unlink(missing_ok=True)
            raise ProjectRiskTrendIndexError("risk_trend_index_invalid") from exc
        self._validate_index_file()

    def _connect(self, *, query_only: bool = False) -> sqlite3.Connection:
        self._validate_index_file()
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self.path, timeout=30)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA foreign_keys = ON")
            if query_only:
                connection.execute("PRAGMA query_only = ON")
            row = connection.execute(
                "SELECT value FROM risk_trend_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if row is None or row[0] != str(RISK_TREND_INDEX_SCHEMA_VERSION):
                raise ProjectRiskTrendIndexError("risk_trend_index_invalid")
            tables = {
                str(item[0])
                for item in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            columns = {
                table: {
                    str(item[1])
                    for item in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
                }
                for table in RISK_TREND_INDEX_COLUMNS
            }
            if tables != set(RISK_TREND_INDEX_COLUMNS) or columns != RISK_TREND_INDEX_COLUMNS:
                raise ProjectRiskTrendIndexError("risk_trend_index_invalid")
            return connection
        except Exception:
            if connection is not None:
                connection.close()
            raise

    def _validate_index_file(self) -> None:
        try:
            metadata = self.path.lstat()
        except OSError as exc:
            raise ProjectRiskTrendIndexError("risk_trend_index_invalid") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or metadata.st_size > RISK_TREND_INDEX_MAX_BYTES
        ):
            raise ProjectRiskTrendIndexError("risk_trend_index_invalid")

    def _source_revision(self, organization_id: str) -> str:
        try:
            return self.source_clock.revision(organization_id)
        except RiskTrendSourceClockError as exc:
            raise ProjectRiskTrendIndexError("risk_trend_index_source_invalid") from exc


def _incomparability(base: _ProjectedAnalysis, target: _ProjectedAnalysis) -> str | None:
    if base.local_invalid or target.local_invalid:
        return "invalid_local_findings"
    if base.profile_digest is None or target.profile_digest is None:
        return "missing_execution_profile"
    if base.analysis_profile != target.analysis_profile or base.profile_digest != target.profile_digest:
        return "profile_changed"
    if base.coverage is None or target.coverage is None or base.coverage["signature"] != target.coverage["signature"]:
        return "coverage_changed"
    return None


def _coverage_projection(record: JobRecord) -> dict[str, Any] | None:
    result = record.result if isinstance(record.result, dict) else {}
    if not isinstance(result.get("summary"), dict):
        return None
    coverage = build_project_analysis_coverage(record)
    values = {
        "coverage_status": coverage.coverage_status,
        "total_entries_seen": coverage.total_entries_seen,
        "supported_manifests_parsed": coverage.supported_manifests_parsed,
        "lockfiles_parsed": coverage.lockfiles_parsed,
        "total_dependencies": coverage.total_dependencies,
    }
    signature_source = {
        "total_entries_seen": coverage.total_entries_seen,
        "supported_manifests_parsed": coverage.supported_manifests_parsed,
        "lockfiles_parsed": coverage.lockfiles_parsed,
        "total_dependencies": coverage.total_dependencies,
        "supported_manifests_found": coverage.supported_manifests_found,
        "unsupported_manifests_detected": coverage.unsupported_manifests_detected,
        "lockfiles_detected": coverage.lockfiles_detected,
        "analysis_limit_reached": "analysis_limit_reached" in coverage.limitations,
    }
    return {
        **values,
        "signature": hashlib.sha256(
            json.dumps(signature_source, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest(),
    }


def _coverage_direction(base: dict[str, Any] | None, target: dict[str, Any] | None) -> tuple[int, int]:
    if base is None or target is None or base["signature"] == target["signature"]:
        return 0, 0

    def decreased(left: dict[str, Any], right: dict[str, Any]) -> bool:
        return (
            (left["coverage_status"] == "complete" and right["coverage_status"] != "complete")
            or right["supported_manifests_parsed"] < left["supported_manifests_parsed"]
            or right["lockfiles_parsed"] < left["lockfiles_parsed"]
            or right["total_dependencies"] < left["total_dependencies"]
            or right["total_entries_seen"] < left["total_entries_seen"]
        )

    return int(decreased(base, target)), int(decreased(target, base))


def _dimension(row: sqlite3.Row, *, include_completed: bool) -> dict[str, Any]:
    return {
        "key": str(row["key"]),
        "current_findings": int(row["current_findings"] or 0) if "current_findings" in row.keys() else 0,
        "completed_analyses": int(row["completed_analyses"] or 0) if include_completed else 0,
        "comparable_transitions": int(row["comparable_transitions"] or 0),
        "new_findings": int(row["new_findings"] or 0),
        "resolved_findings": int(row["resolved_findings"] or 0),
    }


def _opaque_ref(kind: str, scope: str, value: str) -> str:
    return hashlib.sha256(
        f"inspectra-risk-trend-{kind}-v1\0{scope}\0{value}".encode("utf-8")
    ).hexdigest()


def _micros(value: datetime) -> int:
    return int(_utc(value).timestamp() * 1_000_000)


def _from_micros(value: Any) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(int(value) / 1_000_000, tz=timezone.utc)


def hmac_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


def _file_state(path: Path) -> tuple[int, int, int, int, int]:
    metadata = path.lstat()
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
