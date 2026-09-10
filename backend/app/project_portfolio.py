"""Conservative, owner-scoped project portfolio projection.

The portfolio ranks only closed, visible signals.  It never emits or persists a
numeric risk score, and it refuses to classify incompatible evidence as an
improvement.  Authoritative project/job/advisory/decision records remain in
their existing stores; this module builds a bounded read model on demand.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
from typing import Any

from fastapi import HTTPException, status
from pydantic import ValidationError

from app.finding_lifecycle import FindingLifecycleError, effective_status
from app.models import (
    FindingDecisionRecord,
    JobRecord,
    NormalizedFinding,
    ProjectAnalysisCoverage,
    ProjectAnalysisCoverageComparison,
    ProjectPortfolioChangeCounts,
    ProjectPortfolioCoverage,
    ProjectPortfolioFindingCounts,
    ProjectPortfolioItem,
    ProjectPortfolioPage,
    ProjectPortfolioResponsibility,
    ProjectStableResponsibility,
    ProjectPortfolioSearchRequest,
    ProjectPortfolioSummary,
    ProjectRecord,
    ProjectView,
    ProjectVulnerabilityFinding,
    current_project_responsibility,
    PublicVulnerabilitySourceFreshness,
    effective_project_source_channel,
)
from app.project_coverage import build_project_analysis_coverage, compare_project_analysis_coverage
from app.project_portfolio_priority_index import (
    PORTFOLIO_PRIORITY_INDEX_MAX_PROJECTS,
    PortfolioPriorityRow,
    ProjectPortfolioPriorityIndex,
    ProjectPortfolioPriorityIndexError,
    priority_row,
)


PROJECT_PORTFOLIO_CONTRACT_VERSION = "2026-09-10.2"
PROJECT_PORTFOLIO_MAX_PROJECTS = PORTFOLIO_PRIORITY_INDEX_MAX_PROJECTS
PROJECT_AGGREGATE_MAX_PROJECTS = 5_000
PROJECT_PORTFOLIO_RECENT_DAYS = 30
PROJECT_PORTFOLIO_EXCEPTION_REVIEW_DAYS = 30
PROJECT_PORTFOLIO_MAX_FINDINGS_PER_ANALYSIS = 10_000
_CURSOR_KEY = secrets.token_bytes(32)
_PRIORITY_ORDER = {"urgent": 0, "high": 1, "review": 2, "monitor": 3}
_REASON_ORDER = (
    "known_exploited",
    "critical_findings",
    "latest_analysis_failed",
    "coverage_lost",
    "high_findings",
    "new_findings",
    "analysis_incomplete",
    "public_intelligence_stale",
    "public_intelligence_failed",
    "exception_review_due",
    "pending_triage",
    "no_baseline",
    "no_recent_analysis",
    "no_completed_analysis",
)


class ProjectPortfolioService:
    def __init__(
        self,
        projects,
        jobs,
        vulnerability_store,
        decision_store,
        team_identity=None,
        priority_index=None,
    ) -> None:
        self.projects = projects
        self.jobs = jobs
        self.vulnerability_store = vulnerability_store
        self.decision_store = decision_store
        self.team_identity = team_identity
        self.priority_index = priority_index or ProjectPortfolioPriorityIndex(jobs.settings)

    def search(
        self,
        *,
        organization_id: str,
        payload: ProjectPortfolioSearchRequest,
        now: datetime | None = None,
        _stale_retry_allowed: bool = True,
    ) -> ProjectPortfolioPage:
        observed_at = _as_utc(now or datetime.now(timezone.utc))
        cursor = _decode_cursor(payload.cursor) if payload.cursor else None
        filter_digest = _filter_digest(organization_id, payload)
        if cursor is not None:
            if cursor.get("filter") != filter_digest:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Portfolio cursor is invalid. Restart from the first page.",
                )
            try:
                observed_at = _as_utc(datetime.fromisoformat(str(cursor["snapshot_at"])))
                offset = int(cursor["offset"])
                expected_digest = str(cursor["digest"])
            except (KeyError, TypeError, ValueError) as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Portfolio cursor is invalid. Restart from the first page.",
                ) from exc
        else:
            offset = 0
            expected_digest = ""

        try:
            source_revision = self.priority_index.source_revision()
            observed_at_micros = int(observed_at.timestamp() * 1_000_000)
            if not self.priority_index.is_current(
                owner_id=organization_id,
                source_revision=source_revision,
                observed_at_micros=observed_at_micros,
            ):
                self._rebuild_priority_index(
                    organization_id=organization_id,
                    observed_at=observed_at,
                    source_revision=source_revision,
                )
            indexed = self.priority_index.search(
                owner_id=organization_id, payload=payload, offset=offset
            )
        except ProjectPortfolioPriorityIndexError as exc:
            if str(exc) == "portfolio_priority_index_limit":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Portfolio exceeds the current materialized project limit.",
                ) from exc
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Portfolio materialization is temporarily unavailable.",
            ) from exc
        digest = indexed.projection_digest
        if expected_digest and not hmac.compare_digest(expected_digest, digest):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Portfolio changed while paging. Restart from the first page to use one coherent snapshot.",
            )
        if offset < 0 or offset > indexed.filtered_projects:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Portfolio cursor is invalid. Restart from the first page.",
            )
        page_rows = indexed.rows
        try:
            page_items = self._validated_page_items(
                organization_id=organization_id,
                rows=page_rows,
                observed_at=observed_at,
            )
        except ProjectPortfolioPriorityIndexError as exc:
            if not _stale_retry_allowed:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Portfolio materialization is temporarily unavailable.",
                ) from exc
            current_revision = self.priority_index.source_revision()
            self._rebuild_priority_index(
                organization_id=organization_id,
                observed_at=observed_at,
                source_revision=current_revision,
            )
            return self.search(
                organization_id=organization_id,
                payload=payload,
                now=observed_at,
                _stale_retry_allowed=False,
            )
        try:
            if self.priority_index.source_revision() != source_revision:
                raise ProjectPortfolioPriorityIndexError("portfolio_priority_index_source_changed")
        except ProjectPortfolioPriorityIndexError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Portfolio changed while paging. Restart from the first page to use one coherent snapshot.",
            ) from exc
        next_offset = offset + len(page_rows)
        next_cursor = (
            _encode_cursor(
                {
                    "snapshot_at": observed_at.isoformat(),
                    "offset": next_offset,
                    "digest": digest,
                    "filter": filter_digest,
                }
            )
            if next_offset < indexed.filtered_projects
            else None
        )
        return ProjectPortfolioPage(
            snapshot_at=observed_at,
            items=page_items,
            returned_count=len(page_items),
            total_count=indexed.filtered_projects,
            has_more=next_cursor is not None,
            next_cursor=next_cursor,
            summary=ProjectPortfolioSummary(
                total_projects=indexed.total_projects,
                filtered_projects=indexed.filtered_projects,
                **indexed.summary,
            ),
            limitations=[
                "Priority, filters and summary use private materialized closed signals; every returned project is revalidated against authoritative records.",
                *(
                    ["Commit-attributed snapshots created before source-channel attestation are shown as Git/CLI or CI, never guessed as one channel."]
                    if indexed.ambiguous_channels
                    else []
                ),
            ],
        )

    def _rebuild_priority_index(
        self,
        *,
        organization_id: str,
        observed_at: datetime,
        source_revision: str,
    ) -> None:
        projects = self.projects.bounded_owner_snapshot(
            owner_id=organization_id, limit=PROJECT_PORTFOLIO_MAX_PROJECTS
        )
        if len(projects) > PROJECT_PORTFOLIO_MAX_PROJECTS:
            raise ProjectPortfolioPriorityIndexError("portfolio_priority_index_limit")
        project_ids = {project.id for project in projects}
        try:
            decisions = self.decision_store.list_for_projects(organization_id, project_ids)
        except FindingLifecycleError as exc:
            raise ProjectPortfolioPriorityIndexError(
                "portfolio_priority_index_source_invalid"
            ) from exc
        active_members = self._active_members(organization_id)
        items = [
            self._build_item(
                project,
                decisions=decisions.get(project.id, []),
                active_members=active_members,
                now=observed_at,
            )
            for project in projects
        ]
        valid_until = self._next_time_boundary(
            projects=projects,
            decisions=decisions,
            now=observed_at,
        )
        if self.priority_index.source_revision() != source_revision:
            raise ProjectPortfolioPriorityIndexError("portfolio_priority_index_source_changed")
        self.priority_index.rebuild_owner(
            owner_id=organization_id,
            source_revision=source_revision,
            built_at_micros=int(observed_at.timestamp() * 1_000_000),
            valid_until_micros=int(valid_until.timestamp() * 1_000_000),
            projects=projects,
            items=items,
        )

    def _validated_page_items(
        self,
        *,
        organization_id: str,
        rows: list[PortfolioPriorityRow],
        observed_at: datetime,
    ) -> list[ProjectPortfolioItem]:
        projects: list[ProjectRecord] = []
        for row in rows:
            project = self.projects.get(row.project_id)
            if (
                project.owner_id != organization_id
                or not hmac.compare_digest(
                    row.project_record_digest,
                    hashlib.sha256(
                        json.dumps(
                            project.model_dump(mode="json"),
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest(),
                )
            ):
                raise ProjectPortfolioPriorityIndexError(
                    "portfolio_priority_index_source_diverged"
                )
            projects.append(project)
        try:
            decisions = self.decision_store.list_for_projects(
                organization_id, {project.id for project in projects}
            )
        except FindingLifecycleError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Portfolio triage state is temporarily unavailable.",
            ) from exc
        active_members = self._active_members(organization_id)
        items: list[ProjectPortfolioItem] = []
        for row, project in zip(rows, projects, strict=True):
            item = self._build_item(
                project,
                decisions=decisions.get(project.id, []),
                active_members=active_members,
                now=observed_at,
            )
            actual = priority_row(item, project=project, name_rank=row.name_rank)
            if not hmac.compare_digest(actual.fact_digest, row.fact_digest):
                raise ProjectPortfolioPriorityIndexError(
                    "portfolio_priority_index_source_diverged"
                )
            items.append(item)
        return items

    def _next_time_boundary(
        self,
        *,
        projects: list[ProjectRecord],
        decisions: dict[str, list[FindingDecisionRecord]],
        now: datetime,
    ) -> datetime:
        candidates: list[datetime] = []
        for project in projects:
            current = self.jobs.latest_completed_project_job(
                project.id, owner_id=project.owner_id
            )
            if current is not None:
                candidates.append(_as_utc(current.created_at) + timedelta(days=PROJECT_PORTFOLIO_RECENT_DAYS))
                snapshot = self.vulnerability_store.get(current.id)
                if isinstance(snapshot, dict):
                    if expiry := _parse_timestamp(snapshot.get("expires_at")):
                        candidates.append(expiry)
                    raw_sources = snapshot.get("sources", [])
                    if isinstance(raw_sources, list):
                        for source in raw_sources[:3]:
                            if isinstance(source, dict) and (
                                expiry := _parse_timestamp(source.get("expires_at"))
                            ):
                                candidates.append(expiry)
            for decision in _current_decisions(decisions.get(project.id, [])).values():
                if decision.status in {"accepted", "false_positive"} and decision.review_at is not None:
                    review_at = _as_utc(decision.review_at)
                    candidates.extend((review_at - timedelta(days=PROJECT_PORTFOLIO_EXCEPTION_REVIEW_DAYS), review_at))
        future = [candidate for candidate in candidates if candidate > now]
        return min(future) if future else now + timedelta(days=365)

    def _active_members(self, organization_id: str) -> dict[str, str] | None:
        if self.team_identity is None:
            return None
        try:
            return {
                member.user_id: member.username
                for member in self.team_identity.list_members(organization_id)
            }
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Portfolio responsibility state is temporarily unavailable.",
            ) from exc

    def _build_item(
        self,
        project: ProjectRecord,
        *,
        decisions: list[FindingDecisionRecord],
        active_members: dict[str, str] | None,
        now: datetime,
    ) -> ProjectPortfolioItem:
        latest = _owned_project_job(self.jobs, project, project.latest_job_id)
        current = self.jobs.latest_completed_project_job(project.id, owner_id=project.owner_id)
        baseline = _owned_project_job(self.jobs, project, project.baseline_analysis_id)
        current_findings, local_invalid = _local_findings(current)
        current_snapshot = self.vulnerability_store.get(current.id) if current is not None else None
        public_findings, public_invalid = _public_findings(current_snapshot)
        lifecycle = _current_decisions(decisions)
        finding_counts = _finding_counts(current_findings, public_findings, lifecycle, now=now)
        coverage = _coverage(current, baseline)
        changes = _changes(current, baseline, current_findings, current_snapshot, self.vulnerability_store)
        public_state, public_sources = _public_state(current_snapshot, now=now)
        pending_actions, exceptions_due, exceptions_overdue = _triage_counts(
            current_findings, lifecycle, public_findings, now=now
        )
        responsibility = _responsibility(
            current_findings, lifecycle, active_members=active_members, now=now
        )
        project_responsibility = _project_responsibility(
            project, active_members=active_members
        )
        operational_state = latest.status if latest is not None else "no_analysis"
        source_type, source_detail = _source_type(project)
        reasons: list[str] = []
        if finding_counts.kev:
            reasons.append("known_exploited")
        if finding_counts.critical:
            reasons.append("critical_findings")
        if latest is not None and latest.status == "failed":
            reasons.append("latest_analysis_failed")
        if coverage.state == "lost":
            reasons.append("coverage_lost")
        if finding_counts.high:
            reasons.append("high_findings")
        if changes.state == "ready" and changes.new + changes.public_new:
            reasons.append("new_findings")
        if coverage.state in {"partial", "unknown"} or (latest is not None and latest.status in {"cancelled", "cancelling"}):
            reasons.append("analysis_incomplete")
        if public_state == "stale":
            reasons.append("public_intelligence_stale")
        if public_state in {"partial", "failed"}:
            reasons.append("public_intelligence_failed")
        if exceptions_due or exceptions_overdue:
            reasons.append("exception_review_due")
        if pending_actions:
            reasons.append("pending_triage")
        if project.baseline_analysis_id is None:
            reasons.append("no_baseline")
        if current is not None and now - _as_utc(current.created_at) > timedelta(days=PROJECT_PORTFOLIO_RECENT_DAYS):
            reasons.append("no_recent_analysis")
        if current is None:
            reasons.append("no_completed_analysis")
        reasons = [reason for reason in _REASON_ORDER if reason in reasons]
        if any(reason in reasons for reason in ("known_exploited", "critical_findings", "latest_analysis_failed", "coverage_lost")):
            priority = "urgent"
        elif any(
            reason in reasons
            for reason in (
                "high_findings",
                "new_findings",
                "analysis_incomplete",
                "public_intelligence_stale",
                "public_intelligence_failed",
                "exception_review_due",
            )
        ):
            priority = "high"
        elif reasons:
            priority = "review"
        else:
            priority = "monitor"
        limitations: list[str] = []
        if local_invalid:
            limitations.append("Current normalized findings were invalid or exceeded the safe portfolio limit.")
        if public_invalid:
            limitations.append("Current public vulnerability evidence was invalid or exceeded the safe portfolio limit.")
        if changes.state == "not_comparable":
            limitations.append("Baseline and current evidence are not comparable; no improvement is inferred.")
        if source_detail == "commit_attributed_channel_ambiguous":
            limitations.append("The retained commit proves Git provenance but not whether CLI or CI submitted it.")
        return ProjectPortfolioItem(
            project=ProjectView.model_validate(project),
            latest_job=self.jobs.get_list_item(latest.id) if latest is not None else None,
            latest_completed_analysis=self.jobs.get_list_item(current.id) if current is not None else None,
            priority=priority,
            priority_reasons=reasons,
            finding_counts=finding_counts,
            changes=changes,
            coverage=coverage,
            public_intelligence_state=public_state,
            public_sources=public_sources,
            source_type=source_type,
            source_type_detail=source_detail,
            operational_state=operational_state,
            pending_actions=pending_actions,
            exceptions_due=exceptions_due,
            exceptions_overdue=exceptions_overdue,
            responsibility=responsibility,
            project_responsibility=project_responsibility,
            last_comparable_analysis_at=(current.finished_at or current.updated_at)
            if current is not None and changes.state in {"ready", "baseline_is_latest"}
            else None,
            limitations=limitations,
        )


def _owned_project_job(jobs, project: ProjectRecord, job_id: str | None) -> JobRecord | None:
    if not job_id:
        return None
    try:
        candidate = jobs.get(job_id)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            return None
        raise
    if candidate.owner_id != project.owner_id or candidate.project_id != project.id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Portfolio project history is inconsistent.",
        )
    return candidate


def _local_findings(job: JobRecord | None) -> tuple[list[NormalizedFinding], bool]:
    if job is None or not isinstance(job.result, dict):
        return [], False
    raw = job.result.get("normalized_findings")
    if raw is None:
        return [], False
    if not isinstance(raw, list) or len(raw) > PROJECT_PORTFOLIO_MAX_FINDINGS_PER_ANALYSIS:
        return [], True
    findings: list[NormalizedFinding] = []
    try:
        for item in raw:
            findings.append(NormalizedFinding.model_validate(item))
    except ValidationError:
        return [], True
    return findings, False


def _public_findings(snapshot: object) -> tuple[list[ProjectVulnerabilityFinding], bool]:
    if not isinstance(snapshot, dict):
        return [], False
    raw = snapshot.get("findings")
    if raw is None:
        return [], False
    if not isinstance(raw, list) or len(raw) > PROJECT_PORTFOLIO_MAX_FINDINGS_PER_ANALYSIS:
        return [], True
    findings: list[ProjectVulnerabilityFinding] = []
    try:
        for item in raw:
            findings.append(ProjectVulnerabilityFinding.model_validate(item))
    except ValidationError:
        return [], True
    return findings, False


def _current_decisions(records: list[FindingDecisionRecord]) -> dict[str, FindingDecisionRecord]:
    current: dict[str, FindingDecisionRecord] = {}
    for record in records:
        candidate = current.get(record.finding_id)
        if candidate is None or (record.created_at, record.id) > (candidate.created_at, candidate.id):
            current[record.finding_id] = record
    return current


def _finding_counts(
    local: list[NormalizedFinding],
    public: list[ProjectVulnerabilityFinding],
    decisions: dict[str, FindingDecisionRecord],
    *,
    now: datetime,
) -> ProjectPortfolioFindingCounts:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    local_count = 0
    for finding in local:
        decision = decisions.get(finding.id)
        # A workflow decision cannot erase evidence that is still present in the
        # current analysis.  Only a later comparable analysis can verify a fix.
        if decision is not None and effective_status(decision, now=now) == "false_positive":
            continue
        severity = "informational" if finding.severity == "info" else finding.severity
        counts[severity] += 1
        local_count += 1
    kev = 0
    for finding in public:
        if finding.cvss_band in counts:
            counts[finding.cvss_band] += 1
        if any(signal.status == "known_exploited" for signal in finding.kev_signals):
            kev += 1
    return ProjectPortfolioFindingCounts(
        **counts,
        kev=kev,
        local=local_count,
        public=len(public),
    )


def _coverage(current: JobRecord | None, baseline: JobRecord | None) -> ProjectPortfolioCoverage:
    if current is None:
        return ProjectPortfolioCoverage(state="unknown")
    current_coverage = build_project_analysis_coverage(current)
    comparison = compare_project_analysis_coverage(baseline, current) if baseline is not None else None
    lost = comparison is not None and comparison.status != "equivalent" and _coverage_decreased(comparison)
    return ProjectPortfolioCoverage(
        state="lost" if lost else current_coverage.coverage_status,
        current=current_coverage,
        comparison=comparison,
    )


def _coverage_decreased(comparison: ProjectAnalysisCoverageComparison) -> bool:
    if comparison.status == "unknown":
        return True
    base = comparison.base
    target = comparison.target
    return (
        (base.coverage_status == "complete" and target.coverage_status != "complete")
        or target.supported_manifests_parsed < base.supported_manifests_parsed
        or target.lockfiles_parsed < base.lockfiles_parsed
        or target.total_dependencies < base.total_dependencies
        or target.total_entries_seen < base.total_entries_seen
    )


def _changes(
    current: JobRecord | None,
    baseline: JobRecord | None,
    current_findings: list[NormalizedFinding],
    current_snapshot: object,
    vulnerability_store,
) -> ProjectPortfolioChangeCounts:
    if baseline is None:
        return ProjectPortfolioChangeCounts(state="missing_baseline")
    if current is None:
        return ProjectPortfolioChangeCounts(state="not_comparable")
    if baseline.id == current.id:
        return ProjectPortfolioChangeCounts(state="baseline_is_latest")
    coverage = compare_project_analysis_coverage(baseline, current)
    compatible = (
        baseline.status == "completed"
        and current.status == "completed"
        and baseline.audit_type == current.audit_type
        and baseline.analysis_profile == current.analysis_profile
        and baseline.execution_profile == current.execution_profile
        and (coverage is None or coverage.status == "equivalent")
    )
    baseline_findings, baseline_invalid = _local_findings(baseline)
    baseline_snapshot = vulnerability_store.get(baseline.id)
    base_public, base_public_invalid = _public_findings(baseline_snapshot)
    current_public, current_public_invalid = _public_findings(current_snapshot)
    if not compatible or baseline_invalid or base_public_invalid or current_public_invalid:
        return ProjectPortfolioChangeCounts(state="not_comparable")
    base_ids = {item.id for item in baseline_findings}
    current_ids = {item.id for item in current_findings}
    base_public_ids = {item.id for item in base_public}
    current_public_ids = {item.id for item in current_public}
    public_comparable = _snapshot_comparable(baseline_snapshot) and _snapshot_comparable(current_snapshot)
    if not public_comparable and (baseline_snapshot is not None or current_snapshot is not None):
        return ProjectPortfolioChangeCounts(
            state="not_comparable",
            new=len(current_ids - base_ids),
            persistent=len(current_ids & base_ids),
            resolved=len(base_ids - current_ids),
        )
    return ProjectPortfolioChangeCounts(
        state="ready",
        new=len(current_ids - base_ids),
        persistent=len(current_ids & base_ids),
        resolved=len(base_ids - current_ids),
        public_new=len(current_public_ids - base_public_ids),
        public_persistent=len(current_public_ids & base_public_ids),
        public_resolved=len(base_public_ids - current_public_ids),
    )


def _snapshot_comparable(snapshot: object) -> bool:
    return isinstance(snapshot, dict) and snapshot.get("state") == "ready"


def _public_state(
    snapshot: object, *, now: datetime
) -> tuple[str, list[PublicVulnerabilitySourceFreshness]]:
    if not isinstance(snapshot, dict):
        return "not_requested", []
    sources: list[PublicVulnerabilitySourceFreshness] = []
    try:
        raw_sources = snapshot.get("sources", [])
        if not isinstance(raw_sources, list) or len(raw_sources) > 3:
            return "failed", []
        sources = [PublicVulnerabilitySourceFreshness.model_validate(item) for item in raw_sources]
    except ValidationError:
        return "failed", []
    state = snapshot.get("state")
    expires_at = _parse_timestamp(snapshot.get("expires_at"))
    if state == "ready" and expires_at is not None and expires_at <= now:
        return "stale", sources
    if any(
        source.state == "fresh"
        and (source_expiry := _parse_timestamp(source.expires_at)) is not None
        and source_expiry <= now
        for source in sources
    ):
        return "stale", sources
    if state == "ready":
        return "fresh", sources
    if state == "stale":
        return "stale", sources
    if state == "degraded":
        return ("failed" if sources and all(item.state == "unavailable" for item in sources) else "partial"), sources
    if state == "disabled":
        return "disabled", sources
    return "not_requested", sources


def _triage_counts(
    local: list[NormalizedFinding],
    decisions: dict[str, FindingDecisionRecord],
    public: list[ProjectVulnerabilityFinding],
    *,
    now: datetime,
) -> tuple[int, int, int]:
    pending = len(public)
    due = 0
    overdue = 0
    horizon = now + timedelta(days=PROJECT_PORTFOLIO_EXCEPTION_REVIEW_DAYS)
    for finding in local:
        decision = decisions.get(finding.id)
        state = effective_status(decision, now=now) if decision is not None else "open"
        if state in {"open", "in_review", "resolved"}:
            pending += 1
        if decision is not None and decision.status in {"accepted", "false_positive"}:
            if decision.review_at is None:
                overdue += 1
            else:
                review_at = _as_utc(decision.review_at)
                if review_at <= now:
                    overdue += 1
                elif review_at <= horizon:
                    due += 1
    return pending, due, overdue


def _responsibility(
    local: list[NormalizedFinding],
    decisions: dict[str, FindingDecisionRecord],
    *,
    active_members: dict[str, str] | None,
    now: datetime,
) -> ProjectPortfolioResponsibility:
    assigned: dict[str, str] = {}
    inactive = 0
    for finding in local:
        decision = decisions.get(finding.id)
        if (
            decision is None
            or effective_status(decision, now=now) == "false_positive"
            or decision.assignee_user_id is None
            or decision.assignee_username is None
        ):
            continue
        if active_members is not None:
            username = active_members.get(decision.assignee_user_id)
            if username is None:
                inactive += 1
                continue
        else:
            username = decision.assignee_username
        assigned[decision.assignee_user_id] = username
    names = sorted(assigned.values(), key=str.casefold)
    state = "unassigned" if not names else "assigned" if len(names) == 1 else "multiple"
    return ProjectPortfolioResponsibility(
        state=state,
        active_assignees=names[:5],
        active_assignee_count=len(names),
        inactive_assignment_count=inactive,
        truncated=len(names) > 5,
    )


def _project_responsibility(
    project: ProjectRecord,
    *,
    active_members: dict[str, str] | None,
) -> ProjectStableResponsibility:
    responsibility = current_project_responsibility(project)
    if responsibility.state != "assigned" or responsibility.responsible_user_id is None:
        return ProjectStableResponsibility(
            state=responsibility.state,
            revision=responsibility.revision,
        )
    if active_members is None:
        username = (
            "local-admin"
            if responsibility.responsible_user_id == "local-admin"
            else "Assigned member"
        )
    else:
        username = active_members.get(responsibility.responsible_user_id)
        if username is None:
            return ProjectStableResponsibility(
                state="unassigned_attention",
                revision=responsibility.revision,
            )
    return ProjectStableResponsibility(
        state="assigned",
        responsible_username=username,
        revision=responsibility.revision,
    )


def _source_type(project: ProjectRecord) -> tuple[str, str]:
    current = project.source_snapshots[-1] if project.source_snapshots else None
    if current is not None:
        channel = effective_project_source_channel(current)
        if channel == "sbom":
            return "sbom", "normalized_sbom"
        if channel == "git_cli":
            return "git_or_ci", "attested_git_cli"
        if channel == "ci":
            return "git_or_ci", "attested_ci"
        if channel == "unknown_git_or_ci":
            return "git_or_ci", "commit_attributed_channel_ambiguous"
    if project.source_filename == "sbom.json":
        return "sbom", "normalized_sbom"
    return "archive", "uploaded_archive"


def _matches(item: ProjectPortfolioItem, payload: ProjectPortfolioSearchRequest) -> bool:
    if payload.search:
        candidate = item.project.name.casefold()
        needle = payload.search.casefold()
        if payload.search_mode == "exact" and candidate != needle:
            return False
        if payload.search_mode == "prefix" and not candidate.startswith(needle):
            return False
    if payload.priority is not None and item.priority != payload.priority:
        return False
    if payload.severity is not None and getattr(item.finding_counts, payload.severity) == 0:
        return False
    if payload.source_type is not None and item.source_type != payload.source_type:
        return False
    if payload.operational_state is not None and item.operational_state != payload.operational_state:
        return False
    if payload.coverage is not None and item.coverage.state != payload.coverage:
        return False
    if payload.public_intelligence is not None and item.public_intelligence_state != payload.public_intelligence:
        return False
    if payload.baseline is not None and (item.project.baseline_analysis_id is not None) != (payload.baseline == "available"):
        return False
    if payload.responsibility is not None and item.responsibility.state != payload.responsibility:
        return False
    return True


def _sort_key(item: ProjectPortfolioItem, sort: str) -> tuple[Any, ...]:
    if sort == "name":
        return (item.project.name.casefold(), item.project.id)
    if sort == "updated":
        return (-_as_utc(item.project.updated_at).timestamp(), item.project.id)
    return (
        _PRIORITY_ORDER[item.priority],
        -item.finding_counts.kev,
        -item.finding_counts.critical,
        -item.finding_counts.high,
        -(item.changes.new + item.changes.public_new),
        item.project.name.casefold(),
        item.project.id,
    )


def _portfolio_summary(
    all_items: list[ProjectPortfolioItem], filtered: list[ProjectPortfolioItem]
) -> ProjectPortfolioSummary:
    return ProjectPortfolioSummary(
        total_projects=len(all_items),
        filtered_projects=len(filtered),
        urgent_projects=sum(item.priority == "urgent" for item in filtered),
        high_priority_projects=sum(item.priority == "high" for item in filtered),
        projects_with_kev=sum(item.finding_counts.kev > 0 for item in filtered),
        projects_without_baseline=sum(item.project.baseline_analysis_id is None for item in filtered),
        projects_with_partial_data=sum(
            item.coverage.state in {"partial", "unknown", "lost"}
            or item.public_intelligence_state in {"stale", "partial", "failed"}
            or item.changes.state == "not_comparable"
            for item in filtered
        ),
        stale_or_failed_intelligence=sum(
            item.public_intelligence_state in {"stale", "partial", "failed"}
            for item in filtered
        ),
        pending_actions=sum(item.pending_actions for item in filtered),
    )


def _portfolio_summary_rows(
    total_projects: int, filtered: list[PortfolioPriorityRow]
) -> ProjectPortfolioSummary:
    return ProjectPortfolioSummary(
        total_projects=total_projects,
        filtered_projects=len(filtered),
        urgent_projects=sum(item.priority == "urgent" for item in filtered),
        high_priority_projects=sum(item.priority == "high" for item in filtered),
        projects_with_kev=sum(item.kev > 0 for item in filtered),
        projects_without_baseline=sum(not item.baseline_available for item in filtered),
        projects_with_partial_data=sum(item.partial_data for item in filtered),
        stale_or_failed_intelligence=sum(item.stale_or_failed for item in filtered),
        pending_actions=sum(item.pending_actions for item in filtered),
    )


def _priority_snapshot_digest(items: list[PortfolioPriorityRow]) -> str:
    return hashlib.sha256(
        json.dumps(
            [(item.project_id, item.fact_digest) for item in items],
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()


def _filter_digest(organization_id: str, payload: ProjectPortfolioSearchRequest) -> str:
    body = payload.model_dump(exclude={"cursor", "page_size"}, mode="json")
    return hashlib.sha256(
        json.dumps(
            {"organization_id": organization_id, "filters": body},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _snapshot_digest(items: list[ProjectPortfolioItem]) -> str:
    projection = [
        {
            "project_id": item.project.id,
            "name": item.project.name,
            "updated_at": item.project.updated_at.isoformat(),
            "latest_job_id": item.latest_job.id if item.latest_job else None,
            "latest_job_state": item.operational_state,
            "priority": item.priority,
            "reasons": item.priority_reasons,
            "findings": item.finding_counts.model_dump(mode="json"),
            "changes": item.changes.model_dump(mode="json"),
            "coverage": item.coverage.model_dump(mode="json"),
            "public": item.public_intelligence_state,
            "actions": item.pending_actions,
            "exceptions_due": item.exceptions_due,
            "exceptions_overdue": item.exceptions_overdue,
            "responsibility": item.responsibility.model_dump(mode="json"),
        }
        for item in items
    ]
    return hashlib.sha256(
        json.dumps(projection, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _encode_cursor(payload: dict[str, object]) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(_CURSOR_KEY, body, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(body + signature).decode("ascii").rstrip("=")


def _decode_cursor(value: str) -> dict[str, object]:
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(value + padding)
        if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
            raise ValueError
        body, signature = decoded[:-32], decoded[-32:]
        if len(body) == 0 or not hmac.compare_digest(signature, hmac.new(_CURSOR_KEY, body, hashlib.sha256).digest()):
            raise ValueError
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise ValueError
        return payload
    except (ValueError, TypeError, json.JSONDecodeError, binascii.Error) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Portfolio cursor is invalid. Restart from the first page.",
        ) from exc


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return _as_utc(datetime.fromisoformat(value))
    except ValueError:
        return None
