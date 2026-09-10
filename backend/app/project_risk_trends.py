"""Bounded, owner-scoped risk trends derived from retained project evidence.

The projection deliberately treats comparability as a prerequisite for change.
It does not synthesize SLAs, exposure, or remediation from workflow state.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException

from app.models import (
    ProjectPortfolioSearchRequest,
    RiskTrendBucket,
    RiskTrendChangeCounts,
    RiskTrendDimension,
    RiskTrendDuration,
    RiskTrendExclusion,
    RiskTrendMaterialization,
    RiskTrendPriorityProject,
    RiskTrendRequest,
    RiskTrendResponse,
    RiskTrendSummary,
    RiskTrendViewResponse,
)
from app.project_portfolio import (
    PROJECT_AGGREGATE_MAX_PROJECTS,
    _as_utc,
)
from app.project_risk_trend_index import (
    ProjectRiskTrendIndex,
    ProjectRiskTrendIndexError,
)

class ProjectRiskTrendsService:
    def __init__(self, projects, jobs, vulnerability_store, decisions, portfolio, trend_index=None) -> None:
        self.projects = projects
        self.jobs = jobs
        self.vulnerability_store = vulnerability_store
        self.decisions = decisions
        self.portfolio = portfolio
        self.trend_index = trend_index or ProjectRiskTrendIndex(
            jobs.settings, projects, jobs, vulnerability_store, decisions
        )

    def build(
        self,
        *,
        organization_id: str,
        payload: RiskTrendRequest,
        now: datetime | None = None,
    ) -> RiskTrendResponse:
        observed_at = _as_utc(now or datetime.now(timezone.utc))
        cutoff = observed_at - timedelta(days=payload.period_days)
        projects = self.projects.bounded_owner_snapshot(
            owner_id=organization_id, limit=PROJECT_AGGREGATE_MAX_PROJECTS
        )
        if len(projects) > PROJECT_AGGREGATE_MAX_PROJECTS:
            raise HTTPException(status_code=409, detail="Risk trends exceed the current safe project limit.")
        try:
            facts = self.trend_index.query(
                organization_id=organization_id,
                projects=projects,
                cutoff=cutoff,
                observed_at=observed_at,
                bucket_days=payload.bucket_days,
            )
        except ProjectRiskTrendIndexError as exc:
            if str(exc) == "risk_trend_index_limit":
                raise HTTPException(
                    status_code=409,
                    detail="Risk trends exceed the current safe retained-analysis limit.",
                ) from exc
            raise HTTPException(
                status_code=503,
                detail="Risk trend materialization is temporarily unavailable.",
            ) from exc

        return self._response_from_facts(
            organization_id=organization_id,
            projects=projects,
            facts=facts,
            payload=payload,
            observed_at=observed_at,
            cutoff=cutoff,
        )

    def read(
        self,
        *,
        organization_id: str,
        payload: RiskTrendRequest,
        now: datetime | None = None,
        force_refresh: bool = False,
    ) -> RiskTrendViewResponse:
        """Request bounded refresh work and read only an already-published snapshot."""

        observed_at = _as_utc(now or datetime.now(timezone.utc))
        cutoff = observed_at - timedelta(days=payload.period_days)
        projects = self.projects.bounded_owner_snapshot(
            owner_id=organization_id, limit=PROJECT_AGGREGATE_MAX_PROJECTS
        )
        if len(projects) > PROJECT_AGGREGATE_MAX_PROJECTS:
            raise HTTPException(status_code=409, detail="Risk trends exceed the current safe project limit.")
        try:
            status = self.trend_index.request_refresh(
                organization_id=organization_id,
                observed_at=observed_at,
                force=force_refresh,
            )
        except ProjectRiskTrendIndexError as exc:
            raise HTTPException(
                status_code=503,
                detail="Risk trend materialization is temporarily unavailable.",
            ) from exc
        try:
            facts = (
                self.trend_index.query_available(
                    organization_id=organization_id,
                    projects=projects,
                    cutoff=cutoff,
                    observed_at=observed_at,
                    bucket_days=payload.bucket_days,
                )
                if status.data_state != "unavailable"
                else None
            )
        except ProjectRiskTrendIndexError:
            status = self.trend_index.discard_owner_and_request_refresh(
                organization_id=organization_id,
                observed_at=observed_at,
            )
            facts = None
        trend = (
            self._response_from_facts(
                organization_id=organization_id,
                projects=projects,
                facts=facts,
                payload=payload,
                observed_at=observed_at,
                cutoff=cutoff,
            )
            if facts is not None
            else None
        )
        return RiskTrendViewResponse(
            materialization=RiskTrendMaterialization(
                state=status.state,
                data_state=status.data_state,
                refresh_in_progress=status.refresh_in_progress,
                retryable=status.retryable,
                requested_at=status.requested_at,
                started_at=status.started_at,
                completed_at=status.completed_at,
                failure_code=status.failure_code,
                retry_after_seconds=1 if status.refresh_in_progress else None,
            ),
            trend=trend,
        )

    def refresh_once(
        self,
        *,
        organization_id: str,
        now: datetime | None = None,
    ) -> bool:
        """Claim and atomically publish one coalesced owner rebuild.

        Returns true only when a source mutation observed during the rebuild
        queued one further bounded pass.
        """

        started_at = _as_utc(now or datetime.now(timezone.utc))
        claimed_revision = self.trend_index.claim_refresh(
            organization_id=organization_id,
            started_at=started_at,
        )
        if claimed_revision is None:
            return False
        try:
            projects = self.projects.bounded_owner_snapshot(
                owner_id=organization_id, limit=PROJECT_AGGREGATE_MAX_PROJECTS
            )
            if len(projects) > PROJECT_AGGREGATE_MAX_PROJECTS:
                return self.trend_index.fail_refresh(
                    organization_id=organization_id,
                    claimed_revision=claimed_revision,
                    failed_at=_as_utc(datetime.now(timezone.utc)),
                    failure_code="limit",
                )
            self.trend_index.rebuild_owner(
                organization_id=organization_id,
                projects=projects,
            )
            return self.trend_index.complete_refresh(
                organization_id=organization_id,
                claimed_revision=claimed_revision,
                completed_at=_as_utc(datetime.now(timezone.utc)),
            )
        except ProjectRiskTrendIndexError as exc:
            failure_code = (
                "source_changed"
                if str(exc) == "risk_trend_index_source_changed"
                else "limit"
                if str(exc) == "risk_trend_index_limit"
                else "rebuild_failed"
            )
            return self.trend_index.fail_refresh(
                organization_id=organization_id,
                claimed_revision=claimed_revision,
                failed_at=_as_utc(datetime.now(timezone.utc)),
                failure_code=failure_code,
            )
        except Exception:
            return self.trend_index.fail_refresh(
                organization_id=organization_id,
                claimed_revision=claimed_revision,
                failed_at=_as_utc(datetime.now(timezone.utc)),
                failure_code="rebuild_failed",
            )

    def recover_pending_refreshes(self) -> list[str]:
        return self.trend_index.recover_pending_refreshes()

    def _response_from_facts(
        self,
        *,
        organization_id: str,
        projects,
        facts: dict[str, Any],
        payload: RiskTrendRequest,
        observed_at: datetime,
        cutoff: datetime,
    ) -> RiskTrendResponse:
        portfolio = self.portfolio.search(
            organization_id=organization_id,
            payload=ProjectPortfolioSearchRequest(page_size=8),
            now=observed_at,
        )
        bucket_models = [_bucket_model(value) for value in facts["buckets"]]
        total_changes = RiskTrendChangeCounts(**{
            field: facts["changes"][field] for field in RiskTrendChangeCounts.model_fields
        })
        comparable_local = sum(item.comparable_local_transitions for item in bucket_models)
        comparable_public = sum(item.comparable_public_transitions for item in bucket_models)
        excluded = sum(item.excluded_transitions for item in bucket_models)
        analyses_in_period = sum(item.completed_analyses for item in bucket_models)
        source_dimensions = [RiskTrendDimension(**item) for item in facts["source_types"]]
        ecosystem_dimensions = [RiskTrendDimension(**item) for item in facts["ecosystems"]]
        return RiskTrendResponse(
            generated_at=observed_at,
            period_starts_at=cutoff,
            period_ends_at=observed_at,
            bucket_days=payload.bucket_days,
            summary=RiskTrendSummary(
                projects_in_scope=len(projects),
                projects_analyzed_in_period=facts["projects_period"],
                projects_without_recent_analysis=facts["projects_without_recent"],
                retained_completed_analyses=facts["retained"],
                completed_analyses_in_period=analyses_in_period,
                comparable_local_transitions=comparable_local,
                comparable_public_transitions=comparable_public,
                excluded_transitions=excluded,
                pending_actions=portfolio.summary.pending_actions,
                overdue_exceptions=facts["overdue_exceptions"],
                current_known_exploited_findings=facts["current_kev"],
                current_critical_or_high_findings=facts["current_high"],
            ),
            changes=total_changes,
            buckets=bucket_models,
            ecosystems=ecosystem_dimensions,
            source_types=source_dimensions,
            time_to_first_review=RiskTrendDuration(**facts["time_to_first_review"]),
            time_to_verified_resolution=RiskTrendDuration(**facts["time_to_verified_resolution"]),
            priority_projects=[
                RiskTrendPriorityProject(
                    project=item.project,
                    priority=item.priority,
                    reasons=list(item.priority_reasons),
                    pending_actions=item.pending_actions,
                )
                for item in portfolio.items
            ],
            exclusions=[RiskTrendExclusion(reason=reason, count=count) for reason, count in facts["exclusions"] if count],
            denominators={
                "projects": len(projects),
                "retained_completed_analyses": facts["retained"],
                "analyses_in_period": analyses_in_period,
                "local_comparable_transitions": comparable_local,
                "public_comparable_transitions": comparable_public,
                "first_review_samples": facts["time_to_first_review"]["sample_count"],
                "verified_resolution_samples": facts["time_to_verified_resolution"]["sample_count"],
            },
            limitations=[
                "Change counts use consecutive retained analyses with identical recorded execution profiles and equivalent coverage.",
                "Public-vulnerability changes require ready retained snapshots on both sides; KEV remains an enrichment, not severity.",
                "Duration cohorts begin at the first retained observation in the selected period; they are measurements, not service-level objectives.",
                "Project exposure and source-channel identity are never inferred from passive evidence.",
                "Historical counters come from a private rebuildable index; authoritative records remain the source of truth and sampled digests are revalidated on every query.",
            ],
        )

def _bucket_model(value: dict[str, Any]) -> RiskTrendBucket:
    return RiskTrendBucket(
        starts_at=value["starts_at"],
        ends_at=value["ends_at"],
        completed_analyses=value["completed_analyses"],
        projects_analyzed=(
            value["projects_analyzed"]
            if "projects_analyzed" in value
            else len(value["projects"])
        ),
        comparable_local_transitions=value["comparable_local_transitions"],
        comparable_public_transitions=value["comparable_public_transitions"],
        excluded_transitions=value["excluded_transitions"],
        coverage_gained=value["coverage_gained"],
        coverage_lost=value["coverage_lost"],
        changes=RiskTrendChangeCounts(**{
            field: value["changes"][field] for field in RiskTrendChangeCounts.model_fields
        }),
    )
