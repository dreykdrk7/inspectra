from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from time import perf_counter
import tracemalloc
import sqlite3

from app.config import Settings
from app.finding_lifecycle import FindingDecisionStore
from app.models import JobExecutionProfile, JobRecord, ProjectRecord, ProjectSourceSnapshot, RiskTrendRequest
from app.project_portfolio import ProjectPortfolioService
from app.project_risk_trends import ProjectRiskTrendsService
from app.project_risk_trend_index import ProjectRiskTrendIndex
from app.project_vulnerability_intelligence import ProjectVulnerabilityIntelligenceStore
from app.risk_trend_reporting import render_risk_trend_report
from app.storage import JobStore, ProjectStore


NOW = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
OWNER = "local-admin"
FOREIGN = "b" * 32


def _settings(tmp_path):
    value = Settings(data_dir=tmp_path, tool_runner_url="http://audit-tools:8081")
    value.ensure_directories()
    return value


def _profile(name="project_archive_basic"):
    return JobExecutionProfile(
        contract_version="test.1",
        profile_name=name,
        ruleset_version="test.1",
        max_upload_bytes=1024,
        audit_max_concurrency=1,
    )


def _project(index, owner=OWNER):
    source = f"{index + 100:064x}"
    return ProjectRecord(
        id=f"{index:032x}", owner_id=owner, name=f"Project {index}",
        source_file_id=f"{index + 200:032x}", source_filename="private-source.zip",
        source_sha256=source,
        source_snapshots=[ProjectSourceSnapshot(
            id=f"{index + 300:032x}", source_file_id=f"{index + 200:032x}",
            source_filename="private-source.zip", source_sha256=source, created_at=NOW - timedelta(days=30),
        )],
        created_at=NOW - timedelta(days=30), updated_at=NOW,
    )


def _finding(value, severity="high"):
    return {
        "id": f"{value:064x}", "rule_id": f"rule_{value}",
        "source_audit_type": "project_archive_basic", "title": f"Finding {value}",
        "category": "configuration", "severity": severity, "confidence": "high",
    }


def _job(index, project, when, findings, *, profile=None, dependencies=2):
    return JobRecord(
        id=f"{index + 500:032x}", owner_id=project.owner_id, project_id=project.id,
        audit_type="project_archive_basic", analysis_profile="project_archive_basic",
        execution_profile=profile or _profile(), source_sha256=project.source_sha256,
        status="completed", created_at=when, updated_at=when, finished_at=when,
        result={
            "normalized_findings": findings,
            "summary": {
                "total_entries_seen": 8, "supported_manifests_found": 1,
                "supported_manifests_parsed": 1, "unsupported_manifests_detected": 0,
                "lockfiles_detected": 1, "lockfiles_parsed": 1,
                "total_dependencies": dependencies, "truncated": False,
            },
        },
    )


def _public(value):
    return {
        "id": "pvf_" + f"{value:064x}", "fingerprint_version": "test.1", "provider": "osv",
        "advisory_id": f"CVE-2026-{value:04d}", "aliases": [f"CVE-2026-{value:04d}"],
        "ecosystem": "npm", "component_name": "public-package", "component_version": "1.0.0",
        "package_url": "pkg:npm/public-package@1.0.0", "component_identity_provenance": "npm_registry_lockfile",
        "dependency_scope": "direct", "relationship_status": "reported", "affected_ranges": [],
        "fixed_versions": ["1.0.1"], "severity": [], "cvss_base_score": 9.8,
        "cvss_band": "critical", "cvss_score_status": "source_provided", "references": [],
        "kev_signals": [{
            "provider": "cisa_kev", "status": "known_exploited", "cve_id": f"CVE-2026-{value:04d}",
            "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "evidence_digest": "e" * 64,
        }],
        "recommendation": "Upgrade and verify with a comparable analysis.", "evidence_digest": "f" * 64,
    }


def _stores(tmp_path):
    settings = _settings(tmp_path)
    projects, jobs = ProjectStore(settings), JobStore(settings)
    intelligence = ProjectVulnerabilityIntelligenceStore(
        settings.public_advisories_dir,
        settings=settings,
    )
    decisions = FindingDecisionStore(settings, now_func=lambda: NOW - timedelta(days=5))
    portfolio = ProjectPortfolioService(projects, jobs, intelligence, decisions)
    return projects, jobs, intelligence, decisions, ProjectRiskTrendsService(projects, jobs, intelligence, decisions, portfolio)


def _save_snapshot(store, job, findings):
    store.put(
        job.id,
        {"state": "ready", "findings": findings, "sources": [], "summary": {"findings": len(findings)}},
        organization_id=job.owner_id,
    )


def test_trends_use_only_comparable_transitions_and_keep_kev_separate(tmp_path):
    projects, jobs, intelligence, decisions, service = _stores(tmp_path)
    project = _project(1)
    first = _job(1, project, NOW - timedelta(days=20), [_finding(1)])
    second = _job(2, project, NOW - timedelta(days=10), [_finding(1), _finding(2)])
    third = _job(3, project, NOW - timedelta(days=1), [_finding(2)])
    for record in (first, second, third):
        jobs._save_unlocked(record)
    _save_snapshot(intelligence, first, [_public(1)])
    _save_snapshot(intelligence, second, [_public(1), _public(2)])
    _save_snapshot(intelligence, third, [_public(2)])
    projects._save_unlocked(project.model_copy(update={
        "latest_job_id": third.id, "baseline_analysis_id": first.id, "analysis_count": 3,
    }))
    decisions.record(
        organization_id=OWNER, project_id=project.id, finding_id=_finding(2)["id"], rule_id="rule_2",
        status="in_review", reason="Review assigned", comment=None, actor_id=OWNER,
        actor_username="local-admin", actor_role="administrator", review_at=None,
        assignee_user_id=None, assignee_username=None,
    )

    result = service.build(organization_id=OWNER, payload=RiskTrendRequest(period_days=30), now=NOW)

    assert result.summary.projects_in_scope == 1
    assert result.summary.comparable_local_transitions == 2
    assert result.summary.comparable_public_transitions == 2
    assert result.changes.local_new == 1 and result.changes.local_resolved == 1
    assert result.changes.public_new == 1 and result.changes.public_resolved == 1
    assert result.summary.current_known_exploited_findings == 1
    assert result.summary.current_critical_or_high_findings == 2
    assert result.time_to_first_review.sample_count == 1
    assert result.time_to_first_review.median_hours == 120
    assert result.time_to_verified_resolution.sample_count == 2
    assert result.ecosystems[0].key == "npm"
    assert result.ecosystems[0].current_findings == 1
    assert result.denominators["public_comparable_transitions"] == 2


def test_trends_exclude_changed_profiles_and_other_owners(tmp_path):
    projects, jobs, intelligence, _decisions, service = _stores(tmp_path)
    own = _project(2)
    foreign = _project(3, FOREIGN)
    own_first = _job(10, own, NOW - timedelta(days=5), [_finding(10)])
    own_second = _job(11, own, NOW - timedelta(days=1), [], profile=_profile("changed"))
    foreign_job = _job(12, foreign, NOW - timedelta(days=1), [_finding(12)])
    for record in (own_first, own_second, foreign_job):
        jobs._save_unlocked(record)
    projects._save_unlocked(own.model_copy(update={"latest_job_id": own_second.id, "analysis_count": 2}))
    projects._save_unlocked(foreign.model_copy(update={"latest_job_id": foreign_job.id, "analysis_count": 1}))

    result = service.build(organization_id=OWNER, payload=RiskTrendRequest(period_days=30), now=NOW)

    assert result.summary.projects_in_scope == 1
    assert result.summary.retained_completed_analyses == 2
    assert result.summary.comparable_local_transitions == 0
    assert result.changes.local_resolved == 0
    assert {item.reason: item.count for item in result.exclusions} == {
        "no_previous_analysis": 1,
        "profile_changed": 1,
    }

    foreign_result = service.build(
        organization_id=FOREIGN, payload=RiskTrendRequest(period_days=30), now=NOW
    )
    repeated = service.build(
        organization_id=OWNER, payload=RiskTrendRequest(period_days=30), now=NOW
    )
    assert foreign_result.summary.projects_in_scope == 1
    assert foreign_result.summary.retained_completed_analyses == 1
    assert repeated.summary.retained_completed_analyses == 2


def test_trend_exports_are_reproducible_and_do_not_include_source_labels(tmp_path):
    projects, jobs, _intelligence, _decisions, service = _stores(tmp_path)
    project = _project(4)
    job = _job(20, project, NOW - timedelta(days=1), [])
    jobs._save_unlocked(job)
    projects._save_unlocked(project.model_copy(update={"latest_job_id": job.id, "analysis_count": 1}))
    trend = service.build(organization_id=OWNER, payload=RiskTrendRequest(period_days=30), now=NOW)

    json_a = render_risk_trend_report(trend, profile="developer", report_format="json")
    json_b = render_risk_trend_report(trend, profile="developer", report_format="json")
    csv_report = render_risk_trend_report(trend, profile="security", report_format="csv")

    assert json_a == json_b
    assert b"private-source.zip" not in json_a[0]
    assert b"private-source.zip" not in csv_report[0]
    assert json_a[2] == "inspectra-risk-trends-developer.json"
    assert len(json_a[3]) == 64


def test_materialized_trends_rebuild_after_tampering_and_never_store_private_text(tmp_path):
    projects, jobs, intelligence, decisions, service = _stores(tmp_path)
    project = _project(8).model_copy(update={
        "name": "PRIVATE-PROJECT-CANARY",
        "source_filename": "PRIVATE-PATH-CANARY.zip",
    })
    first = _job(30, project, NOW - timedelta(days=2), [{
        **_finding(30), "title": "PRIVATE-FINDING-CANARY",
    }])
    second = _job(31, project, NOW - timedelta(days=1), [])
    for record in (first, second):
        jobs._save_unlocked(record)
    projects._save_unlocked(project.model_copy(update={
        "latest_job_id": second.id, "analysis_count": 2,
    }))

    original = service.build(
        organization_id=OWNER, payload=RiskTrendRequest(period_days=30), now=NOW
    )
    assert original.changes.local_resolved == 1
    path = tmp_path / "results" / "project_risk_trend_index.sqlite3"
    raw = path.read_bytes()
    for canary in (
        b"PRIVATE-PROJECT-CANARY",
        b"PRIVATE-PATH-CANARY",
        b"PRIVATE-FINDING-CANARY",
    ):
        assert canary not in raw
    assert path.stat().st_mode & 0o077 == 0

    path.write_bytes(b"not-a-valid-sqlite-database")
    rebuilt = service.build(
        organization_id=OWNER, payload=RiskTrendRequest(period_days=30), now=NOW
    )
    assert rebuilt.changes.local_resolved == 1


def test_materialized_trends_refresh_after_public_and_lifecycle_authority_changes(tmp_path):
    projects, jobs, intelligence, decisions, service = _stores(tmp_path)
    project = _project(10)
    first = _job(40, project, NOW - timedelta(days=20), [_finding(40)])
    second = _job(41, project, NOW - timedelta(days=1), [_finding(40)])
    for record in (first, second):
        jobs._save_unlocked(record)
    projects._save_unlocked(project.model_copy(update={
        "latest_job_id": second.id, "analysis_count": 2,
    }))

    before = service.build(
        organization_id=OWNER, payload=RiskTrendRequest(period_days=30), now=NOW
    )
    assert before.summary.comparable_public_transitions == 0
    assert before.time_to_first_review.sample_count == 0

    _save_snapshot(intelligence, first, [_public(40)])
    _save_snapshot(intelligence, second, [_public(40)])
    decisions.record(
        organization_id=OWNER,
        project_id=project.id,
        finding_id=_finding(40)["id"],
        rule_id="rule_40",
        status="in_review",
        reason="Synthetic review",
        comment=None,
        actor_id=OWNER,
        actor_username="local-admin",
        actor_role="administrator",
        review_at=None,
        assignee_user_id=None,
        assignee_username=None,
    )
    refreshed = service.build(
        organization_id=OWNER, payload=RiskTrendRequest(period_days=30), now=NOW
    )
    assert refreshed.summary.comparable_public_transitions == 1
    assert refreshed.time_to_first_review.sample_count == 1


def test_non_blocking_refresh_publishes_stale_failure_and_retry_states(tmp_path, monkeypatch):
    projects, jobs, _intelligence, _decisions, service = _stores(tmp_path)
    project = _project(12)
    first = _job(50, project, NOW - timedelta(days=2), [_finding(50)])
    jobs._save_unlocked(first)
    projects._save_unlocked(project.model_copy(update={
        "latest_job_id": first.id, "analysis_count": 1,
    }))

    pending = service.read(
        organization_id=OWNER, payload=RiskTrendRequest(period_days=30), now=NOW
    )
    assert pending.materialization.state == "rebuilding"
    assert pending.materialization.data_state == "unavailable"
    assert pending.materialization.refresh_in_progress is True
    assert pending.trend is None

    assert service.refresh_once(organization_id=OWNER, now=NOW) is False
    ready = service.read(
        organization_id=OWNER, payload=RiskTrendRequest(period_days=30), now=NOW
    )
    assert ready.materialization.state == "ready"
    assert ready.materialization.data_state == "current"
    assert ready.trend is not None
    assert ready.trend.summary.retained_completed_analyses == 1

    second = _job(51, project, NOW - timedelta(days=1), [])
    jobs._save_unlocked(second)
    projects._save_unlocked(project.model_copy(update={
        "latest_job_id": second.id, "analysis_count": 2,
    }))
    stale = service.read(
        organization_id=OWNER,
        payload=RiskTrendRequest(period_days=30),
        now=NOW + timedelta(seconds=1),
    )
    assert stale.materialization.state == "stale"
    assert stale.materialization.data_state == "stale"
    assert stale.materialization.refresh_in_progress is True
    assert stale.trend is not None
    assert stale.trend.summary.retained_completed_analyses == 1

    original = service.trend_index.rebuild_owner
    monkeypatch.setattr(
        service.trend_index,
        "rebuild_owner",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("PRIVATE-PATH-CANARY")),
    )
    assert service.refresh_once(organization_id=OWNER, now=NOW) is False
    failed = service.read(
        organization_id=OWNER,
        payload=RiskTrendRequest(period_days=30),
        now=NOW + timedelta(seconds=2),
    )
    assert failed.materialization.state == "failed"
    assert failed.materialization.data_state == "stale"
    assert failed.materialization.failure_code == "rebuild_failed"
    assert "PRIVATE-PATH-CANARY" not in str(failed.materialization)

    monkeypatch.setattr(service.trend_index, "rebuild_owner", original)
    retry = service.read(
        organization_id=OWNER,
        payload=RiskTrendRequest(period_days=30),
        now=NOW + timedelta(seconds=3),
        force_refresh=True,
    )
    assert retry.materialization.refresh_in_progress is True
    assert service.refresh_once(organization_id=OWNER, now=NOW) is False
    refreshed = service.read(
        organization_id=OWNER,
        payload=RiskTrendRequest(period_days=30),
        now=NOW + timedelta(seconds=4),
    )
    assert refreshed.materialization.state == "ready"
    assert refreshed.trend is not None
    assert refreshed.trend.summary.retained_completed_analyses == 2


def test_authoritative_writers_invalidate_only_the_affected_owner(tmp_path):
    projects, jobs, intelligence, decisions, service = _stores(tmp_path)
    own = _project(16)
    foreign = _project(17, FOREIGN)
    own_job = _job(80, own, NOW - timedelta(days=2), [])
    foreign_job = _job(81, foreign, NOW - timedelta(days=2), [])
    for record in (own_job, foreign_job):
        jobs._save_unlocked(record)
    projects._save_unlocked(own.model_copy(update={"latest_job_id": own_job.id, "analysis_count": 1}))
    projects._save_unlocked(foreign.model_copy(update={"latest_job_id": foreign_job.id, "analysis_count": 1}))

    def publish(owner):
        pending = service.read(
            organization_id=owner,
            payload=RiskTrendRequest(period_days=30),
            now=NOW,
        )
        assert pending.materialization.refresh_in_progress is True
        assert service.refresh_once(organization_id=owner, now=NOW) is False
        ready = service.read(
            organization_id=owner,
            payload=RiskTrendRequest(period_days=30),
            now=NOW,
        )
        assert ready.materialization.state == "ready"

    publish(OWNER)
    publish(FOREIGN)

    def assert_only_owner_is_stale(changed_owner, unchanged_owner):
        changed = service.read(
            organization_id=changed_owner,
            payload=RiskTrendRequest(period_days=30),
            now=NOW + timedelta(seconds=1),
        )
        unchanged = service.read(
            organization_id=unchanged_owner,
            payload=RiskTrendRequest(period_days=30),
            now=NOW + timedelta(seconds=1),
        )
        assert changed.materialization.state == "stale"
        assert unchanged.materialization.state == "ready"

    later = _job(82, own, NOW - timedelta(days=1), [])
    jobs._save_unlocked(later)
    assert_only_owner_is_stale(OWNER, FOREIGN)
    publish(OWNER)

    _save_snapshot(intelligence, own_job, [_public(80)])
    assert_only_owner_is_stale(OWNER, FOREIGN)
    publish(OWNER)

    decisions.record(
        organization_id=OWNER,
        project_id=own.id,
        finding_id=_finding(80)["id"],
        rule_id="rule_80",
        status="in_review",
        reason="Synthetic review",
        comment=None,
        actor_id=OWNER,
        actor_username="local-admin",
        actor_role="administrator",
        review_at=None,
        assignee_user_id=None,
        assignee_username=None,
    )
    assert_only_owner_is_stale(OWNER, FOREIGN)
    publish(OWNER)

    projects._save_unlocked(foreign.model_copy(update={"name": "Foreign renamed"}))
    assert_only_owner_is_stale(FOREIGN, OWNER)


def test_interrupted_refresh_claim_is_recovered_without_private_state(tmp_path):
    projects, jobs, intelligence, decisions, service = _stores(tmp_path)
    project = _project(13)
    record = _job(60, project, NOW - timedelta(days=1), [])
    jobs._save_unlocked(record)
    projects._save_unlocked(project.model_copy(update={
        "latest_job_id": record.id, "analysis_count": 1,
    }))
    service.read(
        organization_id=OWNER, payload=RiskTrendRequest(period_days=30), now=NOW
    )
    claimed = service.trend_index.claim_refresh(
        organization_id=OWNER, started_at=NOW
    )
    assert claimed is not None

    restarted = ProjectRiskTrendsService(
        projects,
        jobs,
        intelligence,
        decisions,
        ProjectPortfolioService(projects, jobs, intelligence, decisions),
    )
    assert restarted.recover_pending_refreshes() == [OWNER]
    recovered = restarted.read(
        organization_id=OWNER, payload=RiskTrendRequest(period_days=30), now=NOW
    )
    assert recovered.materialization.state == "rebuilding"
    assert recovered.materialization.refresh_in_progress is True
    raw = (tmp_path / "results" / "project_risk_trend_index.sqlite3").read_bytes()
    assert b"private-source.zip" not in raw
    assert b"Project 13" not in raw


def test_semantic_corruption_discards_only_the_affected_owner_projection(tmp_path):
    projects, jobs, _intelligence, _decisions, service = _stores(tmp_path)
    own = _project(14)
    foreign = _project(15, FOREIGN)
    own_job = _job(70, own, NOW - timedelta(days=1), [])
    foreign_job = _job(71, foreign, NOW - timedelta(days=1), [])
    for record in (own_job, foreign_job):
        jobs._save_unlocked(record)
    projects._save_unlocked(own.model_copy(update={"latest_job_id": own_job.id, "analysis_count": 1}))
    projects._save_unlocked(foreign.model_copy(update={"latest_job_id": foreign_job.id, "analysis_count": 1}))
    for owner in (OWNER, FOREIGN):
        service.read(
            organization_id=owner, payload=RiskTrendRequest(period_days=30), now=NOW
        )
        assert service.refresh_once(organization_id=owner, now=NOW) is False

    path = tmp_path / "results" / "project_risk_trend_index.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE risk_trend_analysis_fact SET record_digest = ? WHERE owner_id = ?",
            ("0" * 64, OWNER),
        )
        connection.commit()

    affected = service.read(
        organization_id=OWNER, payload=RiskTrendRequest(period_days=30), now=NOW
    )
    unaffected = service.read(
        organization_id=FOREIGN, payload=RiskTrendRequest(period_days=30), now=NOW
    )
    assert affected.materialization.state == "rebuilding"
    assert affected.materialization.data_state == "unavailable"
    assert affected.trend is None
    assert unaffected.materialization.state == "ready"
    assert unaffected.trend is not None


class _SyntheticJobs:
    """Generate a large retained history without persisting private job payloads."""

    def __init__(self, settings, histories):
        self.settings = settings
        self.histories = {
            (project.owner_id, project.id): (project, count, prefix)
            for project, count, prefix in histories
        }
        self.by_prefix = {prefix: (project, count) for project, count, prefix in histories}
        self.get_calls = 0
        self.profile = _profile()

    def page(self, *, owner_id, project_id, page_size, cursor=None, **_filters):
        _project, count, prefix = self.histories[(owner_id, project_id)]
        offset = int(cursor or 0)
        amount = min(page_size, count - offset)
        items = [
            SimpleNamespace(id=f"{prefix}{count - offset - index:031x}")
            for index in range(amount)
        ]
        next_cursor = str(offset + amount) if offset + amount < count else None
        return items, count, next_cursor

    def get(self, job_id):
        self.get_calls += 1
        project, count = self.by_prefix[job_id[0]]
        sequence = int(job_id[1:], 16)
        when = NOW - timedelta(seconds=count - sequence + 1)
        # The corpus generator is outside the materializer under test. Build an
        # already-valid record without charging 100,000 repeated Pydantic input
        # validations to the index rebuild budget.
        return JobRecord.model_construct(
            id=job_id,
            owner_id=project.owner_id,
            project_id=project.id,
            audit_type="project_archive_basic",
            analysis_profile="project_archive_basic",
            execution_profile=self.profile,
            source_sha256=project.source_sha256,
            status="completed",
            created_at=when,
            updated_at=when,
            finished_at=when,
            result={
                "normalized_findings": [],
                "summary": {
                    "total_entries_seen": 1,
                    "supported_manifests_found": 0,
                    "supported_manifests_parsed": 0,
                    "unsupported_manifests_detected": 0,
                    "lockfiles_detected": 0,
                    "lockfiles_parsed": 0,
                    "total_dependencies": 0,
                    "truncated": False,
                },
            },
        )


class _NoIntelligence:
    @staticmethod
    def get(_analysis_id):
        return None


class _NoDecisions:
    @staticmethod
    def list_for_projects(_organization_id, project_ids):
        return {project_id: [] for project_id in project_ids}


def test_materialized_trends_scale_to_one_hundred_thousand_analyses(tmp_path):
    settings = _settings(tmp_path)
    project = _project(9)
    foreign_project = _project(11, FOREIGN)
    jobs = _SyntheticJobs(settings, [
        (project, 50_000, "1"),
        (foreign_project, 50_000, "2"),
    ])
    index = ProjectRiskTrendIndex(
        settings, object(), jobs, _NoIntelligence(), _NoDecisions()
    )
    assert index.source_clock.recover() is True
    cutoff = NOW - timedelta(days=30)

    scheduled_at = perf_counter()
    owner_status = index.request_refresh(organization_id=OWNER, observed_at=NOW)
    foreign_status = index.request_refresh(organization_id=FOREIGN, observed_at=NOW)
    scheduling_seconds = perf_counter() - scheduled_at
    assert owner_status.state == foreign_status.state == "rebuilding"
    assert index.query_available(
        organization_id=OWNER,
        projects=[project],
        cutoff=cutoff,
        observed_at=NOW,
        bucket_days=7,
    ) is None
    assert jobs.get_calls == 0
    assert scheduling_seconds < 0.25

    tracemalloc.start()
    owner_revision = index.claim_refresh(organization_id=OWNER, started_at=NOW)
    assert owner_revision is not None
    index.rebuild_owner(organization_id=OWNER, projects=[project])
    assert index.complete_refresh(
        organization_id=OWNER,
        claimed_revision=owner_revision,
        completed_at=NOW,
    ) is False
    foreign_revision = index.claim_refresh(organization_id=FOREIGN, started_at=NOW)
    assert foreign_revision is not None
    index.rebuild_owner(organization_id=FOREIGN, projects=[foreign_project])
    assert index.complete_refresh(
        organization_id=FOREIGN,
        claimed_revision=foreign_revision,
        completed_at=NOW,
    ) is False
    calls_before_foreign_mutation = jobs.get_calls
    source_revision = index.source_clock.raw_source_revision()
    (settings.projects_dir / "foreign-authority-change").write_text(
        "fixture",
        encoding="utf-8",
    )
    assert index.source_clock.record_mutation(
        FOREIGN,
        previous_source_revision=source_revision,
    ) == "owner_invalidated"
    assert index.request_refresh(
        organization_id=OWNER,
        observed_at=NOW + timedelta(seconds=1),
    ).state == "ready"
    assert index.request_refresh(
        organization_id=FOREIGN,
        observed_at=NOW + timedelta(seconds=1),
    ).state == "stale"
    assert jobs.get_calls == calls_before_foreign_mutation
    result = index.query_available(
        organization_id=OWNER,
        projects=[project],
        cutoff=cutoff,
        observed_at=NOW,
        bucket_days=7,
    )
    foreign_result = index.query_available(
        organization_id=FOREIGN,
        projects=[foreign_project],
        cutoff=cutoff,
        observed_at=NOW,
        bucket_days=7,
    )
    assert result is not None and foreign_result is not None
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert result["retained"] == 50_000
    assert result["in_period"] == 50_000
    assert foreign_result["retained"] == 50_000
    assert foreign_result["in_period"] == 50_000
    assert result["changes"]["local_persistent"] == 0
    assert peak < 64 * 1024 * 1024
    calls_after_rebuild = jobs.get_calls

    started = perf_counter()
    repeated = index.query_available(
        organization_id=OWNER,
        projects=[project],
        cutoff=cutoff,
        observed_at=NOW,
        bucket_days=7,
    )
    assert repeated is not None
    warm_seconds = perf_counter() - started
    assert repeated["retained"] == 50_000
    assert jobs.get_calls - calls_after_rebuild <= 8
    assert warm_seconds < 1

    # Measure the rebuild budget without tracemalloc's allocation tracing. The
    # memory and wall-clock guards remain independent and therefore portable to
    # shared CI runners without relaxing either product limit.
    timed_settings = _settings(tmp_path / "timed-rebuild")
    timed_jobs = _SyntheticJobs(timed_settings, [
        (project, 50_000, "1"),
        (foreign_project, 50_000, "2"),
    ])
    timed_index = ProjectRiskTrendIndex(
        timed_settings, object(), timed_jobs, _NoIntelligence(), _NoDecisions()
    )
    assert timed_index.source_clock.recover() is True
    for owner in (OWNER, FOREIGN):
        assert timed_index.request_refresh(
            organization_id=owner, observed_at=NOW
        ).state == "rebuilding"
    timed_started = perf_counter()
    for owner, owner_project in ((OWNER, project), (FOREIGN, foreign_project)):
        revision = timed_index.claim_refresh(organization_id=owner, started_at=NOW)
        assert revision is not None
        timed_index.rebuild_owner(
            organization_id=owner, projects=[owner_project]
        )
        assert timed_index.complete_refresh(
            organization_id=owner,
            claimed_revision=revision,
            completed_at=NOW,
        ) is False
    assert perf_counter() - timed_started < 60
