from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import multiprocessing
from pathlib import Path
import sqlite3
import stat
import time
import tracemalloc

import pytest
from fastapi import HTTPException

from app.config import Settings, load_settings
from app.finding_lifecycle import FindingDecisionStore
from app.models import JobRecord, ProjectPortfolioSearchRequest, ProjectRecord, ProjectSourceSnapshot
from app.project_portfolio import (
    ProjectPortfolioService,
    _matches,
    _portfolio_summary,
    _sort_key,
)
from app.project_portfolio_priority_index import (
    ProjectPortfolioPriorityIndex,
    ProjectPortfolioPriorityIndexError,
)
from app.project_vulnerability_intelligence import ProjectVulnerabilityIntelligenceStore
from app.storage import JobStore, ProjectStore


NOW = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
OWNER = "local-admin"
FOREIGN_OWNER = "b" * 32


def _settings(tmp_path, *, portfolio_index_hmac_key: bytes | None = None) -> Settings:
    settings = Settings(
        data_dir=tmp_path,
        tool_runner_url="http://audit-tools:8081",
        portfolio_index_hmac_key=portfolio_index_hmac_key,
    )
    settings.ensure_directories()
    return settings


def _read_shared_priority_index(
    data_dir: str, key: bytes, search: str, results
) -> None:
    settings = _settings(Path(data_dir), portfolio_index_hmac_key=key)
    try:
        page = ProjectPortfolioPriorityIndex(settings).search(
            owner_id=OWNER,
            payload=ProjectPortfolioSearchRequest(search=search, search_mode="prefix"),
            offset=0,
        )
        results.put(("ok", [row.project_id for row in page.rows], page.filtered_projects))
    except Exception as exc:  # pragma: no cover - failure detail crosses a process boundary
        results.put(("error", type(exc).__name__, str(exc)))


def _coverage_summary(*, dependencies: int = 3, truncated: bool = False) -> dict:
    return {
        "total_entries_seen": 10,
        "supported_manifests_found": 1,
        "supported_manifests_parsed": 1,
        "unsupported_manifests_detected": 0,
        "lockfiles_detected": 1,
        "lockfiles_parsed": 1,
        "total_dependencies": dependencies,
        "truncated": truncated,
    }


def _finding(index: int, severity: str = "high") -> dict:
    return {
        "id": f"{index:064x}",
        "rule_id": f"rule_{index}",
        "source_audit_type": "project_archive_basic",
        "title": f"Finding {index}",
        "category": "configuration",
        "severity": severity,
        "confidence": "high",
    }


def _project(index: int, *, owner_id: str = OWNER, name: str | None = None, commit: bool = False) -> ProjectRecord:
    project_id = f"{index:032x}"
    source_id = f"{100_000 + index:032x}"
    snapshot = ProjectSourceSnapshot(
        id=f"{200_000 + index:032x}",
        source_file_id=source_id,
        source_filename="private.zip",
        source_sha256=f"{300_000 + index:064x}",
        source_commit_sha="c" * 40 if commit else None,
        created_at=NOW,
    )
    return ProjectRecord(
        id=project_id,
        owner_id=owner_id,
        name=name or f"Project {index}",
        source_file_id=source_id,
        source_filename="private.zip",
        source_sha256=snapshot.source_sha256,
        source_snapshots=[snapshot],
        created_at=NOW,
        updated_at=NOW,
    )


def _job(
    index: int,
    project: ProjectRecord,
    *,
    status: str = "completed",
    findings: list[dict] | None = None,
    dependencies: int = 3,
    truncated: bool = False,
    created_at: datetime = NOW,
) -> JobRecord:
    return JobRecord(
        id=f"{500_000 + index:032x}",
        owner_id=project.owner_id,
        project_id=project.id,
        audit_type="project_archive_basic",
        analysis_profile="project_archive_basic",
        status=status,
        created_at=created_at,
        updated_at=created_at,
        finished_at=created_at if status == "completed" else None,
        result={
            "normalized_findings": findings or [],
            "summary": _coverage_summary(dependencies=dependencies, truncated=truncated),
        }
        if status == "completed"
        else None,
        error="[REDACTED]" if status == "failed" else None,
    )


def _public_snapshot(*, kev: bool = False, state: str = "ready") -> dict:
    finding = {
        "id": "pvf_" + "d" * 60,
        "fingerprint_version": "2026-09-05.1",
        "provider": "osv",
        "advisory_id": "CVE-2026-1000",
        "aliases": ["CVE-2026-1000"],
        "ecosystem": "npm",
        "component_name": "public-package",
        "component_version": "1.0.0",
        "package_url": "pkg:npm/public-package@1.0.0",
        "component_identity_provenance": "npm_registry_lockfile",
        "dependency_scope": "direct",
        "relationship_status": "reported",
        "affected_ranges": [],
        "fixed_versions": ["1.0.1"],
        "severity": [],
        "kev_signals": [
            {
                "provider": "cisa_kev",
                "status": "known_exploited" if kev else "not_listed",
                "cve_id": "CVE-2026-1000",
                "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "evidence_digest": "e" * 64,
            }
        ],
        "cvss_base_score": 9.8,
        "cvss_band": "critical",
        "cvss_score_status": "derived_from_vector",
        "references": [],
        "recommendation": "Upgrade using the project dependency workflow and validate with a comparable analysis.",
        "evidence_digest": "f" * 64,
    }
    return {
        "contract_version": "2026-09-06.1",
        "state": state,
        "provider": "osv",
        "queried_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(days=1)).isoformat(),
        "sources": [
            {
                "provider": "osv",
                "state": "fresh" if state == "ready" else "stale",
                "reason": "fresh_cache" if state == "ready" else "stale_cache_fallback",
                "as_of": NOW.isoformat(),
                "expires_at": (NOW + timedelta(days=1)).isoformat(),
            },
            {"provider": "github_advisories", "state": "not_requested", "reason": "not_requested"},
            {"provider": "cisa_kev", "state": "fresh", "reason": "fresh_cache"},
        ],
        "findings": [finding],
        "summary": {
            "inventory_components": 1,
            "correlation_eligible_components": 1,
            "queryable_components": 1,
            "queried_components": 1,
            "findings": 1,
            "fixed_version_available": 1,
            "excluded_components": 0,
            "unverified_advisories": 0,
            "withdrawn_advisories": 0,
            "failed_batches": 0,
            "fresh_cache_batches": 1,
            "stale_cache_batches": 0,
        },
    }


def _service(tmp_path, *, portfolio_index_hmac_key: bytes | None = None):
    settings = _settings(
        tmp_path, portfolio_index_hmac_key=portfolio_index_hmac_key
    )
    projects = ProjectStore(settings)
    jobs = JobStore(settings)
    vulnerability_store = ProjectVulnerabilityIntelligenceStore(settings.public_advisories_dir)
    decisions = FindingDecisionStore(settings, now_func=lambda: NOW)
    return settings, projects, jobs, vulnerability_store, decisions, ProjectPortfolioService(
        projects, jobs, vulnerability_store, decisions
    )


def _save_project_job(projects: ProjectStore, jobs: JobStore, project: ProjectRecord, job: JobRecord) -> ProjectRecord:
    jobs._save_unlocked(job)
    project = project.model_copy(
        update={"latest_job_id": job.id, "analysis_count": 1, "updated_at": job.updated_at}
    )
    projects._save_unlocked(project)
    return project


def test_portfolio_ranks_visible_signals_and_keeps_foreign_projects_out(tmp_path):
    _settings_value, projects, jobs, vulnerability_store, _decisions, service = _service(tmp_path)
    urgent = _project(1, name="Urgent project", commit=True)
    urgent_job = _job(1, urgent, findings=[_finding(1, "high")])
    urgent = _save_project_job(projects, jobs, urgent, urgent_job)
    vulnerability_store.put(urgent_job.id, _public_snapshot(kev=True), recorded_at=NOW)

    review = _project(2, name="Review project")
    review_job = _job(2, review, truncated=True)
    _save_project_job(projects, jobs, review, review_job)

    foreign = _project(3, owner_id=FOREIGN_OWNER, name="Foreign secret project")
    _save_project_job(projects, jobs, foreign, _job(3, foreign, findings=[_finding(3, "critical")]))

    page = service.search(organization_id=OWNER, payload=ProjectPortfolioSearchRequest(), now=NOW)

    assert [item.project.name for item in page.items] == ["Urgent project", "Review project"]
    first = page.items[0]
    assert first.priority == "urgent"
    assert first.priority_reasons[:2] == ["known_exploited", "critical_findings"]
    assert first.finding_counts.kev == 1
    assert first.finding_counts.critical == 1
    assert first.finding_counts.high == 1
    assert first.source_type == "git_or_ci"
    assert first.source_type_detail == "commit_attributed_channel_ambiguous"
    assert page.summary.total_projects == 2
    assert page.summary.projects_with_kev == 1
    assert "Foreign secret project" not in page.model_dump_json()
    assert page.priority_model == "closed_signals_no_opaque_score"


def test_portfolio_distinguishes_attested_cli_and_ci_but_keeps_legacy_ambiguous(tmp_path):
    _settings_value, projects, _jobs, _vulnerability_store, _decisions, service = _service(tmp_path)
    projects_to_save = []
    for index, channel in ((10, "git_cli"), (11, "ci"), (12, None)):
        project = _project(index, commit=True)
        snapshot = project.source_snapshots[0].model_copy(update={"source_channel": channel})
        projects_to_save.append(project.model_copy(update={"source_snapshots": [snapshot]}))
    for project in projects_to_save:
        projects._save_unlocked(project)

    page = service.search(organization_id=OWNER, payload=ProjectPortfolioSearchRequest(), now=NOW)
    details = {item.project.id: item for item in page.items}

    assert details[projects_to_save[0].id].source_type_detail == "attested_git_cli"
    assert details[projects_to_save[1].id].source_type_detail == "attested_ci"
    assert details[projects_to_save[2].id].source_type_detail == "commit_attributed_channel_ambiguous"
    ambiguity = "The retained commit proves Git provenance but not whether CLI or CI submitted it."
    assert ambiguity not in details[projects_to_save[0].id].limitations
    assert ambiguity not in details[projects_to_save[1].id].limitations
    assert ambiguity in details[projects_to_save[2].id].limitations


def test_portfolio_marks_an_expired_ready_snapshot_stale(tmp_path):
    _settings_value, projects, jobs, vulnerability_store, _decisions, service = _service(tmp_path)
    project = _project(4, name="Expired intelligence")
    job = _job(4, project)
    _save_project_job(projects, jobs, project, job)
    snapshot = _public_snapshot()
    snapshot["expires_at"] = (NOW - timedelta(seconds=1)).isoformat()
    vulnerability_store.put(job.id, snapshot, recorded_at=NOW - timedelta(days=1))

    result = service.search(
        organization_id=OWNER,
        payload=ProjectPortfolioSearchRequest(),
        now=NOW,
    )

    assert result.items[0].public_intelligence_state == "stale"
    assert "public_intelligence_stale" in result.items[0].priority_reasons


def test_portfolio_comparison_never_calls_lost_coverage_resolved(tmp_path):
    _settings_value, projects, jobs, vulnerability_store, _decisions, service = _service(tmp_path)
    project = _project(10, name="Coverage regression")
    baseline = _job(10, project, findings=[_finding(10, "high")], dependencies=8, created_at=NOW - timedelta(days=2))
    current = _job(11, project, findings=[], dependencies=2, created_at=NOW)
    jobs._save_unlocked(baseline)
    jobs._save_unlocked(current)
    project = project.model_copy(
        update={
            "latest_job_id": current.id,
            "baseline_analysis_id": baseline.id,
            "baseline_version": 1,
            "analysis_count": 2,
        }
    )
    projects._save_unlocked(project)

    item = service.search(organization_id=OWNER, payload=ProjectPortfolioSearchRequest(), now=NOW).items[0]

    assert item.coverage.state == "lost"
    assert item.changes.state == "not_comparable"
    assert item.changes.resolved == 0
    assert item.priority == "urgent"
    assert "coverage_lost" in item.priority_reasons
    assert any("no improvement is inferred" in limitation for limitation in item.limitations)


def test_portfolio_triage_responsibility_and_exception_review_are_current(tmp_path):
    _settings_value, projects, jobs, _vulnerability_store, decisions, service = _service(tmp_path)
    project = _project(20, name="Assigned project")
    finding = _finding(20, "medium")
    current = _job(20, project, findings=[finding])
    _save_project_job(projects, jobs, project, current)
    accepted = decisions.record(
        organization_id=OWNER,
        project_id=project.id,
        finding_id=finding["id"],
        rule_id=finding["rule_id"],
        status="accepted",
        reason="Temporary documented exception",
        comment=None,
        actor_id="admin",
        actor_username="admin",
        actor_role="administrator",
        review_at=NOW + timedelta(days=7),
        assignee_user_id="developer-id",
        assignee_username="developer",
    )

    item = service.search(organization_id=OWNER, payload=ProjectPortfolioSearchRequest(), now=NOW).items[0]

    assert item.pending_actions == 0
    assert item.exceptions_due == 1
    assert item.exceptions_overdue == 0
    assert item.responsibility.state == "assigned"
    assert item.responsibility.active_assignees == ["developer"]
    assert "exception_review_due" in item.priority_reasons

    path = decisions.directory / f"{accepted.id}.json"
    legacy = json.loads(path.read_text(encoding="utf-8"))
    legacy["review_at"] = None
    path.write_text(json.dumps(legacy), encoding="utf-8")
    legacy_item = service.search(organization_id=OWNER, payload=ProjectPortfolioSearchRequest(), now=NOW).items[0]
    assert legacy_item.pending_actions == 1
    assert legacy_item.exceptions_due == 0
    assert legacy_item.exceptions_overdue == 1


def test_portfolio_keeps_current_evidence_visible_after_resolved_decision(tmp_path):
    _settings_value, projects, jobs, _vulnerability_store, decisions, service = _service(tmp_path)
    project = _project(21, name="Awaiting verification")
    finding = _finding(21, "high")
    current = _job(21, project, findings=[finding])
    _save_project_job(projects, jobs, project, current)
    decisions.record(
        organization_id=OWNER,
        project_id=project.id,
        finding_id=finding["id"],
        rule_id=finding["rule_id"],
        status="resolved",
        reason="Correction prepared for reanalysis",
        comment=None,
        actor_id="admin",
        actor_username="admin",
        actor_role="administrator",
        review_at=None,
        assignee_user_id="developer-id",
        assignee_username="developer",
    )

    item = service.search(organization_id=OWNER, payload=ProjectPortfolioSearchRequest(), now=NOW).items[0]

    assert item.finding_counts.high == 1
    assert item.finding_counts.local == 1
    assert item.pending_actions == 1
    assert item.responsibility.active_assignees == ["developer"]


def test_portfolio_filters_paginates_and_rejects_changed_snapshot(tmp_path):
    _settings_value, projects, jobs, _vulnerability_store, _decisions, service = _service(tmp_path)
    for index, name in enumerate(("Alpha", "Alpine", "Beta"), start=30):
        project = _project(index, name=name)
        _save_project_job(projects, jobs, project, _job(index, project))

    request = ProjectPortfolioSearchRequest(page_size=1, search="Al", search_mode="prefix", sort="name")
    first = service.search(organization_id=OWNER, payload=request, now=NOW)
    assert [item.project.name for item in first.items] == ["Alpha"]
    assert first.total_count == 2
    assert first.next_cursor is not None

    second = service.search(
        organization_id=OWNER,
        payload=request.model_copy(update={"cursor": first.next_cursor}),
        now=NOW + timedelta(hours=1),
    )
    assert [item.project.name for item in second.items] == ["Alpine"]
    assert second.snapshot_at == NOW

    changed = projects.get(f"{30:032x}").model_copy(update={"name": "Alpha changed"})
    projects._save_unlocked(changed)
    with pytest.raises(HTTPException) as failure:
        service.search(
            organization_id=OWNER,
            payload=request.model_copy(update={"cursor": first.next_cursor}),
            now=NOW,
        )
    assert failure.value.status_code == 409


def test_portfolio_cursor_is_owner_and_filter_bound(tmp_path):
    _settings_value, projects, jobs, _vulnerability_store, _decisions, service = _service(tmp_path)
    for index in range(40, 42):
        project = _project(index)
        _save_project_job(projects, jobs, project, _job(index, project))
    first = service.search(
        organization_id=OWNER,
        payload=ProjectPortfolioSearchRequest(page_size=1),
        now=NOW,
    )
    assert first.next_cursor

    with pytest.raises(HTTPException) as changed_filter:
        service.search(
            organization_id=OWNER,
            payload=ProjectPortfolioSearchRequest(page_size=1, cursor=first.next_cursor, priority="urgent"),
            now=NOW,
        )
    assert changed_filter.value.status_code == 400

    with pytest.raises(HTTPException) as changed_owner:
        service.search(
            organization_id=FOREIGN_OWNER,
            payload=ProjectPortfolioSearchRequest(page_size=1, cursor=first.next_cursor),
            now=NOW,
        )
    assert changed_owner.value.status_code == 400

    tampered = first.next_cursor[:-1] + ("A" if first.next_cursor[-1] != "A" else "B")
    with pytest.raises(HTTPException) as invalid:
        service.search(
            organization_id=OWNER,
            payload=ProjectPortfolioSearchRequest(page_size=1, cursor=tampered),
            now=NOW,
        )
    assert invalid.value.status_code == 400


def test_materialized_portfolio_index_keeps_names_and_source_metadata_out(tmp_path):
    settings, projects, jobs, vulnerability_store, decisions, service = _service(tmp_path)
    for index, name in ((50, "Private Alpha Canary"), (51, "Private Beta Canary")):
        project = _project(index, name=name)
        _save_project_job(projects, jobs, project, _job(index, project))

    result = service.search(
        organization_id=OWNER,
        payload=ProjectPortfolioSearchRequest(search="Private A", sort="name"),
        now=NOW,
    )

    assert [item.project.name for item in result.items] == ["Private Alpha Canary"]
    index_path = settings.results_dir / "project_portfolio_priority_index.sqlite3"
    assert stat.S_IMODE(index_path.stat().st_mode) == 0o600
    stored = index_path.read_bytes()
    for canary in (b"Private Alpha Canary", b"Private Beta Canary", b"private.zip"):
        assert canary not in stored
    connection = sqlite3.connect(index_path)
    try:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(portfolio_priority_fact)")
        }
        assert "name" not in columns
        assert "path" not in columns
        assert "evidence" not in columns
        assert connection.execute(
            "SELECT COUNT(*) FROM portfolio_priority_name_prefix"
        ).fetchone()[0] > 0
    finally:
        connection.close()


def test_materialized_portfolio_index_fails_closed_on_fact_tampering_and_rebuilds_on_restart(tmp_path):
    settings, projects, jobs, vulnerability_store, decisions, service = _service(tmp_path)
    project = _project(60, name="Restarted portfolio")
    _save_project_job(projects, jobs, project, _job(60, project, findings=[_finding(60, "critical")]))
    first = service.search(
        organization_id=OWNER, payload=ProjectPortfolioSearchRequest(), now=NOW
    )
    assert first.items[0].priority == "urgent"

    index_path = settings.results_dir / "project_portfolio_priority_index.sqlite3"
    connection = sqlite3.connect(index_path)
    try:
        connection.execute(
            "UPDATE portfolio_priority_fact SET priority = 'monitor' WHERE project_id = ?",
            (project.id,),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(HTTPException) as corrupted:
        service.search(
            organization_id=OWNER, payload=ProjectPortfolioSearchRequest(), now=NOW
        )
    assert corrupted.value.status_code == 503

    restarted = ProjectPortfolioService(
        ProjectStore(settings), JobStore(settings), vulnerability_store, decisions
    )
    recovered = restarted.search(
        organization_id=OWNER, payload=ProjectPortfolioSearchRequest(), now=NOW
    )
    assert recovered.items[0].priority == "urgent"

    with sqlite3.connect(index_path) as connection:
        connection.execute(
            "DELETE FROM portfolio_priority_name_prefix WHERE project_id = ?",
            (project.id,),
        )
        connection.commit()
    with pytest.raises(HTTPException) as incomplete_search_index:
        restarted.search(
            organization_id=OWNER,
            payload=ProjectPortfolioSearchRequest(search="Restarted"),
            now=NOW,
        )
    assert incomplete_search_index.value.status_code == 503
    healed = ProjectPortfolioService(
        ProjectStore(settings), JobStore(settings), vulnerability_store, decisions
    ).search(
        organization_id=OWNER,
        payload=ProjectPortfolioSearchRequest(search="Restarted"),
        now=NOW,
    )
    assert [item.project.id for item in healed.items] == [project.id]


def test_materialized_portfolio_is_equivalent_to_authoritative_closed_signal_projection(tmp_path):
    _settings_value, projects, jobs, vulnerability_store, decisions, service = _service(tmp_path)
    fixtures = [
        (_project(70, name="Zulu"), [_finding(70, "medium")], False),
        (_project(71, name="Alpha"), [_finding(71, "critical")], False),
        (_project(72, name="Alpine"), [], True),
        (_project(73, name="Beta"), [_finding(73, "high")], False),
    ]
    saved: list[ProjectRecord] = []
    for offset, (project, findings, truncated) in enumerate(fixtures):
        saved.append(
            _save_project_job(
                projects,
                jobs,
                project,
                _job(
                    70 + offset,
                    project,
                    findings=findings,
                    truncated=truncated,
                    created_at=NOW - timedelta(hours=offset),
                ),
            )
        )
    authoritative = [
        service._build_item(project, decisions=[], active_members=None, now=NOW)
        for project in saved
    ]
    requests = [
        ProjectPortfolioSearchRequest(page_size=100),
        ProjectPortfolioSearchRequest(page_size=100, sort="name"),
        ProjectPortfolioSearchRequest(page_size=100, sort="updated"),
        ProjectPortfolioSearchRequest(page_size=100, search="Al", search_mode="prefix", sort="name"),
        ProjectPortfolioSearchRequest(page_size=100, severity="high"),
        ProjectPortfolioSearchRequest(page_size=100, priority="urgent"),
        ProjectPortfolioSearchRequest(page_size=100, coverage="partial"),
    ]
    for request in requests:
        expected = sorted(
            [item for item in authoritative if _matches(item, request)],
            key=lambda item: _sort_key(item, request.sort),
        )
        actual = service.search(organization_id=OWNER, payload=request, now=NOW)
        assert [item.model_dump(mode="json") for item in actual.items] == [
            item.model_dump(mode="json") for item in expected
        ]
        assert actual.summary == _portfolio_summary(authoritative, expected)


def test_materialized_portfolio_refreshes_when_a_time_based_signal_changes(tmp_path):
    _settings_value, projects, jobs, _vulnerability_store, _decisions, service = _service(tmp_path)
    project = _project(80, name="Time bounded")
    _save_project_job(projects, jobs, project, _job(80, project, created_at=NOW))

    current = service.search(
        organization_id=OWNER, payload=ProjectPortfolioSearchRequest(), now=NOW
    )
    assert "no_recent_analysis" not in current.items[0].priority_reasons

    refreshed = service.search(
        organization_id=OWNER,
        payload=ProjectPortfolioSearchRequest(),
        now=NOW + timedelta(days=31),
    )
    assert "no_recent_analysis" in refreshed.items[0].priority_reasons


def test_portfolio_index_hmac_key_configuration_is_canonical_and_redacted(monkeypatch):
    key = bytes(range(32))
    encoded = base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii")
    monkeypatch.setenv("INSPECTRA_PORTFOLIO_INDEX_HMAC_KEY", encoded)

    settings = load_settings()

    assert settings.portfolio_index_hmac_key == key
    assert encoded not in repr(settings)
    assert repr(key) not in repr(settings)
    for invalid in ("short", encoded + "=", "!" * 43, "A" * 42):
        monkeypatch.setenv("INSPECTRA_PORTFOLIO_INDEX_HMAC_KEY", invalid)
        with pytest.raises(ValueError, match="base64url-encoded 32-byte secret"):
            load_settings()


def test_configured_portfolio_key_is_shared_across_processes_and_rotation_fails_closed(tmp_path):
    key = hashlib.sha256(b"portfolio-key-a").digest()
    settings, projects, jobs, vulnerability_store, decisions, service = _service(
        tmp_path, portfolio_index_hmac_key=key
    )
    project = _project(90, name="Customer portal")
    _save_project_job(projects, jobs, project, _job(90, project))
    built = service.search(
        organization_id=OWNER,
        payload=ProjectPortfolioSearchRequest(search="Customer", search_mode="prefix"),
        now=NOW,
    )
    assert [item.project.id for item in built.items] == [project.id]

    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    workers = [
        context.Process(
            target=_read_shared_priority_index,
            args=(str(tmp_path), key, "Customer", results),
        )
        for _index in range(2)
    ]
    for worker in workers:
        worker.start()
    observed = [results.get(timeout=10) for _worker in workers]
    for worker in workers:
        worker.join(timeout=10)
        assert worker.exitcode == 0
    results.close()
    results.join_thread()
    assert observed == [("ok", [project.id], 1), ("ok", [project.id], 1)]

    index_path = settings.results_dir / "project_portfolio_priority_index.sqlite3"
    before = hashlib.sha256(index_path.read_bytes()).hexdigest()
    rotated = ProjectPortfolioPriorityIndex(
        _settings(
            tmp_path,
            portfolio_index_hmac_key=hashlib.sha256(b"portfolio-key-b").digest(),
        )
    )
    with pytest.raises(
        ProjectPortfolioPriorityIndexError,
        match="portfolio_priority_index_key_mismatch",
    ):
        rotated.is_current(
            owner_id=OWNER,
            source_revision=rotated.source_revision(),
            observed_at_micros=int(NOW.timestamp() * 1_000_000),
        )
    assert hashlib.sha256(index_path.read_bytes()).hexdigest() == before
    assert key not in index_path.read_bytes()


class _SyntheticProjects:
    def __init__(self, records: list[ProjectRecord]) -> None:
        self.records = {record.id: record for record in records}
        self.by_owner: dict[str, list[ProjectRecord]] = {}
        self.get_calls = 0
        for record in records:
            self.by_owner.setdefault(str(record.owner_id), []).append(record)

    def bounded_owner_snapshot(self, *, owner_id: str, limit: int) -> list[ProjectRecord]:
        return self.by_owner.get(owner_id, [])[: limit + 1]

    def get(self, project_id: str) -> ProjectRecord:
        self.get_calls += 1
        return self.records[project_id]


class _SyntheticJobs:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @staticmethod
    def latest_completed_project_job(_project_id: str, *, owner_id: str):
        return None


class _NoIntelligence:
    @staticmethod
    def get(_analysis_id: str):
        return None


class _NoDecisions:
    @staticmethod
    def list_for_projects(_organization_id: str, project_ids: set[str]):
        return {project_id: [] for project_id in project_ids}


def test_materialized_portfolio_handles_twenty_thousand_projects_across_two_owners(tmp_path):
    settings = _settings(tmp_path)
    owner_a = "a" * 32
    owner_b = "b" * 32
    records = [
        _project(
            index + 1_000,
            owner_id=owner_a if index < 18_000 else owner_b,
            name=f"Portfolio {index:05d}",
        )
        for index in range(20_000)
    ]
    projects = _SyntheticProjects(records)
    service = ProjectPortfolioService(
        projects, _SyntheticJobs(settings), _NoIntelligence(), _NoDecisions()
    )

    started = time.perf_counter()
    first = service.search(
        organization_id=owner_a,
        payload=ProjectPortfolioSearchRequest(page_size=24, sort="name"),
        now=NOW,
    )
    foreign = service.search(
        organization_id=owner_b,
        payload=ProjectPortfolioSearchRequest(page_size=24, sort="name"),
        now=NOW,
    )
    rebuild_seconds = time.perf_counter() - started
    assert first.summary.total_projects == 18_000
    assert foreign.summary.total_projects == 2_000
    assert all(item.project.owner_id == owner_a for item in first.items)
    assert all(item.project.owner_id == owner_b for item in foreign.items)
    assert rebuild_seconds < 60

    samples: list[float] = []
    calls_before = projects.get_calls
    tracemalloc.start()
    for _index in range(10):
        sample_started = time.perf_counter()
        result = service.search(
            organization_id=owner_a,
            payload=ProjectPortfolioSearchRequest(page_size=24),
            now=NOW,
        )
        samples.append(time.perf_counter() - sample_started)
        assert result.summary.total_projects == 18_000
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert projects.get_calls - calls_before == 240
    assert sorted(samples)[8] < 1.0
    assert peak < 64 * 1024 * 1024
    assert service.priority_index.path.stat().st_size < 256 * 1024 * 1024
