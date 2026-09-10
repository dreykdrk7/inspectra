from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.config import Settings
from app.finding_lifecycle import FindingDecisionStore
from app.models import (
    JobRecord,
    ProjectRecord,
    ProjectSourceSnapshot,
    RemediationBulkSelection,
    RemediationSearchRequest,
)
from app.project_vulnerability_intelligence import ProjectVulnerabilityIntelligenceStore
from app.remediation_center import RemediationCenterService
from app.storage import JobStore, ProjectStore


NOW = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
OWNER = "local-admin"
FOREIGN_OWNER = "b" * 32


def _service(tmp_path):
    settings = Settings(data_dir=tmp_path, tool_runner_url="http://audit-tools:8081")
    settings.ensure_directories()
    projects = ProjectStore(settings)
    jobs = JobStore(settings)
    intelligence = ProjectVulnerabilityIntelligenceStore(settings.public_advisories_dir)
    decisions = FindingDecisionStore(settings, now_func=lambda: NOW)
    return projects, jobs, intelligence, decisions, RemediationCenterService(
        projects, jobs, intelligence, decisions
    )


def _project(index: int, *, owner: str = OWNER, name: str | None = None) -> ProjectRecord:
    snapshot = ProjectSourceSnapshot(
        id=f"{200_000 + index:032x}",
        source_file_id=f"{100_000 + index:032x}",
        source_filename="private.zip",
        source_sha256=f"{300_000 + index:064x}",
        created_at=NOW,
    )
    return ProjectRecord(
        id=f"{index:032x}",
        owner_id=owner,
        name=name or f"Project {index}",
        source_file_id=snapshot.source_file_id,
        source_filename=snapshot.source_filename,
        source_sha256=snapshot.source_sha256,
        source_snapshots=[snapshot],
        created_at=NOW,
        updated_at=NOW,
    )


def _job(
    index: int,
    project: ProjectRecord,
    *,
    findings: list[dict] | None = None,
    dependencies: int = 3,
    created_at: datetime = NOW,
) -> JobRecord:
    return JobRecord(
        id=f"{500_000 + index:032x}",
        owner_id=project.owner_id,
        project_id=project.id,
        audit_type="project_archive_basic",
        analysis_profile="project_archive_basic",
        status="completed",
        created_at=created_at,
        updated_at=created_at,
        finished_at=created_at,
        result={
            "normalized_findings": findings or [],
            "summary": {
                "total_entries_seen": 10,
                "supported_manifests_found": 1,
                "supported_manifests_parsed": 1,
                "unsupported_manifests_detected": 0,
                "lockfiles_detected": 1,
                "lockfiles_parsed": 1,
                "total_dependencies": dependencies,
                "truncated": False,
            },
        },
    )


def _finding(index: int, *, severity: str = "high") -> dict:
    return {
        "id": f"{index:064x}",
        "rule_id": f"rule_{index}",
        "source_audit_type": "project_archive_basic",
        "title": f"Finding {index}",
        "category": "configuration",
        "severity": severity,
        "confidence": "high",
        "recommendation": "Correct the configuration and run a comparable analysis.",
    }


def _save(projects: ProjectStore, jobs: JobStore, project: ProjectRecord, job: JobRecord) -> None:
    jobs._save_unlocked(job)
    projects._save_unlocked(project.model_copy(update={
        "latest_job_id": job.id,
        "analysis_count": 1,
        "updated_at": job.updated_at,
    }))


def _public_snapshot(
    finding_id: str,
    *,
    component: str = "public-package",
    version: str = "1.0.0",
    fixed: list[str] | None = None,
    kev: bool = True,
    conflict: bool = False,
) -> dict:
    return {
        "contract_version": "2026-09-06.1",
        "state": "ready",
        "provider": "osv",
        "queried_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(days=1)).isoformat(),
        "sources": [{"provider": "osv", "state": "fresh", "reason": "live", "as_of": NOW.isoformat()}],
        "findings": [{
            "id": finding_id,
            "fingerprint_version": "2026-09-05.1",
            "provider": "osv",
            "advisory_id": "GHSA-AAAA-BBBB-CCCC",
            "aliases": ["CVE-2026-1000", "GHSA-AAAA-BBBB-CCCC"],
            "ecosystem": "npm",
            "component_name": component,
            "component_version": version,
            "package_url": f"pkg:npm/{component}@{version}",
            "component_identity_provenance": "npm_registry_lockfile",
            "dependency_scope": "direct",
            "relationship_status": "reported",
            "affected_ranges": [{"type": "SEMVER", "introduced": "0", "fixed": "2.0.0"}],
            "fixed_versions": fixed if fixed is not None else ["2.0.0"],
            "severity": [],
            "kev_signals": [{
                "provider": "cisa_kev",
                "status": "known_exploited" if kev else "not_listed",
                "cve_id": "CVE-2026-1000",
                "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "evidence_digest": "e" * 64,
            }],
            "cvss_base_score": 9.8,
            "cvss_band": "critical",
            "cvss_score_status": "derived_from_vector",
            "references": [{"type": "source", "url": "https://osv.dev/vulnerability/GHSA-AAAA-BBBB-CCCC"}],
            "recommendation": "Upgrade with the normal dependency workflow, then run a comparable analysis.",
            "evidence_digest": "f" * 64,
            "source_conflicts": [{
                "provider": "github_advisories",
                "advisory_id": "GHSA-AAAA-BBBB-CCCC",
                "type": "fixed_version",
                "observed_at": NOW.isoformat(),
                "evidence_digest": "a" * 64,
            }] if conflict else [],
            "source_consensus": "conflicting" if conflict else "osv_only",
        }],
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
            "fresh_cache_batches": 0,
            "stale_cache_batches": 0,
        },
    }


def test_groups_same_public_action_across_projects_and_isolates_owner(tmp_path):
    projects, jobs, intelligence, _decisions, service = _service(tmp_path)
    for index, owner, version in ((1, OWNER, "1.0.0"), (2, OWNER, "1.1.0"), (3, FOREIGN_OWNER, "1.2.0")):
        project = _project(index, owner=owner, name=f"Private {index}")
        job = _job(index, project)
        _save(projects, jobs, project, job)
        intelligence.put(job.id, _public_snapshot(f"{index:064x}", version=version), recorded_at=NOW)

    page = service.search(organization_id=OWNER, payload=RemediationSearchRequest(), now=NOW)

    assert page.total_count == 1
    group = page.items[0]
    assert group.component_name == "public-package"
    assert group.advisory_ids == ["CVE-2026-1000", "GHSA-AAAA-BBBB-CCCC"]
    assert group.observed_versions == ["1.0.0", "1.1.0"]
    assert group.recommended_fixed_version == "2.0.0"
    assert group.affected_project_count == 2
    assert group.priority == "urgent"
    assert group.priority_reasons[0] == "known_exploited"
    assert group.exposure_state == "not_assessed"
    assert page.summary.projects_affected == 2
    assert "Private 3" not in page.model_dump_json()


def test_conflicting_sources_never_produce_an_automatic_target(tmp_path):
    projects, jobs, intelligence, _decisions, service = _service(tmp_path)
    project = _project(10)
    job = _job(10, project)
    _save(projects, jobs, project, job)
    intelligence.put(job.id, _public_snapshot(f"{10:064x}", conflict=True), recorded_at=NOW)

    group = service.search(organization_id=OWNER, payload=RemediationSearchRequest(), now=NOW).items[0]

    assert group.source_conflict is True
    assert group.recommended_fixed_version is None
    assert "source_conflict" in group.priority_reasons
    assert any("No single conflict-free" in value for value in group.limitations)


def test_resolved_workflow_remains_visible_until_comparable_reanalysis(tmp_path):
    projects, jobs, _intelligence, decisions, service = _service(tmp_path)
    project = _project(20)
    finding = _finding(20)
    current = _job(20, project, findings=[finding], created_at=NOW)
    _save(projects, jobs, project, current)
    decisions.record(
        organization_id=OWNER,
        project_id=project.id,
        finding_id=finding["id"],
        rule_id=finding["rule_id"],
        status="resolved",
        reason="Correction prepared for verification",
        comment=None,
        actor_id="admin",
        actor_username="admin",
        actor_role="administrator",
        review_at=None,
        assignee_user_id=None,
        assignee_username=None,
    )

    first = service.search(organization_id=OWNER, payload=RemediationSearchRequest(), now=NOW).items[0]
    assert first.occurrences[0].workflow_state == "awaiting_reanalysis"
    assert first.workflow_counts.awaiting_reanalysis == 1

    later = current.model_copy(update={"created_at": NOW + timedelta(hours=1), "updated_at": NOW + timedelta(hours=1)})
    jobs._save_unlocked(later)
    second = service.search(organization_id=OWNER, payload=RemediationSearchRequest(), now=NOW + timedelta(hours=2)).items[0]
    assert second.occurrences[0].workflow_state == "still_detected"
    assert second.workflow_counts.still_detected == 1


def test_lost_coverage_does_not_claim_new_evidence(tmp_path):
    projects, jobs, _intelligence, _decisions, service = _service(tmp_path)
    project = _project(30)
    baseline = _job(30, project, findings=[], dependencies=8, created_at=NOW - timedelta(days=1))
    current = _job(31, project, findings=[_finding(31)], dependencies=2, created_at=NOW)
    jobs._save_unlocked(baseline)
    jobs._save_unlocked(current)
    projects._save_unlocked(project.model_copy(update={
        "latest_job_id": current.id,
        "baseline_analysis_id": baseline.id,
        "analysis_count": 2,
    }))

    occurrence = service.search(organization_id=OWNER, payload=RemediationSearchRequest(), now=NOW).items[0].occurrences[0]
    assert occurrence.coverage_state == "lost"
    assert occurrence.is_new is None


def test_filters_cursor_and_snapshot_change_are_enforced(tmp_path):
    projects, jobs, _intelligence, _decisions, service = _service(tmp_path)
    for index in (40, 41):
        project = _project(index)
        _save(projects, jobs, project, _job(index, project, findings=[_finding(index, severity="medium")]))
    request = RemediationSearchRequest(page_size=1, evidence_kind="local_finding", sort="component")
    first = service.search(organization_id=OWNER, payload=request, now=NOW)
    assert first.next_cursor

    with pytest.raises(HTTPException) as wrong_owner:
        service.search(
            organization_id=FOREIGN_OWNER,
            payload=request.model_copy(update={"cursor": first.next_cursor}),
            now=NOW,
        )
    assert wrong_owner.value.status_code == 400

    tampered = first.next_cursor[:-1] + ("A" if first.next_cursor[-1] != "A" else "B")
    with pytest.raises(HTTPException) as invalid:
        service.search(
            organization_id=OWNER,
            payload=request.model_copy(update={"cursor": tampered}),
            now=NOW,
        )
    assert invalid.value.status_code == 400

    project = projects.get(f"{40:032x}")
    assert project is not None
    projects._save_unlocked(project.model_copy(update={"name": "Changed"}))
    with pytest.raises(HTTPException) as changed:
        service.search(
            organization_id=OWNER,
            payload=request.model_copy(update={"cursor": first.next_cursor}),
            now=NOW,
        )
    assert changed.value.status_code == 409


def test_bulk_selection_is_bounded_to_current_group_revision(tmp_path):
    projects, jobs, _intelligence, decisions, service = _service(tmp_path)
    project = _project(50)
    finding = _finding(50)
    job = _job(50, project, findings=[finding])
    _save(projects, jobs, project, job)
    group = service.search(organization_id=OWNER, payload=RemediationSearchRequest(), now=NOW).items[0]
    selection = RemediationBulkSelection(
        project_id=project.id,
        analysis_id=job.id,
        finding_id=finding["id"],
    )

    resolved = service.validate_bulk_selection(
        organization_id=OWNER,
        group_id=group.id,
        expected_revision=group.revision,
        selections=[selection],
        now=NOW,
    )
    assert resolved[0].rule_id == finding["rule_id"]

    decisions.record(
        organization_id=OWNER,
        project_id=project.id,
        finding_id=finding["id"],
        rule_id=finding["rule_id"],
        status="in_review",
        reason="Owner review started",
        comment=None,
        actor_id="admin",
        actor_username="admin",
        actor_role="administrator",
        review_at=None,
        assignee_user_id=None,
        assignee_username=None,
    )
    with pytest.raises(HTTPException) as stale:
        service.validate_bulk_selection(
            organization_id=OWNER,
            group_id=group.id,
            expected_revision=group.revision,
            selections=[selection],
            now=NOW,
        )
    assert stale.value.status_code == 409
