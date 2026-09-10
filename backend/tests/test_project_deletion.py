from datetime import datetime, timezone
import hashlib

import pytest
from fastapi import HTTPException

from app.config import Settings
from app.finding_lifecycle import FindingDecisionStore
from app.models import StoredFile
from app.project_deletion import ProjectDeletionError, ProjectDeletionService
from app.project_action_inbox import ProjectActionInboxStore, ProjectActionRecord
from app.project_vulnerability_intelligence import ProjectVulnerabilityIntelligenceStore
from app.risk_trend_source_clock import RiskTrendSourceClock
from app.storage import (
    ExecutionWorkspaceStore,
    FileStore,
    JobStore,
    ProjectSnapshotAdmissionRecord,
    ProjectSnapshotAdmissionStore,
    ProjectStore,
    _atomic_write_json,
)


NOW = datetime(2026, 9, 6, 14, 0, tzinfo=timezone.utc)
OWNER_A = "a" * 32
OWNER_B = "b" * 32


def stores(tmp_path, *, after_step=None):
    settings = Settings(data_dir=tmp_path, tool_runner_url="http://audit-tools:8081")
    settings.ensure_directories()
    files = FileStore(settings)
    jobs = JobStore(settings)
    projects = ProjectStore(settings)
    decisions = FindingDecisionStore(settings, now_func=lambda: NOW)
    admissions = ProjectSnapshotAdmissionStore(settings, files, projects, jobs)
    intelligence = ProjectVulnerabilityIntelligenceStore(
        settings.public_advisories_dir,
        settings=settings,
    )
    workspaces = ExecutionWorkspaceStore(settings, files)
    service = ProjectDeletionService(
        settings,
        projects,
        jobs,
        decisions,
        admissions,
        intelligence,
        workspaces,
        now_func=lambda: NOW,
        after_step=after_step,
    )
    return settings, files, jobs, projects, decisions, admissions, intelligence, workspaces, service


def create_project_fixture(stores_tuple, *, owner_id=OWNER_A, job_status="completed"):
    settings, files, jobs, projects, decisions, admissions, intelligence, _workspaces, _service = stores_tuple
    payload = b"PK\x03\x04authorized"
    file_id = "1" * 32 if owner_id == OWNER_A else "2" * 32
    source = StoredFile(
        id=file_id,
        owner_id=owner_id,
        kind="archive",
        original_filename="authorized-private.zip",
        stored_filename=f"{file_id}.zip",
        content_type="application/zip",
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        created_at=NOW,
    )
    files.source_path(source).write_bytes(payload)
    files._save_record(source)
    project = projects.create(name="Private fixture", source=source, owner_id=owner_id)
    job = jobs.create_project_archive_job(
        source.id,
        owner_id=owner_id,
        project_id=project.id,
        source_sha256=source.sha256,
    )
    project = projects.attach_job(project.id, job.id)
    if job_status != "queued":
        job = jobs.update(
            job.id,
            status=job_status,
            result={"findings": []} if job_status == "completed" else None,
            termination_reason="completed" if job_status == "completed" else "cancelled_by_owner",
        )
    intelligence.put(
        job.id,
        {"state": "ready", "summary": {"findings": 0}},
        organization_id=owner_id,
    )
    workspace = settings.execution_workspaces_dir / job.id
    workspace.mkdir(mode=0o700)
    (workspace / "source.archive").write_bytes(payload)
    decisions.record(
        organization_id=owner_id,
        project_id=project.id,
        finding_id="f" * 64,
        rule_id="fixture_rule",
        status="in_review",
        reason="Needs authorized review",
        comment=None,
        actor_id=owner_id,
        actor_username="operator",
        actor_role="administrator",
        review_at=None,
        assignee_user_id=None,
        assignee_username=None,
    )
    admission = ProjectSnapshotAdmissionRecord(
        id="3" * 32,
        idempotency_key_sha256="4" * 64,
        owner_id=owner_id,
        project_id=project.id,
        source_file_id=source.id,
        source_sha256=source.sha256,
        source_channel="archive_upload",
        snapshot_id=project.source_snapshots[0].id,
        job_id=job.id,
        status="completed",
        created_at=NOW,
        updated_at=NOW,
    )
    _atomic_write_json(settings.project_snapshot_admissions_dir / f"{admission.id}.json", admission.model_dump(mode="json"))
    return source, project, job


def test_project_deletion_removes_derived_records_but_retains_independent_upload(tmp_path):
    configured = stores(tmp_path)
    settings, files, jobs, projects, decisions, _admissions, intelligence, workspaces, service = configured
    source, project, job = create_project_fixture(configured)
    action_store = ProjectActionInboxStore(settings)
    action_store.reconcile(OWNER_A, [ProjectActionRecord(
        id="9" * 32,
        organization_id=OWNER_A,
        project_id=project.id,
        analysis_id=job.id,
        reason="critical_findings",
        priority="urgent",
        destination="findings",
        occurred_at=NOW,
    )])
    service.project_action_inbox = action_store

    preview = service.preview(organization_id=OWNER_A, project_id=project.id)
    by_key = {item.key: item for item in preview.items}
    assert preview.state == "ready"
    assert by_key["analysis_results"].item_count == 1
    assert by_key["finding_decisions"].item_count == 1
    assert by_key["snapshot_admissions"].item_count == 1
    assert by_key["source_uploads"].disposition == "retain"
    assert by_key["public_advisory_cache"].disposition == "retain"
    assert by_key["passive_project_actions"].disposition == "delete"

    result = service.delete(organization_id=OWNER_A, project_id=project.id)

    assert result.state == "completed"
    with pytest.raises(HTTPException, match="Project not found"):
        projects.get(project.id)
    with pytest.raises(HTTPException, match="Job not found"):
        jobs.get(job.id)
    assert intelligence.get(job.id) is None
    assert decisions.list_for_project(OWNER_A, project.id) == []
    assert not (settings.execution_workspaces_dir / job.id).exists()
    assert not any(settings.project_snapshot_admissions_dir.iterdir())
    assert action_store._load(OWNER_A).events == ()
    assert not any(settings.project_deletions_dir.iterdir())
    assert files.get(source.id).id == source.id
    assert files.source_path(source).read_bytes().startswith(b"PK")
    assert workspaces.cleanup(job.id) is False


def test_project_deletion_blocks_active_work_without_hiding_project(tmp_path):
    configured = stores(tmp_path)
    settings, _files, jobs, projects, _decisions, _admissions, _intelligence, _workspaces, service = configured
    _source, project, job = create_project_fixture(configured, job_status="queued")

    assert service.preview(organization_id=OWNER_A, project_id=project.id).state == "blocked_active_work"
    with pytest.raises(ProjectDeletionError, match="active_work"):
        service.delete(organization_id=OWNER_A, project_id=project.id)

    assert projects.get(project.id).id == project.id
    assert jobs.get(job.id).status == "queued"
    assert not any(settings.project_deletions_dir.iterdir())


def test_project_deletion_is_cross_owner_safe_and_repeatable(tmp_path):
    configured = stores(tmp_path)
    _settings, _files, _jobs, projects, _decisions, _admissions, _intelligence, _workspaces, service = configured
    _source, project, _job = create_project_fixture(configured, owner_id=OWNER_B)

    foreign = service.delete(organization_id=OWNER_A, project_id=project.id)
    assert foreign.state == "already_absent"
    assert projects.get(project.id).owner_id == OWNER_B

    assert service.delete(organization_id=OWNER_B, project_id=project.id).state == "completed"
    assert service.delete(organization_id=OWNER_B, project_id=project.id).state == "already_absent"


def test_expired_source_does_not_block_project_derived_data_deletion(tmp_path):
    configured = stores(tmp_path)
    _settings, files, jobs, projects, _decisions, _admissions, _intelligence, _workspaces, service = configured
    source, project, job = create_project_fixture(configured)
    files.delete(source.id, owner_id=OWNER_A)
    projects.mark_source_file_deleted(source.id, owner_id=OWNER_A)
    jobs.mark_file_deleted(source.id, owner_id=OWNER_A)

    assert service.delete(organization_id=OWNER_A, project_id=project.id).state == "completed"
    with pytest.raises(HTTPException, match="Project not found"):
        projects.get(project.id)
    with pytest.raises(HTTPException, match="Job not found"):
        jobs.get(job.id)


def test_interrupted_project_deletion_hides_project_blocks_admission_and_recovers(tmp_path, caplog):
    def fail_after_decisions(step: str) -> None:
        if step == "finding_decisions":
            raise OSError("/private/customer/project/source.zip")

    configured = stores(tmp_path, after_step=fail_after_decisions)
    settings, files, jobs, projects, decisions, admissions, intelligence, workspaces, service = configured
    _source, project, job = create_project_fixture(configured)

    with pytest.raises(ProjectDeletionError, match="cleanup_failed"):
        service.delete(organization_id=OWNER_A, project_id=project.id)

    assert "/private/customer/project/source.zip" not in "\n".join(record.getMessage() for record in caplog.records)

    assert service.has_pending() is True
    assert projects.list(owner_id=OWNER_A) == []
    with pytest.raises(HTTPException, match="Project not found"):
        projects.get(project.id)
    with pytest.raises(HTTPException, match="deletion is in progress"):
        jobs.create_project_archive_job(
            "1" * 32,
            owner_id=OWNER_A,
            project_id=project.id,
            source_sha256="0" * 64,
        )

    recovered = ProjectDeletionService(
        settings,
        projects,
        jobs,
        decisions,
        admissions,
        intelligence,
        workspaces,
        now_func=lambda: NOW,
    )
    assert recovered.recover_pending() == 1
    assert recovered.has_pending() is False
    assert not any(settings.project_deletions_dir.iterdir())
    assert files.get("1" * 32).id == "1" * 32
    with pytest.raises(HTTPException, match="Job not found"):
        jobs.get(job.id)


def test_deletion_marker_invalidates_only_its_owner_before_the_cascade(tmp_path):
    configured = stores(tmp_path)
    settings, _files, _jobs, _projects, _decisions, _admissions, _intelligence, _workspaces, service = configured
    _source, project, _job = create_project_fixture(configured, owner_id=OWNER_A)
    clock = RiskTrendSourceClock(settings)
    clock.recover()
    owner_before = clock.revision(OWNER_A)
    foreign_before = clock.revision(OWNER_B)

    operation = service._prepare(organization_id=OWNER_A, project_id=project.id)

    assert operation is not None
    assert clock.revision(OWNER_A) != owner_before
    assert clock.revision(OWNER_B) == foreign_before
    assert service.has_pending() is True
    service._execute(operation)
    assert service.has_pending() is False
