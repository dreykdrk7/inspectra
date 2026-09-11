from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3

import pytest

from app.auth import hash_password
from app.active_assets import ActiveAssetCreateRequest, ActiveAssetStore
from app.active_change_approvals import ActiveChangeApprovalStore, ActiveChangeSummary
from app.active_asset_verification import ActiveAssetVerificationObservation, ActiveAssetVerificationStartRequest, ActiveAssetVerificationStore
from app.active_recurrence import ActiveRecurrenceCreateRequest, ActiveRecurrenceStore
from app.active_weekly_report import ActiveWeeklyReportPreflight
from app.active_weekly_review_receipts import (
    ACTIVE_WEEKLY_REVIEW_RECEIPT_KEY_NAME,
    ActiveWeeklyReviewReceiptStore,
)
from app.auth_state_sqlite import SQLiteAuthStateStore
from app.backup import BackupError, create_backup, restore_backup, validate_data_store, verify_backup
from app.config import Settings
from app.finding_lifecycle import FindingDecisionStore
from app.integration_events import IntegrationEventStore
from app.remediation_saved_views import (
    RemediationSavedViewCreateRequest,
    RemediationSavedViewFilters,
    RemediationSavedViewStore,
)
from app.remediation_plan_jobs import (
    RemediationPlanArtifact,
    RemediationPlanCreateRequest,
    RemediationPlanJobStore,
)
from app.models import RemediationSearchRequest, RemediationSummary
from app.models import JobRecord, ProjectPortfolioSearchRequest, StoredFile
from app.project_portfolio import ProjectPortfolioService
from app.product_audit import ProductAuditStore
from app.project_vulnerability_intelligence import ProjectVulnerabilityIntelligenceStore
from app.project_risk_trend_index import ProjectRiskTrendIndex
from app.project_action_inbox import ProjectActionInboxStore, ProjectActionRecord
from app.storage import FileStore, JobStore, ProjectStore
from app.team_identity import TeamIdentityStore


NOW = datetime(2026, 9, 6, 16, 0, tzinfo=timezone.utc)
OWNER_A = "a" * 32
OWNER_B = "b" * 32
BACKUP_ID = "c" * 32


def _settings(data_dir: Path) -> Settings:
    settings = Settings(data_dir=data_dir, tool_runner_url="http://audit-tools:8081")
    settings.ensure_directories()
    return settings


def _add_project(settings: Settings, *, owner_id: str, file_id: str, payload: bytes):
    files = FileStore(settings)
    projects = ProjectStore(settings)
    jobs = JobStore(settings)
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
    project = projects.create(name="Synthetic project", source=source, owner_id=owner_id)
    job = jobs.create_project_archive_job(
        source.id,
        owner_id=owner_id,
        project_id=project.id,
        source_sha256=source.sha256,
    )
    project = projects.attach_job(project.id, job.id)
    job = jobs.update(
        job.id,
        status="completed",
        result={"analyzer": "project_archive_basic", "summary": {}, "findings": []},
    )
    return source, project, job


def _build_complete_fixture(data_dir: Path):
    settings = _settings(data_dir)
    source_a, project_a, job_a = _add_project(
        settings,
        owner_id=OWNER_A,
        file_id="1" * 32,
        payload=b"PK\x03\x04synthetic-owner-a",
    )
    attested_snapshot = project_a.source_snapshots[0].model_copy(
        update={"source_commit_sha": "a" * 40, "source_channel": "git_cli"}
    )
    project_a = project_a.model_copy(update={"source_snapshots": [attested_snapshot]})
    ProjectStore(settings)._save_unlocked(project_a)
    source_b, project_b, job_b = _add_project(
        settings,
        owner_id=OWNER_B,
        file_id="2" * 32,
        payload=b"PK\x03\x04synthetic-owner-b",
    )
    FindingDecisionStore(settings, now_func=lambda: NOW).record(
        organization_id=OWNER_A,
        project_id=project_a.id,
        finding_id="f" * 64,
        rule_id="fixture.rule",
        status="in_review",
        reason="Synthetic review",
        comment=None,
        actor_id=OWNER_A,
        actor_username="fixture.admin",
        actor_role="administrator",
        review_at=None,
        assignee_user_id=None,
        assignee_username=None,
    )
    ProductAuditStore(settings, now_func=lambda: NOW).record(
        organization_id=OWNER_A,
        actor_id=OWNER_A,
        actor_role="administrator",
        action="project.created",
        resource_type="project",
        resource_id=project_a.id,
        correlation_id=f"project:{project_a.id}",
    )
    ProjectVulnerabilityIntelligenceStore(settings.public_advisories_dir).put(
        job_a.id,
        {"state": "disabled", "queried_at": NOW.isoformat(), "sources": [], "summary": {"findings": 0}},
        recorded_at=NOW,
    )

    password_hash = hash_password("synthetic-bootstrap-password")
    identity = TeamIdentityStore(
        settings.resolved_auth_state_db_path,
        organization_name="Synthetic team",
        bootstrap_admin_password_hash=password_hash,
        invitation_ttl_seconds=3600,
        now_func=lambda: NOW,
        token_factory=lambda: "synthetic-invitation-token-with-enough-entropy",
    )
    admin = identity.authenticate("admin", "synthetic-bootstrap-password")
    assert admin is not None
    identity.create_invitation(principal=admin, username="restore.reader", role="reader")
    public_identity = identity.propose_public_identity(
        principal=admin,
        ecosystem="pypi",
        package_name="requests-library",
        requested_ttl_days=30,
    )
    identity.approve_public_identity(principal=admin, attestation_id=public_identity.attestation_id)
    auth = SQLiteAuthStateStore(settings.resolved_auth_state_db_path)
    auth.create_session(
        "synthetic-session",
        "synthetic-csrf",
        OWNER_A,
        organization_id=OWNER_A,
        role="administrator",
        expires_at=NOW + timedelta(hours=1),
        now=NOW,
    )
    return settings, (source_a, project_a, job_a), (source_b, project_b, job_b)


def _create(data_dir: Path, destination: Path):
    return create_backup(
        data_dir,
        destination,
        offline_confirmed=True,
        sensitive_data_confirmed=True,
        encrypted_destination_confirmed=True,
        now=NOW,
        backup_id=BACKUP_ID,
    )


def test_full_backup_verify_restore_preserves_owner_boundaries_and_revokes_access_state(tmp_path):
    data_dir = tmp_path / "source-data"
    settings, owner_a, owner_b = _build_complete_fixture(data_dir)
    file_index = FileStore(settings).retention_index
    assert [record.id for record in file_index.expired_records(
        cutoff=NOW, protected_file_ids=set(), owner_id=OWNER_A
    )] == [owner_a[0].id]
    project_index = ProjectStore(settings).reference_index
    assert [record.id for record in project_index.records_for_sources(
        file_ids={owner_a[0].id}, owner_id=OWNER_A
    )] == [owner_a[1].id]
    backup_dir = tmp_path / "encrypted-backup"

    created = _create(data_dir, backup_dir)
    verified = verify_backup(backup_dir, sensitive_data_confirmed=True)
    restored_dir = tmp_path / "restored-data"
    restored = restore_backup(
        backup_dir,
        restored_dir,
        offline_confirmed=True,
        sensitive_data_confirmed=True,
    )

    assert created == verified
    assert created.backup_id == BACKUP_ID
    assert created.file_count > 8
    assert created.contains_sensitive_data is True
    assert restored.sessions_revoked == 1
    assert restored.invitations_revoked == 1
    validation = validate_data_store(restored_dir)
    assert validation.auth_schema_version == 2
    assert validation.team_identity_schema_version == 3
    restored_settings = _settings(restored_dir)
    restored_file_index = restored_settings.data_dir / "results" / "file_retention_index.sqlite3"
    assert restored_file_index.exists()
    with sqlite3.connect(restored_file_index) as connection:
        connection.execute(
            "UPDATE file_retention_index SET stored_filename = ? WHERE file_id = ?",
            (f"{owner_a[0].id}.tar", owner_a[0].id),
        )
    with pytest.raises(BackupError, match="invalid_storage_reference"):
        validate_data_store(restored_dir)
    repaired_files = FileStore(restored_settings)
    assert [record.id for record in repaired_files.retention_index.expired_records(
        cutoff=NOW, protected_file_ids=set(), owner_id=OWNER_A
    )] == [owner_a[0].id]
    validate_data_store(restored_dir)
    restored_project_index = restored_settings.data_dir / "results" / "project_reference_index.sqlite3"
    assert restored_project_index.exists()
    with sqlite3.connect(restored_project_index) as connection:
        connection.execute(
            "UPDATE project_reference_index SET baseline_reference_digest = ? WHERE project_id = ?",
            ("f" * 64, owner_a[1].id),
        )
    with pytest.raises(BackupError, match="invalid_storage_reference"):
        validate_data_store(restored_dir)
    repaired_projects = ProjectStore(restored_settings)
    assert [record.id for record in repaired_projects.reference_index.records_for_sources(
        file_ids={owner_a[0].id}, owner_id=OWNER_A
    )] == [owner_a[1].id]
    validate_data_store(restored_dir)
    with sqlite3.connect(restored_project_index) as connection:
        connection.execute("ALTER TABLE project_reference_index ADD COLUMN private_name TEXT")
        connection.execute(
            "UPDATE project_reference_index SET private_name = ? WHERE project_id = ?",
            ("backup-private-project-canary", owner_a[1].id),
        )
    with pytest.raises(BackupError, match="invalid_storage_reference"):
        validate_data_store(restored_dir)
    restored_project_index.unlink()
    rebuilt_projects = ProjectStore(restored_settings)
    assert rebuilt_projects.page(owner_id=OWNER_A, page_size=10)[1] == 1
    assert b"backup-private-project-canary" not in restored_project_index.read_bytes()
    validate_data_store(restored_dir)
    assert ProjectStore(restored_settings).get(owner_a[1].id).owner_id == OWNER_A
    assert ProjectStore(restored_settings).get(owner_a[1].id).source_snapshots[0].source_channel == "git_cli"
    assert ProjectStore(restored_settings).get(owner_b[1].id).owner_id == OWNER_B
    assert JobStore(restored_settings).get(owner_a[2].id).owner_id == OWNER_A
    assert JobStore(restored_settings).get(owner_b[2].id).owner_id == OWNER_B
    assert FileStore(restored_settings).source_path(FileStore(restored_settings).get(owner_a[0].id)).read_bytes() == b"PK\x03\x04synthetic-owner-a"
    with sqlite3.connect(restored_settings.resolved_auth_state_db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM auth_login_attempts").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM team_invitations").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM team_users").fetchone()[0] == 1
        assert connection.execute(
            "SELECT ecosystem, package_name, state FROM team_public_identity_attestations"
        ).fetchone() == ("pypi", "requests-library", "approved")
    for directory, _directories, files in os.walk(restored_dir):
        assert Path(directory).stat().st_mode & 0o077 == 0
        for filename in files:
            assert (Path(directory) / filename).stat().st_mode & 0o077 == 0


def test_backup_restore_preserves_committed_remediation_batch_receipts(tmp_path):
    data_dir = tmp_path / "source-data"
    settings, owner_a, _owner_b = _build_complete_fixture(data_dir)
    project = owner_a[1]
    store = FindingDecisionStore(settings, now_func=lambda: NOW, id_factory=lambda: "9" * 32)
    request_payload = {"group_id": "8" * 64, "selection": project.id}
    operation_id, request_digest = store.batch_binding(
        organization_id=OWNER_A,
        actor_id="team-admin",
        idempotency_key="backup-remediation-batch-01",
        request_payload=request_payload,
    )
    decisions, replayed = store.record_many(
        organization_id=OWNER_A,
        operation_id=operation_id,
        request_digest=request_digest,
        group_id="8" * 64,
        items=[(project.id, "7" * 64, "configuration_backup_fixture")],
        status="in_review",
        reason="Restore must preserve this decision",
        comment=None,
        actor_id="team-admin",
        actor_username="admin",
        actor_role="administrator",
        review_at=None,
        assignee_user_id=None,
        assignee_username=None,
    )
    assert replayed is False

    backup_dir = tmp_path / "encrypted-backup"
    _create(data_dir, backup_dir)
    restored_dir = tmp_path / "restored-data"
    restore_backup(
        backup_dir,
        restored_dir,
        offline_confirmed=True,
        sensitive_data_confirmed=True,
    )

    restored = FindingDecisionStore(_settings(restored_dir))
    assert restored.replay_batch(
        operation_id,
        organization_id=OWNER_A,
        request_digest=request_digest,
    ) == decisions
    validate_data_store(restored_dir)


def test_backup_restore_preserves_scoped_remediation_saved_views(tmp_path):
    data_dir = tmp_path / "source-data"
    settings, _owner_a, _owner_b = _build_complete_fixture(data_dir)
    saved = RemediationSavedViewStore(settings, now_func=lambda: NOW, id_factory=lambda: "9" * 32)
    created = saved.create(
        OWNER_A,
        "team-admin",
        RemediationSavedViewCreateRequest(
            name="Urgent public review",
            visibility="private",
            make_default=True,
            filters=RemediationSavedViewFilters(priority="urgent", evidence_kind="public_vulnerability"),
        ),
        can_share=True,
    )
    backup_dir = tmp_path / "encrypted-backup"
    _create(data_dir, backup_dir)
    restored_dir = tmp_path / "restored-data"
    restore_backup(
        backup_dir,
        restored_dir,
        offline_confirmed=True,
        sensitive_data_confirmed=True,
    )
    page = RemediationSavedViewStore(_settings(restored_dir)).list_visible(OWNER_A, "team-admin")
    assert page.items == [created]
    assert page.default_view_id == created.id
    validate_data_store(restored_dir)
    saved_path = restored_dir / "results" / "remediation_saved_views" / f"{OWNER_A}.json"
    saved_payload = json.loads(saved_path.read_text(encoding="utf-8"))
    saved_payload["views"][0]["organization_id"] = OWNER_B
    saved_path.write_text(json.dumps(saved_payload), encoding="utf-8")
    with pytest.raises(BackupError, match="invalid_storage_record"):
        validate_data_store(restored_dir)


def test_backup_restore_preserves_project_action_reads_and_rejects_cross_tenant_reference(tmp_path):
    data_dir = tmp_path / "source-data"
    settings, owner_a, owner_b = _build_complete_fixture(data_dir)
    action_store = ProjectActionInboxStore(settings)
    action_store.reconcile(OWNER_A, [ProjectActionRecord(
        id="9" * 32,
        organization_id=OWNER_A,
        project_id=owner_a[1].id,
        analysis_id=owner_a[2].id,
        reason="critical_findings",
        priority="urgent",
        destination="findings",
        occurred_at=NOW,
    )])
    action_store.mark_read(OWNER_A, "9" * 32, "team-admin")

    backup_dir = tmp_path / "encrypted-backup"
    _create(data_dir, backup_dir)
    restored_dir = tmp_path / "restored-data"
    restore_backup(
        backup_dir,
        restored_dir,
        offline_confirmed=True,
        sensitive_data_confirmed=True,
    )

    restored_path = restored_dir / "results" / "project_action_inbox" / f"{OWNER_A}.json"
    restored_payload = json.loads(restored_path.read_text(encoding="utf-8"))
    assert restored_payload["events"][0]["read_by"]
    validate_data_store(restored_dir)

    restored_payload["events"][0]["project_id"] = owner_b[1].id
    restored_path.write_text(json.dumps(restored_payload), encoding="utf-8")
    with pytest.raises(BackupError, match="invalid_ownership_boundary"):
        validate_data_store(restored_dir)


def test_backup_restore_preserves_completed_remediation_plan_and_rejects_pending(tmp_path):
    data_dir = tmp_path / "source-data"
    settings, _owner_a, _owner_b = _build_complete_fixture(data_dir)
    store = RemediationPlanJobStore(settings, now_func=lambda: NOW)
    job = store.create(OWNER_A, RemediationPlanCreateRequest(
        filters=RemediationSearchRequest(),
        idempotency_key="backup-remediation-plan-0001",
        project_metadata_confirmed=True,
    ))
    store.claim(OWNER_A, job.id, project_revision="revision-a", total_projects=0)
    store.complete(OWNER_A, job.id, RemediationPlanArtifact(
        job_id=job.id,
        organization_id=OWNER_A,
        cutoff_at=NOW,
        project_revision="revision-a",
        processed_projects=0,
        total_projects=0,
        included_groups=0,
        included_occurrences=0,
        groups_truncated=False,
        occurrences_truncated=False,
        summary=RemediationSummary(
            total_groups=0, filtered_groups=0, urgent_groups=0, high_groups=0,
            projects_affected=0, known_exploited_groups=0, conflicting_groups=0,
            awaiting_reanalysis=0,
        ),
        groups=[],
        limitations=["Comparable reanalysis is required."],
    ))
    backup_dir = tmp_path / "encrypted-backup"
    _create(data_dir, backup_dir)
    restored_dir = tmp_path / "restored-data"
    restore_backup(
        backup_dir, restored_dir,
        offline_confirmed=True, sensitive_data_confirmed=True,
    )
    restored = RemediationPlanJobStore(_settings(restored_dir), now_func=lambda: NOW)
    restored_job, artifact = restored.artifact(OWNER_A, job.id)
    assert restored_job.snapshot_sha256
    assert artifact.cutoff_at == NOW
    validate_data_store(restored_dir)

    pending = store.create(OWNER_A, RemediationPlanCreateRequest(
        filters=RemediationSearchRequest(),
        idempotency_key="backup-remediation-plan-0002",
        project_metadata_confirmed=True,
    ))
    with pytest.raises(BackupError, match="active_jobs_present"):
        _create(data_dir, tmp_path / "must-not-exist")
    assert store.get(OWNER_A, pending.id).status == "queued"


def test_backup_validates_private_risk_trend_projection_and_rejects_schema_drift(tmp_path):
    data_dir = tmp_path / "source-data"
    settings, owner_a, _owner_b = _build_complete_fixture(data_dir)
    decisions = FindingDecisionStore(settings, now_func=lambda: NOW)
    jobs = JobStore(settings)
    projects = ProjectStore(settings)
    intelligence = ProjectVulnerabilityIntelligenceStore(settings.public_advisories_dir)
    index = ProjectRiskTrendIndex(settings, projects, jobs, intelligence, decisions)
    index.rebuild_owner(organization_id=OWNER_A, projects=[owner_a[1]])
    index.request_refresh(organization_id=OWNER_A, observed_at=NOW)
    validate_data_store(data_dir)

    backup_dir = tmp_path / "encrypted-backup"
    _create(data_dir, backup_dir)
    restored_dir = tmp_path / "restored-data"
    restore_backup(
        backup_dir,
        restored_dir,
        offline_confirmed=True,
        sensitive_data_confirmed=True,
    )
    validate_data_store(restored_dir)

    restored_clock = restored_dir / "results" / "risk_trend_source_clock.sqlite3"
    with sqlite3.connect(restored_clock) as connection:
        original_epoch = connection.execute(
            "SELECT value FROM risk_trend_source_clock_metadata WHERE key = 'epoch'"
        ).fetchone()[0]
        connection.execute(
            "UPDATE risk_trend_source_clock_metadata SET value = 'invalid' WHERE key = 'epoch'"
        )
        connection.commit()
    with pytest.raises(BackupError, match="invalid_storage_reference"):
        validate_data_store(restored_dir)
    with sqlite3.connect(restored_clock) as connection:
        connection.execute(
            "UPDATE risk_trend_source_clock_metadata SET value = ? WHERE key = 'epoch'",
            (original_epoch,),
        )
        connection.commit()
    validate_data_store(restored_dir)

    restored_index = restored_dir / "results" / "project_risk_trend_index.sqlite3"
    with sqlite3.connect(restored_index) as connection:
        desired = connection.execute(
            "SELECT desired_revision FROM risk_trend_refresh_state WHERE owner_id = ?",
            (OWNER_A,),
        ).fetchone()[0]
        connection.execute(
            "UPDATE risk_trend_refresh_state SET built_revision = 'invalid' WHERE owner_id = ?",
            (OWNER_A,),
        )
        connection.commit()
    with pytest.raises(BackupError, match="invalid_storage_reference"):
        validate_data_store(restored_dir)
    with sqlite3.connect(restored_index) as connection:
        connection.execute(
            "UPDATE risk_trend_refresh_state SET built_revision = ? WHERE owner_id = ?",
            (desired, OWNER_A),
        )
        connection.execute(
            "UPDATE risk_trend_metadata SET value = '999' WHERE key = 'schema_version'"
        )
        connection.commit()
    with pytest.raises(BackupError, match="invalid_storage_reference"):
        validate_data_store(restored_dir)


def test_backup_validates_private_portfolio_priority_projection_and_rebuilds_after_restore(tmp_path):
    data_dir = tmp_path / "source-data"
    settings, owner_a, _owner_b = _build_complete_fixture(data_dir)
    decisions = FindingDecisionStore(settings, now_func=lambda: NOW)
    jobs = JobStore(settings)
    projects = ProjectStore(settings)
    intelligence = ProjectVulnerabilityIntelligenceStore(settings.public_advisories_dir)
    portfolio = ProjectPortfolioService(projects, jobs, intelligence, decisions)
    page = portfolio.search(
        organization_id=OWNER_A,
        payload=ProjectPortfolioSearchRequest(),
        now=NOW,
    )
    assert page.total_count == 1
    index_path = settings.results_dir / "project_portfolio_priority_index.sqlite3"
    assert b"Synthetic project" not in index_path.read_bytes()
    validate_data_store(data_dir)

    backup_dir = tmp_path / "encrypted-backup"
    _create(data_dir, backup_dir)
    restored_dir = tmp_path / "restored-data"
    restore_backup(
        backup_dir,
        restored_dir,
        offline_confirmed=True,
        sensitive_data_confirmed=True,
    )
    restored_settings = _settings(restored_dir)
    restored_projects = ProjectStore(restored_settings)
    restored_jobs = JobStore(restored_settings)
    restored_intelligence = ProjectVulnerabilityIntelligenceStore(
        restored_settings.public_advisories_dir
    )
    restored_decisions = FindingDecisionStore(restored_settings, now_func=lambda: NOW)
    recovered = ProjectPortfolioService(
        restored_projects, restored_jobs, restored_intelligence, restored_decisions
    ).search(
        organization_id=OWNER_A,
        payload=ProjectPortfolioSearchRequest(),
        now=NOW,
    )
    assert recovered.total_count == 1

    restored_index = restored_settings.results_dir / "project_portfolio_priority_index.sqlite3"
    with sqlite3.connect(restored_index) as connection:
        connection.execute(
            "ALTER TABLE portfolio_priority_fact ADD COLUMN private_name TEXT"
        )
        connection.commit()
    with pytest.raises(BackupError, match="invalid_storage_reference"):
        validate_data_store(restored_dir)


def test_manifest_is_host_path_and_human_identity_free_but_declares_sensitive_scope(tmp_path):
    data_dir = tmp_path / "source-data"
    _build_complete_fixture(data_dir)
    settings = _settings(data_dir)
    outbox = IntegrationEventStore(settings.integration_event_outbox_path, now_func=lambda: NOW)
    outbox.enqueue_terminal_analysis(
        organization_id=OWNER_A,
        project_id="d" * 32,
        analysis_id="e" * 32,
        status="failed",
        occurred_at=NOW,
        finding_count=None,
    )
    claimed = outbox.claim_due()
    assert claimed is not None
    outbox.record_result(claimed.payload.event_id, accepted=True, retryable=False)
    backup_dir = tmp_path / "encrypted-backup"
    _create(data_dir, backup_dir)

    manifest_text = (backup_dir / "manifest.json").read_text(encoding="utf-8")
    manifest = json.loads(manifest_text)

    assert manifest["contains_sensitive_data"] is True
    assert manifest["source_bytes_included"] is True
    assert manifest["auth_state_included"] is True
    assert "external_configuration" in manifest["excluded_classes"]
    assert "execution_workspaces" in manifest["excluded_classes"]
    assert "integration_event_outbox" in manifest["excluded_classes"]
    assert all("integration_event_outbox" not in entry["relative_path"] for entry in manifest["entries"])
    assert not (backup_dir / "payload" / "runtime" / "integration_event_outbox.sqlite3").exists()
    restored_dir = tmp_path / "restored-data"
    restore_backup(
        backup_dir,
        restored_dir,
        offline_confirmed=True,
        sensitive_data_confirmed=True,
    )
    assert not (_settings(restored_dir).integration_event_outbox_path).exists()
    for forbidden in (
        str(data_dir),
        "authorized-private.zip",
        "Synthetic project",
        "synthetic-session",
        "synthetic-csrf",
        "synthetic-invitation-token",
    ):
        assert forbidden not in manifest_text


def test_backup_refuses_to_drop_pending_integration_events(tmp_path):
    data_dir = tmp_path / "source-data"
    _build_complete_fixture(data_dir)
    settings = _settings(data_dir)
    IntegrationEventStore(settings.integration_event_outbox_path, now_func=lambda: NOW).enqueue_terminal_analysis(
        organization_id=OWNER_A,
        project_id="d" * 32,
        analysis_id="e" * 32,
        status="failed",
        occurred_at=NOW,
        finding_count=None,
    )

    with pytest.raises(BackupError, match="pending_integration_events_present"):
        _create(data_dir, tmp_path / "encrypted-backup")


def test_backup_validates_restores_and_replays_active_batch_receipts(tmp_path):
    data_dir = tmp_path / "source-data"
    settings = _settings(data_dir)
    request = ActiveAssetCreateRequest.model_validate(
        {
            "asset_type": "domain",
            "value": "batch-backup.example.test",
            "responsible_user_ids": [OWNER_A],
            "capabilities": ["active_dns_inventory"],
            "allowed_ports": [],
            "allowed_protocols": ["dns"],
            "authorization_method": "manual_attestation",
            "authorization_reference": "approved-backup-fixture",
            "authorized_at": NOW.isoformat(),
            "expires_at": (NOW + timedelta(days=30)).isoformat(),
            "notes": [],
        }
    )
    created, replayed, _batch_id = ActiveAssetStore(settings, now_func=lambda: NOW).create_many(
        [request],
        organization_id=OWNER_A,
        actor_id=OWNER_A,
        normalized_digest_sha256="d" * 64,
        idempotency_key="e" * 32,
    )
    assert replayed is False
    asset = created[0]
    verifications = ActiveAssetVerificationStore(settings, now_func=lambda: NOW)
    pending, token = verifications.start(
        asset,
        ActiveAssetVerificationStartRequest(method="manual_attestation", valid_for_days=7, control_check_confirmed=True),
        organization_id=OWNER_A,
        actor_id=OWNER_A,
    )
    verified = verifications.complete(
        pending.id, asset=asset, organization_id=OWNER_A, challenge_token=token,
        observation=ActiveAssetVerificationObservation(True, "matched"),
    )
    assert verifications.latest(asset.id, organization_id=OWNER_A).id == verified.id
    active_job = JobRecord(
        id="f" * 32,
        owner_id=OWNER_A,
        active_asset_id=asset.id,
        audit_type="active_dns_inventory",
        status="completed",
        created_at=NOW,
        updated_at=NOW,
    )
    jobs = JobStore(settings)
    jobs.save(active_job)
    assert jobs.active_operations_snapshot(
        owner_id=OWNER_A, asset_ids={asset.id}
    )[1] == 1
    revision = asset.authorization_revisions[-1]
    recurrence_store = ActiveRecurrenceStore(settings, now_func=lambda: NOW)
    schedule, _ = recurrence_store.create(
        ActiveRecurrenceCreateRequest(
            capability="active_dns_inventory", interval_days=7,
            timezone_name="UTC", window_weekdays=["monday"],
            window_start_hour=9, window_duration_hours=4,
            recurrence_confirmed=True, idempotency_key="a" * 32,
        ),
        organization_id=OWNER_A, asset_id=asset.id, actor_id=OWNER_A,
        actor_role="administrator", authorization_revision_id=revision.id,
        authorization_revision_digest_sha256=revision.digest_sha256,
        authorization_revision_sequence=revision.sequence,
        authorization_expires_at=revision.expires_at, verification_id=verified.id,
    )
    assert recurrence_store.list_for_asset(asset.id, organization_id=OWNER_A)[0].id == schedule.id
    approval_store = ActiveChangeApprovalStore(settings, now_func=lambda: NOW)
    approval = approval_store.request(
        organization_id=OWNER_A,
        actor_id=OWNER_A,
        actor_role="maintainer",
        kind="renewal",
        asset_id=asset.id,
        operation_digest_sha256="9" * 64,
        summary=ActiveChangeSummary(
            asset_type="domain",
            scope_change="same_scope",
            capabilities=("active_dns_inventory",),
            allowed_protocols=("dns",),
            authorization_expires_at=NOW + timedelta(days=30),
        ),
    )
    weekly_digest = "6" * 64
    receipt_store = ActiveWeeklyReviewReceiptStore(settings, now_func=lambda: NOW)
    weekly_receipt = receipt_store.create(
        organization_id=OWNER_A,
        preflight=ActiveWeeklyReportPreflight(
            state="ready", period="7d", starts_at=NOW - timedelta(days=7),
            state_at=NOW, snapshot_digest=weekly_digest,
            assets_total=1, assets_included=1, jobs_total=1, jobs_included=1,
            actions_total=0, actions_included=0,
            recurrence_attention_total=0, recurrence_attention_included=0,
            incomplete=False,
        ),
        outcome="reviewed",
        expected_revision=0,
        idempotency_key="weekly-review-backup-fixture-001",
    )

    backup_dir = tmp_path / "backup"
    _create(data_dir, backup_dir)
    manifest = json.loads((backup_dir / "manifest.json").read_text(encoding="utf-8"))
    backup_paths = {
        entry["relative_path"] for entry in manifest["entries"]
    }
    assert {
        "results/active_asset_index.sqlite3",
        "results/active_job_index.sqlite3",
        "results/active_verification_index.sqlite3",
        "results/active_recurrence_index.sqlite3",
        f"results/active_change_approvals/{OWNER_A}.json",
        f"results/active_weekly_review_receipts/{OWNER_A}.json",
        f"results/active_weekly_review_receipts/{ACTIVE_WEEKLY_REVIEW_RECEIPT_KEY_NAME}",
    } <= backup_paths
    restored_dir = tmp_path / "restored"
    restore_backup(
        backup_dir,
        restored_dir,
        offline_confirmed=True,
        sensitive_data_confirmed=True,
    )
    restored = ActiveAssetStore(_settings(restored_dir), now_func=lambda: NOW)
    repeated, was_replayed, _ = restored.create_many(
        [request],
        organization_id=OWNER_A,
        actor_id=OWNER_A,
        normalized_digest_sha256="d" * 64,
        idempotency_key="e" * 32,
    )
    assert was_replayed is True
    assert [item.id for item in repeated] == [created[0].id]
    assert [item.id for item in restored.page(organization_id=OWNER_A).items] == [asset.id]
    restored_jobs = JobStore(_settings(restored_dir))
    restored_job_records, restored_job_total = restored_jobs.active_operations_snapshot(
        owner_id=OWNER_A, asset_ids={asset.id}
    )
    assert restored_job_total == 1
    assert [item.id for item in restored_job_records] == [active_job.id]
    restored_verifications = ActiveAssetVerificationStore(
        _settings(restored_dir), now_func=lambda: NOW
    )
    assert restored_verifications.latest(asset.id, organization_id=OWNER_A).id == verified.id
    restored_recurrences = ActiveRecurrenceStore(_settings(restored_dir), now_func=lambda: NOW)
    restored_schedules = restored_recurrences.list_for_asset(
        asset.id, organization_id=OWNER_A
    )
    assert [item.id for item in restored_schedules] == [schedule.id]
    restored_approvals = ActiveChangeApprovalStore(
        _settings(restored_dir), now_func=lambda: NOW
    ).list(OWNER_A)
    assert [item.id for item in restored_approvals] == [approval.id]
    restored_receipts = ActiveWeeklyReviewReceiptStore(
        _settings(restored_dir), now_func=lambda: NOW
    )
    assert [item.id for item in restored_receipts.list(OWNER_A).items] == [weekly_receipt.receipt.id]
    assert restored_receipts.verify(OWNER_A, weekly_receipt.receipt.id, weekly_digest).valid is True

    with sqlite3.connect(restored.index_path) as connection:
        connection.execute(
            "DELETE FROM active_asset_index WHERE organization_id = ? AND asset_id = ?",
            (OWNER_A, asset.id),
        )
    with pytest.raises(BackupError, match="invalid_storage_reference"):
        validate_data_store(restored_dir)
    repaired = ActiveAssetStore(_settings(restored_dir), now_func=lambda: NOW)
    assert [item.id for item in repaired.page(organization_id=OWNER_A).items] == [asset.id]
    validate_data_store(restored_dir)

    with sqlite3.connect(restored_jobs.active_index.path) as connection:
        connection.execute("DELETE FROM active_job_index WHERE job_id = ?", (active_job.id,))
    with pytest.raises(BackupError, match="invalid_storage_reference"):
        validate_data_store(restored_dir)
    assert restored_jobs.active_operations_snapshot(
        owner_id=OWNER_A, asset_ids={asset.id}
    )[1] == 1
    validate_data_store(restored_dir)

    with sqlite3.connect(restored_jobs.active_index.path) as connection:
        source_job_id = active_job.id
        connection.execute(
            "UPDATE active_job_index SET source_reference_digest = ? WHERE job_id = ?",
            ("f" * 64, source_job_id),
        )
    with pytest.raises(BackupError, match="invalid_storage_reference"):
        validate_data_store(restored_dir)
    restored_jobs.page(owner_id=OWNER_A)
    validate_data_store(restored_dir)

    with sqlite3.connect(restored_jobs.active_index.path) as connection:
        connection.execute(
            "UPDATE active_job_index SET source_deleted = 1 - source_deleted WHERE job_id = ?",
            (source_job_id,),
        )
    with pytest.raises(BackupError, match="invalid_storage_reference"):
        validate_data_store(restored_dir)
    restored_jobs.page(owner_id=OWNER_A)
    validate_data_store(restored_dir)

    with sqlite3.connect(restored_verifications.index.path) as connection:
        connection.execute(
            "DELETE FROM active_verification_index WHERE verification_id = ?",
            (verified.id,),
        )
    with pytest.raises(BackupError, match="invalid_storage_reference"):
        validate_data_store(restored_dir)
    assert restored_verifications.latest(asset.id, organization_id=OWNER_A).id == verified.id
    validate_data_store(restored_dir)

    with sqlite3.connect(restored_recurrences.index.path) as connection:
        connection.execute(
            "UPDATE active_recurrence_index SET status = 'paused' WHERE schedule_id = ?",
            (schedule.id,),
        )
    with pytest.raises(BackupError, match="invalid_storage_reference"):
        validate_data_store(restored_dir)
    assert restored_recurrences.list_for_asset(
        asset.id, organization_id=OWNER_A
    )[0].status == "active"
    validate_data_store(restored_dir)

    receipt_path = next((restored_dir / "results" / "active_asset_batches").rglob("*.json"))
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["record_ids"] = ["f" * 32]
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    with pytest.raises(BackupError, match="invalid_ownership_boundary"):
        validate_data_store(restored_dir)


@pytest.mark.parametrize(
    ("offline", "sensitive", "encrypted", "code"),
    [
        (False, True, True, "offline_confirmation_required"),
        (True, False, True, "sensitive_data_confirmation_required"),
        (True, True, False, "encrypted_destination_confirmation_required"),
    ],
)
def test_backup_requires_explicit_operator_confirmations(tmp_path, offline, sensitive, encrypted, code):
    data_dir = tmp_path / "source-data"
    _settings(data_dir)
    with pytest.raises(BackupError, match=code):
        create_backup(
            data_dir,
            tmp_path / "backup",
            offline_confirmed=offline,
            sensitive_data_confirmed=sensitive,
            encrypted_destination_confirmed=encrypted,
        )


@pytest.mark.parametrize("active_state", ["queued", "running", "cancelling"])
def test_backup_rejects_active_jobs_without_leaving_partial_output(tmp_path, active_state):
    data_dir = tmp_path / "source-data"
    settings = _settings(data_dir)
    _source, _project, job = _add_project(
        settings,
        owner_id=OWNER_A,
        file_id="1" * 32,
        payload=b"PK\x03\x04synthetic",
    )
    JobStore(settings).update(job.id, status=active_state)
    backup_dir = tmp_path / "backup"

    with pytest.raises(BackupError, match="active_jobs_present"):
        _create(data_dir, backup_dir)
    assert not backup_dir.exists()
    assert not list(tmp_path.glob(".backup.tmp-*"))


@pytest.mark.parametrize(
    ("relative_path", "code"),
    [
        ("workspaces/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/source.archive", "execution_workspaces_present"),
        ("runtime/project_snapshot_admissions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json", "pending_operations_present"),
        ("runtime/project_deletions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json", "pending_operations_present"),
        ("runtime/remediation_batches/" + "a" * 64 + ".json", "pending_operations_present"),
        ("results/active_asset_batches/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/.pending-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.json", "pending_operations_present"),
        ("runtime/auth_state.sqlite3-wal", "sqlite_not_quiescent"),
    ],
)
def test_backup_rejects_non_quiescent_ephemeral_state(tmp_path, relative_path, code):
    data_dir = tmp_path / "source-data"
    _settings(data_dir)
    marker = data_dir / relative_path
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("synthetic", encoding="utf-8")

    with pytest.raises(BackupError, match=code):
        _create(data_dir, tmp_path / "backup")


def test_checksum_corruption_and_extra_entry_fail_before_restore_publication(tmp_path):
    data_dir = tmp_path / "source-data"
    _build_complete_fixture(data_dir)
    backup_dir = tmp_path / "backup"
    _create(data_dir, backup_dir)
    payload_entry = next(path for path in (backup_dir / "payload").rglob("*") if path.is_file())
    original_payload = payload_entry.read_bytes()
    payload_entry.write_bytes(original_payload + b"corrupt")

    with pytest.raises(BackupError, match="checksum_mismatch"):
        restore_backup(
            backup_dir,
            tmp_path / "restored-data",
            offline_confirmed=True,
            sensitive_data_confirmed=True,
        )
    assert not (tmp_path / "restored-data").exists()
    assert not list(tmp_path.glob(".restored-data.restore-*"))

    payload_entry.write_bytes(original_payload)
    extra = backup_dir / "unexpected"
    extra.write_text("synthetic", encoding="utf-8")
    with pytest.raises(BackupError, match="unexpected_backup_entry"):
        verify_backup(backup_dir, sensitive_data_confirmed=True)


def test_restore_rejects_existing_target_and_unsafe_manifest_path(tmp_path):
    data_dir = tmp_path / "source-data"
    _build_complete_fixture(data_dir)
    backup_dir = tmp_path / "backup"
    _create(data_dir, backup_dir)
    target = tmp_path / "existing"
    target.mkdir()
    with pytest.raises(BackupError, match="destination_exists"):
        restore_backup(backup_dir, target, offline_confirmed=True, sensitive_data_confirmed=True)

    manifest_path = backup_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["entries"][0]["relative_path"] = "../outside"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(BackupError, match="invalid_relative_path"):
        verify_backup(backup_dir, sensitive_data_confirmed=True)


def test_cross_owner_reference_and_unexpected_symlink_are_rejected(tmp_path):
    data_dir = tmp_path / "source-data"
    settings, owner_a, _owner_b = _build_complete_fixture(data_dir)
    job_path = settings.jobs_dir / f"{owner_a[2].id}.json"
    job = json.loads(job_path.read_text(encoding="utf-8"))
    job["owner_id"] = OWNER_B
    job["organization_id"] = OWNER_B
    job_path.write_text(json.dumps(job), encoding="utf-8")
    with pytest.raises(BackupError, match="invalid_ownership_boundary"):
        _create(data_dir, tmp_path / "backup-owner")

    job["owner_id"] = OWNER_A
    job["organization_id"] = OWNER_A
    job_path.write_text(json.dumps(job), encoding="utf-8")
    (settings.results_dir / "unsafe-link").symlink_to(tmp_path / "outside")
    with pytest.raises(BackupError, match="symlink_not_allowed"):
        _create(data_dir, tmp_path / "backup-link")


def test_unsupported_auth_schema_and_cli_errors_are_content_free(tmp_path, capsys):
    from app.backup_cli import main

    data_dir = tmp_path / "source-data"
    _build_complete_fixture(data_dir)
    with sqlite3.connect(data_dir / "runtime" / "auth_state.sqlite3") as connection:
        connection.execute("UPDATE auth_state_metadata SET value = '999' WHERE key = 'schema_version'")
        connection.commit()
    with pytest.raises(BackupError, match="unsupported_auth_schema"):
        _create(data_dir, tmp_path / "backup")

    sensitive_marker = "private-path-marker"
    exit_code = main(["verify", "--backup", str(tmp_path / sensitive_marker)])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert sensitive_marker not in captured.err
    assert json.loads(captured.err) == {"code": "sensitive_data_confirmation_required", "status": "failed"}


def test_restore_migrates_supported_legacy_auth_schema_and_revokes_legacy_session(tmp_path):
    data_dir = tmp_path / "source-data"
    settings = _settings(data_dir)
    db_path = settings.resolved_auth_state_db_path
    with sqlite3.connect(db_path) as connection:
        connection.executescript(
            """
            CREATE TABLE auth_sessions (
                session_id_hash TEXT PRIMARY KEY,
                csrf_token_hash TEXT NOT NULL,
                operator_id TEXT NOT NULL,
                auth_mode TEXT NOT NULL,
                created_at REAL NOT NULL,
                last_seen_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                revoked_at REAL NULL,
                revocation_reason TEXT NULL,
                client_key_hash TEXT NULL,
                user_agent_hash TEXT NULL
            );
            CREATE TABLE auth_state_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at REAL NOT NULL
            );
            INSERT INTO auth_sessions VALUES (
                'legacy-session-hash', 'legacy-csrf-hash', 'local-admin',
                'self_hosted_single_admin', 1, 1, 4102444800,
                NULL, NULL, NULL, NULL
            );
            INSERT INTO auth_state_metadata VALUES ('schema_version', '1', 1);
            """
        )
    backup_dir = tmp_path / "backup"
    created = _create(data_dir, backup_dir)
    assert created.auth_state_included is True

    restored_dir = tmp_path / "restored-data"
    restored = restore_backup(
        backup_dir,
        restored_dir,
        offline_confirmed=True,
        sensitive_data_confirmed=True,
    )

    assert restored.sessions_revoked == 1
    restored_db = restored_dir / "runtime" / "auth_state.sqlite3"
    with sqlite3.connect(restored_db) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(auth_sessions)")}
        version = connection.execute("SELECT value FROM auth_state_metadata WHERE key = 'schema_version'").fetchone()[0]
        sessions = connection.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0]
    assert {"organization_id", "role"}.issubset(columns)
    assert version == "2"
    assert sessions == 0
