from datetime import datetime, timedelta, timezone
import hashlib
import json
import sqlite3

import pytest
from fastapi import HTTPException

from app.config import load_settings
from app.auth import hash_password
from app.automation_tokens import AutomationTokenError, AutomationTokenStore
from app.active_weekly_report import ActiveWeeklyReportPreflight
from app.active_weekly_review_receipts import ActiveWeeklyReviewReceiptStore
from app.models import JobRecord, StoredFile
from app.product_audit import ProductAuditStore
from app.project_vulnerability_intelligence import ProjectVulnerabilityIntelligenceStore
from app.public_advisory_egress import PublicAdvisoryResponseCache, public_advisory_cache_key
from app.retention import RetentionMaintenanceService, build_retention_policy
from app.storage import FileStore, JobStore, ProjectStore
from app.team_identity import TeamIdentityStore, hash_invitation_token


NOW = datetime(2026, 9, 6, 12, tzinfo=timezone.utc)
OLD = NOW - timedelta(days=40)
OWNER_A = "a" * 32
OWNER_B = "b" * 32


def configured_stores(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    settings = load_settings()
    settings.ensure_directories()
    files = FileStore(settings)
    jobs = JobStore(settings)
    projects = ProjectStore(settings)
    intelligence = ProjectVulnerabilityIntelligenceStore(settings.public_advisories_dir)
    cache = PublicAdvisoryResponseCache(
        settings.public_advisories_dir,
        ttl_seconds=settings.public_advisory_cache_ttl_seconds,
        retention_seconds=settings.public_advisory_cache_retention_seconds,
        max_response_bytes=settings.public_advisory_max_response_bytes,
    )
    audit_clock = [OLD]
    audit = ProductAuditStore(settings, now_func=lambda: audit_clock[0])
    return settings, files, jobs, projects, intelligence, cache, audit, audit_clock


def store_source(files: FileStore, file_id: str, owner_id: str, created_at: datetime) -> StoredFile:
    record = StoredFile(
        id=file_id,
        owner_id=owner_id,
        kind="archive",
        original_filename="authorized.zip",
        stored_filename=f"{file_id}.zip",
        content_type="application/zip",
        size_bytes=4,
        sha256=hashlib.sha256(b"PK00").hexdigest(),
        created_at=created_at,
    )
    files.source_path(record).write_bytes(b"PK00")
    files._save_record(record)
    return record


def store_job(jobs: JobStore, job_id: str, owner_id: str, file_id: str, status: str = "completed") -> JobRecord:
    record = JobRecord(
        id=job_id,
        owner_id=owner_id,
        audit_type="project_archive_basic",
        file_id=file_id,
        status=status,
        created_at=OLD,
        updated_at=OLD,
        result={"component_inventory": {"components": []}} if status == "completed" else None,
    )
    jobs.save(record)
    return record


def test_policy_exposes_only_lifecycle_values_and_honest_operator_boundaries(monkeypatch, tmp_path):
    settings, *_ = configured_stores(monkeypatch, tmp_path)
    payload = build_retention_policy(settings, manual_cleanup_allowed=False).model_dump(mode="json")
    serialized = json.dumps(payload)

    assert payload["contract_version"] == "2026-09-10.7"
    assert payload["manual_cleanup_allowed"] is False
    assert payload["application_encryption_at_rest"] == "operator_managed"
    assert payload["backups"] == "offline_bundle_operator_encrypted_not_automatically_purged"
    assert payload["backup_contract_version"] == "2026-09-06.1"
    assert payload["data_classification_complete"] is True
    assert payload["source_metadata_contract_version"] == "2026-09-09.2"
    source_metadata = {item["key"]: item for item in payload["source_metadata"]}
    assert set(source_metadata) == {
        "original_filename",
        "content_sha256",
        "source_file_id",
        "source_reference",
        "source_channel",
    }
    assert source_metadata["source_file_id"]["project_view_disclosure"] == "withheld"
    assert source_metadata["original_filename"]["project_view_disclosure"] == "withheld"
    assert source_metadata["content_sha256"]["report_disclosure"] == "withheld"
    assert source_metadata["source_file_id"]["integration_disclosure"] == "withheld"
    assert source_metadata["source_reference"]["report_disclosure"] == "shown"
    assert source_metadata["source_reference"]["retention_relation"] == "derived_not_stored"
    assert source_metadata["source_channel"]["sensitivity"] == "non_sensitive_provenance_enum"
    assert source_metadata["source_channel"]["report_disclosure"] == "shown"
    assert source_metadata["source_channel"]["retention_relation"] == "follows_each_parent_record"
    by_key = {item["key"]: item for item in payload["classes"]}
    assert len(by_key) == len(payload["classes"]) == 25
    assert by_key["source_uploads"]["retention_days"] == 30
    assert by_key["source_uploads"]["backup_disposition"] == "included_sensitive"
    assert by_key["analysis_inventories"]["follows_class"] == "analysis_results"
    assert by_key["public_advisory_snapshots"]["follows_class"] == "analysis_results"
    assert by_key["report_exports"]["retention_mode"] == "not_persisted"
    assert by_key["remediation_plan_artifacts"]["retention_days"] == 7
    assert by_key["remediation_plan_artifacts"]["storage"] == "durable_remediation_plan_store"
    assert by_key["remediation_plan_artifacts"]["backup_disposition"] == "included_sensitive"
    assert by_key["active_weekly_review_receipts"]["retention_days"] == 400
    assert by_key["active_weekly_review_receipts"]["storage"] == "durable_active_weekly_review_receipt_store"
    assert by_key["active_weekly_review_receipts"]["backup_disposition"] == "included_sensitive"
    assert by_key["project_metadata"]["manual_cleanup"] is True
    assert by_key["finding_decisions"]["follows_class"] == "project_metadata"
    assert by_key["passive_project_actions"]["follows_class"] == "project_metadata"
    assert by_key["passive_project_actions"]["storage"] == "durable_project_action_store"
    assert by_key["active_asset_metadata"]["deletion_triggers"] == ["explicit_active_asset_deletion"]
    assert by_key["active_authorization_revisions"]["follows_class"] == "active_asset_metadata"
    assert by_key["active_verification_records"]["follows_class"] == "active_asset_metadata"
    assert by_key["active_execution_records"]["retention_days"] == 30
    assert by_key["active_change_approvals"]["retention_days"] == 90
    assert by_key["active_change_approvals"]["scope"] == "organization"
    assert by_key["active_change_approvals"]["backup_disposition"] == "included_sensitive"
    assert by_key["execution_workspaces"]["backup_disposition"] == "excluded_ephemeral"
    assert by_key["operation_journals"]["backup_disposition"] == "excluded_ephemeral"
    assert by_key["auth_sessions"]["restore_behavior"] == "discarded"
    assert by_key["automation_credentials"]["retention_days"] == 30
    assert by_key["automation_credentials"]["scope"] == "organization"
    assert by_key["team_invitations"]["retention_days"] == 30
    assert by_key["team_invitations"]["restore_behavior"] == "discarded"
    assert by_key["team_invitations"]["deletion_triggers"] == ["retention_expiry", "operator_restore"]
    assert by_key["team_identity"]["restore_behavior"] == "restored_sessions_revoked"
    assert by_key["team_identity"]["deletion_triggers"] == ["membership_revocation"]
    assert by_key["backup_bundles"]["retention_mode"] == "external_policy"
    assert str(tmp_path) not in serialized
    assert "authorized.zip" not in serialized


def test_manual_cleanup_is_org_scoped_preserves_active_sources_and_removes_derived_evidence(monkeypatch, tmp_path):
    settings, files, jobs, projects, intelligence, cache, audit, audit_clock = configured_stores(monkeypatch, tmp_path)
    source_a = store_source(files, "1" * 32, OWNER_A, OLD)
    active_source_a = store_source(files, "2" * 32, OWNER_A, OLD)
    source_b = store_source(files, "3" * 32, OWNER_B, OLD)
    job_a = store_job(jobs, "4" * 32, OWNER_A, source_a.id)
    active_job_a = store_job(jobs, "5" * 32, OWNER_A, active_source_a.id, status="running")
    job_b = store_job(jobs, "6" * 32, OWNER_B, source_b.id)
    intelligence.put(job_a.id, {"state": "ready", "summary": {"findings": 0}})
    intelligence.put(job_b.id, {"state": "ready", "summary": {"findings": 0}})

    cache_key = public_advisory_cache_key("osv", [{"package": {"ecosystem": "npm", "name": "fixture"}, "version": "1.0.0"}])
    assert cache.put("osv", cache_key, b'{"results":[]}', now=NOW - timedelta(days=8)) is not None
    audit_clock[0] = NOW - timedelta(days=100)
    audit.record(
        organization_id=OWNER_A,
        actor_id=OWNER_A,
        actor_role="administrator",
        action="project.created",
        resource_type="project",
        resource_id="7" * 32,
        correlation_id="retention-test-a",
    )
    event_b = audit.record(
        organization_id=OWNER_B,
        actor_id=OWNER_B,
        actor_role="administrator",
        action="project.created",
        resource_type="project",
        resource_id="8" * 32,
        correlation_id="retention-test-b",
    )
    audit_clock[0] = NOW

    token_clock = [OLD]
    automation_tokens = AutomationTokenStore(
        settings.resolved_auth_state_db_path,
        now_func=lambda: token_clock[0],
    )
    token_a, _ = automation_tokens.create(
        name="Old credential A", organization_id=OWNER_A, project_id="a" * 32,
        scopes=("project:read",), created_by=OWNER_A, lifetime_seconds=300,
    )
    token_b, _ = automation_tokens.create(
        name="Old credential B", organization_id=OWNER_B, project_id="b" * 32,
        scopes=("project:read",), created_by=OWNER_B, lifetime_seconds=300,
    )
    token_clock[0] = NOW
    service = RetentionMaintenanceService(settings, files, jobs, projects, intelligence, cache, audit, automation_tokens)
    result = service.run(organization_id=OWNER_A, correlation_id="retention-request", now=NOW)

    assert result.state == "completed"
    by_key = {item.key: item for item in result.results}
    assert by_key["analysis_results"].removed_items == 1
    assert by_key["source_uploads"].removed_items == 1
    assert by_key["public_advisory_cache"].removed_items == 1
    assert by_key["product_audit"].removed_items == 1
    assert by_key["automation_credentials"].removed_items == 1
    with pytest.raises(AutomationTokenError, match="not_found"):
        automation_tokens.get(OWNER_A, token_a.token_id)
    assert automation_tokens.get(OWNER_B, token_b.token_id).token_id == token_b.token_id
    assert intelligence.get(job_a.id) is None
    assert intelligence.get(job_b.id) is not None
    with pytest.raises(HTTPException, match="Job not found"):
        jobs.get(job_a.id)
    assert jobs.get(job_b.id).owner_id == OWNER_B
    assert jobs.get(active_job_a.id).status == "running"
    assert files.source_path(active_source_a).exists()
    assert files.source_path(source_b).exists()
    assert not files.source_path(source_a).exists()
    assert (settings.product_audit_dir / OWNER_B / f"{event_b.id}.json").exists()
    assert audit.list(OWNER_A).items == []


def test_partial_cleanup_redacts_storage_failures_and_other_classes_continue(monkeypatch, tmp_path, caplog):
    settings, files, jobs, projects, intelligence, cache, audit, audit_clock = configured_stores(monkeypatch, tmp_path)
    audit_clock[0] = NOW

    def fail_with_sensitive_path(*_args, **_kwargs):
        raise OSError("/private/customer/source.zip")

    monkeypatch.setattr(files, "purge_expired", fail_with_sensitive_path)
    caplog.set_level("INFO", logger="inspectra.audit")
    result = RetentionMaintenanceService(settings, files, jobs, projects, intelligence, cache, audit, None).run(
        organization_id=OWNER_A,
        correlation_id="retention-partial",
        now=NOW,
    )

    assert result.state == "partial"
    by_key = {item.key: item for item in result.results}
    assert by_key["source_uploads"].status == "failed"
    assert by_key["source_uploads"].removed_items is None
    assert by_key["analysis_results"].status == "completed"
    assert by_key["public_advisory_cache"].status == "completed"
    serialized = result.model_dump_json() + "\n" + "\n".join(record.getMessage() for record in caplog.records)
    assert "/private/customer/source.zip" not in serialized
    assert "OSError" in serialized


def test_retention_cleanup_purges_only_expired_weekly_receipts_for_active_organization(
    monkeypatch, tmp_path
):
    settings, files, jobs, projects, intelligence, cache, audit, _ = configured_stores(
        monkeypatch, tmp_path
    )
    clock = [NOW - timedelta(days=401)]
    receipts = ActiveWeeklyReviewReceiptStore(settings, now_func=lambda: clock[0])

    def create(owner: str, key: str) -> str:
        state_at = clock[0]
        return receipts.create(
            organization_id=owner,
            preflight=ActiveWeeklyReportPreflight(
                state="ready", period="7d", starts_at=state_at - timedelta(days=7),
                state_at=state_at, snapshot_digest=hashlib.sha256(key.encode()).hexdigest(),
                assets_total=1, assets_included=1, jobs_total=0, jobs_included=0,
                actions_total=0, actions_included=0,
                recurrence_attention_total=0, recurrence_attention_included=0,
                incomplete=False,
            ),
            outcome="reviewed", expected_revision=0, idempotency_key=key,
        ).receipt.id

    expired_id = create(OWNER_A, "weekly-retention-owner-a-001")
    clock[0] = NOW
    other_id = create(OWNER_B, "weekly-retention-owner-b-001")
    result = RetentionMaintenanceService(
        settings, files, jobs, projects, intelligence, cache, audit, None,
        active_weekly_review_receipts=receipts,
    ).run(organization_id=OWNER_A, correlation_id="weekly-receipt-retention", now=NOW)

    by_key = {item.key: item for item in result.results}
    assert by_key["active_weekly_review_receipts"].removed_items == 1
    assert receipts.list(OWNER_A).items == ()
    assert [item.id for item in receipts.list(OWNER_B).items] == [other_id]
    assert expired_id != other_id


def test_retention_cleanup_purges_only_terminal_team_invitations_after_window(monkeypatch, tmp_path):
    settings, files, jobs, projects, intelligence, cache, audit, _audit_clock = configured_stores(
        monkeypatch,
        tmp_path,
    )
    clock = [OLD]
    identity = TeamIdentityStore(
        settings.resolved_auth_state_db_path,
        organization_name="Retention workspace",
        bootstrap_admin_password_hash=hash_password("bootstrap-password"),
        invitation_ttl_seconds=60,
        now_func=lambda: clock[0],
    )
    admin = identity.authenticate("admin", "bootstrap-password")
    assert admin is not None
    old = identity.create_invitation(principal=admin, username="old.invitation", role="reader")
    clock[0] = NOW
    recent = identity.create_invitation(principal=admin, username="recent.invitation", role="reader")

    result = RetentionMaintenanceService(
        settings,
        files,
        jobs,
        projects,
        intelligence,
        cache,
        audit,
        None,
        identity,
    ).run(organization_id=admin.organization_id, correlation_id="team-invitation-cleanup", now=NOW)

    invitation_result = next(item for item in result.results if item.key == "team_invitations")
    assert invitation_result.status == "completed"
    assert invitation_result.removed_items == 1
    assert old.token not in result.model_dump_json()
    with sqlite3.connect(settings.resolved_auth_state_db_path) as connection:
        hashes = {row[0] for row in connection.execute("SELECT token_hash FROM team_invitations")}
    assert hash_invitation_token(old.token) not in hashes
    assert hash_invitation_token(recent.token) in hashes


def test_snapshot_and_cache_cleanup_reject_symlink_traversal(monkeypatch, tmp_path):
    settings, _files, _jobs, _projects, intelligence, cache, _audit, _clock = configured_stores(monkeypatch, tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("keep", encoding="utf-8")
    analysis_id = "9" * 32
    current = settings.public_advisories_dir / "osv" / f"{analysis_id}.json"
    current.parent.mkdir(parents=True, exist_ok=True)
    current.symlink_to(outside)
    with pytest.raises(ValueError, match="snapshot path is invalid"):
        intelligence.delete_analysis(analysis_id)
    assert outside.read_text(encoding="utf-8") == "keep"

    cache_dir = settings.public_advisories_dir / "github_advisories"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_link = cache_dir / f"{'d' * 64}.json"
    cache_link.symlink_to(outside)
    with pytest.raises(ValueError, match="cache entry is invalid"):
        cache.purge_expired(now=NOW)
    assert outside.read_text(encoding="utf-8") == "keep"
