from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.active_asset_deletion import ActiveAssetDeletionError, ActiveAssetDeletionService
from app.active_change_approvals import ActiveChangeApprovalStore, ActiveChangeSummary
from app.active_asset_verification import (
    ActiveAssetVerificationObservation,
    ActiveAssetVerificationStartRequest,
    ActiveAssetVerificationStore,
)
from app.active_assets import ActiveAssetCreateRequest, ActiveAssetNote, ActiveAssetStore, ActiveAssetStoreError
from app.active_recurrence import ActiveRecurrenceCreateRequest, ActiveRecurrenceError, ActiveRecurrenceStore
from app.backup import BackupError, create_backup, restore_backup, validate_data_store
from app.config import Settings
from app.product_audit import ProductAuditStore
from app.storage import JobStore


NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
OWNER_A = "a" * 32
OWNER_B = "b" * 32


def configured(tmp_path, *, after_step=None):
    settings = Settings(data_dir=tmp_path, tool_runner_url="http://audit-tools:8081")
    settings.ensure_directories()
    assets = ActiveAssetStore(settings, now_func=lambda: NOW)
    verifications = ActiveAssetVerificationStore(settings, now_func=lambda: NOW)
    jobs = JobStore(settings)
    audit = ProductAuditStore(settings, now_func=lambda: NOW)
    recurrences = ActiveRecurrenceStore(settings, now_func=lambda: NOW)
    approvals = ActiveChangeApprovalStore(settings, now_func=lambda: NOW)
    service = ActiveAssetDeletionService(
        settings,
        assets,
        verifications,
        jobs,
        audit,
        recurrences,
        approvals,
        now_func=lambda: NOW,
        after_step=after_step,
    )
    return settings, assets, verifications, jobs, audit, service


def create_asset_fixture(stores, *, owner=OWNER_A, job_status="completed", with_pending=False):
    _settings, assets, verifications, jobs, audit, _service = stores
    asset = assets.create(
        ActiveAssetCreateRequest(
            asset_type="domain",
            value="private.example.test",
            responsible_user_ids=[owner],
            capabilities=["active_dns_inventory"],
            allowed_ports=[],
            allowed_protocols=["dns"],
            authorization_method="manual_attestation",
            authorization_reference="approved-change-42",
            authorized_at=NOW,
            expires_at=NOW + timedelta(days=30),
            notes=[ActiveAssetNote(kind="business_context", value="private staging")],
        ),
        organization_id=owner,
        actor_id=owner,
    )
    revision = asset.authorization_revisions[-1]
    job, _ = jobs.create_active_asset_execution_job(
        "active_dns_inventory",
        owner_id=owner,
        active_asset_id=asset.id,
        active_authorization_contract=asset.contract_version,
        active_authorization_revision_id=revision.id,
        active_authorization_revision_digest_sha256=revision.digest_sha256,
        active_authorization_revision_sequence=revision.sequence,
        active_execution_port=None,
        idempotency_key_sha256="f" * 64,
    )
    if job_status != "queued":
        job = jobs.update(
            job.id,
            status=job_status,
            result={"contract_version": "fixture", "records": []} if job_status == "completed" else None,
            termination_reason="completed" if job_status == "completed" else "cancelled_by_owner",
        )
    verification, token = verifications.start(
        asset,
        ActiveAssetVerificationStartRequest(
            method="manual_attestation", valid_for_days=7, control_check_confirmed=True
        ),
        organization_id=owner,
        actor_id=owner,
    )
    if not with_pending:
        verification = verifications.complete(
            verification.id,
            asset=asset,
            organization_id=owner,
            challenge_token=token,
            observation=ActiveAssetVerificationObservation(True, "matched"),
        )
    audit.record(
        organization_id=owner,
        actor_id=owner,
        actor_role="administrator",
        action="active_asset.execution_requested",
        resource_type="active_asset",
        resource_id=asset.id,
        correlation_id=f"active-asset:{asset.id}",
        metadata={"job_id": job.id, "authorization_revision_id": revision.id},
    )
    return asset, verification, job


def test_active_asset_deletion_previews_and_removes_entire_aggregate(tmp_path, monkeypatch):
    stores = configured(tmp_path)
    settings, assets, verifications, jobs, audit, service = stores
    asset, verification, job = create_asset_fixture(stores)
    assert jobs.active_asset_history(owner_id=OWNER_A, asset_id=asset.id) == [job]
    original_glob = Path.glob

    def guarded_glob(path, pattern):
        if path == settings.jobs_dir:
            raise AssertionError("asset deletion must not glob global job history")
        return original_glob(path, pattern)

    monkeypatch.setattr(Path, "glob", guarded_glob)
    revision = asset.authorization_revisions[-1]
    recurrence, _ = service.recurrences.create(
        ActiveRecurrenceCreateRequest(
            capability="active_dns_inventory", interval_days=7,
            timezone_name="UTC", window_weekdays=["monday"],
            window_start_hour=9, window_duration_hours=4,
            recurrence_confirmed=True, idempotency_key="e" * 32,
        ),
        organization_id=OWNER_A, asset_id=asset.id, actor_id=OWNER_A,
        actor_role="administrator", authorization_revision_id=revision.id,
        authorization_revision_digest_sha256=revision.digest_sha256,
        authorization_revision_sequence=revision.sequence,
        authorization_expires_at=revision.expires_at, verification_id=verification.id,
    )
    approval = service.approvals.request(
        organization_id=OWNER_A, actor_id=OWNER_A, actor_role="maintainer",
        kind="renewal", asset_id=asset.id,
        operation_digest_sha256="9" * 64,
        summary=ActiveChangeSummary(
            asset_type=asset.asset_type, scope_change="same_scope",
            capabilities=tuple(asset.capabilities),
            allowed_ports=tuple(asset.allowed_ports),
            allowed_protocols=tuple(asset.allowed_protocols),
            authorization_expires_at=revision.expires_at,
        ),
    )

    preview = service.preview(organization_id=OWNER_A, asset_id=asset.id)
    scope = {item.key: item for item in preview.items}
    assert preview.state == "ready"
    assert scope["authorization_revisions"].item_count == 1
    assert scope["verification_challenges"].item_count == 1
    assert scope["execution_results"].item_count == 1
    assert scope["recurrence_policies"].item_count == 1
    assert scope["change_approvals"].item_count == 1
    assert scope["product_audit"].disposition == "anonymize"
    assert scope["report_exports"].disposition == "not_persisted"

    result = service.delete(organization_id=OWNER_A, asset_id=asset.id)

    assert result.state == "completed"
    with pytest.raises(ActiveAssetStoreError, match="asset_not_found"):
        assets.get(asset.id, organization_id=OWNER_A)
    with pytest.raises(ActiveAssetStoreError, match="asset_not_found"):
        assets.revoke(
            asset.id,
            organization_id=OWNER_A,
            actor_id=OWNER_A,
            reason_code="security_hold",
        )
    with pytest.raises(HTTPException, match="Job not found"):
        jobs.get(job.id)
    with pytest.raises(Exception, match="verification_not_found"):
        verifications.get(verification.id, asset_id=asset.id, organization_id=OWNER_A)
    with pytest.raises(ActiveRecurrenceError, match="not_found"):
        service.recurrences.get(recurrence.id, organization_id=OWNER_A, asset_id=asset.id)
    assert all(item.id != approval.id for item in service.approvals.list(OWNER_A))
    assert not any(settings.active_asset_deletions_dir.iterdir())
    serialized = "\n".join(path.read_text() for path in settings.product_audit_dir.rglob("*.json"))
    assert asset.id not in serialized
    assert job.id not in serialized
    assert asset.canonical_value not in serialized
    retained = audit.list(OWNER_A).items
    assert retained[0].resource_type == "deleted_active_asset"
    assert retained[0].resource_id == result.deletion_receipt_id
    assert retained[0].metadata == {}


def test_active_asset_deletion_invalidates_the_whole_batch_replay_receipt(tmp_path):
    stores = configured(tmp_path)
    settings, assets, _verifications, _jobs, _audit, service = stores
    requests = [
        ActiveAssetCreateRequest(
            asset_type="domain",
            value=value,
            responsible_user_ids=[OWNER_A],
            capabilities=["active_dns_inventory"],
            allowed_ports=[],
            allowed_protocols=["dns"],
            authorization_method="manual_attestation",
            authorization_reference="approved-batch-deletion",
            authorized_at=NOW,
            expires_at=NOW + timedelta(days=30),
            notes=[],
        )
        for value in ("batch-delete-a.example.test", "batch-delete-b.example.test")
    ]
    records, replayed, _batch_id = assets.create_many(
        requests,
        organization_id=OWNER_A,
        actor_id=OWNER_A,
        normalized_digest_sha256="d" * 64,
        idempotency_key="e" * 32,
    )
    assert replayed is False
    assert len(list((settings.data_dir / "results" / "active_asset_batches").rglob("*.json"))) == 1
    preview = service.preview(organization_id=OWNER_A, asset_id=records[0].id)
    assert {item.key: item.item_count for item in preview.items}["batch_replay_receipts"] == 1

    result = service.delete(organization_id=OWNER_A, asset_id=records[0].id)

    assert result.state == "completed"
    assert not list((settings.data_dir / "results" / "active_asset_batches").rglob("*.json"))
    assert assets.get(records[1].id, organization_id=OWNER_A).id == records[1].id
    with pytest.raises(ActiveAssetStoreError, match="batch_asset_conflict"):
        assets.create_many(
            requests,
            organization_id=OWNER_A,
            actor_id=OWNER_A,
            normalized_digest_sha256="d" * 64,
            idempotency_key="e" * 32,
        )


@pytest.mark.parametrize("blocker", ["queued_job", "pending_verification"])
def test_active_asset_deletion_blocks_live_work_without_hiding_asset(tmp_path, blocker):
    stores = configured(tmp_path)
    _settings, assets, _verifications, jobs, _audit, service = stores
    asset, verification, job = create_asset_fixture(
        stores,
        job_status="queued" if blocker == "queued_job" else "completed",
        with_pending=blocker == "pending_verification",
    )

    assert service.preview(organization_id=OWNER_A, asset_id=asset.id).state == "blocked_active_work"
    with pytest.raises(ActiveAssetDeletionError, match="active_work"):
        service.delete(organization_id=OWNER_A, asset_id=asset.id)
    assert assets.get(asset.id, organization_id=OWNER_A).id == asset.id
    assert jobs.get(job.id).id == job.id
    assert verification.asset_id == asset.id


def test_active_asset_deletion_is_owner_scoped_and_idempotent(tmp_path):
    stores = configured(tmp_path)
    _settings, assets, _verifications, _jobs, _audit, service = stores
    asset, _verification, _job = create_asset_fixture(stores, owner=OWNER_B)

    foreign = service.delete(organization_id=OWNER_A, asset_id=asset.id)
    assert foreign.state == "already_absent"
    assert assets.get(asset.id, organization_id=OWNER_B).id == asset.id
    assert service.delete(organization_id=OWNER_B, asset_id=asset.id).state == "completed"
    assert service.delete(organization_id=OWNER_B, asset_id=asset.id).state == "already_absent"


def test_interrupted_active_asset_deletion_hides_asset_blocks_admission_and_recovers(tmp_path, caplog):
    def fail_after_jobs(step):
        if step == "execution_jobs":
            raise OSError("/private/customer/target.example/secret")

    stores = configured(tmp_path, after_step=fail_after_jobs)
    settings, assets, verifications, jobs, audit, service = stores
    asset, _verification, _job = create_asset_fixture(stores)

    with pytest.raises(ActiveAssetDeletionError, match="cleanup_failed"):
        service.delete(organization_id=OWNER_A, asset_id=asset.id)
    assert "/private/customer/target.example/secret" not in "\n".join(record.getMessage() for record in caplog.records)
    assert service.has_pending() is True
    journal = next(settings.active_asset_deletions_dir.glob("*.json")).read_text(encoding="utf-8")
    assert asset.canonical_value not in journal
    assert asset.authorization_reference not in journal
    assert "challenge_sha256" not in journal
    assert assets.list(organization_id=OWNER_A) == []
    with pytest.raises(ActiveAssetStoreError, match="asset_not_found"):
        assets.get(asset.id, organization_id=OWNER_A)
    with pytest.raises(ActiveAssetStoreError, match="asset_not_found"):
        assets.revoke(
            asset.id,
            organization_id=OWNER_A,
            actor_id=OWNER_A,
            reason_code="security_hold",
        )
    with pytest.raises(ActiveAssetStoreError, match="asset_deletion_pending"):
        assets.create_many(
            [
                ActiveAssetCreateRequest(
                    asset_type=asset.asset_type,
                    value=asset.canonical_value,
                    responsible_user_ids=asset.responsible_user_ids,
                    capabilities=asset.capabilities,
                    allowed_ports=asset.allowed_ports,
                    allowed_protocols=asset.allowed_protocols,
                    authorization_method=asset.authorization_method,
                    authorization_reference="approved-batch-replacement",
                    authorized_at=NOW,
                    expires_at=NOW + timedelta(days=30),
                    notes=[],
                )
            ],
            organization_id=OWNER_A,
            actor_id=OWNER_A,
            normalized_digest_sha256="a" * 64,
            idempotency_key="b" * 32,
        )
    revision = asset.authorization_revisions[-1]
    with pytest.raises(HTTPException, match="deletion is in progress"):
        jobs.create_active_asset_execution_job(
            "active_dns_inventory",
            owner_id=OWNER_A,
            active_asset_id=asset.id,
            active_authorization_contract=asset.contract_version,
            active_authorization_revision_id=revision.id,
            active_authorization_revision_digest_sha256=revision.digest_sha256,
            active_authorization_revision_sequence=revision.sequence,
            active_execution_port=None,
            idempotency_key_sha256="e" * 64,
        )

    recovered = ActiveAssetDeletionService(
        settings, assets, verifications, jobs, audit, now_func=lambda: NOW
    )
    assert recovered.recover_pending() == 1
    assert recovered.has_pending() is False
    assert not any(settings.active_asset_deletions_dir.iterdir())


def test_active_asset_deletion_rejects_malformed_or_cross_owner_state(tmp_path):
    stores = configured(tmp_path)
    settings, _assets, _verifications, _jobs, _audit, service = stores
    with pytest.raises(ActiveAssetDeletionError, match="not_found"):
        service.preview(organization_id=OWNER_A, asset_id="../private-target")
    marker = settings.active_asset_deletions_dir / ("a" * 32 + ".json")
    marker.write_text('{"asset_id":"' + "b" * 32 + '"}', encoding="utf-8")
    assert service.recover_pending() == 0
    assert marker.exists()


def test_active_asset_deletion_fails_closed_on_cross_owner_job_reference(tmp_path):
    stores = configured(tmp_path)
    _settings, _assets, _verifications, jobs, _audit, service = stores
    asset, _verification, _job = create_asset_fixture(stores)
    foreign, _ = jobs.create_active_asset_execution_job(
        "active_dns_inventory",
        owner_id=OWNER_B,
        active_asset_id=asset.id,
        active_authorization_contract="2026-09-09.1",
        active_authorization_revision_id="b" * 32,
        active_authorization_revision_digest_sha256="c" * 64,
        active_authorization_revision_sequence=1,
        active_execution_port=None,
        idempotency_key_sha256="e" * 64,
    )
    jobs.update(
        foreign.id,
        status="completed",
        result={"contract_version": "fixture", "records": []},
        termination_reason="completed",
    )

    with pytest.raises(ActiveAssetDeletionError, match="state_invalid"):
        service.preview(organization_id=OWNER_A, asset_id=asset.id)


def test_active_asset_and_verification_round_trip_through_offline_backup(tmp_path):
    source = tmp_path / "source"
    stores = configured(source)
    _settings, _assets, _verifications, _jobs, _audit, _service = stores
    asset, verification, job = create_asset_fixture(stores)
    backup = tmp_path / "encrypted-backup"
    create_backup(
        source,
        backup,
        offline_confirmed=True,
        sensitive_data_confirmed=True,
        encrypted_destination_confirmed=True,
        now=NOW,
        backup_id="c" * 32,
    )
    restored = tmp_path / "restored"
    restore_backup(
        backup,
        restored,
        offline_confirmed=True,
        sensitive_data_confirmed=True,
    )
    restored_settings = Settings(data_dir=restored, tool_runner_url="http://audit-tools:8081")
    restored_asset = ActiveAssetStore(restored_settings, now_func=lambda: NOW).get(
        asset.id, organization_id=OWNER_A
    )
    restored_verification = ActiveAssetVerificationStore(
        restored_settings, now_func=lambda: NOW
    ).get(verification.id, asset_id=asset.id, organization_id=OWNER_A)
    assert restored_asset.canonical_value == asset.canonical_value
    assert restored_verification.status == "verified"
    assert JobStore(restored_settings).get(job.id).active_asset_id == asset.id
    (restored_settings.data_dir / "results" / "active_assets" / OWNER_A / f"{asset.id}.json").unlink()
    with pytest.raises(BackupError, match="invalid_ownership_boundary"):
        validate_data_store(restored_settings.data_dir)
