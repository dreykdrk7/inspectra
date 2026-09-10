from datetime import datetime, timedelta, timezone
import json
import shutil

import pytest

from app.config import Settings, load_settings
from app.product_audit import ProductAuditError, ProductAuditStore


ORGANIZATION_A = "a" * 32
ORGANIZATION_B = "b" * 32
ACTOR = "c" * 32
RESOURCE = "d" * 32


def make_store(tmp_path, *, now, retention_days=90, max_events=50_000):
    settings = Settings(
        data_dir=tmp_path,
        tool_runner_url="http://audit-tools:8081",
        product_audit_retention_days=retention_days,
        product_audit_max_events=max_events,
    )
    settings.ensure_directories()
    return ProductAuditStore(settings, now_func=lambda: now[0])


def record(store, *, organization_id=ORGANIZATION_A, action="project.created", metadata=None):
    return store.record(
        organization_id=organization_id,
        actor_id=ACTOR,
        actor_role="administrator",
        action=action,
        resource_type="project",
        resource_id=RESOURCE,
        correlation_id=f"request:{RESOURCE}",
        metadata=metadata,
    )


def test_records_only_allowlisted_minimal_metadata_and_never_sensitive_values(tmp_path):
    now = [datetime(2026, 9, 6, 12, tzinfo=timezone.utc)]
    store = make_store(tmp_path, now=now)
    secret = "sensitive-token-value"
    private_path = "/srv/customer/private/project.zip"

    event = record(
        store,
        metadata={
            "project_id": "e" * 32,
            "report_format": "markdown",
            "report_profile": "minimal",
            "token": secret,
            "path": private_path,
            "evidence": "source contents",
            "provider": "https://attacker.invalid/private",
        },
    )

    assert event.metadata == {
        "project_id": "e" * 32,
        "report_format": "markdown",
        "report_profile": "minimal",
    }
    serialized = next(tmp_path.glob("results/product_audit/*/*.json")).read_text(encoding="utf-8")
    assert next(tmp_path.glob("results/product_audit/*/*.json")).stat().st_mode & 0o777 == 0o600
    for forbidden in (secret, private_path, "source contents", "attacker.invalid"):
        assert forbidden not in serialized


def test_pagination_is_stable_scoped_and_filterable(tmp_path):
    now = [datetime(2026, 9, 6, 12, tzinfo=timezone.utc)]
    store = make_store(tmp_path, now=now)
    recorded = [
        record(store, action="project.created"),
        record(store, action="project.report_exported"),
        record(store, action="project.created"),
    ]
    record(store, organization_id=ORGANIZATION_B)

    first = store.list(ORGANIZATION_A, limit=2)
    second = store.list(ORGANIZATION_A, limit=2, cursor=first.next_cursor)

    assert first.next_cursor is not None
    assert {event.id for event in first.items + second.items} == {event.id for event in recorded}
    assert len(first.items + second.items) == 3
    assert store.list(ORGANIZATION_A, action="project.report_exported").items[0].action == "project.report_exported"
    assert all(event.organization_id == ORGANIZATION_A for event in first.items + second.items)


def test_active_export_selection_is_time_asset_job_and_organization_scoped(tmp_path):
    now = [datetime(2026, 9, 6, 12, tzinfo=timezone.utc)]
    store = make_store(tmp_path, now=now)
    asset_id = "e" * 32
    job_id = "f" * 32
    direct = store.record(
        organization_id=ORGANIZATION_A,
        actor_id=ACTOR,
        actor_role="administrator",
        action="active_asset.registered",
        resource_type="active_asset",
        resource_id=asset_id,
        correlation_id="request:direct",
    )
    linked_job = store.record(
        organization_id=ORGANIZATION_A,
        actor_id=ACTOR,
        actor_role="administrator",
        action="active_asset.execution_cancelled",
        resource_type="active_execution",
        resource_id=job_id,
        correlation_id="request:job",
    )
    record(store, organization_id=ORGANIZATION_A, action="project.created")
    record(store, organization_id=ORGANIZATION_B, action="active_asset.registered")

    selected, total = store.active_events_for_export(
        ORGANIZATION_A,
        starts_at=now[0] - timedelta(days=1),
        ends_at=now[0] + timedelta(seconds=1),
        asset_id=asset_id,
        job_ids={job_id},
    )

    assert total == 2
    assert {event.id for event in selected} == {direct.id, linked_job.id}
    assert all(event.organization_id == ORGANIZATION_A for event in selected)


def test_expiry_and_capacity_are_bounded(tmp_path):
    now = [datetime(2026, 9, 1, 12, tzinfo=timezone.utc)]
    store = make_store(tmp_path, now=now, retention_days=1, max_events=1)
    old = record(store)
    now[0] += timedelta(days=2)
    current = record(store, action="project.report_exported")

    page = store.list(ORGANIZATION_A)
    assert [event.id for event in page.items] == [current.id]
    assert old.id != current.id
    with pytest.raises(ProductAuditError, match="audit_capacity_reached"):
        record(store, action="project.created")


def test_rejects_foreign_or_corrupt_records_in_an_organization_scope(tmp_path):
    now = [datetime(2026, 9, 6, 12, tzinfo=timezone.utc)]
    store = make_store(tmp_path, now=now)
    event = record(store)
    path = next(tmp_path.glob("results/product_audit/*/*.json"))
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["organization_id"] = ORGANIZATION_B
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProductAuditError, match="audit_integrity_invalid"):
        store.list(ORGANIZATION_A)
    with pytest.raises(ProductAuditError, match="invalid_organization"):
        store.list("../../outside")
    assert event.id == path.stem


def test_configuration_is_bounded_and_creates_a_private_audit_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_PRODUCT_AUDIT_RETENTION_DAYS", "30")
    monkeypatch.setenv("INSPECTRA_PRODUCT_AUDIT_MAX_EVENTS", "250")
    settings = load_settings()
    settings.ensure_directories()

    assert settings.product_audit_retention_days == 30
    assert settings.product_audit_max_events == 250
    assert settings.product_audit_dir.is_dir()

    monkeypatch.setenv("INSPECTRA_PRODUCT_AUDIT_RETENTION_DAYS", "3651")
    with pytest.raises(ValueError, match="INSPECTRA_PRODUCT_AUDIT_RETENTION_DAYS"):
        load_settings()


def test_retention_never_follows_a_symlink_outside_the_audit_root(tmp_path):
    now = [datetime(2026, 9, 6, 12, tzinfo=timezone.utc)]
    store = make_store(tmp_path, now=now, retention_days=1)
    outside = tmp_path / "outside"
    outside.mkdir()
    protected = outside / f"{'f' * 32}.json"
    protected.write_text("external-marker", encoding="utf-8")
    linked_organization = store.root / ORGANIZATION_B
    linked_organization.symlink_to(outside, target_is_directory=True)

    assert store.purge_expired() == 0
    assert protected.read_text(encoding="utf-8") == "external-marker"


def test_integrity_chain_is_owner_scoped_bootstraps_legacy_and_tracks_retention_anchor(tmp_path):
    clock = [datetime(2026, 9, 1, 12, tzinfo=timezone.utc)]
    store = make_store(tmp_path, now=clock, retention_days=1)
    record(store, organization_id=ORGANIZATION_A)
    first = store.verify_integrity(ORGANIZATION_A)
    assert first.state == "valid"
    assert first.retained_events == first.head_sequence == 1
    assert first.anchor_sequence == 0

    shutil.rmtree(store.root / ORGANIZATION_A / ".integrity")
    legacy = store.verify_integrity(ORGANIZATION_A)
    assert legacy.state == "valid"
    assert legacy.bootstrap_performed is True
    assert legacy.generation == 1

    clock[0] += timedelta(days=2)
    record(store, organization_id=ORGANIZATION_A, action="project.report_exported")
    rotated = store.verify_integrity(ORGANIZATION_A)
    assert rotated.state == "valid"
    assert rotated.retained_events == 1
    assert rotated.anchor_sequence == 1
    assert rotated.head_sequence == 2

    assert store.verify_integrity(ORGANIZATION_B).state == "empty"
    assert store.verify_integrity(ORGANIZATION_B).head_digest != rotated.head_digest


@pytest.mark.parametrize("corruption", ["event", "entry", "state", "cut", "order"])
def test_integrity_verifier_detects_changed_cut_or_reordered_history(tmp_path, corruption):
    now = [datetime(2026, 9, 10, 12, tzinfo=timezone.utc)]
    store = make_store(tmp_path, now=now)
    record(store)
    record(store, action="project.report_exported")
    organization_dir = store.root / ORGANIZATION_A
    entries = sorted((organization_dir / ".integrity" / "entries").glob("*.json"))
    events = sorted(organization_dir.glob("*.json"))

    if corruption == "event":
        payload = json.loads(events[0].read_text(encoding="utf-8"))
        payload["action"] = "project.changed"
        events[0].write_text(json.dumps(payload), encoding="utf-8")
    elif corruption == "entry":
        payload = json.loads(entries[0].read_text(encoding="utf-8"))
        payload["previous_chain_digest"] = "f" * 64
        entries[0].write_text(json.dumps(payload), encoding="utf-8")
    elif corruption == "state":
        state_path = organization_dir / ".integrity" / "state.json"
        payload = json.loads(state_path.read_text(encoding="utf-8"))
        payload["head_digest"] = "f" * 64
        state_path.write_text(json.dumps(payload), encoding="utf-8")
    elif corruption == "cut":
        events[-1].unlink()
        entries[-1].unlink()
    else:
        first = entries[0].read_bytes()
        second = entries[1].read_bytes()
        entries[0].write_bytes(second)
        entries[1].write_bytes(first)

    status = store.verify_integrity(ORGANIZATION_A)
    assert status.state == "invalid"
    assert status.failure_reason == "integrity_check_failed"
    assert status.head_digest is None
    with pytest.raises(ProductAuditError, match="audit_integrity_invalid"):
        store.list(ORGANIZATION_A)


def test_authorized_active_anonymization_rotates_and_preserves_chain(tmp_path):
    now = [datetime(2026, 9, 10, 12, tzinfo=timezone.utc)]
    store = make_store(tmp_path, now=now)
    asset_id = "e" * 32
    job_id = "f" * 32
    store.record(
        organization_id=ORGANIZATION_A,
        actor_id=ACTOR,
        actor_role="administrator",
        action="active_asset.execution_cancelled",
        resource_type="active_execution",
        resource_id=job_id,
        correlation_id="request:active",
        metadata={"job_id": job_id},
    )

    assert store.anonymize_active_asset(
        organization_id=ORGANIZATION_A,
        asset_id=asset_id,
        job_ids={job_id},
        deletion_receipt_id="1" * 32,
    ) == 1
    status = store.verify_integrity(ORGANIZATION_A)
    assert status.state == "valid"
    assert status.generation == 2
    event = store.list(ORGANIZATION_A).items[0]
    assert event.resource_type == "deleted_active_asset"
    assert event.resource_id == "1" * 32
    assert event.metadata == {}
