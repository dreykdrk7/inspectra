from datetime import datetime, timedelta, timezone
import json

import pytest

from app.config import Settings
from app.product_audit import ProductAuditError, ProductAuditStore
from app.product_audit_export import (
    ProductAuditExportError,
    ProductAuditExportRequest,
    render_product_audit_export,
    select_product_audit_export,
    validate_product_audit_export_request,
)


ORGANIZATION_A = "a" * 32
ORGANIZATION_B = "b" * 32
ACTOR = "c" * 32
RESOURCE = "d" * 32


def make_store(tmp_path, now):
    settings = Settings(data_dir=tmp_path, tool_runner_url="http://audit-tools:8081")
    settings.ensure_directories()
    return ProductAuditStore(settings, now_func=lambda: now)


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


def request_for(selection, **updates):
    values = {
        "period": selection.preflight.period,
        "export_format": "json",
        "action_filter": selection.preflight.action_filter,
        "state_at": selection.preflight.state_at,
        "snapshot_digest": selection.preflight.snapshot_digest,
        "redacted_export_confirmed": True,
    }
    values.update(updates)
    return ProductAuditExportRequest(**values)


def test_export_is_deterministic_org_scoped_filtered_and_omits_sensitive_fields(tmp_path):
    now = datetime(2026, 9, 10, 12, tzinfo=timezone.utc)
    store = make_store(tmp_path, now)
    selected = record(store, action="project.report_exported", metadata={"report_format": "json"})
    record(store, action="project.created")
    record(store, organization_id=ORGANIZATION_B, action="project.report_exported")

    first = select_product_audit_export(
        store,
        organization_id=ORGANIZATION_A,
        period="30d",
        action_filter="project.report_exported",
        state_at=now + timedelta(seconds=1),
    )
    second = select_product_audit_export(
        store,
        organization_id=ORGANIZATION_A,
        period="30d",
        action_filter="project.report_exported",
        state_at=now + timedelta(seconds=1),
    )

    assert first.preflight == second.preflight
    assert first.preflight.total_events == first.preflight.included_events == 1
    assert first.events[0].action == "project.report_exported"
    assert first.events[0].event_reference != selected.id
    payload = render_product_audit_export(first, "json")
    document = json.loads(payload)
    assert document["preflight"]["snapshot_digest"] == first.preflight.snapshot_digest
    assert set(document["events"][0]) == {
        "event_reference", "occurred_at", "actor_reference", "actor_role",
        "action", "result", "resource_type", "resource_reference",
    }
    serialized = payload.decode()
    for forbidden in (
        ORGANIZATION_A, ORGANIZATION_B, ACTOR, RESOURCE, '"correlation_id":', '"metadata":',
        "report_format", "request:",
    ):
        assert forbidden not in serialized


def test_export_request_requires_live_exact_nonempty_snapshot(tmp_path):
    now = datetime(2026, 9, 10, 12, tzinfo=timezone.utc)
    store = make_store(tmp_path, now)
    record(store)
    selection = select_product_audit_export(
        store, organization_id=ORGANIZATION_A, period="7d", state_at=now
    )

    validate_product_audit_export_request(selection, request_for(selection), now=now)
    with pytest.raises(ProductAuditExportError, match="snapshot_changed"):
        validate_product_audit_export_request(
            selection,
            request_for(selection, snapshot_digest="f" * 64),
            now=now,
        )
    with pytest.raises(ProductAuditExportError, match="preflight_expired"):
        validate_product_audit_export_request(
            selection,
            request_for(selection),
            now=now + timedelta(minutes=6),
        )

    empty = select_product_audit_export(
        store,
        organization_id=ORGANIZATION_A,
        period="7d",
        action_filter="project.report_exported",
        state_at=now,
    )
    with pytest.raises(ProductAuditExportError, match="no_matches"):
        validate_product_audit_export_request(empty, request_for(empty), now=now)


def test_csv_is_bounded_and_corrupt_store_fails_closed(tmp_path):
    now = datetime(2026, 9, 10, 12, tzinfo=timezone.utc)
    store = make_store(tmp_path, now)
    record(store)
    selection = select_product_audit_export(
        store, organization_id=ORGANIZATION_A, period="30d", state_at=now
    )
    csv_payload = render_product_audit_export(selection, "csv").decode()
    assert csv_payload.startswith("record_type,contract_version,period")
    assert "manifest,2026-09-10.1,30d" in csv_payload
    assert "event,2026-09-10.1" in csv_payload
    with pytest.raises(ProductAuditExportError, match="invalid_format"):
        render_product_audit_export(selection, "xml")  # type: ignore[arg-type]

    path = next(store.root.glob("*/*.json"))
    path.write_text("{corrupt", encoding="utf-8")
    with pytest.raises(ProductAuditError, match="audit_integrity_invalid"):
        select_product_audit_export(
            store, organization_id=ORGANIZATION_A, period="30d", state_at=now
        )


def test_selection_reports_truncation_and_applies_store_retention(tmp_path, monkeypatch):
    clock = [datetime(2026, 9, 1, 12, tzinfo=timezone.utc)]
    settings = Settings(
        data_dir=tmp_path,
        tool_runner_url="http://audit-tools:8081",
        product_audit_retention_days=1,
    )
    settings.ensure_directories()
    store = ProductAuditStore(settings, now_func=lambda: clock[0])
    old = record(store)
    clock[0] += timedelta(days=2)
    current = record(store)

    retained = select_product_audit_export(
        store, organization_id=ORGANIZATION_A, period="7d", state_at=clock[0]
    )
    assert retained.preflight.total_events == 1
    assert retained.events[0].event_reference != current.id
    assert old.id != current.id

    monkeypatch.setattr(
        store,
        "events_for_export",
        lambda *args, **kwargs: ([current] * 1_000, 1_001),
    )
    truncated = select_product_audit_export(
        store, organization_id=ORGANIZATION_A, period="7d", state_at=clock[0]
    )
    assert truncated.preflight.included_events == 1_000
    assert truncated.preflight.total_events == 1_001
    assert truncated.preflight.truncated is True
