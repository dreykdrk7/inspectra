from datetime import datetime, timedelta, timezone
import json

from app.active_audit_export import (
    ACTIVE_AUDIT_EXPORT_CONTRACT_VERSION,
    ACTIVE_AUDIT_EXPORT_MAX_EVENTS,
    render_active_audit_export,
    select_active_audit_export,
)
from app.models import ProductAuditEvent


def _event(index: int, *, occurred_at: datetime) -> ProductAuditEvent:
    return ProductAuditEvent(
        id=f"{index + 1:032x}",
        organization_id="a" * 32,
        actor_id="b" * 32,
        actor_role="maintainer",
        action="active_asset.execution_requested",
        resource_type="unexpected_resource",
        resource_id="c" * 32,
        result="succeeded",
        correlation_id=f"private-correlation-{index}",
        occurred_at=occurred_at,
        metadata={
            "authorization_revision_id": "d" * 32,
            "authorization_revision_sequence": 2,
            "private_value": "private-metadata-canary",
        },
    )


class _FakeStore:
    retention_days = 90

    def __init__(self, events):
        self.events = events

    def active_events_for_export(self, _organization_id, **options):
        limit = options["limit"]
        return self.events[-limit:], len(self.events)


def test_active_audit_export_reports_truncation_and_projects_only_closed_fields():
    now = datetime(2026, 9, 8, 12, tzinfo=timezone.utc)
    events = [_event(index, occurred_at=now - timedelta(seconds=ACTIVE_AUDIT_EXPORT_MAX_EVENTS - index)) for index in range(ACTIVE_AUDIT_EXPORT_MAX_EVENTS + 1)]
    selection = select_active_audit_export(
        _FakeStore(events),
        organization_id="a" * 32,
        period="30d",
        now=now,
    )

    assert selection.preflight.contract_version == ACTIVE_AUDIT_EXPORT_CONTRACT_VERSION
    assert selection.preflight.total_events == ACTIVE_AUDIT_EXPORT_MAX_EVENTS + 1
    assert selection.preflight.included_events == ACTIVE_AUDIT_EXPORT_MAX_EVENTS
    assert selection.preflight.truncated is True
    assert selection.events[0].resource_type == "active_resource"
    assert selection.events[0].authorization_revision_id == "d" * 32
    assert selection.events[0].authorization_revision_sequence == 2

    json_payload = render_active_audit_export(selection, "json")
    csv_payload = render_active_audit_export(selection, "csv")
    document = json.loads(json_payload)
    assert document["preflight"]["truncated"] is True
    assert len(document["events"]) == ACTIVE_AUDIT_EXPORT_MAX_EVENTS
    assert csv_payload.splitlines()[1].startswith(b"manifest,2026-09-08.1,30d")
    for forbidden in (
        b"private-metadata-canary",
        b"private-correlation",
        ("a" * 32).encode(),
        ("b" * 32).encode(),
        ("c" * 32).encode(),
    ):
        assert forbidden not in json_payload
        assert forbidden not in csv_payload
