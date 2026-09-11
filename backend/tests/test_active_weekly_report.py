from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.active_weekly_report import (
    ACTIVE_WEEKLY_REPORT_MAX_BYTES,
    ActiveWeeklyReportError,
    build_active_weekly_report_snapshot,
    render_active_weekly_report,
)


def _summary(*, total: int, considered: int) -> dict:
    return {
        "assets": {
            "total": total,
            "active": considered,
            "expired": 0,
            "revoked": 0,
            "expiring_14_days": 0,
            "duplicate_identity_groups": 0,
            "duplicate_identity_records": 0,
        },
        "actions": {
            "total": 0,
            "authorization_expiring": 0,
            "authorization_expired": 0,
            "failed_jobs": 0,
            "degraded_jobs": 0,
            "verification_attention": 0,
            "observation_changes": 0,
        },
        "action_queue": {"items": [], "total": 0, "items_truncated": False},
        "changes": {
            "assets_compared": 0,
            "assets_with_changes": 0,
            "observations_changed": 0,
            "inconclusive": 0,
        },
        "limits": {
            "assets_total": total,
            "assets_considered": considered,
            "jobs_total": 0,
            "jobs_considered": 0,
            "selection_strategy": "priority_then_recency",
            "incomplete": considered < total,
        },
    }


def _asset(index: int, now: datetime, *, organization_id: str = "organization-a"):
    return SimpleNamespace(
        id=f"{index:032x}",
        organization_id=organization_id,
        canonical_value=f"asset-{index}.example.test",
        asset_type="domain",
        status="active",
        expires_at=now + timedelta(days=30),
        updated_at=now - timedelta(minutes=1),
        capabilities=["active_dns_inventory"],
    )


def test_weekly_report_declares_bounded_portfolio_coverage_and_stays_under_limit():
    now = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
    assets = [_asset(index, now) for index in range(500)]

    snapshot = build_active_weekly_report_snapshot(
        _summary(total=501, considered=500),
        assets,
        [],
        [],
        organization_id="organization-a",
        period="7d",
        state_at=now,
    )

    assert snapshot.preflight.state == "partial"
    assert snapshot.preflight.assets_included == 500
    assert snapshot.preflight.assets_total == 501
    assert snapshot.preflight.incomplete is True
    assert len(snapshot.document["asset_inventory"]) == 500
    assert snapshot.document["coverage"]["selection_strategy"] == "priority_then_recency"
    for report_format in ("markdown", "json"):
        payload = render_active_weekly_report(snapshot, report_format)
        assert 0 < len(payload) <= ACTIVE_WEEKLY_REPORT_MAX_BYTES
        assert b"asset-0.example.test" in payload
        assert b"change-ticket" not in payload


def test_weekly_report_rejects_cross_organization_assets_before_rendering():
    now = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
    with pytest.raises(ActiveWeeklyReportError, match="snapshot_changed"):
        build_active_weekly_report_snapshot(
            _summary(total=1, considered=1),
            [_asset(1, now, organization_id="organization-b")],
            [],
            [],
            organization_id="organization-a",
            period="30d",
            state_at=now,
        )
