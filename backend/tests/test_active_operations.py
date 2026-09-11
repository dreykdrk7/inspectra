from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.active_operations import (
    ACTIVE_OPERATIONS_MAX_ACTIONS,
    ACTIVE_OPERATIONS_MAX_ASSETS,
    build_active_operations_summary,
)
from app.models import JobRecord


def test_active_operations_summary_is_bounded_and_marks_partial_counts():
    now = datetime(2026, 9, 9, tzinfo=timezone.utc)
    assets = [
        SimpleNamespace(
            id=f"asset-{index}",
            status="active",
            expires_at=now + timedelta(days=30),
            capabilities=["active_dns_inventory"],
            baseline_execution_id=None,
        )
        for index in range(ACTIVE_OPERATIONS_MAX_ASSETS + 1)
    ]

    summary = build_active_operations_summary(
        assets,
        [],
        {},
        capability_configuration={"active_dns_inventory": True},
        verification_enabled=False,
        legacy_free_targets_enabled=False,
        now=now,
    )

    assert summary["assets"]["total"] == ACTIVE_OPERATIONS_MAX_ASSETS + 1
    assert summary["assets"]["active"] == ACTIVE_OPERATIONS_MAX_ASSETS
    assert summary["limits"] == {
        "assets_considered": ACTIVE_OPERATIONS_MAX_ASSETS,
        "assets_total": ACTIVE_OPERATIONS_MAX_ASSETS + 1,
        "jobs_considered": 0,
        "jobs_total": 0,
        "incomplete": True,
        "selection_strategy": "priority_then_recency",
        "priority_candidates": 0,
    }
    assert summary["interpretation"] == "portfolio_counts_and_bounded_observations_not_vulnerability_findings"
    assert summary["capacity"] == {"admission": "ready", "retry_after_seconds": 5}
    assert "asset-0" not in str(summary)


def test_active_operations_uses_exact_projection_totals_without_inflating_bounded_detail():
    now = datetime(2026, 9, 9, tzinfo=timezone.utc)
    assets = [_asset("a", "active", now + timedelta(days=30))]
    summary = build_active_operations_summary(
        assets,
        [],
        {},
        capability_configuration={"active_dns_inventory": True},
        verification_enabled=False,
        legacy_free_targets_enabled=False,
        asset_counts_override={
            "total": 10_000,
            "active": 9_000,
            "expired": 800,
            "revoked": 200,
            "expiring_14_days": 400,
            "duplicate_identity_groups": 2,
            "duplicate_identity_records": 4,
        },
        total_jobs_override=20_000,
        now=now,
    )

    assert summary["assets"] == {
        "total": 10_000,
        "active": 9_000,
        "expired": 800,
        "revoked": 200,
        "expiring_14_days": 400,
        "duplicate_identity_groups": 2,
        "duplicate_identity_records": 4,
    }
    assert summary["jobs"]["total"] == 20_000
    assert summary["jobs"]["completed"] == 0
    assert summary["limits"]["incomplete"] is True
    assert summary["action_queue"]["source_incomplete"] is True


def test_active_operations_capacity_is_closed_and_count_free():
    summary = build_active_operations_summary(
        [],
        [],
        {},
        capability_configuration={},
        verification_enabled=False,
        legacy_free_targets_enabled=False,
        admission_available=False,
    )

    assert summary["capacity"] == {"admission": "saturated", "retry_after_seconds": 5}
    assert not ({"count", "limit", "owner", "asset", "capability"} & set(summary["capacity"]))


def _asset(identifier: str, status: str, expires_at: datetime):
    return SimpleNamespace(
        id=identifier * 32 if len(identifier) == 1 else identifier,
        status=status,
        expires_at=expires_at,
        capabilities=["active_dns_inventory"],
        baseline_execution_id=None,
        triage=[],
    )


def _active_job(identifier: str, asset_id: str, at: datetime, *, status="completed", result=None):
    return JobRecord(
        id=identifier * 32,
        owner_id="local-admin",
        active_asset_id=asset_id,
        audit_type="active_dns_inventory",
        status=status,
        created_at=at,
        updated_at=at,
        result=result,
    )


def test_action_queue_is_stable_target_free_and_only_keeps_latest_execution_state():
    now = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
    expired = _asset("a", "expired", now - timedelta(days=2))
    expiring = _asset("b", "active", now + timedelta(days=3))
    verification_asset = _asset("c", "active", now + timedelta(days=30))
    recovered_asset = _asset("d", "active", now + timedelta(days=30))
    failed_asset = _asset("e", "active", now + timedelta(days=30))
    degraded_asset = _asset("f", "active", now + timedelta(days=30))
    changed_asset = _asset("1", "active", now + timedelta(days=30))
    verification = SimpleNamespace(
        id="2" * 32, status="failed", last_attempt_at=now - timedelta(days=10),
        verification_expires_at=None, challenge_expires_at=now - timedelta(days=10),
        created_at=now - timedelta(days=11),
    )
    jobs = [
        _active_job("3", recovered_asset.id, now - timedelta(days=2), status="failed"),
        _active_job("4", recovered_asset.id, now - timedelta(days=1)),
        _active_job("5", failed_asset.id, now - timedelta(days=8), status="failed"),
        _active_job("6", degraded_asset.id, now - timedelta(days=4), result={"status": "partial"}),
        _active_job("7", changed_asset.id, now - timedelta(days=3), result={"records": {"A": {"count": 1}}, "limits": {}}),
        _active_job("8", changed_asset.id, now - timedelta(days=2), result={"records": {"A": {"count": 2}}, "limits": {}}),
    ]
    summary = build_active_operations_summary(
        [expired, expiring, verification_asset, recovered_asset, failed_asset, degraded_asset, changed_asset],
        jobs,
        {verification_asset.id: verification},
        capability_configuration={"active_dns_inventory": True},
        verification_enabled=True,
        legacy_free_targets_enabled=False,
        now=now,
    )

    queue = summary["action_queue"]
    assert [item["kind"] for item in queue["items"]] == [
        "authorization_expired", "verification_failed", "execution_failed",
        "authorization_expiring", "execution_degraded", "observations_changed",
    ]
    assert all(item["asset_id"] != recovered_asset.id for item in queue["items"])
    assert summary["actions"] == {
        "total": 6, "authorization_expiring": 1, "authorization_expired": 1,
        "failed_jobs": 1, "degraded_jobs": 1, "verification_attention": 1,
        "observation_changes": 1,
    }
    assert queue == build_active_operations_summary(
        [expired, expiring, verification_asset, recovered_asset, failed_asset, degraded_asset, changed_asset],
        jobs,
        {verification_asset.id: verification},
        capability_configuration={"active_dns_inventory": True},
        verification_enabled=True,
        legacy_free_targets_enabled=False,
        now=now,
    )["action_queue"]
    serialized = str(queue)
    assert not any(value in serialized for value in ("target", "path", "secret", "example.test"))


def test_action_queue_is_bounded_and_marks_truncation():
    now = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
    assets = [
        _asset(f"{index + 1:032x}", "expired", now - timedelta(days=index + 1))
        for index in range(ACTIVE_OPERATIONS_MAX_ACTIONS + 1)
    ]
    summary = build_active_operations_summary(
        assets, [], {}, capability_configuration={}, verification_enabled=False,
        legacy_free_targets_enabled=False, now=now,
    )
    assert summary["action_queue"]["returned"] == ACTIVE_OPERATIONS_MAX_ACTIONS
    assert summary["action_queue"]["total"] == ACTIVE_OPERATIONS_MAX_ACTIONS + 1
    assert summary["action_queue"]["items_truncated"] is True


def test_summary_detects_legacy_duplicate_identities_without_returning_the_identity():
    now = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
    assets = [_asset("a", "active", now + timedelta(days=30)), _asset("b", "active", now + timedelta(days=30))]
    for asset in assets:
        asset.asset_type = "domain"
        asset.canonical_value = "private-legacy-identity.example.test"
    summary = build_active_operations_summary(
        assets, [], {}, capability_configuration={}, verification_enabled=False,
        legacy_free_targets_enabled=False, now=now,
    )
    assert summary["assets"]["duplicate_identity_groups"] == 1
    assert summary["assets"]["duplicate_identity_records"] == 2
    assert "private-legacy-identity" not in str(summary)


def test_action_queue_clears_only_observation_changes_with_a_closed_triage_decision():
    now = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
    asset = _asset("a", "active", now + timedelta(days=30))
    jobs = [
        _active_job("1", asset.id, now - timedelta(days=2), result={"records": {"A": {"count": 1}}, "limits": {}}),
        _active_job("2", asset.id, now - timedelta(days=1), result={"records": {"A": {"count": 2}}, "limits": {}}),
    ]
    pending = build_active_operations_summary(
        [asset], jobs, {}, capability_configuration={"active_dns_inventory": True},
        verification_enabled=False, legacy_free_targets_enabled=False, now=now,
    )
    action = next(item for item in pending["action_queue"]["items"] if item["kind"] == "observations_changed")
    assert action["occurrence_count"] == 1

    asset.triage = [SimpleNamespace(observation_key="dns_count:A", status="acknowledged")]
    resolved = build_active_operations_summary(
        [asset], jobs, {}, capability_configuration={"active_dns_inventory": True},
        verification_enabled=False, legacy_free_targets_enabled=False, now=now,
    )
    assert all(item["kind"] != "observations_changed" for item in resolved["action_queue"]["items"])
    assert resolved["changes"]["observations_changed"] == 1
    assert resolved["actions"]["observation_changes"] == 0


def test_action_queue_never_offers_retry_or_reverification_without_current_authorization():
    now = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
    expired = _asset("a", "expired", now - timedelta(days=1))
    verification = SimpleNamespace(
        id="b" * 32,
        status="failed",
        last_attempt_at=now - timedelta(days=2),
        verification_expires_at=None,
        challenge_expires_at=now - timedelta(days=2),
        created_at=now - timedelta(days=3),
    )
    summary = build_active_operations_summary(
        [expired],
        [_active_job("c", expired.id, now - timedelta(days=2), status="failed")],
        {expired.id: verification},
        capability_configuration={"active_dns_inventory": True},
        verification_enabled=True,
        legacy_free_targets_enabled=False,
        now=now,
    )

    assert [item["kind"] for item in summary["action_queue"]["items"]] == [
        "authorization_expired"
    ]


def _runner_health(*, available=True, enabled=False, error_code=None):
    return {
        "available": available,
        "error_code": error_code,
        "capabilities": {
            capability: {
                "status": "ready_bounded_execution" if enabled else "disabled_no_scan",
                "execution_enabled": enabled,
                "target_input_allowed": False,
            }
            for capability in (
                "active_dns_inventory",
                "active_dns_osint",
                "active_http_basic_header_review",
                "active_nmap_basic",
                "active_tls_basic",
            )
        },
    }


@pytest.mark.parametrize(
    ("backend_enabled", "runner_health", "expected_state", "expected_reason"),
    [
        (False, _runner_health(enabled=False), "disabled", "backend_disabled"),
        (False, _runner_health(enabled=True), "disabled", "backend_disabled_runner_enabled"),
        (True, _runner_health(enabled=True), "ready", "ready"),
        (True, _runner_health(enabled=False), "degraded", "runner_gate_disabled"),
        (True, _runner_health(available=False, error_code="active_tools_unconfigured"), "unavailable", "runner_unconfigured"),
        (True, _runner_health(available=False, error_code="active_tools_timeout"), "unavailable", "runner_unavailable"),
        (True, _runner_health(available=False, error_code="active_tools_invalid_response"), "degraded", "runner_health_invalid"),
    ],
)
def test_active_operations_combines_backend_and_runner_gates_without_target_metadata(
    backend_enabled,
    runner_health,
    expected_state,
    expected_reason,
):
    summary = build_active_operations_summary(
        [],
        [],
        {},
        capability_configuration={"active_dns_inventory": backend_enabled},
        runner_health=runner_health,
        verification_enabled=False,
        legacy_free_targets_enabled=False,
    )

    item = next(entry for entry in summary["capabilities"] if entry["capability"] == "active_dns_inventory")
    assert item == {
        "capability": "active_dns_inventory",
        "enabled": expected_state == "ready",
        "backend_enabled": backend_enabled,
        "runner_enabled": runner_health["capabilities"]["active_dns_inventory"]["execution_enabled"],
        "readiness": expected_state,
        "reason_code": expected_reason,
        "asset_count": 0,
        "execution_count": 0,
    }
    assert not ({"url", "host", "target", "path"} & set(item))
