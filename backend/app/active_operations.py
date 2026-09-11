from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from typing import Any

from app.active_asset_verification import ActiveAssetVerificationRecord
from app.active_assets import ACTIVE_CAPABILITIES, ActiveAssetRecord
from app.active_posture import build_active_posture
from app.models import JobRecord


ACTIVE_OPERATIONS_SUMMARY_CONTRACT_VERSION = "2026-09-09.4"
ACTIVE_OPERATIONS_MAX_ASSETS = 500
ACTIVE_OPERATIONS_MAX_JOBS = 2_000
ACTIVE_OPERATIONS_MAX_ACTIONS = 100
_ACTION_URGENCY_ORDER = {"immediate": 0, "high": 1, "scheduled": 2, "review": 3}


def build_active_operations_summary(
    assets: list[ActiveAssetRecord],
    jobs: list[JobRecord],
    verifications: dict[str, ActiveAssetVerificationRecord | None],
    *,
    capability_configuration: dict[str, bool],
    runner_health: dict[str, Any] | None = None,
    verification_enabled: bool,
    legacy_free_targets_enabled: bool,
    recurrence_enabled: bool = False,
    four_eyes_enabled: bool = False,
    admission_available: bool = True,
    asset_counts_override: dict[str, int] | None = None,
    total_jobs_override: int | None = None,
    priority_candidates_override: int = 0,
    now: datetime | None = None,
) -> dict[str, Any]:
    generated_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    total_assets = (
        int(asset_counts_override["total"])
        if asset_counts_override is not None
        else len(assets)
    )
    total_jobs = int(total_jobs_override) if total_jobs_override is not None else len(jobs)
    considered_assets = assets[:ACTIVE_OPERATIONS_MAX_ASSETS]
    considered_asset_ids = {asset.id for asset in considered_assets}
    considered_assets_by_id = {asset.id: asset for asset in considered_assets}
    considered_jobs = [job for job in jobs if job.active_asset_id in considered_asset_ids][:ACTIVE_OPERATIONS_MAX_JOBS]

    if asset_counts_override is None:
        identity_counts: dict[tuple[str, str], int] = {}
        for asset in assets:
            asset_type = getattr(asset, "asset_type", None)
            canonical_value = getattr(asset, "canonical_value", None)
            if isinstance(asset_type, str) and isinstance(canonical_value, str):
                identity = (asset_type, canonical_value)
                identity_counts[identity] = identity_counts.get(identity, 0) + 1
        duplicate_counts = [count for count in identity_counts.values() if count > 1]
        asset_counts = {
            "total": total_assets,
            "active": 0,
            "expired": 0,
            "revoked": 0,
            "expiring_14_days": 0,
            "duplicate_identity_groups": len(duplicate_counts),
            "duplicate_identity_records": sum(duplicate_counts),
        }
    else:
        asset_counts = {
            key: int(asset_counts_override[key])
            for key in (
                "total",
                "active",
                "expired",
                "revoked",
                "expiring_14_days",
                "duplicate_identity_groups",
                "duplicate_identity_records",
            )
        }
    verification_counts = {"not_started": 0, "pending": 0, "verified": 0, "failed": 0, "expired": 0, "revoked": 0}
    job_counts = {"total": total_jobs, "queued": 0, "running": 0, "cancelling": 0, "cancelled": 0, "completed": 0, "failed": 0, "degraded": 0}
    capability_assets = {capability: 0 for capability in sorted(ACTIVE_CAPABILITIES)}
    capability_jobs = {capability: 0 for capability in sorted(ACTIVE_CAPABILITIES)}

    for asset in considered_assets:
        if asset_counts_override is None:
            asset_counts[asset.status] += 1
            if asset.status == "active" and asset.expires_at <= generated_at + timedelta(days=14):
                asset_counts["expiring_14_days"] += 1
        latest = verifications.get(asset.id)
        verification_counts[latest.status if latest is not None else "not_started"] += 1
        for capability in asset.capabilities:
            capability_assets[capability] += 1

    jobs_by_asset: dict[str, list[JobRecord]] = {asset.id: [] for asset in considered_assets}
    for job in considered_jobs:
        if job.status in job_counts:
            job_counts[job.status] += 1
        if _job_is_degraded(job):
            job_counts["degraded"] += 1
        if job.audit_type in capability_jobs:
            capability_jobs[job.audit_type] += 1
        if job.active_asset_id in jobs_by_asset:
            jobs_by_asset[job.active_asset_id].append(job)

    observations_changed = 0
    assets_compared = 0
    assets_with_changes = 0
    inconclusive = 0
    action_candidates: list[dict[str, Any]] = []
    for asset in considered_assets:
        posture = build_active_posture(jobs_by_asset[asset.id], baseline_execution_id=asset.baseline_execution_id)
        comparison = posture.get("comparison")
        if comparison is None:
            continue
        assets_compared += 1
        if comparison.get("state") != "ready":
            inconclusive += 1
        changed = sum(int(comparison["summary"].get(key, 0)) for key in ("new", "changed", "disappeared"))
        observations_changed += changed
        if changed:
            assets_with_changes += 1
            target_execution_id = comparison.get("target_execution_id")
            target_job = next(
                (job for job in jobs_by_asset[asset.id] if job.id == target_execution_id),
                None,
            )
            triage_state = {
                entry.observation_key: entry.status
                for entry in getattr(asset, "triage", [])
            }
            unresolved_changes = [
                item for item in comparison.get("changes", [])
                if triage_state.get(item.get("signal"), "needs_review") == "needs_review"
            ]
            if unresolved_changes:
                action_candidates.append(_action_item(
                    kind="observations_changed",
                    urgency="review",
                    action_code="triage_changes",
                    asset_id=asset.id,
                    reference_at=target_job.updated_at if target_job is not None else generated_at,
                    job_id=target_job.id if target_job is not None else None,
                    occurrence_count=len(unresolved_changes),
                ))

    for asset in considered_assets:
        if asset.status == "expired":
            action_candidates.append(_action_item(
                kind="authorization_expired", urgency="immediate",
                action_code="renew_authorization", asset_id=asset.id,
                reference_at=asset.expires_at, due_at=asset.expires_at,
            ))
        elif asset.status == "active" and asset.expires_at <= generated_at + timedelta(days=14):
            action_candidates.append(_action_item(
                kind="authorization_expiring", urgency="scheduled",
                action_code="renew_authorization", asset_id=asset.id,
                reference_at=asset.expires_at, due_at=asset.expires_at,
            ))
        verification = verifications.get(asset.id)
        if (
            asset.status == "active"
            and verification is not None
            and verification.status in {"failed", "expired"}
        ):
            action_candidates.append(_action_item(
                kind=f"verification_{verification.status}", urgency="high",
                action_code="reverify_control", asset_id=asset.id,
                reference_at=(
                    verification.last_attempt_at
                    or verification.verification_expires_at
                    or verification.challenge_expires_at
                    or verification.created_at
                ),
                source_id=verification.id,
            ))

    latest_jobs: dict[tuple[str, str], JobRecord] = {}
    for job in considered_jobs:
        if job.active_asset_id is None:
            continue
        key = (job.active_asset_id, job.audit_type)
        current = latest_jobs.get(key)
        if current is None or (job.updated_at, job.id) > (current.updated_at, current.id):
            latest_jobs[key] = job
    for job in latest_jobs.values():
        asset = considered_assets_by_id.get(job.active_asset_id)
        if (
            job.status == "failed"
            and asset is not None
            and asset.status == "active"
            and job.audit_type in asset.capabilities
        ):
            action_candidates.append(_action_item(
                kind="execution_failed", urgency="high", action_code="retry_execution",
                asset_id=job.active_asset_id, job_id=job.id, reference_at=job.updated_at,
            ))
        elif _job_is_degraded(job):
            action_candidates.append(_action_item(
                kind="execution_degraded", urgency="review", action_code="review_execution",
                asset_id=job.active_asset_id, job_id=job.id, reference_at=job.updated_at,
            ))

    action_candidates.sort(key=_action_sort_key)
    action_items = action_candidates[:ACTIVE_OPERATIONS_MAX_ACTIONS]
    action_counts = {
        "authorization_expiring": sum(item["kind"] == "authorization_expiring" for item in action_candidates),
        "authorization_expired": sum(item["kind"] == "authorization_expired" for item in action_candidates),
        "failed_jobs": sum(item["kind"] == "execution_failed" for item in action_candidates),
        "degraded_jobs": sum(item["kind"] == "execution_degraded" for item in action_candidates),
        "verification_attention": sum(item["kind"].startswith("verification_") for item in action_candidates),
        "observation_changes": sum(item["kind"] == "observations_changed" for item in action_candidates),
    }

    return {
        "contract_version": ACTIVE_OPERATIONS_SUMMARY_CONTRACT_VERSION,
        "generated_at": generated_at.isoformat(),
        "assets": asset_counts,
        "verifications": verification_counts,
        "jobs": job_counts,
        "changes": {
            "assets_compared": assets_compared,
            "assets_with_changes": assets_with_changes,
            "observations_changed": observations_changed,
            "inconclusive": inconclusive,
        },
        "actions": {
            "total": len(action_candidates),
            **action_counts,
        },
        "action_queue": {
            "items": action_items,
            "returned": len(action_items),
            "total": len(action_candidates),
            "items_truncated": len(action_candidates) > ACTIVE_OPERATIONS_MAX_ACTIONS,
            "source_incomplete": total_assets > ACTIVE_OPERATIONS_MAX_ASSETS or total_jobs > ACTIVE_OPERATIONS_MAX_JOBS,
        },
        "capabilities": [
            build_active_capability_readiness(
                capability,
                backend_enabled=bool(capability_configuration.get(capability, False)),
                runner_health=runner_health,
            )
            | {
                "asset_count": capability_assets[capability],
                "execution_count": capability_jobs[capability],
            }
            for capability in sorted(ACTIVE_CAPABILITIES)
        ],
        "configuration": {
            "verification_enabled": verification_enabled,
            "recurrence_enabled": recurrence_enabled,
            "four_eyes_enabled": four_eyes_enabled,
            "legacy_free_targets_enabled": legacy_free_targets_enabled,
            "all_live_capabilities_disabled": not any(capability_configuration.values()),
        },
        "capacity": {
            "admission": "ready" if admission_available else "saturated",
            "retry_after_seconds": 5,
        },
        "limits": {
            "assets_considered": len(considered_assets),
            "assets_total": total_assets,
            "jobs_considered": len(considered_jobs),
            "jobs_total": total_jobs,
            "incomplete": total_assets > ACTIVE_OPERATIONS_MAX_ASSETS or total_jobs > ACTIVE_OPERATIONS_MAX_JOBS,
            "selection_strategy": "priority_then_recency",
            "priority_candidates": max(0, min(int(priority_candidates_override), len(considered_assets))),
        },
        "interpretation": "portfolio_counts_and_bounded_observations_not_vulnerability_findings",
    }


def _action_item(
    *,
    kind: str,
    urgency: str,
    action_code: str,
    asset_id: str,
    reference_at: datetime,
    due_at: datetime | None = None,
    job_id: str | None = None,
    source_id: str | None = None,
    occurrence_count: int = 1,
) -> dict[str, Any]:
    stable_source = source_id or job_id or reference_at.astimezone(timezone.utc).isoformat()
    action_id = hashlib.sha256(
        f"{ACTIVE_OPERATIONS_SUMMARY_CONTRACT_VERSION}\0{kind}\0{asset_id}\0{stable_source}".encode("ascii")
    ).hexdigest()[:32]
    return {
        "id": action_id,
        "kind": kind,
        "urgency": urgency,
        "action_code": action_code,
        "asset_id": asset_id,
        "job_id": job_id,
        "reference_at": reference_at.astimezone(timezone.utc).isoformat(),
        "due_at": due_at.astimezone(timezone.utc).isoformat() if due_at is not None else None,
        "occurrence_count": occurrence_count,
    }


def _action_sort_key(item: dict[str, Any]) -> tuple[int, str, str]:
    return (
        _ACTION_URGENCY_ORDER[item["urgency"]],
        item["due_at"] or item["reference_at"],
        item["id"],
    )


def build_active_capability_readiness(
    capability: str,
    *,
    backend_enabled: bool,
    runner_health: dict[str, Any] | None,
) -> dict[str, Any]:
    """Combine both opt-in gates into a targetless, closed readiness state."""

    health = runner_health if isinstance(runner_health, dict) else {}
    runner_capabilities = health.get("capabilities")
    runner_capability = runner_capabilities.get(capability) if isinstance(runner_capabilities, dict) else None
    runner_enabled = (
        runner_capability.get("execution_enabled")
        if isinstance(runner_capability, dict) and isinstance(runner_capability.get("execution_enabled"), bool)
        else None
    )
    health_available = health.get("available") is True
    error_code = health.get("error_code") if isinstance(health.get("error_code"), str) else None

    if not backend_enabled:
        readiness = "disabled"
        reason_code = "backend_disabled_runner_enabled" if runner_enabled is True else "backend_disabled"
    elif not health_available:
        if error_code in {"active_tools_invalid_response", "active_tools_unexpected_fields", "active_tools_not_ready"}:
            readiness = "degraded"
            reason_code = "runner_health_invalid"
        elif error_code == "active_tools_unconfigured":
            readiness = "unavailable"
            reason_code = "runner_unconfigured"
        else:
            readiness = "unavailable"
            reason_code = "runner_unavailable"
    elif runner_enabled is not True:
        readiness = "degraded"
        reason_code = "runner_gate_disabled" if runner_enabled is False else "runner_contract_mismatch"
    else:
        readiness = "ready"
        reason_code = "ready"

    return {
        "capability": capability,
        "enabled": readiness == "ready",
        "backend_enabled": backend_enabled,
        "runner_enabled": runner_enabled,
        "readiness": readiness,
        "reason_code": reason_code,
    }


def _job_is_degraded(job: JobRecord) -> bool:
    if job.status != "completed" or not isinstance(job.result, dict):
        return False
    result_status = job.result.get("status")
    coverage = job.result.get("coverage_level")
    return result_status in {"partial", "timed_out", "request_failed", "source_unavailable"} or coverage in {
        "partial",
        "partial_inventory",
        "incomplete",
    }
