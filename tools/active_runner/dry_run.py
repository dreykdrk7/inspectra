from __future__ import annotations

from typing import Any

from .audit_log import audit_event
from .models import (
    ALLOWED_PROFILES,
    APPROVED_AUTHORIZATION_STATEMENT,
    DRY_RUN_MODE,
    HTTP_HEADER_PROBE_PREVIEW,
    POLICY_VERSION,
    ActiveDryRunRequest,
    ActiveDryRunResult,
)
from .safety import blocked_reason, normalize_target


def run_active_network_dry_run(request: ActiveDryRunRequest) -> ActiveDryRunResult:
    audit_log: list[dict[str, Any]] = [audit_event("active_request_received", {"mode": request.mode, "profile": request.profile})]
    blocked_reasons: list[dict[str, str]] = []

    if not request.authorization.confirmed or request.authorization.statement != APPROVED_AUTHORIZATION_STATEMENT:
        blocked_reasons.append(blocked_reason("authorization_missing"))
    audit_log.append(audit_event("authorization_checked", {"confirmed": request.authorization.confirmed}))

    target, target_reasons = normalize_target(request.target)
    blocked_reasons.extend(target_reasons)
    if target_reasons:
        audit_log.append(audit_event("target_rejected", {"blocked_reasons": [reason["code"] for reason in target_reasons]}))
    else:
        audit_log.append(audit_event("target_normalized", {"type": target["type"], "classification": target["classification"]}))

    blocked_reasons.extend(validate_mode_profile_and_limits(request))

    allowed = not blocked_reasons
    policy = {
        "allowed": allowed,
        "mode": DRY_RUN_MODE if allowed else "blocked",
        "policy_version": POLICY_VERSION,
        "reasons": [],
        "blocked_reasons": blocked_reasons,
        "warnings": [],
    }
    audit_log.append(audit_event("policy_evaluated", {"allowed": allowed, "blocked_reasons": [reason["code"] for reason in blocked_reasons]}))

    planned_checks = planned_checks_for_target(request, target) if allowed else []
    audit_log.append(audit_event("dry_run_planned" if allowed else "dry_run_blocked", {"planned_checks_count": len(planned_checks)}))

    return {
        "analyzer": "active_network_dry_run",
        "mode": DRY_RUN_MODE,
        "profile": request.profile,
        "target": target,
        "authorization": request.authorization.to_result(),
        "policy": policy,
        "limits": request.limits.to_result(),
        "planned_checks": planned_checks,
        "blocked_reasons": blocked_reasons,
        "findings": [],
        "audit_log": audit_log,
        "errors": [],
        "summary": {
            "allowed": allowed,
            "planned_checks_count": len(planned_checks),
            "blocked_reasons_count": len(blocked_reasons),
            "network_requests_sent": 0,
        },
    }


def validate_mode_profile_and_limits(request: ActiveDryRunRequest) -> list[dict[str, str]]:
    reasons: list[dict[str, str]] = []
    if request.mode != DRY_RUN_MODE:
        reasons.append(blocked_reason("live_mode_not_available"))
    if request.profile.lower().startswith("nmap"):
        reasons.append(blocked_reason("nmap_not_allowed"))
    elif request.profile not in ALLOWED_PROFILES:
        reasons.append(blocked_reason("unknown_profile"))
    if not request.limits.is_zero():
        reasons.append(blocked_reason("limits_exceed_dry_run"))
    return reasons


def planned_checks_for_target(request: ActiveDryRunRequest, target: dict[str, object]) -> list[dict[str, Any]]:
    if request.profile != HTTP_HEADER_PROBE_PREVIEW:
        return []
    preview_url = preview_url_for_target(target)
    return [
        {
            "id": HTTP_HEADER_PROBE_PREVIEW,
            "title": "HTTP header probe preview",
            "would_contact_target": False,
            "method": "HEAD",
            "url": preview_url,
            "network_disabled": True,
            "reason": DRY_RUN_MODE,
        }
    ]


def preview_url_for_target(target: dict[str, object]) -> str:
    target_type = str(target.get("type") or "")
    normalized = target.get("normalized")
    if target_type == "url" and isinstance(normalized, str):
        return normalized
    host = target.get("host")
    if isinstance(host, str) and host:
        return f"https://{host}/"
    return ""
