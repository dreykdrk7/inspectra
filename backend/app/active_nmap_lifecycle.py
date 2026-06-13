from __future__ import annotations

from typing import Any, Mapping, Protocol

from app.active_nmap_boundary import build_active_nmap_basic_boundary_request
from app.active_nmap_handoff import ActiveNmapBasicHandoffPlan
from app.config import Settings


ACTIVE_NMAP_BASIC_LIFECYCLE_CONTROLLED_STATES = {
    "blocked_missing_approval",
    "blocked_unconfigured",
    "client_error_controlled",
    "completed_no_live",
    "not_executed",
}
ACTIVE_NMAP_BASIC_LIFECYCLE_CLIENT_CONTROLLED_ERRORS = {
    "active_tools_invalid_response",
    "active_tools_timeout",
    "active_tools_unavailable",
    "active_tools_unconfigured",
    "active_tools_unexpected_fields",
}


class ActiveNmapBasicNoLiveClient(Protocol):
    client_mode: str

    async def __call__(
        self,
        base_url: str | None,
        request_payload: Mapping[str, Any],
        *,
        timeout_seconds: float,
    ) -> Mapping[str, Any]:
        """Return a controlled no-live active-tools client result."""


class ActiveNmapBasicJobLifecycleSkeleton:
    def __init__(
        self,
        settings: Settings,
        *,
        client: ActiveNmapBasicNoLiveClient | None = None,
    ) -> None:
        self.settings = settings
        self.client = client

    async def run(
        self,
        handoff_plan: ActiveNmapBasicHandoffPlan,
        *,
        internal_approval_confirmed: bool,
        fake_client_approved: bool,
        request_id: str = "active-nmap-basic-lifecycle-skeleton",
        job_id: str = "active-nmap-basic-skeleton-job",
        correlation_id: str = "active-nmap-basic-skeleton-correlation",
    ) -> dict[str, Any]:
        blocked = self._blocked_before_client(
            handoff_plan,
            internal_approval_confirmed=internal_approval_confirmed,
            fake_client_approved=fake_client_approved,
        )
        if blocked is not None:
            return blocked

        request_payload = build_active_nmap_basic_boundary_request(
            handoff_plan.units[0],
            job_id=job_id,
            request_id=request_id,
            correlation_id=correlation_id,
        )
        client_result = await self.client(
            self.settings.active_tools_url,
            request_payload,
            timeout_seconds=self.settings.active_tools_health_timeout_seconds,
        )
        return _normalize_lifecycle_client_result(client_result, handoff_plan=handoff_plan)

    def _blocked_before_client(
        self,
        handoff_plan: ActiveNmapBasicHandoffPlan,
        *,
        internal_approval_confirmed: bool,
        fake_client_approved: bool,
    ) -> dict[str, Any] | None:
        if not self.settings.active_nmap_basic_enabled or not self.settings.active_tools_url:
            return _lifecycle_state("blocked_unconfigured", "active_nmap_basic_not_configured")
        if not internal_approval_confirmed or not fake_client_approved:
            return _lifecycle_state("blocked_missing_approval", "internal_approval_missing")
        if self.client is None or getattr(self.client, "client_mode", None) != "fake_no_live":
            return _lifecycle_state("blocked_missing_approval", "fake_no_live_client_required")
        if not _handoff_plan_is_single_bounded_unit(handoff_plan):
            return _lifecycle_state("blocked_missing_approval", "bounded_single_unit_required")
        return None


async def run_active_nmap_basic_lifecycle_skeleton(
    settings: Settings,
    handoff_plan: ActiveNmapBasicHandoffPlan,
    *,
    client: ActiveNmapBasicNoLiveClient | None = None,
    internal_approval_confirmed: bool,
    fake_client_approved: bool,
) -> dict[str, Any]:
    lifecycle = ActiveNmapBasicJobLifecycleSkeleton(settings, client=client)
    return await lifecycle.run(
        handoff_plan,
        internal_approval_confirmed=internal_approval_confirmed,
        fake_client_approved=fake_client_approved,
    )


def _normalize_lifecycle_client_result(client_result: Mapping[str, Any], *, handoff_plan: ActiveNmapBasicHandoffPlan) -> dict[str, Any]:
    if not isinstance(client_result, Mapping):
        result = _lifecycle_state("client_error_controlled", "active_tools_invalid_response")
        result["client_invoked"] = True
        return result

    if not client_result.get("available"):
        result = _lifecycle_state(
            "client_error_controlled",
            _safe_client_error_code(client_result.get("error_code")),
            client_status=_safe_status(client_result.get("status")),
        )
        result["client_invoked"] = True
        return result

    if not _client_result_is_no_live_safe(client_result):
        result = _lifecycle_state("client_error_controlled", "unsafe_client_result")
        result["client_invoked"] = True
        result["active_tools_client_available"] = True
        return result

    result = _lifecycle_state("completed_no_live", "fake_client_not_executed", client_status="not_executed")
    result.update(
        {
            "client_invoked": True,
            "active_tools_client_available": True,
            "active_tools_status": "not_executed",
            "target_count": handoff_plan.target_count,
            "port_count": handoff_plan.port_count,
            "target_port_checks": handoff_plan.target_port_checks,
            "network_requests_sent": 0,
            "nmap_executed": False,
            "target_expansion_performed": False,
            "observations": [],
        }
    )
    return result


def _client_result_is_no_live_safe(client_result: Mapping[str, Any]) -> bool:
    return (
        client_result.get("status") == "not_executed"
        and client_result.get("service") == "active-tools"
        and client_result.get("capability") == "active_nmap_basic"
        and client_result.get("execution_enabled") is False
        and client_result.get("target_input_allowed") is False
        and client_result.get("manual_validation_required") is True
        and client_result.get("job_created") is False
        and client_result.get("target_expansion_performed") is False
        and client_result.get("network_requests_sent") == 0
        and client_result.get("nmap_executed") is False
        and client_result.get("evidence_available") is False
        and client_result.get("observations") == []
        and client_result.get("error_code") is None
    )


def _lifecycle_state(
    state: str,
    reason: str,
    *,
    client_status: str | None = None,
) -> dict[str, Any]:
    controlled_state = state if state in ACTIVE_NMAP_BASIC_LIFECYCLE_CONTROLLED_STATES else "client_error_controlled"
    return {
        "audit_type": "active_nmap_basic",
        "lifecycle_state": controlled_state,
        "execution_state": client_status or "not_executed",
        "reason": reason,
        "job_created": False,
        "storage_persisted": False,
        "client_invoked": False,
        "active_tools_client_available": False,
        "active_tools_real_call_allowed": False,
        "nmap_executed": False,
        "network_requests_sent": 0,
        "dns_queries_sent": 0,
        "subprocess_invoked": False,
        "target_expansion_performed": False,
        "evidence_available": False,
        "observations": [],
        "warnings": [],
        "errors": [reason] if controlled_state != "completed_no_live" else [],
    }


def _handoff_plan_is_single_bounded_unit(handoff_plan: ActiveNmapBasicHandoffPlan) -> bool:
    if not isinstance(handoff_plan, ActiveNmapBasicHandoffPlan):
        return False
    if handoff_plan.target_count != 1 or len(handoff_plan.units) != 1:
        return False
    unit = handoff_plan.units[0]
    return len(unit.ports) == 1 and handoff_plan.port_count == 1 and handoff_plan.target_port_checks == 1


def _safe_client_error_code(value: Any) -> str:
    return value if isinstance(value, str) and value in ACTIVE_NMAP_BASIC_LIFECYCLE_CLIENT_CONTROLLED_ERRORS else "active_tools_invalid_response"


def _safe_status(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None
