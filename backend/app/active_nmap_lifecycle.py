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
ACTIVE_NMAP_BASIC_LIFECYCLE_ROUTE_REASONS = ACTIVE_NMAP_BASIC_LIFECYCLE_CLIENT_CONTROLLED_ERRORS | {
    "active_nmap_basic_not_configured",
    "bounded_single_unit_required",
    "fake_client_not_executed",
    "fake_no_live_client_required",
    "internal_approval_missing",
    "unsafe_client_result",
    "unsafe_lifecycle_result",
}
ACTIVE_NMAP_BASIC_LIFECYCLE_FORBIDDEN_RESULT_KEYS = {
    "banner",
    "banners",
    "command",
    "raw_args",
    "raw_command",
    "raw_xml",
    "service",
    "service_details",
    "stderr",
    "stdout",
    "version",
    "versions",
    "xml",
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


class ActiveNmapBasicRouteNoLiveClient:
    client_mode = "fake_no_live"

    async def __call__(
        self,
        base_url: str | None,
        request_payload: Mapping[str, Any],
        *,
        timeout_seconds: float,
    ) -> Mapping[str, Any]:
        return _no_live_client_result()


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


def normalize_active_nmap_basic_lifecycle_route_result(result: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(result, Mapping) or _route_result_has_unsafe_markers(result):
        return _route_state("client_error_controlled", "unsafe_lifecycle_result")

    lifecycle_state = result.get("lifecycle_state")
    if lifecycle_state not in ACTIVE_NMAP_BASIC_LIFECYCLE_CONTROLLED_STATES:
        return _route_state("client_error_controlled", "unsafe_lifecycle_result")

    reason = _safe_lifecycle_route_reason(result.get("reason"))
    execution_state = _safe_status(result.get("execution_state")) or "not_executed"
    response = _route_state(lifecycle_state, reason, execution_state=execution_state)
    response.update(
        {
            "client_invoked": result.get("client_invoked") is True,
            "active_tools_client_available": result.get("active_tools_client_available") is True,
        }
    )
    for count_field in ("target_count", "port_count", "target_port_checks"):
        value = result.get(count_field)
        if isinstance(value, int) and value >= 0:
            response[count_field] = value
    return response


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


def _route_state(
    lifecycle_state: str,
    reason: str,
    *,
    execution_state: str = "not_executed",
) -> dict[str, Any]:
    state = lifecycle_state if lifecycle_state in ACTIVE_NMAP_BASIC_LIFECYCLE_CONTROLLED_STATES else "client_error_controlled"
    safe_reason = _safe_lifecycle_route_reason(reason)
    return {
        "audit_type": "active_nmap_basic",
        "status": execution_state,
        "lifecycle_state": state,
        "execution_state": execution_state,
        "reason": safe_reason,
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
        "errors": [] if state == "completed_no_live" else [safe_reason],
    }


def _no_live_client_result() -> dict[str, Any]:
    return {
        "available": True,
        "status": "not_executed",
        "service": "active-tools",
        "capability": "active_nmap_basic",
        "mode": "live_nmap_basic",
        "profile": "tcp_connect_small",
        "execution_enabled": False,
        "target_input_allowed": False,
        "manual_validation_required": True,
        "job_created": False,
        "target_expansion_performed": False,
        "network_requests_sent": 0,
        "nmap_executed": False,
        "evidence_available": False,
        "observations": [],
        "warnings": ["no_scan_route_lifecycle"],
        "errors": [],
        "error_code": None,
    }


def _route_result_has_unsafe_markers(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if isinstance(key, str) and key.lower() in ACTIVE_NMAP_BASIC_LIFECYCLE_FORBIDDEN_RESULT_KEYS:
                return True
            if key == "job_created" and nested is not False:
                return True
            if key == "storage_persisted" and nested is not False:
                return True
            if key == "active_tools_real_call_allowed" and nested is not False:
                return True
            if key == "nmap_executed" and nested is not False:
                return True
            if key == "network_requests_sent" and nested != 0:
                return True
            if key == "dns_queries_sent" and nested != 0:
                return True
            if key == "subprocess_invoked" and nested is not False:
                return True
            if key == "target_expansion_performed" and nested is not False:
                return True
            if key == "evidence_available" and nested is not False:
                return True
            if key == "observations" and nested != []:
                return True
            if _route_result_has_unsafe_markers(nested):
                return True
        return False
    if isinstance(value, list):
        return any(_route_result_has_unsafe_markers(item) for item in value)
    return False


def _safe_lifecycle_route_reason(value: Any) -> str:
    return value if isinstance(value, str) and value in ACTIVE_NMAP_BASIC_LIFECYCLE_ROUTE_REASONS else "active_tools_invalid_response"


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
