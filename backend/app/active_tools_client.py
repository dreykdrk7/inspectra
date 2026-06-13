from __future__ import annotations

from typing import Any, Mapping

import httpx

from app.config import DEFAULT_ACTIVE_TOOLS_HEALTH_TIMEOUT_SECONDS


ACTIVE_TOOLS_HEALTH_ALLOWED_FIELDS = {
    "capabilities",
    "network_requests_sent",
    "nmap_executed",
    "service",
    "status",
}
ACTIVE_TOOLS_HEALTH_ALLOWED_CAPABILITIES = {"active_nmap_basic"}
ACTIVE_TOOLS_HEALTH_ALLOWED_NMAP_FIELDS = {
    "execution_enabled",
    "status",
    "target_input_allowed",
}
ACTIVE_TOOLS_HEALTH_ERROR_CODES = {
    "active_tools_unconfigured",
    "active_tools_unavailable",
    "active_tools_timeout",
    "active_tools_invalid_response",
    "active_tools_unexpected_fields",
    "active_tools_not_ready",
}


async def check_active_tools_health(
    base_url: str | None,
    *,
    timeout_seconds: float = DEFAULT_ACTIVE_TOOLS_HEALTH_TIMEOUT_SECONDS,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    normalized_base_url = _normalize_active_tools_base_url(base_url)
    if not normalized_base_url:
        return _active_tools_health_error("active_tools_unconfigured")

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds, transport=transport) as client:
            response = await client.get(f"{normalized_base_url}/health")
            response.raise_for_status()
    except httpx.TimeoutException:
        return _active_tools_health_error("active_tools_timeout")
    except httpx.HTTPStatusError as exc:
        error_code = "active_tools_not_ready" if exc.response.status_code == 503 else "active_tools_unavailable"
        return _active_tools_health_error(error_code)
    except httpx.RequestError:
        return _active_tools_health_error("active_tools_unavailable")

    try:
        payload = response.json()
    except ValueError:
        return _active_tools_health_error("active_tools_invalid_response")

    return validate_active_tools_health_payload(payload)


def validate_active_tools_health_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        return _active_tools_health_error("active_tools_invalid_response")

    normalized_keys = {_normalize_key(key) for key in payload}
    if normalized_keys != ACTIVE_TOOLS_HEALTH_ALLOWED_FIELDS:
        return _active_tools_health_error("active_tools_unexpected_fields")

    capabilities = payload.get("capabilities")
    if not isinstance(capabilities, Mapping):
        return _active_tools_health_error("active_tools_invalid_response")
    if {_normalize_key(key) for key in capabilities} != ACTIVE_TOOLS_HEALTH_ALLOWED_CAPABILITIES:
        return _active_tools_health_error("active_tools_unexpected_fields")

    nmap_capability = capabilities.get("active_nmap_basic")
    if not isinstance(nmap_capability, Mapping):
        return _active_tools_health_error("active_tools_invalid_response")
    if {_normalize_key(key) for key in nmap_capability} != ACTIVE_TOOLS_HEALTH_ALLOWED_NMAP_FIELDS:
        return _active_tools_health_error("active_tools_unexpected_fields")

    status = _safe_status(payload.get("status"))
    active_nmap_basic_status = _safe_status(nmap_capability.get("status"))
    execution_enabled = nmap_capability.get("execution_enabled")
    target_input_allowed = nmap_capability.get("target_input_allowed")
    network_requests_sent = payload.get("network_requests_sent")
    nmap_executed = payload.get("nmap_executed")

    result = _active_tools_health_error(
        "",
        status=status,
        active_nmap_basic_status=active_nmap_basic_status,
        execution_enabled=execution_enabled if isinstance(execution_enabled, bool) else None,
        target_input_allowed=target_input_allowed if isinstance(target_input_allowed, bool) else None,
        network_requests_sent=network_requests_sent if _is_non_negative_int(network_requests_sent) else None,
        nmap_executed=nmap_executed if isinstance(nmap_executed, bool) else None,
    )

    if (
        status != "scaffold_ready"
        or active_nmap_basic_status != "disabled_no_scan"
        or not isinstance(execution_enabled, bool)
        or not isinstance(target_input_allowed, bool)
    ):
        result["error_code"] = "active_tools_not_ready"
        return result
    if execution_enabled or target_input_allowed:
        result["error_code"] = "active_tools_invalid_response"
        return result
    if not _is_non_negative_int(network_requests_sent) or not isinstance(nmap_executed, bool):
        result["error_code"] = "active_tools_invalid_response"
        return result
    if network_requests_sent != 0 or nmap_executed:
        result["error_code"] = "active_tools_invalid_response"
        return result

    result["available"] = True
    result["error_code"] = None
    return result


def _active_tools_health_error(
    error_code: str,
    *,
    status: str | None = None,
    active_nmap_basic_status: str | None = None,
    execution_enabled: bool | None = None,
    target_input_allowed: bool | None = None,
    network_requests_sent: int | None = None,
    nmap_executed: bool | None = None,
) -> dict[str, Any]:
    controlled_error = error_code if error_code in ACTIVE_TOOLS_HEALTH_ERROR_CODES else None
    return {
        "available": False,
        "status": status,
        "active_nmap_basic_status": active_nmap_basic_status,
        "execution_enabled": execution_enabled,
        "target_input_allowed": target_input_allowed,
        "network_requests_sent": network_requests_sent,
        "nmap_executed": nmap_executed,
        "error_code": controlled_error,
    }


def _normalize_active_tools_base_url(base_url: str | None) -> str:
    if not isinstance(base_url, str):
        return ""
    return base_url.strip().rstrip("/")


def _safe_status(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _is_non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _normalize_key(value: Any) -> str:
    return str(value).lower().replace("-", "_")
