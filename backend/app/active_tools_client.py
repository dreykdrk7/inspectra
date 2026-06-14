from __future__ import annotations

from ipaddress import ip_address
from typing import Any, Mapping
from urllib.parse import urlparse

import httpx

from app.active_nmap_boundary import validate_active_nmap_basic_boundary_response
from app.config import DEFAULT_ACTIVE_TOOLS_HEALTH_TIMEOUT_SECONDS


ACTIVE_TOOLS_NMAP_BASIC_PATH = "/active/nmap-basic"
ACTIVE_TOOLS_NMAP_BASIC_MODE = "live_nmap_basic"
ACTIVE_TOOLS_NMAP_BASIC_PROFILE = "tcp_connect_small"
ACTIVE_TOOLS_NMAP_BASIC_MAX_PORTS = 32
ACTIVE_TOOLS_NMAP_BASIC_ALLOWED_REQUEST_FIELDS = {
    "confirmations_verified_by_backend",
    "correlation_id",
    "job_id",
    "limits",
    "mode",
    "profile",
    "request_id",
    "target_unit",
}
ACTIVE_TOOLS_NMAP_BASIC_ALLOWED_TARGET_UNIT_FIELDS = {
    "accepted_ports",
    "target",
    "target_kind",
}
ACTIVE_TOOLS_NMAP_BASIC_ALLOWED_TARGET_KINDS = {
    "authorized_fqdn",
    "container_loopback",
    "private_hostname",
    "private_ip",
}
ACTIVE_TOOLS_NMAP_BASIC_ALLOWED_LIMIT_FIELDS = {
    "process_timeout_seconds",
    "response_max_bytes",
    "stderr_max_bytes",
    "stdout_max_bytes",
}
ACTIVE_TOOLS_NMAP_BASIC_ALLOWED_RESPONSE_FIELDS = {
    "capability",
    "errors",
    "execution_metadata",
    "execution_enabled",
    "job_created",
    "manual_validation_required",
    "mode",
    "network_requests_sent",
    "observations",
    "output_truncated",
    "profile",
    "reason",
    "result_interpretation",
    "service",
    "status",
    "summary",
    "target_kind",
    "target_expansion_performed",
    "target_input_allowed",
    "warnings",
}
ACTIVE_TOOLS_NMAP_BASIC_ALLOWED_SUMMARY_FIELDS = {
    "evidence_available",
    "fake_executor",
    "nmap_executed",
    "port_count",
    "target_count",
}
ACTIVE_TOOLS_NMAP_BASIC_SENSITIVE_FIELDS = {
    "args",
    "argv",
    "banner",
    "banners",
    "cmd",
    "command",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "extra_args",
    "header",
    "headers",
    "host",
    "hostname",
    "hostnames",
    "ip",
    "ips",
    "local_path",
    "nse",
    "nse_output",
    "ptr_hostname",
    "ptr_hostnames",
    "raw_args",
    "raw_command",
    "raw_stderr",
    "raw_stdout",
    "raw_xml",
    "resolved_ip",
    "resolved_ips",
    "script",
    "script_output",
    "scripts",
    "service_banner",
    "service_product",
    "stderr",
    "stdout",
    "target_file",
    "target_files",
    "token",
    "tokens",
    "version",
    "xml",
}
ACTIVE_TOOLS_NMAP_BASIC_ERROR_CODES = {
    "active_tools_invalid_response",
    "active_tools_timeout",
    "active_tools_unavailable",
    "active_tools_unconfigured",
    "active_tools_unexpected_fields",
}
ACTIVE_TOOLS_NMAP_BASIC_ERROR_STATUS = {
    "active_tools_invalid_response": "malformed",
    "active_tools_timeout": "timed_out",
    "active_tools_unavailable": "failed",
    "active_tools_unconfigured": "failed",
    "active_tools_unexpected_fields": "blocked",
}
ACTIVE_TOOLS_NMAP_BASIC_REAL_STATUSES = {
    "blocked",
    "completed",
    "empty",
    "failed",
    "malformed",
    "nmap_missing",
    "no_ports",
    "timed_out",
    "truncated",
    "unsupported_shape",
}
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


async def run_active_nmap_basic(
    base_url: str | None,
    request_payload: Mapping[str, Any] | Any,
    *,
    timeout_seconds: float = DEFAULT_ACTIVE_TOOLS_HEALTH_TIMEOUT_SECONDS,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    request_error = validate_active_tools_nmap_basic_request(request_payload)
    if request_error is not None:
        return request_error

    normalized_base_url = _normalize_active_tools_base_url(base_url)
    if not normalized_base_url:
        return _active_tools_nmap_basic_error("active_tools_unconfigured")

    try:
        async with httpx.AsyncClient(timeout=timeout_seconds, transport=transport) as client:
            response = await client.post(f"{normalized_base_url}{ACTIVE_TOOLS_NMAP_BASIC_PATH}", json=request_payload)
            response.raise_for_status()
    except httpx.TimeoutException:
        return _active_tools_nmap_basic_error("active_tools_timeout")
    except httpx.HTTPStatusError:
        return _active_tools_nmap_basic_error("active_tools_unavailable")
    except httpx.RequestError:
        return _active_tools_nmap_basic_error("active_tools_unavailable")

    try:
        payload = response.json()
    except ValueError:
        return _active_tools_nmap_basic_error("active_tools_invalid_response")

    return validate_active_tools_nmap_basic_response(payload, request_payload)


def validate_active_tools_nmap_basic_request(payload: Mapping[str, Any] | Any) -> dict[str, Any] | None:
    if not isinstance(payload, Mapping):
        return _active_tools_nmap_basic_error("active_tools_invalid_response")
    normalized_keys = {_normalize_key(key) for key in payload}
    if normalized_keys != ACTIVE_TOOLS_NMAP_BASIC_ALLOWED_REQUEST_FIELDS:
        return _active_tools_nmap_basic_error("active_tools_unexpected_fields")
    if any(_normalize_key(key) in ACTIVE_TOOLS_NMAP_BASIC_SENSITIVE_FIELDS for key in payload):
        return _active_tools_nmap_basic_error("active_tools_unexpected_fields")

    if payload.get("mode") != ACTIVE_TOOLS_NMAP_BASIC_MODE or payload.get("profile") != ACTIVE_TOOLS_NMAP_BASIC_PROFILE:
        return _active_tools_nmap_basic_error("active_tools_invalid_response")
    if payload.get("confirmations_verified_by_backend") is not True:
        return _active_tools_nmap_basic_error("active_tools_invalid_response")

    for key in ("request_id", "job_id", "correlation_id"):
        if not _is_safe_identifier(payload.get(key)):
            return _active_tools_nmap_basic_error("active_tools_invalid_response")

    target_unit = payload.get("target_unit")
    if not isinstance(target_unit, Mapping):
        return _active_tools_nmap_basic_error("active_tools_invalid_response")
    target_unit_keys = {_normalize_key(key) for key in target_unit}
    if target_unit_keys != ACTIVE_TOOLS_NMAP_BASIC_ALLOWED_TARGET_UNIT_FIELDS:
        return _active_tools_nmap_basic_error("active_tools_unexpected_fields")
    if any(_normalize_key(key) in ACTIVE_TOOLS_NMAP_BASIC_SENSITIVE_FIELDS for key in target_unit):
        return _active_tools_nmap_basic_error("active_tools_unexpected_fields")

    target = target_unit.get("target")
    if not isinstance(target, str) or not target or len(target) > 253 or any(char.isspace() for char in target):
        return _active_tools_nmap_basic_error("active_tools_invalid_response")
    if target_unit.get("target_kind") not in ACTIVE_TOOLS_NMAP_BASIC_ALLOWED_TARGET_KINDS:
        return _active_tools_nmap_basic_error("active_tools_invalid_response")
    accepted_ports = target_unit.get("accepted_ports")
    if not _is_port_list(accepted_ports):
        return _active_tools_nmap_basic_error("active_tools_invalid_response")

    limits = payload.get("limits")
    if not isinstance(limits, Mapping):
        return _active_tools_nmap_basic_error("active_tools_invalid_response")
    limit_keys = {_normalize_key(key) for key in limits}
    if limit_keys != ACTIVE_TOOLS_NMAP_BASIC_ALLOWED_LIMIT_FIELDS:
        return _active_tools_nmap_basic_error("active_tools_unexpected_fields")
    for value in limits.values():
        if not _is_positive_int(value):
            return _active_tools_nmap_basic_error("active_tools_invalid_response")

    return None


def validate_active_tools_nmap_basic_response(payload: Mapping[str, Any] | Any, request_payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        return _active_tools_nmap_basic_error("active_tools_invalid_response")

    normalized_keys = {_normalize_key(key) for key in payload}
    unexpected_fields = normalized_keys - ACTIVE_TOOLS_NMAP_BASIC_ALLOWED_RESPONSE_FIELDS
    sensitive_fields = normalized_keys & ACTIVE_TOOLS_NMAP_BASIC_SENSITIVE_FIELDS
    if unexpected_fields or sensitive_fields:
        return _active_tools_nmap_basic_error("active_tools_unexpected_fields")

    summary = payload.get("summary")
    if not isinstance(summary, Mapping):
        return _active_tools_nmap_basic_error("active_tools_invalid_response")
    summary_keys = {_normalize_key(key) for key in summary}
    if summary_keys - ACTIVE_TOOLS_NMAP_BASIC_ALLOWED_SUMMARY_FIELDS:
        return _active_tools_nmap_basic_error("active_tools_unexpected_fields")
    if summary_keys & ACTIVE_TOOLS_NMAP_BASIC_SENSITIVE_FIELDS:
        return _active_tools_nmap_basic_error("active_tools_unexpected_fields")

    request_target_unit = request_payload.get("target_unit")
    accepted_ports = request_target_unit.get("accepted_ports") if isinstance(request_target_unit, Mapping) else []
    expected_port_count = len(accepted_ports) if _is_port_list(accepted_ports) else None

    execution_enabled = payload.get("execution_enabled")
    target_input_allowed = payload.get("target_input_allowed", False)
    job_created = payload.get("job_created")
    target_expansion_performed = payload.get("target_expansion_performed")
    network_requests_sent = payload.get("network_requests_sent")
    nmap_executed = summary.get("nmap_executed")
    evidence_available = summary.get("evidence_available")
    observations = payload.get("observations")

    if payload.get("status") == "not_executed":
        if (
            payload.get("service") != "active-tools"
            or payload.get("capability") != "active_nmap_basic"
            or payload.get("mode") != ACTIVE_TOOLS_NMAP_BASIC_MODE
            or payload.get("profile") != ACTIVE_TOOLS_NMAP_BASIC_PROFILE
            or payload.get("manual_validation_required") is not True
            or execution_enabled is not False
            or target_input_allowed is not False
            or job_created is not False
            or target_expansion_performed is not False
            or network_requests_sent != 0
            or nmap_executed is not False
            or evidence_available is not False
            or observations != []
            or summary.get("target_count") != 1
            or summary.get("port_count") != expected_port_count
        ):
            return _active_tools_nmap_basic_error("active_tools_invalid_response")

        return {
            "available": True,
            "status": "not_executed",
            "service": "active-tools",
            "capability": "active_nmap_basic",
            "mode": ACTIVE_TOOLS_NMAP_BASIC_MODE,
            "profile": ACTIVE_TOOLS_NMAP_BASIC_PROFILE,
            "execution_enabled": False,
            "target_input_allowed": False,
            "manual_validation_required": True,
            "job_created": False,
            "target_expansion_performed": False,
            "network_requests_sent": 0,
            "nmap_executed": False,
            "evidence_available": False,
            "observations": [],
            "warnings": _controlled_nmap_basic_strings(payload.get("warnings")),
            "errors": _controlled_nmap_basic_strings(payload.get("errors")),
            "error_code": None,
        }

    boundary_payload = {
        "status": payload.get("status"),
        "profile": payload.get("profile"),
        "target_kind": payload.get("target_kind"),
        "manual_validation_required": payload.get("manual_validation_required"),
        "result_interpretation": payload.get("result_interpretation"),
        "observations": payload.get("observations"),
        "output_truncated": payload.get("output_truncated"),
        "execution_metadata": payload.get("execution_metadata"),
        "warnings": payload.get("warnings"),
        "errors": payload.get("errors"),
    }
    boundary_result = validate_active_nmap_basic_boundary_response(
        boundary_payload,
        accepted_ports=accepted_ports if _is_port_list(accepted_ports) else [],
        target_kind=payload.get("target_kind"),
    )
    if boundary_result.get("errors"):
        error_code = "active_tools_unexpected_fields" if "unexpected_fields" in boundary_result["errors"] else "active_tools_invalid_response"
        return _active_tools_nmap_basic_error(error_code, status=boundary_result.get("status"))

    if (
        payload.get("service") != "active-tools"
        or payload.get("status") not in ACTIVE_TOOLS_NMAP_BASIC_REAL_STATUSES
        or payload.get("capability") != "active_nmap_basic"
        or payload.get("mode") != ACTIVE_TOOLS_NMAP_BASIC_MODE
        or payload.get("profile") != ACTIVE_TOOLS_NMAP_BASIC_PROFILE
        or payload.get("manual_validation_required") is not True
        or execution_enabled is not True
        or target_input_allowed is not False
        or job_created is not False
        or target_expansion_performed is not False
        or not _is_non_negative_int(network_requests_sent)
        or not isinstance(nmap_executed, bool)
        or not isinstance(evidence_available, bool)
        or summary.get("target_count") != 1
        or summary.get("port_count") != expected_port_count
    ):
        return _active_tools_nmap_basic_error("active_tools_invalid_response")

    safe_observations = boundary_result["observations"]
    return {
        "available": True,
        "status": boundary_result["status"],
        "service": "active-tools",
        "capability": "active_nmap_basic",
        "mode": ACTIVE_TOOLS_NMAP_BASIC_MODE,
        "profile": ACTIVE_TOOLS_NMAP_BASIC_PROFILE,
        "target_kind": boundary_result.get("target_kind"),
        "execution_enabled": True,
        "target_input_allowed": False,
        "manual_validation_required": True,
        "job_created": False,
        "target_expansion_performed": False,
        "network_requests_sent": network_requests_sent,
        "nmap_executed": nmap_executed,
        "evidence_available": evidence_available,
        "observations": safe_observations,
        "output_truncated": boundary_result["output_truncated"],
        "execution_metadata": boundary_result["execution_metadata"],
        "result_interpretation": boundary_result["result_interpretation"],
        "warnings": boundary_result["warnings"],
        "errors": boundary_result["errors"],
        "error_code": None,
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
        or active_nmap_basic_status not in {"disabled_no_scan", "ready_bounded_execution"}
        or not isinstance(execution_enabled, bool)
        or not isinstance(target_input_allowed, bool)
    ):
        result["error_code"] = "active_tools_not_ready"
        return result
    if target_input_allowed:
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


def _active_tools_nmap_basic_error(
    error_code: str,
    *,
    status: str | None = None,
) -> dict[str, Any]:
    controlled_error = error_code if error_code in ACTIVE_TOOLS_NMAP_BASIC_ERROR_CODES else "active_tools_unexpected_fields"
    return {
        "available": False,
        "status": status or ACTIVE_TOOLS_NMAP_BASIC_ERROR_STATUS[controlled_error],
        "service": "active-tools",
        "capability": "active_nmap_basic",
        "mode": ACTIVE_TOOLS_NMAP_BASIC_MODE,
        "profile": ACTIVE_TOOLS_NMAP_BASIC_PROFILE,
        "execution_enabled": None,
        "target_input_allowed": None,
        "manual_validation_required": True,
        "job_created": False,
        "target_expansion_performed": False,
        "network_requests_sent": None,
        "nmap_executed": None,
        "evidence_available": None,
        "observations": [],
        "warnings": [],
        "errors": [controlled_error],
        "error_code": controlled_error,
    }


def _normalize_active_tools_base_url(base_url: str | None) -> str:
    if not isinstance(base_url, str):
        return ""
    candidate = base_url.strip().rstrip("/")
    if not candidate:
        return ""
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    if parsed.username or parsed.password or parsed.params or parsed.query or parsed.fragment:
        return ""
    if parsed.path not in {"", "/"}:
        return ""
    if not _is_internal_active_tools_host(parsed.hostname):
        return ""
    return candidate


def _is_internal_active_tools_host(hostname: str) -> bool:
    host = hostname.strip().lower().rstrip(".")
    if not host:
        return False
    if host in {"active-tools", "localhost"}:
        return True
    try:
        address = ip_address(host)
    except ValueError:
        return _is_internal_service_name(host)
    return address.is_loopback or address.is_private


def _is_internal_service_name(host: str) -> bool:
    if len(host) > 253:
        return False
    labels = host.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return False
    if any(not all(char.isalnum() or char == "-" for char in label) for label in labels):
        return False
    if len(labels) == 1:
        return False
    return host.endswith((".internal", ".local", ".localhost"))


def _safe_status(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _is_non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _is_port_list(value: Any) -> bool:
    if not isinstance(value, list) or not value or len(value) > ACTIVE_TOOLS_NMAP_BASIC_MAX_PORTS:
        return False
    return all(isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535 for port in value)


def _is_safe_identifier(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 128:
        return False
    return all(char.isalnum() or char in {"-", "_", ".", ":"} for char in value)


def _controlled_nmap_basic_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    allowed = {"no_scan_service_skeleton"}
    result: list[str] = []
    for item in value:
        if isinstance(item, str) and item in allowed:
            result.append(item)
    return result


def _normalize_key(value: Any) -> str:
    return str(value).lower().replace("-", "_")
