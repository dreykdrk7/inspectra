from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from active_runner.contracts import (
    ACTIVE_NMAP_BASIC_CAPABILITY,
    ACTIVE_NMAP_BASIC_MAX_PORTS,
    ACTIVE_NMAP_BASIC_MODE,
    ACTIVE_NMAP_BASIC_PROFILE,
)


ACTIVE_TOOLS_SERVICE_NAME = "active-tools"
ACTIVE_TOOLS_HEALTH_PATH = "/health"
ACTIVE_TOOLS_NMAP_BASIC_PATH = "/active/nmap-basic"
ACTIVE_TOOLS_NO_SCAN_REASON = "active_tools_internal_service_skeleton_no_scan"

_ALLOWED_BOUNDARY_FIELDS = frozenset(
    {
        "confirmations_verified_by_backend",
        "correlation_id",
        "job_id",
        "limits",
        "mode",
        "profile",
        "request_id",
        "target_unit",
    }
)
_ALLOWED_TARGET_UNIT_FIELDS = frozenset({"accepted_ports", "target", "target_kind"})
_DANGEROUS_REQUEST_FIELDS = frozenset(
    {
        "args",
        "argv",
        "command",
        "cookie",
        "cookies",
        "credential",
        "credentials",
        "custom_profile",
        "env",
        "environment",
        "extra_args",
        "flag",
        "flags",
        "header",
        "headers",
        "nse",
        "nse_output",
        "raw_args",
        "raw_command",
        "raw_flags",
        "script",
        "script_args",
        "script_output",
        "scripts",
        "shell",
        "shell_command",
        "stderr",
        "stdout",
        "target_file",
        "target_files",
        "token",
        "tokens",
    }
)
_SENSITIVE_RESPONSE_TERMS = (
    "raw_xml",
    "stdout",
    "stderr",
    "command",
    "ptr_hostname",
    "resolved_ip",
    "script_output",
    "credentials",
    "cookies",
    "tokens",
    "headers",
)


def handle_active_tools_health(payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if payload and any(_normalize_key(key) in {"target", "targets", "target_unit"} for key in payload):
        return _blocked_response("health_target_not_accepted")
    return {
        "service": ACTIVE_TOOLS_SERVICE_NAME,
        "status": "scaffold_ready",
        "network_requests_sent": 0,
        "nmap_executed": False,
        "target_required": False,
        "capabilities": {
            ACTIVE_NMAP_BASIC_CAPABILITY: {
                "status": "disabled_no_scan",
                "execution_enabled": False,
                "endpoint": ACTIVE_TOOLS_NMAP_BASIC_PATH,
            }
        },
    }


def handle_active_tools_request(method: str, path: str, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
    normalized_method = method.upper()
    if normalized_method == "GET" and path == ACTIVE_TOOLS_HEALTH_PATH:
        return handle_active_tools_health(payload)
    if normalized_method == "POST" and path == ACTIVE_TOOLS_NMAP_BASIC_PATH:
        return handle_active_nmap_basic_no_scan(payload)
    if path in {ACTIVE_TOOLS_HEALTH_PATH, ACTIVE_TOOLS_NMAP_BASIC_PATH}:
        return _blocked_response("method_not_allowed")
    return _blocked_response("not_found")


def handle_active_nmap_basic_no_scan(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        return _blocked_response("request_not_mapping")

    dangerous_field = _first_dangerous_field(payload)
    if dangerous_field:
        return _blocked_response("unsupported_request_field")

    unknown_fields = {_normalize_key(key) for key in payload} - _ALLOWED_BOUNDARY_FIELDS
    if "targets" in unknown_fields:
        return _blocked_response("multiple_targets_not_supported")
    if unknown_fields:
        return _blocked_response("unknown_request_field")

    if payload.get("mode") != ACTIVE_NMAP_BASIC_MODE:
        return _blocked_response("unsupported_mode")
    if payload.get("profile") != ACTIVE_NMAP_BASIC_PROFILE:
        return _blocked_response("unsupported_profile")
    if payload.get("confirmations_verified_by_backend") is not True:
        return _blocked_response("backend_confirmations_missing")

    target_unit = payload.get("target_unit")
    if not isinstance(target_unit, Mapping):
        return _blocked_response("target_unit_missing")

    target_unit_keys = {_normalize_key(key) for key in target_unit}
    if target_unit_keys - _ALLOWED_TARGET_UNIT_FIELDS:
        return _blocked_response("unsupported_target_unit_field")

    target = target_unit.get("target")
    if not isinstance(target, str) or not target:
        return _blocked_response("target_missing")
    if _target_looks_like_range(target):
        return _blocked_response("target_range_rejected")

    accepted_ports = target_unit.get("accepted_ports")
    port_count = _validated_port_count(accepted_ports)
    if port_count is None:
        return _blocked_response("accepted_ports_invalid")

    return {
        "service": ACTIVE_TOOLS_SERVICE_NAME,
        "status": "not_executed",
        "capability": ACTIVE_NMAP_BASIC_CAPABILITY,
        "mode": ACTIVE_NMAP_BASIC_MODE,
        "profile": ACTIVE_NMAP_BASIC_PROFILE,
        "execution_enabled": False,
        "manual_validation_required": True,
        "reason": ACTIVE_TOOLS_NO_SCAN_REASON,
        "observations": [],
        "job_created": False,
        "target_expansion_performed": False,
        "network_requests_sent": 0,
        "summary": {
            "target_count": 1,
            "port_count": port_count,
            "nmap_executed": False,
            "evidence_available": False,
        },
        "warnings": ["no_scan_service_skeleton"],
        "errors": [],
    }


def _blocked_response(reason: str) -> dict[str, Any]:
    return {
        "service": ACTIVE_TOOLS_SERVICE_NAME,
        "status": "blocked_no_live_service",
        "capability": ACTIVE_NMAP_BASIC_CAPABILITY,
        "execution_enabled": False,
        "manual_validation_required": True,
        "reason": reason,
        "observations": [],
        "job_created": False,
        "target_expansion_performed": False,
        "network_requests_sent": 0,
        "summary": {
            "target_count": 0,
            "port_count": 0,
            "nmap_executed": False,
            "evidence_available": False,
        },
        "warnings": [],
        "errors": [reason],
    }


def _first_dangerous_field(value: Any) -> str:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized_key = _normalize_key(key)
            if normalized_key in _DANGEROUS_REQUEST_FIELDS:
                return normalized_key
            nested = _first_dangerous_field(item)
            if nested:
                return nested
    if isinstance(value, list):
        for item in value:
            nested = _first_dangerous_field(item)
            if nested:
                return nested
    return ""


def _validated_port_count(value: Any) -> int | None:
    if not isinstance(value, list) or not value:
        return None
    normalized: set[int] = set()
    for port in value:
        if isinstance(port, bool) or not isinstance(port, int) or port < 1 or port > 65535:
            return None
        normalized.add(port)
    if not normalized or len(normalized) > ACTIVE_NMAP_BASIC_MAX_PORTS:
        return None
    return len(normalized)


def _target_looks_like_range(target: str) -> bool:
    return any(marker in target for marker in ("/", "*", ",")) or ".." in target


def _normalize_key(value: Any) -> str:
    return str(value).lower().replace("-", "_")


def response_contains_sensitive_terms(response: Mapping[str, Any]) -> bool:
    body = repr(response).lower()
    return any(term in body for term in _SENSITIVE_RESPONSE_TERMS)
