from __future__ import annotations

from ipaddress import ip_address
import json
import re
from typing import Any, Mapping

from active_runner.contracts import (
    ACTIVE_NMAP_BASIC_MAX_STDERR_BYTES,
    ACTIVE_NMAP_BASIC_MAX_STDOUT_BYTES,
    ACTIVE_NMAP_BASIC_PROCESS_TIMEOUT_SECONDS,
    ACTIVE_NMAP_BASIC_PROFILE,
)
from app.active_nmap_handoff import ACTIVE_NMAP_BASIC_MODE, ActiveNmapBasicHandoffUnit


ACTIVE_NMAP_BASIC_BOUNDARY_RESPONSE_MAX_BYTES = 32_768
ACTIVE_NMAP_BASIC_BOUNDARY_ALLOWED_STATUSES = {
    "completed",
    "failed",
    "timed_out",
    "nmap_missing",
    "malformed",
    "unsupported_shape",
    "blocked",
    "empty",
    "no_ports",
    "truncated",
}
ACTIVE_NMAP_BASIC_BOUNDARY_ALLOWED_RESPONSE_FIELDS = {
    "status",
    "profile",
    "target_kind",
    "manual_validation_required",
    "result_interpretation",
    "observations",
    "output_truncated",
    "execution_metadata",
    "warnings",
    "errors",
}
ACTIVE_NMAP_BASIC_BOUNDARY_SENSITIVE_FIELDS = {
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
    "service",
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
ACTIVE_NMAP_BASIC_BOUNDARY_CONTROLLED_ERROR_CODES = {
    "active_tools_unavailable",
    "active_tools_timeout",
    "nmap_missing",
    "malformed_output",
    "unsupported_shape",
    "policy_drift",
    "result_too_large",
    "unexpected_fields",
    "network_failure",
    "fqdn_resolution_failed",
    "malformed_xml",
    "nmap_nonzero_exit",
    "process_timeout",
    "unexpected_execution_error",
    "unexpected_port",
    "unsupported_xml_shape",
}
ACTIVE_NMAP_BASIC_BOUNDARY_ERROR_STATUS = {
    "active_tools_unavailable": "failed",
    "active_tools_timeout": "timed_out",
    "nmap_missing": "nmap_missing",
    "malformed_output": "malformed",
    "unsupported_shape": "unsupported_shape",
    "policy_drift": "blocked",
    "result_too_large": "failed",
    "unexpected_fields": "blocked",
    "network_failure": "failed",
    "fqdn_resolution_failed": "failed",
    "malformed_xml": "malformed",
    "nmap_nonzero_exit": "failed",
    "process_timeout": "timed_out",
    "unexpected_execution_error": "failed",
    "unexpected_port": "blocked",
    "unsupported_xml_shape": "unsupported_shape",
}
_SAFE_ID_RE = re.compile(r"[^a-zA-Z0-9_.:-]+")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def build_active_nmap_basic_boundary_request(
    unit: ActiveNmapBasicHandoffUnit,
    *,
    job_id: str,
    request_id: str,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    return {
        "mode": ACTIVE_NMAP_BASIC_MODE,
        "profile": ACTIVE_NMAP_BASIC_PROFILE,
        "request_id": _safe_boundary_id(request_id, default="request"),
        "job_id": _safe_boundary_id(job_id, default="job"),
        "correlation_id": _safe_boundary_id(correlation_id or f"active-nmap-basic-{unit.sequence_index}", default="correlation"),
        "target_unit": {
            "target": unit.target,
            "target_kind": _classify_target_kind(unit.target),
            "accepted_ports": list(unit.ports),
        },
        "confirmations_verified_by_backend": (
            unit.authorization_confirmed
            and unit.local_private_scope_confirmed
            and unit.live_traffic_confirmed
        ),
        "limits": {
            "process_timeout_seconds": ACTIVE_NMAP_BASIC_PROCESS_TIMEOUT_SECONDS,
            "stdout_max_bytes": ACTIVE_NMAP_BASIC_MAX_STDOUT_BYTES,
            "stderr_max_bytes": ACTIVE_NMAP_BASIC_MAX_STDERR_BYTES,
            "response_max_bytes": ACTIVE_NMAP_BASIC_BOUNDARY_RESPONSE_MAX_BYTES,
        },
    }


def validate_active_nmap_basic_boundary_response(
    response: Mapping[str, Any] | Any,
    *,
    accepted_ports: tuple[int, ...] | list[int],
    target_kind: str | None = None,
) -> dict[str, Any]:
    if not isinstance(response, Mapping):
        return map_active_nmap_basic_boundary_error("malformed_output")
    if _response_over_limit(response):
        return map_active_nmap_basic_boundary_error("result_too_large")

    normalized_keys = {_normalize_key(key) for key in response}
    unexpected_fields = normalized_keys - ACTIVE_NMAP_BASIC_BOUNDARY_ALLOWED_RESPONSE_FIELDS
    sensitive_fields = normalized_keys & ACTIVE_NMAP_BASIC_BOUNDARY_SENSITIVE_FIELDS
    if unexpected_fields or sensitive_fields or _contains_sensitive_field(response):
        return map_active_nmap_basic_boundary_error("unexpected_fields")

    status = response.get("status")
    if not isinstance(status, str) or status not in ACTIVE_NMAP_BASIC_BOUNDARY_ALLOWED_STATUSES:
        return map_active_nmap_basic_boundary_error("unexpected_fields")

    observations, observation_error = _safe_observations(response.get("observations"), accepted_ports=accepted_ports)
    if observation_error:
        return map_active_nmap_basic_boundary_error(observation_error)

    errors = _controlled_strings(response.get("errors"))
    warnings = _controlled_strings(response.get("warnings"))
    safe_target_kind = _safe_target_kind(response.get("target_kind") or target_kind)
    result: dict[str, Any] = {
        "status": status,
        "profile": ACTIVE_NMAP_BASIC_PROFILE,
        "manual_validation_required": True,
        "result_interpretation": "observed_exposure_review_indicator",
        "observations": observations,
        "output_truncated": bool(response.get("output_truncated")),
        "execution_metadata": _safe_execution_metadata(response.get("execution_metadata")),
        "warnings": warnings,
        "errors": errors,
    }
    if safe_target_kind:
        result["target_kind"] = safe_target_kind
    return result


def map_active_nmap_basic_boundary_error(error_code: str) -> dict[str, Any]:
    controlled_error = error_code if error_code in ACTIVE_NMAP_BASIC_BOUNDARY_CONTROLLED_ERROR_CODES else "unexpected_fields"
    return {
        "status": ACTIVE_NMAP_BASIC_BOUNDARY_ERROR_STATUS[controlled_error],
        "profile": ACTIVE_NMAP_BASIC_PROFILE,
        "manual_validation_required": True,
        "result_interpretation": "observed_exposure_review_indicator",
        "observations": [],
        "output_truncated": controlled_error == "result_too_large",
        "execution_metadata": {"executor": "active_nmap_basic_boundary"},
        "warnings": [],
        "errors": [controlled_error],
    }


def _safe_observations(value: Any, *, accepted_ports: tuple[int, ...] | list[int]) -> tuple[list[dict[str, Any]], str | None]:
    if value is None:
        return [], None
    if not isinstance(value, list):
        return [], "malformed_output"

    accepted = set(accepted_ports)
    observations: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            return [], "malformed_output"
        normalized_keys = {_normalize_key(key) for key in item}
        allowed = {"port", "protocol", "state", "reason", "manual_validation_required", "result_interpretation"}
        if normalized_keys - allowed or normalized_keys & ACTIVE_NMAP_BASIC_BOUNDARY_SENSITIVE_FIELDS:
            return [], "unexpected_fields"
        port = item.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or port not in accepted:
            return [], "policy_drift"
        protocol = item.get("protocol")
        if str(protocol).lower() != "tcp":
            return [], "unsupported_shape"
        state = item.get("state")
        if not isinstance(state, str) or not state:
            return [], "malformed_output"
        observation = {
            "port": port,
            "protocol": "tcp",
            "state": state,
            "manual_validation_required": True,
            "result_interpretation": "observed_exposure_review_indicator",
        }
        reason = item.get("reason")
        if isinstance(reason, str) and reason:
            observation["reason"] = reason
        observations.append(observation)
    return observations, None


def _safe_execution_metadata(value: Any) -> dict[str, Any]:
    metadata = {"executor": "active_nmap_basic_boundary"}
    if not isinstance(value, Mapping):
        return metadata
    executor = value.get("executor")
    if executor == "active_nmap_basic":
        metadata["executor"] = executor
    duration_ms = value.get("duration_ms")
    if isinstance(duration_ms, int) and not isinstance(duration_ms, bool) and duration_ms >= 0:
        metadata["duration_ms"] = min(duration_ms, 3_600_000)
    for key in ("nmap_invoked", "subprocess_invoked_inside_active_tools"):
        if isinstance(value.get(key), bool):
            metadata[key] = value[key]
    return metadata


def _response_over_limit(response: Mapping[str, Any]) -> bool:
    encoded = json.dumps(response, default=str, separators=(",", ":"))
    return len(encoded.encode("utf-8")) > ACTIVE_NMAP_BASIC_BOUNDARY_RESPONSE_MAX_BYTES


def _contains_sensitive_field(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if _normalize_key(key) in ACTIVE_NMAP_BASIC_BOUNDARY_SENSITIVE_FIELDS:
                return True
            if _contains_sensitive_field(nested):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_sensitive_field(item) for item in value)
    return False


def _controlled_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        if isinstance(item, str) and item in ACTIVE_NMAP_BASIC_BOUNDARY_CONTROLLED_ERROR_CODES:
            result.append(item)
    return result


def _safe_target_kind(value: Any) -> str:
    return value if isinstance(value, str) and value in {"authorized_fqdn", "container_loopback", "private_ip", "private_hostname"} else ""


def _classify_target_kind(target: str) -> str:
    try:
        parsed = ip_address(target)
    except ValueError:
        return "private_hostname"
    if parsed.is_loopback:
        return "container_loopback"
    return "private_ip"


def _safe_boundary_id(value: str, *, default: str) -> str:
    if not isinstance(value, str) or not value:
        return default
    safe = _SAFE_ID_RE.sub("-", value)[:96].strip("-")
    safe = _IPV4_RE.sub("redacted-ip", safe)
    return safe or default


def _normalize_key(value: Any) -> str:
    return str(value).lower().replace("-", "_")
