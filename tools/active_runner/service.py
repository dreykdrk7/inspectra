from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from active_runner.contracts import (
    ACTIVE_NMAP_BASIC_CAPABILITY,
    ACTIVE_NMAP_BASIC_MAX_PORTS,
    ACTIVE_NMAP_BASIC_MODE,
    ACTIVE_NMAP_BASIC_PROFILE,
)
from active_runner.nmap_basic.executor import execute_active_nmap_basic
from active_runner.nmap_basic.parser import parse_active_nmap_basic_xml
from active_runner.nmap_basic.result import build_active_nmap_basic_result_payload


ACTIVE_TOOLS_SERVICE_NAME = "active-tools"
ACTIVE_TOOLS_HEALTH_PATH = "/health"
ACTIVE_TOOLS_NMAP_BASIC_PATH = "/active/nmap-basic"
ACTIVE_TOOLS_NO_SCAN_REASON = "active_tools_internal_service_skeleton_no_scan"
ACTIVE_TOOLS_FAKE_EXECUTOR_NAME = "active_tools_fake_executor"
_SAFE_RESULT_INTERPRETATION = "observed_exposure_review_indicator"

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
        "hostname",
        "local_path",
        "local_paths",
        "nse",
        "nse_output",
        "ptr_hostname",
        "ptr_hostnames",
        "raw_args",
        "raw_command",
        "raw_flags",
        "raw_xml",
        "resolved_ip",
        "resolved_ips",
        "script",
        "script_args",
        "script_output",
        "scripts",
        "service",
        "service_banner",
        "shell",
        "shell_command",
        "stderr",
        "stdout",
        "target_file",
        "target_files",
        "token",
        "tokens",
        "version",
        "xml",
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
_ALLOWED_FAKE_RESPONSE_FIELDS = frozenset(
    {
        "errors",
        "execution_metadata",
        "manual_validation_required",
        "observations",
        "output_truncated",
        "profile",
        "result_interpretation",
        "status",
        "target_kind",
        "warnings",
    }
)
_ALLOWED_FAKE_OBSERVATION_FIELDS = frozenset(
    {
        "manual_validation_required",
        "port",
        "protocol",
        "reason",
        "result_interpretation",
        "state",
    }
)
_ALLOWED_FAKE_EXECUTION_METADATA_FIELDS = frozenset({"duration_ms", "executor", "nmap_executed"})
_ALLOWED_FAKE_STATUSES = frozenset(
    {"completed", "failed", "timed_out", "nmap_missing", "malformed", "unsupported_shape", "blocked"}
)
_ALLOWED_TARGET_KINDS = frozenset(
    {"authorized_fqdn", "container_loopback", "private_ip", "private_hostname"}
)
_CONTROLLED_FAKE_ERROR_CODES = frozenset(
    {
        "fake_executor_exception",
        "malformed",
        "malformed_xml",
        "nmap_missing",
        "nmap_nonzero_exit",
        "policy_drift",
        "process_timeout",
        "timed_out",
        "unexpected_execution_error",
        "unexpected_fields",
        "unexpected_port",
        "unsupported_shape",
        "unsupported_xml_shape",
    }
)
_CONTROLLED_FAKE_ERROR_STATUS = {
    "fake_executor_exception": "failed",
    "malformed": "malformed",
    "malformed_xml": "malformed",
    "nmap_missing": "nmap_missing",
    "nmap_nonzero_exit": "failed",
    "policy_drift": "blocked",
    "process_timeout": "timed_out",
    "timed_out": "timed_out",
    "unexpected_execution_error": "failed",
    "unexpected_fields": "blocked",
    "unexpected_port": "blocked",
    "unsupported_shape": "unsupported_shape",
    "unsupported_xml_shape": "unsupported_shape",
}

ActiveToolsFakeExecutor = Callable[[Mapping[str, Any]], Mapping[str, Any]]
ActiveToolsNmapRunner = Callable[..., Any]


def active_tools_capability_metadata(*, active_nmap_basic_execution_enabled: bool = False) -> dict[str, Any]:
    return {
        ACTIVE_NMAP_BASIC_CAPABILITY: {
            "status": "ready_bounded_execution" if active_nmap_basic_execution_enabled else "disabled_no_scan",
            "execution_enabled": active_nmap_basic_execution_enabled,
            "target_input_allowed": False,
        }
    }


def handle_active_tools_health(
    payload: Mapping[str, Any] | None = None,
    *,
    active_nmap_basic_execution_enabled: bool = False,
) -> dict[str, Any]:
    if payload is not None:
        if not isinstance(payload, Mapping):
            return _blocked_health_response("health_payload_not_mapping")
        if payload:
            return _blocked_health_response("health_payload_not_accepted")
    return {
        "service": ACTIVE_TOOLS_SERVICE_NAME,
        "status": "scaffold_ready",
        "capabilities": active_tools_capability_metadata(
            active_nmap_basic_execution_enabled=active_nmap_basic_execution_enabled
        ),
        "network_requests_sent": 0,
        "nmap_executed": False,
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


def handle_active_nmap_basic_real(
    payload: Mapping[str, Any] | None,
    *,
    runner: ActiveToolsNmapRunner | None = None,
) -> dict[str, Any]:
    validation = _validate_active_nmap_basic_boundary_payload(payload)
    if validation.get("error"):
        return _blocked_response(validation["error"])

    accepted_ports = validation["accepted_ports"]
    target_kind = validation["target_kind"]
    assert isinstance(payload, Mapping)
    target_unit = payload["target_unit"]
    assert isinstance(target_unit, Mapping)
    limits = _safe_limits(payload.get("limits"))
    execution_result = execute_active_nmap_basic(
        {
            "mode": ACTIVE_NMAP_BASIC_MODE,
            "profile": ACTIVE_NMAP_BASIC_PROFILE,
            "target": target_unit["target"],
            "ports": list(accepted_ports),
            "authorization_confirmed": True,
            "local_private_scope_confirmed": True,
            "live_traffic_confirmed": True,
        },
        runner=runner,
        timeout_seconds=limits.get("process_timeout_seconds", 35),
        max_stdout_bytes=limits.get("stdout_max_bytes", 131072),
        max_stderr_bytes=limits.get("stderr_max_bytes", 16384),
    )
    parse_result = None
    if execution_result.get("status") == "completed":
        parse_result = parse_active_nmap_basic_xml(
            execution_result.get("stdout"),
            accepted_ports=accepted_ports,
            target_kind=target_kind,
        )
    result_payload = build_active_nmap_basic_result_payload(execution_result, parse_result)
    return _real_execution_response(
        result_payload,
        execution_result,
        accepted_ports=accepted_ports,
        target_kind=target_kind,
    )


def handle_active_nmap_basic_no_scan(
    payload: Mapping[str, Any] | None,
    *,
    executor: ActiveToolsFakeExecutor | None = None,
) -> dict[str, Any]:
    validation = _validate_active_nmap_basic_boundary_payload(payload)
    if validation.get("error"):
        return _blocked_response(validation["error"])

    accepted_ports = validation["accepted_ports"]
    port_count = len(accepted_ports)

    if executor is None:
        return _not_executed_response(port_count)

    try:
        fake_response = executor(
            _fake_executor_request(payload, accepted_ports=accepted_ports, target_kind=validation["target_kind"])
        )
    except Exception:
        return _controlled_fake_response("fake_executor_exception")
    return _validated_fake_executor_response(
        fake_response,
        accepted_ports=accepted_ports,
        target_kind=validation["target_kind"],
        port_count=port_count,
    )


def _not_executed_response(port_count: int) -> dict[str, Any]:
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


def _real_execution_response(
    result_payload: Mapping[str, Any],
    execution_result: Mapping[str, Any],
    *,
    accepted_ports: tuple[int, ...],
    target_kind: str,
) -> dict[str, Any]:
    status = _safe_real_status(result_payload.get("status"))
    observations = _safe_real_observations(result_payload.get("port_observations"), accepted_ports=accepted_ports)
    limits = result_payload.get("limits")
    if not isinstance(limits, Mapping):
        limits = {}
    execution_attempted = execution_result.get("execution_attempted") is True
    nmap_executed = execution_attempted and status != "nmap_missing"
    network_requests_sent = len(accepted_ports) if nmap_executed else 0
    errors = _controlled_strings(result_payload.get("errors"))
    warnings = _controlled_strings(result_payload.get("parser_warnings"))
    return {
        "service": ACTIVE_TOOLS_SERVICE_NAME,
        "status": status,
        "capability": ACTIVE_NMAP_BASIC_CAPABILITY,
        "mode": ACTIVE_NMAP_BASIC_MODE,
        "profile": ACTIVE_NMAP_BASIC_PROFILE,
        "target_kind": target_kind,
        "execution_enabled": True,
        "target_input_allowed": False,
        "manual_validation_required": True,
        "result_interpretation": _SAFE_RESULT_INTERPRETATION,
        "observations": observations,
        "output_truncated": bool(limits.get("output_truncated")),
        "job_created": False,
        "target_expansion_performed": False,
        "network_requests_sent": network_requests_sent,
        "execution_metadata": {
            "executor": "active_nmap_basic",
            "nmap_invoked": nmap_executed,
            "subprocess_invoked_inside_active_tools": execution_attempted,
        },
        "summary": {
            "target_count": 1,
            "port_count": len(accepted_ports),
            "nmap_executed": nmap_executed,
            "evidence_available": bool(observations),
        },
        "warnings": warnings,
        "errors": errors,
    }


def _validate_active_nmap_basic_boundary_payload(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        return {"error": "request_not_mapping"}

    dangerous_field = _first_dangerous_field(payload)
    if dangerous_field:
        return {"error": "unsupported_request_field"}

    unknown_fields = {_normalize_key(key) for key in payload} - _ALLOWED_BOUNDARY_FIELDS
    if "targets" in unknown_fields:
        return {"error": "multiple_targets_not_supported"}
    if unknown_fields:
        return {"error": "unknown_request_field"}

    if payload.get("mode") != ACTIVE_NMAP_BASIC_MODE:
        return {"error": "unsupported_mode"}
    if payload.get("profile") != ACTIVE_NMAP_BASIC_PROFILE:
        return {"error": "unsupported_profile"}
    if payload.get("confirmations_verified_by_backend") is not True:
        return {"error": "backend_confirmations_missing"}

    target_unit = payload.get("target_unit")
    if not isinstance(target_unit, Mapping):
        return {"error": "target_unit_missing"}

    target_unit_keys = {_normalize_key(key) for key in target_unit}
    if target_unit_keys - _ALLOWED_TARGET_UNIT_FIELDS:
        return {"error": "unsupported_target_unit_field"}

    target = target_unit.get("target")
    if not isinstance(target, str) or not target:
        return {"error": "target_missing"}
    if _target_looks_like_range(target):
        return {"error": "target_range_rejected"}

    target_kind = target_unit.get("target_kind")
    if not isinstance(target_kind, str) or target_kind not in _ALLOWED_TARGET_KINDS:
        return {"error": "unsupported_target_kind"}

    accepted_ports = _validated_ports(target_unit.get("accepted_ports"))
    if accepted_ports is None:
        return {"error": "accepted_ports_invalid"}
    return {"accepted_ports": accepted_ports, "target_kind": target_kind}


def _fake_executor_request(
    payload: Mapping[str, Any] | None, *, accepted_ports: tuple[int, ...], target_kind: str
) -> dict[str, Any]:
    assert isinstance(payload, Mapping)
    target_unit = payload["target_unit"]
    assert isinstance(target_unit, Mapping)
    return {
        "mode": ACTIVE_NMAP_BASIC_MODE,
        "profile": ACTIVE_NMAP_BASIC_PROFILE,
        "request_id": _safe_string(payload.get("request_id")),
        "job_id": _safe_string(payload.get("job_id")),
        "correlation_id": _safe_string(payload.get("correlation_id")),
        "confirmations_verified_by_backend": True,
        "target_unit": {
            "target": target_unit["target"],
            "target_kind": target_kind,
            "accepted_ports": list(accepted_ports),
        },
        "limits": _safe_limits(payload.get("limits")),
    }


def _validated_fake_executor_response(
    response: Mapping[str, Any] | Any,
    *,
    accepted_ports: tuple[int, ...],
    target_kind: str,
    port_count: int,
) -> dict[str, Any]:
    if not isinstance(response, Mapping):
        return _controlled_fake_response("malformed")

    normalized_keys = {_normalize_key(key) for key in response}
    if (normalized_keys - _ALLOWED_FAKE_RESPONSE_FIELDS) or _first_dangerous_field(response):
        return _controlled_fake_response("unexpected_fields")

    status = response.get("status")
    if not isinstance(status, str) or status not in _ALLOWED_FAKE_STATUSES:
        return _controlled_fake_response("malformed")
    if response.get("profile") != ACTIVE_NMAP_BASIC_PROFILE:
        return _controlled_fake_response("unsupported_shape")
    if response.get("manual_validation_required") is not True:
        return _controlled_fake_response("unsupported_shape")
    if response.get("result_interpretation") != _SAFE_RESULT_INTERPRETATION:
        return _controlled_fake_response("unsupported_shape")

    response_target_kind = response.get("target_kind") or target_kind
    if not isinstance(response_target_kind, str) or response_target_kind not in _ALLOWED_TARGET_KINDS:
        return _controlled_fake_response("unsupported_shape")
    if not _fake_execution_metadata_shape_is_safe(response.get("execution_metadata")):
        return _controlled_fake_response("unexpected_fields")

    observations, observation_error = _validated_fake_observations(
        response.get("observations"), accepted_ports=accepted_ports
    )
    if observation_error:
        return _controlled_fake_response(observation_error)

    errors = _controlled_strings(response.get("errors"))
    warnings = _controlled_strings(response.get("warnings"))
    return {
        "service": ACTIVE_TOOLS_SERVICE_NAME,
        "status": status,
        "capability": ACTIVE_NMAP_BASIC_CAPABILITY,
        "mode": ACTIVE_NMAP_BASIC_MODE,
        "profile": ACTIVE_NMAP_BASIC_PROFILE,
        "target_kind": response_target_kind,
        "execution_enabled": False,
        "manual_validation_required": True,
        "result_interpretation": _SAFE_RESULT_INTERPRETATION,
        "observations": observations,
        "output_truncated": bool(response.get("output_truncated")),
        "job_created": False,
        "target_expansion_performed": False,
        "network_requests_sent": 0,
        "execution_metadata": _safe_execution_metadata(response.get("execution_metadata")),
        "summary": {
            "target_count": 1,
            "port_count": port_count,
            "nmap_executed": False,
            "fake_executor": True,
            "evidence_available": bool(observations),
        },
        "warnings": warnings,
        "errors": errors,
    }


def _validated_fake_observations(
    value: Any, *, accepted_ports: tuple[int, ...]
) -> tuple[list[dict[str, Any]], str | None]:
    if value is None:
        return [], None
    if not isinstance(value, list):
        return [], "malformed"

    observations: list[dict[str, Any]] = []
    accepted = set(accepted_ports)
    for item in value:
        if not isinstance(item, Mapping):
            return [], "malformed"
        normalized_keys = {_normalize_key(key) for key in item}
        if (normalized_keys - _ALLOWED_FAKE_OBSERVATION_FIELDS) or (normalized_keys & _DANGEROUS_REQUEST_FIELDS):
            return [], "unexpected_fields"
        port = item.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or port not in accepted:
            return [], "policy_drift"
        if str(item.get("protocol")).lower() != "tcp":
            return [], "unsupported_shape"
        if item.get("manual_validation_required") is not True:
            return [], "unsupported_shape"
        if item.get("result_interpretation") != _SAFE_RESULT_INTERPRETATION:
            return [], "unsupported_shape"
        state = item.get("state")
        if not isinstance(state, str) or not state:
            return [], "malformed"
        observation = {
            "port": port,
            "protocol": "tcp",
            "state": state,
            "manual_validation_required": True,
            "result_interpretation": _SAFE_RESULT_INTERPRETATION,
        }
        reason = item.get("reason")
        if isinstance(reason, str) and reason:
            observation["reason"] = reason
        observations.append(observation)
    return observations, None


def _safe_real_observations(value: Any, *, accepted_ports: tuple[int, ...]) -> list[dict[str, Any]]:
    observations, error = _validated_fake_observations(value, accepted_ports=accepted_ports)
    return [] if error else observations


def _safe_real_status(value: Any) -> str:
    if value in {
        "completed",
        "failed",
        "timed_out",
        "nmap_missing",
        "malformed",
        "unsupported_shape",
        "blocked",
        "truncated",
        "no_ports",
        "empty",
    }:
        return value
    return "malformed"


def _controlled_fake_response(reason: str) -> dict[str, Any]:
    controlled_reason = reason if reason in _CONTROLLED_FAKE_ERROR_CODES else "unexpected_fields"
    return {
        "service": ACTIVE_TOOLS_SERVICE_NAME,
        "status": _CONTROLLED_FAKE_ERROR_STATUS[controlled_reason],
        "capability": ACTIVE_NMAP_BASIC_CAPABILITY,
        "mode": ACTIVE_NMAP_BASIC_MODE,
        "profile": ACTIVE_NMAP_BASIC_PROFILE,
        "execution_enabled": False,
        "manual_validation_required": True,
        "result_interpretation": _SAFE_RESULT_INTERPRETATION,
        "observations": [],
        "output_truncated": False,
        "job_created": False,
        "target_expansion_performed": False,
        "network_requests_sent": 0,
        "execution_metadata": {"executor": ACTIVE_TOOLS_FAKE_EXECUTOR_NAME},
        "summary": {
            "target_count": 0,
            "port_count": 0,
            "nmap_executed": False,
            "fake_executor": True,
            "evidence_available": False,
        },
        "warnings": [],
        "errors": [controlled_reason],
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


def _blocked_health_response(reason: str) -> dict[str, Any]:
    return {
        "service": ACTIVE_TOOLS_SERVICE_NAME,
        "status": "blocked_no_live_service",
        "capabilities": active_tools_capability_metadata(),
        "execution_enabled": False,
        "network_requests_sent": 0,
        "nmap_executed": False,
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


def _safe_string(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return "".join(character if character.isalnum() or character in "_.:-" else "-" for character in value)[
        :96
    ].strip("-")


def _safe_limits(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    safe: dict[str, int] = {}
    for key in (
        "process_timeout_seconds",
        "stdout_max_bytes",
        "stderr_max_bytes",
        "response_max_bytes",
    ):
        item = value.get(key)
        if isinstance(item, int) and not isinstance(item, bool) and item >= 0:
            safe[key] = item
    return safe


def _safe_execution_metadata(value: Any) -> dict[str, Any]:
    metadata: dict[str, Any] = {"executor": ACTIVE_TOOLS_FAKE_EXECUTOR_NAME}
    if not isinstance(value, Mapping):
        return metadata
    if value.get("executor") == ACTIVE_TOOLS_FAKE_EXECUTOR_NAME:
        metadata["executor"] = ACTIVE_TOOLS_FAKE_EXECUTOR_NAME
    duration_ms = value.get("duration_ms")
    if isinstance(duration_ms, int) and not isinstance(duration_ms, bool) and duration_ms >= 0:
        metadata["duration_ms"] = min(duration_ms, 3_600_000)
    if value.get("nmap_executed") is False:
        metadata["nmap_executed"] = False
    return metadata


def _fake_execution_metadata_shape_is_safe(value: Any) -> bool:
    if value is None:
        return True
    if not isinstance(value, Mapping):
        return False
    normalized_keys = {_normalize_key(key) for key in value}
    return not (normalized_keys - _ALLOWED_FAKE_EXECUTION_METADATA_FIELDS) and not _first_dangerous_field(
        value
    )


def _controlled_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    allowed = _CONTROLLED_FAKE_ERROR_CODES | _ALLOWED_FAKE_STATUSES | frozenset({"synthetic_fake_completed"})
    return [item for item in value if isinstance(item, str) and item in allowed]


def _validated_ports(value: Any) -> tuple[int, ...] | None:
    if not isinstance(value, list) or not value:
        return None
    normalized: set[int] = set()
    for port in value:
        if isinstance(port, bool) or not isinstance(port, int) or port < 1 or port > 65535:
            return None
        normalized.add(port)
    if not normalized or len(normalized) > ACTIVE_NMAP_BASIC_MAX_PORTS:
        return None
    return tuple(sorted(normalized))


def _validated_port_count(value: Any) -> int | None:
    normalized = _validated_ports(value)
    if normalized is None:
        return None
    return len(normalized)


def _target_looks_like_range(target: str) -> bool:
    return any(marker in target for marker in ("/", "*", ",")) or ".." in target


def _normalize_key(value: Any) -> str:
    return str(value).lower().replace("-", "_")


def response_contains_sensitive_terms(response: Mapping[str, Any]) -> bool:
    body = repr(response).lower()
    return any(term in body for term in _SENSITIVE_RESPONSE_TERMS)
