from __future__ import annotations

from typing import Any, Mapping, TypeAlias

from active_runner.contracts import ACTIVE_NMAP_BASIC_CAPABILITY, ACTIVE_NMAP_BASIC_PROFILE


ActiveNmapBasicResultPayload: TypeAlias = dict[str, Any]

_RESULT_INTERPRETATION = "observed_exposure_review_indicator"
_ALLOWED_TARGET_KINDS = {"authorized_fqdn", "container_loopback"}


def build_active_nmap_basic_result_payload(
    execution_result: Mapping[str, Any],
    parse_result: Mapping[str, Any] | None,
) -> ActiveNmapBasicResultPayload:
    parser_ran = parse_result is not None
    execution_status = _string_value(execution_result.get("status"), "failed")
    parse_status = _string_value(parse_result.get("status"), "malformed") if parse_result is not None else None
    status = parse_status if execution_status == "completed" and parse_status is not None else execution_status
    port_observations = _safe_port_observations(parse_result.get("port_observations") if parse_result else None)
    warnings = _string_list(parse_result.get("parser_warnings") if parse_result else None)
    errors = _controlled_errors(execution_result, parse_result)
    output_truncated = bool(execution_result.get("output_truncated")) or bool(parse_result and parse_result.get("output_truncated"))
    stderr_truncated = bool(execution_result.get("stderr_truncated"))
    timed_out = bool(execution_result.get("timed_out")) or execution_status == "timed_out"
    observation_count = len(port_observations)

    return {
        "audit_type": ACTIVE_NMAP_BASIC_CAPABILITY,
        "capability": ACTIVE_NMAP_BASIC_CAPABILITY,
        "mode": "live_nmap_basic",
        "profile": ACTIVE_NMAP_BASIC_PROFILE,
        "status": status,
        "target_kind": _safe_target_kind(parse_result.get("target_kind") if parse_result else None),
        "execution_attempted": bool(execution_result.get("execution_attempted")),
        "parser_ran": parser_ran,
        "findings_created": False,
        "raw_xml_returned": False,
        "command_returned": False,
        "target_returned": False,
        "stdout_returned": False,
        "stderr_returned": False,
        "manual_validation_required": True,
        "result_interpretation": _RESULT_INTERPRETATION,
        "port_observations": port_observations,
        "observation_count": observation_count,
        "parser_warnings": warnings,
        "errors": errors,
        "limits": {
            "output_truncated": output_truncated,
            "stderr_truncated": stderr_truncated,
            "timed_out": timed_out,
        },
        "summary": {
            "observation_count": observation_count,
            "open_tcp_observations_count": sum(
                1
                for observation in port_observations
                if observation.get("protocol") == "tcp" and observation.get("state") == "open"
            ),
        },
    }


def _safe_port_observations(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    observations: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        port = item.get("port")
        protocol = str(item.get("protocol", "")).lower()
        state = str(item.get("state", "")).lower()
        if isinstance(port, bool) or not isinstance(port, int) or port < 1 or port > 65535:
            continue
        if protocol != "tcp":
            continue
        observation: dict[str, Any] = {
            "port": port,
            "protocol": "tcp",
            "state": state or "unknown",
            "manual_validation_required": True,
            "result_interpretation": _RESULT_INTERPRETATION,
        }
        reason = item.get("reason")
        if isinstance(reason, str) and reason:
            observation["reason"] = reason
        observations.append(observation)
    return observations


def _controlled_errors(execution_result: Mapping[str, Any], parse_result: Mapping[str, Any] | None) -> list[str]:
    errors: list[str] = []
    reason = execution_result.get("reason")
    if isinstance(reason, str) and reason and reason not in {"raw_bounded"}:
        errors.append(reason)
    parse_error = parse_result.get("parse_error") if parse_result else None
    if isinstance(parse_error, str) and parse_error:
        errors.append(parse_error)
    return errors


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _string_value(value: Any, default: str) -> str:
    return value if isinstance(value, str) and value else default


def _safe_target_kind(value: Any) -> str | None:
    return value if isinstance(value, str) and value in _ALLOWED_TARGET_KINDS else None
