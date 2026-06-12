from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, TypeAlias

from active_runner.contracts import (
    ACTIVE_NMAP_BASIC_CAPABILITY,
    ACTIVE_NMAP_BASIC_HOST_TIMEOUT_SECONDS,
    ACTIVE_NMAP_BASIC_MAX_PORTS,
    ACTIVE_NMAP_BASIC_MAX_RETRIES,
    ACTIVE_NMAP_BASIC_MODE,
    ACTIVE_NMAP_BASIC_NOT_EXECUTED_REASON,
    ACTIVE_NMAP_BASIC_PROFILE,
    ActiveNmapBasicCommandError,
)

from .command_builder import build_active_nmap_basic_argv


ActiveNmapBasicSkeletonResult: TypeAlias = dict[str, Any]

UNSUPPORTED_NMAP_BASIC_SERVICE_FIELDS = frozenset(
    {
        "args",
        "binary",
        "command",
        "cookies",
        "credentials",
        "custom_profile",
        "env",
        "environment",
        "executable",
        "extra_args",
        "flags",
        "headers",
        "path",
        "raw_flags",
        "script",
        "script_args",
        "scripts",
        "shell",
        "shell_command",
        "stderr",
        "stdin",
        "stdout",
        "target_file",
        "target_files",
        "tokens",
    }
)
_ALLOWED_NMAP_BASIC_SERVICE_FIELDS = frozenset(
    {
        "authorization_confirmed",
        "live_traffic_confirmed",
        "local_private_scope_confirmed",
        "mode",
        "ports",
        "profile",
        "target",
    }
)


class ActiveNmapBasicServiceError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class ActiveNmapBasicServiceRequest:
    target: str
    ports: object
    mode: str = ACTIVE_NMAP_BASIC_MODE
    profile: str = ACTIVE_NMAP_BASIC_PROFILE
    authorization_confirmed: bool = False
    local_private_scope_confirmed: bool = False
    live_traffic_confirmed: bool = False

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ActiveNmapBasicServiceRequest":
        _reject_unsupported_fields(data)
        return cls(
            target=_required_string(data, "target"),
            ports=_required_value(data, "ports"),
            mode=_required_string(data, "mode"),
            profile=_required_string(data, "profile"),
            authorization_confirmed=_required_true(data, "authorization_confirmed"),
            local_private_scope_confirmed=_required_true(data, "local_private_scope_confirmed"),
            live_traffic_confirmed=_required_true(data, "live_traffic_confirmed"),
        )


def handle_active_nmap_basic_skeleton(
    request: ActiveNmapBasicServiceRequest | Mapping[str, Any],
) -> ActiveNmapBasicSkeletonResult:
    normalized_request = coerce_active_nmap_basic_service_request(request)
    validate_active_nmap_basic_service_contract(normalized_request)

    try:
        argv = build_active_nmap_basic_argv(
            target=normalized_request.target,
            ports=normalized_request.ports,
            profile=normalized_request.profile,
        )
    except ActiveNmapBasicCommandError as exc:
        raise ActiveNmapBasicServiceError(exc.reason_code) from exc

    return {
        "status": "not_executed",
        "capability": ACTIVE_NMAP_BASIC_CAPABILITY,
        "mode": ACTIVE_NMAP_BASIC_MODE,
        "profile": ACTIVE_NMAP_BASIC_PROFILE,
        "execution_enabled": False,
        "job_created": False,
        "reason": ACTIVE_NMAP_BASIC_NOT_EXECUTED_REASON,
        "argv_preview_available": False,
        "command_builder_checked": True,
        "target_count": 1,
        "port_count": _port_count_from_argv(argv),
        "network_requests_sent": None,
        "limits": {
            "max_ports": ACTIVE_NMAP_BASIC_MAX_PORTS,
            "host_timeout_seconds": ACTIVE_NMAP_BASIC_HOST_TIMEOUT_SECONDS,
            "max_retries": ACTIVE_NMAP_BASIC_MAX_RETRIES,
        },
        "summary": {
            "nmap_executed": False,
            "parser_ran": False,
            "evidence_available": False,
        },
    }


def coerce_active_nmap_basic_service_request(
    request: ActiveNmapBasicServiceRequest | Mapping[str, Any],
) -> ActiveNmapBasicServiceRequest:
    if isinstance(request, ActiveNmapBasicServiceRequest):
        return request
    if isinstance(request, Mapping):
        return ActiveNmapBasicServiceRequest.from_mapping(request)
    raise ActiveNmapBasicServiceError("request_not_mapping")


def validate_active_nmap_basic_service_contract(request: ActiveNmapBasicServiceRequest) -> None:
    if request.mode != ACTIVE_NMAP_BASIC_MODE:
        raise ActiveNmapBasicServiceError("unsupported_mode")
    if request.profile != ACTIVE_NMAP_BASIC_PROFILE:
        raise ActiveNmapBasicServiceError("unsupported_profile")
    if request.authorization_confirmed is not True:
        raise ActiveNmapBasicServiceError("authorization_confirmation_missing")
    if request.local_private_scope_confirmed is not True:
        raise ActiveNmapBasicServiceError("local_private_scope_confirmation_missing")
    if request.live_traffic_confirmed is not True:
        raise ActiveNmapBasicServiceError("live_traffic_confirmation_missing")


def _reject_unsupported_fields(data: Mapping[str, Any]) -> None:
    unknown = set(data) - _ALLOWED_NMAP_BASIC_SERVICE_FIELDS
    if unknown & UNSUPPORTED_NMAP_BASIC_SERVICE_FIELDS:
        raise ActiveNmapBasicServiceError("unsupported_request_field")
    if unknown:
        raise ActiveNmapBasicServiceError("unknown_request_field")


def _required_string(data: Mapping[str, Any], field_name: str) -> str:
    value = _required_value(data, field_name)
    if not isinstance(value, str):
        raise ActiveNmapBasicServiceError(f"{field_name}_not_string")
    return value


def _required_true(data: Mapping[str, Any], field_name: str) -> bool:
    value = _required_value(data, field_name)
    if value is not True:
        raise ActiveNmapBasicServiceError(f"{field_name}_missing")
    return value


def _required_value(data: Mapping[str, Any], field_name: str) -> Any:
    if field_name not in data:
        raise ActiveNmapBasicServiceError(f"{field_name}_missing")
    return data[field_name]


def _port_count_from_argv(argv: list[str]) -> int:
    port_argument = argv[argv.index("-p") + 1]
    return len(port_argument.split(","))
