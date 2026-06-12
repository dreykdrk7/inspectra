from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from app.active_nmap_policy import ActiveNmapTargetPolicyError, validate_active_nmap_basic_targets


ACTIVE_NMAP_BASIC_MODE = "live_nmap_basic"
ACTIVE_NMAP_BASIC_PROFILE = "tcp_connect_small"
ACTIVE_NMAP_BASIC_MAX_PORTS_PER_TARGET = 32
ACTIVE_NMAP_BASIC_MAX_TOTAL_TARGET_PORT_CHECKS = 96
ACTIVE_NMAP_BASIC_CONFIRMATION_FIELDS = (
    "authorization_confirmed",
    "local_private_scope_confirmed",
    "live_traffic_confirmed",
)
ACTIVE_NMAP_BASIC_HANDOFF_ALLOWED_FIELDS = frozenset(
    {
        "mode",
        "profile",
        "targets",
        "ports",
        "authorization_confirmed",
        "local_private_scope_confirmed",
        "live_traffic_confirmed",
    }
)


class ActiveNmapBasicHandoffError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class ActiveNmapBasicHandoffUnit:
    target: str
    ports: tuple[int, ...]
    mode: str
    profile: str
    authorization_confirmed: bool
    local_private_scope_confirmed: bool
    live_traffic_confirmed: bool
    sequence_index: int


@dataclass(frozen=True)
class ActiveNmapBasicHandoffPlan:
    units: tuple[ActiveNmapBasicHandoffUnit, ...]
    target_count: int
    port_count: int
    target_port_checks: int
    implicit_concurrency: int = 1


def build_active_nmap_basic_handoff_plan(payload: Mapping[str, Any]) -> ActiveNmapBasicHandoffPlan:
    _validate_handoff_fields(payload)
    _validate_mode_and_profile(payload)
    _validate_confirmations(payload)
    target_policy = _validate_targets(payload.get("targets"))
    ports = _validate_ports(payload.get("ports"))

    total_checks = target_policy.target_count * len(ports)
    if total_checks > ACTIVE_NMAP_BASIC_MAX_TOTAL_TARGET_PORT_CHECKS:
        raise ActiveNmapBasicHandoffError("too_many_target_port_checks")

    units = tuple(
        ActiveNmapBasicHandoffUnit(
            target=target,
            ports=ports,
            mode=ACTIVE_NMAP_BASIC_MODE,
            profile=ACTIVE_NMAP_BASIC_PROFILE,
            authorization_confirmed=True,
            local_private_scope_confirmed=True,
            live_traffic_confirmed=True,
            sequence_index=index,
        )
        for index, target in enumerate(target_policy.normalized_targets)
    )
    return ActiveNmapBasicHandoffPlan(
        units=units,
        target_count=len(units),
        port_count=len(ports),
        target_port_checks=total_checks,
    )


def _validate_handoff_fields(payload: Mapping[str, Any]) -> None:
    fields = set(payload)
    if fields - ACTIVE_NMAP_BASIC_HANDOFF_ALLOWED_FIELDS:
        raise ActiveNmapBasicHandoffError("unsupported_request_field")
    if ACTIVE_NMAP_BASIC_HANDOFF_ALLOWED_FIELDS - fields:
        raise ActiveNmapBasicHandoffError("missing_required_field")


def _validate_mode_and_profile(payload: Mapping[str, Any]) -> None:
    if payload.get("mode") != ACTIVE_NMAP_BASIC_MODE:
        raise ActiveNmapBasicHandoffError("unsupported_mode")
    if payload.get("profile") != ACTIVE_NMAP_BASIC_PROFILE:
        raise ActiveNmapBasicHandoffError("unsupported_profile")


def _validate_confirmations(payload: Mapping[str, Any]) -> None:
    for field_name in ACTIVE_NMAP_BASIC_CONFIRMATION_FIELDS:
        if payload.get(field_name) is not True:
            raise ActiveNmapBasicHandoffError(f"{field_name}_missing")


def _validate_targets(targets: object):
    try:
        return validate_active_nmap_basic_targets(targets)
    except ActiveNmapTargetPolicyError as exc:
        raise ActiveNmapBasicHandoffError(exc.reason_code) from exc


def _validate_ports(ports: object) -> tuple[int, ...]:
    if not isinstance(ports, list) or not ports:
        raise ActiveNmapBasicHandoffError("ports_not_list")
    if len(ports) > ACTIVE_NMAP_BASIC_MAX_PORTS_PER_TARGET:
        raise ActiveNmapBasicHandoffError("too_many_ports")
    normalized: list[int] = []
    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int):
            raise ActiveNmapBasicHandoffError("port_not_integer")
        if port < 1 or port > 65535:
            raise ActiveNmapBasicHandoffError("port_out_of_range")
        normalized.append(port)
    return tuple(normalized)
