from __future__ import annotations

from typing import Any, TypeAlias
from xml.etree import ElementTree

from active_runner.contracts import (
    ACTIVE_NMAP_BASIC_MAX_PARSE_BYTES,
    ACTIVE_NMAP_BASIC_MAX_PORT_OBSERVATIONS,
)


ActiveNmapBasicParseResult: TypeAlias = dict[str, Any]

_ALLOWED_PORT_STATES = {
    "closed",
    "closed|filtered",
    "filtered",
    "open",
    "open|filtered",
    "unfiltered",
}
_ALLOWED_STATE_REASONS = {
    "admin-prohibited",
    "arp-response",
    "conn-refused",
    "echo-reply",
    "host-prohibited",
    "host-unreach",
    "localhost-response",
    "net-prohibited",
    "net-unreach",
    "no-response",
    "no-responses",
    "port-unreach",
    "proto-response",
    "reset",
    "reset-ttl",
    "syn-ack",
    "timestamp-reply",
    "udp-response",
    "user-set",
}


def parse_active_nmap_basic_xml(
    output: bytes | str | None,
    *,
    max_input_bytes: int = ACTIVE_NMAP_BASIC_MAX_PARSE_BYTES,
    max_port_observations: int = ACTIVE_NMAP_BASIC_MAX_PORT_OBSERVATIONS,
) -> ActiveNmapBasicParseResult:
    max_bytes = _bounded_limit(max_input_bytes, ACTIVE_NMAP_BASIC_MAX_PARSE_BYTES)
    max_observations = _bounded_limit(max_port_observations, ACTIVE_NMAP_BASIC_MAX_PORT_OBSERVATIONS)
    raw = _coerce_output(output)
    if raw is None:
        return _base_result("malformed") | {"parse_error": "unsupported_input_type"}
    if not raw.strip():
        return _base_result("empty")
    if len(raw) > max_bytes:
        return _base_result("truncated") | {
            "output_truncated": True,
            "parse_error": "output_exceeds_parser_limit",
            "parser_warnings": ["input_truncated_before_parse"],
        }
    if _contains_unsupported_xml_shape(raw):
        return _base_result("unsupported_shape") | {
            "parse_error": "unsupported_xml_shape",
            "parser_warnings": ["doctype_or_entity_rejected"],
        }

    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError:
        return _base_result("malformed") | {"parse_error": "malformed_xml"}

    if _tag_name(root) != "nmaprun":
        return _base_result("unsupported_shape") | {"parse_error": "unexpected_root"}

    observations: list[dict[str, Any]] = []
    warnings: list[str] = []
    for port_node in root.findall(".//port"):
        observation = _parse_port_observation(port_node, warnings)
        if observation is None:
            continue
        if len(observations) >= max_observations:
            warnings.append("port_observation_limit_reached")
            return _base_result("completed") | {
                "port_observations": observations,
                "observation_count": len(observations),
                "output_truncated": True,
                "parser_warnings": _dedupe(warnings),
            }
        observations.append(observation)

    if not observations:
        return _base_result("no_ports") | {"parser_warnings": _dedupe(warnings)}

    return _base_result("completed") | {
        "port_observations": observations,
        "observation_count": len(observations),
        "parser_warnings": _dedupe(warnings),
    }


def _base_result(status: str) -> ActiveNmapBasicParseResult:
    return {
        "status": status,
        "port_observations": [],
        "output_truncated": False,
        "parse_error": None,
        "observation_count": 0,
        "parser_warnings": [],
        "raw_xml_returned": False,
        "command_returned": False,
        "target_returned": False,
        "findings_created": False,
    }


def _coerce_output(output: bytes | str | None) -> bytes | None:
    if output is None:
        return b""
    if isinstance(output, bytes):
        return output
    if isinstance(output, str):
        return output.encode("utf-8", errors="replace")
    return None


def _contains_unsupported_xml_shape(raw: bytes) -> bool:
    lowered = raw.lower()
    return b"<!doctype" in lowered or b"<!entity" in lowered


def _parse_port_observation(port_node: ElementTree.Element, warnings: list[str]) -> dict[str, Any] | None:
    protocol = str(port_node.attrib.get("protocol", "")).lower()
    if protocol != "tcp":
        warnings.append("unsupported_protocol_ignored")
        return None

    try:
        port = int(str(port_node.attrib.get("portid", "")))
    except ValueError:
        warnings.append("invalid_port_ignored")
        return None
    if port < 1 or port > 65535:
        warnings.append("invalid_port_ignored")
        return None

    state_node = port_node.find("state")
    raw_state = ""
    raw_reason = ""
    if state_node is not None:
        raw_state = str(state_node.attrib.get("state", "")).lower()
        raw_reason = str(state_node.attrib.get("reason", ""))

    observation: dict[str, Any] = {
        "port": port,
        "protocol": "tcp",
        "state": _normalize_state(raw_state, warnings),
    }
    reason = _safe_reason(raw_reason)
    if reason:
        observation["reason"] = reason
    return observation


def _normalize_state(raw_state: str, warnings: list[str]) -> str:
    if raw_state in _ALLOWED_PORT_STATES:
        return raw_state
    if raw_state:
        warnings.append("unknown_state_normalized")
    else:
        warnings.append("missing_state_normalized")
    return "unknown"


def _safe_reason(reason: str) -> str:
    return reason if reason in _ALLOWED_STATE_REASONS else ""


def _tag_name(node: ElementTree.Element) -> str:
    tag = str(node.tag)
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _bounded_limit(value: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return maximum
    return min(value, maximum)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
