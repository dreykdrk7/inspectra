from __future__ import annotations

import re
from typing import Any, Collection, TypeAlias
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
_SAFE_NMAP_DOCTYPE_RE = re.compile(br"(?is)<!DOCTYPE\s+nmaprun\s*>")


def parse_active_nmap_basic_xml(
    output: bytes | str | None,
    *,
    max_input_bytes: int = ACTIVE_NMAP_BASIC_MAX_PARSE_BYTES,
    max_port_observations: int = ACTIVE_NMAP_BASIC_MAX_PORT_OBSERVATIONS,
    accepted_ports: Collection[int] | None = None,
    target_kind: str | None = None,
) -> ActiveNmapBasicParseResult:
    max_bytes = _bounded_limit(max_input_bytes, ACTIVE_NMAP_BASIC_MAX_PARSE_BYTES)
    max_observations = _bounded_limit(max_port_observations, ACTIVE_NMAP_BASIC_MAX_PORT_OBSERVATIONS)
    accepted_port_set = _normalize_accepted_ports(accepted_ports)
    raw = _coerce_output(output)
    if raw is None:
        return _base_result("malformed", target_kind=target_kind) | {"parse_error": "unsupported_input_type"}
    if not raw.strip():
        return _base_result("empty", target_kind=target_kind)
    if len(raw) > max_bytes:
        return _base_result("truncated", target_kind=target_kind) | {
            "output_truncated": True,
            "parse_error": "output_exceeds_parser_limit",
            "parser_warnings": ["input_truncated_before_parse"],
        }
    if _contains_unsupported_xml_shape(raw):
        return _base_result("unsupported_shape", target_kind=target_kind) | {
            "parse_error": "unsupported_xml_shape",
            "parser_warnings": ["doctype_or_entity_rejected"],
        }
    raw = _strip_safe_nmap_doctype(raw).strip()

    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError:
        return _base_result("malformed", target_kind=target_kind) | {"parse_error": "malformed_xml"}

    if _tag_name(root) != "nmaprun":
        return _base_result("unsupported_shape", target_kind=target_kind) | {"parse_error": "unexpected_root"}

    hosts = root.findall(".//host")
    if len(hosts) > 1:
        return _base_result("unsupported_shape", target_kind=target_kind) | {
            "parse_error": "multiple_hosts_unsupported",
            "parser_warnings": ["multiple_hosts_rejected"],
        }
    if _contains_unsupported_live_sections(root):
        return _base_result("unsupported_shape", target_kind=target_kind) | {
            "parse_error": "unsupported_live_output_section",
            "parser_warnings": ["script_or_os_output_rejected"],
        }

    observations: list[dict[str, Any]] = []
    warnings: list[str] = []
    for port_node in root.findall(".//port"):
        port_id = _extract_port_id(port_node)
        if accepted_port_set is not None and port_id not in accepted_port_set:
            return _base_result("unsupported_shape", target_kind=target_kind) | {
                "parse_error": "unexpected_port",
                "parser_warnings": ["unexpected_port_rejected"],
            }
        observation = _parse_port_observation(port_node, warnings)
        if observation is None:
            continue
        if len(observations) >= max_observations:
            warnings.append("port_observation_limit_reached")
            return _base_result("completed", target_kind=target_kind) | {
                "port_observations": observations,
                "observation_count": len(observations),
                "output_truncated": True,
                "parser_warnings": _dedupe(warnings),
            }
        observations.append(observation)

    if not observations:
        return _base_result("no_ports", target_kind=target_kind) | {"parser_warnings": _dedupe(warnings)}

    return _base_result("completed", target_kind=target_kind) | {
        "port_observations": observations,
        "observation_count": len(observations),
        "parser_warnings": _dedupe(warnings),
    }


def _base_result(status: str, *, target_kind: str | None = None) -> ActiveNmapBasicParseResult:
    result: ActiveNmapBasicParseResult = {
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
    safe_target_kind = _safe_target_kind(target_kind)
    if safe_target_kind:
        result["target_kind"] = safe_target_kind
    return result


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
    if b"<!entity" in lowered:
        return True
    if b"<!doctype" not in lowered:
        return False
    without_safe_doctype = _SAFE_NMAP_DOCTYPE_RE.sub(b"", raw, count=1)
    return b"<!doctype" in without_safe_doctype.lower()


def _strip_safe_nmap_doctype(raw: bytes) -> bytes:
    return _SAFE_NMAP_DOCTYPE_RE.sub(b"", raw, count=1)


def _contains_unsupported_live_sections(root: ElementTree.Element) -> bool:
    return root.find(".//script") is not None or root.find(".//os") is not None


def _extract_port_id(port_node: ElementTree.Element) -> int | None:
    try:
        port = int(str(port_node.attrib.get("portid", "")))
    except ValueError:
        return None
    if port < 1 or port > 65535:
        return None
    return port


def _parse_port_observation(port_node: ElementTree.Element, warnings: list[str]) -> dict[str, Any] | None:
    protocol = str(port_node.attrib.get("protocol", "")).lower()
    if protocol != "tcp":
        warnings.append("unsupported_protocol_ignored")
        return None

    port = _extract_port_id(port_node)
    if port is None:
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


def _normalize_accepted_ports(value: Collection[int] | None) -> set[int] | None:
    if value is None:
        return None
    ports: set[int] = set()
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or item < 1 or item > 65535:
            continue
        ports.add(item)
    return ports


def _safe_target_kind(value: str | None) -> str:
    return value if value in {"authorized_fqdn", "container_loopback"} else ""


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
