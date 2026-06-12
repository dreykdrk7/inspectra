from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_network

from active_runner.contracts import ACTIVE_NMAP_BASIC_MAX_TARGET_LENGTH


ACTIVE_NMAP_BASIC_LOCAL_HOSTNAME_SUFFIXES = (
    ".local",
    ".localhost",
    ".lan",
    ".home",
    ".internal",
    ".private",
    ".test",
    ".example",
    ".invalid",
)

_ALLOWED_IPV4_NETWORKS = tuple(
    ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
    )
)
_ALLOWED_IPV6_NETWORKS = tuple(ip_network(network) for network in ("::1/128", "fc00::/7"))
_BLOCKED_IP_NETWORKS = tuple(
    ip_network(network)
    for network in (
        "0.0.0.0/8",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "::/128",
        "64:ff9b::/96",
        "2001:db8::/32",
        "fe80::/10",
        "ff00::/8",
    )
)
_BLOCKED_HOSTNAMES = {
    "metadata",
    "metadata.google.internal",
    "169.254.169.254",
    "169.254.170.2",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
}
_BLOCKED_HOSTNAME_FRAGMENTS = ("metadata",)
_DISALLOWED_TARGET_MARKERS = ("*", "/", "\\", ",", "@", "?", "#", "[", "]")
_DISALLOWED_SCHEME_MARKERS = ("://", "file:", "http:", "https:")


@dataclass(frozen=True)
class ActiveNmapBasicTargetPolicyResult:
    normalized_target: str


class ActiveNmapBasicTargetPolicyError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def validate_active_nmap_basic_execution_target(target: object) -> ActiveNmapBasicTargetPolicyResult:
    return ActiveNmapBasicTargetPolicyResult(normalized_target=_normalize_single_target(target))


def _normalize_single_target(target: object) -> str:
    if not isinstance(target, str):
        raise ActiveNmapBasicTargetPolicyError("target_not_string")

    value = target.strip()
    if not value:
        raise ActiveNmapBasicTargetPolicyError("target_empty")
    if value != target:
        raise ActiveNmapBasicTargetPolicyError("target_ambiguous")
    if len(value) > ACTIVE_NMAP_BASIC_MAX_TARGET_LENGTH:
        raise ActiveNmapBasicTargetPolicyError("target_too_long")
    if any(character.isspace() for character in value):
        raise ActiveNmapBasicTargetPolicyError("target_list_in_string")
    if any(marker in value for marker in _DISALLOWED_TARGET_MARKERS):
        raise ActiveNmapBasicTargetPolicyError("target_unsupported_syntax")
    if any(value.lower().startswith(marker) for marker in _DISALLOWED_SCHEME_MARKERS):
        raise ActiveNmapBasicTargetPolicyError("target_url_not_allowed")
    if _looks_like_dash_range(value):
        raise ActiveNmapBasicTargetPolicyError("target_range_not_allowed")
    if _looks_like_port_suffix(value):
        raise ActiveNmapBasicTargetPolicyError("target_port_not_allowed")

    try:
        parsed_ip = ip_address(value)
    except ValueError:
        return _normalize_hostname_target(value)

    return _normalize_ip_target(parsed_ip)


def _normalize_ip_target(parsed_ip) -> str:
    if any(parsed_ip in blocked_network for blocked_network in _BLOCKED_IP_NETWORKS):
        raise ActiveNmapBasicTargetPolicyError("target_special_purpose_blocked")
    if parsed_ip.version == 4 and (str(parsed_ip).endswith(".0") or str(parsed_ip).endswith(".255")):
        raise ActiveNmapBasicTargetPolicyError("target_broadcast_or_network_like")

    allowed_networks = _ALLOWED_IPV4_NETWORKS if parsed_ip.version == 4 else _ALLOWED_IPV6_NETWORKS
    if not any(parsed_ip in allowed_network for allowed_network in allowed_networks):
        raise ActiveNmapBasicTargetPolicyError("target_not_local_private")

    return parsed_ip.compressed.lower()


def _normalize_hostname_target(value: str) -> str:
    if ":" in value:
        raise ActiveNmapBasicTargetPolicyError("target_port_not_allowed")
    if value.endswith(".") or value.startswith(".") or ".." in value:
        raise ActiveNmapBasicTargetPolicyError("target_ambiguous")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ActiveNmapBasicTargetPolicyError("target_non_ascii") from exc

    normalized = value.lower()
    if len(normalized) > ACTIVE_NMAP_BASIC_MAX_TARGET_LENGTH:
        raise ActiveNmapBasicTargetPolicyError("target_too_long")
    if normalized in _BLOCKED_HOSTNAMES or any(fragment in normalized for fragment in _BLOCKED_HOSTNAME_FRAGMENTS):
        raise ActiveNmapBasicTargetPolicyError("target_control_plane_blocked")
    if not _is_valid_hostname(normalized):
        raise ActiveNmapBasicTargetPolicyError("target_invalid_hostname")
    if "." in normalized and not normalized.endswith(ACTIVE_NMAP_BASIC_LOCAL_HOSTNAME_SUFFIXES):
        raise ActiveNmapBasicTargetPolicyError("target_not_local_private")

    return normalized


def _is_valid_hostname(value: str) -> bool:
    labels = value.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(character.isalnum() or character == "-" for character in label):
            return False
    return True


def _looks_like_dash_range(value: str) -> bool:
    if "-" not in value:
        return False
    head, tail = value.rsplit("-", 1)
    return bool(head and tail.isdigit() and any(character.isdigit() for character in head))


def _looks_like_port_suffix(value: str) -> bool:
    if value.count(":") != 1:
        return False
    host, port = value.rsplit(":", 1)
    return bool(host and port.isdigit())
