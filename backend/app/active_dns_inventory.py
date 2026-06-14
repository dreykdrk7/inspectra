from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any


ACTIVE_DNS_INVENTORY_ALLOWED_RECORD_TYPES = frozenset({"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"})
ACTIVE_DNS_INVENTORY_REDACTED_DOMAIN = "[REDACTED_DOMAIN]"

_DOMAIN_PATTERN = re.compile(r"^[a-z0-9.-]+$")
_DASH_RANGE_PATTERN = re.compile(r"^[0-9a-f:.]+-[0-9a-f:.]+$", re.IGNORECASE)
_BLOCKED_EXACT_DOMAINS = {
    "ip6-loopback",
    "metadata",
    "metadata.google.internal",
    "metadata.google.com",
    "169.254.169.254",
}
_BLOCKED_SUFFIXES = (
    ".localdomain",
    ".metadata.google.internal",
    ".compute.internal",
)
_LIST_SEPARATORS = {",", ";", "\n", "\r", "\t"}
_URL_OR_PATH_MARKERS = ("://", "/", "\\", "?", "#", "@", "[", "]")
_TARGET_FILE_SUFFIXES = (".txt", ".csv", ".json", ".lst", ".list")


@dataclass(frozen=True)
class ActiveDnsInventoryContract:
    domain: str
    record_types: tuple[str, ...]
    include_security_records: bool
    include_subdomain_discovery: bool
    attempt_zone_transfer: bool


class ActiveDnsInventoryPolicyError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def normalize_active_dns_inventory_domain(raw_domain: Any) -> str:
    if not isinstance(raw_domain, str):
        raise ActiveDnsInventoryPolicyError("domain_must_be_string")

    value = raw_domain.strip()
    if not value:
        raise ActiveDnsInventoryPolicyError("domain_required")
    if len(value) > 253:
        raise ActiveDnsInventoryPolicyError("domain_too_long")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ActiveDnsInventoryPolicyError("domain_contains_control_character")
    if any(separator in value for separator in _LIST_SEPARATORS) or any(character.isspace() for character in value):
        raise ActiveDnsInventoryPolicyError("domain_must_be_single_value")
    if "*" in value:
        raise ActiveDnsInventoryPolicyError("wildcard_domain_rejected")
    if any(marker in value for marker in _URL_OR_PATH_MARKERS):
        raise ActiveDnsInventoryPolicyError("url_or_path_domain_rejected")
    if value.lower().endswith(_TARGET_FILE_SUFFIXES):
        raise ActiveDnsInventoryPolicyError("target_file_domain_rejected")
    if _DASH_RANGE_PATTERN.fullmatch(value):
        raise ActiveDnsInventoryPolicyError("range_domain_rejected")

    normalized = value.rstrip(".").lower()
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        raise ActiveDnsInventoryPolicyError("ip_domain_rejected")

    if normalized in _BLOCKED_EXACT_DOMAINS or normalized.endswith(_BLOCKED_SUFFIXES):
        raise ActiveDnsInventoryPolicyError("metadata_or_control_plane_domain_rejected")

    try:
        ascii_domain = normalized.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ActiveDnsInventoryPolicyError("domain_idna_normalization_failed") from exc

    if len(ascii_domain) > 253:
        raise ActiveDnsInventoryPolicyError("domain_too_long")
    if "." not in ascii_domain:
        raise ActiveDnsInventoryPolicyError("root_domain_required")
    if not _DOMAIN_PATTERN.fullmatch(ascii_domain):
        raise ActiveDnsInventoryPolicyError("domain_contains_unsupported_characters")

    labels = ascii_domain.split(".")
    for label in labels:
        if not label:
            raise ActiveDnsInventoryPolicyError("domain_empty_label")
        if len(label) > 63:
            raise ActiveDnsInventoryPolicyError("domain_label_too_long")
        if label.startswith("-") or label.endswith("-"):
            raise ActiveDnsInventoryPolicyError("domain_label_hyphen_boundary")

    return ascii_domain


def normalize_active_dns_inventory_record_types(raw_record_types: Any) -> tuple[str, ...]:
    if not isinstance(raw_record_types, list) or not raw_record_types:
        raise ActiveDnsInventoryPolicyError("record_types_required")

    normalized: list[str] = []
    seen: set[str] = set()
    for raw_record_type in raw_record_types:
        if not isinstance(raw_record_type, str):
            raise ActiveDnsInventoryPolicyError("record_type_must_be_string")
        record_type = raw_record_type.strip().upper()
        if record_type not in ACTIVE_DNS_INVENTORY_ALLOWED_RECORD_TYPES:
            raise ActiveDnsInventoryPolicyError("record_type_not_allowed")
        if record_type in seen:
            continue
        seen.add(record_type)
        normalized.append(record_type)

    if not normalized:
        raise ActiveDnsInventoryPolicyError("record_types_required")
    return tuple(normalized)


def build_active_dns_inventory_not_executed_response(contract: ActiveDnsInventoryContract) -> dict[str, Any]:
    return {
        "audit_type": "active_dns_inventory",
        "capability": "active_dns_inventory",
        "status": "not_executed",
        "result_status": "not_executed",
        "coverage_level": "not_executed",
        "domain": ACTIVE_DNS_INVENTORY_REDACTED_DOMAIN,
        "record_types": list(contract.record_types),
        "include_security_records": contract.include_security_records,
        "include_subdomain_discovery": contract.include_subdomain_discovery,
        "dns_queries_sent": 0,
        "subdomain_queries_sent": 0,
        "zone_transfer_attempted": False,
        "provider_import_attempted": False,
        "job_created": False,
        "storage_persisted": False,
        "execution_enabled": False,
        "manual_validation_required": True,
        "result_interpretation": "dns_configuration_review_indicator",
    }
