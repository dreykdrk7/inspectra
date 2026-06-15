from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any


ACTIVE_DNS_OSINT_REDACTED_DOMAIN = "[REDACTED_DOMAIN]"
ACTIVE_DNS_OSINT_MODE = "live_dns_osint"
ACTIVE_DNS_OSINT_PROFILE = "ct_subdomain_discovery_bounded"
ACTIVE_DNS_OSINT_MIN_NAMES = 1
ACTIVE_DNS_OSINT_MAX_NAMES = 100
ACTIVE_DNS_OSINT_DEFAULT_MAX_NAMES = 100

_DOMAIN_PATTERN = re.compile(r"^[a-z0-9.-]+$")
_DASH_RANGE_PATTERN = re.compile(r"^[0-9a-f:.]+-[0-9a-f:.]+$", re.IGNORECASE)
_LIST_SEPARATORS = {",", ";", "\n", "\r", "\t"}
_URL_OR_PATH_MARKERS = ("://", "/", "\\", "?", "#", "@", "[", "]")
_TARGET_FILE_SUFFIXES = (".txt", ".csv", ".json", ".lst", ".list")
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


@dataclass(frozen=True)
class ActiveDnsOsintContract:
    domain: str
    include_certificate_transparency: bool
    include_passive_dns: bool
    max_names: int


class ActiveDnsOsintPolicyError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def normalize_active_dns_osint_domain(raw_domain: Any) -> str:
    if not isinstance(raw_domain, str):
        raise ActiveDnsOsintPolicyError("domain_must_be_string")

    value = raw_domain.strip()
    if not value:
        raise ActiveDnsOsintPolicyError("domain_required")
    if len(value) > 253:
        raise ActiveDnsOsintPolicyError("domain_too_long")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ActiveDnsOsintPolicyError("domain_contains_control_character")
    if any(separator in value for separator in _LIST_SEPARATORS) or any(character.isspace() for character in value):
        raise ActiveDnsOsintPolicyError("domain_must_be_single_value")
    if "*" in value:
        raise ActiveDnsOsintPolicyError("wildcard_domain_rejected")
    if any(marker in value for marker in _URL_OR_PATH_MARKERS):
        raise ActiveDnsOsintPolicyError("url_or_path_domain_rejected")
    if value.lower().endswith(_TARGET_FILE_SUFFIXES):
        raise ActiveDnsOsintPolicyError("target_file_domain_rejected")
    if _DASH_RANGE_PATTERN.fullmatch(value):
        raise ActiveDnsOsintPolicyError("range_domain_rejected")

    normalized = value.rstrip(".").lower()
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        raise ActiveDnsOsintPolicyError("ip_domain_rejected")

    if normalized in _BLOCKED_EXACT_DOMAINS or normalized.endswith(_BLOCKED_SUFFIXES):
        raise ActiveDnsOsintPolicyError("metadata_or_control_plane_domain_rejected")

    try:
        ascii_domain = normalized.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ActiveDnsOsintPolicyError("domain_idna_normalization_failed") from exc

    if len(ascii_domain) > 253:
        raise ActiveDnsOsintPolicyError("domain_too_long")
    if "." not in ascii_domain:
        raise ActiveDnsOsintPolicyError("root_domain_required")
    if not _DOMAIN_PATTERN.fullmatch(ascii_domain):
        raise ActiveDnsOsintPolicyError("domain_contains_unsupported_characters")

    labels = ascii_domain.split(".")
    for label in labels:
        if not label:
            raise ActiveDnsOsintPolicyError("domain_empty_label")
        if len(label) > 63:
            raise ActiveDnsOsintPolicyError("domain_label_too_long")
        if label.startswith("-") or label.endswith("-"):
            raise ActiveDnsOsintPolicyError("domain_label_hyphen_boundary")

    return ascii_domain


def normalize_active_dns_osint_max_names(raw_max_names: Any) -> int:
    if isinstance(raw_max_names, bool) or not isinstance(raw_max_names, int):
        raise ActiveDnsOsintPolicyError("max_names_must_be_integer")
    if raw_max_names < ACTIVE_DNS_OSINT_MIN_NAMES or raw_max_names > ACTIVE_DNS_OSINT_MAX_NAMES:
        raise ActiveDnsOsintPolicyError("max_names_out_of_range")
    return raw_max_names


def build_active_dns_osint_not_executed_result(contract: ActiveDnsOsintContract) -> dict[str, Any]:
    return {
        "status": "not_executed",
        "capability": "active_dns_osint",
        "audit_type": "active_dns_osint",
        "result_status": "not_executed",
        "coverage_level": "osint_best_effort",
        "domain": ACTIVE_DNS_OSINT_REDACTED_DOMAIN,
        "external_requests_sent": 0,
        "ct_queries_sent": 0,
        "passive_dns_queries_sent": 0,
        "job_created": False,
        "storage_persisted": False,
        "sources": {
            "certificate_transparency": {
                "attempted": False,
                "status": "not_executed",
                "enabled_by_contract": contract.include_certificate_transparency,
            },
            "passive_dns": {
                "attempted": False,
                "status": "not_supported",
                "enabled_by_contract": contract.include_passive_dns,
            },
        },
        "observed_names": {
            "count": 0,
            "sample": [],
            "max_names": contract.max_names,
            "truncated": False,
        },
        "manual_validation_required": True,
        "result_interpretation": "dns_osint_review_indicator",
    }
