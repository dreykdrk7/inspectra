from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Protocol


ACTIVE_DNS_OSINT_REDACTED_DOMAIN = "[REDACTED_DOMAIN]"
ACTIVE_DNS_OSINT_REDACTED_NAME = "[REDACTED_DNS_NAME]"
ACTIVE_DNS_OSINT_MODE = "live_dns_osint"
ACTIVE_DNS_OSINT_PROFILE = "ct_subdomain_discovery_bounded"
ACTIVE_DNS_OSINT_MIN_NAMES = 1
ACTIVE_DNS_OSINT_MAX_NAMES = 100
ACTIVE_DNS_OSINT_DEFAULT_MAX_NAMES = 100
ACTIVE_DNS_OSINT_SAMPLE_SIZE = 5
ACTIVE_DNS_OSINT_SOURCE_STATUSES = {
    "not_attempted",
    "disabled",
    "completed",
    "partial",
    "timed_out",
    "rate_limited",
    "source_unavailable",
    "source_error_controlled",
    "truncated",
    "invalid_source_response",
    "blocked_by_policy",
}

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


@dataclass(frozen=True)
class ActiveDnsOsintCtSourceResult:
    status: str
    observed_names: tuple[str, ...] = ()
    truncated: bool = False


class ActiveDnsOsintCtSource(Protocol):
    def query_certificate_transparency(
        self,
        *,
        domain: str,
        max_names: int,
    ) -> ActiveDnsOsintCtSourceResult:
        ...


class ActiveDnsOsintPolicyError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class ActiveDnsOsintSourceError(RuntimeError):
    def __init__(self, status: str = "source_error_controlled") -> None:
        super().__init__(status)
        self.status = status if status in ACTIVE_DNS_OSINT_SOURCE_STATUSES else "source_error_controlled"


class DisabledActiveDnsOsintCtSource:
    def query_certificate_transparency(
        self,
        *,
        domain: str,
        max_names: int,
    ) -> ActiveDnsOsintCtSourceResult:
        return ActiveDnsOsintCtSourceResult(status="disabled")


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


def run_active_dns_osint(
    contract: ActiveDnsOsintContract,
    *,
    ct_source: ActiveDnsOsintCtSource | None = None,
) -> dict[str, Any]:
    source = ct_source or DisabledActiveDnsOsintCtSource()
    ct_result = _query_certificate_transparency_source(source, contract)
    observed_names = _bounded_observed_names(contract.domain, ct_result.observed_names, contract.max_names)
    truncated_by_policy = observed_names["eligible_name_count"] > observed_names["retained_name_count"]
    source_status = ct_result.status
    if source_status == "completed" and (ct_result.truncated or truncated_by_policy):
        source_status = "truncated"
    source_attempted = contract.include_certificate_transparency and source_status not in {"disabled", "not_attempted"}
    errors = _source_errors(source_status)

    return {
        "audit_type": "active_dns_osint",
        "capability": "active_dns_osint",
        "mode": ACTIVE_DNS_OSINT_MODE,
        "profile": ACTIVE_DNS_OSINT_PROFILE,
        "status": "osint_best_effort",
        "result_status": "osint_best_effort",
        "coverage_level": "osint_best_effort",
        "domain": ACTIVE_DNS_OSINT_REDACTED_DOMAIN,
        "sources": {
            "certificate_transparency": {
                "attempted": source_attempted,
                "status": source_status,
                "names_observed_count": observed_names["source_name_count"],
                "names_retained_count": observed_names["retained_name_count"],
                "names_discarded_count": observed_names["discarded_name_count"],
                "truncated": bool(ct_result.truncated or truncated_by_policy),
            },
            "passive_dns": {
                "attempted": False,
                "status": "not_attempted",
            },
        },
        "observed_names": {
            "count": observed_names["retained_name_count"],
            "sample": _redacted_name_sample(observed_names["retained_name_count"]),
            "max_names": contract.max_names,
            "truncated": bool(ct_result.truncated or truncated_by_policy),
        },
        "summary": {
            "manual_validation_required": True,
            "result_interpretation": "dns_osint_review_indicator",
            "coverage_level": "osint_best_effort",
            "observed_names_count": observed_names["retained_name_count"],
            "ct_source_status": source_status,
            "passive_dns_status": "not_attempted",
        },
        "execution": {
            "external_requests_sent": 0,
            "ct_queries_sent": 0,
            "passive_dns_queries_sent": 0,
            "dns_queries_sent": 0,
            "http_requests_sent": 0,
            "provider_api_used": False,
            "credential_validation_performed": False,
            "crawling_performed": False,
            "subprocess_invoked": False,
            "nmap_invoked": False,
            "target_expansion_performed": False,
            "observed_name_auto_scan_performed": False,
        },
        "limits": {
            "max_names": contract.max_names,
            "backend_max_names": ACTIVE_DNS_OSINT_MAX_NAMES,
            "sample_size": ACTIVE_DNS_OSINT_SAMPLE_SIZE,
            "domain_value_persisted": False,
            "observed_name_values_persisted": False,
            "ct_source_values_persisted": False,
            "certificate_material_persisted": False,
            "source_error_details_persisted": False,
        },
        "manual_validation_required": True,
        "result_interpretation": "dns_osint_review_indicator",
        "errors": errors,
        "warnings": [],
        "surface_caveats": [
            "DNS OSINT review indicator",
            "Manual validation required",
            "Public-source observed-name inventory is best-effort",
            "Observed names are redacted",
            "No passive DNS source used",
            "No provider import",
            "No auto-scan of observed names",
        ],
    }


def active_dns_osint_job_status(result: dict[str, Any]) -> str:
    return "completed" if result.get("result_status") == "osint_best_effort" else "failed"


def active_dns_osint_job_error(result: dict[str, Any]) -> str | None:
    ct_source = result.get("sources", {}).get("certificate_transparency") if isinstance(result.get("sources"), dict) else {}
    source_status = ct_source.get("status") if isinstance(ct_source, dict) else None
    if source_status in {"timed_out", "rate_limited", "source_unavailable", "source_error_controlled", "invalid_source_response"}:
        return str(source_status)
    if result.get("result_status") != "osint_best_effort":
        return "dns_osint_error_controlled"
    return None


def _query_certificate_transparency_source(
    source: ActiveDnsOsintCtSource,
    contract: ActiveDnsOsintContract,
) -> ActiveDnsOsintCtSourceResult:
    try:
        result = source.query_certificate_transparency(domain=contract.domain, max_names=contract.max_names)
    except TimeoutError:
        return ActiveDnsOsintCtSourceResult(status="timed_out")
    except ActiveDnsOsintSourceError as exc:
        return ActiveDnsOsintCtSourceResult(status=exc.status)
    except Exception:
        return ActiveDnsOsintCtSourceResult(status="source_error_controlled")
    if not isinstance(result, ActiveDnsOsintCtSourceResult):
        return ActiveDnsOsintCtSourceResult(status="invalid_source_response")
    if result.status not in ACTIVE_DNS_OSINT_SOURCE_STATUSES:
        return ActiveDnsOsintCtSourceResult(status="invalid_source_response")
    if not isinstance(result.observed_names, tuple) or any(not isinstance(name, str) for name in result.observed_names):
        return ActiveDnsOsintCtSourceResult(status="invalid_source_response")
    return result


def _bounded_observed_names(domain: str, raw_names: tuple[str, ...], max_names: int) -> dict[str, int]:
    retained: list[str] = []
    seen: set[str] = set()
    discarded = 0
    eligible = 0
    for raw_name in raw_names:
        normalized = _normalize_observed_name(raw_name, domain)
        if normalized is None:
            discarded += 1
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        eligible += 1
        if len(retained) < max_names:
            retained.append(normalized)
    return {
        "source_name_count": len(raw_names),
        "eligible_name_count": eligible,
        "retained_name_count": len(retained),
        "discarded_name_count": discarded,
    }


def _normalize_observed_name(raw_name: str, domain: str) -> str | None:
    value = raw_name.strip().lower()
    if not value:
        return None
    if value.startswith("*."):
        value = value[2:]
    if "*" in value:
        return None
    try:
        normalized = normalize_active_dns_osint_domain(value)
    except ActiveDnsOsintPolicyError:
        return None
    if normalized == domain or normalized.endswith(f".{domain}"):
        return normalized
    return None


def _redacted_name_sample(count: int) -> list[str]:
    return [ACTIVE_DNS_OSINT_REDACTED_NAME for _ in range(min(max(count, 0), ACTIVE_DNS_OSINT_SAMPLE_SIZE))]


def _source_errors(status: str) -> list[dict[str, str]]:
    if status in {"completed", "disabled", "not_attempted", "partial", "truncated"}:
        return []
    return [{"code": status, "source": "certificate_transparency"}]
