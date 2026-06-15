from __future__ import annotations

import json
import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Protocol

import httpx


ACTIVE_DNS_OSINT_REDACTED_DOMAIN = "[REDACTED_DOMAIN]"
ACTIVE_DNS_OSINT_REDACTED_NAME = "[REDACTED_DNS_NAME]"
ACTIVE_DNS_OSINT_MODE = "live_dns_osint"
ACTIVE_DNS_OSINT_PROFILE = "ct_subdomain_discovery_bounded"
ACTIVE_DNS_OSINT_MIN_NAMES = 1
ACTIVE_DNS_OSINT_MAX_NAMES = 100
ACTIVE_DNS_OSINT_DEFAULT_MAX_NAMES = 100
ACTIVE_DNS_OSINT_SAMPLE_SIZE = 5
ACTIVE_DNS_OSINT_CT_SOURCE_KIND_CRTSH = "crtsh"
ACTIVE_DNS_OSINT_CRTSH_ALLOWED_HOST = "crt.sh"
ACTIVE_DNS_OSINT_CRTSH_EXPECTED_FIELDS = ("name_value", "common_name")
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
    external_requests_sent: int = 0
    ct_queries_sent: int = 0
    http_requests_sent: int = 0
    source_kind: str = "injected"


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
        return ActiveDnsOsintCtSourceResult(status="disabled", source_kind="disabled")


class BlockedActiveDnsOsintCtSource:
    def query_certificate_transparency(
        self,
        *,
        domain: str,
        max_names: int,
    ) -> ActiveDnsOsintCtSourceResult:
        return ActiveDnsOsintCtSourceResult(status="blocked_by_policy", source_kind="blocked")


class CrtShActiveDnsOsintCtSource:
    def __init__(
        self,
        *,
        source_url: str,
        timeout_seconds: float,
        max_response_bytes: int,
        max_names_parsed: int,
        http_transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.source_url = source_url
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.max_names_parsed = max_names_parsed
        self.http_transport = http_transport

    def query_certificate_transparency(
        self,
        *,
        domain: str,
        max_names: int,
    ) -> ActiveDnsOsintCtSourceResult:
        if max_names < ACTIVE_DNS_OSINT_MIN_NAMES or max_names > ACTIVE_DNS_OSINT_MAX_NAMES:
            return ActiveDnsOsintCtSourceResult(status="blocked_by_policy", source_kind=ACTIVE_DNS_OSINT_CT_SOURCE_KIND_CRTSH)

        try:
            with httpx.Client(
                follow_redirects=False,
                timeout=self.timeout_seconds,
                transport=self.http_transport,
            ) as client:
                with client.stream(
                    "GET",
                    self.source_url,
                    params={"q": f"%.{domain}", "output": "json"},
                ) as response:
                    status_result = _status_from_crtsh_http_response(response.status_code)
                    if status_result is not None:
                        return ActiveDnsOsintCtSourceResult(
                            status=status_result,
                            external_requests_sent=1,
                            ct_queries_sent=1,
                            http_requests_sent=1,
                            source_kind=ACTIVE_DNS_OSINT_CT_SOURCE_KIND_CRTSH,
                        )
                    response_bytes = _read_bounded_response_bytes(response, self.max_response_bytes)
        except httpx.TimeoutException:
            return ActiveDnsOsintCtSourceResult(
                status="timed_out",
                external_requests_sent=1,
                ct_queries_sent=1,
                http_requests_sent=1,
                source_kind=ACTIVE_DNS_OSINT_CT_SOURCE_KIND_CRTSH,
            )
        except httpx.TransportError:
            return ActiveDnsOsintCtSourceResult(
                status="source_unavailable",
                external_requests_sent=1,
                ct_queries_sent=1,
                http_requests_sent=1,
                source_kind=ACTIVE_DNS_OSINT_CT_SOURCE_KIND_CRTSH,
            )
        except Exception:
            return ActiveDnsOsintCtSourceResult(
                status="source_error_controlled",
                external_requests_sent=1,
                ct_queries_sent=1,
                http_requests_sent=1,
                source_kind=ACTIVE_DNS_OSINT_CT_SOURCE_KIND_CRTSH,
            )

        if response_bytes is None:
            return ActiveDnsOsintCtSourceResult(
                status="truncated",
                truncated=True,
                external_requests_sent=1,
                ct_queries_sent=1,
                http_requests_sent=1,
                source_kind=ACTIVE_DNS_OSINT_CT_SOURCE_KIND_CRTSH,
            )

        parsed_names = _parse_crtsh_response(response_bytes, self.max_names_parsed)
        if parsed_names is None:
            return ActiveDnsOsintCtSourceResult(
                status="invalid_source_response",
                external_requests_sent=1,
                ct_queries_sent=1,
                http_requests_sent=1,
                source_kind=ACTIVE_DNS_OSINT_CT_SOURCE_KIND_CRTSH,
            )

        observed_names, truncated = parsed_names
        return ActiveDnsOsintCtSourceResult(
            status="truncated" if truncated else "completed",
            observed_names=observed_names,
            truncated=truncated,
            external_requests_sent=1,
            ct_queries_sent=1,
            http_requests_sent=1,
            source_kind=ACTIVE_DNS_OSINT_CT_SOURCE_KIND_CRTSH,
        )


def build_active_dns_osint_ct_source(
    *,
    enabled: bool,
    source_url: str,
    timeout_seconds: float,
    max_response_bytes: int,
    max_names_parsed: int,
    http_transport: httpx.BaseTransport | None = None,
) -> ActiveDnsOsintCtSource:
    if not enabled:
        return DisabledActiveDnsOsintCtSource()
    normalized_source_url = _normalize_crtsh_source_url(source_url)
    if normalized_source_url is None:
        return DisabledActiveDnsOsintCtSource() if not str(source_url).strip() else BlockedActiveDnsOsintCtSource()
    return CrtShActiveDnsOsintCtSource(
        source_url=normalized_source_url,
        timeout_seconds=timeout_seconds,
        max_response_bytes=max_response_bytes,
        max_names_parsed=max_names_parsed,
        http_transport=http_transport,
    )


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
            "external_requests_sent": _bounded_counter(ct_result.external_requests_sent),
            "ct_queries_sent": _bounded_counter(ct_result.ct_queries_sent),
            "passive_dns_queries_sent": 0,
            "dns_queries_sent": 0,
            "http_requests_sent": _bounded_counter(ct_result.http_requests_sent),
            "provider_api_used": False,
            "credential_validation_performed": False,
            "crawling_performed": False,
            "subprocess_invoked": False,
            "nmap_invoked": False,
            "target_expansion_performed": False,
            "observed_name_auto_scan_performed": False,
            "ct_real_call_performed": ct_result.source_kind == ACTIVE_DNS_OSINT_CT_SOURCE_KIND_CRTSH
            and _bounded_counter(ct_result.ct_queries_sent) == 1,
            "passive_dns_api_used": False,
        },
        "limits": {
            "max_names": contract.max_names,
            "backend_max_names": ACTIVE_DNS_OSINT_MAX_NAMES,
            "sample_size": ACTIVE_DNS_OSINT_SAMPLE_SIZE,
            "ct_source_kind": ct_result.source_kind,
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
    return ActiveDnsOsintCtSourceResult(
        status=result.status,
        observed_names=result.observed_names,
        truncated=bool(result.truncated),
        external_requests_sent=_bounded_counter(result.external_requests_sent),
        ct_queries_sent=_bounded_counter(result.ct_queries_sent),
        http_requests_sent=_bounded_counter(result.http_requests_sent),
        source_kind=result.source_kind
        if result.source_kind in {"disabled", "blocked", "injected", ACTIVE_DNS_OSINT_CT_SOURCE_KIND_CRTSH}
        else "controlled",
    )


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


def _normalize_crtsh_source_url(raw_url: str) -> str | None:
    try:
        url = httpx.URL(raw_url.strip())
    except Exception:
        return None
    if url.scheme != "https":
        return None
    if url.host != ACTIVE_DNS_OSINT_CRTSH_ALLOWED_HOST:
        return None
    if url.username or url.password or url.query or url.fragment:
        return None
    if url.path not in {"", "/"}:
        return None
    return str(url.copy_with(path="/", query=None, fragment=None))


def _status_from_crtsh_http_response(status_code: int) -> str | None:
    if status_code == 200:
        return None
    if status_code == 429:
        return "rate_limited"
    if status_code in {408, 504}:
        return "timed_out"
    if 500 <= status_code <= 599:
        return "source_unavailable"
    return "source_error_controlled"


def _read_bounded_response_bytes(response: httpx.Response, max_response_bytes: int) -> bytes | None:
    content = bytearray()
    for chunk in response.iter_bytes():
        content.extend(chunk)
        if len(content) > max_response_bytes:
            return None
    return bytes(content)


def _parse_crtsh_response(response_bytes: bytes, max_names_parsed: int) -> tuple[tuple[str, ...], bool] | None:
    try:
        decoded = response_bytes.decode("utf-8")
        payload = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, list):
        return None

    names: list[str] = []
    truncated = False
    for entry in payload:
        if not isinstance(entry, dict):
            return None
        for field_name in ACTIVE_DNS_OSINT_CRTSH_EXPECTED_FIELDS:
            if field_name not in entry:
                continue
            raw_value = entry[field_name]
            if not isinstance(raw_value, str):
                return None
            for candidate in raw_value.splitlines():
                value = candidate.strip()
                if not value:
                    continue
                if len(names) >= max_names_parsed:
                    truncated = True
                    return tuple(names), truncated
                names.append(value)
    return tuple(names), truncated


def _bounded_counter(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    if value <= 0:
        return 0
    return min(value, 1)
