from __future__ import annotations

import ipaddress
import re
import socket
import struct
from dataclasses import dataclass
from typing import Any


ACTIVE_DNS_INVENTORY_ALLOWED_RECORD_TYPES = frozenset({"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"})
ACTIVE_DNS_INVENTORY_REDACTED_DOMAIN = "[REDACTED_DOMAIN]"
ACTIVE_DNS_INVENTORY_REDACTED_NAME = "[REDACTED_DNS_NAME]"
ACTIVE_DNS_INVENTORY_REDACTED_VALUE = "[REDACTED_DNS_VALUE]"
ACTIVE_DNS_INVENTORY_SUBDOMAIN_CANDIDATES = (
    "www",
    "mail",
    "smtp",
    "imap",
    "pop",
    "api",
    "app",
    "admin",
    "portal",
    "dev",
    "staging",
    "test",
)
ACTIVE_DNS_INVENTORY_SUBDOMAIN_RECORD_TYPES = ("A", "AAAA", "CNAME")
ACTIVE_DNS_INVENTORY_MAX_RECORDS_PER_TYPE = 12
ACTIVE_DNS_INVENTORY_MAX_SUBDOMAIN_SAMPLE = 12
ACTIVE_DNS_INVENTORY_MAX_ERRORS = 16
ACTIVE_DNS_INVENTORY_TIMEOUT_SECONDS = 2.0
ACTIVE_DNS_INVENTORY_MAX_NAMESERVERS = 1

_DNS_PORT = 53
_DNS_CLASS_IN = 1
_DNS_QTYPE_BY_NAME = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "CAA": 257,
}
_DNS_QTYPE_BY_CODE = {code: name for name, code in _DNS_QTYPE_BY_NAME.items()}

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


@dataclass(frozen=True)
class ActiveDnsInventoryRecord:
    name: str
    record_type: str
    value: str
    ttl: int | None = None
    priority: int | None = None


@dataclass(frozen=True)
class ActiveDnsInventoryQueryResult:
    status: str
    records: tuple[ActiveDnsInventoryRecord, ...] = ()
    error_code: str | None = None
    truncated: bool = False


class UdpDnsInventoryResolver:
    def __init__(
        self,
        *,
        nameservers: tuple[str, ...] | None = None,
        timeout_seconds: float = ACTIVE_DNS_INVENTORY_TIMEOUT_SECONDS,
    ) -> None:
        self.nameservers = nameservers or _load_system_nameservers()
        self.timeout_seconds = timeout_seconds

    def query(self, name: str, record_type: str) -> ActiveDnsInventoryQueryResult:
        last_error = "resolver_unavailable"
        for nameserver in self.nameservers[:ACTIVE_DNS_INVENTORY_MAX_NAMESERVERS]:
            try:
                return _query_udp_dns(nameserver, name, record_type, timeout_seconds=self.timeout_seconds)
            except TimeoutError:
                last_error = "dns_query_timeout"
            except OSError:
                last_error = "dns_query_error"
            except ValueError:
                last_error = "dns_parse_error"
        return ActiveDnsInventoryQueryResult(status="error", error_code=last_error)


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


def run_active_dns_inventory(
    contract: ActiveDnsInventoryContract,
    *,
    resolver: Any | None = None,
) -> dict[str, Any]:
    dns_resolver = resolver or UdpDnsInventoryResolver()
    query_cache: dict[tuple[str, str], ActiveDnsInventoryQueryResult] = {}
    root_records: dict[str, list[ActiveDnsInventoryRecord]] = {record_type: [] for record_type in contract.record_types}
    security_raw: dict[str, list[ActiveDnsInventoryRecord]] = {"TXT": [], "DMARC": [], "CAA": []}
    subdomain_results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    partial = False
    dns_queries_sent = 0
    subdomain_queries_sent = 0

    def safe_query(name: str, record_type: str, *, purpose: str) -> ActiveDnsInventoryQueryResult:
        nonlocal dns_queries_sent, partial
        cache_key = (name, record_type)
        if cache_key in query_cache:
            return query_cache[cache_key]
        dns_queries_sent += 1
        try:
            result = _coerce_query_result(dns_resolver.query(name, record_type))
        except TimeoutError:
            result = ActiveDnsInventoryQueryResult(status="timeout", error_code="dns_query_timeout")
        except Exception:
            result = ActiveDnsInventoryQueryResult(status="error", error_code="dns_query_error")
        query_cache[cache_key] = result
        if result.status in {"timeout", "error", "truncated"} or result.truncated:
            partial = True
            if len(errors) < ACTIVE_DNS_INVENTORY_MAX_ERRORS:
                errors.append(
                    {
                        "code": result.error_code or result.status,
                        "record_type": record_type,
                        "purpose": purpose,
                    }
                )
        return result

    for record_type in contract.record_types:
        result = safe_query(contract.domain, record_type, purpose="root_standard_record")
        root_records.setdefault(record_type, []).extend(
            record for record in result.records if record.record_type == record_type
        )

    if contract.include_security_records:
        txt_result = safe_query(contract.domain, "TXT", purpose="spf_indicator")
        caa_result = safe_query(contract.domain, "CAA", purpose="caa_indicator")
        dmarc_result = safe_query(f"_dmarc.{contract.domain}", "TXT", purpose="dmarc_indicator")
        security_raw["TXT"] = list(txt_result.records)
        security_raw["CAA"] = list(caa_result.records)
        security_raw["DMARC"] = list(dmarc_result.records)

    if contract.include_subdomain_discovery:
        for candidate in ACTIVE_DNS_INVENTORY_SUBDOMAIN_CANDIDATES:
            candidate_records: list[ActiveDnsInventoryRecord] = []
            candidate_name = f"{candidate}.{contract.domain}"
            for record_type in ACTIVE_DNS_INVENTORY_SUBDOMAIN_RECORD_TYPES:
                subdomain_queries_sent += 1
                result = safe_query(candidate_name, record_type, purpose="bounded_subdomain_discovery")
                candidate_records.extend(record for record in result.records if record.record_type == record_type)
            if candidate_records:
                subdomain_results.append(
                    {
                        "name": ACTIVE_DNS_INVENTORY_REDACTED_NAME,
                        "record_types": sorted({record.record_type for record in candidate_records}),
                        "record_count": len(candidate_records),
                    }
                )

    coverage_level = "partial_inventory" if partial else "best_effort_inventory"
    grouped_records = {
        record_type: _public_record_group(records)
        for record_type, records in root_records.items()
        if record_type in ACTIVE_DNS_INVENTORY_ALLOWED_RECORD_TYPES
    }
    security_records = _build_security_record_indicators(security_raw)
    return {
        "audit_type": "active_dns_inventory",
        "capability": "active_dns_inventory",
        "mode": "live_dns_inventory",
        "profile": "dns_inventory_authorized",
        "status": coverage_level,
        "result_status": coverage_level,
        "coverage_level": coverage_level,
        "domain": ACTIVE_DNS_INVENTORY_REDACTED_DOMAIN,
        "record_types": list(contract.record_types),
        "records": grouped_records,
        "security_records": security_records,
        "subdomains": {
            "enabled": contract.include_subdomain_discovery,
            "strategy": "fixed_candidate_allowlist",
            "candidates_checked": len(ACTIVE_DNS_INVENTORY_SUBDOMAIN_CANDIDATES) if contract.include_subdomain_discovery else 0,
            "query_record_types": list(ACTIVE_DNS_INVENTORY_SUBDOMAIN_RECORD_TYPES),
            "count": len(subdomain_results),
            "sample": subdomain_results[:ACTIVE_DNS_INVENTORY_MAX_SUBDOMAIN_SAMPLE],
            "sample_truncated": len(subdomain_results) > ACTIVE_DNS_INVENTORY_MAX_SUBDOMAIN_SAMPLE,
        },
        "zone_transfer": {"attempted": False, "status": "not_attempted"},
        "provider_import": {"attempted": False, "status": "not_attempted"},
        "dns_queries_sent": dns_queries_sent,
        "subdomain_queries_sent": subdomain_queries_sent,
        "errors": errors,
        "execution": {
            "dns_queries_sent": dns_queries_sent,
            "subdomain_queries_sent": subdomain_queries_sent,
            "http_requests_sent": 0,
            "subprocess_invoked": False,
            "nmap_invoked": False,
            "target_expansion_performed": False,
            "recursive_discovery_performed": False,
            "zone_transfer_attempted": False,
            "provider_api_used": False,
            "credential_validation_performed": False,
            "crawling_performed": False,
        },
        "limits": {
            "timeout_seconds": ACTIVE_DNS_INVENTORY_TIMEOUT_SECONDS,
            "allowed_record_types": sorted(ACTIVE_DNS_INVENTORY_ALLOWED_RECORD_TYPES),
            "subdomain_candidates": len(ACTIVE_DNS_INVENTORY_SUBDOMAIN_CANDIDATES),
            "subdomain_record_types": list(ACTIVE_DNS_INVENTORY_SUBDOMAIN_RECORD_TYPES),
            "max_records_per_type": ACTIVE_DNS_INVENTORY_MAX_RECORDS_PER_TYPE,
            "max_subdomain_sample": ACTIVE_DNS_INVENTORY_MAX_SUBDOMAIN_SAMPLE,
            "domain_value_persisted": False,
            "dns_packets_persisted": False,
            "resolver_logs_persisted": False,
        },
        "manual_validation_required": True,
        "result_interpretation": "dns_configuration_review_indicator",
        "surface_caveats": [
            "Best-effort DNS inventory only",
            "Manual validation required",
            "No complete-zone claim",
            "No provider import",
            "No zone transfer",
            "No brute-force discovery",
            "No raw domain or resolver output stored",
        ],
    }


def active_dns_inventory_job_status(result: dict[str, Any]) -> str:
    if result.get("result_status") in {"best_effort_inventory", "partial_inventory"}:
        return "completed"
    return "failed"


def active_dns_inventory_job_error(result: dict[str, Any]) -> str | None:
    if result.get("result_status") == "partial_inventory":
        return "partial_inventory"
    if result.get("result_status") not in {"best_effort_inventory", "partial_inventory"}:
        return "dns_inventory_error_controlled"
    return None


def _public_record_group(records: list[ActiveDnsInventoryRecord]) -> dict[str, Any]:
    sample_records = records[:ACTIVE_DNS_INVENTORY_MAX_RECORDS_PER_TYPE]
    return {
        "count": len(records),
        "sample": [_public_record(record) for record in sample_records],
        "truncated": len(records) > ACTIVE_DNS_INVENTORY_MAX_RECORDS_PER_TYPE,
    }


def _public_record(record: ActiveDnsInventoryRecord) -> dict[str, Any]:
    public = {
        "name": ACTIVE_DNS_INVENTORY_REDACTED_DOMAIN if record.name.count(".") <= 1 else ACTIVE_DNS_INVENTORY_REDACTED_NAME,
        "type": record.record_type,
        "value": ACTIVE_DNS_INVENTORY_REDACTED_VALUE,
        "ttl": record.ttl if isinstance(record.ttl, int) and record.ttl >= 0 else None,
    }
    if record.priority is not None:
        public["priority"] = record.priority
    return public


def _build_security_record_indicators(records: dict[str, list[ActiveDnsInventoryRecord]]) -> dict[str, Any]:
    txt_values = [record.value for record in records.get("TXT", [])]
    dmarc_values = [record.value for record in records.get("DMARC", [])]
    caa_values = [record.value for record in records.get("CAA", [])]
    spf_present = any(value.lower().startswith("v=spf1") for value in txt_values)
    dmarc_present = any(value.lower().startswith("v=dmarc1") for value in dmarc_values)
    return {
        "spf": {
            "checked": True,
            "present": spf_present,
            "record_value": ACTIVE_DNS_INVENTORY_REDACTED_VALUE if spf_present else None,
            "interpretation": "dns_mail_authentication_review_indicator",
        },
        "dmarc": {
            "checked": True,
            "present": dmarc_present,
            "record_value": ACTIVE_DNS_INVENTORY_REDACTED_VALUE if dmarc_present else None,
            "interpretation": "dns_mail_authentication_review_indicator",
        },
        "caa": {
            "checked": True,
            "present": bool(caa_values),
            "record_count": len(caa_values),
            "interpretation": "dns_certificate_authority_review_indicator",
        },
        "dkim": {"checked": False, "status": "not_attempted"},
    }


def _coerce_query_result(value: Any) -> ActiveDnsInventoryQueryResult:
    if isinstance(value, ActiveDnsInventoryQueryResult):
        return value
    if isinstance(value, list):
        return ActiveDnsInventoryQueryResult(status="ok" if value else "noerror_empty", records=_coerce_records(value))
    if isinstance(value, tuple):
        return ActiveDnsInventoryQueryResult(status="ok" if value else "noerror_empty", records=_coerce_records(list(value)))
    if isinstance(value, dict):
        status_value = str(value.get("status") or "ok")
        records = _coerce_records(value.get("records") if isinstance(value.get("records"), list) else [])
        return ActiveDnsInventoryQueryResult(
            status=status_value,
            records=records,
            error_code=str(value.get("error_code")) if value.get("error_code") is not None else None,
            truncated=bool(value.get("truncated", False)),
        )
    return ActiveDnsInventoryQueryResult(status="error", error_code="dns_query_result_invalid")


def _coerce_records(value: list[Any]) -> tuple[ActiveDnsInventoryRecord, ...]:
    records: list[ActiveDnsInventoryRecord] = []
    for item in value:
        if isinstance(item, ActiveDnsInventoryRecord):
            records.append(item)
        elif isinstance(item, dict):
            record_type = str(item.get("record_type") or item.get("type") or "").upper()
            if record_type not in ACTIVE_DNS_INVENTORY_ALLOWED_RECORD_TYPES:
                continue
            name = str(item.get("name") or "")
            raw_ttl = item.get("ttl")
            raw_priority = item.get("priority")
            records.append(
                ActiveDnsInventoryRecord(
                    name=name,
                    record_type=record_type,
                    value=str(item.get("value") or ""),
                    ttl=raw_ttl if isinstance(raw_ttl, int) and raw_ttl >= 0 else None,
                    priority=raw_priority if isinstance(raw_priority, int) and raw_priority >= 0 else None,
                )
            )
    return tuple(records)


def _load_system_nameservers() -> tuple[str, ...]:
    nameservers: list[str] = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as handle:
            for line in handle:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    try:
                        ipaddress.ip_address(parts[1])
                    except ValueError:
                        continue
                    nameservers.append(parts[1])
    except OSError:
        pass
    return tuple(nameservers[:ACTIVE_DNS_INVENTORY_MAX_NAMESERVERS])


def _query_udp_dns(nameserver: str, name: str, record_type: str, *, timeout_seconds: float) -> ActiveDnsInventoryQueryResult:
    qtype = _DNS_QTYPE_BY_NAME[record_type]
    packet_id = (hash((name, record_type)) & 0xFFFF) or 1
    query = _build_dns_query(packet_id, name, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout_seconds)
        try:
            sock.sendto(query, (nameserver, _DNS_PORT))
            response, _ = sock.recvfrom(4096)
        except socket.timeout as exc:
            raise TimeoutError("dns query timed out") from exc

    return _parse_dns_response(response, packet_id, record_type)


def _build_dns_query(packet_id: int, name: str, qtype: int) -> bytes:
    header = struct.pack("!HHHHHH", packet_id, 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    question = labels + b"\x00" + struct.pack("!HH", qtype, _DNS_CLASS_IN)
    return header + question


def _parse_dns_response(packet: bytes, expected_id: int, requested_record_type: str) -> ActiveDnsInventoryQueryResult:
    if len(packet) < 12:
        raise ValueError("short dns response")
    response_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", packet[:12])
    if response_id != expected_id:
        raise ValueError("dns transaction id mismatch")
    rcode = flags & 0x000F
    truncated = bool(flags & 0x0200)
    if rcode == 3:
        return ActiveDnsInventoryQueryResult(status="nxdomain", truncated=truncated)
    if rcode != 0:
        return ActiveDnsInventoryQueryResult(status="error", error_code=f"dns_rcode_{rcode}", truncated=truncated)

    offset = 12
    for _ in range(qdcount):
        _, offset = _decode_dns_name(packet, offset)
        offset += 4

    records: list[ActiveDnsInventoryRecord] = []
    for _ in range(ancount):
        name, offset = _decode_dns_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("short dns rr")
        rr_type, rr_class, ttl, rdlength = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        rdata_offset = offset
        offset += rdlength
        if rr_class != _DNS_CLASS_IN:
            continue
        record_type = _DNS_QTYPE_BY_CODE.get(rr_type)
        if record_type not in ACTIVE_DNS_INVENTORY_ALLOWED_RECORD_TYPES:
            continue
        parsed_record = _parse_dns_record(packet, name, record_type, ttl, rdata_offset, rdlength)
        if parsed_record is not None:
            records.append(parsed_record)

    status_value = "truncated" if truncated else "ok" if records else "noerror_empty"
    return ActiveDnsInventoryQueryResult(
        status=status_value,
        records=tuple(records),
        error_code="dns_response_truncated" if truncated else None,
        truncated=truncated,
    )


def _parse_dns_record(
    packet: bytes,
    name: str,
    record_type: str,
    ttl: int,
    rdata_offset: int,
    rdlength: int,
) -> ActiveDnsInventoryRecord | None:
    rdata = packet[rdata_offset : rdata_offset + rdlength]
    try:
        if record_type == "A" and len(rdata) == 4:
            return ActiveDnsInventoryRecord(name=name, record_type=record_type, value=str(ipaddress.IPv4Address(rdata)), ttl=ttl)
        if record_type == "AAAA" and len(rdata) == 16:
            return ActiveDnsInventoryRecord(name=name, record_type=record_type, value=str(ipaddress.IPv6Address(rdata)), ttl=ttl)
        if record_type in {"CNAME", "NS"}:
            value, _ = _decode_dns_name(packet, rdata_offset)
            return ActiveDnsInventoryRecord(name=name, record_type=record_type, value=value, ttl=ttl)
        if record_type == "MX" and len(rdata) >= 3:
            priority = struct.unpack("!H", rdata[:2])[0]
            exchange, _ = _decode_dns_name(packet, rdata_offset + 2)
            return ActiveDnsInventoryRecord(name=name, record_type=record_type, value=exchange, ttl=ttl, priority=priority)
        if record_type == "TXT":
            chunks: list[str] = []
            cursor = 0
            while cursor < len(rdata):
                size = rdata[cursor]
                cursor += 1
                chunks.append(rdata[cursor : cursor + size].decode("utf-8", errors="replace"))
                cursor += size
            return ActiveDnsInventoryRecord(name=name, record_type=record_type, value="".join(chunks), ttl=ttl)
        if record_type == "SOA":
            mname, cursor = _decode_dns_name(packet, rdata_offset)
            rname, cursor = _decode_dns_name(packet, cursor)
            if cursor + 20 > len(packet):
                return None
            serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", packet[cursor : cursor + 20])
            value = f"mname={mname};rname={rname};serial={serial};refresh={refresh};retry={retry};expire={expire};minimum={minimum}"
            return ActiveDnsInventoryRecord(name=name, record_type=record_type, value=value, ttl=ttl)
        if record_type == "CAA" and len(rdata) >= 2:
            tag_length = rdata[1]
            tag = rdata[2 : 2 + tag_length].decode("ascii", errors="replace")
            caa_value = rdata[2 + tag_length :].decode("utf-8", errors="replace")
            return ActiveDnsInventoryRecord(name=name, record_type=record_type, value=f"{tag} {caa_value}".strip(), ttl=ttl)
    except (UnicodeError, ValueError, struct.error):
        return None
    return None


def _decode_dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    next_offset = offset
    seen_offsets: set[int] = set()
    while True:
        if offset >= len(packet):
            raise ValueError("dns name offset out of range")
        if offset in seen_offsets:
            raise ValueError("dns name compression loop")
        seen_offsets.add(offset)
        length = packet[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("short dns compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                next_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        if offset + length > len(packet):
            raise ValueError("short dns label")
        labels.append(packet[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
        if not jumped:
            next_offset = offset
    return ".".join(labels).rstrip(".").lower(), next_offset
