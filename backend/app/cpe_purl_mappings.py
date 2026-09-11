"""Reviewed CPE-to-package identity mappings with no heuristic fallback.

NVD CPE data is product-centric and is not a package vulnerability signal.
This module can only corroborate an identity relationship when code-reviewed
policy binds an exact ecosystem/name, CPE part/vendor/product and CVE.  It does
not evaluate affected versions and must never create a finding.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable, Literal

from app.cisa_kev import normalize_cve_identifier


CPE_PURL_MAPPING_POLICY_VERSION = "2026-09-09.1"
MAX_CPE_MAPPING_ENTRIES = 256
_MAPPING_ID = re.compile(r"^cpe-map-[a-z0-9][a-z0-9-]{2,63}$")
_CPE_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_ECOSYSTEM = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")


@dataclass(frozen=True)
class ReviewedCpePurlMapping:
    mapping_id: str
    ecosystem: str
    package_name: str
    cpe_part: Literal["a", "o", "h"]
    cpe_vendor: str
    cpe_product: str
    cve_ids: tuple[str, ...]


@dataclass(frozen=True)
class CpeIdentityAssessment:
    status: Literal["not_present", "present_unmapped", "identity_corroborated"]
    match_count: int
    corroborated_match_count: int
    mapping_ids: tuple[str, ...]
    policy_version: str = CPE_PURL_MAPPING_POLICY_VERSION


class CpePurlMappingPolicy:
    """Immutable, bounded registry. Invalid or ambiguous policy fails closed."""

    def __init__(self, entries: Iterable[ReviewedCpePurlMapping] = ()) -> None:
        retained = tuple(entries)
        if len(retained) > MAX_CPE_MAPPING_ENTRIES:
            raise ValueError("too many CPE mapping entries")
        keys: set[tuple[str, str, str, str, str]] = set()
        ids: set[str] = set()
        normalized: list[ReviewedCpePurlMapping] = []
        for entry in retained:
            candidate = _normalize_entry(entry)
            key = (
                candidate.ecosystem,
                candidate.package_name,
                candidate.cpe_part,
                candidate.cpe_vendor,
                candidate.cpe_product,
            )
            if candidate.mapping_id in ids or key in keys:
                raise ValueError("duplicate or ambiguous CPE mapping entry")
            ids.add(candidate.mapping_id)
            keys.add(key)
            normalized.append(candidate)
        self._entries = tuple(sorted(normalized, key=lambda item: item.mapping_id))

    def assess(
        self,
        *,
        ecosystem: object,
        package_name: object,
        cve_id: object,
        cpe_criteria: Iterable[object],
    ) -> CpeIdentityAssessment:
        normalized_ecosystem = ecosystem.strip().lower() if isinstance(ecosystem, str) else ""
        normalized_name = package_name.strip() if isinstance(package_name, str) else ""
        normalized_cve = normalize_cve_identifier(cve_id)
        candidates = tuple(cpe_criteria)
        parsed = tuple(value for raw in candidates if (value := _parse_cpe_identity(raw)) is not None)
        if not candidates:
            return CpeIdentityAssessment("not_present", 0, 0, ())
        if not _ECOSYSTEM.fullmatch(normalized_ecosystem) or not normalized_name or normalized_cve is None:
            return CpeIdentityAssessment("present_unmapped", len(candidates), 0, ())

        matched: set[str] = set()
        for entry in self._entries:
            if (
                entry.ecosystem == normalized_ecosystem
                and entry.package_name == normalized_name
                and normalized_cve in entry.cve_ids
                and (entry.cpe_part, entry.cpe_vendor, entry.cpe_product) in parsed
            ):
                matched.add(entry.mapping_id)
        return CpeIdentityAssessment(
            "identity_corroborated" if matched else "present_unmapped",
            len(candidates),
            sum(1 for value in parsed if any(
                entry.mapping_id in matched
                and (entry.cpe_part, entry.cpe_vendor, entry.cpe_product) == value
                for entry in self._entries
            )),
            tuple(sorted(matched)),
        )


def _normalize_entry(entry: ReviewedCpePurlMapping) -> ReviewedCpePurlMapping:
    if not isinstance(entry, ReviewedCpePurlMapping) or not _MAPPING_ID.fullmatch(entry.mapping_id):
        raise ValueError("invalid CPE mapping id")
    ecosystem = entry.ecosystem.strip().lower()
    package_name = entry.package_name.strip()
    vendor = entry.cpe_vendor.strip().lower()
    product = entry.cpe_product.strip().lower()
    if not _ECOSYSTEM.fullmatch(ecosystem) or not package_name or len(package_name) > 214:
        raise ValueError("invalid mapped package identity")
    if entry.cpe_part not in {"a", "o", "h"} or not _CPE_TOKEN.fullmatch(vendor) or not _CPE_TOKEN.fullmatch(product):
        raise ValueError("invalid mapped CPE identity")
    cves = tuple(sorted({value for raw in entry.cve_ids if (value := normalize_cve_identifier(raw)) is not None}))
    if not cves or len(cves) != len(set(entry.cve_ids)) or len(cves) > 64:
        raise ValueError("invalid mapped CVE set")
    return ReviewedCpePurlMapping(entry.mapping_id, ecosystem, package_name, entry.cpe_part, vendor, product, cves)


def _parse_cpe_identity(value: object) -> tuple[str, str, str] | None:
    """Read only unescaped CPE 2.3 identity fields; ambiguous forms stay unmapped."""

    if not isinstance(value, str) or len(value) > 1_024 or "\\" in value:
        return None
    parts = value.split(":")
    if len(parts) != 13 or parts[:2] != ["cpe", "2.3"]:
        return None
    part, vendor, product = parts[2:5]
    if part not in {"a", "o", "h"} or not _CPE_TOKEN.fullmatch(vendor) or not _CPE_TOKEN.fullmatch(product):
        return None
    return part, vendor, product


# Deliberately empty until a real mapping has primary-source evidence and code
# review. Consumers may inject a reviewed immutable policy; there is no runtime
# user input or name-derived fallback.
DEFAULT_CPE_PURL_MAPPING_POLICY = CpePurlMappingPolicy()
