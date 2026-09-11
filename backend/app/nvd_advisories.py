"""CVE-bound normalization of the NVD CVE API 2.0 response.

NVD can enrich an exact CVE already correlated by OSV/GHSA. It never creates a
package finding and this module deliberately discards CPE values, descriptions,
provider account identifiers, and arbitrary product metadata.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Literal

from app.cisa_kev import normalize_cve_identifier
from app.cpe_purl_mappings import (
    CPE_PURL_MAPPING_POLICY_VERSION,
    DEFAULT_CPE_PURL_MAPPING_POLICY,
    CpePurlMappingPolicy,
)
from app.cvss import assess_cvss_metric
from app.public_advisories import PublicAdvisoryReference, PublicAdvisorySeverity


NVD_ADVISORY_CONTRACT_VERSION = "2026-09-09.2"
MAX_NVD_METRICS = 16
MAX_NVD_WEAKNESSES = 32
MAX_NVD_CONFIGURATIONS = 64
MAX_NVD_CPE_MATCHES = 2_000
_CWE = re.compile(r"^CWE-(?:[1-9]\d{0,5})$")


@dataclass(frozen=True)
class NvdCveEvidence:
    contract_version: str
    provider: Literal["nvd"]
    cve_id: str
    status: Literal["analyzed", "modified", "rejected", "under_analysis", "deferred", "unknown"]
    severity: tuple[PublicAdvisorySeverity, ...]
    cwes: tuple[str, ...]
    cpe_status: Literal["not_present", "present_unmapped", "identity_corroborated"]
    cpe_match_count: int
    cpe_corroborated_match_count: int
    cpe_mapping_ids: tuple[str, ...]
    cpe_mapping_policy_version: str
    references: tuple[PublicAdvisoryReference, ...]
    published_at: str | None
    updated_at: str | None
    evidence_digest: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class NvdCveNormalization:
    status: Literal["ready", "not_found", "invalid_source_response"]
    evidence: NvdCveEvidence | None = None
    errors: tuple[str, ...] = ()


def normalize_nvd_cve_response(
    expected_cve_id: object,
    payload: object,
    *,
    component_ecosystem: object = None,
    component_name: object = None,
    mapping_policy: CpePurlMappingPolicy = DEFAULT_CPE_PURL_MAPPING_POLICY,
) -> NvdCveNormalization:
    cve_id = normalize_cve_identifier(expected_cve_id)
    if cve_id is None:
        return NvdCveNormalization("invalid_source_response", errors=("nvd_invalid_cve_lookup",))
    if not isinstance(payload, dict) or payload.get("format") != "NVD_CVE" or payload.get("version") != "2.0":
        return NvdCveNormalization("invalid_source_response", errors=("nvd_response_contract_invalid",))
    vulnerabilities = payload.get("vulnerabilities")
    total = payload.get("totalResults")
    if total == 0 and vulnerabilities == []:
        return NvdCveNormalization("not_found", errors=("nvd_cve_not_found",))
    if total != 1 or not isinstance(vulnerabilities, list) or len(vulnerabilities) != 1:
        return NvdCveNormalization("invalid_source_response", errors=("nvd_result_count_invalid",))
    wrapper = vulnerabilities[0]
    raw = wrapper.get("cve") if isinstance(wrapper, dict) else None
    if not isinstance(raw, dict) or normalize_cve_identifier(raw.get("id")) != cve_id:
        return NvdCveNormalization("invalid_source_response", errors=("nvd_cve_mismatch",))

    severity = _severity(raw.get("metrics"))
    cwes = _cwes(raw.get("weaknesses"))
    cpe_criteria = _cpe_criteria(raw.get("configurations"))
    if cpe_criteria is None:
        return NvdCveNormalization("invalid_source_response", errors=("nvd_configurations_invalid",))
    assessment = mapping_policy.assess(
        ecosystem=component_ecosystem,
        package_name=component_name,
        cve_id=cve_id,
        cpe_criteria=cpe_criteria,
    )
    source_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    references = (PublicAdvisoryReference("source", source_url),)
    evidence_values = {
        "provider": "nvd",
        "cve_id": cve_id,
        "status": _status(raw.get("vulnStatus")),
        "severity": [asdict(value) for value in severity],
        "cwes": cwes,
        "cpe_status": assessment.status,
        "cpe_match_count": assessment.match_count,
        "cpe_corroborated_match_count": assessment.corroborated_match_count,
        "cpe_mapping_ids": assessment.mapping_ids,
        "cpe_mapping_policy_version": assessment.policy_version,
        "references": [asdict(value) for value in references],
        "published_at": _timestamp(raw.get("published")),
        "updated_at": _timestamp(raw.get("lastModified")),
    }
    digest = hashlib.sha256(json.dumps(evidence_values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return NvdCveNormalization(
        "ready",
        evidence=NvdCveEvidence(
            contract_version=NVD_ADVISORY_CONTRACT_VERSION,
            evidence_digest=digest,
            provider="nvd",
            cve_id=cve_id,
            status=evidence_values["status"],
            severity=severity,
            cwes=cwes,
            cpe_status=evidence_values["cpe_status"],
            cpe_match_count=assessment.match_count,
            cpe_corroborated_match_count=assessment.corroborated_match_count,
            cpe_mapping_ids=assessment.mapping_ids,
            cpe_mapping_policy_version=CPE_PURL_MAPPING_POLICY_VERSION,
            references=references,
            published_at=evidence_values["published_at"],
            updated_at=evidence_values["updated_at"],
        ),
    )


def _severity(raw: object) -> tuple[PublicAdvisorySeverity, ...]:
    if not isinstance(raw, dict):
        return ()
    values: list[PublicAdvisorySeverity] = []
    for key, kind, expected_version in (
        ("cvssMetricV40", "CVSS_V4", "4.0"),
        ("cvssMetricV31", "CVSS_V3", "3.1"),
        ("cvssMetricV30", "CVSS_V3", "3.0"),
    ):
        entries = raw.get(key, [])
        if not isinstance(entries, list) or len(entries) > MAX_NVD_METRICS:
            continue
        for entry in entries:
            data = entry.get("cvssData") if isinstance(entry, dict) else None
            if not isinstance(data, dict) or data.get("version") != expected_version:
                continue
            vector = data.get("vectorString")
            assessment = assess_cvss_metric(kind, vector, source_score=data.get("baseScore"))
            if assessment is None or assessment.version != expected_version:
                continue
            values.append(PublicAdvisorySeverity(
                kind=kind,
                vector=vector,
                base_score=assessment.base_score,
                band=assessment.band,
                score_status=assessment.score_status,
                cvss_version=assessment.version,
            ))
    return tuple(sorted(set(values), key=lambda value: (value.cvss_version or "", value.vector, value.base_score or -1)))


def _cwes(raw: object) -> tuple[str, ...]:
    if not isinstance(raw, list) or len(raw) > MAX_NVD_WEAKNESSES:
        return ()
    values: set[str] = set()
    for group in raw:
        descriptions = group.get("description") if isinstance(group, dict) else None
        if not isinstance(descriptions, list) or len(descriptions) > MAX_NVD_WEAKNESSES:
            continue
        for description in descriptions:
            value = description.get("value") if isinstance(description, dict) else None
            if isinstance(value, str) and _CWE.fullmatch(value):
                values.add(value)
    return tuple(sorted(values))


def _cpe_criteria(raw: object) -> tuple[str, ...] | None:
    if raw is None:
        return ()
    if not isinstance(raw, list) or len(raw) > MAX_NVD_CONFIGURATIONS:
        return None
    criteria_values: list[str] = []
    pending: list[object] = list(raw)
    visited = 0
    while pending:
        value = pending.pop()
        visited += 1
        if visited > MAX_NVD_CPE_MATCHES * 4:
            return None
        if not isinstance(value, dict):
            return None
        matches = value.get("cpeMatch", [])
        nodes = value.get("nodes", [])
        if not isinstance(matches, list) or not isinstance(nodes, list):
            return None
        if len(matches) + len(criteria_values) > MAX_NVD_CPE_MATCHES:
            return None
        for match in matches:
            if not isinstance(match, dict):
                return None
            criteria = match.get("criteria")
            if isinstance(criteria, str) and criteria.startswith("cpe:2.3:"):
                criteria_values.append(criteria)
        pending.extend(nodes)
    return tuple(criteria_values)


def _status(value: object) -> Literal["analyzed", "modified", "rejected", "under_analysis", "deferred", "unknown"]:
    normalized = value.strip().lower() if isinstance(value, str) else ""
    return {
        "analyzed": "analyzed",
        "modified": "modified",
        "rejected": "rejected",
        "awaiting analysis": "under_analysis",
        "undergoing analysis": "under_analysis",
        "received": "under_analysis",
        "deferred": "deferred",
    }.get(normalized, "unknown")


def _timestamp(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
