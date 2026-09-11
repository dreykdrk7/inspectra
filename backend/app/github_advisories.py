"""Defensive, component-bound normalization of one GitHub GHSA response.

This module deliberately accepts only a response for a previously normalized
GHSA identifier and a component already present in a safe OSV snapshot.  It is
not a GitHub search client and does not receive project metadata or package
identities from a request.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Literal
from urllib.parse import urlsplit

from app.cvss import assess_cvss_metric
from app.public_advisories import PublicAdvisoryRange, PublicAdvisoryReference, PublicAdvisorySeverity
from app.public_advisory_egress import PublicComponentIdentity, normalize_github_advisory_identifier, normalize_osv_component_identity
from app.version_matching import match_exact_version_against_range


GITHUB_ADVISORY_CONTRACT_VERSION = "2026-09-10.2"
MAX_GITHUB_REFERENCES = 12
MAX_GITHUB_IDENTIFIERS = 24
MAX_GITHUB_VULNERABILITIES = 24
_CVE_IDENTIFIER = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_SAFE_RANGE = re.compile(r"^[^\r\n\x00]{1,200}$")
# Closed mapping verified against GitHub's documented SecurityAdvisoryEcosystem
# vocabulary. Adding a key requires a contract bump and ecosystem fixtures.
GITHUB_ECOSYSTEM_BY_INSPECTRA = {
    "npm": "npm",
    "pypi": "pip",
    "go": "go",
    "cargo": "rust",
    "composer": "composer",
    "maven": "maven",
    "nuget": "nuget",
}


@dataclass(frozen=True)
class GithubAdvisoryCorroboration:
    contract_version: str
    provider: Literal["github_advisories"]
    provider_advisory_id: str
    aliases: tuple[str, ...]
    references: tuple[PublicAdvisoryReference, ...]
    affected_ranges: tuple[PublicAdvisoryRange, ...]
    fixed_versions: tuple[str, ...]
    severity: tuple[PublicAdvisorySeverity, ...]
    published_at: str | None
    updated_at: str | None
    withdrawn_at: str | None
    evidence_digest: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class GithubAdvisoryNormalization:
    status: Literal["ready", "not_found", "not_correlated", "invalid_source_response"]
    corroboration: GithubAdvisoryCorroboration | None = None
    errors: tuple[str, ...] = ()


def normalize_github_advisory_response(
    expected_ghsa_id: object,
    component: PublicComponentIdentity,
    payload: object,
) -> GithubAdvisoryNormalization:
    """Normalize a one-item response from the fixed GHSA list endpoint.

    A component must be named by the response and its exact version must match
    the source's range locally.  A mismatch is an explicit lack of
    corroboration, not a finding and not a replacement for OSV evidence.
    """

    ghsa_id = normalize_github_advisory_identifier(expected_ghsa_id)
    if ghsa_id is None or normalize_osv_component_identity(component) is None:
        return GithubAdvisoryNormalization("invalid_source_response", errors=("github_invalid_lookup",))
    if not isinstance(payload, list):
        return GithubAdvisoryNormalization("invalid_source_response", errors=("github_response_not_list",))
    if not payload:
        return GithubAdvisoryNormalization("not_found", errors=("github_advisory_not_found",))
    if len(payload) != 1:
        return GithubAdvisoryNormalization("invalid_source_response", errors=("github_result_count_invalid",))
    corroboration = _normalize_github_advisory(ghsa_id, component, payload[0])
    if corroboration is None:
        return GithubAdvisoryNormalization("not_correlated", errors=("github_advisory_not_correlated",))
    return GithubAdvisoryNormalization("ready", corroboration=corroboration)


def _normalize_github_advisory(
    expected_ghsa_id: str,
    component: PublicComponentIdentity,
    raw: object,
) -> GithubAdvisoryCorroboration | None:
    if not isinstance(raw, dict):
        return None
    provider_advisory_id = normalize_github_advisory_identifier(raw.get("ghsa_id"))
    if provider_advisory_id != expected_ghsa_id:
        return None
    affected_ranges, fixed_versions = _matching_component_ranges(component, raw.get("vulnerabilities"))
    if not affected_ranges:
        return None
    aliases = _aliases(provider_advisory_id, raw.get("cve_id"), raw.get("identifiers"))
    references = _references(provider_advisory_id, raw.get("html_url"), raw.get("references"))
    severity = _severity(raw)
    published_at = _timestamp(raw.get("published_at"))
    updated_at = _timestamp(raw.get("updated_at"))
    withdrawn_at = _timestamp(raw.get("withdrawn_at"))
    evidence = {
        "provider": "github_advisories",
        "provider_advisory_id": provider_advisory_id,
        "component": asdict(component),
        "aliases": aliases,
        "references": [asdict(value) for value in references],
        "affected_ranges": [asdict(value) for value in affected_ranges],
        "fixed_versions": fixed_versions,
        "severity": [asdict(value) for value in severity],
        "published_at": published_at,
        "updated_at": updated_at,
        "withdrawn_at": withdrawn_at,
    }
    return GithubAdvisoryCorroboration(
        contract_version=GITHUB_ADVISORY_CONTRACT_VERSION,
        provider="github_advisories",
        provider_advisory_id=provider_advisory_id,
        aliases=aliases,
        references=references,
        affected_ranges=affected_ranges,
        fixed_versions=fixed_versions,
        severity=severity,
        published_at=published_at,
        updated_at=updated_at,
        withdrawn_at=withdrawn_at,
        evidence_digest=hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest(),
    )


def _matching_component_ranges(
    component: PublicComponentIdentity,
    raw_vulnerabilities: object,
) -> tuple[tuple[PublicAdvisoryRange, ...], tuple[str, ...]]:
    # Unsupported mappings remain uncorroborated; there is no inferred fallback.
    github_ecosystem = GITHUB_ECOSYSTEM_BY_INSPECTRA.get(component.ecosystem)
    if github_ecosystem is None:
        return (), ()
    expected = normalize_osv_component_identity(component)
    if expected is None or not isinstance(raw_vulnerabilities, list) or len(raw_vulnerabilities) > MAX_GITHUB_VULNERABILITIES:
        return (), ()
    expected_name = expected["package"]["name"]
    ranges: list[PublicAdvisoryRange] = []
    fixed_versions: set[str] = set()
    for raw_vulnerability in raw_vulnerabilities:
        if not isinstance(raw_vulnerability, dict):
            continue
        package = raw_vulnerability.get("package")
        if not isinstance(package, dict) or package.get("ecosystem") != github_ecosystem:
            continue
        package_name = _normalized_package_name(component, package.get("name"))
        if package_name != expected_name:
            continue
        expression = _safe_range(raw_vulnerability.get("vulnerable_version_range"))
        if expression is None:
            continue
        match = match_exact_version_against_range(component.ecosystem, component.version, expression)
        if match.status != "matched":
            continue
        fixed = _first_patched_version(raw_vulnerability.get("first_patched_version"))
        ranges.append(PublicAdvisoryRange("ECOSYSTEM", fixed=fixed, expression=expression))
        if fixed is not None:
            fixed_versions.add(fixed)
    return tuple(ranges), tuple(sorted(fixed_versions))


def _normalized_package_name(component: PublicComponentIdentity, value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = PublicComponentIdentity(ecosystem=component.ecosystem, name=value, version=component.version)
    normalized = normalize_osv_component_identity(candidate)
    return normalized["package"]["name"] if normalized is not None else None


def _safe_range(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized if _SAFE_RANGE.fullmatch(normalized) else None


def _first_patched_version(value: object) -> str | None:
    if not isinstance(value, dict):
        return None
    identifier = value.get("identifier")
    if not isinstance(identifier, str):
        return None
    normalized = identifier.strip()
    return normalized if _SAFE_RANGE.fullmatch(normalized) else None


def _aliases(ghsa_id: str, cve_id: object, identifiers: object) -> tuple[str, ...]:
    values = {ghsa_id}
    candidates = [cve_id]
    if isinstance(identifiers, list):
        candidates.extend(identifiers)
    for candidate in candidates:
        value = candidate.get("value") if isinstance(candidate, dict) else candidate
        if not isinstance(value, str):
            continue
        normalized_ghsa = normalize_github_advisory_identifier(value)
        if normalized_ghsa is not None:
            values.add(normalized_ghsa)
        elif _CVE_IDENTIFIER.fullmatch(value.strip()):
            values.add(value.strip().upper())
        if len(values) >= MAX_GITHUB_IDENTIFIERS:
            break
    return tuple(sorted(values))


def _references(ghsa_id: str, html_url: object, raw_references: object) -> tuple[PublicAdvisoryReference, ...]:
    values = [PublicAdvisoryReference("source", f"https://github.com/advisories/{ghsa_id}")]
    # The canonical GitHub advisory link is reconstructed from the validated
    # identifier. Do not trust or retain a provider-supplied HTML URL merely
    # because it happens to look similar.
    _ = html_url
    candidates: list[object] = []
    if isinstance(raw_references, list):
        candidates.extend(raw_references)
    for value in candidates:
        url = _safe_https_url(value)
        if url is not None and url not in {reference.url for reference in values}:
            values.append(PublicAdvisoryReference("reference", url))
        if len(values) >= MAX_GITHUB_REFERENCES:
            break
    return tuple(values)


def _severity(raw: dict[str, Any]) -> tuple[PublicAdvisorySeverity, ...]:
    values: list[PublicAdvisorySeverity] = []
    raw_severities = raw.get("cvss_severities")
    if isinstance(raw_severities, dict):
        for kind, key in (("CVSS_V3", "cvss_v3"), ("CVSS_V4", "cvss_v4")):
            metric = raw_severities.get(key)
            normalized = _source_metric(kind, metric)
            if normalized is not None:
                values.append(normalized)
    if not values:
        fallback = _source_metric("CVSS_V3", raw.get("cvss"))
        if fallback is not None:
            values.append(fallback)
    return tuple(sorted(set(values), key=lambda value: (value.kind, value.vector, value.base_score or -1)))


def _source_metric(kind: str, raw: object) -> PublicAdvisorySeverity | None:
    if not isinstance(raw, dict):
        return None
    vector = raw.get("vector_string")
    score = raw.get("score")
    if not isinstance(vector, str) or len(vector) > 256 or any(character.isspace() for character in vector):
        return None
    assessment = assess_cvss_metric(kind, vector, source_score=score)
    if assessment is None:
        return None
    return PublicAdvisorySeverity(
        kind,
        vector,
        assessment.base_score,
        assessment.band,
        assessment.score_status,
        assessment.version,
    )


def _timestamp(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_https_url(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 2048 or any(ord(character) < 32 for character in value):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return None
    if port not in {None, 443} or parsed.fragment or any(character.isspace() for character in value):
        return None
    return value
