"""Versioned, defensive normalization for public advisory provider payloads."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Literal
from urllib.parse import urlsplit

from app.cvss import CvssBand, CvssScoreStatus, CvssVersion, assess_cvss_metric
from app.public_advisory_egress import (
    MAX_OSV_VULNERABILITIES_PER_QUERY,
    PublicComponentIdentity,
    normalize_osv_component_identity,
)
from app.version_matching import canonicalize_nuget_version


PUBLIC_ADVISORY_CONTRACT_VERSION = "2026-09-09.1"
MAX_OSV_RANGES_PER_ADVISORY = 25
MAX_OSV_EVENTS_PER_RANGE = MAX_OSV_RANGES_PER_ADVISORY * 2
MAX_OSV_REFERENCES_PER_ADVISORY = 12
MAX_OSV_ALIASES_PER_ADVISORY = 24
_ADVISORY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_GHSA_ID = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.IGNORECASE)
_RANGE_EVENT_VERSION = re.compile(r"^[^\s/\\?#@]{1,200}$")


@dataclass(frozen=True)
class PublicAdvisoryReference:
    kind: Literal["source", "reference"]
    url: str


@dataclass(frozen=True)
class PublicAdvisoryRange:
    range_type: Literal["SEMVER", "ECOSYSTEM", "GIT", "UNKNOWN"]
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    expression: str | None = None


@dataclass(frozen=True)
class PublicAdvisorySeverity:
    kind: str
    vector: str
    base_score: float | None
    band: CvssBand
    score_status: CvssScoreStatus
    cvss_version: CvssVersion | None = None


@dataclass(frozen=True)
class PublicAdvisory:
    """Safe subset of one advisory affecting one exact public component."""

    contract_version: str
    provider: Literal["osv"]
    provider_advisory_id: str
    component: PublicComponentIdentity
    aliases: tuple[str, ...]
    references: tuple[PublicAdvisoryReference, ...]
    affected_ranges: tuple[PublicAdvisoryRange, ...]
    fixed_versions: tuple[str, ...]
    severity: tuple[PublicAdvisorySeverity, ...]
    published_at: str | None
    updated_at: str | None
    withdrawn_at: str | None
    evidence_digest: str
    # ``False`` means that OSV exposed an affected package but at least one
    # interval could not be retained safely. Callers must keep the decision
    # unknown instead of treating the retained subset as complete coverage.
    affected_ranges_complete: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PublicAdvisoryNormalization:
    status: Literal["ready", "invalid_source_response"]
    advisories: tuple[PublicAdvisory, ...] = ()
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class _OsvRangeNormalization:
    ranges: tuple[PublicAdvisoryRange, ...]
    complete: bool


def normalize_osv_batch_response(
    components: list[PublicComponentIdentity],
    payload: object,
) -> PublicAdvisoryNormalization:
    """Normalize OSV ``querybatch`` data without trusting its JSON shape.

    Each result is bound to the exact submitted component by its position. A
    malformed result cannot become a clean result: callers receive an explicit
    controlled error and must surface degraded coverage instead.
    """

    queries = [normalize_osv_component_identity(component) for component in components]
    if not components or any(query is None for query in queries):
        return PublicAdvisoryNormalization("invalid_source_response", errors=("invalid_component_identity",))
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        return PublicAdvisoryNormalization("invalid_source_response", errors=("osv_results_missing",))
    raw_results = payload["results"]
    if len(raw_results) != len(components):
        return PublicAdvisoryNormalization("invalid_source_response", errors=("osv_result_count_mismatch",))

    advisories: list[PublicAdvisory] = []
    errors: set[str] = set()
    for component, raw_result in zip(components, raw_results, strict=True):
        if not isinstance(raw_result, dict):
            errors.add("osv_result_invalid")
            continue
        raw_vulnerabilities = raw_result.get("vulns")
        if not isinstance(raw_vulnerabilities, list) or len(raw_vulnerabilities) > MAX_OSV_VULNERABILITIES_PER_QUERY:
            errors.add("osv_vulnerabilities_invalid")
            continue
        for raw_vulnerability in raw_vulnerabilities:
            advisory = normalize_osv_advisory(component, raw_vulnerability)
            if advisory is None:
                errors.add("osv_advisory_invalid_or_unrelated")
                continue
            advisories.append(advisory)

    # Identical repeated entries can be collapsed. Entries with different range,
    # timestamp, severity, or source evidence have a distinct evidence digest and
    # deliberately remain separate instead of being silently merged.
    deduplicated = {advisory.evidence_digest: advisory for advisory in advisories}
    status: Literal["ready", "invalid_source_response"] = "ready" if not errors else "invalid_source_response"
    return PublicAdvisoryNormalization(
        status,
        tuple(sorted(deduplicated.values(), key=lambda item: (item.provider_advisory_id, item.evidence_digest))),
        tuple(sorted(errors)),
    )


def normalize_osv_advisory(component: PublicComponentIdentity, raw: object) -> PublicAdvisory | None:
    if not isinstance(raw, dict):
        return None
    provider_advisory_id = _safe_advisory_id(raw.get("id"))
    expected_package = normalize_osv_component_identity(component)
    if provider_advisory_id is None or expected_package is None:
        return None
    range_normalization = _matching_osv_ranges(
        raw.get("affected"), expected_package["package"], component.ecosystem
    )
    if range_normalization is None:
        return None
    affected_ranges = range_normalization.ranges
    aliases = _normalize_aliases(raw.get("aliases"))
    references = _normalize_references(provider_advisory_id, raw.get("references"))
    severity = _normalize_severity(raw.get("severity"))
    published_at = _safe_timestamp(raw.get("published"))
    updated_at = _safe_timestamp(raw.get("modified"))
    withdrawn_at = _safe_timestamp(raw.get("withdrawn"))
    fixed_versions = tuple(sorted({item.fixed for item in affected_ranges if item.fixed}))
    evidence = {
        "provider": "osv",
        "provider_advisory_id": provider_advisory_id,
        "component": asdict(component),
        "aliases": aliases,
        "references": [asdict(item) for item in references],
        "affected_ranges": [asdict(item) for item in affected_ranges],
        "affected_ranges_complete": range_normalization.complete,
        "fixed_versions": fixed_versions,
        "severity": [asdict(item) for item in severity],
        "published_at": published_at,
        "updated_at": updated_at,
        "withdrawn_at": withdrawn_at,
    }
    evidence_digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return PublicAdvisory(
        contract_version=PUBLIC_ADVISORY_CONTRACT_VERSION,
        provider="osv",
        provider_advisory_id=provider_advisory_id,
        component=component,
        aliases=aliases,
        references=references,
        affected_ranges=affected_ranges,
        fixed_versions=fixed_versions,
        severity=severity,
        published_at=published_at,
        updated_at=updated_at,
        withdrawn_at=withdrawn_at,
        evidence_digest=evidence_digest,
        affected_ranges_complete=range_normalization.complete,
    )


def _matching_osv_ranges(
    raw_affected: object,
    expected_package: dict[str, str],
    component_ecosystem: str,
) -> _OsvRangeNormalization | None:
    if not isinstance(raw_affected, list):
        return None
    ranges: list[PublicAdvisoryRange] = []
    matched_package = False
    complete = True
    for raw_entry in raw_affected:
        if not isinstance(raw_entry, dict):
            continue
        raw_package = raw_entry.get("package")
        if not isinstance(raw_package, dict):
            continue
        if raw_package.get("ecosystem") != expected_package["ecosystem"] or raw_package.get("name") != expected_package["name"]:
            continue
        matched_package = True
        raw_ranges = raw_entry.get("ranges")
        if not isinstance(raw_ranges, list):
            complete = False
            continue
        for raw_range in raw_ranges:
            normalized = _normalize_osv_range(raw_range, component_ecosystem=component_ecosystem)
            if normalized is None:
                complete = False
                continue
            if len(ranges) + len(normalized) > MAX_OSV_RANGES_PER_ADVISORY:
                # Never silently keep a prefix of a discontinuous range: an
                # omitted later interval could contain the installed version.
                complete = False
                continue
            ranges.extend(normalized)
    if not matched_package:
        return None
    return _OsvRangeNormalization(tuple(ranges), complete)


def _normalize_osv_range(
    raw: object, *, component_ecosystem: str
) -> tuple[PublicAdvisoryRange, ...] | None:
    if not isinstance(raw, dict) or not isinstance(raw.get("events"), list):
        return None
    if len(raw["events"]) > MAX_OSV_EVENTS_PER_RANGE:
        return None
    type_value = raw.get("type") if isinstance(raw.get("type"), str) else "UNKNOWN"
    range_type: Literal["SEMVER", "ECOSYSTEM", "GIT", "UNKNOWN"] = (
        type_value if type_value in {"SEMVER", "ECOSYSTEM", "GIT"} else "UNKNOWN"
    )
    active_introduced: str | None = None
    intervals: list[PublicAdvisoryRange] = []
    for raw_event in raw["events"]:
        if not isinstance(raw_event, dict):
            return None
        values = []
        for kind in ("introduced", "fixed", "last_affected"):
            if kind not in raw_event:
                continue
            normalized = _safe_range_version(raw_event.get(kind))
            if normalized is None:
                return None
            if component_ecosystem == "nuget" and not (kind == "introduced" and normalized == "0"):
                normalized = canonicalize_nuget_version(normalized)
                if normalized is None:
                    return None
            values.append((kind, normalized))
        if len(values) != 1:
            return None
        kind, value = values[0]
        if kind == "introduced":
            if active_introduced is not None:
                return None
            active_introduced = value
            continue
        if active_introduced is None:
            # Do not invent an implicit lower bound for an out-of-order feed.
            return None
        intervals.append(
            PublicAdvisoryRange(
                range_type,
                introduced=active_introduced,
                fixed=value if kind == "fixed" else None,
                last_affected=value if kind == "last_affected" else None,
            )
        )
        active_introduced = None
    if active_introduced is not None:
        intervals.append(PublicAdvisoryRange(range_type, introduced=active_introduced))
    return tuple(intervals) or None


def _normalize_aliases(raw: object) -> tuple[str, ...]:
    if not isinstance(raw, list):
        return ()
    aliases = []
    for value in raw:
        normalized = _safe_advisory_id(value)
        if normalized and (_CVE_ID.fullmatch(normalized) or _GHSA_ID.fullmatch(normalized)):
            aliases.append(normalized.upper() if normalized.upper().startswith("CVE-") else normalized.upper())
        if len(aliases) >= MAX_OSV_ALIASES_PER_ADVISORY:
            break
    return tuple(sorted(set(aliases)))


def _normalize_references(advisory_id: str, raw: object) -> tuple[PublicAdvisoryReference, ...]:
    references = [PublicAdvisoryReference("source", f"https://osv.dev/vulnerability/{advisory_id}")]
    if not isinstance(raw, list):
        return tuple(references)
    for item in raw:
        if not isinstance(item, dict):
            continue
        url = _safe_https_url(item.get("url"))
        if url is not None and url not in {reference.url for reference in references}:
            references.append(PublicAdvisoryReference("reference", url))
        if len(references) >= MAX_OSV_REFERENCES_PER_ADVISORY:
            break
    return tuple(references)


def _normalize_severity(raw: object) -> tuple[PublicAdvisorySeverity, ...]:
    if not isinstance(raw, list):
        return ()
    values = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        vector = item.get("score")
        if not isinstance(kind, str) or not isinstance(vector, str):
            continue
        if len(kind) > 32 or len(vector) > 256 or any(character.isspace() for character in vector):
            continue
        assessment = assess_cvss_metric(kind, vector)
        if assessment is None:
            continue
        values.append(
            PublicAdvisorySeverity(
                kind=kind.upper(),
                vector=vector,
                base_score=assessment.base_score,
                band=assessment.band,
                score_status=assessment.score_status,
                cvss_version=assessment.version,
            )
        )
    return tuple(sorted(set(values), key=lambda item: (item.kind, item.vector, item.base_score or -1)))


def _safe_advisory_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized if _ADVISORY_ID.fullmatch(normalized) else None


def _safe_range_version(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized if _RANGE_EVENT_VERSION.fullmatch(normalized) else None


def _safe_timestamp(value: object) -> str | None:
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
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
    ):
        return None
    return value
