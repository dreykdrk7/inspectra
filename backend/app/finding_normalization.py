from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlsplit


NORMALIZED_FINDINGS_CONTRACT_VERSION = "2026-09-05.1"
SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
CONFIDENCE_LEVELS = frozenset({"high", "medium", "low"})
REFERENCE_TYPES = frozenset({"cve", "ghsa", "owasp"})
CVE_IDENTIFIER_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
GHSA_IDENTIFIER_PATTERN = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.IGNORECASE)
OWASP_IDENTIFIER_PATTERN = re.compile(r"^(?:A\d{2}:\d{4}|OWASP-[A-Z0-9_.:-]+)$", re.IGNORECASE)


def normalize_result_findings(audit_type: str, result: dict[str, Any]) -> dict[str, Any]:
    """Add a conservative cross-analyzer finding view without replacing source data.

    This is intentionally a compatibility layer. Unknown fields and unsupported
    references remain in the original result rather than being guessed into a
    product contract.
    """

    candidates = list(finding_candidates(result))
    if not candidates:
        return result

    normalized = dict(result)
    findings: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for finding, index, default_path in candidates:
        item = normalized_finding(audit_type, finding, index, default_path=default_path)
        if item["id"] in seen_ids:
            continue
        seen_ids.add(item["id"])
        findings.append(item)

    normalized["normalized_findings_contract_version"] = NORMALIZED_FINDINGS_CONTRACT_VERSION
    normalized["normalized_findings"] = findings
    normalized["normalized_findings_summary"] = normalized_findings_summary(findings)
    return normalized


def finding_candidates(result: dict[str, Any]):
    """Yield source findings while avoiding archive manifest duplicates.

    Project archive analysis keeps parser findings both in the top-level list and
    below their parsed manifest. The nested copy is preferred because it carries
    the actual manifest path; other top-level findings remain intact.
    """

    nested_signatures: set[tuple[str, str]] = set()
    nested: list[tuple[dict[str, Any], str]] = []
    parsed_manifests = result.get("parsed_manifests")
    if isinstance(parsed_manifests, list):
        for manifest in parsed_manifests:
            if not isinstance(manifest, dict):
                continue
            path = text_value(manifest.get("path"))
            manifest_findings = manifest.get("findings")
            if not isinstance(manifest_findings, list):
                continue
            for finding in manifest_findings:
                if not isinstance(finding, dict):
                    continue
                nested.append((finding, path))
                rule_id = text_value(finding.get("id"))
                evidence = text_value(finding.get("evidence"))
                if rule_id:
                    nested_signatures.add((rule_id, scoped_evidence(path, evidence)))

    raw_findings = result.get("findings")
    if isinstance(raw_findings, list):
        for index, finding in enumerate(raw_findings):
            if not isinstance(finding, dict):
                continue
            rule_id = text_value(finding.get("id"))
            evidence = text_value(finding.get("evidence"))
            if rule_id and (rule_id, evidence) in nested_signatures:
                continue
            yield finding, index, ""

    offset = len(raw_findings) if isinstance(raw_findings, list) else 0
    for index, (finding, path) in enumerate(nested, start=offset):
        yield finding, index, path


def normalized_finding(
    audit_type: str,
    finding: dict[str, Any],
    index: int,
    *,
    default_path: str = "",
) -> dict[str, Any]:
    rule_id = text_value(finding.get("id")) or f"{audit_type}.unclassified.{index + 1}"
    raw_path = (
        text_value(finding.get("path"))
        or text_value(finding.get("file"))
        or text_value(finding.get("file_path"))
        or default_path
    )
    path = normalize_project_relative_path(raw_path) if raw_path else None
    evidence = text_value(finding.get("evidence"))
    line = positive_int(finding.get("line")) or positive_int(finding.get("line_number"))
    severity = normalized_severity(finding.get("severity"))
    confidence = normalized_confidence(finding.get("confidence"))
    unsafe_path_withheld = bool(raw_path) and path is None
    location = {"path": path, "line": line} if path or (line and not unsafe_path_withheld) else None
    location_status = "withheld_unsafe_path" if unsafe_path_withheld else "reported" if location else "not_reported"

    return {
        "id": stable_finding_id(audit_type, rule_id, path or "", line if not unsafe_path_withheld else None, evidence),
        "rule_id": rule_id,
        "source_audit_type": audit_type,
        "title": text_value(finding.get("title")) or "Unclassified review indicator",
        "category": text_value(finding.get("category")) or "uncategorized_review_indicator",
        "severity": severity,
        "confidence": confidence,
        "description": text_value(finding.get("description")),
        "evidence": evidence,
        "location": location,
        "location_status": location_status,
        "recommendation": text_value(finding.get("recommendation")),
        "references": normalized_references(finding.get("references")),
    }


def normalized_findings_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_severity = {severity: 0 for severity in ("critical", "high", "medium", "low", "info")}
    by_category: dict[str, int] = {}
    for finding in findings:
        severity = finding["severity"]
        by_severity[severity] += 1
        category = finding["category"]
        by_category[category] = by_category.get(category, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_category": dict(sorted(by_category.items())),
    }


def normalized_severity(value: Any) -> str:
    normalized = text_value(value).lower()
    return normalized if normalized in SEVERITIES else "info"


def normalized_confidence(value: Any) -> str:
    normalized = text_value(value).lower()
    return normalized if normalized in CONFIDENCE_LEVELS else "unknown"


def normalized_references(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    references: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        identifier = text_value(item.get("id"))
        url = text_value(item.get("url"))
        reference_type = text_value(item.get("type")).lower()
        if not is_canonical_public_reference(reference_type, identifier, url):
            continue
        reference = {"type": reference_type, "id": identifier, "url": url}
        if reference not in references:
            references.append(reference)
    return references


def is_canonical_public_reference(reference_type: str, identifier: str, url: str) -> bool:
    if reference_type not in REFERENCE_TYPES:
        return False
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        return False

    hostname = parsed.hostname.lower()
    path = parsed.path.rstrip("/")
    identifier_upper = identifier.upper()
    if reference_type == "cve":
        return (
            bool(CVE_IDENTIFIER_PATTERN.fullmatch(identifier))
            and (
                (hostname == "nvd.nist.gov" and path == f"/vuln/detail/{identifier_upper}")
                or (hostname in {"cve.org", "www.cve.org"} and path == "/CVERecord")
                or (hostname == "cve.mitre.org" and path == f"/cgi-bin/cvename.cgi")
            )
        )
    if reference_type == "ghsa":
        return bool(GHSA_IDENTIFIER_PATTERN.fullmatch(identifier)) and hostname == "github.com" and path == f"/advisories/{identifier}"
    return bool(OWASP_IDENTIFIER_PATTERN.fullmatch(identifier)) and hostname in {"owasp.org", "www.owasp.org"} and bool(path)


def stable_finding_id(audit_type: str, rule_id: str, path: str, line: int | None, evidence: str) -> str:
    material = "\x00".join((audit_type, rule_id, path, str(line or ""), evidence)).encode("utf-8", errors="replace")
    return hashlib.sha256(material).hexdigest()


def normalize_project_relative_path(value: str) -> str | None:
    """Return a portable archive-relative path or withhold an unsafe location.

    The normalized finding contract crosses API, UI, comparison, and export
    boundaries. It must never turn an analyzer's path-like string into a host
    path disclosure, even when a legacy or future adapter supplies it.
    """

    normalized = value.strip().replace("\\", "/")
    if not normalized or any(ord(character) < 32 for character in normalized):
        return None
    if normalized.startswith("/") or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", normalized):
        return None
    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return None
    return "/".join(parts)


def positive_int(value: Any) -> int | None:
    if isinstance(value, int) and value > 0:
        return value
    return None


def text_value(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def scoped_evidence(path: str, evidence: str) -> str:
    return f"{path}: {evidence}" if evidence else path
