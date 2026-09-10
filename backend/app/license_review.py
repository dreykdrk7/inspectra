"""Conservative review of root-project license declarations.

This module never infers dependency licenses or legal compatibility.  It only
compares exact, runner-normalized SPDX identifiers with an immutable deployment
policy captured on the job execution profile.
"""

from __future__ import annotations

from typing import Any, Iterable


LICENSE_REVIEW_CONTRACT_VERSION = "2026-09-09.1"


def add_project_license_review(result: dict[str, Any], denied_identifiers: Iterable[str]) -> dict[str, Any]:
    reviewed = dict(result)
    findings = list(result.get("findings")) if isinstance(result.get("findings"), list) else []
    denied = frozenset(value.lower() for value in denied_identifiers)
    declarations: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    manifests = result.get("parsed_manifests") if isinstance(result.get("parsed_manifests"), list) else []
    for item in manifests:
        if not isinstance(item, dict):
            continue
        path = _safe_text(item.get("path")) or "manifest"
        parsed = item.get("parsed") if isinstance(item.get("parsed"), dict) else {}
        project = parsed.get("project") if isinstance(parsed.get("project"), dict) else {}
        expression = _safe_text(project.get("license"))
        parser_status = _safe_text(project.get("license_status"))
        status = "unknown"
        if expression:
            status = "not_permitted" if expression.lower() in denied else "declared"
        elif parser_status == "unrecognized_withheld":
            status = "unknown_unrecognized_withheld"
        key = (path, expression or status)
        if key in seen:
            continue
        seen.add(key)
        declaration = {"manifest_path": path, "status": status}
        if expression:
            declaration["expression"] = expression
        declarations.append(declaration)
        if status == "not_permitted":
            findings.append(_finding(
                "project_license_not_permitted",
                "Declared project license conflicts with the configured review policy",
                "medium",
                path,
                f"Declared SPDX identifier {expression} matches an exact operator-configured deny entry.",
                "Ask the legal or compliance owner to review the declaration and policy; Inspectra does not determine legal compatibility.",
            ))
        elif status.startswith("unknown"):
            findings.append(_finding(
                "project_license_unknown",
                "Project license declaration is unavailable",
                "info",
                path,
                "No supported SPDX declaration was retained from this manifest.",
                "Confirm the project license with its owner; do not treat this signal as a legal conclusion.",
            ))

    reviewed["findings"] = findings
    reviewed["license_review"] = {
        "contract_version": LICENSE_REVIEW_CONTRACT_VERSION,
        "policy_mode": "exact_deny_identifiers" if denied else "inventory_only",
        "denied_identifier_count": len(denied),
        "declarations": declarations,
        "summary": {
            "manifests_reviewed": len(declarations),
            "declared": sum(item["status"] == "declared" for item in declarations),
            "unknown": sum(item["status"].startswith("unknown") for item in declarations),
            "not_permitted": sum(item["status"] == "not_permitted" for item in declarations),
        },
        "limitations": [
            "Only root-project declarations from supported manifests are reviewed.",
            "Dependency licenses, compatibility, obligations, exceptions and legal conclusions are not inferred.",
            "Compound expressions are inventory-only unless the whole normalized expression exactly matches policy.",
        ],
    }
    summary = dict(result.get("summary")) if isinstance(result.get("summary"), dict) else {}
    summary["license_review_status"] = "not_permitted" if any(item["status"] == "not_permitted" for item in declarations) else "completed"
    summary["license_declarations"] = sum(bool(item.get("expression")) for item in declarations)
    summary["license_unknown"] = sum(item["status"].startswith("unknown") for item in declarations)
    reviewed["summary"] = summary
    return reviewed


def _finding(rule_id: str, title: str, severity: str, path: str, evidence: str, recommendation: str) -> dict[str, Any]:
    return {
        "id": rule_id,
        "title": title,
        "level": severity,
        "confidence": "high",
        "category": "license_review",
        "project_review": "license",
        "file_path": path,
        "description": "This is a declared-license policy signal, not legal advice or a license compatibility determination.",
        "evidence": evidence,
        "recommendation": recommendation,
    }


def _safe_text(value: Any) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else ""
