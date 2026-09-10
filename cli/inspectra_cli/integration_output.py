"""Bounded CI output renderers for an already-redacted API contract."""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Any

from inspectra_cli import __version__


def render_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def render_markdown(payload: dict[str, Any]) -> str:
    policy = payload.get("policy") if isinstance(payload.get("policy"), dict) else {}
    findings = payload.get("finding_results") if isinstance(payload.get("finding_results"), list) else []
    lines = [
        "# Inspectra CI result",
        "",
        f"- Status: `{_text(payload.get('status'), 40)}`",
        f"- Policy: `{_text(policy.get('policy'), 20)}` → **{_text(policy.get('verdict'), 20).upper()}**",
        f"- Analysis: `{_text(payload.get('analysis_id'), 64)}`",
        f"- Findings included: {len(findings)}",
        "",
    ]
    incomplete = policy.get("incomplete_reasons") if isinstance(policy.get("incomplete_reasons"), list) else []
    if incomplete:
        lines.extend(["## Incomplete evidence", "", *[f"- `{_text(item, 80)}`" for item in incomplete], ""])
    if findings:
        lines.extend(["## Actionable findings", ""])
        for item in findings[:200]:
            if not isinstance(item, dict):
                continue
            title = _text(item.get("title") or item.get("advisory_id") or "Finding", 160)
            severity = _severity(item)
            recommendation = _text(item.get("recommendation") or "Review the finding evidence in Inspectra.", 300)
            lines.extend([f"### {title}", "", f"Severity: **{severity.upper()}**", "", recommendation, ""])
    return "\n".join(lines).rstrip() + "\n"


def render_sarif(payload: dict[str, Any]) -> str:
    findings = payload.get("finding_results") if isinstance(payload.get("finding_results"), list) else []
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for index, finding in enumerate(findings[:1000]):
        if not isinstance(finding, dict):
            continue
        rule_id = _text(finding.get("rule_id") or finding.get("advisory_id") or f"inspectra-{index}", 160)
        title = _text(finding.get("title") or finding.get("advisory_id") or "Inspectra finding", 160)
        severity = _severity(finding)
        rules.setdefault(rule_id, {"id": rule_id, "shortDescription": {"text": title}})
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": "error" if severity in {"critical", "high"} else "warning" if severity == "medium" else "note",
            "message": {"text": _text(finding.get("recommendation") or title, 500)},
            "properties": {"inspectraSeverity": severity},
        }
        location = finding.get("location")
        if finding.get("location_status") == "reported" and isinstance(location, dict):
            safe_path = _safe_relative_path(location.get("path"))
            if safe_path:
                region = {}
                if isinstance(location.get("line"), int) and location["line"] > 0:
                    region["startLine"] = location["line"]
                physical = {"artifactLocation": {"uri": safe_path, "uriBaseId": "%SRCROOT%"}}
                if region:
                    physical["region"] = region
                result["locations"] = [{"physicalLocation": physical}]
        results.append(result)
    policy = payload.get("policy") if isinstance(payload.get("policy"), dict) else {}
    incomplete = policy.get("incomplete_reasons") if isinstance(policy.get("incomplete_reasons"), list) else []
    run_properties: dict[str, Any] = {
        "inspectraPolicy": _text(policy.get("policy"), 20),
        "inspectraVerdict": _text(policy.get("verdict"), 20),
    }
    safe_incomplete = [_text(item, 80) for item in incomplete[:50] if isinstance(item, str)]
    if safe_incomplete:
        run_properties["inspectraIncompleteReasons"] = safe_incomplete
    document = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Inspectra", "semanticVersion": __version__, "rules": list(rules.values())}},
            "results": results,
            "properties": run_properties,
        }],
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"


def _safe_relative_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 512 or "\\" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path.as_posix()


def _severity(item: dict[str, Any]) -> str:
    value = item.get("severity") if isinstance(item.get("severity"), str) else item.get("cvss_band")
    return value if value in {"critical", "high", "medium", "low", "info", "none"} else "unknown"


def _text(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return "unknown"
    return " ".join(value.replace("\x00", "").split())[:limit] or "unknown"
