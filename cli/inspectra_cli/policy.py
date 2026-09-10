"""Deterministic, source-free policy evaluation for CI results."""

from __future__ import annotations

from typing import Any, Literal


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
PolicyName = Literal["observe", "standard", "strict"]


POLICIES: dict[str, dict[str, Any]] = {
    "observe": {"current": None, "new": None, "kev": False, "public": False},
    "standard": {"current": "critical", "new": "high", "kev": True, "public": True},
    "strict": {"current": "high", "new": "medium", "kev": True, "public": True},
}


def _finding_severity(item: dict[str, Any]) -> str:
    value = item.get("severity")
    if isinstance(value, str):
        return value
    cvss_band = item.get("cvss_band")
    return cvss_band if isinstance(cvss_band, str) else "unknown"


def _finding_is_known_exploited(item: dict[str, Any]) -> bool:
    if item.get("known_exploited") is True:  # compatible with bounded integration fixtures
        return True
    signals = item.get("kev_signals")
    return isinstance(signals, list) and any(
        isinstance(signal, dict) and signal.get("status") == "known_exploited" for signal in signals
    )


def evaluate_policy(name: PolicyName, context: dict[str, Any]) -> dict[str, Any]:
    policy = POLICIES[name]
    reasons: list[str] = []
    failures: list[str] = []
    findings = context.get("findings") if isinstance(context.get("findings"), dict) else {}
    coverage = findings.get("coverage") if isinstance(findings.get("coverage"), dict) else None
    local_summary = findings.get("summary") if isinstance(findings.get("summary"), dict) else {}
    intelligence = context.get("public_intelligence") if isinstance(context.get("public_intelligence"), dict) else {}
    comparison = context.get("comparison") if isinstance(context.get("comparison"), dict) else None

    if findings.get("state") != "ready":
        reasons.append("local_findings_not_ready")
    if coverage is None or coverage.get("coverage_status") != "complete":
        reasons.append("local_coverage_incomplete")
    if findings.get("result_truncated") is True:
        reasons.append("local_results_truncated")
    if policy["public"] and intelligence.get("state") != "ready":
        reasons.append("public_intelligence_not_current")

    current_threshold = policy["current"]
    current_severities = local_summary.get("by_severity") if isinstance(local_summary.get("by_severity"), dict) else {}
    public_findings = intelligence.get("findings") if isinstance(intelligence.get("findings"), list) else []
    if current_threshold:
        threshold = SEVERITY_RANK[current_threshold]
        local_count = sum(
            int(count)
            for severity, count in current_severities.items()
            if severity in SEVERITY_RANK and SEVERITY_RANK[severity] >= threshold and isinstance(count, int)
        )
        public_count = sum(
            1 for item in public_findings
            if isinstance(item, dict) and SEVERITY_RANK.get(_finding_severity(item), -1) >= threshold
        )
        if local_count + public_count > 0:
            failures.append(f"severity_at_or_above_{current_threshold}")

    if policy["kev"] and any(
        isinstance(item, dict) and _finding_is_known_exploited(item) for item in public_findings
    ):
        failures.append("known_exploited_vulnerability")

    baseline_state = "absent"
    new_threshold = policy["new"]
    new_at_threshold = 0
    if comparison is not None:
        baseline_state = "ready" if comparison.get("state") == "ready" else "not_comparable"
        if baseline_state != "ready":
            reasons.append("baseline_not_comparable")
        elif new_threshold:
            threshold = SEVERITY_RANK[new_threshold]
            local_comparisons = comparison.get("comparisons") if isinstance(comparison.get("comparisons"), list) else []
            new_at_threshold += sum(
                1 for item in local_comparisons
                if isinstance(item, dict)
                and item.get("status") == "new"
                and isinstance(item.get("finding"), dict)
                and SEVERITY_RANK.get(str(item["finding"].get("severity")), -1) >= threshold
            )
            public_comparison = comparison.get("public_vulnerability_comparison")
            if isinstance(public_comparison, dict) and public_comparison.get("state") == "ready":
                public_items = public_comparison.get("comparisons")
                if isinstance(public_items, list):
                    new_at_threshold += sum(
                        1 for item in public_items
                        if isinstance(item, dict)
                        and item.get("status") == "new"
                        and isinstance(item.get("finding"), dict)
                        and SEVERITY_RANK.get(_finding_severity(item["finding"]), -1) >= threshold
                    )
            elif policy["public"]:
                reasons.append("public_baseline_not_comparable")
            if new_at_threshold:
                failures.append(f"new_severity_at_or_above_{new_threshold}")

    verdict = "fail" if failures else "inconclusive" if reasons else "pass"
    return {
        "contract_version": "2026-09-07.1",
        "policy": name,
        "verdict": verdict,
        "failures": sorted(set(failures)),
        "incomplete_reasons": sorted(set(reasons)),
        "baseline_state": baseline_state,
        "metrics": {
            "local_findings": int(local_summary.get("total", 0)) if isinstance(local_summary.get("total", 0), int) else 0,
            "public_findings": len(public_findings),
            "new_at_threshold": new_at_threshold,
        },
    }
