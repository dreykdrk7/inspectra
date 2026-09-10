from inspectra_cli.policy import evaluate_policy


def context(*, coverage="complete", public_state="ready", findings=None, comparison=None):
    return {
        "findings": {
            "state": "ready",
            "result_truncated": False,
            "coverage": {"coverage_status": coverage},
            "summary": {"total": 0, "by_severity": {}},
        },
        "public_intelligence": {"state": public_state, "findings": findings or []},
        "comparison": comparison,
    }


def test_standard_policy_fails_critical_and_kev():
    result = evaluate_policy(
        "standard",
        context(findings=[{"severity": "critical", "known_exploited": True}]),
    )
    assert result["verdict"] == "fail"
    assert result["failures"] == ["known_exploited_vulnerability", "severity_at_or_above_critical"]


def test_policy_never_passes_incomplete_or_stale_results():
    incomplete = evaluate_policy("observe", context(coverage="partial", public_state="disabled"))
    stale = evaluate_policy("standard", context(public_state="stale"))
    assert incomplete["verdict"] == "inconclusive"
    assert "local_coverage_incomplete" in incomplete["incomplete_reasons"]
    assert stale["verdict"] == "inconclusive"
    assert "public_intelligence_not_current" in stale["incomplete_reasons"]


def test_strict_policy_uses_new_findings_only_when_baseline_is_comparable():
    comparison = {
        "state": "ready",
        "comparisons": [{"status": "new", "finding": {"severity": "medium"}}],
        "public_vulnerability_comparison": {"state": "ready", "comparisons": []},
    }
    result = evaluate_policy("strict", context(comparison=comparison))
    assert result["verdict"] == "fail"
    assert result["baseline_state"] == "ready"
    assert result["metrics"]["new_at_threshold"] == 1
