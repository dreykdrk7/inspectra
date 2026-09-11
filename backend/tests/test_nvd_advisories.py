from __future__ import annotations

import json
from pathlib import Path

from app.cpe_purl_mappings import CpePurlMappingPolicy, ReviewedCpePurlMapping
from app.nvd_advisories import normalize_nvd_cve_response


FIXTURE = Path(__file__).parent / "fixtures" / "nvd" / "cve-valid.json"


def _payload():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_nvd_enriches_only_the_expected_cve_and_never_retains_cpe_or_description():
    result = normalize_nvd_cve_response("CVE-2025-1234", _payload())

    assert result.status == "ready"
    assert result.evidence is not None
    evidence = result.evidence
    assert evidence.cve_id == "CVE-2025-1234"
    assert evidence.status == "analyzed"
    assert evidence.cwes == ("CWE-79",)
    assert evidence.cpe_status == "present_unmapped"
    assert evidence.cpe_match_count == 1
    assert evidence.cpe_corroborated_match_count == 0
    assert evidence.cpe_mapping_ids == ()
    assert [(value.cvss_version, value.base_score, value.band) for value in evidence.severity] == [("3.1", 9.8, "critical")]
    rendered = json.dumps(evidence.to_dict())
    for withheld in ("synthetic:component", "Synthetic description", "matchCriteriaId", "nvd@nist.gov"):
        assert withheld not in rendered


def test_nvd_can_only_corroborate_identity_through_exact_cve_bound_reviewed_policy():
    policy = CpePurlMappingPolicy((ReviewedCpePurlMapping(
        mapping_id="cpe-map-synthetic-component",
        ecosystem="npm",
        package_name="component",
        cpe_part="a",
        cpe_vendor="synthetic",
        cpe_product="component",
        cve_ids=("CVE-2025-1234",),
    ),))

    matched = normalize_nvd_cve_response(
        "CVE-2025-1234", _payload(), component_ecosystem="npm", component_name="component", mapping_policy=policy,
    )
    homonym = normalize_nvd_cve_response(
        "CVE-2025-1234", _payload(), component_ecosystem="pypi", component_name="component", mapping_policy=policy,
    )

    assert matched.evidence is not None
    assert matched.evidence.cpe_status == "identity_corroborated"
    assert matched.evidence.cpe_mapping_ids == ("cpe-map-synthetic-component",)
    assert homonym.evidence is not None
    assert homonym.evidence.cpe_status == "present_unmapped"


def test_nvd_rejects_mismatch_ambiguous_shape_and_invalid_cve_lookup():
    payload = _payload()
    payload["vulnerabilities"][0]["cve"]["id"] = "CVE-2025-9999"
    assert normalize_nvd_cve_response("CVE-2025-1234", payload).status == "invalid_source_response"
    assert normalize_nvd_cve_response("not-a-cve", _payload()).status == "invalid_source_response"
    payload = _payload()
    payload["totalResults"] = 2
    assert normalize_nvd_cve_response("CVE-2025-1234", payload).status == "invalid_source_response"


def test_nvd_keeps_missing_or_invalid_cvss_explicit_and_rejected_status_distinct():
    payload = _payload()
    cve = payload["vulnerabilities"][0]["cve"]
    cve["vulnStatus"] = "Rejected"
    cve["metrics"] = {"cvssMetricV40": [{"cvssData": {"version": "4.0", "vectorString": "CVSS:4.0/AV:N", "baseScore": 9.9}}]}

    result = normalize_nvd_cve_response("CVE-2025-1234", payload)

    assert result.status == "ready"
    assert result.evidence is not None
    assert result.evidence.status == "rejected"
    assert result.evidence.severity == ()


def test_nvd_cpe_bomb_fails_closed_without_mapping_any_package():
    payload = _payload()
    payload["vulnerabilities"][0]["cve"]["configurations"] = [
        {"nodes": [], "cpeMatch": [{"criteria": "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"}] * 2001}
    ]
    result = normalize_nvd_cve_response("CVE-2025-1234", payload)
    assert result.status == "invalid_source_response"
    assert result.evidence is None
