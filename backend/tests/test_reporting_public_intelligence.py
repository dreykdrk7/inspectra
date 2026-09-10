from types import SimpleNamespace

from app.reporting import build_public_vulnerability_intelligence_sections


def test_public_intelligence_report_labels_policy_bound_vendor_bulletin_as_supporting_evidence():
    finding = SimpleNamespace(
        id="pvf_fixture",
        fingerprint_version="2026-09-05.1",
        advisory_id="CVE-2025-1234",
        aliases=["GHSA-AAAA-BBBB-CCCC"],
        source_consensus="osv_only",
        ecosystem="npm",
        component_name="react",
        component_version="18.3.1",
        component_identity_provenance="operator_attested_public_pypi",
        dependency_scope="direct",
        relationship_status="not_reported",
        affected_ranges=[],
        fixed_versions=["18.3.2"],
        severity=[],
        recommendation="Upgrade react to a reviewed version at or above 18.3.2.",
        references=[],
        corroborations=[],
        source_conflicts=[],
        kev_signals=[],
        vendor_bulletins=[
            SimpleNamespace(
                publisher="React",
                advisory_id="GHSA-AAAA-BBBB-CCCC",
                url="https://github.com/react/react/security/advisories/GHSA-AAAA-BBBB-CCCC",
                policy_version="2026-09-05.1",
            )
        ],
        field_provenance=[
            SimpleNamespace(
                field="fixed_versions",
                state="conflicting",
                sources=[
                    SimpleNamespace(provider="osv", status="primary", observed_at="2025-01-02T00:00:00Z"),
                    SimpleNamespace(provider="github_advisories", status="conflicting", observed_at="2025-01-03T00:00:00Z"),
                ],
            )
        ],
    )
    intelligence = SimpleNamespace(
        state="ready",
        provider="osv",
        snapshot_recorded_at=None,
        is_latest_snapshot=True,
        queried_at=None,
        expires_at=None,
        sources=[],
        findings=[finding],
        summary=SimpleNamespace(
            correlation_eligible_components=1,
            queryable_components=1,
            queried_components=1,
            osv_pages=1,
            findings=1,
            unverified_advisories=0,
            withdrawn_advisories=0,
        ),
    )

    sections = build_public_vulnerability_intelligence_sections(intelligence)
    rows = dict(sections[1].items)

    assert rows["Official vendor security bulletin"] == "React advisory GHSA-AAAA-BBBB-CCCC (policy 2026-09-05.1)."
    assert rows["Official vendor bulletin link"] == "https://github.com/react/react/security/advisories/GHSA-AAAA-BBBB-CCCC"
    assert rows["Fixed versions"] == "18.3.2"
    assert rows["Public identity evidence"] == "operator attested public pypi"
    assert rows["Relationship evidence"] == "not_reported"
    assert rows["Field-level source trace"] == (
        "fixed_versions: conflicting [osv primary (2025-01-02T00:00:00Z), "
        "github_advisories conflicting (2025-01-03T00:00:00Z)]"
    )


def test_public_intelligence_report_keeps_nvd_cpe_evidence_unmapped():
    finding = SimpleNamespace(
        id="pvf_fixture",
        fingerprint_version="2026-09-05.1",
        advisory_id="CVE-2025-1234",
        aliases=[],
        source_consensus="osv_only",
        ecosystem="npm",
        component_name="react",
        component_version="18.3.1",
        component_identity_provenance="npm_registry_lockfile",
        dependency_scope="direct",
        relationship_status="reported",
        affected_ranges=[],
        fixed_versions=["18.3.2"],
        severity=[],
        cvss_base_score=None,
        cvss_band="unknown",
        cvss_score_status="not_available",
        recommendation="Review the exact OSV match.",
        references=[],
        vendor_bulletins=[],
        corroborations=[],
        source_conflicts=[],
        kev_signals=[],
        nvd_evidence=[SimpleNamespace(
            provider="nvd",
            cve_id="CVE-2025-1234",
            status="analyzed",
            severity=[SimpleNamespace(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")],
            cwes=["CWE-79"],
            cpe_status="present_unmapped",
            cpe_match_count=1,
            published_at="2025-01-02T03:04:05Z",
            updated_at="2025-02-03T04:05:06Z",
            references=[SimpleNamespace(type="source", url="https://nvd.nist.gov/vuln/detail/CVE-2025-1234")],
        )],
    )
    intelligence = SimpleNamespace(
        state="ready",
        provider="osv",
        snapshot_recorded_at=None,
        is_latest_snapshot=True,
        queried_at=None,
        expires_at=None,
        sources=[],
        findings=[finding],
        summary=SimpleNamespace(
            correlation_eligible_components=1,
            queryable_components=1,
            queried_components=1,
            osv_pages=1,
            findings=1,
            unverified_advisories=0,
            withdrawn_advisories=0,
        ),
    )

    rows = dict(build_public_vulnerability_intelligence_sections(intelligence)[1].items)

    assert rows["NVD CVE evidence"].startswith("CVE-2025-1234 — analyzed")
    assert rows["NVD CPE evidence"] == (
        "CPE match records present but deliberately unmapped (1); "
        "NVD does not establish package applicability."
    )
    assert rows["NVD source"] == "https://nvd.nist.gov/vuln/detail/CVE-2025-1234"

    evidence = finding.nvd_evidence[0]
    evidence.cpe_status = "identity_corroborated"
    evidence.cpe_corroborated_match_count = 1
    evidence.cpe_mapping_ids = ["cpe-map-reviewed-fixture"]
    evidence.cpe_mapping_policy_version = "2026-09-09.1"
    corroborated_rows = dict(build_public_vulnerability_intelligence_sections(intelligence)[1].items)

    assert corroborated_rows["NVD CPE evidence"] == (
        "Package identity corroborated by reviewed mapping cpe-map-reviewed-fixture under policy "
        "2026-09-09.1 (1 of 1 records). This does not replace OSV affected-version evidence."
    )
