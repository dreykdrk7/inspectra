import pytest

from app.cpe_purl_mappings import CpePurlMappingPolicy, ReviewedCpePurlMapping


ENTRY = ReviewedCpePurlMapping(
    mapping_id="cpe-map-synthetic-component",
    ecosystem="npm",
    package_name="component",
    cpe_part="a",
    cpe_vendor="synthetic",
    cpe_product="component",
    cve_ids=("CVE-2025-1234",),
)
CRITERIA = "cpe:2.3:a:synthetic:component:*:*:*:*:*:*:*:*"


def test_exact_reviewed_mapping_corroborates_identity_but_is_bound_to_cve():
    policy = CpePurlMappingPolicy((ENTRY,))

    corroborated = policy.assess(
        ecosystem="npm", package_name="component", cve_id="CVE-2025-1234", cpe_criteria=(CRITERIA,),
    )
    wrong_cve = policy.assess(
        ecosystem="npm", package_name="component", cve_id="CVE-2025-9999", cpe_criteria=(CRITERIA,),
    )

    assert corroborated.status == "identity_corroborated"
    assert corroborated.corroborated_match_count == 1
    assert corroborated.mapping_ids == ("cpe-map-synthetic-component",)
    assert wrong_cve.status == "present_unmapped"


@pytest.mark.parametrize(
    ("ecosystem", "name", "criteria"),
    [
        ("pypi", "component", CRITERIA),
        ("npm", "component-js", CRITERIA),
        ("npm", "component", "cpe:2.3:a:other:component:*:*:*:*:*:*:*:*"),
        ("npm", "component", "cpe:2.3:a:synthetic:component\\:alias:*:*:*:*:*:*:*:*"),
    ],
)
def test_homonyms_and_ambiguous_cpe_values_never_match(ecosystem, name, criteria):
    result = CpePurlMappingPolicy((ENTRY,)).assess(
        ecosystem=ecosystem, package_name=name, cve_id="CVE-2025-1234", cpe_criteria=(criteria,),
    )

    assert result.status in {"not_present", "present_unmapped"}
    assert result.mapping_ids == ()


def test_policy_rejects_duplicate_or_invalid_entries():
    with pytest.raises(ValueError, match="duplicate or ambiguous"):
        CpePurlMappingPolicy((ENTRY, ENTRY))
    with pytest.raises(ValueError, match="invalid mapped CPE"):
        CpePurlMappingPolicy((ReviewedCpePurlMapping(
            mapping_id="cpe-map-invalid-entry",
            ecosystem="npm",
            package_name="component",
            cpe_part="a",
            cpe_vendor="*",
            cpe_product="component",
            cve_ids=("CVE-2025-1234",),
        ),))
