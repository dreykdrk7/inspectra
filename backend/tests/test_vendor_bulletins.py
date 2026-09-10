from app.public_advisories import PublicAdvisoryReference
from app.public_advisory_egress import PublicComponentIdentity
from app.vendor_bulletins import VENDOR_BULLETIN_POLICY_VERSION, official_vendor_bulletins


def test_policy_bound_vendor_bulletin_requires_exact_component_path_and_retained_ghsa_alias():
    evidence = official_vendor_bulletins(
        PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1"),
        ("CVE-2025-1234", "GHSA-AAAA-BBBB-CCCC"),
        (
            PublicAdvisoryReference("source", "https://osv.dev/vulnerability/CVE-2025-1234"),
            PublicAdvisoryReference("reference", "https://github.com/react/react/security/advisories/GHSA-AAAA-BBBB-CCCC"),
            PublicAdvisoryReference("reference", "https://github.com.evil.invalid/react/react/security/advisories/GHSA-AAAA-BBBB-CCCC"),
            PublicAdvisoryReference("reference", "https://github.com/react/react/releases/tag/GHSA-AAAA-BBBB-CCCC"),
            PublicAdvisoryReference("reference", "https://github.com/react/react/security/advisories/GHSA-DDDD-EEEE-FFFF"),
            PublicAdvisoryReference("reference", "https://github.com/react/react/security/advisories/GHSA-AAAA-BBBB-CCCC?token=never-retain"),
        ),
    )

    assert [item.publisher for item in evidence] == ["React"]
    assert evidence[0].advisory_id == "GHSA-AAAA-BBBB-CCCC"
    assert evidence[0].url == "https://github.com/react/react/security/advisories/GHSA-AAAA-BBBB-CCCC"
    assert evidence[0].policy_version == VENDOR_BULLETIN_POLICY_VERSION


def test_vendor_bulletin_policy_does_not_infer_ownership_from_a_matching_host_or_unreviewed_component():
    references = (PublicAdvisoryReference("reference", "https://github.com/react/react/security/advisories/GHSA-AAAA-BBBB-CCCC"),)

    assert official_vendor_bulletins(
        PublicComponentIdentity(ecosystem="npm", name="unreviewed-package", version="1.0.0"),
        ("GHSA-AAAA-BBBB-CCCC",),
        references,
    ) == ()
    assert official_vendor_bulletins(
        PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1"),
        ("GHSA-DDDD-EEEE-FFFF",),
        references,
    ) == ()
