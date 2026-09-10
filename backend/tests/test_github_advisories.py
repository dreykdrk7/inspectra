import json
from pathlib import Path

from app.github_advisories import GITHUB_ADVISORY_CONTRACT_VERSION, normalize_github_advisory_response
from app.public_advisory_egress import PublicComponentIdentity


FIXTURES = Path(__file__).parent / "fixtures" / "github"
COMPONENT = PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")


def test_github_fixture_is_bound_to_the_expected_ghsa_component_and_exact_version():
    payload = json.loads((FIXTURES / "global-advisory-valid.json").read_text(encoding="utf-8"))

    result = normalize_github_advisory_response("GHSA-aaaa-bbbb-cccc", COMPONENT, payload)

    assert result.status == "ready"
    assert result.corroboration is not None
    corroboration = result.corroboration
    assert corroboration.contract_version == GITHUB_ADVISORY_CONTRACT_VERSION
    assert corroboration.provider_advisory_id == "GHSA-AAAA-BBBB-CCCC"
    assert corroboration.aliases == ("CVE-2025-1234", "GHSA-AAAA-BBBB-CCCC")
    assert corroboration.affected_ranges[0].expression == "<18.3.2"
    assert corroboration.fixed_versions == ("18.3.2",)
    assert [(item.kind, item.cvss_version, item.base_score, item.band, item.score_status) for item in corroboration.severity] == [
        ("CVSS_V3", "3.1", 9.8, "critical", "source_provided"),
        ("CVSS_V4", "4.0", 9.3, "critical", "source_provided"),
    ]
    assert corroboration.references[0].url == "https://github.com/advisories/GHSA-AAAA-BBBB-CCCC"


def test_github_response_that_is_wrong_package_version_or_identifier_is_not_correlated():
    payload = json.loads((FIXTURES / "global-advisory-valid.json").read_text(encoding="utf-8"))
    payload[0]["vulnerabilities"][0]["package"]["name"] = "other-package"

    result = normalize_github_advisory_response("GHSA-aaaa-bbbb-cccc", COMPONENT, payload)

    assert result.status == "not_correlated"
    assert result.corroboration is None
    assert result.errors == ("github_advisory_not_correlated",)


def test_github_response_shape_and_untrusted_identifiers_never_become_evidence():
    assert normalize_github_advisory_response("not-a-ghsa", COMPONENT, []).status == "invalid_source_response"
    assert normalize_github_advisory_response("GHSA-aaaa-bbbb-cccc", COMPONENT, {"ghsa_id": "GHSA-aaaa-bbbb-cccc"}).status == "invalid_source_response"
    assert normalize_github_advisory_response("GHSA-aaaa-bbbb-cccc", COMPONENT, []).status == "not_found"
    assert normalize_github_advisory_response("GHSA-aaaa-bbbb-cccc", COMPONENT, [{}, {}]).status == "invalid_source_response"


def test_github_normalizer_keeps_only_https_references_without_credentials_or_scripts():
    payload = json.loads((FIXTURES / "global-advisory-valid.json").read_text(encoding="utf-8"))
    payload[0]["references"] = [
        "https://vendor.example.test/fix",
        "javascript:alert(1)",
        "https://user:password@vendor.example.test/private",
        "https://vendor.example.test/ok#fragment",
    ]

    result = normalize_github_advisory_response("GHSA-aaaa-bbbb-cccc", COMPONENT, payload)

    assert result.status == "ready"
    assert result.corroboration is not None
    assert [reference.url for reference in result.corroboration.references] == [
        "https://github.com/advisories/GHSA-AAAA-BBBB-CCCC",
        "https://vendor.example.test/fix",
    ]


def test_github_normalizer_does_not_treat_unsupported_ecosystems_as_pip():
    payload = json.loads((FIXTURES / "global-advisory-valid.json").read_text(encoding="utf-8"))
    payload[0]["vulnerabilities"][0]["package"] = {"ecosystem": "pip", "name": "serde"}
    cargo = PublicComponentIdentity(ecosystem="cargo", name="serde", version="18.3.1")

    result = normalize_github_advisory_response("GHSA-aaaa-bbbb-cccc", cargo, payload)

    assert result.status == "not_correlated"
    assert result.corroboration is None


def test_github_normalizer_maps_go_and_cargo_only_to_their_official_ecosystems():
    base = json.loads((FIXTURES / "global-advisory-valid.json").read_text(encoding="utf-8"))
    cases = [
        (PublicComponentIdentity(ecosystem="go", name="golang.org/x/text", version="v0.19.0"), "go", "<0.20.0"),
        (PublicComponentIdentity(ecosystem="cargo", name="serde", version="1.0.210"), "rust", "<1.0.211"),
    ]
    for component, github_ecosystem, affected_range in cases:
        payload = json.loads(json.dumps(base))
        payload[0]["vulnerabilities"][0]["package"] = {"ecosystem": github_ecosystem, "name": component.name}
        payload[0]["vulnerabilities"][0]["vulnerable_version_range"] = affected_range
        payload[0]["vulnerabilities"][0]["first_patched_version"] = None
        result = normalize_github_advisory_response("GHSA-aaaa-bbbb-cccc", component, payload)
        assert result.status == "ready"
        payload[0]["vulnerabilities"][0]["package"]["ecosystem"] = "pip"
        assert normalize_github_advisory_response("GHSA-aaaa-bbbb-cccc", component, payload).status == "not_correlated"


def test_github_normalizer_has_explicit_mappings_for_supported_future_verticals_and_no_fallback():
    base = json.loads((FIXTURES / "global-advisory-valid.json").read_text(encoding="utf-8"))
    cases = [
        ("composer", "vendor/package", "1.2.3", "composer"),
        ("maven", "org.example:library", "1.2.3", "maven"),
        ("nuget", "Example.Library", "1.2.3", "nuget"),
    ]
    for ecosystem, name, version, github_ecosystem in cases:
        payload = json.loads(json.dumps(base))
        payload[0]["vulnerabilities"][0]["package"] = {"ecosystem": github_ecosystem, "name": name}
        payload[0]["vulnerabilities"][0]["vulnerable_version_range"] = "<2.0.0"
        component = PublicComponentIdentity(ecosystem=ecosystem, name=name, version=version)
        assert normalize_github_advisory_response("GHSA-aaaa-bbbb-cccc", component, payload).status == "ready"
        payload[0]["vulnerabilities"][0]["package"]["ecosystem"] = "npm"
        assert normalize_github_advisory_response("GHSA-aaaa-bbbb-cccc", component, payload).status == "not_correlated"

    unknown = PublicComponentIdentity(ecosystem="unknown", name="vendor/package", version="1.2.3")
    assert normalize_github_advisory_response("GHSA-aaaa-bbbb-cccc", unknown, base).status == "invalid_source_response"


def test_github_normalizer_does_not_keep_invalid_or_mislabeled_cvss_metrics():
    payload = json.loads((FIXTURES / "global-advisory-valid.json").read_text(encoding="utf-8"))
    payload[0]["cvss_severities"]["cvss_v3"]["vector_string"] = payload[0]["cvss_severities"]["cvss_v4"]["vector_string"]
    payload[0]["cvss_severities"]["cvss_v4"]["vector_string"] += "/UNKNOWN:X"

    result = normalize_github_advisory_response("GHSA-aaaa-bbbb-cccc", COMPONENT, payload)

    assert result.status == "ready"
    assert result.corroboration is not None
    assert result.corroboration.severity == ()
