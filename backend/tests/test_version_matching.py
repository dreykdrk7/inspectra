import pytest

from app.version_matching import canonicalize_nuget_version, match_exact_version_against_range


@pytest.mark.parametrize(
    ("version", "affected_range", "status", "reason"),
    [
        ("1.2.3", ">=1.2.0 <2.0.0", "matched", "npm_all_comparators_satisfied"),
        ("2.0.0", ">=1.2.0 <2.0.0", "not_matched", "npm_comparator_not_satisfied"),
        ("1.2.3+build.7", "=1.2.3", "matched", "npm_all_comparators_satisfied"),
        ("1.2.3-alpha.1", ">=1.2.0", "unknown", "npm_prerelease_not_supported"),
        ("1.2.3", "^1.2.0", "unknown", "npm_range_syntax_not_supported"),
        ("1.2.3", "1.2.3 || >=2.0.0", "unknown", "npm_range_syntax_not_supported"),
    ],
)
def test_npm_version_matching_is_limited_and_deterministic(version, affected_range, status, reason):
    result = match_exact_version_against_range("npm", version, affected_range)

    assert result.status == status
    assert result.reason == reason


@pytest.mark.parametrize(
    ("version", "affected_range", "status", "reason"),
    [
        ("1!2.0+local.1", ">=1!2.0,<2!0.0", "matched", "pypi_specifier_satisfied"),
        ("2.0", "<2.0", "not_matched", "pypi_specifier_not_satisfied"),
        ("1.0rc1", ">=1.0rc1", "unknown", "pypi_prerelease_not_supported"),
        ("1.0", "===1.0", "unknown", "pypi_range_syntax_not_supported"),
        ("1.0", "==1.*", "unknown", "pypi_range_syntax_not_supported"),
        ("not-a-version", ">=1.0", "unknown", "pypi_version_not_supported"),
    ],
)
def test_pypi_version_matching_uses_pep_440_but_does_not_guess(version, affected_range, status, reason):
    result = match_exact_version_against_range("pypi", version, affected_range)

    assert result.status == status
    assert result.reason == reason


@pytest.mark.parametrize(
    ("version", "affected_range", "status", "reason"),
    [
        ("v0.19.0", ">=v0.1.0 <v0.20.0", "matched", "go_all_comparators_satisfied"),
        ("v0.20.0", ">=v0.1.0 <v0.20.0", "not_matched", "go_comparator_not_satisfied"),
        (
            "v0.0.0-20240102030405-abcdef123456",
            ">=v0.0.0-20230101000000-aaaaaaaaaaaa <v0.1.0",
            "matched",
            "go_all_comparators_satisfied",
        ),
        ("v1.2", ">=v1.0.0", "unknown", "go_version_not_supported"),
        ("v1.2.3", "^v1.0.0", "unknown", "go_range_syntax_not_supported"),
    ],
)
def test_go_version_matching_handles_exact_and_pseudo_versions_without_coercion(version, affected_range, status, reason):
    result = match_exact_version_against_range("go", version, affected_range)
    assert result.status == status
    assert result.reason == reason


@pytest.mark.parametrize(
    ("version", "affected_range", "status", "reason"),
    [
        ("1.0.210", ">=1.0.0 <1.0.220", "matched", "cargo_all_comparators_satisfied"),
        ("1.0.220", ">=1.0.0 <1.0.220", "not_matched", "cargo_comparator_not_satisfied"),
        ("2.0.0-rc.1", ">=2.0.0-beta.1 <2.0.0", "matched", "cargo_all_comparators_satisfied"),
        ("v1.0.0", ">=1.0.0", "unknown", "cargo_version_not_supported"),
        ("1.0.0", "^1.0.0", "unknown", "cargo_range_syntax_not_supported"),
    ],
)
def test_cargo_semver_matching_is_exact_and_does_not_coerce_unsupported_ranges(version, affected_range, status, reason):
    result = match_exact_version_against_range("cargo", version, affected_range)
    assert result.status == status
    assert result.reason == reason


@pytest.mark.parametrize(
    ("version", "affected_range", "status", "reason"),
    [
        ("7.1.3", ">=7.0.0 <7.1.4", "matched", "composer_all_comparators_satisfied"),
        ("7.1.4", ">=7.0.0 <7.1.4", "not_matched", "composer_comparator_not_satisfied"),
        ("7.2.0-rc.1", ">=7.2.0-beta.1 <7.2.0", "matched", "composer_all_comparators_satisfied"),
        ("dev-main", ">=1.0.0", "unknown", "composer_version_not_supported"),
        ("7.1.3", "^7.1", "unknown", "composer_range_syntax_not_supported"),
    ],
)
def test_composer_semver_matching_is_conservative(version, affected_range, status, reason):
    result = match_exact_version_against_range("composer", version, affected_range)
    assert result.status == status
    assert result.reason == reason


@pytest.mark.parametrize(
    ("version", "affected_range", "status", "reason"),
    [
        ("3.14.0", ">=3.0.0 <3.15.0", "matched", "maven_all_comparators_satisfied"),
        ("3.15.0", ">=3.0.0 <3.15.0", "not_matched", "maven_comparator_not_satisfied"),
        ("1.0.Final", ">=1.0.0 <=1.0-RELEASE", "matched", "maven_all_comparators_satisfied"),
        ("2.0-RC2", ">=2.0-beta1 <2.0-SNAPSHOT", "matched", "maven_all_comparators_satisfied"),
        ("2.0-SNAPSHOT", "<2.0", "matched", "maven_all_comparators_satisfied"),
        ("2.0-sp1", ">2.0", "matched", "maven_all_comparators_satisfied"),
        ("1.2.3.4", ">1.2.3 <1.2.4", "matched", "maven_all_comparators_satisfied"),
        ("1.0.Final1", ">=1.0", "unknown", "maven_version_not_supported"),
        ("1.0-vendor", ">=1.0", "unknown", "maven_version_not_supported"),
        ("1.0.RC1", ">=1.0-rc1", "unknown", "maven_version_not_supported"),
        ("01.0", ">=1.0", "unknown", "maven_version_not_supported"),
        ("1.0", "[1.0,2.0)", "unknown", "maven_range_syntax_not_supported"),
    ],
)
def test_maven_matching_supports_a_reviewed_comparable_version_subset(version, affected_range, status, reason):
    result = match_exact_version_against_range("maven", version, affected_range)
    assert result.status == status
    assert result.reason == reason


@pytest.mark.parametrize(
    ("version", "affected_range", "status", "reason"),
    [
        ("13.0.3", ">=12.0.0 <13.0.4", "matched", "nuget_all_comparators_satisfied"),
        ("13.0.4.0", ">=12.0.0.0 <13.0.4.0", "not_matched", "nuget_comparator_not_satisfied"),
        ("1.2.3-beta.1", ">=1.2.3-beta.0 <1.2.3", "matched", "nuget_all_comparators_satisfied"),
        ("1.0", ">=1.0.0", "matched", "nuget_all_comparators_satisfied"),
        ("1", "=1.0.0.0", "matched", "nuget_all_comparators_satisfied"),
        ("1.00.01.0+Build.Agent", "=1.0.1", "matched", "nuget_all_comparators_satisfied"),
        ("1.0-BETA.10", ">1.0-beta.2 <1.0", "matched", "nuget_all_comparators_satisfied"),
        ("1.0-alpha.01", "=1.0.0-ALPHA.1", "matched", "nuget_all_comparators_satisfied"),
        ("1.0.0.1", ">1.0.0 <1.0.0.2", "matched", "nuget_all_comparators_satisfied"),
        ("1.0.0.0.1", ">=1.0.0", "unknown", "nuget_version_not_supported"),
        ("1.0.0-alpha..1", ">=1.0.0-alpha", "unknown", "nuget_version_not_supported"),
        ("2147483648.0.0", ">=1.0.0", "unknown", "nuget_version_not_supported"),
        ("1.0.0", "[1.0,2.0)", "unknown", "nuget_range_syntax_not_supported"),
    ],
)
def test_nuget_matching_supports_bounded_official_version_precedence(version, affected_range, status, reason):
    result = match_exact_version_against_range("nuget", version, affected_range)
    assert result.status == status
    assert result.reason == reason


@pytest.mark.parametrize(
    ("value", "canonical"),
    [
        ("1", "1.0.0"),
        ("1.0", "1.0.0"),
        ("1.00.01", "1.0.1"),
        ("1.0.0.0", "1.0.0"),
        ("1.0.0.7", "1.0.0.7"),
        ("1.0-BETA.010+Build.Agent", "1.0.0-beta.10"),
        ("1.0.0-alpha..1", None),
        ("1.0.0/../../private", None),
        ("1.0.0.0.1", None),
        ("2147483648", None),
    ],
)
def test_nuget_version_identity_has_one_safe_canonical_form(value, canonical):
    assert canonicalize_nuget_version(value) == canonical


def test_version_matching_never_coerces_an_unknown_ecosystem():
    assert match_exact_version_against_range("gem", "1.2.3", ">=1.0.0").status == "unknown"
