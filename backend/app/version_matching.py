"""Conservative, offline version-range matching for vulnerability intelligence.

This module intentionally supports a small, documented subset rather than
coercing an unfamiliar ecosystem or range. Callers must surface ``unknown`` as
insufficient data; it is never a clean-vulnerability result.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Literal

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


VersionMatchStatus = Literal["matched", "not_matched", "unknown"]


@dataclass(frozen=True)
class VersionRangeMatch:
    """A deterministic range decision plus a safe machine-readable reason."""

    status: VersionMatchStatus
    reason: str


_NPM_RELEASE_VERSION = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_NPM_COMPARATOR = re.compile(r"^(<=|>=|<|>|=)?((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)$")
_PYPI_SUPPORTED_OPERATORS = frozenset({"==", "!=", "<", "<=", ">", ">=", "~="})
_GO_VERSION = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)
_GO_COMPARATOR = re.compile(r"^(<=|>=|<|>|=)?(v?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$")
NUGET_VERSION_SEMANTICS_CONTRACT_VERSION = "2026-09-10.1"
_NUGET_VERSION = re.compile(
    r"^(\d+(?:\.\d+){0,3})(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_NUGET_COMPARATOR = re.compile(r"^(<=|>=|<|>|=)?(.+)$")
_NUGET_MAX_VERSION_LENGTH = 64
_NUGET_MAX_INTEGER = 2_147_483_647
_MAVEN_SAFE_VERSION = re.compile(
    r"^(?P<core>(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))*)"
    r"(?:(?P<separator>[.-])(?P<qualifier>alpha|a|beta|b|milestone|m|rc|cr|snapshot|ga|final|release|sp)"
    r"(?:[.-]?(?P<qualifier_number>0|[1-9]\d*))?)?$",
    re.IGNORECASE,
)
_MAVEN_QUALIFIER_ALIASES = {
    "a": "alpha", "b": "beta", "m": "milestone", "cr": "rc",
    "ga": "", "final": "", "release": "",
}
_MAVEN_QUALIFIER_ORDER = {"alpha": 0, "beta": 1, "milestone": 2, "rc": 3, "snapshot": 4, "": 5, "sp": 6}


def match_exact_version_against_range(
    ecosystem: str,
    exact_version: str,
    affected_range: str,
) -> VersionRangeMatch:
    """Return whether an exact local version satisfies one safe affected range.

    The caller supplies an already-normalized ecosystem and an exact version;
    this function performs no package lookup, filesystem work, or network I/O.
    """

    if ecosystem == "npm":
        return _match_npm_version(exact_version, affected_range)
    if ecosystem == "pypi":
        return _match_pypi_version(exact_version, affected_range)
    if ecosystem == "go":
        return _match_go_version(exact_version, affected_range)
    if ecosystem == "cargo":
        return _match_semver_version(exact_version, affected_range, reason_prefix="cargo", allow_v_prefix=False)
    if ecosystem == "composer":
        return _match_semver_version(exact_version, affected_range, reason_prefix="composer", allow_v_prefix=False)
    if ecosystem == "maven":
        return _match_maven_version(exact_version, affected_range)
    if ecosystem == "nuget":
        return _match_nuget_version(exact_version, affected_range)
    return VersionRangeMatch("unknown", "unsupported_ecosystem")


def _match_npm_version(exact_version: str, affected_range: str) -> VersionRangeMatch:
    version, version_reason = _parse_npm_release_version(exact_version)
    if version is None:
        return VersionRangeMatch("unknown", version_reason)

    normalized_range = affected_range.strip()
    if not normalized_range:
        return VersionRangeMatch("unknown", "npm_empty_range")
    if any(marker in normalized_range for marker in ("||", "^", "~", "*", "x", "X")) or " - " in normalized_range:
        return VersionRangeMatch("unknown", "npm_range_syntax_not_supported")

    comparators = normalized_range.replace(",", " ").split()
    if not comparators:
        return VersionRangeMatch("unknown", "npm_empty_range")
    for comparator in comparators:
        parsed = _NPM_COMPARATOR.fullmatch(comparator)
        if parsed is None:
            return VersionRangeMatch("unknown", "npm_range_syntax_not_supported")
        operator = parsed.group(1) or "="
        candidate, candidate_reason = _parse_npm_release_version(parsed.group(2))
        if candidate is None:
            return VersionRangeMatch("unknown", candidate_reason)
        if not _compare_npm_versions(version, candidate, operator):
            return VersionRangeMatch("not_matched", "npm_comparator_not_satisfied")
    return VersionRangeMatch("matched", "npm_all_comparators_satisfied")


def _match_nuget_version(exact_version: str, affected_range: str) -> VersionRangeMatch:
    version = _parse_nuget_version(exact_version)
    if version is None:
        return VersionRangeMatch("unknown", "nuget_version_not_supported")
    comparators = affected_range.strip().replace(",", " ").split()
    if not comparators:
        return VersionRangeMatch("unknown", "nuget_empty_range")
    for comparator in comparators:
        matched = _NUGET_COMPARATOR.fullmatch(comparator)
        if matched is None:
            return VersionRangeMatch("unknown", "nuget_range_syntax_not_supported")
        bound = _parse_nuget_version(matched.group(2))
        if bound is None:
            return VersionRangeMatch("unknown", "nuget_range_syntax_not_supported")
        comparison = _compare_nuget_versions(version, bound)
        operator = matched.group(1) or "="
        if not {"=": comparison == 0, ">": comparison > 0, ">=": comparison >= 0, "<": comparison < 0, "<=": comparison <= 0}[operator]:
            return VersionRangeMatch("not_matched", "nuget_comparator_not_satisfied")
    return VersionRangeMatch("matched", "nuget_all_comparators_satisfied")


def canonicalize_nuget_version(value: str) -> str | None:
    """Return one bounded NuGetVersion identity string or reject the value.

    This mirrors the documented NuGet package-identity semantics without
    importing or executing .NET: one to four numeric segments, missing
    minor/patch values equal to zero, zero revision omitted, build metadata
    excluded from identity, and case-insensitive prerelease labels. Values
    beyond System.Version's signed integer domain remain unsupported.
    """

    parsed = _parse_nuget_version(value)
    if parsed is None:
        return None
    numbers, prerelease = parsed
    core = ".".join(str(part) for part in numbers[:3])
    if numbers[3] != 0:
        core = f"{core}.{numbers[3]}"
    if prerelease is None:
        return core
    labels = ".".join(str(item[1]) for item in prerelease)
    return f"{core}-{labels}"


def is_supported_maven_version(value: str) -> bool:
    """Return true only for the reviewed, reproducible ComparableVersion subset."""

    return _parse_maven_version(value) is not None


def _match_maven_version(exact_version: str, affected_range: str) -> VersionRangeMatch:
    version = _parse_maven_version(exact_version)
    if version is None:
        return VersionRangeMatch("unknown", "maven_version_not_supported")
    comparators = affected_range.strip().replace(",", " ").split()
    if not comparators:
        return VersionRangeMatch("unknown", "maven_empty_range")
    for comparator in comparators:
        matched = re.fullmatch(r"(<=|>=|<|>|=)?(.+)", comparator)
        if matched is None:
            return VersionRangeMatch("unknown", "maven_range_syntax_not_supported")
        bound = _parse_maven_version(matched.group(2))
        if bound is None:
            return VersionRangeMatch("unknown", "maven_range_syntax_not_supported")
        comparison = _compare_maven_versions(version, bound)
        operator = matched.group(1) or "="
        if not {"=": comparison == 0, ">": comparison > 0, ">=": comparison >= 0, "<": comparison < 0, "<=": comparison <= 0}[operator]:
            return VersionRangeMatch("not_matched", "maven_comparator_not_satisfied")
    return VersionRangeMatch("matched", "maven_all_comparators_satisfied")


def _parse_maven_version(value: str) -> tuple[tuple[int, ...], int, int] | None:
    """Parse a strict subset whose order is identical to Maven ComparableVersion.

    Unknown qualifiers, mixed separators, build metadata and ambiguous forms
    remain unsupported instead of being coerced.
    """

    normalized = value.strip()
    if not normalized or len(normalized) > 160:
        return None
    matched = _MAVEN_SAFE_VERSION.fullmatch(normalized)
    if matched is None:
        return None
    numbers = [int(part) for part in matched.group("core").split(".")]
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers.pop()
    qualifier = (matched.group("qualifier") or "").lower()
    separator = matched.group("separator")
    if separator == "." and qualifier not in {"ga", "final", "release"}:
        return None
    if qualifier in {"a", "b", "m"} and matched.group("qualifier_number") is None:
        return None
    qualifier = _MAVEN_QUALIFIER_ALIASES.get(qualifier, qualifier)
    qualifier_number_text = matched.group("qualifier_number")
    if qualifier in {"", "snapshot"} and qualifier_number_text is not None:
        return None
    qualifier_number = int(qualifier_number_text) if qualifier_number_text is not None else 0
    return tuple(numbers), _MAVEN_QUALIFIER_ORDER[qualifier], qualifier_number


def _compare_maven_versions(left: tuple[tuple[int, ...], int, int], right: tuple[tuple[int, ...], int, int]) -> int:
    width = max(len(left[0]), len(right[0]))
    left_numbers, right_numbers = left[0] + (0,) * (width - len(left[0])), right[0] + (0,) * (width - len(right[0]))
    if left_numbers != right_numbers:
        return -1 if left_numbers < right_numbers else 1
    if left[1:] == right[1:]:
        return 0
    return -1 if left[1:] < right[1:] else 1


def _parse_nuget_version(value: str) -> tuple[tuple[int, int, int, int], tuple[tuple[int, int | str], ...] | None] | None:
    normalized = value.strip()
    if not normalized or len(normalized) > _NUGET_MAX_VERSION_LENGTH:
        return None
    matched = _NUGET_VERSION.fullmatch(normalized)
    if matched is None:
        return None
    numbers = tuple(int(part) for part in matched.group(1).split("."))
    if any(part > _NUGET_MAX_INTEGER for part in numbers):
        return None
    padded = (numbers + (0, 0, 0, 0))[:4]
    prerelease = matched.group(2)
    if prerelease is None:
        return padded, None
    parts = prerelease.split(".")
    if any(not part or (part.isdigit() and int(part) > _NUGET_MAX_INTEGER) for part in parts):
        return None
    return padded, tuple((0, int(part)) if part.isdigit() else (1, part.lower()) for part in parts)


def _compare_nuget_versions(
    left: tuple[tuple[int, int, int, int], tuple[tuple[int, int | str], ...] | None],
    right: tuple[tuple[int, int, int, int], tuple[tuple[int, int | str], ...] | None],
) -> int:
    if left[0] != right[0]:
        return -1 if left[0] < right[0] else 1
    left_pre, right_pre = left[1], right[1]
    if left_pre is None or right_pre is None:
        if left_pre is right_pre:
            return 0
        return 1 if left_pre is None else -1
    for left_item, right_item in zip(left_pre, right_pre):
        if left_item == right_item:
            continue
        if left_item[0] != right_item[0]:
            return -1 if left_item[0] < right_item[0] else 1
        return -1 if left_item[1] < right_item[1] else 1
    if len(left_pre) == len(right_pre):
        return 0
    return -1 if len(left_pre) < len(right_pre) else 1


def _parse_npm_release_version(value: str) -> tuple[tuple[int, int, int] | None, str]:
    normalized = value.strip()
    if "-" in normalized.split("+", 1)[0]:
        return None, "npm_prerelease_not_supported"
    matched = _NPM_RELEASE_VERSION.fullmatch(normalized)
    if matched is None:
        return None, "npm_version_not_supported"
    return (int(matched.group(1)), int(matched.group(2)), int(matched.group(3))), "npm_release_version"


def _compare_npm_versions(left: tuple[int, int, int], right: tuple[int, int, int], operator: str) -> bool:
    if operator == "=":
        return left == right
    if operator == ">":
        return left > right
    if operator == ">=":
        return left >= right
    if operator == "<":
        return left < right
    return left <= right


def _match_pypi_version(exact_version: str, affected_range: str) -> VersionRangeMatch:
    try:
        version = Version(exact_version.strip())
    except InvalidVersion:
        return VersionRangeMatch("unknown", "pypi_version_not_supported")
    if version.is_prerelease:
        return VersionRangeMatch("unknown", "pypi_prerelease_not_supported")

    normalized_range = affected_range.strip()
    if not normalized_range:
        return VersionRangeMatch("unknown", "pypi_empty_range")
    try:
        specifier_set = SpecifierSet(normalized_range)
    except InvalidSpecifier:
        return VersionRangeMatch("unknown", "pypi_range_syntax_not_supported")
    specifiers = tuple(specifier_set)
    if not specifiers:
        return VersionRangeMatch("unknown", "pypi_empty_range")
    for specifier in specifiers:
        if specifier.operator not in _PYPI_SUPPORTED_OPERATORS or "*" in specifier.version:
            return VersionRangeMatch("unknown", "pypi_range_syntax_not_supported")
        try:
            bound_version = Version(specifier.version)
        except InvalidVersion:
            return VersionRangeMatch("unknown", "pypi_range_syntax_not_supported")
        if bound_version.is_prerelease:
            return VersionRangeMatch("unknown", "pypi_prerelease_not_supported")
    return VersionRangeMatch(
        "matched" if version in specifier_set else "not_matched",
        "pypi_specifier_satisfied" if version in specifier_set else "pypi_specifier_not_satisfied",
    )


def _match_go_version(exact_version: str, affected_range: str) -> VersionRangeMatch:
    return _match_semver_version(exact_version, affected_range, reason_prefix="go", allow_v_prefix=True)


def _match_semver_version(
    exact_version: str,
    affected_range: str,
    *,
    reason_prefix: str,
    allow_v_prefix: bool,
) -> VersionRangeMatch:
    version = _parse_go_version(exact_version)
    if not allow_v_prefix and exact_version.strip().startswith("v"):
        version = None
    if version is None:
        return VersionRangeMatch("unknown", f"{reason_prefix}_version_not_supported")
    comparators = affected_range.strip().replace(",", " ").split()
    if not comparators:
        return VersionRangeMatch("unknown", f"{reason_prefix}_empty_range")
    for comparator in comparators:
        matched = _GO_COMPARATOR.fullmatch(comparator)
        if matched is None:
            return VersionRangeMatch("unknown", f"{reason_prefix}_range_syntax_not_supported")
        bound = _parse_go_version(matched.group(2))
        if bound is None or (not allow_v_prefix and matched.group(2).startswith("v")):
            return VersionRangeMatch("unknown", f"{reason_prefix}_range_syntax_not_supported")
        comparison = _compare_go_versions(version, bound)
        operator = matched.group(1) or "="
        satisfied = {
            "=": comparison == 0,
            ">": comparison > 0,
            ">=": comparison >= 0,
            "<": comparison < 0,
            "<=": comparison <= 0,
        }[operator]
        if not satisfied:
            return VersionRangeMatch("not_matched", f"{reason_prefix}_comparator_not_satisfied")
    return VersionRangeMatch("matched", f"{reason_prefix}_all_comparators_satisfied")


def _parse_go_version(value: str) -> tuple[int, int, int, tuple[tuple[int, int | str], ...] | None] | None:
    matched = _GO_VERSION.fullmatch(value.strip())
    if matched is None:
        return None
    prerelease = matched.group(4)
    identifiers: tuple[tuple[int, int | str], ...] | None = None
    if prerelease is not None:
        parts = prerelease.split(".")
        if any(not part for part in parts):
            return None
        identifiers = tuple(
            (0, int(part)) if part.isdigit() else (1, part)
            for part in parts
        )
    return int(matched.group(1)), int(matched.group(2)), int(matched.group(3)), identifiers


def _compare_go_versions(
    left: tuple[int, int, int, tuple[tuple[int, int | str], ...] | None],
    right: tuple[int, int, int, tuple[tuple[int, int | str], ...] | None],
) -> int:
    if left[:3] != right[:3]:
        return -1 if left[:3] < right[:3] else 1
    left_pre, right_pre = left[3], right[3]
    if left_pre is None or right_pre is None:
        if left_pre is right_pre:
            return 0
        return 1 if left_pre is None else -1
    for left_item, right_item in zip(left_pre, right_pre):
        if left_item == right_item:
            continue
        if left_item[0] != right_item[0]:
            return -1 if left_item[0] < right_item[0] else 1
        return -1 if left_item[1] < right_item[1] else 1
    if len(left_pre) == len(right_pre):
        return 0
    return -1 if len(left_pre) < len(right_pre) else 1
