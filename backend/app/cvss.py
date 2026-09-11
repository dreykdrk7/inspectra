"""Small, deterministic CVSS vector validator and v3/v4 score evaluator.

The evaluator is intentionally not a vulnerability source.  It only derives a
score from a provider-supplied CVSS vector so Inspectra can make that vector
easier to triage.  An unsupported or malformed vector remains ``unknown``;
callers must retain the original vector and never invent a score.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Literal

from cvss import CVSS4
import cvss.cvss4 as _cvss4_implementation
from cvss.exceptions import CVSS4Error


CvssBand = Literal["none", "low", "medium", "high", "critical", "unknown"]
CvssScoreStatus = Literal["derived_from_vector", "source_provided", "not_available"]
CvssVersion = Literal["3.0", "3.1", "4.0"]


@dataclass(frozen=True)
class CvssAssessment:
    base_score: float | None
    band: CvssBand
    score_status: CvssScoreStatus
    version: CvssVersion | None = None


_BASE_METRICS = frozenset({"AV", "AC", "PR", "UI", "S", "C", "I", "A"})
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_V3_OPTIONAL_METRICS = {
    "E": frozenset({"X", "U", "P", "F", "H"}),
    "RL": frozenset({"X", "O", "T", "W", "U"}),
    "RC": frozenset({"X", "U", "R", "C"}),
    "CR": frozenset({"X", "H", "M", "L"}),
    "IR": frozenset({"X", "H", "M", "L"}),
    "AR": frozenset({"X", "H", "M", "L"}),
    "MAV": frozenset({"X", "N", "A", "L", "P"}),
    "MAC": frozenset({"X", "L", "H"}),
    "MPR": frozenset({"X", "N", "L", "H"}),
    "MUI": frozenset({"X", "N", "R"}),
    "MS": frozenset({"X", "U", "C"}),
    "MC": frozenset({"X", "N", "L", "H"}),
    "MI": frozenset({"X", "N", "L", "H"}),
    "MA": frozenset({"X", "N", "L", "H"}),
}
_V4_BASE_METRICS = {
    "AV": frozenset({"N", "A", "L", "P"}),
    "AC": frozenset({"L", "H"}),
    "AT": frozenset({"N", "P"}),
    "PR": frozenset({"N", "L", "H"}),
    "UI": frozenset({"N", "P", "A"}),
    "VC": frozenset({"H", "L", "N"}),
    "VI": frozenset({"H", "L", "N"}),
    "VA": frozenset({"H", "L", "N"}),
    "SC": frozenset({"H", "L", "N"}),
    "SI": frozenset({"H", "L", "N"}),
    "SA": frozenset({"H", "L", "N"}),
}
_V4_OPTIONAL_METRICS = {
    "E": frozenset({"X", "A", "P", "U"}),
    "CR": frozenset({"X", "H", "M", "L"}),
    "IR": frozenset({"X", "H", "M", "L"}),
    "AR": frozenset({"X", "H", "M", "L"}),
    "MAV": frozenset({"X", "N", "A", "L", "P"}),
    "MAC": frozenset({"X", "L", "H"}),
    "MAT": frozenset({"X", "N", "P"}),
    "MPR": frozenset({"X", "N", "L", "H"}),
    "MUI": frozenset({"X", "N", "P", "A"}),
    "MVC": frozenset({"X", "H", "L", "N"}),
    "MVI": frozenset({"X", "H", "L", "N"}),
    "MVA": frozenset({"X", "H", "L", "N"}),
    "MSC": frozenset({"X", "H", "L", "N"}),
    "MSI": frozenset({"X", "S", "H", "L", "N"}),
    "MSA": frozenset({"X", "S", "H", "L", "N"}),
    "S": frozenset({"X", "N", "P"}),
    "AU": frozenset({"X", "N", "Y"}),
    "R": frozenset({"X", "A", "U", "I"}),
    "V": frozenset({"X", "D", "C"}),
    "RE": frozenset({"X", "L", "M", "H"}),
    "U": frozenset({"X", "Clear", "Green", "Amber", "Red"}),
}
_V4_METRIC_ORDER = tuple(_V4_BASE_METRICS) + tuple(_V4_OPTIONAL_METRICS)


def _official_cvss_v4_rounding(value: float) -> float:
    """Match the FIRST reference calculator's ``Math.round(value * 10)``."""

    return math.floor(value * 10 + 0.5) / 10


# cvss 3.6 is a maintained Python port of the FIRST algorithm, but adds an
# EPSILON before final rounding.  That differs from the reference calculator
# and FIRST's base/threat corpus at exact binary-float boundaries.  The version
# is pinned and this one hook restores the reference implementation semantics.
_cvss4_implementation.final_rounding = _official_cvss_v4_rounding


def assess_cvss_v3_vector(vector: object) -> CvssAssessment:
    """Derive a CVSS 3.0/3.1 base score, or explicitly return unknown.

    Formula and qualitative bands follow the public CVSS v3.1 specification:
    https://www.first.org/cvss/v3.1/specification-document
    """

    metrics = _parse_base_metrics(vector)
    if metrics is None:
        return CvssAssessment(None, "unknown", "not_available")
    version = str(vector).split("/", 1)[0].removeprefix("CVSS:")
    scope = metrics["S"]
    impact_sub_score = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
    if impact_sub_score <= 0:
        return CvssAssessment(0.0, "none", "derived_from_vector", version)  # type: ignore[arg-type]

    impact = (
        6.42 * impact_sub_score
        if scope == "U"
        else 7.52 * (impact_sub_score - 0.029) - 3.25 * (impact_sub_score - 0.02) ** 15
    )
    privileges_required = (_PR_UNCHANGED if scope == "U" else _PR_CHANGED)[metrics["PR"]]
    exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * privileges_required * _UI[metrics["UI"]]
    score = min(impact + exploitability, 10.0)
    if scope == "C":
        score = min(1.08 * score, 10.0)
    rounded = _round_up(score)
    return CvssAssessment(rounded, cvss_band_for_score(rounded), "derived_from_vector", version)  # type: ignore[arg-type]


def assess_cvss_metric(
    kind: object,
    vector: object,
    *,
    source_score: object = None,
) -> CvssAssessment | None:
    """Validate a provider metric without mixing CVSS generations.

    CVSS v3 and v4 scores can be derived deterministically. A finite score
    published by the source remains authoritative and is never replaced by a
    derived value.
    """

    if not isinstance(kind, str):
        return None
    normalized_kind = kind.upper()
    version = cvss_version_for_vector(vector)
    if version is None:
        return None
    if (normalized_kind == "CVSS_V3" and version not in {"3.0", "3.1"}) or (
        normalized_kind == "CVSS_V4" and version != "4.0"
    ):
        return None
    if normalized_kind not in {"CVSS_V3", "CVSS_V4"}:
        return None
    if (
        isinstance(source_score, (int, float))
        and not isinstance(source_score, bool)
        and math.isfinite(source_score)
        and 0 <= source_score <= 10
    ):
        score = float(source_score)
        return CvssAssessment(score, cvss_band_for_score(score), "source_provided", version)
    if normalized_kind == "CVSS_V3":
        return assess_cvss_v3_vector(vector)
    return assess_cvss_v4_vector(vector)


def assess_cvss_v4_vector(vector: object) -> CvssAssessment:
    """Derive a CVSS v4 score using the pinned FIRST-compatible algorithm."""

    parsed = _parse_vector(vector)
    if parsed is None or parsed[0] != "4.0":
        return CvssAssessment(None, "unknown", "not_available")
    try:
        score = float(CVSS4(str(vector)).scores()[0])
    except (CVSS4Error, KeyError, TypeError, ValueError, ArithmeticError):
        return CvssAssessment(None, "unknown", "not_available", "4.0")
    if not math.isfinite(score) or not 0 <= score <= 10:
        return CvssAssessment(None, "unknown", "not_available", "4.0")
    return CvssAssessment(score, cvss_band_for_score(score), "derived_from_vector", "4.0")


def cvss_version_for_vector(vector: object) -> CvssVersion | None:
    """Return the supported CVSS generation only for a valid vector shape."""

    parsed = _parse_vector(vector)
    return parsed[0] if parsed is not None else None


def cvss_band_for_score(score: float) -> CvssBand:
    """Map an already validated CVSS score to its standard band."""

    if not isinstance(score, (float, int)) or isinstance(score, bool) or score < 0 or score > 10:
        return "unknown"
    if score == 0:
        return "none"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def _parse_base_metrics(vector: object) -> dict[str, str] | None:
    parsed = _parse_vector(vector)
    if parsed is None or parsed[0] not in {"3.0", "3.1"}:
        return None
    metrics = parsed[1]
    if set(metrics) != _BASE_METRICS:
        return None
    if (
        metrics["AV"] not in _AV
        or metrics["AC"] not in _AC
        or metrics["PR"] not in _PR_UNCHANGED
        or metrics["UI"] not in _UI
        or metrics["S"] not in {"U", "C"}
        or any(metrics[key] not in _CIA for key in ("C", "I", "A"))
    ):
        return None
    return metrics


def _parse_vector(vector: object) -> tuple[CvssVersion, dict[str, str]] | None:
    if not isinstance(vector, str) or len(vector) > 256 or any(character.isspace() for character in vector):
        return None
    parts = vector.split("/")
    if not parts or parts[0] not in {"CVSS:3.0", "CVSS:3.1", "CVSS:4.0"}:
        return None
    version: CvssVersion = parts[0].removeprefix("CVSS:")  # type: ignore[assignment]
    allowed = (
        {
            "AV": frozenset(_AV), "AC": frozenset(_AC), "PR": frozenset(_PR_UNCHANGED),
            "UI": frozenset(_UI), "S": frozenset({"U", "C"}),
            "C": frozenset(_CIA), "I": frozenset(_CIA), "A": frozenset(_CIA),
            **_V3_OPTIONAL_METRICS,
        }
        if version in {"3.0", "3.1"}
        else {**_V4_BASE_METRICS, **_V4_OPTIONAL_METRICS}
    )
    required = _BASE_METRICS if version in {"3.0", "3.1"} else frozenset(_V4_BASE_METRICS)
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if part.count(":") != 1:
            return None
        key, value = part.split(":", 1)
        if key in metrics or key not in allowed or value not in allowed[key]:
            return None
        metrics[key] = value
    if not required.issubset(metrics):
        return None
    if version == "4.0" and tuple(metrics) != tuple(
        key for key in _V4_METRIC_ORDER if key in metrics
    ):
        return None
    return version, metrics


def _round_up(value: float) -> float:
    # CVSS requires rounding up to one decimal, not ordinary nearest rounding.
    return math.ceil(value * 10 - 1e-9) / 10
