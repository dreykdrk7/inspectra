import pytest

from app.cvss import assess_cvss_metric, assess_cvss_v3_vector, cvss_band_for_score


def test_cvss_v31_vector_derives_a_standard_base_score_and_band():
    assessment = assess_cvss_v3_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    assert assessment.base_score == 9.8
    assert assessment.band == "critical"
    assert assessment.score_status == "derived_from_vector"
    assert assessment.version == "3.1"


def test_cvss_none_vector_and_qualitative_boundaries_are_explicit():
    assessment = assess_cvss_v3_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")

    assert assessment.base_score == 0.0
    assert assessment.band == "none"
    assert [cvss_band_for_score(score) for score in (0, 0.1, 3.9, 4, 6.9, 7, 8.9, 9, 10)] == [
        "none", "low", "low", "medium", "medium", "high", "high", "critical", "critical"
    ]


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
        "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/INVALID",
    ],
)
def test_unsupported_or_malformed_vectors_stay_unknown(vector):
    assessment = assess_cvss_v3_vector(vector)

    assert assessment.base_score is None
    assert assessment.band == "unknown"
    assert assessment.score_status == "not_available"


def test_cvss_v4_is_validated_but_only_uses_a_score_published_by_the_source():
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

    published = assess_cvss_metric("CVSS_V4", vector, source_score=9.3)
    absent = assess_cvss_metric("CVSS_V4", vector)

    assert published is not None
    assert (published.version, published.base_score, published.band, published.score_status) == (
        "4.0", 9.3, "critical", "source_provided"
    )
    assert absent is not None
    assert (absent.version, absent.base_score, absent.band, absent.score_status) == (
        "4.0", None, "unknown", "not_available"
    )


@pytest.mark.parametrize(
    ("kind", "vector"),
    [
        ("CVSS_V3", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
        ("CVSS_V4", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        ("CVSS_V4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N"),
        ("CVSS_V4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/X:Y"),
        ("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:INVALID"),
    ],
)
def test_cvss_generation_mismatch_incomplete_or_unknown_metrics_are_rejected(kind, vector):
    assert assess_cvss_metric(kind, vector, source_score=9.9) is None
