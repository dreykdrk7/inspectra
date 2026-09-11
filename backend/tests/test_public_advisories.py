import json
from pathlib import Path

from app.public_advisories import MAX_OSV_RANGES_PER_ADVISORY, PUBLIC_ADVISORY_CONTRACT_VERSION, normalize_osv_batch_response
from app.public_advisory_egress import PublicComponentIdentity
from app.vulnerability_correlation import correlate_advisory


FIXTURES = Path(__file__).parent / "fixtures" / "osv"


def components():
    return [
        PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1"),
        PublicComponentIdentity(ecosystem="pypi", name="requests", version="2.32.0"),
    ]


def test_valid_osv_fixture_normalizes_only_safe_traced_advisory_fields():
    payload = json.loads((FIXTURES / "querybatch-valid.json").read_text(encoding="utf-8"))

    result = normalize_osv_batch_response(components(), payload)

    assert result.status == "ready"
    assert result.errors == ()
    assert len(result.advisories) == 1
    advisory = result.advisories[0]
    assert advisory.contract_version == PUBLIC_ADVISORY_CONTRACT_VERSION
    assert advisory.provider == "osv"
    assert advisory.provider_advisory_id == "GHSA-aaaa-bbbb-cccc"
    assert advisory.component == components()[0]
    assert advisory.aliases == ("CVE-2025-12345", "GHSA-AAAA-BBBB-CCCC")
    assert advisory.affected_ranges[0].introduced == "0"
    assert advisory.affected_ranges[0].fixed == "18.3.2"
    assert advisory.fixed_versions == ("18.3.2",)
    assert advisory.severity[0].vector.startswith("CVSS:3.1/")
    assert advisory.severity[0].base_score == 9.8
    assert advisory.severity[0].band == "critical"
    assert advisory.severity[0].score_status == "derived_from_vector"
    assert advisory.severity[0].cvss_version == "3.1"
    assert advisory.published_at == "2025-01-02T03:04:05Z"
    assert advisory.updated_at == "2025-02-03T04:05:06Z"
    assert advisory.withdrawn_at == "2025-03-04T05:06:07Z"
    assert advisory.references[0].url == "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc"
    assert all(reference.url.startswith("https://") for reference in advisory.references)
    rendered = json.dumps(advisory.to_dict())
    assert "javascript:" not in rendered
    assert "project" not in rendered.lower()
    assert "owner" not in rendered.lower()


def test_osv_cvss_v4_without_source_score_derives_first_compatible_score():
    payload = json.loads((FIXTURES / "querybatch-valid.json").read_text(encoding="utf-8"))
    payload["results"][0]["vulns"][0]["severity"] = [{
        "type": "CVSS_V4",
        "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    }]

    result = normalize_osv_batch_response(components(), payload)

    assert result.status == "ready"
    metric = result.advisories[0].severity[0]
    assert (metric.cvss_version, metric.base_score, metric.band, metric.score_status) == (
        "4.0", 9.3, "critical", "derived_from_vector"
    )


def test_batch_shape_or_component_mismatch_is_a_controlled_data_error_not_clean_coverage():
    assert normalize_osv_batch_response(components(), {"results": []}).status == "invalid_source_response"
    unrelated = {
        "results": [
            {"vulns": [{"id": "CVE-2025-1234", "affected": [{"package": {"ecosystem": "npm", "name": "other"}, "ranges": []}]}]},
            {"vulns": []},
        ]
    }

    result = normalize_osv_batch_response(components(), unrelated)

    assert result.status == "invalid_source_response"
    assert result.advisories == ()
    assert "osv_advisory_invalid_or_unrelated" in result.errors


def test_exact_duplicates_are_removed_but_conflicting_evidence_is_not_merged():
    raw = {
        "id": "CVE-2025-1234",
        "affected": [{"package": {"ecosystem": "npm", "name": "react"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]}],
    }
    changed = {
        **raw,
        "affected": [{"package": {"ecosystem": "npm", "name": "react"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.2"}]}]}],
    }
    payload = {"results": [{"vulns": [raw, raw, changed]}, {"vulns": []}]}

    result = normalize_osv_batch_response(components(), payload)

    assert result.status == "ready"
    assert len(result.advisories) == 2
    assert {item.fixed_versions for item in result.advisories} == {("1.0.1",), ("1.0.2",)}


def test_nuget_range_versions_are_canonicalized_without_retaining_build_metadata():
    component = PublicComponentIdentity(
        ecosystem="nuget", name="newtonsoft.json", version="13.0.3-beta.10"
    )
    payload = {"results": [{"vulns": [{
        "id": "GHSA-aaaa-bbbb-cccc",
        "affected": [{
            "package": {"ecosystem": "NuGet", "name": "newtonsoft.json"},
            "ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "013.0.00-BETA.001+internal-agent"},
                {"fixed": "13.0.03.0+private-build"},
            ]}],
        }],
    }]}]}

    result = normalize_osv_batch_response([component], payload)

    assert result.status == "ready"
    advisory = result.advisories[0]
    assert advisory.affected_ranges[0].introduced == "13.0.0-beta.1"
    assert advisory.affected_ranges[0].fixed == "13.0.3"
    assert advisory.fixed_versions == ("13.0.3",)
    assert "private" not in json.dumps(advisory.to_dict())


def test_hostile_ids_urls_dates_and_ranges_are_withheld_or_rejected():
    payload = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "<script>alert(1)</script>",
                        "published": "not-a-date",
                        "references": [{"url": "https://user:password@example.test/advisory"}],
                        "affected": [{"package": {"ecosystem": "npm", "name": "react"}, "ranges": [{"events": [{"fixed": "1.0.0\\path"}]}]}],
                    }
                ]
            },
            {"vulns": []},
        ]
    }

    result = normalize_osv_batch_response(components(), payload)

    assert result.status == "invalid_source_response"
    assert result.advisories == ()


def test_discontinuous_osv_events_remain_separate_intervals_and_match_a_reintroduced_version():
    target = PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")
    payload = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "CVE-2026-1234",
                        "affected": [
                            {
                                "package": {"ecosystem": "npm", "name": "react"},
                                "ranges": [
                                    {
                                        "type": "SEMVER",
                                        "events": [
                                            {"introduced": "0"},
                                            {"fixed": "18.3.0"},
                                            {"introduced": "18.3.1"},
                                            {"fixed": "18.3.2"},
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ]
    }

    result = normalize_osv_batch_response([target], payload)
    advisory = result.advisories[0]

    assert result.status == "ready"
    assert advisory.affected_ranges_complete is True
    assert [(item.introduced, item.fixed, item.last_affected) for item in advisory.affected_ranges] == [
        ("0", "18.3.0", None),
        ("18.3.1", "18.3.2", None),
    ]
    assert correlate_advisory(target, advisory).status == "affected"


def test_unrepresentable_or_over_limit_osv_intervals_are_preserved_as_incomplete_not_negative_coverage():
    target = components()[0]
    excessive_events = []
    for index in range(MAX_OSV_RANGES_PER_ADVISORY + 1):
        excessive_events.extend(({"introduced": f"{index}.0.0"}, {"fixed": f"{index}.0.1"}))
    payload = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "CVE-2026-1234",
                        "affected": [
                            {
                                "package": {"ecosystem": "npm", "name": "react"},
                                "ranges": [
                                    {"type": "SEMVER", "events": [{"fixed": "18.3.2"}]},
                                    {"type": "SEMVER", "events": excessive_events},
                                ],
                            }
                        ],
                    }
                ]
            },
            {"vulns": []},
        ]
    }

    result = normalize_osv_batch_response(components(), payload)
    advisory = result.advisories[0]

    assert result.status == "ready"
    assert advisory.affected_ranges_complete is False
    assert len(advisory.affected_ranges) <= MAX_OSV_RANGES_PER_ADVISORY
    assert correlate_advisory(target, advisory).status == "unknown"
    assert correlate_advisory(target, advisory).reason == "affected_ranges_incomplete"
