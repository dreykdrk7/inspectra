from datetime import datetime, timezone
import json
from pathlib import Path

from app.cisa_kev import CISA_KEV_CATALOG_URL, CISA_KEV_CONTRACT_VERSION, normalize_cisa_kev_feed


FIXTURE = Path(__file__).parent / "fixtures" / "cisa" / "kev-valid.json"


def test_cisa_kev_fixture_keeps_only_exact_cve_priority_evidence():
    result = normalize_cisa_kev_feed(json.loads(FIXTURE.read_text(encoding="utf-8")))

    assert result.status == "ready"
    assert result.catalog_version == "2026.09.05"
    signal = result.signals_by_cve["CVE-2025-1234"]
    assert signal.contract_version == CISA_KEV_CONTRACT_VERSION
    assert signal.status == "known_exploited"
    assert signal.date_added == "2026-09-04"
    assert signal.due_date == "2026-09-18"
    assert signal.required_action == "Apply the vendor update or mitigation by the due date."
    assert signal.source_url == CISA_KEV_CATALOG_URL
    assert "Example vendor" not in json.dumps(signal.to_dict())


def test_cisa_kev_rejects_ambiguous_catalog_and_marks_bad_rows_as_incomplete_coverage():
    valid = json.loads(FIXTURE.read_text(encoding="utf-8"))
    invalid = dict(valid["vulnerabilities"][0])
    invalid["cveID"] = "not-a-cve"
    valid["vulnerabilities"].append(invalid)
    valid["count"] = 2

    partially_valid = normalize_cisa_kev_feed(valid)

    assert partially_valid.status == "ready"
    assert partially_valid.errors == ("cisa_kev_invalid_entries",)

    conflicting = json.loads(FIXTURE.read_text(encoding="utf-8"))
    duplicate = dict(conflicting["vulnerabilities"][0])
    duplicate["requiredAction"] = "Different action"
    conflicting["vulnerabilities"].append(duplicate)
    conflicting["count"] = 2
    result = normalize_cisa_kev_feed(conflicting)

    assert result.status == "invalid_source_response"
    assert result.errors == ("cisa_kev_conflicting_duplicate_cve",)


def test_cisa_kev_requires_catalog_version_release_date_and_safe_required_action():
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload.pop("catalogVersion")
    assert normalize_cisa_kev_feed(payload).status == "invalid_source_response"

    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["vulnerabilities"][0]["requiredAction"] = "line one\nline two"
    result = normalize_cisa_kev_feed(payload)
    assert result.status == "ready"
    assert result.signals_by_cve == {}
    assert result.errors == ("cisa_kev_invalid_entries",)


def test_cisa_kev_accepts_the_catalog_release_timestamp_variant_without_accepting_naive_time():
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["dateReleased"] = "2026-09-05T12:00:00.000Z"
    assert normalize_cisa_kev_feed(payload).date_released == "2026-09-05T12:00:00Z"

    payload["dateReleased"] = "2026-09-05T12:00:00"
    assert normalize_cisa_kev_feed(payload).status == "invalid_source_response"


def test_cisa_kev_detects_schema_count_version_and_release_date_drift():
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["unexpected"] = "field"
    assert normalize_cisa_kev_feed(payload).errors == ("cisa_kev_schema_changed",)

    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["vulnerabilities"][0]["unexpected"] = "field"
    assert normalize_cisa_kev_feed(payload).errors == ("cisa_kev_schema_changed",)

    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["count"] = 2
    assert normalize_cisa_kev_feed(payload).status == "invalid_source_response"

    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["catalogVersion"] = "unversioned"
    assert normalize_cisa_kev_feed(payload).status == "invalid_source_response"

    stale = normalize_cisa_kev_feed(
        json.loads(FIXTURE.read_text(encoding="utf-8")),
        observed_at=datetime(2026, 9, 13, tzinfo=timezone.utc),
    )
    assert stale.status == "ready"
    assert stale.freshness == "stale"

    future = normalize_cisa_kev_feed(
        json.loads(FIXTURE.read_text(encoding="utf-8")),
        observed_at=datetime(2026, 9, 4, tzinfo=timezone.utc),
    )
    assert future.status == "invalid_source_response"
    assert future.errors == ("cisa_kev_release_date_invalid",)
