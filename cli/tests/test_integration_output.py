import hashlib
import json
from pathlib import Path

from jsonschema import Draft4Validator

from inspectra_cli.integration_output import render_json, render_markdown, render_sarif


SCHEMA_PATH = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0-errata01.json"
SCHEMA_SHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"


def validate_sarif(rendered: str) -> dict:
    schema_bytes = SCHEMA_PATH.read_bytes()
    assert hashlib.sha256(schema_bytes).hexdigest() == SCHEMA_SHA256
    schema = json.loads(schema_bytes)
    Draft4Validator.check_schema(schema)
    document = json.loads(rendered)
    errors = sorted(Draft4Validator(schema).iter_errors(document), key=lambda item: list(item.absolute_path))
    assert errors == [], "\n".join(error.message for error in errors[:10])
    return document


def payload():
    return {
        "status": "completed",
        "analysis_id": "a" * 32,
        "policy": {"policy": "standard", "verdict": "fail", "incomplete_reasons": []},
        "finding_results": [
            {
                "rule_id": "SEC-TEST",
                "title": "Unsafe configuration",
                "severity": "high",
                "recommendation": "Enable the safe setting.",
                "location_status": "reported",
                "location": {"path": "src/settings.py", "line": 12},
            },
            {
                "advisory_id": "GHSA-xxxx-yyyy-zzzz",
                "cvss_band": "critical",
                "recommendation": "Upgrade the dependency.",
                "location_status": "withheld_unsafe_path",
                "location": {"path": "/home/private/source.py", "line": 1},
            },
        ],
    }


def test_ci_outputs_are_valid_bounded_and_withhold_unsafe_paths():
    document = payload()
    assert json.loads(render_json(document))["policy"]["verdict"] == "fail"
    markdown = render_markdown(document)
    assert "Unsafe configuration" in markdown
    sarif = validate_sarif(render_sarif(document))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/settings.py"
    assert "locations" not in sarif["runs"][0]["results"][1]
    assert "/home/private" not in json.dumps(sarif)


def test_sarif_official_schema_accepts_empty_unknown_and_bounded_result_sets():
    empty = validate_sarif(render_sarif({"policy": {}, "finding_results": []}))
    assert empty["runs"][0]["results"] == []

    unknown = validate_sarif(render_sarif({
        "policy": {"policy": "observe", "verdict": "inconclusive", "incomplete_reasons": ["provider_partial"]},
        "finding_results": [{"rule_id": "UNKNOWN", "severity": "future-band", "title": "Review evidence"}],
    }))
    assert unknown["runs"][0]["results"][0]["level"] == "note"
    assert unknown["runs"][0]["properties"]["inspectraIncompleteReasons"] == ["provider_partial"]

    bounded = validate_sarif(render_sarif({
        "policy": {"policy": "strict", "verdict": "fail"},
        "finding_results": [
            {"rule_id": f"RULE-{index}", "severity": "high", "title": f"Finding {index}"}
            for index in range(1001)
        ],
    }))
    assert len(bounded["runs"][0]["results"]) == 1000
    assert len(bounded["runs"][0]["tool"]["driver"]["rules"]) == 1000
