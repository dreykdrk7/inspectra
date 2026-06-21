import json
from pathlib import Path
import zipfile

from sanitizer_fixture_classifier import classify_directory, classify_zip, records_to_json


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "sanitizer"
FORBIDDEN_MARKER_VALUES = (
    "[FAKE_TOKEN_FOR_SANITIZER_FIXTURE]",
    "[REDACTED_SECRET_EXAMPLE_FOR_FIXTURE_TEST]",
    "[REDACTED_DOCS_EXAMPLE_API_KEY]",
    "[DEMO_FAKE_API_KEY_PLACEHOLDER]",
    "[BLOCKED_FAKE_ENV_SECRET_PLACEHOLDER]",
    "[BLOCKED_FAKE_KEY_FILE_PLACEHOLDER]",
    "[BLOCKED_FAKE_CONFIG_TOKEN_PLACEHOLDER]",
    "[BLOCKED_FAKE_RECORD_REFERENCE]",
)


def records_by_path(records):
    return {record.path: record for record in records}


def test_fixture_set_classifies_expected_paths_without_marker_values():
    records = classify_directory(FIXTURE_ROOT)
    by_path = records_by_path(records)

    assert by_path["safe_synthetic/tests/example_token_fixture.txt"].classification == "synthetic_test_fixture_marker"
    assert by_path["safe_synthetic/redaction/example_redacted_secret.txt"].classification == "redaction_example_marker"
    assert by_path["safe_synthetic/docs/example_placeholder.md"].classification == "documentation_example_marker"
    assert by_path["safe_synthetic/demo/generated_demo_config.txt"].classification == "generated_demo_fixture_marker"
    assert by_path["unsafe_counterexamples/.env"].classification == "blocked_private_material"
    assert by_path["unsafe_counterexamples/private.key"].classification == "blocked_private_material"
    assert by_path["unsafe_counterexamples/config_with_token.txt"].classification == "real_or_unknown_sensitive_marker"
    assert by_path["unsafe_counterexamples/customer_record.txt"].classification == "blocked_private_material"
    assert by_path["manifest_only_safe_snapshot/package.json"].classification == "manifest_only_safe_snapshot"
    assert by_path["manifest_only_safe_snapshot/requirements.txt"].classification == "manifest_only_safe_snapshot"
    assert by_path["manifest_only_safe_snapshot/docker-compose.yml"].classification == "manifest_only_safe_snapshot"

    serialized = records_to_json(records, pretty=True)
    for marker_value in FORBIDDEN_MARKER_VALUES:
        assert marker_value not in serialized


def test_unsafe_counterexample_decisions_remain_blocked():
    records = records_by_path(classify_directory(FIXTURE_ROOT))

    assert records["unsafe_counterexamples/.env"].decision == "block"
    assert records["unsafe_counterexamples/.env"].reason_code == "blocked_env_file"
    assert records["unsafe_counterexamples/private.key"].decision == "block"
    assert records["unsafe_counterexamples/private.key"].reason_code == "blocked_key_file"
    assert records["unsafe_counterexamples/config_with_token.txt"].decision == "block"
    assert records["unsafe_counterexamples/customer_record.txt"].decision == "block"


def test_unknown_source_like_path_with_marker_remains_blocked(tmp_path):
    source_file = tmp_path / "src" / "settings.py"
    source_file.parent.mkdir()
    source_file.write_text("SERVICE_TOKEN = '[SYNTHETIC_UNKNOWN_TOKEN]'\n", encoding="utf-8")

    records = classify_directory(tmp_path)

    assert records == [
        records[0],
    ]
    record = records[0]
    assert record.path == "src/settings.py"
    assert record.marker_category == "token_like_value"
    assert record.classification == "real_or_unknown_sensitive_marker"
    assert record.decision == "block"
    assert "[SYNTHETIC_UNKNOWN_TOKEN]" not in records_to_json(records)


def test_output_is_deterministically_ordered():
    first = records_to_json(classify_directory(FIXTURE_ROOT))
    second = records_to_json(classify_directory(FIXTURE_ROOT))

    assert first == second
    payload = json.loads(first)
    assert payload == sorted(payload, key=lambda item: (item["path"], item["marker_category"], item["classification"]))


def test_zip_archive_is_enumerated_without_extraction(tmp_path):
    archive_path = tmp_path / "fixtures.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.write(
            FIXTURE_ROOT / "safe_synthetic" / "tests" / "example_token_fixture.txt",
            "tests/fixtures/sanitizer/safe_synthetic/tests/example_token_fixture.txt",
        )
        archive.write(
            FIXTURE_ROOT / "unsafe_counterexamples" / ".env",
            "tests/fixtures/sanitizer/unsafe_counterexamples/.env",
        )

    records = records_by_path(classify_zip(archive_path))

    assert (
        records["tests/fixtures/sanitizer/safe_synthetic/tests/example_token_fixture.txt"].classification
        == "synthetic_test_fixture_marker"
    )
    assert records["tests/fixtures/sanitizer/unsafe_counterexamples/.env"].decision == "block"
