import json
from pathlib import Path
import zipfile

import pytest

from sanitizer_fixture_classifier import MAX_FILE_BYTES, classify_directory, classify_zip, records_to_json


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


def payload_from_records(records):
    return json.loads(records_to_json(records))


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


def test_output_fields_are_allowlisted_only():
    payload = payload_from_records(classify_directory(FIXTURE_ROOT))

    assert payload
    assert all(
        set(item) == {"path", "marker_category", "classification", "decision", "reason_code"} for item in payload
    )


def test_unsafe_counterexample_decisions_remain_blocked():
    records = records_by_path(classify_directory(FIXTURE_ROOT))

    assert records["unsafe_counterexamples/.env"].decision == "block"
    assert records["unsafe_counterexamples/.env"].reason_code == "blocked_env_file"
    assert records["unsafe_counterexamples/private.key"].decision == "block"
    assert records["unsafe_counterexamples/private.key"].reason_code == "blocked_key_file"
    assert records["unsafe_counterexamples/config_with_token.txt"].decision == "block"
    assert records["unsafe_counterexamples/customer_record.txt"].decision == "block"


def test_synthetic_path_with_unexpected_category_is_blocked(tmp_path):
    suspicious_fixture = tmp_path / "safe_synthetic" / "tests" / "record_fixture.txt"
    suspicious_fixture.parent.mkdir(parents=True)
    suspicious_fixture.write_text("record subject reference\n", encoding="utf-8")

    records = classify_directory(tmp_path)

    assert len(records) == 1
    assert records[0].path == "safe_synthetic/tests/record_fixture.txt"
    assert records[0].classification == "real_or_unknown_sensitive_marker"
    assert records[0].decision == "block"
    assert records[0].reason_code == "synthetic_path_category_mismatch"


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


def test_uppercase_unsafe_path_variants_remain_blocked(tmp_path):
    env_file = tmp_path / ".ENV"
    env_file.write_text("PLACEHOLDER_SECRET=synthetic\n", encoding="utf-8")
    key_file = tmp_path / "PRIVATE.KEY"
    key_file.write_text("placeholder text only\n", encoding="utf-8")

    records = records_by_path(classify_directory(tmp_path))

    assert records[".ENV"].marker_category == "env_file"
    assert records[".ENV"].classification == "blocked_private_material"
    assert records["PRIVATE.KEY"].marker_category == "key_file"
    assert records["PRIVATE.KEY"].classification == "blocked_private_material"


def test_missing_directory_fails_safely(tmp_path):
    with pytest.raises(ValueError, match="input path must be a directory"):
        classify_directory(tmp_path / "missing")


def test_unknown_file_without_marker_does_not_crash_or_emit_record(tmp_path):
    unknown_file = tmp_path / "src" / "plain.txt"
    unknown_file.parent.mkdir()
    unknown_file.write_text("ordinary fixture text\n", encoding="utf-8")

    assert classify_directory(tmp_path) == []


def test_output_is_deterministically_ordered():
    first = records_to_json(classify_directory(FIXTURE_ROOT))
    second = records_to_json(classify_directory(FIXTURE_ROOT))

    assert first == second
    payload = json.loads(first)
    assert payload == sorted(payload, key=lambda item: (item["path"], item["marker_category"], item["classification"]))


def test_empty_directory_and_empty_zip_return_empty_output(tmp_path):
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    archive_path = tmp_path / "empty.zip"
    with zipfile.ZipFile(archive_path, "w"):
        pass

    assert classify_directory(empty_dir) == []
    assert classify_zip(archive_path) == []
    assert records_to_json([]) == "[]"


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


def test_zip_member_traversal_paths_are_blocked(tmp_path):
    archive_path = tmp_path / "traversal.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../outside.txt", "SERVICE_TOKEN = '[TRAVERSAL_TOKEN]'\n")
        archive.writestr("/absolute.txt", "SERVICE_TOKEN = '[ABSOLUTE_TOKEN]'\n")
        archive.writestr("safe/../outside.txt", "SERVICE_TOKEN = '[INNER_TRAVERSAL_TOKEN]'\n")

    records = classify_zip(archive_path)

    assert [record.reason_code for record in records] == [
        "unsafe_archive_member_path",
        "unsafe_archive_member_path",
        "unsafe_archive_member_path",
    ]
    serialized = records_to_json(records)
    assert "[TRAVERSAL_TOKEN]" not in serialized
    assert "[ABSOLUTE_TOKEN]" not in serialized
    assert "[INNER_TRAVERSAL_TOKEN]" not in serialized


def test_zip_read_is_bounded_for_unknown_source_marker(tmp_path):
    archive_path = tmp_path / "large.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("src/late_marker.txt", ("A" * MAX_FILE_BYTES) + " SERVICE_TOKEN = '[LATE_TOKEN]'\n")

    records = classify_zip(archive_path)

    assert records == []
