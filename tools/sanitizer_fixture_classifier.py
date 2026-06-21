"""Local-only fixture classifier for passive sanitizer dogfood planning.

This helper is intentionally not wired into app uploads, runner orchestration,
or runtime sanitizer behavior. It emits path/category/classification records
only; raw marker values and source snippets are never returned.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path, PurePosixPath
import sys
import zipfile


MAX_FILE_BYTES = 32_768
MAX_ZIP_MEMBERS = 512

SAFE_SYNTHETIC_PREFIXES = (
    ("safe_synthetic/tests/", "synthetic_test_fixture_marker", "synthetic_test_path"),
    ("safe_synthetic/redaction/", "redaction_example_marker", "redaction_fixture_path"),
    ("safe_synthetic/docs/", "documentation_example_marker", "docs_fixture_path"),
    ("safe_synthetic/demo/", "generated_demo_fixture_marker", "generated_demo_path"),
    ("tests/fixtures/sanitizer/safe_synthetic/tests/", "synthetic_test_fixture_marker", "synthetic_test_path"),
    ("tests/fixtures/sanitizer/safe_synthetic/redaction/", "redaction_example_marker", "redaction_fixture_path"),
    ("tests/fixtures/sanitizer/safe_synthetic/docs/", "documentation_example_marker", "docs_fixture_path"),
    ("tests/fixtures/sanitizer/safe_synthetic/demo/", "generated_demo_fixture_marker", "generated_demo_path"),
)
MANIFEST_ONLY_PREFIXES = ("manifest_only_safe_snapshot/", "tests/fixtures/sanitizer/manifest_only_safe_snapshot/")
UNSAFE_COUNTEREXAMPLE_PREFIXES = ("unsafe_counterexamples/", "tests/fixtures/sanitizer/unsafe_counterexamples/")
MANIFEST_FILENAMES = frozenset({"package.json", "requirements.txt", "docker-compose.yml", "Dockerfile"})


@dataclass(frozen=True, order=True)
class ClassificationRecord:
    path: str
    marker_category: str
    classification: str
    decision: str
    reason_code: str


def classify_directory(path: Path) -> list[ClassificationRecord]:
    root = path.resolve()
    if not root.is_dir():
        raise ValueError("input path must be a directory")

    records: list[ClassificationRecord] = []
    for item in sorted((candidate for candidate in root.rglob("*") if candidate.is_file()), key=lambda p: p.as_posix()):
        relative_path = _normalize_path(item.relative_to(root).as_posix())
        content = item.read_bytes()[:MAX_FILE_BYTES].decode("utf-8", errors="ignore")
        records.extend(classify_content(relative_path, content))
    return sorted(records)


def classify_zip(path: Path) -> list[ClassificationRecord]:
    if not zipfile.is_zipfile(path):
        raise ValueError("input archive must be a zip file")

    records: list[ClassificationRecord] = []
    with zipfile.ZipFile(path) as archive:
        members = [info for info in archive.infolist() if not info.is_dir()]
        if len(members) > MAX_ZIP_MEMBERS:
            raise ValueError("zip member count exceeds local helper limit")

        for info in sorted(members, key=lambda candidate: candidate.filename):
            relative_path = _safe_zip_member_path(info.filename)
            if relative_path is None:
                records.append(
                    ClassificationRecord(
                        path=_normalize_path(info.filename),
                        marker_category="archive_path",
                        classification="blocked_private_material",
                        decision="block",
                        reason_code="unsafe_archive_member_path",
                    )
                )
                continue

            with archive.open(info) as handle:
                content = handle.read(MAX_FILE_BYTES).decode("utf-8", errors="ignore")
            records.extend(classify_content(relative_path, content))
    return sorted(records)


def classify_content(relative_path: str, content: str) -> list[ClassificationRecord]:
    path = _normalize_path(relative_path)
    category = _marker_category(path, content)
    if category is None:
        return []

    classification, decision, reason_code = _classification_for(path, category)
    return [
        ClassificationRecord(
            path=path,
            marker_category=category,
            classification=classification,
            decision=decision,
            reason_code=reason_code,
        )
    ]


def records_to_json(records: list[ClassificationRecord], *, pretty: bool = False) -> str:
    payload = [asdict(record) for record in sorted(records)]
    if pretty:
        return json.dumps(payload, indent=2, sort_keys=True)
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _classification_for(path: str, marker_category: str) -> tuple[str, str, str]:
    if _starts_with_any(path, MANIFEST_ONLY_PREFIXES) and Path(path).name in MANIFEST_FILENAMES:
        return "manifest_only_safe_snapshot", "allow_manifest_snapshot", "manifest_only_path"

    if _starts_with_any(path, UNSAFE_COUNTEREXAMPLE_PREFIXES):
        if marker_category in {"env_file", "key_file", "record_like_private_material"}:
            return "blocked_private_material", "block", f"blocked_{marker_category}"
        return "real_or_unknown_sensitive_marker", "block", "unsafe_counterexample"

    for prefix, classification, reason_code in SAFE_SYNTHETIC_PREFIXES:
        if path.startswith(prefix):
            if classification == "documentation_example_marker" and marker_category != "docs_placeholder":
                return "real_or_unknown_sensitive_marker", "block", "docs_fixture_without_docs_placeholder"
            if classification == "redaction_example_marker" and marker_category != "redaction_placeholder":
                return "real_or_unknown_sensitive_marker", "block", "redaction_fixture_without_redaction_placeholder"
            return classification, "allow_synthetic_fixture", reason_code

    if marker_category == "env_file":
        return "blocked_private_material", "block", "env_path_blocked"
    if marker_category == "key_file":
        return "blocked_private_material", "block", "key_path_blocked"
    if marker_category == "record_like_private_material":
        return "blocked_private_material", "block", "record_shape_blocked"
    return "real_or_unknown_sensitive_marker", "block", "unknown_marker_context"


def _marker_category(path: str, content: str) -> str | None:
    name = Path(path).name.lower()
    lower_path = path.lower()
    lower_content = content.lower()

    if name == ".env" or name.startswith(".env."):
        return "env_file"
    if name.endswith(".key") or "private.key" in lower_path:
        return "key_file"
    if name in MANIFEST_FILENAMES and _starts_with_any(path, MANIFEST_ONLY_PREFIXES):
        return "manifest_file"
    if "example configuration value" in lower_content:
        return "docs_placeholder"
    if "redacted" in lower_content:
        return "redaction_placeholder"
    if "cookie" in lower_content:
        return "cookie_like_value"
    if "token" in lower_content or "api_key" in lower_content:
        return "token_like_value"
    if "secret" in lower_content or "credential" in lower_content:
        return "credential_like_value"
    if "placeholder" in lower_content:
        return "docs_placeholder"
    if "record" in lower_content and ("subject" in lower_content or "reference" in lower_content):
        return "record_like_private_material"
    return None


def _safe_zip_member_path(raw_path: str) -> str | None:
    normalized = _normalize_path(raw_path)
    candidate = PurePosixPath(normalized)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    return normalized


def _normalize_path(raw_path: str) -> str:
    return raw_path.replace("\\", "/").lstrip("./")


def _starts_with_any(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path.startswith(prefix) for prefix in prefixes)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Classify local sanitizer fixtures without printing marker values.")
    parser.add_argument("path", help="Directory or .zip archive to scan.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    path = Path(args.path)
    try:
        if path.is_dir():
            records = classify_directory(path)
        elif path.is_file() and path.suffix.lower() == ".zip":
            records = classify_zip(path)
        else:
            raise ValueError("input must be a directory or .zip archive")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(records_to_json(records, pretty=args.pretty))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
