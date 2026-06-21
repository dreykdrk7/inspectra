# Passive Sanitizer Fixture Classification Local Helper

Decision: `PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_03_LOCAL_HELPER_ACCEPTED`

Status: local-only helper and focused tests were added for classifying the
synthetic sanitizer fixture set. App upload behavior remains unchanged and
fail-closed.

## Scope

This phase adds a local helper, focused tests, and this record. It does not
change backend endpoints, frontend runtime, Active runtime, app upload
behavior, production sanitizer runtime, `archive/run-all`, or
`tools/runner/main.py`. It does not add network behavior, run Docker, run Nmap,
submit live Active jobs, upload archives to staging, use outside targets, take
screenshots, deploy, create a release, create a tag, or push.

## Helper Location

```text
tools/sanitizer_fixture_classifier.py
```

The helper lives in `tools/` because it is a local operator/dev utility. It is
not imported by backend runtime, frontend runtime, the passive runner service,
`archive/run-all`, or `tools/runner/main.py`.

## Purpose

The helper scans a local directory or zip archive and emits deterministic JSON
records for the sanitizer fixture classification model. It is intended to prove
path/category/classification expectations before any app-side preflight design.

It does not try to become a broad detector. It uses a small local category set
for the fixture model:

- `env_file`
- `key_file`
- `token_like_value`
- `cookie_like_value`
- `credential_like_value`
- `record_like_private_material`
- `docs_placeholder`
- `redaction_placeholder`
- `manifest_file`

## Output Shape

Each record contains only:

```json
{
  "path": "safe_synthetic/tests/example_token_fixture.txt",
  "marker_category": "token_like_value",
  "classification": "synthetic_test_fixture_marker",
  "decision": "allow_synthetic_fixture",
  "reason_code": "synthetic_test_path"
}
```

The helper does not emit marker strings, source snippets, private config
values, or surrounding file contents.

## Local Usage

Directory scan:

```text
.venv/bin/python tools/sanitizer_fixture_classifier.py tests/fixtures/sanitizer --pretty
```

Zip scan:

```text
.venv/bin/python tools/sanitizer_fixture_classifier.py path/to/local-fixtures.zip --pretty
```

Zip support enumerates members and reads bounded bytes without extraction.

## Classification Behavior

- safe synthetic test fixture paths classify as
  `synthetic_test_fixture_marker`;
- redaction example paths classify as `redaction_example_marker`;
- docs placeholder paths classify as `documentation_example_marker`;
- generated demo paths classify as `generated_demo_fixture_marker`;
- manifest-only snapshot files classify as `manifest_only_safe_snapshot`;
- environment-file paths remain blocked;
- key-file paths remain blocked;
- token-like config outside approved synthetic paths remains blocked;
- record-shaped material remains blocked;
- unknown source paths with marker categories remain blocked.

## Tests

Focused tests were added in:

```text
tools/tests/test_sanitizer_fixture_classifier.py
```

The tests cover the fixture classifications, blocked counterexamples, unknown
source-like marker handling, deterministic ordering, zip enumeration, and the
absence of raw fixture marker strings in serialized helper output.

## Deferred Items

- No app upload preflight was added.
- No backend or frontend UI was added.
- No helper output storage was added.
- No broad source dogfood was run.
- No staging upload was performed.

## Recommended Next Phase

Recommended next microphase:

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_04_HELPER_REVIEW
```

Goal: review the helper boundary, output shape, fixture assumptions, and
negative cases before using it in any operator dogfood workflow.

## Decision

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_03_LOCAL_HELPER_ACCEPTED
```
