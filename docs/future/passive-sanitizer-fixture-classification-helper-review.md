# Passive Sanitizer Fixture Classification Helper Review

Decision: `PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_04_HELPER_REVIEW_ACCEPTED`

Status: the local-only sanitizer fixture classifier was reviewed and hardened
before any operator dogfood use.

## Scope

This phase reviewed and hardened only:

- `tools/sanitizer_fixture_classifier.py`
- `tools/tests/test_sanitizer_fixture_classifier.py`
- the existing sanitizer fixture tree under `tests/fixtures/sanitizer/`

It did not change app upload behavior, production sanitizer runtime, backend
endpoints, frontend runtime, Active runtime, `archive/run-all`, or
`tools/runner/main.py`. It did not add network behavior, run Docker, run Nmap,
submit Active jobs, upload archives to staging, use outside targets, take
screenshots, deploy, create a release, create a tag, or push.

## Review Result

The helper remains local/dev-only and suitable for continued review. It is not
wired into app upload flow, backend runtime, frontend runtime, Active runtime,
`archive/run-all`, or `tools/runner/main.py`.

Repository search for the helper name found only:

- the helper itself;
- focused helper tests;
- local-helper documentation.

## Gaps Found

Two hardening gaps were found:

1. Zip member path normalization could remove a leading `../` before traversal
   validation.
2. Safe synthetic paths did not restrict marker categories tightly enough, so a
   suspicious category in an otherwise allowed path could be classified too
   generously.

The existing tests also lacked explicit coverage for:

- traversal-style zip member names;
- empty directory and empty archive behavior;
- uppercase unsafe path variants;
- bounded zip reads;
- allowlisted output fields;
- missing-path and unknown-file behavior;
- suspicious category mismatch inside a synthetic path.

## Hardening Applied

Path normalization now removes only leading `./` segments and preserves `../`
segments for validation. Zip member validation rejects absolute paths and any
member path containing parent-directory traversal.

Synthetic path handling now checks both path and marker category:

- safe synthetic test paths allow only `token_like_value`;
- redaction fixture paths allow only `redaction_placeholder`;
- docs fixture paths allow only `docs_placeholder`;
- generated demo paths allow only `token_like_value`.

Unexpected marker categories in synthetic paths now remain blocked.

## Output Safety

The helper output remains limited to:

- `path`
- `marker_category`
- `classification`
- `decision`
- `reason_code`

It does not emit marker strings, source snippets, surrounding file contents,
private config contents, or access material.

Focused tests now assert the output field set and check that fixture marker
strings are absent from serialized output.

## Zip Safety

Zip support still enumerates members and reads bounded bytes without
extraction. Added tests cover:

- traversal-style member paths;
- absolute member paths;
- empty archive output;
- bounded read behavior for a marker placed beyond the helper read limit.

## Classification Review

The helper continues to classify:

- safe synthetic test fixture as `synthetic_test_fixture_marker`;
- redaction example as `redaction_example_marker`;
- documentation example as `documentation_example_marker`;
- generated demo config as `generated_demo_fixture_marker`;
- manifest-only files as `manifest_only_safe_snapshot`;
- environment-file and key-file counterexamples as blocked private material;
- token-like unknown config as `real_or_unknown_sensitive_marker`;
- record-shaped material as blocked private material;
- unknown source-like marker paths as blocked.

## Validation

Validation run:

```text
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache .venv/bin/python -m py_compile tools/sanitizer_fixture_classifier.py tools/tests/test_sanitizer_fixture_classifier.py
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache .venv/bin/python -m pytest tools/tests/test_sanitizer_fixture_classifier.py -q
.venv/bin/python tools/sanitizer_fixture_classifier.py tests/fixtures/sanitizer
.venv/bin/python tools/sanitizer_fixture_classifier.py /tmp/inspectra-sanitizer-fixtures-review.zip
```

Results:

- Python compile: passed
- focused tests: `13 passed`
- directory helper output marker-value scan: passed
- zip helper output marker-value scan: passed

## Deferred Items

- no app upload preflight;
- no backend or frontend UI;
- no storage for classification records;
- no operator dogfood upload;
- no broad source snapshot approval.

## Recommendation

Recommended next microphase:

```text
PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_01
```

Reason: the helper boundary is now reviewed. The safest next product move is a
stable manifest/config-only self-dogfood fixture before any broader source
snapshot workflow depends on helper classification.

Alternative:

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_05_OPERATOR_DOGFOOD_DRY_RUN
```

Use this only if the operator wants to run the helper locally against an
owned-source snapshot and record path/category decisions without uploading it.

## Decision

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_04_HELPER_REVIEW_ACCEPTED
```
