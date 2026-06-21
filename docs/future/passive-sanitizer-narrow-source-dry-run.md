# Passive Sanitizer Narrow Source Dry Run

Decision: `PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_07_NARROW_SOURCE_DRY_RUN_ACCEPTED`

Status: accepted. A tiny Tier 1 owned-source candidate snapshot was built from
one narrow metadata/reporting path family and passed the local sanitizer fixture
classifier with zero records.

## Source Candidate Family

Chosen family: project archive finding metadata catalog.

Reason:

- narrow source surface;
- local report metadata only;
- no upload flow;
- no app runtime entrypoint;
- no auth/session/access-material handling;
- no Active live-target logic;
- no storage or runner orchestration.

## Selected Paths

Selected source path:

```text
backend/app/project_archive_findings.py
```

The snapshot preserved the relative path:

```text
snapshot/backend/app/project_archive_findings.py
```

Snapshot size:

- files copied: `1`;
- temp snapshot size: `28K`.

## Excluded Categories

The candidate intentionally excluded:

- broad backend app surfaces;
- frontend app surfaces;
- tests;
- broad docs;
- upload flow;
- runtime storage paths;
- auth/session/access-material paths;
- Active live-target logic;
- runner orchestration;
- generated data, uploads, results, exports, and reports;
- local environment overrides;
- vendored dependencies, build outputs, caches, and virtual environments.

## Helper Command Shape

Temporary workspace:

```text
/tmp/inspectra-narrow-source-dry-run.I68dXW/
```

Helper command shape:

```text
.venv/bin/python tools/sanitizer_fixture_classifier.py /tmp/.../snapshot --pretty > /tmp/.../classifier-output.json
```

The helper output was saved only to a temporary JSON file and deleted after
summary extraction.

## Record Counts

Helper output:

```json
[]
```

Summary:

| Metric | Count |
| --- | ---: |
| Total records | `0` |
| Block decisions | `0` |
| Unknown sensitive-marker records | `0` |
| Blocked private-material records | `0` |
| Allowed synthetic records | `0` |
| Allowed manifest-only records | `0` |

## Representative Safe Path/Category Rows

No path/category rows were emitted because the candidate snapshot produced no
marker records. That is the desired outcome for a marker-free Tier 1 source
candidate.

## Blocked/Unknown Counts

Blocked and unknown counts were both zero:

- `real_or_unknown_sensitive_marker`: `0`;
- `blocked_private_material`: `0`.

The acceptance rule was met.

## Upload Decision

No upload was performed.

This result approves only the tiny selected Tier 1 candidate for future
local-only use. It does not approve broad source snapshots, staging upload,
archive submission, app upload preflight changes, or automatic source-path
allowlisting.

## Cleanup Result

Temporary workspace removed:

```text
/tmp/inspectra-narrow-source-dry-run.I68dXW/
```

Follow-up check confirmed the path no longer existed.

## Next Recommendation

Recommended next phase:

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_08_TIER1_CANDIDATE_CLOSEOUT
```

Suggested scope: close the narrow-source candidate experiment and decide whether
to keep Tier 1 source dogfood limited to this metadata catalog family, test one
additional equally narrow formatter/parser family, or pause source-snapshot work
and continue with manifest/config-only fixtures.

## Decision

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_07_NARROW_SOURCE_DRY_RUN_ACCEPTED
```
