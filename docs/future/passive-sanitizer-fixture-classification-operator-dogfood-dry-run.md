# Passive Sanitizer Fixture Classification Operator Dogfood Dry Run

Decision: `PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_05_OPERATOR_DOGFOOD_DRY_RUN_BLOCKED_SAFE`

Status: safe-blocked. The local helper was run against a broad, filtered
Inspectra owned-source snapshot. It found enough unknown or blocked
path/category records that the snapshot should not be uploaded or promoted into
a broader dogfood input.

## Scope

This phase was a local dry-run only. It did not upload an archive, submit an
analysis job, change app behavior, weaken sanitizer behavior, start services,
deploy, publish, or touch Active surfaces.

The helper remains local/dev-only and is still not wired into app upload flow,
runtime analysis, `archive/run-all`, or `tools/runner/main.py`.

## Project Inspected

Primary target inspected:

```text
inspectra local workspace
```

The suggested `/opt/apps/*` locations were not visible in this local workspace,
so the owned Inspectra repository checkout was used as the first dry-run target.

## Snapshot Preparation

A temporary workspace was created under:

```text
/tmp/inspectra-sanitizer-owned-dry-run.uAETjR/
```

The source tree was copied to a filtered snapshot:

```text
/tmp/inspectra-sanitizer-owned-dry-run.uAETjR/inspectra-owned-filtered/
```

Excluded categories:

- repository metadata;
- local Codex/agent metadata;
- Python virtual environments and cache directories;
- vendored frontend dependencies;
- build output directories;
- app data, uploads, results, and generated output;
- environment override files;
- key/certificate material;
- database files, dumps, backups, and restore artifacts;
- log/cache files;
- Caddy/VPS-local configuration.

Snapshot size:

- files scanned: `515`;
- filtered tree size: `8.4M`.

## Helper Command Shape

The helper output was written only to a temporary JSON file:

```text
.venv/bin/python tools/sanitizer_fixture_classifier.py /tmp/.../inspectra-owned-filtered --pretty > /tmp/.../classifier-output.json
```

The temp JSON was summarized with `jq` and then deleted with the temporary
workspace. No file snippets or marker values were recorded.

## Classification Summary

Total records: `412`

Decision counts:

| Decision | Count |
| --- | ---: |
| `allow_manifest_snapshot` | `3` |
| `allow_synthetic_fixture` | `4` |
| `block` | `405` |

Classification counts:

| Classification | Count |
| --- | ---: |
| `manifest_only_safe_snapshot` | `3` |
| `synthetic_test_fixture_marker` | `1` |
| `documentation_example_marker` | `1` |
| `redaction_example_marker` | `1` |
| `generated_demo_fixture_marker` | `1` |
| `blocked_private_material` | `5` |
| `real_or_unknown_sensitive_marker` | `400` |

Marker-category summary:

| Marker category family | Count |
| --- | ---: |
| redaction-placeholder wording | `267` |
| browser-session-like wording | `70` |
| access-material wording | `40` |
| auth-like value wording | `25` |
| record-shaped material | `5` |
| docs placeholder wording | `2` |
| manifest file | `3` |

Reason-code counts:

| Reason code | Count |
| --- | ---: |
| `unknown_marker_context` | `399` |
| `record_shape_blocked` | `4` |
| `blocked_record_like_private_material` | `1` |
| `manifest_only_path` | `3` |
| `synthetic_test_path` | `1` |
| `docs_fixture_path` | `1` |
| `redaction_fixture_path` | `1` |
| `generated_demo_path` | `1` |
| `unsafe_counterexample` | `1` |

## Representative Path/Category Examples

Allowed manifest-only examples:

| Path | Marker category | Classification | Decision |
| --- | --- | --- | --- |
| `tests/fixtures/sanitizer/manifest_only_safe_snapshot/docker-compose.yml` | `manifest_file` | `manifest_only_safe_snapshot` | `allow_manifest_snapshot` |
| `tests/fixtures/sanitizer/manifest_only_safe_snapshot/package.json` | `manifest_file` | `manifest_only_safe_snapshot` | `allow_manifest_snapshot` |
| `tests/fixtures/sanitizer/manifest_only_safe_snapshot/requirements.txt` | `manifest_file` | `manifest_only_safe_snapshot` | `allow_manifest_snapshot` |

Allowed synthetic fixture example:

| Path | Marker category | Classification | Decision |
| --- | --- | --- | --- |
| `tests/fixtures/sanitizer/safe_synthetic/docs/example_placeholder.md` | `docs_placeholder` | `documentation_example_marker` | `allow_synthetic_fixture` |

Blocked or unknown examples:

| Path | Marker category | Classification | Decision | Reason |
| --- | --- | --- | --- | --- |
| `README.md` | `redaction_placeholder` | `real_or_unknown_sensitive_marker` | `block` | `unknown_marker_context` |
| `backend/app/active_dns_inventory.py` | `redaction_placeholder` | `real_or_unknown_sensitive_marker` | `block` | `unknown_marker_context` |
| `backend/app/active_tools_client.py` | session-like marker | `real_or_unknown_sensitive_marker` | `block` | `unknown_marker_context` |
| `backend/app/auth_state_sqlite.py` | auth-like marker | `real_or_unknown_sensitive_marker` | `block` | `unknown_marker_context` |
| `backend/app/config.py` | access-material marker | `real_or_unknown_sensitive_marker` | `block` | `unknown_marker_context` |
| `backend/app/sbom.py` | `record_like_private_material` | `blocked_private_material` | `block` | `record_shape_blocked` |

## Blocked/Unknown Summary

The broad filtered Inspectra source snapshot produced:

- `400` unknown sensitive-marker classifications;
- `5` blocked private-material classifications;
- `405` total block decisions.

This is enough to stop the broader source-snapshot path for now. The result does
not mean the source tree contains exposed values. It means the local classifier
cannot safely distinguish broad real-source references from approved fixture
contexts without a narrower policy.

## Upload Decision

No upload was performed.

The inspected snapshot is not approved for staging upload, archive submission,
or future report smoke as a broad source tree. Continue using the accepted
manifest/config-only self-dogfood fixture for passive smoke until a narrower
owned-source policy is designed and accepted.

## Cleanup Result

Temporary files removed:

```text
/tmp/inspectra-sanitizer-owned-dry-run.uAETjR/
```

Follow-up check confirmed the path no longer existed.

## Next Recommendation

Recommended next phase:

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_06_NARROW_SOURCE_SNAPSHOT_POLICY
```

Suggested scope: define a narrow owned-source snapshot policy before another
operator dry-run. The policy should decide which path families are eligible,
which path families remain excluded, and when a path/category record can be
treated as an approved fixture context.

Until that policy exists, keep product dogfood on manifest/config-only fixtures
and avoid broad source snapshots.

## Decision

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_05_OPERATOR_DOGFOOD_DRY_RUN_BLOCKED_SAFE
```
