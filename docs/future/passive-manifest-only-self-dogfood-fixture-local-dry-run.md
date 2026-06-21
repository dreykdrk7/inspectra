# Passive Manifest-Only Self Dogfood Fixture Local Dry Run

Decision: `PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_02_LOCAL_ARCHIVE_DRY_RUN_ACCEPTED`

Status: accepted. The manifest/config-only Inspectra self-dogfood fixture was
packaged into a temporary local archive, checked with the local sanitizer fixture
classifier, and analyzed through the existing local project-archive helper.

## Fixture Path

```text
tests/fixtures/project_archives/inspectra_manifest_only_self_dogfood/
```

## Archive Creation

Temporary workspace:

```text
/tmp/inspectra-manifest-dry-run.WRe63d/
```

Archive command:

```text
zip -X -r /tmp/inspectra-manifest-dry-run.WRe63d/inspectra_manifest_only_self_dogfood.zip .
```

Creation result:

- archive type: `zip`;
- archive size: `2025` bytes;
- fixture file count before packaging: `5`;
- zip entries declared by local analysis: `8`, including directory entries;
- files included:
  - `README.md`;
  - `backend/requirements.txt`;
  - `docker-compose.yml`;
  - `frontend/package.json`;
  - `tools/requirements.txt`.

## Sanitizer Helper Result

Directory command:

```text
.venv/bin/python tools/sanitizer_fixture_classifier.py tests/fixtures/project_archives/inspectra_manifest_only_self_dogfood --pretty
```

Directory result:

```json
[]
```

Archive command:

```text
.venv/bin/python tools/sanitizer_fixture_classifier.py /tmp/inspectra-manifest-dry-run.WRe63d/inspectra_manifest_only_self_dogfood.zip --pretty
```

Archive result:

```json
[]
```

The helper returned no records for either input form, so there were no blocked
or unknown marker classifications and no marker strings printed.

## Local Analysis Result

The safest available local path was a direct call to the existing
`project_archive_basic` analysis helper used by the local runner tests. This did
not start a service, upload to staging, or use the runner entrypoint.

Observed payload summary:

```json
{
  "analyzer": "project_archive_basic",
  "archive_type": "zip",
  "errors": [],
  "parsed_manifest_types": [
    "requirements_txt",
    "requirements_txt",
    "package_json"
  ],
  "summary": {
    "dependency_groups": [
      "dependencies",
      "devDependencies"
    ],
    "findings_count": 21,
    "supported_manifests_found": 3,
    "supported_manifests_parsed": 3,
    "total_dependencies": 19,
    "total_entries_seen": 8,
    "truncated": false,
    "unsupported_manifests_detected": 1,
    "zip_central_directory_bytes": 485,
    "zip_entries_declared": 8
  }
}
```

Useful expected report behavior was present at helper level:

- multi-ecosystem signal: `project_archive_multiple_ecosystems`;
- dependency hygiene signal: repeated non-exact dependency findings;
- package script review signal: `package_scripts_present`;
- parsed manifests: backend requirements, tools requirements, and frontend
  package manifest.

The helper payload exposed dependency groups and finding identifiers. It did not
expose the later report-layer category or ecosystem label grouping directly, so
that remains a future report-surface smoke check.

## Cleanup Result

The temporary workspace was removed after validation:

```text
/tmp/inspectra-manifest-dry-run.WRe63d/
```

Follow-up check confirmed the path no longer existed.

## Boundaries Preserved

This phase changed documentation only. It did not alter upload flow, server
routes, browser app code, Active surfaces, batch archive automation, runner
entrypoint orchestration, storage, reports, UI, staging state, publishing state,
or remote environment state.

The phase did not start a container engine, run a port scanner, submit Active
work, call dependency installers, query remote indexes, contact outside services, use
live host examples, or capture screenshots.

## Next Recommended Phase

```text
PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_03_REPORT_SURFACE_SMOKE_PLAN
```

Suggested scope: plan a later report-surface smoke that uses this same fixture
to verify grouped findings, dependency pinning summaries, export readability,
and redaction posture through already-approved local or staging paths.

## Decision

```text
PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_02_LOCAL_ARCHIVE_DRY_RUN_ACCEPTED
```
