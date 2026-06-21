# Passive Manifest-Only Self Dogfood Fixture Report Surface Smoke

Decision: `PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_04_REPORT_SURFACE_SMOKE_ACCEPTED`

Status: accepted. The manifest/config-only Inspectra self-dogfood fixture was
packaged locally, analyzed with the existing local project archive helper, and
rendered through existing backend report/export functions without app startup or
staging upload.

## Execution Path Used

Execution path: local report/export shaping.

The smoke used:

- `zip -X -r` for temporary archive packaging;
- `tools/sanitizer_fixture_classifier.py` for directory and archive checks;
- existing local `project_archive_basic` helper functions;
- existing backend `render_markdown_report`, `render_html_report`,
  `render_xml_report`, and `render_pdf_report` functions.

The smoke did not start the app, upload to staging, use the API, change runtime
code, or use the runner entrypoint.

## Fixture Path

```text
tests/fixtures/project_archives/inspectra_manifest_only_self_dogfood/
```

## Archive Creation Result

Temporary workspace:

```text
/tmp/inspectra-report-smoke.N9DKM1/
```

Archive:

```text
/tmp/inspectra-report-smoke.N9DKM1/inspectra_manifest_only_self_dogfood.zip
```

Result:

- archive type: `zip`;
- archive size: `2025` bytes;
- fixture file count: `5`;
- zip entries declared by local analysis: `8`, including directory entries;
- included files:
  - `README.md`;
  - `backend/requirements.txt`;
  - `docker-compose.yml`;
  - `frontend/package.json`;
  - `tools/requirements.txt`.

## Sanitizer Helper Results

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
.venv/bin/python tools/sanitizer_fixture_classifier.py /tmp/inspectra-report-smoke.N9DKM1/inspectra_manifest_only_self_dogfood.zip --pretty
```

Archive result:

```json
[]
```

Both outputs had no blocked or unknown records and no marker strings.

## Analysis Result

Local project archive analysis completed successfully:

- analyzer: `project_archive_basic`;
- archive type: `zip`;
- status used for report shaping: `completed`;
- errors: `0`;
- truncated: `false`;
- supported manifests found: `3`;
- supported manifests parsed: `3`;
- total dependencies: `19`;
- findings count: `21`;
- dependency groups: `dependencies`, `devDependencies`.

Parsed manifests:

- `backend/requirements.txt`;
- `tools/requirements.txt`;
- `frontend/package.json`.

Observed finding identifiers:

- `dependency_not_exactly_pinned`;
- `package_scripts_present`;
- `project_archive_multiple_ecosystems`;
- `requirements_dependency_not_exactly_pinned`.

## Report Surface Observations

The rendered report surfaces showed the expected report-layer metadata:

- category labels were visible, including `Dependency hygiene` and
  `Package script review`;
- ecosystem groups were visible:
  - `Generic project metadata`;
  - `Node / package.json`;
  - `Python / requirements`;
- dependency pinning summaries were visible:
  - `Node / package.json`: `13` dependency pinning review indicators across
    `1` manifest;
  - `Python / requirements`: `6` dependency pinning review indicators across
    `2` manifests;
- package script review remained visible;
- individual dependency hygiene findings remained visible;
- level, evidence, and recommendation fields remained visible;
- no empty dependency pinning summary section was observed.

One local check was repeated after aligning the expected Python ecosystem label
with the actual report label: `Python / requirements`. No code fix was needed.

## Export Results

Exports were generated in memory through existing backend report functions:

| Export | Result | Approximate size |
| --- | --- | ---: |
| Markdown | generated | `34471` bytes |
| HTML | generated | `53786` bytes |
| XML | generated | `55906` bytes |
| PDF | generated, `%PDF` header present | `41495` bytes |

Markdown, HTML, XML, and PDF surfaces included category, ecosystem, and pinning
summary content where applicable.

## Marker Review

Raw JSON and rendered exports were searched for known fixture marker strings.

Hit counts:

| Surface | Marker hits |
| --- | ---: |
| Raw JSON | `0` |
| Markdown | `0` |
| HTML | `0` |
| XML | `0` |
| PDF | `0` |

Additional sensitive-pattern checks also returned `0` hits across Raw JSON,
Markdown, HTML, XML, and PDF.

## Cleanup Result

Temporary workspace removed:

```text
/tmp/inspectra-report-smoke.N9DKM1/
```

Follow-up check confirmed the path no longer existed.

## Boundaries Preserved

No server-side app behavior, browser app behavior, local tool behavior, batch
archive automation, runner entrypoint orchestration, endpoint, migration, UI,
storage, analyzer, or Active behavior changed.

No container engine, port scanner, Active job, DNS/TLS/CT action, live HTTP
target action, outside host, screenshot, remote rollout, publishing step, or
version mark was used.

No app access material, digest values, browser session values, CSRF values, or
local-only config details were recorded.

## Blockers Or Fixes

No blockers remained after the local label check was aligned to generated report
output. No code, test, helper, runtime, staging, or fixture fix was required.

## Recommendation

Recommended next step:

```text
PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_05_CLOSEOUT
```

Suggested scope: record the fixture as accepted for future passive smoke and
decide whether the next product step should be a small staging replay, a
report-readability polish issue, or a broader dogfood checklist.

## Decision

```text
PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_04_REPORT_SURFACE_SMOKE_ACCEPTED
```
