# Passive Manifest-Only Self Dogfood Fixture Report Surface Smoke Plan

Decision: `PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_03_REPORT_SURFACE_SMOKE_PLAN_ACCEPTED`

Status: accepted as a docs-only plan. This phase does not execute the smoke,
run the app, upload the fixture, or change runtime behavior.

## Objective

Use the existing manifest/config-only self-dogfood fixture to validate report
surfaces in a later phase:

- category labels in project archive report output;
- ecosystem grouping in report output;
- dependency pinning summary presentation;
- individual finding visibility;
- Markdown, HTML, XML, and PDF export behavior;
- marker review across Raw JSON and exports.

This remains separate from analyzer, upload, storage, UI, and runtime changes.

Fixture:

```text
tests/fixtures/project_archives/inspectra_manifest_only_self_dogfood/
```

Current local dry-run baseline:

- temporary zip creation succeeded;
- archive size was `2025` bytes;
- fixture file count was `5`;
- sanitizer helper returned `[]` for the directory;
- sanitizer helper returned `[]` for the archive;
- direct local `project_archive_basic` helper parsed `3` manifests;
- local helper summary reported `19` dependencies, `21` findings, `0` errors,
  and `truncated: false`;
- observed signals included multiple ecosystems, dependency hygiene, and package
  script review.

## Candidate Execution Paths

| Path | Value | Constraints | Fit |
| --- | --- | --- | --- |
| Local backend/report helper route | Best isolation if an existing helper can shape reports and exports from a saved result payload. | Must avoid new helper plumbing, app startup, upload flow, and runtime code changes. | Preferred if already available. |
| Local app/API run | Exercises report and export paths close to operator use. | Requires starting local services; only acceptable if already standard for the phase and no network probes or new tooling are needed. | Secondary. |
| Protected staging upload | Exercises the real authenticated report surfaces. | Requires operator-approved staging use, source deletion afterward, and no deployment changes. | Practical fallback if local report/export shaping is not available. |
| No execution | Preserves scope if every practical path would require new tooling. | Leaves report-layer validation deferred. | Acceptable if the next phase finds no safe route. |

## Preferred Execution Path

Prefer local report/export shaping from existing backend reporting helpers if it
can consume a representative `project_archive_basic` result without starting the
app or changing code.

If that is not practical, use the protected staging app as the fallback path:

- use only the manifest-only fixture archive;
- authenticate through the existing protected app boundary;
- upload the archive once;
- run only passive project archive analysis;
- review report and export surfaces;
- delete the uploaded source afterward;
- clean up the local temporary archive.

The later smoke must not include Active work, outside hosts, screenshots, broad
repository snapshots, or new runtime behavior.

## Later Smoke Checklist

1. Confirm `git status --short --branch` before the smoke.
2. Package the fixture directory into a temporary zip with deterministic options.
3. Record archive size, zip entry count, and fixture file count.
4. Run the sanitizer fixture classifier against the fixture directory.
5. Run the sanitizer fixture classifier against the temporary archive.
6. Confirm both classifier outputs have no blocked or unknown records.
7. Run the chosen report-surface path using only this archive.
8. Confirm `project_archive_basic` completes.
9. Confirm the result has no analyzer errors and is not truncated.
10. Confirm category labels are visible in the report surface.
11. Confirm ecosystem grouping is visible.
12. Confirm dependency pinning summary text is visible.
13. Confirm the package script finding remains visible.
14. Confirm individual dependency hygiene findings remain visible.
15. Export Markdown, HTML, XML, and PDF.
16. Confirm each export completes successfully.
17. Review Raw JSON and exports for marker leakage.
18. If staging is used, delete the uploaded source and confirm it is no longer
    reachable through the app.
19. Remove the temporary archive and workspace.
20. Record final status and residual gaps.

## Acceptance Criteria

- sanitizer helper outputs have no blocked or unknown records;
- `project_archive_basic` completes;
- analyzer errors are absent;
- result is not truncated;
- category metadata appears in report surfaces;
- ecosystem metadata appears in report surfaces;
- dependency pinning summary appears;
- package script review appears;
- individual findings remain visible;
- Markdown, HTML, XML, and PDF exports complete;
- Raw JSON and exports do not expose marker values or sensitive content;
- no Active work, port scanning, or live-host probing occurs.

## No-Go Boundaries

The later smoke must not introduce:

- broad Inspectra source snapshots;
- unresolved marker hits;
- sanitizer weakening;
- upload-flow changes;
- runtime changes;
- staging deployment changes;
- Active behavior;
- outside-host probes;
- screenshots;
- new report, analyzer, storage, UI, or endpoint behavior.

## Suggested Next Phase

```text
PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_04_REPORT_SURFACE_SMOKE
```

Suggested scope: execute the accepted smoke path, preferably through existing
local report/export helpers if available, otherwise through protected staging
with operator approval and source cleanup.

## Decision

```text
PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_03_REPORT_SURFACE_SMOKE_PLAN_ACCEPTED
```
