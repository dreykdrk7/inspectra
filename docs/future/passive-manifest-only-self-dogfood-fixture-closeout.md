# Passive Manifest-Only Self Dogfood Fixture Closeout

Decision: `PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_05_CLOSEOUT_ACCEPTED`

Status: accepted. This closes the manifest/config-only Inspectra self-dogfood
fixture, local archive dry-run, report-surface plan, and report-surface smoke
block.

## Scope

This closeout records the accepted fixture state and its future use policy. It
does not add runtime, upload, staging, analyzer, UI, endpoint, storage, runner,
or Active behavior.

## Reviewed Lineage

- `PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_01`
- `PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_02_LOCAL_ARCHIVE_DRY_RUN`
- `PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_03_REPORT_SURFACE_SMOKE_PLAN`
- `PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_04_REPORT_SURFACE_SMOKE`

Latest accepted smoke commit:

```text
8a49f8c docs(passive): smoke manifest-only self dogfood report surfaces
```

## Accepted Fixture State

Fixture path:

```text
tests/fixtures/project_archives/inspectra_manifest_only_self_dogfood/
```

Included files:

- `README.md`
- `backend/requirements.txt`
- `docker-compose.yml`
- `frontend/package.json`
- `tools/requirements.txt`

Excluded categories:

- broad source trees;
- tests;
- broad docs;
- generated uploads, results, exports, and reports;
- local override files;
- VPS or reverse-proxy config;
- live host values or outside target examples;
- operator auth material and session material;
- client records;
- lockfiles and vendored dependency trees.

Intended use:

- local passive project archive smoke;
- local report/export regression checks;
- bounded self-dogfood of dependency inventory and report metadata;
- future staging replay only in a separately approved phase.

No-go boundaries:

- do not broaden this fixture into a source snapshot;
- do not add project-specific private material;
- do not change app upload flow or report runtime behavior through this fixture;
- do not use it as a substitute for review of real project archives;
- keep it manifest/config-only unless a later phase explicitly approves a
  change.

## Validation Summary

Sanitizer fixture classifier:

- directory result: `[]`;
- temporary archive result: `[]`;
- no blocked or unknown records;
- no marker strings in helper output.

Local archive dry-run:

- deterministic zip creation succeeded;
- archive size: `2025` bytes;
- fixture file count: `5`;
- zip entries: `8`, including directory entries;
- cleanup completed.

Local analysis:

- analyzer: `project_archive_basic`;
- status for report shaping: `completed`;
- parsed manifests: `3`;
- dependencies: `19`;
- findings: `21`;
- analyzer errors: `0`;
- truncated: `false`;
- signals observed:
  - multiple ecosystems;
  - dependency hygiene;
  - package script review.

Report-surface smoke:

- category labels visible;
- ecosystem groups visible;
- dependency pinning summaries visible;
- package script review visible;
- individual dependency hygiene findings visible;
- level, evidence, and recommendation fields visible.

Exports:

- Markdown generated;
- HTML generated;
- XML generated;
- PDF generated with `%PDF` header;
- no empty dependency pinning summary section observed.

Marker review:

- Raw JSON marker hits: `0`;
- Markdown marker hits: `0`;
- HTML marker hits: `0`;
- XML marker hits: `0`;
- PDF marker hits: `0`;
- additional sensitive-pattern hits: `0`.

Cleanup:

- temporary archive workspace removed;
- no staging source cleanup was needed because staging was not used.

## Future Usage Policy

The fixture is accepted as safe for local passive report smoke and local
regression dogfood within its manifest/config-only boundary.

Staging upload is allowed only in a separately approved phase, using this
fixture archive alone and recording only safe summaries.

This fixture is not:

- a broad Inspectra source snapshot;
- approval for broader project archive capture;
- a replacement for sanitizer classification or operator review of owned
  projects;
- a source of runtime behavior.

The fixture should remain manifest/config-only until a later phase approves a
specific change.

## Product Value

This fixture gives Inspectra a stable self-dogfood input that exercises:

- Python requirements;
- Node package metadata;
- generic project metadata;
- dependency hygiene findings;
- package script review;
- multiple ecosystem grouping;
- category metadata;
- ecosystem metadata;
- dependency pinning summaries;
- Markdown, HTML, XML, and PDF report rendering.

It is useful as a repeatable regression and dogfood input because it is small,
deterministic, and not tied to a live system.

## Deferred Items

- staging replay with this fixture if product validation needs it;
- broader owned-source snapshot helper dry-run;
- dashboard-level category rollups;
- app-side upload preflight classification;
- private-alpha tester guide if external sharing becomes imminent.

## Recommended Next Step

Recommended:

```text
PASSIVE_SANITIZER_FIXTURE_CLASSIFICATION_05_OPERATOR_DOGFOOD_DRY_RUN
```

Reason: the product remains operator-led, and the manifest-only fixture block is
now accepted. The next useful move is a local operator dry-run that records
path/category decisions for an owned-source snapshot without upload or runtime
changes.

Alternative:

```text
PRIVATE_ALPHA_TESTER_GUIDE_01
```

Use this only if a trusted tester invitation is imminent.

## Decision

```text
PASSIVE_MANIFEST_ONLY_SELF_DOGFOOD_FIXTURE_05_CLOSEOUT_ACCEPTED
```
