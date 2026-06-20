# Passive Project Finding Categories

Decision: `PASSIVE_PROJECT_FINDING_CATEGORIES_01_ACCEPTED`

Status: implemented the first report-readability recommendation from
`docs/future/active-pre-alpha-dogfood-findings-triage.md` by adding category
metadata for existing passive `project_archive_basic` findings.

## Scope

This phase added a small finding metadata catalog keyed by existing project
archive finding IDs. It did not add analyzers, finding IDs, storage migrations,
endpoints, deployment work, release/tag state, network activity, package-manager
activity, or Active runtime behavior.

## Implemented

Backend:

- added a project archive finding metadata catalog;
- mapped known dogfood and current project archive finding IDs to stable
  category IDs and labels;
- added a neutral fallback for unknown IDs;
- categorized new project archive job results before storage;
- categorized old stored project archive results during report/export shaping.

Frontend:

- preserved category metadata in the project archive report normalizer;
- added the same neutral fallback for unknown IDs;
- rendered category labels beside project archive finding severity.

Exports:

- Markdown, HTML, XML, and PDF project archive exports now include category
  metadata for mapped findings.

## Category Map

| Category ID | Label |
| --- | --- |
| `dependency_hygiene` | Dependency hygiene |
| `dependency_source_review` | Dependency source review |
| `package_script_review` | Package script review |
| `ecosystem_inventory` | Ecosystem inventory |
| `manifest_parse_limits` | Manifest parsing and limits |
| `archive_safety_metadata` | Archive safety metadata |
| `uncategorized_review_indicator` | Uncategorized review indicator |

The fallback is intentional. Unknown future IDs should remain readable and
manual-review oriented without crashing reports or leaking arbitrary fields.

## Preserved Boundaries

- Existing finding IDs were preserved.
- Existing severity values were preserved.
- Existing evidence and recommendation text were preserved.
- Existing redaction behavior was not relaxed.
- Raw JSON remains bounded to the stored job result shape, now with category
  metadata for new project archive jobs.
- No `archive/run-all` or `tools/runner/main.py` orchestration change was made.

## Deferred

- ecosystem grouping;
- dependency pinning grouped summaries;
- sanitizer fixture classification;
- dashboard-wide category rollups;
- category cleanup across other audit families.

## Validation Notes

Focused tests cover:

- known dogfood IDs mapping to non-empty category labels;
- unknown ID fallback;
- frontend normalizer category preservation;
- project archive detail rendering of category labels;
- export category metadata across Markdown, HTML, XML, and PDF;
- preservation of severity, evidence, and recommendation fields.

## Decision

```text
PASSIVE_PROJECT_FINDING_CATEGORIES_01_ACCEPTED
```
