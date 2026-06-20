# Passive Report Ecosystem Grouping

Decision: `PASSIVE_REPORT_ECOSYSTEM_GROUPING_01_ACCEPTED`

Status: implemented the second report-readability recommendation from
`docs/future/active-pre-alpha-dogfood-findings-triage.md` by adding ecosystem
metadata and grouping for existing passive `project_archive_basic` findings.

## Scope

This phase extended the existing project archive finding metadata catalog. It
did not add analyzers, finding IDs, storage migrations, endpoints, deployment
work, release state, package-manager activity, or live target activity.

## Implemented

Backend:

- added ecosystem IDs and labels alongside existing category metadata;
- inferred ecosystems from existing finding IDs, manifest paths, manifest
  types, or evidence already present in stored job results;
- preserved neutral fallback metadata for unknown future findings;
- derived ecosystem metadata for old stored project archive results during
  report and export shaping;
- added a compact ecosystem summary for project archive reports.

Frontend:

- preserved ecosystem metadata in the project archive report normalizer;
- derived ecosystem metadata for older job results where context is present;
- rendered ecosystem labels beside category and severity;
- grouped project archive findings by ecosystem while keeping every finding
  individually visible.

Exports:

- Markdown, HTML, XML, and PDF project archive exports include ecosystem fields
  and labels for mapped findings;
- project archive exports include an ecosystem summary section.

## Ecosystem Map

| Ecosystem ID | Label |
| --- | --- |
| `python_requirements` | Python / requirements |
| `node_package` | Node / package.json |
| `docker_compose` | Docker / Compose |
| `ci_cd` | CI/CD |
| `framework_config` | Framework/config |
| `generic_project_metadata` | Generic project metadata |
| `unknown_ecosystem` | Unknown ecosystem |

Ambiguous dependency findings stay on the neutral fallback unless existing
manifest context identifies a package or Python dependency manifest. Archive
safety metadata maps to generic project metadata rather than a package
ecosystem.

## Preserved Boundaries

- Existing finding IDs were preserved.
- Existing severity values were preserved.
- Existing evidence and recommendation text were preserved.
- Existing category output remains present.
- Existing redaction behavior was not relaxed.
- No `archive/run-all` or `tools/runner/main.py` orchestration change was made.

## Deferred

- dependency pinning grouped summaries;
- sanitizer fixture classification;
- dashboard-wide category and ecosystem rollups;
- ecosystem cleanup across other audit families.

## Validation Notes

Focused tests cover:

- known dogfood finding IDs and context mapping to ecosystem labels;
- unknown ecosystem fallback;
- frontend normalizer ecosystem preservation;
- project archive detail rendering and grouping by ecosystem;
- export ecosystem metadata across Markdown, HTML, XML, and PDF;
- continued category metadata, severity, evidence, and recommendation output.

## Decision

```text
PASSIVE_REPORT_ECOSYSTEM_GROUPING_01_ACCEPTED
```
