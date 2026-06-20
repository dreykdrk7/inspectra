# Passive Dependency Pinning Summary

Decision: `PASSIVE_DEPENDENCY_PINNING_SUMMARY_01_ACCEPTED`

Status: implemented the next readability recommendation from
`docs/future/active-pre-alpha-dogfood-findings-triage.md` by adding grouped
dependency pinning summaries for passive `project_archive_basic` reports.

## Scope

This phase added report-level summaries for existing dependency hygiene
findings. It did not add analyzers, finding IDs, storage migrations, endpoints,
deployment work, release state, package-manager activity, dependency resolution,
or live activity.

## Implemented

Backend:

- derives `dependency_pinning_summary` during project archive result shaping;
- includes only dependency pinning and broad-range dependency hygiene IDs;
- excludes dependency source review and package script findings;
- groups by ecosystem and dependency hygiene theme;
- collects manifest paths from existing evidence or parsed-manifest context;
- keeps individual findings, evidence, recommendations, severities, IDs,
  category metadata, and ecosystem metadata unchanged.

Frontend:

- preserves backend-provided dependency pinning summaries;
- derives the same summary for older result JSON when the backend field is not
  present;
- renders a compact Dependency Pinning Summary section;
- keeps every individual finding visible in the ecosystem-grouped findings
  list.

Exports:

- Markdown, HTML, XML, and PDF project archive exports include the summary when
  dependency pinning findings are present.

## Summary Shape

Each summary row includes:

- ecosystem ID and label;
- dependency hygiene category metadata;
- theme ID and label;
- contributing finding IDs;
- finding count;
- manifest count and manifest paths when available;
- manual-review summary text.

The wording stays review-oriented, for example:

```text
Python / requirements: 8 dependency pinning review indicators across 2 manifests.
```

## Preserved Boundaries

- Existing finding IDs were preserved.
- Existing severity values were preserved.
- Existing evidence and recommendation text were preserved.
- Existing category and ecosystem output remains present.
- Existing redaction behavior was not relaxed.
- No `archive/run-all` or `tools/runner/main.py` orchestration change was made.

## Deferred

- hard caps for pinning findings;
- severity changes;
- sanitizer fixture classification;
- dashboard-wide category and ecosystem rollups.

## Decision

```text
PASSIVE_DEPENDENCY_PINNING_SUMMARY_01_ACCEPTED
```
