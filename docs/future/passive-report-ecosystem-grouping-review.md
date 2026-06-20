# Passive Report Ecosystem Grouping Review

Decision: `PASSIVE_REPORT_ECOSYSTEM_GROUPING_02_REVIEW_ACCEPTED`

Status: reviewed and hardened `PASSIVE_REPORT_ECOSYSTEM_GROUPING_01` before
building more project report features on top of ecosystem metadata.

## Review Scope

Reviewed the phase-01 backend metadata catalog, report/export shaping, frontend
normalizer, project archive detail rendering, focused tests, and implementation
record. This phase did not add analyzers, finding IDs, storage migrations,
endpoints, deployment work, release state, package-manager activity, or live
activity.

## Gap Found

The frontend normalizer derived category labels from its local metadata catalog
even when the backend had already supplied category metadata. Ecosystem IDs were
preserved, but a backend-provided ecosystem ID without a label could render with
the local unknown label.

## Hardening

- frontend findings now preserve backend-provided category and category label
  fields when present;
- frontend findings now preserve backend-provided ecosystem IDs and derive the
  known label when only the ID is present;
- ambiguous dependency findings still use the neutral ecosystem fallback unless
  manifest context identifies a package or Python dependency manifest;
- grouping tests now assert that every individual finding remains visible inside
  ecosystem groups.

## Preserved Boundaries

- Existing finding IDs were preserved.
- Existing severity values were preserved.
- Existing evidence and recommendation text were preserved.
- Existing export category and ecosystem fields remain present.
- Existing redaction behavior was not relaxed.
- No `archive/run-all` or `tools/runner/main.py` orchestration change was made.

## Deferred

- dependency pinning grouped summaries;
- sanitizer fixture classification;
- dashboard-wide category and ecosystem rollups;
- ecosystem cleanup across other audit families.

## Decision

```text
PASSIVE_REPORT_ECOSYSTEM_GROUPING_02_REVIEW_ACCEPTED
```
