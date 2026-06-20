# Passive Dependency Pinning Summary Review

Decision: `PASSIVE_DEPENDENCY_PINNING_SUMMARY_02_REVIEW_ACCEPTED`

Status: reviewed and hardened `PASSIVE_DEPENDENCY_PINNING_SUMMARY_01` before
building more project report UX features on top of dependency summaries.

## Review Scope

Reviewed the phase-01 backend summary derivation, report/export rendering,
frontend normalizer, project archive detail rendering, focused tests, and
implementation record. This phase did not add analyzers, finding IDs, storage
migrations, endpoints, deployment work, release state, package-manager activity,
dependency resolution, or live activity.

## Gap Found

Project archive exports included an empty Dependency Pinning Summary section or
XML element when no pinning rows were present. The summary was empty, but the
export shape was noisier than intended for jobs containing only package-script,
dependency-source, unknown, or other non-pinning findings.

## Hardening

- backend exports now omit Dependency Pinning Summary output when no summary
  rows exist;
- backend tests cover absence of the summary in Markdown, HTML, XML, and PDF
  exports when no pinning findings are present;
- backend tests now cover manifest-path deduplication with repeated pinning
  findings from the same manifest;
- frontend tests now cover preservation of backend-provided summary rows;
- frontend tests now cover package-script and dependency-source exclusion from
  the derived pinning summary.

## Preserved Boundaries

- Existing finding IDs were preserved.
- Existing severity values were preserved.
- Individual findings remain visible.
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
PASSIVE_DEPENDENCY_PINNING_SUMMARY_02_REVIEW_ACCEPTED
```
