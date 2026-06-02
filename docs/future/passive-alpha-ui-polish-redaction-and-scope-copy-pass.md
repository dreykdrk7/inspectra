# Passive Alpha UI Polish: Redaction and Scope Copy Pass

Status: implemented as a frontend/docs-only polish microphase.

Base commit: `88ef149 feat(ui): polish passive report states`

## Purpose

This microphase standardizes visible copy for redaction, passive scope, and no-scope guardrails across the shared passive report shell and the Redis/SQL database reports currently using it.

The change keeps Inspectra Passive technical alpha closed for module expansion. It does not add analyzers, endpoints, payload fields, exports, findings, severities, or redaction behavior.

## Normalized Redaction Copy

Shared report copy:

```text
Sensitive-looking values are redacted in results, exports, and raw JSON. Redacted values use [REDACTED]. This does not sanitize the original uploaded file.
```

This appears in the shared Raw JSON area and in Redis/SQL database redaction notes.

The copy is intentionally narrow:

- It says results, exports, and raw JSON are redacted.
- It says uploaded originals are not sanitized.
- It does not promise all possible secrets are detected.
- It does not validate credential correctness.
- It keeps `[REDACTED]` as the visible fixed placeholder.

## Normalized Passive Scope Copy

Shared report scope copy remains:

```text
Passive static review only. Inspectra reads bounded candidate files from the uploaded archive and reports heuristic review indicators. It does not execute tools, contact live services, validate credentials, query CVEs/advisories, or prove exploitability.
```

Dashboard archive-action copy is kept shorter:

```text
Archive reviews are passive and bounded. Inspectra reports review indicators; it does not execute the project, contact live services, validate credentials, or query CVEs for config checks.
```

The copy is meant to be visible without overwhelming the dashboard.

## Audit Catalog Copy

The audit catalog was reviewed for passive tone. Descriptions remain short and use passive/review/indicator language where appropriate. Audit type values, categories, source families, and labels were not changed.

## Wording Guardrails

Controlled UI copy should avoid words or phrases that imply confirmed compromise, live validation, active exploitation, or a clean verdict. Tests cover these critical phrases in the relevant frontend surfaces:

- compromised
- breached
- exploitable
- confirmed vulnerability
- credentials valid
- hacked
- live exposure confirmed
- database exposed
- Redis exposed

No-findings copy also avoids `safe` and `secure` wording so absence of findings is not framed as a clean bill of health.

## Surfaces Covered

- `PassiveReportShell`
- Redis config report
- SQL database config report
- Archive action copy in the dashboard
- Audit catalog description tests

This pass does not migrate every report family. Remaining reports can adopt the same shell/copy pattern in later small passes.

## Not Changed

- No backend changes.
- No runner changes.
- No export implementation changes.
- No endpoint changes.
- No payload contract changes.
- No redaction logic changes.
- No analyzer additions.
- No finding or severity changes.
- No active scanning or network behavior.

## Tests

Reference validation commands for this microphase:

```bash
npm run test -- --run PassiveReportShell RedisConfigJobReport SqlDatabaseConfigJobReport App dashboardFilters reportHelpers
npm run test -- --run
npm run build
git diff --check
git diff --cached --check
```

## Next Microphase

Recommended next step:

`PASSIVE-ALPHA-SMOKE-DEMO-FIXTURES-01-DOCS-FIRST-DESIGN`

Alternative if the product wants one more UI pass first:

`PASSIVE-ALPHA-UI-POLISH-AND-UX-COHERENCE-06-EXPORT-REPORT-READABILITY-POLISH`
