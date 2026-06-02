# Passive Alpha Smoke Demo Fixtures: Frontend Demo Notes

Status: implemented as a frontend/docs-only microphase.

Base commit: `a8ce9d7 docs(demo): wire passive alpha smoke checklist`

This microphase adds a small local-alpha demo note to the upload area. It does not add analyzers, endpoints, scripts, run-all behavior, backend changes, runner changes, export changes, report contract changes, fixtures, or redaction logic.

## UI Copy Added

The upload panel now shows:

```text
Local alpha demo: use the synthetic fixtures under tests/fixtures/demo/passive-alpha/ to smoke uploads, grouped archive actions, reports, exports, and redaction. Do not upload real secrets or production archives for demos. Results, exports, and Raw JSON are redacted with [REDACTED]; this does not sanitize the original uploaded file.
```

## Location

Frontend surface:

```text
frontend/src/App.tsx
```

The note appears in the `Upload File` panel near the file upload controls. It is intentionally text-only and does not introduce routing, docs links, a wizard, run-all behavior, or new actions.

## Purpose

The note helps local demo/smoke users remember:

- Use the synthetic fixture pack.
- Use local uploads.
- Archive actions are passive reviews.
- Do not upload real secrets.
- Do not upload production archives for demos.
- Results, exports, and Raw JSON are redacted.
- Redaction does not sanitize original uploaded files.

## Guardrails

The note avoids wording that would imply:

- Compromise.
- Breach.
- Exploitability.
- Confirmed vulnerability.
- Credential validity.
- A clean verdict.
- Live exposure.

## Tests

Updated frontend tests verify:

- The note appears in the dashboard/upload area.
- It mentions `tests/fixtures/demo/passive-alpha/`.
- It mentions synthetic fixtures.
- It warns against real secrets and production archives.
- It mentions `[REDACTED]`.
- It says original uploaded files are not sanitized.
- It does not introduce run-all wording.
- Existing grouped archive action tests still pass.
- Redis and SQL DB archive action tests still pass.

Reference validation commands:

```bash
npm run test -- --run App dashboardFilters reportHelpers
npm run test -- --run
npm run build
git diff --check
git diff --cached --check
```

No Python tests are required because backend/tools were not touched.

## Scope Kept

No changes were made to:

- Backend.
- Runner.
- Fixtures.
- Export implementation.
- API endpoints.
- Payload contracts.
- Redaction logic.
- Analyzer list.
- Findings.
- Severities.
- Active/network behavior.

## Next Microphase

Recommended next step:

`PASSIVE-ALPHA-SMOKE-DEMO-FIXTURES-05-ALPHA-PACKAGING-READINESS`
