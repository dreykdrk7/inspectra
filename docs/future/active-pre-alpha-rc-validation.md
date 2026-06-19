# Active Pre-Alpha RC Validation

Decision: `ACTIVE_PRE_ALPHA_RC_VALIDATION_04_ACCEPTED`

Status: release-candidate validation record for the current Inspectra Active
technical alpha candidate. This phase validated the current tree and added this
documentation record only. It did not add backend, frontend, tools,
archive/run-all, or runner behavior.

## Scope

This was a validation and documentation phase only.

Allowed:

- inspect the current release-candidate docs and recent commit state;
- run local static and automated validation commands that do not contact
  targets or external services;
- record validation evidence and release-readiness guidance.

Not performed:

- app server startup;
- Docker or package-build commands;
- Nmap commands;
- live Active jobs;
- HTTP, DNS, TLS, CT, or other network traffic;
- real target usage;
- screenshot capture;
- tag, release, deploy, or push.

## Candidate Inputs

The validation used the current `main` branch state and the accepted Active
pre-alpha planning docs:

- `docs/future/active-pre-alpha-operational-polish.md`;
- `docs/future/active-pre-alpha-release-demo-readiness.md`;
- `docs/future/active-pre-alpha-release-notes.md`.

The release-candidate capability set remains:

- Active / Nmap basic v0;
- Active / TLS basic v0;
- Active DNS inventory v0, including authorized AXFR;
- Active DNS OSINT CT v0;
- Active HTTP basic/header review v1.

The candidate is still positioned for local/private/self-hosted use by an
operator with explicit authorization. Results remain redaction-first review
indicators that require manual validation.

## Git State

Initial status:

```text
## main...origin/main [ahead 1]
```

Recent commits inspected:

```text
e799323 docs(active): draft pre-alpha release notes
d491608 docs(active): add pre-alpha release demo readiness
033c49d docs(active): add pre-alpha operational polish
bbd6be6 docs(active): decide post http header path
dff3b6f fix(active): close http header review v1
```

Branch tracking state:

```text
main e799323 [origin/main: ahead 1] docs(active): draft pre-alpha release notes
```

The branch was one commit ahead of `origin/main` before this validation record.

## Automated Validation

Commands run from the repository root unless noted.

| Validation | Command | Result |
| --- | --- | --- |
| Python compile | `.venv/bin/python -m compileall -q backend/app backend/tests` | Passed with no output. |
| Focused Active backend slice | `.venv/bin/pytest backend/tests/test_backend.py -k "active_nmap_basic or active_tls_basic or active_dns_inventory or active_dns_osint or active_http_basic_header_review"` | Passed: 352 passed, 338 deselected. |
| Full backend suite | `.venv/bin/pytest backend/tests` | Passed: 774 passed. |
| Full frontend suite | `npm run test:run` from `frontend/` | Passed: 196 tests across 28 files. |
| Focused Active frontend slice | `npm run test:run -- ActiveNmapBasicPanel.test.tsx ActiveNmapBasicJobReport.test.tsx ActiveTlsBasicPanel.test.tsx ActiveTlsBasicJobReport.test.tsx ActiveDnsInventoryPanel.test.tsx ActiveDnsInventoryJobReport.test.tsx ActiveDnsOsintPanel.test.tsx ActiveDnsOsintJobReport.test.tsx ActiveHttpBasicHeaderReviewPanel.test.tsx ActiveHttpBasicHeaderReviewJobReport.test.tsx App.test.tsx dashboardFilters.test.ts reportHelpers.test.ts` from `frontend/` | Passed: 154 tests across 13 files. |
| Frontend production build | `npm run build` from `frontend/` | Passed; Vite reported an existing large-chunk warning for the main JavaScript bundle. |

No validation command started the application server, ran Docker, invoked Nmap,
or contacted live targets or external protocol services.

## Documentation Review

Reviewed release-candidate positioning across the pre-alpha docs plus the
current top-level architecture and security scope docs.

Confirmed themes:

- local/private/self-hosted operator posture;
- explicit authorization before any target-aware Active work;
- disabled-by-default Active feature gates;
- redaction-first report, export, Raw JSON, list, and detail behavior;
- review-indicator wording instead of binary verdict wording;
- manual validation requirement;
- no open target-intake positioning;
- no provider credential or connector scope;
- no archive/run-all or `tools/runner/main.py` handoff for Active.

The release notes remain a draft with validation placeholders. This document is
the validation evidence record for this microphase; the release notes were not
converted into a published release note and no tag or release was created.

## Guardrail Review

Current staged validation for this document must remain clean for:

- unsupported certainty or assessment-completeness claims;
- live-action command references;
- Docker, Nmap, screenshot, provider, or passive-source runtime expansion;
- archive/run-all or `tools/runner/main.py` Active handoff;
- secrets, credentials, cookies, account identifiers, or real target examples
  in release/demo docs.

The validation result for this phase is clean for the staged docs-only change.
Existing historical docs may contain explicit no-scope language; those were
not changed by this phase.

## Findings

No release-blocking validation failures were found.

Notes:

- The frontend production build completed with Vite's large-chunk warning. This
  is not treated as an RC blocker for the current technical alpha candidate.
- No manual browser smoke was run.
- No live target smoke was run.
- No screenshots were captured.
- No packaging, tag, release, deploy, or push step was performed.

## Residual Risks

- Release notes still contain draft placeholders and should be updated only
  after packaging or release validation decides the final evidence format.
- Local/private operator smoke on owned lab fixtures remains a separate,
  explicitly approved phase if needed.
- Docker packaging, release artifact checks, tag planning, and public release
  preparation remain separate phases.
- The current validation proves the local automated suites and docs guardrails
  for this tree; it does not replace later packaging validation.

## Release Readiness Recommendation

The current Active technical alpha candidate is ready to proceed to Docker or
release-packaging planning in a separate phase. It is also ready for tag and
release planning after packaging validation has its own evidence record.

Do not add another Active runtime capability before alpha publication. The next
work should consolidate release packaging, final release-note evidence, and any
approved local/private smoke checklist rather than expanding the Active feature
surface.

Suggested next microphase:

```text
ACTIVE_PRE_ALPHA_PACKAGING_PLAN_05
```

## Decision

```text
ACTIVE_PRE_ALPHA_RC_VALIDATION_04_ACCEPTED
```
