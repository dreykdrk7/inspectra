# Post-Alpha Readiness Backlog Triage

Status: docs-only triage for passive alpha tag/release readiness.

Base commit: `26f067b docs(alpha): document passive local demo readiness`

This document classifies the remaining Inspectra Passive alpha work before a local technical alpha tag/release. It does not add analyzers, fixtures, scripts, runtime behavior, backend changes, runner changes, frontend behavior, exports, findings, severities, tags, or release artifacts.

## 1. Current State

Inspectra Passive is closed for module expansion. The current state is documented as `READY_FOR_TRUSTED_LOCAL_ALPHA_DEMO_WITH_LIMITATIONS` in `docs/future/passive-alpha-packaging-readiness.md`.

Current assets are in place:

- Synthetic demo fixtures: `tests/fixtures/demo/passive-alpha/`
- Smoke/demo checklist: `docs/future/passive-alpha-smoke-demo-checklist.md`
- Packaging readiness decision: `docs/future/passive-alpha-packaging-readiness.md`
- Frontend upload-panel demo note: `docs/future/passive-alpha-smoke-demo-fixtures-frontend-demo-notes.md`
- Passive suite closeout: `docs/future/passive-suite-alpha-transversal-closeout.md`
- Release-gate smoke run: `docs/future/passive-alpha-release-gate-smoke-run.md`

Trusted local demo is possible with limitations. Public/external user readiness is not achieved yet. Active scanning, Nmap, network scanning, and new passive analyzers remain outside this release path. No tag or release should be created until the release gate in this document is completed.

## 2. Backlog Classification

### Release-Blocking Before Passive Alpha Tag

These items block a passive alpha tag/release if they are missing:

- Execute the final technical smoke commands and record the result.
- Execute the manual smoke checklist with synthetic fixtures.
- Pass the redaction-negative checklist against UI, Raw JSON, API responses, exports, and controlled errors.
- Confirm final backend tests pass, or document any environment-only failure clearly.
- Confirm final runner tests pass, excluding `web_basic` only when local sockets are blocked by sandbox policy.
- Confirm frontend tests and frontend build pass.
- Confirm `git status --short` is clean before tagging.
- Prepare release notes.
- Decide final tag name.
- Confirm README links to fixtures, smoke checklist, and readiness documentation.
- Confirm no critical scope/copy gaps remain, especially around heuristic findings, redaction limits, local storage, and no active scanning.

Current assessment: these are process gates, not discovered product blockers. The next step is to run and record the smoke/release gate, then prepare release notes.

### Demo-Blocking Before Showing Trusted Local Alpha

These do not necessarily block a technical tag, but they should be completed before showing a trusted local demo:

- Run a real manual smoke with `tests/fixtures/demo/passive-alpha/archives/demo-archive-app-config.zip`.
- Run a real manual smoke with `tests/fixtures/demo/passive-alpha/archives/demo-archive-data-layer.zip`.
- Confirm Redis and SQL DB exports are available and readable enough for demo.
- Confirm the redaction-negative archive does not leak fixture strings in visible result surfaces.
- Confirm the upload-panel demo note is visible.
- Confirm archive-only actions are absent for non-archive files.
- Confirm job filters, labels, categories, running/failed states, and empty states remain readable.
- Prepare a short demo narrative using `docs/future/passive-alpha-smoke-demo-checklist.md`.

### External-User Blockers

These are required before opening Inspectra beyond trusted local alpha use:

- Authentication and deployment hardening.
- Storage retention controls.
- Upload cleanup/reset tooling.
- Clear local-data deletion and retention documentation.
- Legal/security disclaimer for user-uploaded content.
- Clearer onboarding for non-maintainer users.
- Limits and file-size messaging in product/docs.
- Real deployment threat model.
- Multi-user isolation and authorization model.
- Operational logging/error handling posture for deployed environments.
- Review of CORS, data mounts, backup/retention, and secrets handling for non-local deployments.

These are not required for the trusted local alpha tag if the release notes clearly limit the release to local technical alpha use.

### Nice Before Broader Alpha

These improve quality but should not block the local technical alpha tag:

- Export readability polish.
- Migrate more analyzer reports to the shared `PassiveReportShell`.
- Fixture-driven smoke script.
- Demo reset instructions.
- Better report severity and confidence explanations.
- UI onboarding improvements.
- Cross-analyzer summary/dashboard refinement.
- More explicit report copy for sparse, failed, truncated, and no-findings states.

### Post-Release Backlog

These should wait until after the passive alpha tag/release:

- MongoDB passive config module.
- RabbitMQ passive config module.
- Elasticsearch/OpenSearch passive config module.
- Apache config module.
- Additional passive analyzers.
- Richer per-analyzer detection expansions.
- Broader report-shell migration once alpha feedback is collected.

### Out Of Scope Until Active/Network Product Block

These remain outside the passive alpha release and should not be pulled into the tag gate:

- Active/Nmap/network scanning.
- Port scanning.
- Live service reachability validation.
- Credential validation.
- Exploitability confirmation.
- Provider, registry, CVE, advisory, or reputation lookups for passive config modules.
- External target expansion beyond already documented authorized web/DNS/subdomain flows.

## 3. Passive Alpha Release Gate

Minimum checklist before creating a passive alpha tag:

- `git status --short` is clean.
- Backend tests pass:

```bash
.venv/bin/python -m pytest backend/tests/test_backend.py
```

- Runner tests pass:

```bash
.venv/bin/python -m pytest tools/tests/test_runner.py -k "not web_basic"
```

- Python compile checks pass:

```bash
python3 -m compileall backend tools
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools
```

- Frontend tests pass:

```bash
(cd frontend && npm run test -- --run)
```

- Frontend build passes:

```bash
(cd frontend && npm run build)
```

- Smoke checklist is executed with synthetic fixtures:

```text
docs/future/passive-alpha-smoke-demo-checklist.md
```

- Redaction-negative checklist passes for fixture strings.
- README points to fixtures/checklist/readiness documentation.
- Release notes are created.
- Tag name is decided.
- No release-blocking issues remain open.

## 4. Release Tag Naming

Options:

- `v0.1.0-passive-alpha`
- `v0.1.0-alpha-passive`
- `passive-alpha-0.1.0`

Recommended tag: `v0.1.0-passive-alpha`

Rationale:

- Keeps semantic version shape at the front.
- Makes the release channel explicit.
- Reads naturally in changelogs and GitHub release lists.
- Leaves room for later `v0.1.0` or `v0.2.0` releases if the product grows beyond trusted local passive alpha.

## 5. Release Notes Outline

Future release notes should include:

- Scope.
- Included analyzers.
- UI highlights.
- Fixtures and smoke checklist.
- Security and non-scope.
- Redaction posture and limits.
- Local storage caveats.
- Known limitations.
- Not for external or production use.
- Next roadmap.

Recommended title:

```text
Inspectra Passive Technical Alpha v0.1.0
```

Recommended opening copy:

```text
This is a trusted local technical alpha for passive review of uploaded files and archives. Findings are heuristic review indicators, not confirmed vulnerabilities. Results, exports, and Raw JSON are redacted best-effort with [REDACTED], but uploaded originals are not sanitized.
```

## 6. Final Decision

Decision: `READY_FOR_SMOKE_RUN_BEFORE_RELEASE_TAG`.

No documentation blockers were found for proceeding to the final smoke run. Do not create a tag yet. The release-blocking work is now operational: run the gate, record outcomes, prepare release notes, decide final tag metadata, and only then create the passive alpha tag.

If any release gate item fails, change the release state to `BLOCKED_BEFORE_RELEASE_TAG` and record the blocker in the release notes or a follow-up readiness document.

Release-gate follow-up:

```text
docs/future/passive-alpha-release-gate-smoke-run.md
```

That gate found release-blocking redaction failures and records the current release state as `BLOCKED_BEFORE_RELEASE_TAG`.

## 7. Next Recommended Microphase

Recommended next microphase:

`PASSIVE-ALPHA-RELEASE-GATE-SMOKE-RUN`

That microphase should run the technical validations, execute the manual smoke with synthetic fixtures, record redaction-negative outcomes, prepare release notes, and decide whether to create `v0.1.0-passive-alpha`.
