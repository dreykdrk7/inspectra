# Inspectra Passive Alpha Packaging Readiness

Status: `READY_FOR_TRUSTED_LOCAL_ALPHA_DEMO_WITH_LIMITATIONS`.

Base commit: `5952ad1 feat(ui): add passive alpha demo fixture note`

This document closes the local packaging/readiness pass for the Inspectra Passive technical alpha. It does not add analyzers, fixtures, scripts, runtime behavior, backend changes, runner changes, frontend behavior, exports, findings, severities, or redaction logic.

## 1. Final State

Inspectra Passive local technical alpha is ready for a trusted local demo.

Module expansion remains closed. Do not open new passive analyzers before the post-alpha backlog is explicitly re-scoped. Active and network analysis remains a separate future product block with separate authorization, safety, and implementation boundaries.

The alpha is ready to demonstrate local uploads, bounded archive actions, jobs, reports, exports, redaction posture, and synthetic smoke fixtures. It is not ready for external public users, production deployment, multi-user SaaS use, or unattended handling of real sensitive archives.

## 2. Included Assets

Reference assets for the alpha demo/readiness package:

- Main README: `README.md`
- Architecture overview: `docs/architecture.md`
- Security scope: `docs/security-scope.md`
- Passive suite transversal closeout: `docs/future/passive-suite-alpha-transversal-closeout.md`
- UI polish design: `docs/future/passive-alpha-ui-polish-and-ux-coherence-design.md`
- UI redaction/scope copy pass: `docs/future/passive-alpha-ui-polish-redaction-and-scope-copy-pass.md`
- Fixture pack design: `docs/future/passive-alpha-smoke-demo-fixtures-design.md`
- Fixture pack creation closeout: `docs/future/passive-alpha-smoke-demo-fixtures-create-synthetic-pack.md`
- Synthetic fixture pack: `tests/fixtures/demo/passive-alpha/`
- Fixture pack README: `tests/fixtures/demo/passive-alpha/README.md`
- Smoke/demo checklist: `docs/future/passive-alpha-smoke-demo-checklist.md`
- Frontend demo note closeout: `docs/future/passive-alpha-smoke-demo-fixtures-frontend-demo-notes.md`
- Post-alpha release-readiness triage: `docs/future/post-alpha-readiness-backlog-triage.md`
- Release-gate smoke run: `docs/future/passive-alpha-release-gate-smoke-run.md`
- Release-gate smoke rerun: `docs/future/passive-alpha-release-gate-smoke-rerun.md`
- Manual browser smoke before tag: `docs/future/passive-alpha-manual-browser-smoke-before-tag.md`
- Manifest upload/listing fix: `docs/future/passive-alpha-release-gate-manifest-upload-listing-fix.md`
- Final manual browser smoke rerun before tag: `docs/future/passive-alpha-manual-browser-smoke-rerun-before-tag.md`

## 3. Demo Scope

The trusted local alpha demo can show:

- Local upload flow.
- File and archive registration.
- Archive-only grouped passive actions.
- Job creation and status transitions.
- Job filters, labels, categories, and search.
- Readable reports for representative modules.
- Redis and SQL DB reports using `PassiveReportShell`.
- Redacted Raw JSON.
- Markdown, HTML, XML, and PDF export controls.
- No-read behavior for sensitive adjacent files.
- Not-resolved behavior for includes and references.
- Redaction-negative checks using synthetic fixture strings.

The demo must not show or imply:

- Exploitation.
- Active scanning.
- Nmap, port scanning, or network scanning.
- Live service reachability.
- Credential validation.
- CVE or advisory lookup.
- Production readiness.
- Multi-user SaaS readiness.
- Complete analyzer coverage.
- Sanitization of uploaded originals.
- A clean verdict, breach verdict, exploitability verdict, or credential-validity verdict.

## 4. Trusted Local Demo Checklist

Before the demo:

- Confirm `git status --short` is clean.
- Run the technical smoke commands listed in this document or in `docs/future/passive-alpha-smoke-demo-checklist.md`.
- Start the backend and frontend locally.
- Confirm the upload panel shows the local alpha demo fixture note.
- Use only synthetic fixtures under `tests/fixtures/demo/passive-alpha/`.
- Do not upload real secrets.
- Do not upload production archives.
- Do not keep real customer or third-party data in local uploads.

During the demo:

- Upload `tests/fixtures/demo/passive-alpha/archives/demo-archive-app-config.zip`.
- Show grouped archive actions.
- Run a few representative passive analyzers.
- Show jobs, filters, labels, and categories.
- Upload `tests/fixtures/demo/passive-alpha/archives/demo-archive-data-layer.zip`.
- Run Redis and SQL DB analysis.
- Show `PassiveReportShell` structure for Redis/SQL DB.
- Show redacted Raw JSON.
- Show export controls for a completed job.
- Upload or use `demo-archive-redaction-negative.zip` if a redaction-negative check is needed.
- Use the narrative in `docs/future/passive-alpha-smoke-demo-checklist.md`.

After the demo:

- Stop local services.
- Remove local uploaded data if needed according to the existing local storage model.
- Record issues and backlog items.
- Do not keep real data in `data/uploads` or `data/results`.

## 5. Technical Validation Checklist

Recommended commands before a trusted local demo:

```bash
git status --short
python3 -m compileall backend tools
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools
.venv/bin/python -m pytest backend/tests/test_backend.py
.venv/bin/python -m pytest tools/tests/test_runner.py -k "not web_basic"
(cd frontend && npm run test -- --run)
(cd frontend && npm run build)
git diff --check
```

Optional broader validation:

```bash
.venv/bin/python -m pytest
```

When the Python suite runs inside a sandbox that blocks local socket creation, `web_basic` tests can fail while starting a local HTTP server. In that case, run the focused runner command above or re-run the exact suite with appropriate local socket permission and record the result.

## 6. Packaging And Readiness Gaps

Known readiness gaps:

- There is no installer or packaged release artifact yet.
- Local storage caveats still matter: uploaded originals and stored job results remain on disk until removed.
- Upload retention and demo reset steps need clearer tooling for repeated demos.
- Authentication, authorization, deployment hardening, and multi-user controls are not part of this alpha.
- The shared `PassiveReportShell` has only been applied to Redis and SQL DB reports so far.
- Export presentation polish remains backlog.
- Synthetic fixtures demonstrate product behavior, not real-world completeness.
- There is no active scanner in this alpha.
- Passive config modules do not query CVEs or advisories.

## 7. Alpha Messaging

Recommended copy:

```text
Inspectra Passive is a local technical alpha for reviewing uploaded files and archives with bounded passive checks. Findings are heuristic review indicators, not confirmed vulnerabilities. Sensitive-looking values are redacted in results, exports, and Raw JSON, but uploaded originals are not sanitized.
```

Forbidden copy:

- "production ready"
- "proves exploitability"
- "validates credentials"
- "confirms exposure"
- "guarantees no secrets"
- "complete vulnerability scanner"
- "active pentest"

## 8. Backlog After Readiness

Must before public external users:

- Authentication and deployment hardening.
- Retention and storage controls.
- Clearer onboarding.
- Legal and security disclaimer.
- Error handling and report readability pass.

Nice before broader alpha:

- Export polish.
- Report shell migration for more analyzers.
- Fixture-driven smoke script.
- Demo reset instructions.

Post-alpha analyzers:

- MongoDB.
- RabbitMQ.
- Elasticsearch/OpenSearch.
- Apache.

Future separate product block:

- Active/network/Nmap analysis.

## 9. Decision

Decision: `READY_FOR_TRUSTED_LOCAL_ALPHA_DEMO_WITH_LIMITATIONS`.

Rationale:

- The passive suite is closed for module expansion.
- Synthetic fixtures exist and are documented.
- A smoke/demo checklist exists.
- The frontend upload panel now carries a local demo note.
- The UI has grouped archive actions, labels/categories, filter polish, redaction/scope copy, and Redis/SQL DB report-shell coverage.
- The known limitations are explicit and should be communicated before any demo.

No blockers were identified for a trusted local demo using only synthetic fixtures.

Do not treat this as approval for external users, production deployment, real-secret handling, active scanning, or new analyzer expansion.

## 10. Next Recommended Product Step

Recommended next step after the trusted local alpha demo:

`POST_ALPHA_READINESS_BACKLOG_TRIAGE`

Focus that triage on external-user blockers first: auth/deployment hardening, retention/storage controls, onboarding, disclaimers, and report/export readability.

That triage is documented in:

```text
docs/future/post-alpha-readiness-backlog-triage.md
```

The release-gate smoke run is documented in:

```text
docs/future/passive-alpha-release-gate-smoke-run.md
```

The post-fix release-gate API smoke rerun is documented in:

```text
docs/future/passive-alpha-release-gate-smoke-rerun.md
```

That rerun passed API/job/export redaction checks and recorded the release state at that time as `READY_FOR_MANUAL_BROWSER_SMOKE_BEFORE_TAG`.

The manual browser smoke follow-up is documented in:

```text
docs/future/passive-alpha-manual-browser-smoke-before-tag.md
```

It passed archive report DOM and expanded Raw JSON redaction checks, but that recorded run remained `BLOCKED_BEFORE_RELEASE_TAG` because the non-archive `package.json` manifest sanity check failed in the browser flow and backend `/files` returned `500` after manifest upload.

The manifest upload/listing blocker fix is documented in:

```text
docs/future/passive-alpha-release-gate-manifest-upload-listing-fix.md
```

That fix passed focused backend/frontend tests and a focused real-browser smoke for `package.json` manifest upload.

The full browser smoke rerun is documented in:

```text
docs/future/passive-alpha-manual-browser-smoke-rerun-before-tag.md
```

That rerun passed archive DOM, expanded Raw JSON, export-control, redaction-negative, and non-archive manifest sanity checks. The current release-gate state is `READY_TO_TAG_PASSIVE_ALPHA`, assuming `git status --short` remains clean at tag time. No tag was created in the rerun microphase.
