# Passive Alpha Release Gate Smoke Run

Status: `BLOCKED_BEFORE_RELEASE_TAG`.

Base commit: `0fff2c7 docs(alpha): triage passive release readiness backlog`

Release candidate target: `v0.1.0-passive-alpha`

Follow-up: the release-blocking CI/CD and Nginx redaction leaks are tracked and fixed in `docs/future/passive-alpha-release-gate-redaction-fix.md`. The full API smoke rerun is recorded in `docs/future/passive-alpha-release-gate-smoke-rerun.md`; API redaction checks passed, but manual/browser UI DOM and Raw JSON smoke remains pending before any tag.

This document records the release-gate smoke run for Inspectra Passive Technical Alpha. It does not create a tag, create a release, add analyzers, change runtime behavior, change endpoints, change exports, change redaction logic, add scripts, add fixtures, or open active/network scope.

## 1. Initial State

| Item | Result | Notes |
| --- | --- | --- |
| Base commit | Pass | `0fff2c7 docs(alpha): triage passive release readiness backlog` |
| Initial working tree | Pass | `git status --short` was clean before the gate. |
| Release candidate target | Recorded | `v0.1.0-passive-alpha` |
| Tag created | No | This microphase explicitly does not create the tag. |

## 2. Technical Validations

| Command | Result | Notes |
| --- | --- | --- |
| `git status --short` | Pass | Clean at start of gate. |
| `git log --oneline -12` | Pass | Confirmed base commit and recent alpha readiness commits. |
| `python3 -m compileall backend tools` | Pass | Completed successfully. |
| `PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools` | Pass | Completed successfully. |
| `.venv/bin/python -m pytest backend/tests/test_backend.py` | Pass | `189 passed in 2.09s`. |
| `.venv/bin/python -m pytest tools/tests/test_runner.py -k "not web_basic"` | Pass | `115 passed, 11 deselected in 0.79s`. |
| `npm run test -- --run` from `frontend/` | Pass | `16 passed`, `104 passed`. |
| `npm run build` from `frontend/` | Pass | TypeScript and Vite build completed successfully. |
| `git diff --check` | Pass | Final docs-only validation for this microphase. |
| `git diff --cached --check` | Pass | Final staged docs-only validation for this microphase. |

Optional full `.venv/bin/python -m pytest` was not run in this pass. The release gate used the focused backend suite and the runner suite excluding `web_basic`, matching the documented sandbox-local-socket caveat.

## 3. Smoke Execution Method

Technical smoke was executed against local FastAPI services with synthetic fixtures only:

- Data dir: `/tmp/inspectra-release-gate-data`
- Runner: `127.0.0.1:18081`
- Backend: `127.0.0.1:18000`
- Fixtures: `tests/fixtures/demo/passive-alpha/archives/*.zip`

The first API client attempt from the sandbox failed with `PermissionError: [Errno 1] Operation not permitted` while opening a localhost socket. The smoke was re-run with explicit localhost permission. Port `8081` was unavailable in the host namespace, so the smoke used alternate local ports `18081` and `18000`.

The API smoke uploaded four synthetic fixture archives, launched 23 representative passive jobs, waited for completion, fetched each completed job JSON, and downloaded Markdown, HTML, XML, and PDF exports for every completed job.

Temporary smoke summary:

```text
/tmp/inspectra-release-gate-smoke.json
```

The temporary summary is not committed.

## 4. Smoke Manual Matrix

| Fixture | Analyzers executed | Reports reviewed | Exports reviewed | Redaction checks | Result | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `demo-archive-app-config.zip` | `archive`, `project-archive`, `django-config`, `node-package-config`, `secrets-review` | API job JSON fetched for all jobs | Markdown/HTML/XML/PDF for all completed jobs | No listed fixture-string leaks detected | Pass | API-level smoke only; UI DOM not manually exercised. |
| `demo-archive-container-infra.zip` | `docker-config`, `compose-config`, `ci-cd-config`, `k8s-config`, `terraform-config`, `nginx-config`, `secrets-review` | API job JSON fetched for all jobs | Markdown/HTML/XML/PDF for all completed jobs | Leak detected in `ci_cd_config_basic` job JSON and exports | Fail | Release-blocking redaction issue. |
| `demo-archive-data-layer.zip` | `redis-config`, `sql-database-config`, `database-config`, `secrets-review` | API job JSON fetched for all jobs | Markdown/HTML/XML/PDF for all completed jobs | No listed fixture-string leaks detected | Pass | Redis and SQL DB report/export surfaces completed through API. |
| `demo-archive-redaction-negative.zip` | `secrets-review`, `redis-config`, `sql-database-config`, `nginx-config`, `compose-config`, `terraform-config`, `ci-cd-config` | API job JSON fetched for all jobs | Markdown/HTML/XML/PDF for all completed jobs | Leaks detected in `nginx_config_basic` and `ci_cd_config_basic` job JSON and exports | Fail | Release-blocking redaction issue. |

Smoke totals:

- Fixtures uploaded: `4`
- Jobs launched: `23`
- Jobs completed: `23`
- Failed jobs: `0`
- Exports checked: `92`
- `[REDACTED]` observed: yes
- Redaction-negative result: failed

UI DOM smoke was not completed as a real browser/manual demo in this environment. Frontend unit/integration tests and build passed, but DOM/manual smoke remains pending before a tag.

## 5. Redaction Negative Results

Surfaces checked by API smoke:

- `GET /jobs/{job_id}`
- Markdown export
- HTML export
- XML export
- PDF export
- Controlled errors included in stored job/export payloads where present

Surfaces not checked in this environment:

- Browser DOM from a real manual UI session.
- Frontend Raw JSON panel from a real browser session.

Strings checked:

- `super-secret-password`
- `token_should_never_render`
- `raw-api-key-123456`
- `postgres://user:pass@example.com/db`
- `mysql://user:pass@example.com/db`
- `redis://:super-secret-password@redis:6379/0`
- `Authorization: Bearer token_should_never_render`
- `-----BEGIN PRIVATE KEY-----`
- `PRIVATE KEY`
- `dump_row_secret_should_not_render`
- `pgpass_secret_should_not_render`
- `mycnf_secret_should_not_render`
- `acl_password_hash_should_not_render`

Failure details:

| Fixture | Analyzer | Surfaces | Strings observed | Result |
| --- | --- | --- | --- | --- |
| `demo-archive-container-infra.zip` | `ci_cd_config_basic` | Job JSON, Markdown, HTML, XML, PDF | `token_should_never_render`, `Authorization: Bearer token_should_never_render` | Fail |
| `demo-archive-redaction-negative.zip` | `nginx_config_basic` | Job JSON, Markdown, HTML, XML, PDF | `super-secret-password`, `token_should_never_render` | Fail |
| `demo-archive-redaction-negative.zip` | `ci_cd_config_basic` | Job JSON, Markdown, HTML, XML, PDF | `token_should_never_render`, `Authorization: Bearer token_should_never_render` | Fail |

No leaks were detected in the smoke summary for the remaining checked analyzers/surfaces. Because the failures are in stored job JSON and all export formats, this is release-blocking.

## 6. Blockers

### Release-Blocking

- Redaction-negative check failed for `ci_cd_config_basic` on `demo-archive-container-infra.zip`.
- Redaction-negative check failed for `ci_cd_config_basic` on `demo-archive-redaction-negative.zip`.
- Redaction-negative check failed for `nginx_config_basic` on `demo-archive-redaction-negative.zip`.
- Real browser DOM/Raw JSON smoke was not completed in this environment.

### Demo-Blocking

- Complete a manual browser smoke after fixing the redaction blockers.
- Confirm the upload-panel demo note is visible in a real browser session.
- Confirm archive-only actions are absent for non-archive files in a real browser session.
- Confirm Redis/SQL DB `PassiveReportShell` and export controls in a real browser session.

### External-User Blockers

These remain unchanged from readiness triage:

- Authentication and deployment hardening.
- Retention and storage controls.
- Upload cleanup/reset tooling.
- Legal/security disclaimer.
- Clearer onboarding.
- Limits and file-size messaging.
- Real deployment threat model.
- Multi-user isolation.

### Non-Blocking Backlog

- Export readability polish.
- Report shell migration for more analyzers.
- Fixture-driven smoke script.
- Demo reset instructions.
- Better report severity/confidence explanations.
- Future analyzers and active/network/Nmap remain post-release or separate product blocks.

## 7. Release Notes Draft

Title:

```text
Inspectra Passive Technical Alpha v0.1.0
```

Tag:

```text
v0.1.0-passive-alpha
```

Opening copy:

```text
This is a trusted local technical alpha for passive review of uploaded files and archives. Findings are heuristic review indicators, not confirmed vulnerabilities. Results, exports, and Raw JSON are redacted best-effort with [REDACTED], but uploaded originals are not sanitized.
```

### Scope

- Local trusted technical alpha.
- Passive review of uploaded files and archives.
- Bounded archive/file parsing.
- Authorized baseline web/DNS/subdomain flows remain separate from archive-based passive config checks.

### Included Analyzers

- PDF, image, manifest, archive, and project-archive basics.
- Django, Docker, secrets review, Node package config, CI/CD, Kubernetes, Terraform, Nginx, Compose, Database, SQL DB, and Redis passive config modules.
- Authorized web, domain, and explicit subdomain baseline flows.

### UI Highlights

- Local upload workflow.
- Grouped archive actions.
- Job filters, labels, categories, and search.
- Readable reports.
- Redis and SQL DB `PassiveReportShell`.
- Redacted Raw JSON.
- Markdown, HTML, XML, and PDF export controls.

### Synthetic Fixtures And Smoke

- Fixture pack: `tests/fixtures/demo/passive-alpha/`
- Smoke checklist: `docs/future/passive-alpha-smoke-demo-checklist.md`
- Release gate result: blocked before tag until redaction-negative failures are fixed and manual UI smoke is completed.

### Security And Non-Scope

- No exploitation.
- No active scanning.
- No Nmap or port scanning.
- No credential validation.
- No provider, registry, CVE, advisory, cloud, Docker Hub, package registry, Kubernetes, Redis, SQL database, or CI provider lookups for passive config modules.
- No execution of uploaded projects, Docker, Compose, Terraform, Nginx, Kubernetes, Redis, SQL database clients/servers, package managers, or CI workflows for passive config modules.

### Redaction Posture

- Results, exports, and Raw JSON use best-effort redaction with `[REDACTED]`.
- Uploaded originals are not sanitized.
- Current release gate found redaction blockers and the tag must wait.

### Known Limitations

- Heuristic findings can produce false positives and false negatives.
- Some reports still need readability polish.
- `PassiveReportShell` is not yet applied to every analyzer.
- Local uploaded data and results remain on disk until removed.
- Demo fixtures are synthetic and do not prove real-world completeness.

### Not For Production Or External Use

- Not production ready.
- Not a multi-user SaaS.
- Not a complete vulnerability scanner.
- Not proof of exploitability, compromise, exposure, or credential validity.

### Next Roadmap

- Fix release-blocking redaction issues.
- Re-run API smoke and complete manual browser smoke.
- Prepare final release notes.
- Create `v0.1.0-passive-alpha` only after the gate passes.
- After tag/release, triage external-user blockers before broader alpha.

## 8. Final Decision

Decision: `BLOCKED_BEFORE_RELEASE_TAG`.

The technical validation suites passed, and API-level smoke completed all launched jobs and exports. The release cannot be tagged because the redaction-negative gate failed in stored job JSON and export surfaces for `ci_cd_config_basic` and `nginx_config_basic`, and a real browser manual smoke remains pending.

No tag was created.

## 9. Next Recommended Microphase

Recommended next microphase:

`PASSIVE-ALPHA-RELEASE-GATE-REDACTION-FIX`

Scope for that microphase should be narrow: fix the observed CI/CD and Nginx redaction leaks, add regression tests for the fixture strings/surfaces, then re-run this release gate smoke.
