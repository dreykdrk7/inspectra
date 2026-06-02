# Passive Alpha Release Gate Smoke Rerun

Status: `READY_FOR_BROWSER_SMOKE_RERUN_BEFORE_TAG`.

Base commit: `9751e89 fix(redaction): block passive alpha ci nginx leaks`

Previous gate: `c23c0ca docs(alpha): record passive release gate smoke run`

Target tag: `v0.1.0-passive-alpha`

This document records the release-gate rerun for Inspectra Passive Technical Alpha after the CI/CD and Nginx redaction fix. It does not create a tag, create a release, add analyzers, change endpoints, change frontend behavior, add scripts, change exports, expand active/network scope, or inspect real secrets.

Follow-up browser gate: `docs/future/passive-alpha-manual-browser-smoke-before-tag.md`.

The follow-up real browser DOM and Raw JSON smoke passed for seven archive jobs, but the release remains blocked because the required non-archive `package.json` manifest sanity check failed: the UI showed `Cannot read properties of null (reading 'reset')` and backend `/files` returned `500` after manifest upload. Do not create `v0.1.0-passive-alpha` yet.

Manifest blocker fix: `docs/future/passive-alpha-release-gate-manifest-upload-listing-fix.md`.

The manifest upload/listing blocker has been fixed and covered by focused backend/frontend tests plus a focused real-browser smoke. The current state is `READY_FOR_BROWSER_SMOKE_RERUN_BEFORE_TAG`.

## A. Initial State

| Item | Result | Notes |
| --- | --- | --- |
| Working tree | Pass | `git status --short` was clean before the rerun. |
| HEAD | Pass | `9751e89 fix(redaction): block passive alpha ci nginx leaks`. |
| Prior blocker commit | Recorded | `c23c0ca docs(alpha): record passive release gate smoke run`. |
| Fix document | Recorded | `docs/future/passive-alpha-release-gate-redaction-fix.md`. |
| Target tag | Recorded | `v0.1.0-passive-alpha`. |
| Tag created | No | This microphase explicitly does not create the tag. |

## B. Technical Validations

| Command | Result | Notes |
| --- | --- | --- |
| `git status --short` | Pass | Clean at start. |
| `git log --oneline -12` | Pass | Confirmed `9751e89` at HEAD and recent alpha gate commits. |
| `python3 -m compileall backend tools` | Pass | Completed successfully. |
| `PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools` | Pass | Completed successfully with cache outside repo. |
| `.venv/bin/python -m pytest backend/tests/test_backend.py` | Pass | `189 passed in 2.14s`. |
| `.venv/bin/python -m pytest tools/tests/test_runner.py -k "not web_basic"` | Pass | `117 passed, 11 deselected in 0.83s`. |
| `npm run test -- --run` from `frontend/` | Pass | `16 passed`, `104 passed`. |
| `npm run build` from `frontend/` | Pass | TypeScript and Vite build completed successfully. |
| `.venv/bin/python -m pytest` | Environment fail, then Pass | First run failed only in `web_basic` localhost-socket tests with `PermissionError: [Errno 1] Operation not permitted`; approved rerun with local socket permission passed with `317 passed in 7.27s`. |

## C. API Smoke Rerun

API smoke was executed against local FastAPI services with synthetic fixtures only:

- Runner: `127.0.0.1:19281`
- Backend: `127.0.0.1:19200`
- Data dir: temporary `/tmp/inspectra-release-gate-rerun-data-*`
- Summary file: `/tmp/inspectra-release-gate-rerun-smoke.json`
- Fixtures: `tests/fixtures/demo/passive-alpha/archives/*.zip`

The smoke uploaded four archive fixtures, launched 23 representative passive jobs, waited for completion, fetched `GET /jobs/{job_id}`, and downloaded Markdown, HTML, XML, and PDF exports for every completed job.

| Fixture | Analyzers executed | Jobs launched | Jobs completed | Jobs failed | Exports reviewed | Redaction result | Notes |
| --- | --- | ---: | ---: | ---: | ---: | --- | --- |
| `demo-archive-app-config.zip` | `archive`, `project-archive`, `django-config`, `node-package-config`, `secrets-review` | 5 | 5 | 0 | 20 | Pass | No listed fixture-string leaks detected. |
| `demo-archive-container-infra.zip` | `docker-config`, `compose-config`, `ci-cd-config`, `k8s-config`, `terraform-config`, `nginx-config`, `secrets-review` | 7 | 7 | 0 | 28 | Pass | Prior CI/CD leak no longer observed. |
| `demo-archive-data-layer.zip` | `redis-config`, `sql-database-config`, `database-config`, `secrets-review` | 4 | 4 | 0 | 16 | Pass | Redis and SQL DB report/export surfaces completed through API. |
| `demo-archive-redaction-negative.zip` | `secrets-review`, `redis-config`, `sql-database-config`, `nginx-config`, `compose-config`, `terraform-config`, `ci-cd-config` | 7 | 7 | 0 | 28 | Pass | Prior CI/CD and Nginx leaks no longer observed. |

Smoke totals:

- Fixtures uploaded: `4`
- Jobs launched: `23`
- Jobs completed: `23`
- Failed jobs: `0`
- Exports checked: `92`
- Jobs/surfaces with `[REDACTED]` marker observed where applicable: `20`
- Redaction-negative result: pass

## D. Redaction Negative Rerun

Surfaces checked:

- `GET /jobs/{job_id}`
- Markdown export
- HTML export
- XML export
- PDF export

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

| Analyzer | Fixture coverage | Surfaces checked | Result | Notes |
| --- | --- | --- | --- | --- |
| `ci_cd_config_basic` | `demo-archive-container-infra.zip`, `demo-archive-redaction-negative.zip` | Job JSON, Markdown, HTML, XML, PDF | Pass | `token_should_never_render` and `Authorization: Bearer token_should_never_render` were not observed. |
| `nginx_config_basic` | `demo-archive-container-infra.zip`, `demo-archive-redaction-negative.zip` | Job JSON, Markdown, HTML, XML, PDF | Pass | Prior Nginx redaction-negative leaks were not observed. |
| `redis_config_basic` | `demo-archive-data-layer.zip`, `demo-archive-redaction-negative.zip` | Job JSON, Markdown, HTML, XML, PDF | Pass | Redis no-read/redaction surfaces stayed clean. |
| `sql_database_config_basic` | `demo-archive-data-layer.zip`, `demo-archive-redaction-negative.zip` | Job JSON, Markdown, HTML, XML, PDF | Pass | SQL DB no-read/redaction surfaces stayed clean. |
| `secrets_review_basic` | All four fixtures | Job JSON, Markdown, HTML, XML, PDF | Pass | No listed fixture-string leaks detected. |

No leaks were detected in the API smoke summary.

## E. Browser DOM / Raw JSON Smoke

Real browser DOM and Raw JSON smoke was not completed in this environment.

| Fixture | Analyzers | DOM checked | Raw JSON checked | Result | Notes |
| --- | --- | --- | --- | --- | --- |
| `demo-archive-data-layer.zip` | Redis config, SQL DB config | No | No | Pending | Chrome and Firefox binaries exist, but the repo does not include Playwright/Puppeteer/Selenium and no browser automation harness is available. |
| `demo-archive-redaction-negative.zip` | Secrets review, Redis config, SQL DB config, CI/CD config, Nginx config | No | No | Pending | Manual/browser smoke must be performed before creating the tag. |

Frontend Vitest DOM tests and build passed, including report and Raw JSON tests, but those are not a substitute for the requested real browser/manual smoke. This rerun therefore does not mark the release as ready to tag.

## F. Remaining Blockers

### Release-Blocking

- Real browser/manual DOM and Raw JSON smoke remains pending before tag.
- No release tag should be created until the browser smoke passes and `git status --short` is clean at tag time.

### Demo-Blocking

- Confirm the upload-panel demo note is visible in a real browser session.
- Confirm archive-only actions are absent for non-archive files in a real browser session.
- Confirm Redis/SQL DB `PassiveReportShell`, export controls, and Raw JSON panels in a real browser session.
- Confirm `demo-archive-redaction-negative.zip` fixture strings do not appear in DOM/Raw JSON.

### External-User Blockers

These remain unchanged:

- Authentication and deployment hardening.
- Retention and storage controls.
- Upload cleanup/reset tooling.
- Legal/security disclaimer.
- Clearer onboarding.
- Limits and file-size messaging.
- Real deployment threat model.
- Multi-user isolation and authorization model.

### Non-Blocking Backlog

- Export readability polish.
- Report shell migration for more analyzers.
- Fixture-driven smoke script.
- Demo reset instructions.
- Better report severity/confidence explanations.
- Future analyzers and active/network/Nmap remain post-release or separate product blocks.

## G. Release Notes Draft Update

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

Status note:

```text
API release-gate smoke passed after the CI/CD and Nginx redaction fix. The tag is still not created because real browser DOM and Raw JSON smoke remains pending.
```

Scope and non-scope remain unchanged:

- Local trusted technical alpha.
- Passive review of uploaded files and archives.
- Bounded archive/file parsing.
- No exploitation, active scanning, Nmap, port scanning, credential validation, provider/registry/CVE/advisory lookups, or execution of uploaded projects/workflows/configs.
- Findings are review indicators, not proof of exploitability, compromise, exposure, or credential validity.

Known limitations:

- Heuristic findings can produce false positives and false negatives.
- Some reports still need readability polish.
- `PassiveReportShell` is not yet applied to every analyzer.
- Local uploaded data and results remain on disk until removed.
- Synthetic fixtures demonstrate product behavior, not real-world completeness.
- Browser/manual smoke is still required before tag.

## H. Final Decision

Decision: `READY_FOR_BROWSER_SMOKE_RERUN_BEFORE_TAG`.

Rationale:

- Technical validations passed.
- Full API smoke with four synthetic fixture archives passed.
- Redaction-negative checks passed for job JSON and Markdown/HTML/XML/PDF exports.
- The previous CI/CD and Nginx release-blocking leaks were not reproduced.
- Follow-up real browser DOM and Raw JSON smoke was completed for archive reports and recorded in `docs/future/passive-alpha-manual-browser-smoke-before-tag.md`.
- The non-archive `package.json` manifest sanity blocker has been fixed in `docs/future/passive-alpha-release-gate-manifest-upload-listing-fix.md`.

Do not create `v0.1.0-passive-alpha` yet. The next step is to rerun the full browser smoke and then make a final clean-tree/tag decision.
