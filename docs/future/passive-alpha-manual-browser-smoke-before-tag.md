# Passive Alpha Manual Browser Smoke Before Tag

Status: `SUPERSEDED_BY_PASSING_BROWSER_SMOKE_RERUN`.

Base commit: `c245c60 docs(alpha): rerun passive release gate smoke`

Target tag: `v0.1.0-passive-alpha`

This document records the real browser DOM and Raw JSON smoke attempted before creating the passive alpha tag. It does not create a tag, create a release, add analyzers, add scripts, add fixtures, change runtime behavior, change endpoints, change frontend behavior, change exports, or inspect real secrets.

Follow-up fix: `docs/future/passive-alpha-release-gate-manifest-upload-listing-fix.md`.

Passing rerun: `docs/future/passive-alpha-manual-browser-smoke-rerun-before-tag.md`.

The original smoke decision below remains `BLOCKED_BEFORE_RELEASE_TAG` for this recorded run. The manifest upload/listing blocker has since been fixed and the follow-up rerun has passed.

The follow-up rerun passed real-browser DOM, expanded Raw JSON, export-control, redaction-negative, and non-archive manifest sanity checks. The current release-gate state is `READY_TO_TAG_PASSIVE_ALPHA`, assuming `git status --short` remains clean at tag time. No tag was created in that rerun microphase.

## A. Initial State

| Item | Result | Notes |
| --- | --- | --- |
| Working tree | Pass | `git status --short` was clean before the smoke. |
| HEAD | Pass | `c245c60 docs(alpha): rerun passive release gate smoke`. |
| Previous release gate | Recorded | `docs/future/passive-alpha-release-gate-smoke-rerun.md`. |
| Target tag | Recorded | `v0.1.0-passive-alpha`. |
| Tag created | No | This microphase explicitly does not create the tag. |

## B. Browser Environment

Real browser smoke was executed with local services and Google Chrome headless through the Chrome DevTools Protocol:

- Runner: `127.0.0.1:19381`
- Backend: `127.0.0.1:19300`
- Frontend: `http://localhost:5173`
- Frontend API base: `http://127.0.0.1:19300`
- Browser: `google-chrome --headless=new`
- Chrome DevTools: `127.0.0.1:19333`
- Temporary data dirs: `/tmp/inspectra-browser-smoke-data-*`
- Temporary logs: `/tmp/inspectra-browser-smoke-{runner,backend,frontend,chrome}.log`
- Temporary result summary: `/tmp/inspectra-manual-browser-smoke-result.json`

The smoke first attempted `127.0.0.1` frontend origins on alternate ports. Chrome rendered `Failed to fetch` even though the backend returned `200`, because the backend CORS allow-list permits `http://localhost:5173` by default. The successful browser pass used `http://localhost:5173`.

## C. Fixtures

Synthetic fixtures only:

- `tests/fixtures/demo/passive-alpha/archives/demo-archive-data-layer.zip`
- `tests/fixtures/demo/passive-alpha/archives/demo-archive-redaction-negative.zip`
- `tests/fixtures/demo/passive-alpha/sources/demo-file-basic/manifest/package.json`

No real secrets, production archives, `.env` files outside the fixture set, external services, provider APIs, scanners, package managers, Redis/Sentinel clients, SQL clients, Nginx, Docker, or workflows were executed.

## D. Browser DOM Smoke Results

The browser verified the local alpha demo note:

- `Local alpha demo: use the synthetic fixtures under tests/fixtures/demo/passive-alpha/ ...`
- `Results, exports, and Raw JSON are redacted with [REDACTED] ...`

Archive uploads required clicking `Refresh data` after upload before rows appeared. The DOM showed an upload error string after the file submit path:

```text
Cannot read properties of null (reading 'reset')
```

With manual refresh, the two archive fixtures appeared in the file table and archive-only actions were available.

## E. Archive Jobs Reviewed In Browser

The following jobs were launched from archive action buttons in the real browser UI, completed, opened from the jobs table, and reviewed in DOM with Raw JSON expanded:

| Fixture | Action | Audit type | Result |
| --- | --- | --- | --- |
| `demo-archive-data-layer.zip` | `Analyze Redis config` | `redis_config_basic` | Pass |
| `demo-archive-data-layer.zip` | `Analyze SQL DB config` | `sql_database_config_basic` | Pass |
| `demo-archive-redaction-negative.zip` | `Analyze secrets review` | `secrets_review_basic` | Pass |
| `demo-archive-redaction-negative.zip` | `Analyze Redis config` | `redis_config_basic` | Pass |
| `demo-archive-redaction-negative.zip` | `Analyze SQL DB config` | `sql_database_config_basic` | Pass |
| `demo-archive-redaction-negative.zip` | `Analyze CI/CD config` | `ci_cd_config_basic` | Pass |
| `demo-archive-redaction-negative.zip` | `Analyze Nginx config` | `nginx_config_basic` | Pass |

For each completed archive job, the browser smoke verified:

- report opened from the real jobs table;
- Raw JSON section was visible/expanded;
- `[REDACTED]` appeared where applicable;
- `Export Markdown`, `Export HTML`, `Export XML`, and `Export PDF` controls were visible;
- report-specific sections were visible for Redis, SQL DB, CI/CD, and Nginx;
- no checked fixture secret string appeared in visible DOM or expanded Raw JSON.

## F. Redaction Checks

The browser DOM and expanded Raw JSON were checked for these fixture strings:

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

Result for the seven completed archive jobs: pass. No listed fixture string was observed in the report DOM or expanded Raw JSON.

This confirms the prior API/export redaction rerun remains consistent for the archive reports checked in the browser. It does not sanitize uploaded originals and does not replace the previous API export smoke.

## G. Non-Archive Sanity Blocker

The required non-archive sanity check did not pass.

Attempted check:

- upload `tests/fixtures/demo/passive-alpha/sources/demo-file-basic/manifest/package.json` as `Manifest`;
- verify a non-archive row appears;
- verify it exposes `Analyze manifest`;
- verify archive-only actions such as `Analyze Redis config`, `Analyze SQL DB config`, `Analyze secrets review`, `Analyze CI/CD config`, and `Analyze Nginx config` are absent.

Observed result:

- browser DOM still showed the upload error `Cannot read properties of null (reading 'reset')`;
- the smoke timed out waiting for the uploaded `package.json`;
- backend `/files` returned `500 Internal Server Error` after the manifest upload;
- therefore the browser could not complete the non-archive archive-only-action negative check.

Because this is a real release-gate check and not just a harness expectation, it blocks the alpha tag. No runtime fix was made in this docs-only microphase.

## H. Scope And Safety Confirmed

The smoke did not:

- create a tag or release;
- add scripts or fixtures to the repo;
- change backend, runner, frontend, reports, exports, findings, or redaction logic;
- execute uploaded projects or workflows;
- run Redis/Sentinel, SQL clients, Nginx, Docker, Terraform, Kubernetes, package managers, or CI systems;
- call external networks, provider APIs, registries, CVEs, or advisories;
- validate credentials or claim exploitability.

Findings remain heuristic review indicators.

## I. Final Decision

Decision: `BLOCKED_BEFORE_RELEASE_TAG`.

Rationale:

- Real browser DOM and expanded Raw JSON checks passed for seven archive jobs across Redis, SQL DB, Secrets review, CI/CD, and Nginx.
- Export controls were visible for those completed browser-opened reports.
- No listed fixture-string leaks were observed in browser DOM or expanded Raw JSON for those archive reports.
- The required non-archive sanity check failed because uploading `package.json` as a manifest left the UI in an upload error state and caused backend `/files` to return `500`.

Do not create `v0.1.0-passive-alpha` yet. The manifest upload/listing path has been fixed in `docs/future/passive-alpha-release-gate-manifest-upload-listing-fix.md`; the next required work is a full browser smoke rerun and final clean-tree tag decision.

## J. Validation Commands

Docs-only validations for this recording:

```bash
git status --short
git diff --check
git diff --cached --check
```

No pytest/npm suite was required for the documentation commit. The browser smoke itself was executed with local services and Chrome headless as described above.
