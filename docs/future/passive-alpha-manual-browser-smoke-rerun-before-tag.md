# Passive Alpha Manual Browser Smoke Rerun Before Tag

Status: `READY_TO_TAG_PASSIVE_ALPHA`.

Base commit: `a20af37 fix(ui): stabilize manifest upload listing before passive tag`

Target tag: `v0.1.0-passive-alpha`

This document records the final real-browser DOM and Raw JSON smoke rerun after the manifest upload/listing fix. It does not create a tag, create a release, add analyzers, add scripts, add fixtures, change runtime behavior, change endpoints, change frontend behavior, change exports, or inspect real secrets.

## A. Initial State

| Item | Result | Notes |
| --- | --- | --- |
| Working tree | Pass | `git status --short` was clean before the smoke. |
| HEAD | Pass | `a20af37 fix(ui): stabilize manifest upload listing before passive tag`. |
| Prior browser blocker | Fixed | Recorded in `docs/future/passive-alpha-release-gate-manifest-upload-listing-fix.md`. |
| Target tag | Recorded | `v0.1.0-passive-alpha`. |
| Tag created | No | This microphase explicitly does not create the tag. |
| Release created | No | This microphase explicitly does not create a release. |

## B. Browser Environment

Real browser smoke was executed with local services and Google Chrome headless through the Chrome DevTools Protocol:

- Runner: `127.0.0.1:19381`
- Backend: `127.0.0.1:19300`
- Frontend: `http://localhost:5173`
- Frontend API base: `http://127.0.0.1:19300`
- Browser: `google-chrome --headless=new`
- Chrome DevTools: `127.0.0.1:19333`
- Temporary data dir: `/tmp/inspectra-browser-smoke-rerun-data-k5uzivdt`
- Temporary Chrome user-data dir: `/tmp/inspectra-browser-smoke-rerun-chrome-ptdk9z7e`
- Temporary logs:
  - `/tmp/inspectra-browser-smoke-rerun-runner.log`
  - `/tmp/inspectra-browser-smoke-rerun-backend.log`
  - `/tmp/inspectra-browser-smoke-rerun-frontend.log`
  - `/tmp/inspectra-browser-smoke-rerun-chrome.log`
- Temporary result summary: `/tmp/inspectra-manual-browser-smoke-rerun-before-tag.json`

Two harness setup attempts failed before product checks:

- Chrome CDP rejected the WebSocket without `--remote-allow-origins=*`.
- The harness initially connected to the browser target instead of the page target.

The final rerun used the page target and completed successfully. These were smoke harness issues, not Inspectra product blockers.

## C. Fixtures

Synthetic fixtures only:

- `tests/fixtures/demo/passive-alpha/archives/demo-archive-data-layer.zip`
- `tests/fixtures/demo/passive-alpha/archives/demo-archive-redaction-negative.zip`
- `tests/fixtures/demo/passive-alpha/sources/demo-file-basic/manifest/package.json`

No real secrets, production archives, `.env` files outside the fixture set, external services, provider APIs, scanners, package managers, Redis/Sentinel clients, SQL clients, Nginx, Docker, Terraform, Kubernetes, or workflows were executed.

## D. Demo Note

The browser verified the upload-panel local alpha demo note:

- It references `tests/fixtures/demo/passive-alpha/`.
- It warns not to upload real secrets or production archives.
- It states results, exports, and Raw JSON are redacted with `[REDACTED]`.
- It states this does not sanitize the original uploaded file.

Result: pass.

## E. Data Layer Archive

Uploaded fixture:

```text
tests/fixtures/demo/passive-alpha/archives/demo-archive-data-layer.zip
```

The browser verified:

- file row appeared as `kind: archive`;
- grouped archive actions were visible;
- Data layer actions were visible:
  - `Analyze Redis config`
  - `Analyze SQL DB config`
  - `Analyze database config`

Executed jobs:

| Job ID | Audit type | Status | DOM / Raw JSON | Export controls |
| --- | --- | --- | --- | --- |
| `1e738c46b8ef45349139ee12d87a353a` | `redis_config_basic` | completed | Pass | Markdown/HTML/XML/PDF visible |
| `d62be1d05f6c41009add3143efbbb606` | `sql_database_config_basic` | completed | Pass | Markdown/HTML/XML/PDF visible |

Redis report checks passed:

- `Passive review` badge visible.
- Passive scope copy visible.
- Redaction copy visible.
- Redis and Sentinel sections visible.
- ACL / Dumps / AOF / Backups no-read section visible.
- Redacted Raw JSON visible and expanded.
- `[REDACTED]` visible where applicable.

SQL DB report checks passed:

- `Passive review` badge visible.
- Passive scope copy visible.
- Redaction copy visible.
- PostgreSQL, pg_hba.conf, MySQL, and MariaDB sections visible.
- Sensitive files, dumps/backups, and data/WAL/binlog/InnoDB no-read sections visible.
- Redacted Raw JSON visible and expanded.
- `[REDACTED]` visible where applicable.

## F. Redaction Negative Archive

Uploaded fixture:

```text
tests/fixtures/demo/passive-alpha/archives/demo-archive-redaction-negative.zip
```

The browser verified:

- file row appeared as `kind: archive`;
- representative archive actions were visible;
- all launched jobs completed;
- reports opened from the real jobs table;
- Raw JSON was visible or expanded where present;
- `[REDACTED]` appeared where applicable;
- export controls were visible in every reviewed report.

Executed jobs:

| Job ID | Audit type | Status | DOM / Raw JSON | Export controls |
| --- | --- | --- | --- | --- |
| `3b56f3ef12e2480bb242108c7fa0f2b9` | `secrets_review_basic` | completed | Pass | Markdown/HTML/XML/PDF visible |
| `32b1877ee6a940e0814ee6683a874387` | `redis_config_basic` | completed | Pass | Markdown/HTML/XML/PDF visible |
| `1ac6f85f00fa40518ccb487c377f0962` | `sql_database_config_basic` | completed | Pass | Markdown/HTML/XML/PDF visible |
| `f91b37f865ac482f90d3c0d565e40dfe` | `ci_cd_config_basic` | completed | Pass | Markdown/HTML/XML/PDF visible |
| `a44914823b9e41bb88ed8961eca55226` | `nginx_config_basic` | completed | Pass | Markdown/HTML/XML/PDF visible |

Representative report sections verified:

- Secrets review: sensitive files detected but not read, findings, files detected/reviewed, Raw JSON.
- Redis: Redis settings, Sentinel settings, includes, ACL/dumps/AOF/backups no-read, Redacted Raw JSON.
- SQL DB: PostgreSQL configs, pg_hba.conf rules, MySQL/MariaDB configs, no-read data sections, Redacted Raw JSON.
- CI/CD: workflow overview, triggers, jobs/steps, actions/images, Raw JSON.
- Nginx: server blocks, locations, includes, findings, Raw JSON.

## G. Redaction Checks

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

Result: pass.

No listed fixture string was observed in:

- browser DOM;
- expanded report Raw JSON;
- fetched job JSON for reviewed jobs.

`[REDACTED]` was observed in reports where redaction applies.

## H. Non-Archive Manifest Sanity

Uploaded fixture:

```text
tests/fixtures/demo/passive-alpha/sources/demo-file-basic/manifest/package.json
```

The browser and backend verified:

- no `.reset` error appeared;
- backend `GET /files` returned `200`;
- row `package.json` was visible;
- row displayed `kind: manifest`;
- `Analyze manifest` was visible;
- `Run all recommended passive checks` was absent.

Archive-only actions were absent from the manifest row:

- `Analyze Redis config`
- `Analyze SQL DB config`
- `Analyze secrets review`
- `Analyze CI/CD config`
- `Analyze Nginx config`
- `Analyze Docker config`
- `Analyze Kubernetes config`
- `Analyze Terraform config`

Result: pass.

## I. Scope And Safety Confirmed

The smoke did not:

- create a tag or release;
- add scripts or fixtures to the repo;
- change backend, runner, frontend, reports, exports, findings, or redaction logic;
- execute uploaded projects or workflows;
- run Redis/Sentinel, SQL clients, Nginx, Docker, Terraform, Kubernetes, package managers, or CI systems;
- call external networks, provider APIs, registries, CVEs, or advisories;
- validate credentials or claim exploitability.

Findings remain heuristic review indicators.

## J. Final Decision

Decision: `READY_TO_TAG_PASSIVE_ALPHA`.

Rationale:

- Real browser DOM and expanded Raw JSON checks passed for seven archive jobs across Redis, SQL DB, Secrets review, CI/CD, and Nginx.
- Export controls were visible for every completed browser-opened report.
- No listed fixture-string leaks were observed in browser DOM, expanded Raw JSON, or reviewed job JSON.
- The required non-archive `package.json` manifest sanity check passed after the manifest upload/listing fix.
- `GET /files` returned `200` after the manifest upload.
- No new blockers were found.
- No tag or release was created in this microphase.

The next microphase may prepare release notes and create `v0.1.0-passive-alpha`, provided `git status --short` is clean at tag time.

## K. Validation Commands

Technical validation commands for this docs/smoke recording:

```bash
git status --short
git log --oneline -12
git diff --check
git diff --cached --check
```

The browser smoke itself was executed with local services and Chrome headless as described above.
