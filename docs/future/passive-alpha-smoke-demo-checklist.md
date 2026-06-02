# Passive Alpha Smoke Demo Checklist

Status: docs-only smoke checklist for the existing synthetic fixture pack.

Base commit: `9038ab9 test(fixtures): add passive alpha synthetic demo pack`

Fixture root:

```text
tests/fixtures/demo/passive-alpha/
```

This checklist validates and demonstrates Inspectra Passive technical alpha with local synthetic fixtures. It does not add fixtures, scripts, analyzers, runtime behavior, tests, backend, runner, frontend, or export changes.

## 1. Objective

Use the synthetic fixture pack to validate and present:

- Uploads of local fixtures.
- Archive-only grouped actions.
- Job creation and status transitions.
- Dashboard filters and labels.
- Report sections.
- Markdown/HTML/XML/PDF exports through existing controls.
- Redacted Raw JSON.
- No-read sensitive adjacent files.
- Not-resolved includes/references.
- Redaction of fake secret strings.

This smoke does not demonstrate:

- Exploitation.
- Credential validity.
- Live reachability.
- Active scanning.
- Runtime execution.
- CVE/advisory truth.
- Complete coverage.
- Sanitization of original uploaded fixtures.

## 2. Preconditions

Before running the smoke:

1. Confirm `git status --short` is clean.
2. Start the local Inspectra app.
3. Confirm the backend is reachable.
4. Confirm the frontend is reachable.
5. Use only fixtures under `tests/fixtures/demo/passive-alpha/`.
6. Do not use real data.
7. Do not upload real secrets.
8. Do not execute tools from fixture contents.
9. Do not contact live services for archive config checks.

The `.env`, dump, ACL, state, private key, and credential-looking files inside `tests/fixtures/demo/passive-alpha/` are synthetic fixtures and may be inspected as part of this smoke. Do not inspect or upload real `.env` files outside the fixture root.

## 3. Fixture Inventory

Archive fixtures:

- `tests/fixtures/demo/passive-alpha/archives/demo-archive-app-config.zip`
- `tests/fixtures/demo/passive-alpha/archives/demo-archive-container-infra.zip`
- `tests/fixtures/demo/passive-alpha/archives/demo-archive-data-layer.zip`
- `tests/fixtures/demo/passive-alpha/archives/demo-archive-redaction-negative.zip`

Source fixture folders:

- `tests/fixtures/demo/passive-alpha/sources/demo-file-basic/`
- `tests/fixtures/demo/passive-alpha/sources/demo-archive-app-config/`
- `tests/fixtures/demo/passive-alpha/sources/demo-archive-container-infra/`
- `tests/fixtures/demo/passive-alpha/sources/demo-archive-data-layer/`
- `tests/fixtures/demo/passive-alpha/sources/demo-archive-redaction-negative/`

Fixture README:

- `tests/fixtures/demo/passive-alpha/README.md`

## 4. Technical Smoke Before Demo

Recommended commands:

```bash
git status --short
python3 -m compileall backend tools
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools
.venv/bin/python -m pytest backend/tests/test_backend.py
.venv/bin/python -m pytest tools/tests/test_runner.py -k "not web_basic"
npm run test -- --run
npm run build
git diff --check
```

Optional broader Python suite:

```bash
.venv/bin/python -m pytest
```

If the full Python suite fails in a sandbox because `web_basic` creates local sockets, document that as an environment condition and rerun with appropriate permissions. Do not reinterpret a sandbox socket failure as an Inspectra product failure.

## 5. Manual UI Smoke: App Config Archive

Fixture:

```text
tests/fixtures/demo/passive-alpha/archives/demo-archive-app-config.zip
```

Steps:

1. Upload the archive.
2. Confirm the uploaded file is registered as `kind: "archive"`.
3. Confirm grouped archive actions appear.
4. Run:
   - Analyze archive.
   - Analyze project manifests.
   - Analyze secrets review.
   - Analyze Django config.
   - Analyze Node package config.
5. Confirm jobs complete or fail in a controlled state.
6. Open each report.
7. Confirm expected sections:
   - Archive structure.
   - Project manifests.
   - Django config.
   - Node package config.
   - Secrets/redaction.
   - Limits/errors where present.
   - Raw JSON.
8. Export at least one representative report through existing UI export controls.
9. Confirm fake token and password-like strings do not appear in rendered results.

Expected review themes:

- Broad/sample Django settings.
- Secret-like Django and environment-template values.
- Node package script/config indicators.
- Package-manager token redaction.
- `.env` detected/not-read where applicable.

## 6. Manual UI Smoke: Container / Infra Archive

Fixture:

```text
tests/fixtures/demo/passive-alpha/archives/demo-archive-container-infra.zip
```

Steps:

1. Upload the archive.
2. Confirm `kind: "archive"`.
3. Run:
   - Analyze Docker config.
   - Analyze Compose config.
   - Analyze CI/CD config.
   - Analyze Kubernetes config.
   - Analyze Terraform config.
   - Analyze Nginx config.
   - Analyze secrets review.
4. Confirm jobs complete or fail in a controlled state.
5. Open representative reports.
6. Confirm expected sections:
   - Docker/Compose.
   - Workflows.
   - Kubernetes manifests.
   - Terraform resources/state file presence.
   - Nginx server/location/includes.
   - Secrets/redaction.
7. Confirm not-resolved checks:
   - Nginx includes are detected but not resolved.
   - CI/CD remote-looking references are not executed or downloaded.
   - Terraform state is detected but not read.
8. Export at least one infrastructure report and one web-edge or container report through existing UI export controls.

Expected review themes:

- Docker/Compose ports, volumes, images, privileged/service wiring.
- CI/CD permissions/triggers/self-hosted/deploy indicators.
- Kubernetes workload/security/RBAC/service indicators.
- Terraform provider/backend/module/resource and state-file indicators.
- Nginx proxy/header/include indicators.
- Fake credential values redacted.

## 7. Manual UI Smoke: Data Layer Archive

Fixture:

```text
tests/fixtures/demo/passive-alpha/archives/demo-archive-data-layer.zip
```

Steps:

1. Upload the archive.
2. Confirm `kind: "archive"`.
3. Run:
   - Analyze Redis config.
   - Analyze SQL DB config.
   - Analyze database config.
   - Analyze secrets review.
4. Confirm jobs complete or fail in a controlled state.
5. Open Redis and SQL DB reports.
6. Confirm `PassiveReportShell` is visible for Redis/SQL DB reports:
   - `Passive review` badge.
   - Passive scope copy.
   - Redaction copy.
   - Redacted Raw JSON.
7. Confirm Redis/Sentinel sections.
8. Confirm PostgreSQL/pg_hba/MySQL/MariaDB sections.
9. Confirm no-read entries:
   - `.env`.
   - ACL.
   - RDB.
   - AOF.
   - appendonly files.
   - dumps/backups.
   - `.pgpass`.
   - WAL/binlog/InnoDB markers.
10. Confirm includes are detected/not-resolved where applicable.
11. Confirm `[REDACTED]` appears where secret-like values are reported.
12. Export Redis and SQL DB reports through existing UI export controls if available.

Expected review themes:

- Redis bind/auth/TLS/persistence/replication/Sentinel indicators.
- Redis include directives detected/not-resolved.
- SQL database listen/auth/TLS/logging/backup/include indicators.
- Credential/dump/data files detected/not-read.
- Fake DB/Redis URLs and passwords redacted.

## 8. Manual UI Smoke: Redaction Negative Archive

Fixture:

```text
tests/fixtures/demo/passive-alpha/archives/demo-archive-redaction-negative.zip
```

Steps:

1. Upload the archive.
2. Confirm `kind: "archive"`.
3. Run redaction-heavy analyzers:
   - Analyze secrets review.
   - Analyze Redis config.
   - Analyze SQL DB config.
   - Analyze Docker config.
   - Analyze Compose config.
   - Analyze Terraform config.
   - Analyze Nginx config.
   - Analyze CI/CD config.
4. Open completed reports.
5. Open Redacted Raw JSON.
6. Export representative reports through existing UI export controls.
7. Run the redaction negative checklist below.
8. Confirm `[REDACTED]` appears where applicable.

Expected review themes:

- Legacy-like fake secrets in findings/evidence/errors are redacted.
- Private key marker text is not preserved in result surfaces.
- Credential URLs are redacted.
- The original uploaded fixture archive may still contain fake strings.

## 9. Redaction Negative Checklist

The following fake strings must not appear after analysis:

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

Check these surfaces:

- DOM text.
- Redacted Raw JSON.
- `GET /jobs/{job_id}`.
- Markdown export.
- HTML export.
- XML export.
- PDF export.
- Controlled errors.

Expected positive check:

- `[REDACTED]` appears in results where redaction applies.

Important: these strings are intentionally present in fixture source files and archives. The check is for Inspectra result surfaces, not the original fixtures.

## 10. API / Export Smoke

Generic API/export steps:

1. Get a job id from the UI jobs list or `GET /jobs`.
2. Call `GET /jobs/{job_id}`.
3. Search the response text for the fake secret strings in the redaction checklist.
4. Confirm `[REDACTED]` appears where applicable.
5. Export representative reports with existing UI export controls.
6. Search exported Markdown, HTML, XML, and PDF outputs for the fake secret strings.
7. Confirm exported reports frame findings as heuristic review indicators.

Use existing UI export controls rather than inventing endpoint paths in this checklist.

## 11. Expected Results Matrix

| Fixture | Analyzers | Expected report sections | Expected no-read/not-resolved checks | Expected redaction checks | Exports to try | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `demo-archive-app-config.zip` | Archive, project manifests, secrets review, Django config, Node package config | Archive structure, internal manifests, Django settings, package overview, scripts/dependencies, secrets findings, limits/errors, Raw JSON | `.env` detected/not-read where applicable | `.npmrc`, `.env.example`, Django secret-like values, DB URL, token strings redacted | At least one app-config report | Best first archive for dashboard action grouping. |
| `demo-archive-container-infra.zip` | Docker, Compose, CI/CD, Kubernetes, Terraform, Nginx, secrets review | Docker/Compose, workflows, Kubernetes manifests, Terraform providers/resources/state files, Nginx servers/locations/includes, findings, Raw JSON | Terraform state detected/not-read; Nginx includes detected/not-resolved; workflow references not executed | CI token, Terraform credentials, proxy credential URL, private-looking strings redacted | One infra report and one web-edge/container report | Demonstrates breadth without live validation. |
| `demo-archive-data-layer.zip` | Redis, SQL DB, Database, secrets review | Redis/Sentinel, PostgreSQL, pg_hba, MySQL/MariaDB, no-read files, includes, redaction notes, Raw JSON | ACL/RDB/AOF/appendonly/dumps/backups/WAL/binlog/InnoDB/credential files detected/not-read; includes not resolved | Redis URL, DB URLs, password-like values, dump/pgpass/mycnf/ACL strings redacted | Redis and SQL DB reports | Best pack for PassiveReportShell, no-read, and data-layer redaction. |
| `demo-archive-redaction-negative.zip` | Secrets review, Redis, SQL DB, Docker, Compose, Terraform, Nginx, CI/CD | Findings, evidence, redaction notes, errors, Raw JSON | `.env`, ACL, dump/private-key/state/data-like files detected/not-read where applicable | All checklist strings absent from result surfaces; `[REDACTED]` present | At least two redaction-heavy reports | Negative check pack, not a product capability expansion. |
| `sources/demo-file-basic/` | PDF/image/manifest only when individual files are uploaded | Manifest/package summary and file metadata if supported | None expected | No fake secrets expected | File report exports if available | Source-only pack; no PDF/image binary in this microphase. |

## 12. Demo Narrative

Short presentation script:

1. "Inspectra Passive reviews local uploads."
2. "Archive config analyzers are bounded and do not execute tools."
3. "Actions are grouped by surface so users can choose the right passive review."
4. "Findings are review indicators that require human validation."
5. "Sensitive-looking values are redacted in results, exports, and Raw JSON."
6. "Original uploaded fixtures may still contain fake secrets."
7. "This is a technical alpha focused on passive breadth, redaction posture, and report UX, not active exploitation."

Avoid saying:

- "This proves exploitability."
- "These credentials are valid."
- "This service is reachable."
- "No findings means it is safe."
- "The uploaded archive was sanitized."
- "Inspectra validates live infrastructure."

## 13. Failure Handling

If a job fails:

- Treat it as a controlled smoke state unless logs show otherwise.
- Open the report and review the Errors section.
- Confirm uploaded fixture content was not executed.
- Record the analyzer, fixture, job id, status, and controlled error text.
- Do not describe the failure as dangerous execution.

If a job is truncated:

- Confirm the truncation message is visible.
- Confirm report sections remain readable.
- Confirm redaction checks still pass.

If an analyzer reports no findings:

- Do not call the fixture safe or secure.
- Record "no heuristic findings reported" as a smoke result.
- Confirm the report still shows scope, summary, raw JSON, and empty states clearly.

If a fixture source file changes:

- Regenerate the matching zip archive.
- Re-run the relevant smoke path.
- Re-run the redaction negative checklist.

## 14. Regenerating Archives

Regeneration commands live in:

```text
tests/fixtures/demo/passive-alpha/README.md
```

Use the commands there to rebuild the four zip archives from their source folders. Do not add a generation script in this checklist phase.

## 15. No-Scope For This Smoke

Do not:

- Use real data.
- Use real secrets.
- Use real private keys.
- Use third-party projects without permission.
- Add analyzers.
- Add runtime tests.
- Add scripts.
- Modify backend, runner, frontend, job contracts, exports, findings, or severities.
- Execute Docker, Docker Compose, Terraform, Nginx, Kubernetes, Redis, SQL database clients/servers, package managers, CI workflows, or project code from fixture content.
- Contact live services for archive config checks.
- Query providers, registries, CVEs, advisories, cloud APIs, Docker Hub, package registries, CI providers, Kubernetes APIs, Redis, or databases for passive config smoke.
- Claim exploitability, credential validity, complete coverage, or a clean verdict.

## 16. Next Step

Recommended next microphase:

`PASSIVE-ALPHA-SMOKE-DEMO-FIXTURES-04-OPTIONAL-FRONTEND-DEMO-NOTES`

Alternative if the product wants final readiness packaging first:

`PASSIVE-ALPHA-SMOKE-DEMO-FIXTURES-05-ALPHA-PACKAGING-READINESS`
