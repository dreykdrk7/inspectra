# Passive Alpha Smoke Demo Fixtures Design

Status: docs-first design. This document does not create fixtures, change runtime behavior, add analyzers, or touch backend, runner, frontend, jobs, exports, or tests.

Base commit: `da3cc69 feat(ui): standardize passive scope and redaction copy`

Inspectra Passive technical alpha is closed for module expansion. The next work is a small, repeatable, synthetic smoke/demo fixture pack that shows the existing passive suite clearly and safely.

## 1. Objective

Design a local fixture and demo plan for Inspectra Passive technical alpha.

The demo pack should demonstrate:

- Local file and archive uploads.
- Archive-only passive config actions.
- Dashboard labels, categories, filters, grouped actions, and job states.
- Representative passive report sections across app config, containers, infrastructure, web edge, data layer, and secrets.
- Redaction in UI, Raw JSON, API responses, and exports.
- No-read behavior for sensitive adjacent files.
- Not-resolved behavior for includes and references.
- Findings as heuristic review indicators that require human validation.

The demo pack should not demonstrate:

- Exploitation.
- Active scanning.
- Live infrastructure validation.
- Credential validation.
- CVE/advisory lookup.
- External service contact for archive config checks.
- Runtime execution of Docker, Compose, Terraform, Nginx, Kubernetes, Redis, SQL databases, package managers, CI workflows, or uploaded project code.
- Sanitization of original uploaded archives.
- Complete coverage guarantees.

## 2. Fixture Principles

All future fixtures should be:

- Synthetic.
- Small.
- Reproducible.
- Local-only.
- Redaction-friendly.
- Intentionally fake.
- Easy to inspect manually.
- Safe to keep in a public repository.

Fixtures must not contain:

- Real secrets.
- Real private keys.
- Real credentials.
- Real customer data.
- Real sensitive domains.
- Operational tokens.
- Production dumps.
- Private source code from third parties.
- Material that looks usable against a real service.

Use obviously fake strings for negative redaction checks:

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

Use `example.com`, `example.test`, `localhost`, or clearly fake service names for hostnames. Avoid real organizations, real cloud accounts, real registries with credentials, and anything that could be mistaken for live infrastructure.

## 3. Proposed Fixture Root

Proposed future location:

```text
tests/fixtures/demo/passive-alpha/
```

This path is intentionally not created in this microphase. It keeps alpha demo assets separate from unit-test fixtures and makes later smoke scripts easier to document.

If the repository later adopts another convention, keep these principles:

- A single root for demo fixtures.
- One README inside the fixture root.
- One small archive per smoke story.
- No generated runtime output committed.
- No real `.env` content beyond synthetic no-read sentinel strings.

## 4. Proposed Fixture Packs

### A. `demo-file-basic/`

Purpose: demonstrate file-based analyzers.

Proposed contents:

- A tiny synthetic PDF if the existing test tooling supports generating or storing one safely.
- A tiny synthetic PNG or JPEG.
- A basic dependency manifest such as `package.json` or `requirements.txt`.

Expected analyzers:

- `pdf_basic`
- `image_basic`
- `manifest_basic`

Notes:

- The PDF/image should be benign and synthetic.
- The manifest should avoid real dependency claims beyond common fake/sample packages.
- This pack does not need archive config findings.

### B. `demo-archive-app-config.zip`

Purpose: demonstrate app config plus secrets review.

Proposed contents:

```text
django_project/settings.py
django_project/settings_prod.py
package.json
package-lock.json
.npmrc
.env.example
.env
README.md
```

Synthetic signals:

- Django settings with review indicators such as broad hosts, HTTPS/cookie posture, or deployment hints.
- Node package scripts and package-manager config hints.
- `.env.example` with fake secret-like values that should be redacted when read as a template.
- `.env` present as sensitive/no-read where applicable.
- `.npmrc` token-like fixture values redacted.

Expected analyzers:

- `archive_basic`
- `project_archive_basic`
- `django_config_basic`
- `node_package_config_basic`
- `secrets_review_basic`

### C. `demo-archive-container-infra.zip`

Purpose: demonstrate container, infrastructure, workflow, and web-edge breadth.

Proposed contents:

```text
Dockerfile
docker-compose.yml
.github/workflows/deploy.yml
k8s/deployment.yaml
k8s/service.yaml
terraform/main.tf
terraform/variables.tf
terraform/terraform.tfstate
nginx/conf.d/default.conf
```

Synthetic signals:

- Dockerfile image/user and Compose service wiring signals.
- CI/CD triggers, permissions, actions/images, publish/deploy review indicators.
- Kubernetes workload, service, RBAC, and secret/config references.
- Terraform provider/backend/module/resource and state-file presence signals.
- Nginx TLS/header/proxy/include signals.

Expected analyzers:

- `archive_basic`
- `docker_config_basic`
- `compose_config_basic`
- `ci_cd_config_basic`
- `k8s_config_basic`
- `terraform_config_basic`
- `nginx_config_basic`
- `secrets_review_basic`

Important:

- `terraform.tfstate` should be detected but not read.
- Nginx includes should be detected but not resolved.
- Kubernetes Helm/Kustomize context, if present, should be detected but not rendered or built.

### D. `demo-archive-data-layer.zip`

Purpose: demonstrate Redis, SQL database, data-layer no-read, and redaction posture.

Proposed contents:

```text
redis/redis.conf
redis/sentinel.conf
redis/users.acl
redis/dump.rdb
redis/appendonly.aof
postgres/postgresql.conf
postgres/pg_hba.conf
postgres/.pgpass
postgres/pg_wal/000000010000000000000001
mysql/my.cnf
mariadb/mariadb.cnf
backups/dump.sql
mysql/ibdata1
.env
```

Synthetic signals:

- Redis bind/protected-mode/auth/TLS/persistence/replication/Sentinel indicators.
- Redis include directives as detected/not-resolved.
- Redis ACL/RDB/AOF/appendonly/backup entries as detected/not-read.
- PostgreSQL listen, pg_hba, TLS/logging/backup/replication indicators.
- MySQL/MariaDB bind/auth/TLS/logging/backup indicators.
- SQL dumps, WAL, binlog/InnoDB/data files, hidden credential files, and `.env` entries as detected/not-read.

Expected analyzers:

- `redis_config_basic`
- `database_config_basic`
- `sql_database_config_basic`
- `secrets_review_basic`
- `archive_basic`

### E. `demo-archive-redaction-negative.zip`

Purpose: prove fixture-secret strings do not appear in rendered outputs.

Proposed contents:

```text
app/.env.example
config/settings.yml
redis/redis.conf
postgres/postgresql.conf
mysql/my.cnf
nginx/conf.d/default.conf
compose.yml
terraform/main.tf
.github/workflows/deploy.yml
dump.sql
users.acl
```

Synthetic secret placements:

- Database URL with fake credentials.
- Redis URL with fake password.
- Fake token.
- Fake private key marker.
- Fake dump row secret.
- Fake pgpass/mycnf/ACL-like strings.
- Authorization header fixture.
- Credential-bearing proxy or registry URL.

Expected analyzers:

- `secrets_review_basic`
- `django_config_basic` if app settings are included.
- `docker_config_basic`
- `compose_config_basic`
- `ci_cd_config_basic`
- `terraform_config_basic`
- `nginx_config_basic`
- `redis_config_basic`
- `database_config_basic`
- `sql_database_config_basic`

Expected result:

- `[REDACTED]` appears where applicable.
- The fixture secret strings do not appear in UI, Raw JSON, API responses, exports, or controlled errors.

## 5. Manual Smoke Script

Suggested local demo sequence:

1. Confirm the working tree is clean.
2. Start Inspectra locally.
3. Open the frontend.
4. Upload a simple synthetic file from `demo-file-basic/`.
5. Run one file-based analyzer and open the report.
6. Upload `demo-archive-app-config.zip`.
7. Confirm the uploaded source is `kind: "archive"`.
8. Confirm grouped archive actions appear.
9. Run:
   - Analyze archive.
   - Analyze project manifests.
   - Analyze secrets review.
   - Analyze Django config.
   - Analyze Node package config.
10. Upload `demo-archive-container-infra.zip`.
11. Run:
   - Analyze Docker config.
   - Analyze Compose config.
   - Analyze CI/CD config.
   - Analyze Kubernetes config.
   - Analyze Terraform config.
   - Analyze Nginx config.
12. Upload `demo-archive-data-layer.zip`.
13. Run:
   - Analyze Redis config.
   - Analyze SQL DB config.
   - Analyze database config.
   - Analyze secrets review.
14. Upload `demo-archive-redaction-negative.zip`.
15. Run the analyzers most likely to touch redaction-heavy surfaces.
16. Watch jobs move through queued/running/completed or controlled failed states.
17. Use dashboard filters by status, audit type, category label, and search text.
18. Open Redis and SQL DB reports.
19. Confirm the `Passive review` badge is visible.
20. Confirm scope copy says passive, bounded, no execution, no live services, no credential validation, no CVE/advisory lookup, and no exploitability proof.
21. Confirm `Redacted Raw JSON` is visible.
22. Confirm no-read sections show sensitive adjacent files without content.
23. Confirm not-resolved sections show includes/references without resolution.
24. Export representative jobs as Markdown, HTML, XML, and PDF.
25. Run the redaction negative checklist.
26. Confirm the demo language frames findings as review indicators, not confirmed problems.

## 6. Smoke Technical Commands

Recommended technical smoke commands:

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

Optional broader Python run:

```bash
.venv/bin/python -m pytest
```

If the full Python suite fails in a restricted sandbox because a `web_basic` test needs local socket permissions, record that environment condition and run the focused non-web runner command plus backend tests. Do not reinterpret sandbox failure as a product signal.

## 7. Expected Results Matrix

| Fixture | Analyzers to run | Expected sections | Expected findings category | Expected no-read entries | Expected redaction checks | Expected exports | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `demo-file-basic/` | `pdf_basic`, `image_basic`, `manifest_basic` | Metadata, hashes, manifest/dependency summary, raw JSON | File metadata, privacy signals, dependency indicators | None expected | No fixture secrets should exist | Markdown/HTML/XML/PDF where available | Keep files tiny and synthetic. |
| `demo-archive-app-config.zip` | `archive_basic`, `project_archive_basic`, `django_config_basic`, `node_package_config_basic`, `secrets_review_basic` | Archive structure, project manifests, Django settings, Node package config, secrets review, limits/errors, raw JSON | App config, package config, secret-exposure indicators | `.env` detected/not-read where applicable | `.env.example`, `.npmrc`, and secret-like values redacted | Markdown/HTML/XML/PDF | Shows app config plus secrets review without executing code. |
| `demo-archive-container-infra.zip` | `docker_config_basic`, `compose_config_basic`, `ci_cd_config_basic`, `k8s_config_basic`, `terraform_config_basic`, `nginx_config_basic` | Docker/Compose, workflows, Kubernetes, Terraform, Nginx, includes/references, limits/errors, raw JSON | Containers, service wiring, workflow, infra, web edge | Terraform state detected/not-read; optional `.env` no-read | Credential URLs, private key markers, CI/provider tokens redacted | Markdown/HTML/XML/PDF | Shows breadth across deployment surfaces without live validation. |
| `demo-archive-data-layer.zip` | `redis_config_basic`, `database_config_basic`, `sql_database_config_basic`, `secrets_review_basic` | Redis/Sentinel, PostgreSQL/MySQL/MariaDB, pg_hba, settings, no-read files, findings, raw JSON | Cache/database posture, auth, exposure, TLS, logging, backups, sensitive files | `.env`, ACL, RDB, AOF, appendonly, dumps, backups, WAL/binlog/InnoDB, credential files | DB/Redis URLs, passwords, dump-row and ACL-like strings redacted | Markdown/HTML/XML/PDF | Best pack for no-read and data-layer redaction demo. |
| `demo-archive-redaction-negative.zip` | Redaction-heavy archive config analyzers | Findings, redaction notes, errors, Raw JSON | Secret-like values and sensitive references | `.env`, ACL, dumps, state/data files as applicable | All listed fixture secrets absent from DOM, Raw JSON, API, exports, and controlled errors | Markdown/HTML/XML/PDF | This is a negative check pack, not a feature showcase. |

## 8. Redaction Negative Checklist

The following strings must not appear in:

- DOM text.
- Redacted Raw JSON.
- `GET /jobs/{job_id}` API response.
- Markdown export.
- HTML export.
- XML export.
- PDF export.
- Controlled errors.

Strings:

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

Expected positive signal:

- `[REDACTED]` appears where redaction is expected.
- The original uploaded archive may still contain these fake strings.
- The demo must explicitly say that result redaction does not sanitize uploaded originals.

## 9. Demo Narrative

Short script for presenting the alpha:

1. "Inspectra Passive reviews uploaded files and archives locally."
2. "Archive config analyzers are bounded and offered only for files registered as archives."
3. "For config checks, Inspectra does not execute projects or tools and does not contact live services."
4. "Findings are heuristic review indicators. They require human validation."
5. "Sensitive-looking values are redacted in results, exports, and Raw JSON."
6. "The original uploaded archives may still contain secrets, so demo fixtures use fake strings only."
7. "This alpha focuses on passive breadth, redaction posture, and report UX. It is not an active exploitation workflow."

Avoid saying:

- "This proves the system is vulnerable."
- "These credentials are valid."
- "This service is live."
- "This archive is clean."
- "No findings means no risk."
- "The uploaded file was sanitized."

## 10. Demo No-Scope

The demo must not:

- Use real data.
- Use real credentials.
- Use real private keys.
- Use third-party projects without permission.
- Upload sensitive customer or production archives.
- Connect to live services for archive config analyzers.
- Launch Nmap, port scans, fuzzing, brute force, or active scans.
- Run Docker, Docker Compose, Terraform, Nginx, Kubernetes, Redis, SQL DB clients/servers, package managers, CI workflows, or project scripts from fixture content.
- Query providers, registries, CVE databases, advisory feeds, cloud APIs, Docker Hub, package registries, CI providers, Kubernetes APIs, Redis, or databases for passive config smoke.
- Claim exploitability, credential validity, complete coverage, or a clean verdict.

Authorized web/domain/subdomain workflows are separate from archive config demos and must keep their existing explicit authorization language.

## 11. Fixture Creation Guidance For The Next Microphase

When creating the fixtures later:

- Keep archives small enough for fast local smoke.
- Prefer plain text files with minimal syntax needed to trigger existing analyzers.
- Use fake strings consistently.
- Include a `README.md` inside the fixture root explaining each pack.
- Include a manifest listing expected analyzers and expected negative redaction strings.
- Do not generate archives with platform-specific metadata that makes tests flaky.
- Do not include binary dumps with real-looking content; use tiny synthetic marker files where no-read behavior is enough.
- Do not rely on external services, internet access, DNS, Docker daemon, Redis, SQL DB, Kubernetes, Nginx, Terraform, package managers, or CI providers.

## 12. Future Microphases

Recommended sequence:

1. `PASSIVE-ALPHA-SMOKE-DEMO-FIXTURES-02-CREATE-SYNTHETIC-FIXTURE-PACK`
   - Create the fixture root and tiny synthetic files/archives.
   - Keep fixtures fake, small, and public-repo-safe.
2. `PASSIVE-ALPHA-SMOKE-DEMO-FIXTURES-03-WIRE-SMOKE-CHECKLIST-DOCS`
   - Add a concrete smoke checklist tied to the created fixture paths.
   - Document expected commands and manual UI steps.
3. `PASSIVE-ALPHA-SMOKE-DEMO-FIXTURES-04-OPTIONAL-FRONTEND-DEMO-NOTES`
   - Optional, if the UI needs a short local-demo hint or onboarding note.
   - Must not add run-all behavior or active scanning.
4. `PASSIVE-ALPHA-SMOKE-DEMO-FIXTURES-05-ALPHA-PACKAGING-READINESS`
   - Final readiness checklist for trusted local alpha demos.
   - Include retention/local-storage caveats and fixture reset instructions.

Alternative UI line if demo fixtures wait:

`PASSIVE-ALPHA-UI-POLISH-AND-UX-COHERENCE-06-EXPORT-REPORT-READABILITY-POLISH`

## 13. Acceptance Criteria For This Design

- The fixture pack is designed but not created.
- Manual smoke script is defined.
- Technical smoke commands are defined.
- Expected results matrix is included.
- Redaction negative checklist is included.
- Demo narrative is included.
- Demo no-scope is explicit.
- No runtime/frontend/backend behavior changes are made.
- No new analyzers are opened.
