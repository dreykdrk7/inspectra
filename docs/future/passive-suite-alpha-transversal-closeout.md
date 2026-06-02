# Passive Suite Alpha Transversal Closeout

Status: Inspectra Passive technical alpha is READY / CLOSED FOR MODULE EXPANSION.

This closeout records the current passive suite after the individual v1 module closeouts through `sql_database_config_basic`. It is a product, smoke, and scope checkpoint before UI polish and broader alpha readiness work. It does not open new analyzers or expand runtime behavior.

## General State

Inspectra now has enough passive coverage for a technical alpha:

- Local file upload and file-kind registration.
- Passive PDF, image, manifest, archive, project-archive manifest, web, DNS, and explicit subdomain workflows.
- Archive-only passive configuration analyzers across application, container, workflow, infrastructure, web-edge, service-wiring, database, cache, and secrets surfaces.
- Backend jobs, local storage, compact job summaries, full job results, Markdown/HTML/XML/PDF exports, frontend actions, readable reports, and redacted raw JSON for the implemented audit families.

The next recommended line is UI transversal polish and smoke-demo coherence, not another module. MongoDB, RabbitMQ, Elasticsearch/OpenSearch, Apache, and other future analyzers stay in post-alpha backlog unless explicitly re-scoped.

## Included Passive Config Modules

| Audit type | Surface | Backend endpoint | Runner endpoint | UI action | Status | Scope summary | Non-scope summary |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `django_config_basic` | Django settings/deployment config | `POST /audits/django-config/{file_id}` | `POST /analyze/django-config` | `Analyze Django config` | CLOSED / READY | Archive-only bounded review of Django settings, deployment hints, environment templates, and related config. | No Python execution, settings import, `manage.py`, dependency install, DB connection, real `.env` reads, CVEs, or exploitability claims. |
| `docker_config_basic` | Dockerfile and Docker/Compose config | `POST /audits/docker-config/{file_id}` | `POST /analyze/docker-config` | `Analyze Docker config` | CLOSED / READY | Archive-only bounded review of Dockerfile, Docker Compose, and `.dockerignore` indicators. | No Docker execution, builds, containers, Docker socket inspection, image downloads, tag resolution, port scans, CVEs, or runtime exposure claims. |
| `secrets_review_basic` | Secret-exposure indicators | `POST /audits/secrets-review/{file_id}` | `POST /analyze/secrets-review` | `Analyze secrets review` | CLOSED / READY | Archive-only bounded redaction-first review of candidate text and sensitive-file presence. | No credential validation, provider calls, Git history scanning, external scanners, fingerprints, real `.env` reads, or active-secret claims. |
| `node_package_config_basic` | Node package/config posture | `POST /audits/node-package-config/{file_id}` | `POST /analyze/node-package-config` | `Analyze Node package config` | CLOSED / READY | Archive-only bounded review of package manifests, lockfiles, package-manager config, JS/TS tool config, and CI/publishing hints. | No npm/pnpm/yarn/bun/npx execution, lifecycle scripts, JS/TS execution, installs, dependency resolution, registry/CVE/advisory lookup, or malicious-package verdicts. |
| `ci_cd_config_basic` | CI/CD workflow posture | `POST /audits/ci-cd-config/{file_id}` | `POST /analyze/ci-cd-config` | `Analyze CI/CD config` | CLOSED / READY | Archive-only bounded review of workflow files, triggers, permissions, actions/images, secrets/env, publish/deploy signals, runners, artifacts, and service containers. | No workflow execution, runner emulation, dynamic provider expression evaluation, provider API calls, token validation, remote action/image downloads, CVEs, or compromised-pipeline claims. |
| `k8s_config_basic` | Kubernetes manifests | `POST /audits/k8s-config/{file_id}` | `POST /analyze/k8s-config` | `Analyze Kubernetes config` | CLOSED / READY | Archive-only bounded review of Kubernetes manifests, Helm/Kustomize context, workloads, containers, services/ingress, RBAC, and secret/config references. | No `kubectl`, cluster access, API server validation, apply/dry-run, Helm render, Kustomize build, image downloads, registries/CVEs, or exploitability claims. |
| `terraform_config_basic` | Terraform/OpenTofu/Terragrunt IaC | `POST /audits/terraform-config/{file_id}` | `POST /analyze/terraform-config` | `Analyze Terraform config` | CLOSED / READY | Archive-only bounded review of Terraform/OpenTofu/Terragrunt files, providers, backends, modules, resources, variables/outputs, state-file presence, and basic AWS hints. | No Terraform/OpenTofu/Terragrunt execution, init/validate/plan/apply, provider/module downloads, cloud APIs, remote state, state content reads, CVEs, or live-infrastructure claims. |
| `nginx_config_basic` | Nginx/web-edge config | `POST /audits/nginx-config/{file_id}` | `POST /analyze/nginx-config` | `Analyze Nginx config` | CLOSED / READY | Archive-only bounded textual review of Nginx configs, server/location/upstream blocks, includes, TLS/security-header/proxy/CORS/access-control signals. | No Nginx execution, `nginx -t`, container startup, DNS/network/port checks, live server/certificate validation, include resolution, CVEs, or confirmed-vulnerability claims. |
| `compose_config_basic` | Docker Compose service wiring | `POST /audits/compose-config/{file_id}` | `POST /analyze/compose-config` | `Analyze Compose config` | CLOSED / READY | Archive-only bounded review of Compose services, images/build contexts, ports, volumes, networks, secrets/env references, healthchecks/restart/resources, and overrides. | No Docker/Compose execution, `docker compose config`, builds/pulls/inspection, registry/CVE lookups, env interpolation, effective multi-file merge, or runtime exposure truth. |
| `database_config_basic` | PostgreSQL/MySQL/MariaDB config lineage | `POST /audits/database-config/{file_id}` | `POST /analyze/database-config` | `Analyze database config` | CLOSED / READY | Archive-only bounded review of PostgreSQL/MySQL/MariaDB config, includes, credential-adjacent files, dumps, and backups. | No DB clients/servers, sockets, DB connections, credential validation, queries, dump parsing, include resolution, CVEs, or runtime database truth. |
| `redis_config_basic` | Redis/Sentinel config | `POST /audits/redis-config/{file_id}` | `POST /analyze/redis-config` | `Analyze Redis config` | CLOSED / READY | Archive-only bounded review of Redis/Sentinel configs, includes, ACL references, RDB/AOF/appendonly/dump/backup no-read context, and Redis/Sentinel posture signals. | No Redis/Sentinel execution, `redis-cli`, sockets, connections, credential validation, include resolution, ACL/RDB/AOF/backup reads, CVEs, or live Redis truth. |
| `sql_database_config_basic` | Explicit SQL DB config | `POST /audits/sql-database-config/{file_id}` | `POST /analyze/sql-database-config` | `Analyze SQL DB config` | CLOSED / READY | Archive-only bounded review of PostgreSQL/MySQL/MariaDB configs, pg_hba rules, includes, hidden credential files, dumps/backups, data/WAL/binlog/InnoDB, and key/cert no-read context. | No PostgreSQL/MySQL/MariaDB execution, clients, sockets, DB connections, SQL queries, credential validation, include resolution, dump/data/private-key reads, CVEs, breach, compromise, or live reachability claims. |

## Transversal Architecture

The shared flow for archive-based passive config analyzers is:

1. The user uploads a supported archive to `POST /files/archive`.
2. The backend validates filename/signature, stores it under `data/uploads`, records metadata, and assigns `kind: "archive"`.
3. The frontend shows archive-only actions only for archive records.
4. The backend endpoint creates a queued job with a stable audit type.
5. The backend background service sends a relative source path and configured limits to the internal runner endpoint.
6. The runner performs bounded local parsing or textual heuristics without broad extraction, symlink/hardlink following, runtime execution, or external calls.
7. The runner returns structured JSON with summary, limits, reviewed/detected files, findings, redaction notes, controlled errors, and truncation metadata.
8. The backend defensively redacts sensitive module payloads before storing final results.
9. `GET /jobs` exposes compact summaries and `GET /jobs/{job_id}` exposes the full stored job.
10. Backend reporting renders Markdown, static HTML, XML, and PDF from stored job JSON.
11. The frontend renders type-specific reports plus defensively redacted raw JSON.

Redaction layers exist at the runner, backend storage, API response where applicable, reporting/export, frontend report, and frontend raw JSON boundaries. Those layers are intentionally redundant so legacy, sparse, malformed, or partially redacted payloads do not reintroduce obvious secrets.

## Transversal Security Scope

Shared principles:

- Passive.
- Archive/file-only for config modules.
- Local.
- Bounded.
- Heuristic.
- Redaction-first.
- No external services for passive config modules.
- No runtime execution for passive config modules.
- No network or socket connections for passive config modules.
- No credential validation.
- No provider, registry, CVE, or advisory lookup for passive config modules.
- Findings are review indicators, not confirmed vulnerabilities.

The bounded authorized `web_basic`, `domain_basic`, and `subdomain_inventory_basic` flows are separate audit families with their own explicit authorization and network/DNS boundaries. They do not change the no-network posture of archive-based passive config modules.

## Transversal Non-Scope

The passive alpha does not include:

- Exploitation.
- Active pentesting.
- Port scanning or network scanning.
- Connections to databases, caches, orchestrators, cloud providers, registries, CI providers, Docker daemons, Kubernetes clusters, Redis/Sentinel, SQL databases, or live servers for passive config modules.
- Runtime execution of databases, caches, orchestrators, Docker, Terraform, Nginx, package managers, CI workflows, user projects, shell scripts, or uploaded files.
- Shell execution over user-supplied archive content beyond existing safe internal validations and external tools for non-config file audits.
- `.env`, credential, state, ACL, dump, backup, data, private-key, certificate, and similar no-read file contents when a module marks them as sensitive/no-read.
- Parsing of dumps, backups, data files, table rows, WAL/binlogs, RDB/AOF, Terraform state contents, or other data stores when a module defines them as no-read.
- Credential validity checks, token validation, provider lookups, CVE/advisory lookups, package registry lookups, image pulls, or remote include/module/action resolution.
- Claims of exploitability, compromise, breach, live reachability, malicious packages, compromised pipelines, runtime exposure truth, or complete coverage.

## Redaction Posture

Preferred placeholder: `[REDACTED]`.

Redaction protects results and reports for common sensitive patterns:

- Passwords.
- Tokens.
- API keys.
- Client secrets.
- Authorization headers.
- Private key blocks.
- Credential-bearing URLs.
- Database and Redis URLs with credentials.
- `PGPASSWORD`, `MYSQL_PWD`, Redis auth, CI/provider-token-like values, package-manager tokens, and secret-like environment variables.
- Values from secret-like config keys, env vars, labels, commands, scripts, user data, backend/provider settings, and errors.
- Dumps/backups/data secrets when they appear in legacy or malformed payloads.

The implementation intentionally avoids prefixes, suffixes, hashes, fingerprints, and reversible secret identifiers. Redaction is best-effort and may miss unusual formats or field names.

Uploaded archive bytes may still contain secrets and are stored locally. Redaction protects Inspectra result JSON, API responses, exports, frontend reports, and raw JSON views; it does not sanitize the original uploaded file.

## Technical Smoke Checklist

Recommended transversal smoke before publicizing a technical alpha:

1. Confirm `git status --short` is clean.
2. Run `python3 -m compileall backend tools`.
3. Run `PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools`.
4. Run backend tests: `.venv/bin/python -m pytest backend/tests/test_backend.py`.
5. Run runner tests without socket-bound web tests when sandboxed: `.venv/bin/python -m pytest tools/tests/test_runner.py -k "not web_basic"`.
6. Run frontend tests: `npm run test -- --run`.
7. Run frontend build: `npm run build`.
8. Upload a small PDF/image/manifest fixture and run at least one file-based analyzer.
9. Upload a small archive fixture and run at least one archive-based analyzer.
10. Run Redis smoke with a Redis/Sentinel fixture archive.
11. Run SQL DB smoke with PostgreSQL/MySQL/MariaDB fixture archive.
12. Confirm non-archive rejection or absent UI action for archive-only analyzers.
13. Confirm `GET /jobs` summaries include completed config jobs.
14. Confirm `GET /jobs/{job_id}` returns full redacted payloads.
15. Export representative jobs as Markdown, HTML, XML, and PDF.
16. Confirm redaction negative checks: fixture passwords, tokens, API keys, credential URLs, DB/Redis URLs, and private-key markers do not appear in UI, raw JSON, API responses, exports, or controlled errors.
17. Confirm no passive config smoke executes external tools such as Docker, Terraform, Kubernetes, Nginx, Redis, SQL DB clients/servers, package managers, CI providers, registries, or CVE/advisory services.

If the full Python suite is run in a sandbox that blocks local sockets, `web_basic` tests can fail with `PermissionError` while creating a local HTTP server. Re-run the exact command with appropriate permission and record the result.

## Manual UI Smoke Checklist

1. Start Inspectra locally.
2. Upload a simple file and confirm file listing/filtering.
3. Upload an archive fixture containing representative config files.
4. Confirm archive-only actions appear only for archive files.
5. Launch representative analyzers, including Redis and SQL DB.
6. Confirm jobs move through queued/running to completed or controlled failed states.
7. Use dashboard filters by status, audit type, and search.
8. Open reports and confirm summaries, detected/reviewed files, findings, limits/errors, redaction notes, and raw JSON.
9. Confirm raw JSON is redacted.
10. Export representative reports as Markdown, HTML, XML, and PDF.
11. Confirm UI copy says indicators/review signals and does not present findings as confirmed vulnerabilities.
12. Confirm empty, sparse, failed, and running states remain readable.

## Alpha Readiness Decision

Ready for technical alpha:

- Passive module breadth is sufficient.
- Archive-only config module pattern is consistent.
- Runner/backend/frontend/reporting contracts are stable enough for smoke.
- Redaction posture has been validated across multiple sensitive modules.
- Documentation now records shared scope, non-scope, risks, and smoke expectations.

Not ready or still needing polish:

- External-user onboarding.
- Demo fixture pack.
- Cross-module report readability.
- Severity and confidence explanations.
- Empty/error-state UX consistency.
- Report export polish.
- Local storage and retention messaging.
- Authentication/authorization/deployment hardening for any non-local use.
- Packaging and alpha demo workflow.

Before publicizing or opening to users beyond trusted local testing, review:

- UI polish.
- Onboarding.
- Terms/copy of scope.
- File-size and archive-limit messaging.
- Persistence/local-storage caveats.
- Visible error handling.
- Report readability.
- Security disclaimers.
- Demo fixtures.
- Packaging/deploy instructions.

## Product Decision

Inspectra Passive technical alpha is CLOSED FOR MODULE EXPANSION.

Do not open new passive analyzers now. MongoDB, RabbitMQ, Elasticsearch/OpenSearch, Apache, and broader active/network analysis remain backlog after the alpha closeout unless explicitly re-scoped.

Recommended next block: `PASSIVE-ALPHA-UI-POLISH-AND-UX-COHERENCE`.

Alternative if product wants demo readiness first: `PASSIVE-ALPHA-SMOKE-DEMO-FIXTURES`.

Do not open another analyzer before one of those transversal blocks.

## Post-Alpha Backlog

- UI/report readability.
- Demo fixture pack.
- Better onboarding.
- Report severity and confidence explanations.
- Cross-analyzer summary dashboard.
- Export polish.
- Local storage/retention controls.
- Authentication and deployment hardening if Inspectra moves beyond local trusted use.
- Optional future analyzers:
  - MongoDB.
  - RabbitMQ.
  - Elasticsearch/OpenSearch.
  - Apache.
- Active/Nmap/network analysis as a distinct later product block, not part of Passive Alpha.

## Reference Documents

- `docs/future/passive-config-audits-v1-closeout.md`
- `docs/future/passive-package-config-audits-v2-closeout.md`
- `docs/future/passive-ci-cd-config-audits-v3-closeout.md`
- `docs/future/k8s-config-basic-closeout.md`
- `docs/future/terraform-config-basic-closeout.md`
- `docs/future/nginx-config-basic-closeout.md`
- `docs/future/compose-config-basic-closeout.md`
- `docs/future/database-config-basic-closeout.md`
- `docs/future/redis-config-basic-closeout.md`
- `docs/future/sql-database-config-basic-closeout.md`
