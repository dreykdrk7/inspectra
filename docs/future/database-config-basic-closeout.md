# database_config_basic Closeout

Status: `database_config_basic` is implemented and stable as a v1 passive archive-based database config audit module.

This closeout records the runtime scope, smoke checks, redaction posture, residual risks, and product decision for PostgreSQL/MySQL/MariaDB config audits. The original docs-first design remains in `docs/future/database-config-basic-design.md`.

## Commit Series

- `1538c10 docs(database): design passive database config audit`
- `e94f6c0 feat(database): add passive config runner analysis`
- `f1fa976 feat(database): add config backend job`
- `a9f6a26 feat(database): add config report frontend ux`
- `02fcc05 fix(database): align config contract and redaction`

## Implemented Surfaces

- Runner endpoint: `POST /analyze/database-config`.
- Backend endpoint: `POST /audits/database-config/{file_id}`.
- Audit type: `database_config_basic`.
- Source files: uploaded files registered as `kind: "archive"`.
- Frontend action: `Analyze database config`, shown only for archive files.
- Reporting/export: Markdown, HTML, XML, and PDF sections for Database summary data, files, engines, PostgreSQL settings, `pg_hba.conf` rules, MySQL/MariaDB settings, includes, dumps/backups, findings, limits, redaction notes, and errors.
- Frontend raw JSON is defensively redacted before rendering.

## Capabilities

`database_config_basic` passively reviews bounded PostgreSQL, MySQL, and MariaDB config text from uploaded archives. It detects candidate database config files and returns review context for:

- Files detected and reviewed.
- Database engines.
- PostgreSQL settings.
- `pg_hba.conf` rules.
- MySQL and MariaDB settings.
- Include directives as detected context.
- Dumps, backups, and credential-adjacent files as sensitive/no-read context.

The v1 model detects `.env`, `.env.*`, `.envrc`, `.pgpass`, `.my.cnf`, `.mylogin.cnf`, `.sql`, `.dump`, `.backup`, and `.bak` files without reading their contents.

The v1 finding model focuses on conservative review indicators for:

- Network exposure.
- Authentication posture.
- TLS posture.
- Logging and audit posture.
- Replication and backup posture.
- Dangerous or permissive settings.
- Password-like config values.
- Dump/backup presence.
- Credential file presence.
- Include directives detected but not resolved.

Findings are review indicators for human triage. They are not confirmed vulnerabilities, exploitability claims, runtime database truth, data breach claims, or proof of compromised infrastructure.

## Explicit Scope

- Archive-only.
- Local.
- Bounded.
- Passive.
- Heuristic.
- Redaction-first.
- No execution.
- No external services.
- Controlled errors and truncation instead of broad extraction or best-effort execution.

## Explicit Non-Scope

- No PostgreSQL, MySQL, or MariaDB execution.
- No DB client execution.
- No `psql`, `mysql`, `mariadb`, `pg_ctl`, `postgres`, `mysqld`, `mysqladmin`, `pg_dump`, or `mysqldump`.
- No DB connections.
- No credential validation.
- No query execution.
- No socket opening.
- No Docker execution.
- No network calls.
- No runtime configuration validation.
- No live database posture checks.
- No dump parsing.
- No table, row, user-data, or backup-content analysis.
- No `.env`, `.pgpass`, `.my.cnf`, or `.mylogin.cnf` content reads.
- No include resolution outside normal archive candidate scanning.
- No host path reads.
- No CVE or advisory lookup.
- No exploitability, compromise, data breach, or confirmed-vulnerability claims.

## Redaction Guarantees

The module treats database secrets defensively and best-effort:

- Password-like values are redacted.
- Connection strings and DSNs are redacted.
- Database URLs are redacted.
- Replication passwords are redacted.
- Private key blocks are redacted without preserving `PRIVATE KEY`.
- Certificate/private key contents are redacted.
- Audit, log, and backup destination credentials are redacted.
- `.env`, `.pgpass`, `.my.cnf`, and `.mylogin.cnf` contents are not read.
- SQL dump and backup contents are not read.
- Evidence may show safe context such as file path, engine, section/context, setting name, line number, `pg_hba.conf` database/user/address/auth method, bind/listen address, port, or `[REDACTED]`.
- The implementation does not intentionally emit prefixes, suffixes, hashes, fingerprints, or reversible secret identifiers.

Uploaded archive bytes may still contain secrets and are stored locally; redaction protects Inspectra results and reports, not the original uploaded archive.

## Smoke Checklist

Recommended manual smoke before opening the next module:

1. Upload a small `.zip` or `.tar.gz` archive containing PostgreSQL, MySQL, or MariaDB config files.
2. Confirm the uploaded file is registered as `kind: "archive"`.
3. Confirm `Analyze database config` appears for the archive file.
4. Launch the analysis from the UI or call `POST /audits/database-config/{file_id}`.
5. Confirm the job appears as `database_config_basic` and transitions through queued/running to completed or a controlled failed state.
6. Open the frontend report and confirm summary, files, engines, PostgreSQL settings, `pg_hba.conf` rules, MySQL/MariaDB settings, includes, dumps/backups, findings, limits/errors, redaction notes, and raw JSON render clearly.
7. Export the job as Markdown, HTML, XML, and PDF.
8. Confirm `.env*`, `.pgpass`, `.my.cnf`, `.mylogin.cnf`, dumps/backups, and includes are shown as detected/no-read or detected/not resolved.
9. Confirm fixture secrets do not appear in UI, raw JSON, API responses, exports, or controlled errors.
10. Upload a non-archive file and confirm the Database action is not shown or is rejected by the backend according to the standard archive-only pattern.
11. Confirm the smoke does not start databases, run DB clients, connect to DBs, validate credentials, execute queries, parse dumps, resolve includes, read credential files, call networks, or query CVEs/advisories.

Suggested fixture secret strings for negative checks:

- `super-secret-password`
- `raw-db-password-123456`
- `postgres://user:pass@example.com/db`
- `mysql://user:pass@example.com/db`
- `replication_password_should_not_render`
- `PGPASSWORD=super-secret-password`
- `MYSQL_PWD=super-secret-password`
- `-----BEGIN PRIVATE KEY-----`
- `PRIVATE KEY`
- `db_password_plaintext`
- `dump_row_secret_should_not_render`
- `pgpass_secret_should_not_render`
- `mycnf_secret_should_not_render`

## Reference Validations

The end-to-end closeout series used focused runner, backend, frontend, build, and redaction checks, including:

```bash
.venv/bin/python -m pytest tools/tests/test_runner.py -k database_config
.venv/bin/python -m pytest backend/tests/test_backend.py -k database_config
.venv/bin/python -m pytest backend/tests/test_backend.py
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools
npm run test -- --run DatabaseConfigJobReport reportHelpers App dashboardFilters
npm run test -- --run
npm run build
git diff --check
git diff --cached --check
```

For docs-only changes, the minimum validation is:

```bash
git status --short
git diff --check
git diff --cached --check
```

## Residual Risks

- Text heuristics can produce false positives and false negatives.
- PostgreSQL/MySQL/MariaDB syntax support is best-effort.
- Engine version semantics are not validated.
- Includes are detected but not resolved.
- `.env` and credential files are detected but not read.
- Dumps and backups are detected but not parsed.
- Runtime configuration is not validated.
- Live reachability is not checked.
- Credentials are not validated.
- Queries are not executed.
- TLS/certificate status is not validated against a live database.
- Findings are static declarations, not runtime truth.
- Redaction is best-effort and may miss uncommon secret formats.

## Product Decision

`database_config_basic` v1 is ready to close. It fits the Inspectra passive module pattern: docs-first scope, bounded runner analysis, backend job/reporting, frontend report UX, and end-to-end contract/redaction review.

Do not add more Database implementation now. Future Database expansions should be separate docs-first modules or microphases after broader Inspectra coverage improves.

Potential backlog:

- `redis_config_basic`.
- `mongodb_config_basic`.
- `elasticsearch_config_basic`.
- `sqlite_config_basic`.
- Richer PostgreSQL version-aware checks.
- Richer MySQL/MariaDB version-aware checks.
- Optional dump metadata review without parsing data.
- Optional cloud-managed DB static config review if users provide exports.

Recommended next docs-first module: `redis_config_basic`.

Rationale: Redis config is common in real deployments and has a smaller bounded config surface than general database engines. It carries high-impact posture signals around bind/protected-mode, `requirepass`, ACL files, TLS, persistence, append-only files, dangerous commands, and replica settings while staying archive-only and passive. It complements Database, Compose, Docker, Nginx, Kubernetes, and Terraform by reviewing the cache/session/queue layer.

Alternative future candidates:

- `apache_config_basic`, if continuing web-edge coverage.
- `cloudflare_config_basic`, if users provide exported/static configuration.
- `mongodb_config_basic`, if prioritizing document databases.
