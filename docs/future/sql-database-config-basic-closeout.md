# sql_database_config_basic Closeout

Status: `sql_database_config_basic` is implemented and stable as a v1 passive archive-based SQL database config audit module.

This closeout records the runtime scope, smoke checks, redaction posture, residual risks, and product decision for PostgreSQL/MySQL/MariaDB config audits. The original docs-first design remains in `docs/future/sql-database-config-basic-design.md`.

This is the last individual passive config module closeout before the first transversal Inspectra Passive technical-alpha closeout.

## Commit Series

- `c8c61d9 docs(sql-db): design passive database config audit`
- `044ddd1 feat(sql-db): add passive config runner analysis`
- `b6915ff feat(sql-db): integrate passive config backend reporting`
- `b1cadef feat(sql-db): add passive config frontend report ux`
- `ec87e6c test(sql-db): validate passive config end-to-end redaction contract`

## Implemented Surfaces

- Runner endpoint: `POST /analyze/sql-database-config`.
- Backend endpoint: `POST /audits/sql-database-config/{file_id}`.
- Audit type: `sql_database_config_basic`.
- Source files: uploaded files registered as `kind: "archive"`.
- Backend job creation, status transitions, storage, `GET /jobs`, and `GET /jobs/{job_id}` summaries/results.
- Reporting/export: Markdown, HTML, XML, and PDF sections for SQL DB summary data, PostgreSQL configs, pg_hba rules, MySQL/MariaDB configs and settings, includes, sensitive files, dumps/backups, data files, findings, limits, redaction notes, and errors.
- Frontend action: `Analyze SQL DB config`, shown only for archive files.
- Frontend report sections and dashboard filter/label support for `sql_database_config_basic`.
- Frontend raw JSON is defensively redacted before rendering.

## Capabilities

`sql_database_config_basic` passively reviews bounded PostgreSQL, MySQL, and MariaDB config text from uploaded archives. It detects candidate SQL database config files and returns review context for:

- Files detected and reviewed.
- PostgreSQL config files.
- PostgreSQL `pg_hba.conf` rules.
- MySQL and MariaDB config files.
- Database settings and include directives.
- Sensitive adjacent files as no-read context.
- Dump, backup, data, WAL, binlog, InnoDB, private-key, and certificate-like files as no-read context.

The v1 model detects `.env`, `.env.*`, `.envrc`, `.pgpass`, `.my.cnf`, `.mylogin.cnf`, SQL dumps, backups, data files, WAL/binlog/InnoDB files, and key/certificate-like files without reading sensitive adjacent file contents or resolving includes.

The v1 finding model focuses on conservative review indicators for:

- PostgreSQL listen, port, TLS, password-encryption, logging, backup, and replication posture.
- PostgreSQL `pg_hba.conf` trust/password/open-world access rules.
- MySQL/MariaDB bind, auth, TLS, logging, backup, local-file, and secure-file posture.
- Include directives detected but not resolved.
- Sensitive adjacent files present but not read.
- Secret-like SQL database values, DSNs, and credential environment variables.

Findings are review indicators for human triage. They are not confirmed vulnerabilities, exploitability claims, live database truth, reachability claims, data-breach claims, or proof of compromised infrastructure.

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
- No `psql`, `mysql`, `mysqladmin`, `mysqld`, `postgres`, `pg_ctl`, `mariadb`, `mariadbd`, `pg_dump`, `mysqldump`, or equivalent command execution.
- No socket opening.
- No network calls.
- No database connections.
- No SQL query execution.
- No credential validation.
- No Docker execution or container startup.
- No include resolution outside normal archive candidate scanning.
- No host path reads.
- No real `.env`, `.env.*`, or `.envrc` content reads.
- No `.pgpass`, `.my.cnf`, `.mylogin.cnf`, hidden credential file, dump, backup, data, WAL, binlog, InnoDB, private key, or certificate content reads.
- No runtime config validation against live instances.
- No live reachability, drift, role, grant, schema, table, or row analysis.
- No CVE or advisory lookup.
- No exploitability, compromise, data breach, live exposure, or confirmed-vulnerability claims.

## Redaction Guarantees

The module treats SQL database secrets defensively and best-effort:

- Password-like values are redacted.
- `PGPASSWORD` and `MYSQL_PWD` values are redacted.
- PostgreSQL replication password hints are redacted.
- SQL database DSNs and credential-bearing URLs are redacted.
- `.pgpass`, `.my.cnf`, `.mylogin.cnf`, dump, backup, data, WAL, binlog, InnoDB, private-key, and certificate contents are not read.
- Private key blocks are redacted without preserving `PRIVATE KEY`.
- Evidence may show safe context such as file path, engine, config type, directive/setting name, line number, include target, no-read file path, or `[REDACTED]`.
- The implementation does not intentionally emit prefixes, suffixes, hashes, fingerprints, or reversible secret identifiers.

Uploaded archive bytes may still contain secrets and are stored locally; redaction protects Inspectra results and reports, not the original uploaded archive.

## Technical Smoke Checklist

Recommended API/export smoke before the transversal alpha closeout:

1. Upload a small `.zip` or `.tar.gz` archive containing PostgreSQL and MySQL/MariaDB config fixtures.
2. Confirm the uploaded file is registered as `kind: "archive"`.
3. Launch the audit with `POST /audits/sql-database-config/{file_id}`.
4. Confirm the job appears as `sql_database_config_basic` and transitions through queued/running to completed or a controlled failed state.
5. Confirm `GET /jobs` includes a SQL DB summary with file, setting, finding, redaction, truncation, and error metrics when present.
6. Confirm `GET /jobs/{job_id}` returns a redacted SQL DB payload.
7. Export the job as Markdown, HTML, XML, and PDF.
8. Confirm includes are shown as detected/not resolved.
9. Confirm `.env*`, `.envrc`, `.pgpass`, `.my.cnf`, `.mylogin.cnf`, dumps, backups, data/WAL/binlog/InnoDB files, and key/certificate-like files are shown as detected/not read.
10. Confirm fixture secrets do not appear in API responses, exports, raw JSON, or controlled errors.
11. Upload a non-archive file and confirm SQL DB analysis is rejected by the backend according to the standard archive-only pattern.
12. Confirm the smoke does not execute database clients/servers, open sockets, connect to databases, resolve includes, read sensitive adjacent files, call networks, or query CVEs/advisories.

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

## Manual UI Smoke Checklist

1. Upload a SQL database fixture archive from the UI.
2. Confirm the uploaded file is shown as an archive.
3. Confirm `Analyze SQL DB config` appears for the archive.
4. Confirm `Analyze SQL DB config` is not shown for non-archive files.
5. Launch the analysis from the UI.
6. Confirm the job appears as `sql_database_config_basic`.
7. Open the SQL DB report and confirm summary, files, PostgreSQL configs, pg_hba rules, MySQL/MariaDB configs, database settings, includes, sensitive files, dumps/backups, data files, findings, limits/errors, redaction notes, and raw JSON render clearly.
8. Confirm includes are shown as detected/not resolved.
9. Confirm sensitive adjacent files are shown as detected/not read.
10. Confirm DOM text and raw JSON do not contain fixture secrets.
11. Confirm report wording stays passive and does not claim confirmed vulnerabilities, exploitability, compromise, breach, or live database truth.

## Reference Validations

The end-to-end SQL DB series used focused runner, backend, frontend, build, and redaction checks, including:

```bash
git status --short
git log --oneline -8
python3 -m compileall backend tools
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools
.venv/bin/python -m pytest backend/tests/test_backend.py -k sql_database_config
.venv/bin/python -m pytest tools/tests/test_runner.py -k sql_database_config
npm run test -- --run SqlDatabaseConfigJobReport reportHelpers App dashboardFilters
npm run build
.venv/bin/python -m pytest
npm run test -- --run
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

- SQL database config heuristics can produce false positives and false negatives.
- Include directives are detected but not resolved, so effective runtime config can differ from scanned files.
- Runtime defaults, managed database overlays, role permissions, live connectivity, replication state, TLS certificate status, and actual authentication behavior are not validated.
- Sensitive adjacent files are detected but intentionally not read, so their contents are not assessed.
- SQL dumps, backups, data files, WAL/binlog/InnoDB files, private keys, and certificates are not parsed.
- Credentials are not validated.
- Socket reachability and live exposure are not checked.
- Findings are static declarations, not runtime truth.
- Redaction is best-effort and may miss uncommon secret formats.

## Product Decision

`sql_database_config_basic` v1 is CLOSED / READY. It fits the Inspectra passive module pattern: docs-first scope, bounded runner analysis, backend job/reporting, frontend report UX, and end-to-end contract/redaction review.

Do not add more SQL database implementation now. Do not add MongoDB, RabbitMQ, Elasticsearch, OpenSearch, or other database/broker/search modules before the first transversal Inspectra Passive technical-alpha closeout unless explicitly re-scoped.

Future SQL database expansions should be separate docs-first modules or microphases after the transversal alpha closeout.

Potential backlog:

- Richer PostgreSQL `pg_hba.conf` modeling without connecting to a server.
- Richer MySQL/MariaDB option-group interpretation.
- Optional static role/grant review only when users provide explicit safe text fixtures.
- Optional certificate metadata review without reading private key material or validating live TLS.
- Optional managed database static export review if users provide safe local exports.

Recommended next microphase: `PASSIVE-SUITE-ALPHA-TRANSVERSAL-CLOSEOUT`.

Rationale: the individual passive config modules have enough breadth to pause module expansion and review the complete suite across docs, security scope, UX consistency, redaction posture, smoke coverage, and product readiness before opening another feature line.
