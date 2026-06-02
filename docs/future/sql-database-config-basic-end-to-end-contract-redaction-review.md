# sql_database_config_basic End-to-End Contract and Redaction Review

Status: end-to-end review microphase for `sql_database_config_basic`.

This document records the contract, redaction posture, fixture coverage, and residual risks verified after the SQL database runner, backend/job/reporting, and frontend UX microphases. It is not a feature expansion and does not change the passive scope defined in `docs/future/sql-database-config-basic-design.md`.

## Implemented Surfaces Reviewed

- Runner endpoint: `POST /analyze/sql-database-config`.
- Backend endpoint: `POST /audits/sql-database-config/{file_id}`.
- Audit type and analyzer: `sql_database_config_basic`.
- Source files: uploaded files registered as `kind: "archive"`.
- Backend job execution, storage, `GET /jobs`, and `GET /jobs/{job_id}`.
- Backend exports: Markdown, HTML, XML, and PDF.
- Frontend archive action: `Analyze SQL DB config`.
- Frontend dashboard label/filter: `SQL DB config`.
- Frontend report and redacted Raw JSON rendering.

## Contract Checks

- The backend calls the runner endpoint `/analyze/sql-database-config`.
- Backend jobs use `sql_database_config_basic` as the audit type.
- Runner results preserve the expected SQL database result fields: `analyzer`, `archive_type`, `summary`, `limits`, `files_detected`, `files_reviewed`, `postgres_configs`, `postgres_hba_rules`, `mysql_configs`, `database_settings`, `includes`, `sensitive_files`, `dump_or_backup_files`, `data_files`, `findings`, `redaction_notes`, `errors`, and `truncated`.
- `POST /audits/sql-database-config/{file_id}` accepts archive files and rejects non-archives.
- Summaries tolerate sparse or incomplete payloads.
- Findings with incomplete optional fields are rendered/exported without breaking.
- Includes are detected as context and not resolved.
- `.env`, `.env.*`, `.envrc`, `.pgpass`, `.my.cnf`, `.mylogin.cnf`, dump/backup files, data files, WAL/binlog/InnoDB files, and key/certificate-like files are detected but not read.

## Fixtures Reviewed

The runner and layered contract tests use controlled archives/payloads with PostgreSQL and MySQL/MariaDB configuration context:

- PostgreSQL settings such as `listen_addresses`, `port`, `ssl`, `password_encryption`, `primary_conninfo`, and `include`.
- `pg_hba.conf` rules such as `host all all 0.0.0.0/0 trust` and IPv6 public CIDR auth hints.
- MySQL/MariaDB settings such as `bind-address`, `require_secure_transport`, `skip-grant-tables`, `local_infile`, `secure_file_priv`, and `!includedir`.
- Sensitive adjacent files such as `.env`, `.env.production`, `.envrc`, `.pgpass`, `.my.cnf`, `.mylogin.cnf`, SQL dumps, backups, WAL/binlog/InnoDB/data files, and key/certificate-like files.

Those adjacent files are present only as controlled test fixtures and are asserted as no-read surfaces.

## Redaction Surfaces

Redaction is applied at the runner, backend storage path, public API responses, reporting/export generation, frontend report sections, and frontend Raw JSON.

The review fixtures assert that these strings do not appear in serialized outputs:

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

Expected redaction uses the fixed placeholder `[REDACTED]`. The review intentionally avoids prefixes, suffixes, hashes, fingerprints, or reversible identifiers. Safe review wording such as `password encryption is weak`, `trust auth configured`, `secure transport disabled`, and `credential file detected but not read` remains readable when it is not a secret value.

## Exports Reviewed

The backend contract tests cover Markdown, HTML, XML, and PDF export generation for SQL database payloads. The exports are expected to include:

- Summary and limits.
- PostgreSQL configs.
- `pg_hba.conf` rules.
- MySQL/MariaDB configs and settings.
- Includes detected as not resolved.
- Sensitive files detected as not read.
- Dumps/backups detected as not read.
- Data/WAL/binlog/InnoDB files detected as not read.
- Findings and redaction notes.

Legacy/malformed payload tests assert that exports do not include fixture secrets or private key markers.

## Frontend Review

Frontend tests cover:

- Archive-only action visibility for `Analyze SQL DB config`.
- `POST /audits/sql-database-config/{file_id}` call wiring.
- Dashboard filter/label support for `sql_database_config_basic`.
- Completed SQL database report rendering.
- Running, failed, sparse, and malformed payload tolerance.
- DOM and Raw JSON redaction for legacy payloads with raw secrets.

The UI copy presents the module as a passive SQL database configuration review and avoids claims of live reachability, exploitability, breach, compromise, SQL injection, or confirmed vulnerabilities.

## Tests Added or Confirmed

- Runner tests confirm SQL database parsing, no-read sensitive adjacent files, include-not-resolved behavior, archive safety, truncation, context handling, and serialized-result redaction.
- Backend tests confirm endpoint creation/rejection, runner endpoint invocation, SQL DB limit forwarding, background job storage, public API redaction, failed-runner handling, summaries, sparse exports, and Markdown/HTML/XML/PDF redaction for legacy payloads.
- Frontend tests confirm archive-only action, dashboard labels/filters, report sections, queued/running/failed/sparse payload handling, DOM redaction, and Raw JSON redaction.
- This review adds a public contract/export test that validates stored fixture payloads through `GET /jobs/{job_id}` and Markdown/HTML/XML/PDF exports while preserving no-read file markers and redaction.

## Scope Kept Out

- No PostgreSQL, MySQL, or MariaDB execution.
- No `psql`, `mysql`, `mysqladmin`, `mysqld`, `postgres`, `pg_ctl`, `mariadb`, `mariadbd`, `pg_dump`, or `mysqldump` execution.
- No socket opening or network calls.
- No Docker or container startup.
- No SQL query execution.
- No credential validation.
- No include resolution.
- No real `.env`, `.pgpass`, `.my.cnf`, `.mylogin.cnf`, dump, backup, data file, WAL, binlog, InnoDB, private key, or certificate content reads.
- No CVE or advisory lookup.
- No exploitability, compromise, data-breach, live-reachability, or confirmed-vulnerability claims.

## Residual Risks

- SQL database config heuristics can produce false positives and false negatives.
- Includes are not resolved, so effective configuration can differ from scanned files.
- Runtime defaults, managed database overlays, role permissions, live connectivity, replication state, TLS certificate status, and actual authentication behavior are not validated.
- Sensitive adjacent files are detected but intentionally not read, so their contents are not assessed.
- Redaction is defensive and best-effort; unusual secret formats may require future hardening.

## Recommended Next Microphase

Proceed with `SQL-DATABASE-CONFIG-BASIC-06-DOCS-SMOKE-CLOSEOUT`.
