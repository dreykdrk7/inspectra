# sql_database_config_basic Design

Status: docs-first design for a future passive archive-based SQL database config audit. No runner, backend, frontend, jobs, exports, or runtime behavior are implemented by this document.

Product note: Inspectra already has a closed `database_config_basic` lineage in this repository. This design freezes the preferred explicit name `sql_database_config_basic` for the final SQL database configuration coverage decision before the first Inspectra Passive technical alpha. A future runtime microphase should decide whether to implement this as a new audit type, rename/alias the existing SQL database surface, or treat this as the canonical design for the existing PostgreSQL/MySQL/MariaDB capability. It must not duplicate user-facing behavior accidentally.

## 1. Module Objective

`sql_database_config_basic` is a future passive archive audit for static PostgreSQL, MySQL, and MariaDB configuration files supplied by the user.

The module should help users review SQL database posture signals around:

- Network exposure, listen, bind, and default port posture.
- Authentication and password-related settings.
- PostgreSQL `pg_hba.conf` access rules.
- User, role, and replication references in config text without reading dumps or table data.
- TLS/SSL settings and certificate/key path references.
- Logging and audit settings.
- Replication and standby settings.
- Backup, dump, data-directory, and WAL/binlog artifacts detected but not read.
- Sensitive paths and include structure.
- Permissive or dangerous settings.
- Resource limits and operational guardrails.
- Development, local, example, production, deploy, and infrastructure path context.

The module should not validate a live database or prove exploitability. Findings are conservative review indicators that require human validation.

This is useful for Inspectra because PostgreSQL, MySQL, and MariaDB commonly sit behind application, Compose, Nginx, Kubernetes, Terraform, and Redis deployments. A bounded, local, archive-only SQL config review gives defenders early signal without database credentials, runtime access, Docker, network calls, provider APIs, or external services.

## 2. Allowed Scope

Allowed behavior:

- Analyze only uploaded archives registered as `kind: archive`.
- Read bounded bytes from SQL database configuration candidates inside the archive.
- Use textual, best-effort parsing for PostgreSQL config, `pg_hba.conf`, MySQL `.cnf`, and MariaDB `.cnf` files.
- Apply static heuristics only.
- Detect sensitive adjacent files as present without reading contents.
- Detect include/import/config-dir directives as context.
- Review included files only when they also appear as normal archive candidates through ordinary archive scanning, not by resolving include paths.
- Apply redaction before storing evidence, errors, raw result data, backend exports, or frontend display in future runtime phases.
- Record parser uncertainty, skipped files, truncation, and controlled errors.

Findings must remain review indicators, not confirmed vulnerabilities, exploitability claims, compromise claims, live exposure truth, or data-breach assertions.

## 3. Explicit Non-Scope

`sql_database_config_basic` v1 must not perform:

- PostgreSQL execution.
- MySQL execution.
- MariaDB execution.
- `psql`, `mysql`, `mysqladmin`, `mysqld`, `postgres`, `pg_ctl`, `mariadb`, `mariadbd`, `pg_dump`, `mysqldump`, or equivalent command execution.
- Socket opening.
- Network calls.
- Database connections.
- Credential validation.
- SQL query execution.
- SQL dump reads.
- SQL dump parsing.
- Backup reads.
- Table, row, schema-data, grant-data, or user-data analysis from dumps.
- `.env`, `.env.*`, `.envrc`, or real secret file content reads.
- Host path reads.
- Include resolution outside normal archive candidate scanning.
- Symlink or hardlink following.
- Broad archive extraction.
- Docker execution or container startup.
- Runtime configuration validation.
- Engine version validation against live binaries.
- Cloud/provider API calls.
- CVE or advisory lookup.
- Claims that a database is reachable, exploitable, compromised, breached, or confirmed vulnerable.

## 4. Engines In Scope

v1 should cover:

- PostgreSQL.
- MySQL.
- MariaDB.

Out of scope before the first Inspectra Passive technical alpha:

- Redis, already closed separately as `redis_config_basic`.
- MongoDB.
- RabbitMQ.
- Elasticsearch and OpenSearch.
- SQLite.
- Oracle.
- SQL Server.
- Cassandra.
- Cloud-managed database posture through APIs.

Those systems can become future docs-first modules after this SQL database config work and the transversal passive closeout are complete.

## 5. Candidate Files

PostgreSQL candidates:

- `postgresql.conf`
- `postgresql.auto.conf`
- `pg_hba.conf`
- `pg_ident.conf`
- `recovery.conf`
- `standby.signal`
- `postgres/**/*.conf`
- `postgresql/**/*.conf`
- `pg/**/*.conf`
- `db/postgres/**/*.conf`
- `database/postgres/**/*.conf`
- `infra/postgres/**/*.conf`
- `deploy/postgres/**/*.conf`
- `docker/postgres/**/*.conf`
- `config/postgres/**/*.conf`

MySQL and MariaDB candidates:

- `my.cnf`
- `my.ini`
- `mysqld.cnf`
- `mariadb.cnf`
- `50-server.cnf`
- `mysql.cnf`
- `mysql/**/*.cnf`
- `mariadb/**/*.cnf`
- `db/mysql/**/*.cnf`
- `database/mysql/**/*.cnf`
- `infra/mysql/**/*.cnf`
- `deploy/mysql/**/*.cnf`
- `docker/mysql/**/*.cnf`
- `config/mysql/**/*.cnf`
- `config/mariadb/**/*.cnf`

Candidate folders and context paths:

- `postgres/**`
- `postgresql/**`
- `pg/**`
- `mysql/**`
- `mariadb/**`
- `db/**`
- `database/**`
- `data/**`
- `infra/**`
- `infrastructure/**`
- `deploy/**`
- `docker/**`
- `server/**`
- `vps/**`
- `config/**`

## 6. Sensitive and No-Read Files

The analyzer should detect these files as sensitive/contextual and not read their contents:

- `.env`
- `.env.*`
- `.envrc`
- `*.sql`
- `*.dump`
- `*.backup`
- `*.bak`
- `*.tar`
- `*.tar.gz`
- `*.tgz`
- `*.gz`
- `*.xz`
- `*.zst`
- `pg_dump*`
- `mysqldump*`
- `backup*`
- `dump*`
- PostgreSQL `base/**`
- PostgreSQL `pg_wal/**`
- PostgreSQL `pg_xact/**`
- `ibdata*`
- `ib_logfile*`
- `binlog*`
- `mysql-bin.*`
- `*.pem`
- `*.key`
- `*.crt`

Certificate files may be recorded as paths/context. Private keys and certificate contents should not be read or displayed. If a certificate path is referenced in a normal config file, the path can be shown only when it is not secret-like.

## 7. Include Handling

PostgreSQL and MySQL/MariaDB configs can import files or directories. v1 should detect include directives but not act like the database engine:

- Detect PostgreSQL `include`, `include_dir`, and `include_if_exists`.
- Detect MySQL/MariaDB `!include` and `!includedir`.
- Do not resolve includes from absolute paths, host paths, network paths, or paths outside the archive.
- Do not read included files by following include directives.
- If an included file is independently found by normal archive candidate scanning, it may be reviewed as its own candidate.
- Record include path/glob, directive type, file path, line number, and resolved status as `false`.
- Treat unresolved includes as context and parser uncertainty, not as proof of misconfiguration.

## 8. Initial Finding Model

Finding objects should include `id` and `code` with the same value when practical, plus title, level, confidence, category, context, engine, file path, line number when available, description, safe evidence, and recommendation.

### Generic and Sensitive Files

- `sql_database_config_detected`
- `sql_database_env_file_sensitive_present`
- `sql_database_dump_or_backup_present_no_read`
- `sql_database_data_files_present_no_read`
- `sql_database_client_credentials_file_present`
- `sql_database_password_like_value`
- `sql_database_credential_url_hint`
- `sql_database_private_key_hint`
- `sql_database_include_absolute_path`
- `sql_database_include_detected_not_resolved`
- `sql_database_unsupported_or_malformed_config`

### PostgreSQL Findings

- `postgres_config_detected`
- `postgres_hba_detected`
- `postgres_listen_all_interfaces`
- `postgres_listen_public_address_hint`
- `postgres_port_default_exposed_hint`
- `postgres_ssl_disabled_or_missing`
- `postgres_ssl_cert_path_present`
- `postgres_ssl_key_path_present`
- `postgres_password_encryption_weak_hint`
- `postgres_hba_trust_auth_hint`
- `postgres_hba_md5_auth_hint`
- `postgres_hba_all_databases_all_users_hint`
- `postgres_hba_public_cidr_hint`
- `postgres_logging_collector_disabled_hint`
- `postgres_log_connections_disabled_hint`
- `postgres_log_disconnections_disabled_hint`
- `postgres_statement_logging_broad_hint`
- `postgres_shared_preload_libraries_present`
- `postgres_archive_mode_enabled_hint`
- `postgres_wal_level_replication_hint`
- `postgres_hot_standby_present`
- `postgres_include_detected_not_resolved`
- `postgres_include_absolute_path`
- `postgres_data_or_wal_files_present_no_read`
- `postgres_dump_or_backup_present_no_read`

### MySQL and MariaDB Findings

- `mysql_config_detected`
- `mariadb_config_detected`
- `mysql_bind_all_interfaces`
- `mysql_bind_public_address_hint`
- `mysql_port_default_exposed_hint`
- `mysql_skip_networking_disabled_hint`
- `mysql_ssl_disabled_or_missing`
- `mysql_ssl_cert_path_present`
- `mysql_ssl_key_path_present`
- `mysql_require_secure_transport_disabled_hint`
- `mysql_local_infile_enabled_hint`
- `mysql_symbolic_links_enabled_hint`
- `mysql_skip_grant_tables_enabled`
- `mysql_general_log_enabled_hint`
- `mysql_slow_query_log_disabled_hint`
- `mysql_log_error_path_present`
- `mysql_binlog_enabled_hint`
- `mysql_replication_settings_present`
- `mysql_server_id_present`
- `mysql_insecure_file_priv_empty_or_broad_hint`
- `mysql_secure_file_priv_missing_hint`
- `mysql_include_detected_not_resolved`
- `mysql_include_dir_detected_not_resolved`
- `mysql_include_absolute_path`
- `mysql_dump_or_backup_present_no_read`
- `mysql_data_files_present_no_read`

## 9. Severity and Confidence

Severity should remain conservative:

- `medium`: direct strong signals such as `pg_hba.conf` trust auth, public CIDR with broad database/user scope, `skip-grant-tables`, bind/listen on all interfaces in production-like context, secret-like config values, credential URLs, private key blocks, and sensitive data/dump files present in production-like paths.
- `low`: potential posture issues without strong context, such as missing or disabled TLS, default ports, MD5 auth hints, logging disabled, broad statement logging, replication/binlog/archive hints, local infile enabled, or include-not-resolved findings.
- `info`: engine/config detected, certificate/key paths present, data/dump files present but not read when context is ambiguous, parser uncertainty, unsupported syntax, or no-read sensitive adjacent files.

Context adjustments:

- Degrade severity in paths containing `dev`, `test`, `local`, `example`, `sample`, `docs`, or `sandbox`.
- Preserve or elevate context in paths containing `prod`, `production`, `live`, `server`, `vps`, `deploy`, `infra`, or `infrastructure`.
- Missing-auth and missing-TLS findings should generally be low or medium confidence because includes and generated configuration are not resolved.
- Direct directive observations can use high confidence when the parser is certain and evidence is safe.

## 10. Redaction

Use the fixed placeholder:

```text
[REDACTED]
```

Never show raw values for:

- Passwords.
- Connection strings.
- URLs with username/password.
- DSNs.
- `password=...`.
- `PGPASSWORD`.
- `MYSQL_PWD`.
- Replication passwords.
- User hashes.
- Token-like or API-key-like values.
- Private key blocks.
- SSL private keys.
- `.env` contents.
- Dump contents.
- SQL insert values.
- Backup contents.

Do not emit prefixes, suffixes, hashes, fingerprints, or reversible identifiers for secret material.

Safe evidence may include:

- File path.
- Engine.
- Section/context.
- Setting name.
- Include directive name.
- Include target path when not secret-like.
- `pg_hba.conf` record type, database field, user field, address/CIDR, auth method, and line number.
- Bind/listen address.
- Port number.
- No-read file path/category.
- `[REDACTED]`.

## 11. Parsing Strategy

Use bounded textual parsing. Do not add heavy dependencies merely for this module.

PostgreSQL parsing:

- Parse `key = value` lines best-effort.
- Handle comments beginning with `#`.
- Handle quoted strings best-effort.
- Handle comma-separated lists best-effort.
- Detect `include`, `include_dir`, and `include_if_exists`.
- Do not resolve includes.
- Parse `pg_hba.conf` with a line-oriented record model: `type database user address method options`.
- Ignore comments and blank lines.
- Tolerate incomplete lines as controlled parser uncertainty.

MySQL/MariaDB parsing:

- Parse INI-like sections such as `[mysqld]`, `[server]`, `[mariadb]`, `[client]`, `[mysql]`, and `[mysqld_safe]`.
- Parse `key=value`, `key = value`, and boolean flags without values.
- Treat `#` and `;` comments as comments.
- Detect `!include` and `!includedir`.
- Distinguish server sections from client sections when assigning severity.
- Tolerate incomplete lines as controlled parser uncertainty.

General archive handling:

- Do not read outside the archive.
- Do not follow symlinks or hardlinks.
- Do not broadly extract archives.
- Enforce max files, max file bytes, and max total bytes.
- Record controlled errors rather than raising unhandled exceptions.

## 12. Proposed JSON Result

The result should align with existing passive audit modules:

```json
{
  "analyzer": "sql_database_config_basic",
  "archive_type": "zip",
  "summary": {
    "files_considered": 0,
    "files_reviewed": 0,
    "postgres_configs_detected": 0,
    "postgres_hba_files_detected": 0,
    "mysql_configs_detected": 0,
    "mariadb_configs_detected": 0,
    "dump_or_backup_files_detected": 0,
    "data_files_detected": 0,
    "findings_count": 0,
    "redacted_values_count": 0,
    "truncated": false
  },
  "limits": {
    "max_files": 100,
    "max_file_bytes": 524288,
    "max_total_bytes": 2097152
  },
  "files_detected": [],
  "files_reviewed": [],
  "postgres_configs": [],
  "postgres_hba_rules": [],
  "mysql_configs": [],
  "database_settings": [],
  "includes": [],
  "sensitive_files": [],
  "dump_or_backup_files": [],
  "data_files": [],
  "findings": [],
  "redaction_notes": [],
  "errors": [],
  "truncated": false
}
```

Suggested future limits:

- `INSPECTRA_SQL_DATABASE_CONFIG_MAX_FILES`, default `100`.
- `INSPECTRA_SQL_DATABASE_CONFIG_MAX_FILE_BYTES`, default `524288`.
- `INSPECTRA_SQL_DATABASE_CONFIG_MAX_TOTAL_BYTES`, default `2097152`.

## 13. UX and Reporting Expectations

Future UI and exports should present `sql_database_config_basic` as a passive static SQL database config review, not a vulnerability scanner or live database validator.

Expected sections:

- Summary.
- Files reviewed/skipped.
- Engine overview.
- PostgreSQL settings.
- PostgreSQL `pg_hba.conf` rules.
- MySQL/MariaDB settings.
- Network/listen/bind posture.
- Authentication and credential posture.
- TLS/SSL posture.
- Logging and audit posture.
- Replication, WAL, binlog, archive, and backup signals.
- Includes and unresolved config.
- Sensitive files detected but not read.
- Findings grouped by severity, category, engine, and context.
- Limits, truncation, parser uncertainty, and controlled errors.
- Redaction notes.
- Raw JSON, defensively redacted.

Reports should clearly state that Inspectra does not execute database servers or clients, open sockets, connect to databases, validate credentials, execute SQL queries, resolve includes, read `.env` files, read dumps/backups/data files, query CVEs/advisories, or confirm exploitability.

## 14. Future Tests

Runner tests should cover:

- PostgreSQL `listen_addresses = '*'` generates `postgres_listen_all_interfaces`.
- PostgreSQL public-looking `listen_addresses` values generate `postgres_listen_public_address_hint`.
- PostgreSQL default port generates `postgres_port_default_exposed_hint` in relevant context.
- PostgreSQL `ssl = off` or missing TLS context generates conservative TLS findings.
- PostgreSQL `ssl_cert_file` and `ssl_key_file` paths are shown safely.
- PostgreSQL weak `password_encryption` generates `postgres_password_encryption_weak_hint`.
- `pg_hba.conf` trust auth generates `postgres_hba_trust_auth_hint`.
- `pg_hba.conf` MD5 auth generates `postgres_hba_md5_auth_hint`.
- `pg_hba.conf` public CIDR with broad database/user fields generates public/broad HBA findings.
- PostgreSQL logging disabled signals generate logging findings.
- PostgreSQL `include` absolute path generates include findings without host reads.
- MySQL `bind-address=0.0.0.0` generates `mysql_bind_all_interfaces`.
- MySQL public bind values generate `mysql_bind_public_address_hint`.
- MySQL default port generates `mysql_port_default_exposed_hint` in relevant context.
- MySQL `skip-networking=0` or equivalent generates `mysql_skip_networking_disabled_hint`.
- MySQL TLS disabled/missing settings generate conservative TLS findings.
- MySQL `require_secure_transport=OFF` generates `mysql_require_secure_transport_disabled_hint`.
- MySQL `local_infile=1` generates `mysql_local_infile_enabled_hint`.
- MySQL `symbolic-links=1` generates `mysql_symbolic_links_enabled_hint`.
- MySQL `skip-grant-tables` generates `mysql_skip_grant_tables_enabled`.
- MySQL `general_log=1` and missing slow query logging generate logging findings.
- MySQL `secure_file_priv` empty or broad values generate file-priv findings.
- MySQL `!include` and `!includedir` generate include-not-resolved findings.
- `.env`, dumps, backups, PostgreSQL data directories, WAL directories, InnoDB data files, binlogs, and private key files are detected but not read.
- Comments do not generate strong findings.
- Path traversal, absolute archive names, symlinks, hardlinks, and non-regular archive entries are not read.
- Limits and truncation are respected.
- Serialized JSON does not contain fixture secrets.

Backend/reporting tests should cover:

- Endpoint accepts only archives.
- Runner call targets `/analyze/sql-database-config` if that becomes the final endpoint.
- Job type is `sql_database_config_basic`.
- Summary tolerates sparse, null, and malformed payloads.
- Markdown, HTML, XML, and PDF exports redact legacy secrets.
- Dumps, backups, data files, and credential files render as detected/no-read.
- Includes render as detected/not resolved.
- Findings with missing optional fields render without breaking.

Frontend tests should cover:

- Action appears only for archives.
- Report renders summary, engines, PostgreSQL settings, HBA rules, MySQL/MariaDB settings, includes, no-read files, findings, limits, errors, and redaction notes.
- Queued, running, failed, sparse, and malformed payloads do not break.
- Raw JSON is redacted.
- Serialized DOM does not contain fixture secrets.

End-to-end/redaction tests should cover:

- Runner result JSON contains no fixture secrets.
- Backend stored result and `GET /jobs/{job_id}` contain no fixture secrets.
- Markdown, HTML, XML, and PDF exports contain no fixture secrets.
- Frontend report DOM and raw JSON contain no fixture secrets.
- Controlled errors are redacted.

Suggested fixture secrets:

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

## 15. Implementation Microphases

Recommended sequence:

1. Docs-first design and scope freeze.
2. Runner/parser passive analysis plus redaction and tests.
3. Backend endpoint/job/storage/reporting and tests.
4. Frontend action/report UX and tests.
5. End-to-end contract/redaction review.
6. Docs/smoke closeout.
7. Passive suite transversal closeout.

Each runtime phase should preserve the same non-scope: no PostgreSQL/MySQL/MariaDB execution, no database clients, no database connections, no query execution, no socket opening, no Docker execution, no include resolution, no `.env`/dump/backup/data-file reads, no network calls, no CVE/advisory lookups, and no exploitability claims.

## 16. Documentation Updates for Future Runtime Phases

When implemented, update:

- `README.md` with the backend endpoint, UI action, limits, no-scope, and launch example.
- `docs/architecture.md` with the backend/runner/storage/reporting/frontend flow.
- `docs/security-scope.md` with allowed SQL database config review scope and explicit out-of-scope behavior.
- A future closeout document such as `docs/future/sql-database-config-basic-closeout.md`.
- Any session summary document if the repository introduces one.

Documentation must continue to state that Inspectra does not run database servers or clients, connect to databases, execute queries, open sockets, read `.env`/dump/backup/data-file contents, resolve includes, query CVEs/advisories, call external services, or confirm exploitability.
