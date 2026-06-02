# database_config_basic Design

Status: proposed docs-first design. No runtime endpoint, runner analyzer, backend job, frontend UI, or exports are implemented by this document.

## 1. Module Objective

`database_config_basic` is a future passive archive audit for database configuration files supplied by the user, starting with PostgreSQL, MySQL, and MariaDB.

The module should help users review static database posture signals around network exposure, authentication methods, TLS, logging, replication, backups, permissive or dangerous modes, include structure, and sensitive values before deploying or sharing an archive.

It should not start PostgreSQL, MySQL, or MariaDB; execute database clients; connect to databases; validate credentials; execute queries; parse table data; contact live servers; query CVEs; or prove exploitability. Findings must remain conservative review indicators that require human validation.

This is useful for Inspectra because database config files sit close to high-value data and often reveal deployment posture that is not obvious from application code alone. A bounded, local, archive-only review gives defenders early signal without database credentials, runtime access, Docker, or external services.

## 2. Allowed Scope

The module should only analyze archives uploaded by the user and registered as `kind: archive`.

Allowed behavior:

- Bounded reads of candidate PostgreSQL, MySQL, and MariaDB config text inside uploaded archives.
- Textual, INI-like, and line-oriented heuristic analysis.
- PostgreSQL `key = value` scanning with comment handling for `#`.
- PostgreSQL `pg_hba.conf` line-oriented record scanning.
- MySQL/MariaDB section scanning for `[mysqld]`, `[server]`, `[client]`, and related sections.
- MySQL/MariaDB `key=value`, `key = value`, and boolean flag scanning with comment handling for `#` and `;`.
- Detection of include directives as context.
- Detection of database dumps and backups as sensitive files present without reading their content.
- Detection of `.env`, `.env.*`, `.envrc`, `.pgpass`, hidden client credential files such as `.my.cnf`, and binary login paths such as `.mylogin.cnf` as sensitive files present without reading their content.
- Detection of related Compose, Kubernetes, and Terraform database hints only as supporting context, not as separate audits.
- Redaction-first handling of secret-like values in evidence, errors, raw results, and future exports.
- Recording parse uncertainty, unsupported syntax, truncation, and controlled errors.

Disallowed behavior in v1:

- No PostgreSQL, MySQL, or MariaDB execution.
- No `psql`, `mysql`, `mariadb`, `pg_ctl`, `postgres`, `mysqld`, `mysqladmin`, `pg_dump`, `mysqldump`, or similar command execution.
- No database connections.
- No credential validation.
- No query execution.
- No socket opening.
- No network calls.
- No Docker execution.
- No reading complete dumps, backups, table data, or user data.
- No reading real `.env`, `.env.*`, `.envrc`, `.pgpass`, `.my.cnf`, or `.mylogin.cnf` contents.
- No include resolution outside normal archive candidate scanning.
- No reading absolute host paths.
- No broad extraction.
- No symlink or hardlink following.
- No CVE or advisory lookups.
- No exploitability, compromise, data breach, or confirmed-vulnerability claims.

## 3. Engines In Scope

v1 should cover:

- PostgreSQL.
- MySQL.
- MariaDB.

Out of scope for v1 and reserved for future docs-first modules or expansions:

- Redis.
- MongoDB.
- Elasticsearch and OpenSearch.
- SQLite.
- Oracle.
- SQL Server.
- Cassandra.
- RabbitMQ and queue configs.
- Cloud-managed database posture through APIs.

## 4. Candidate Files

PostgreSQL candidates:

- `postgresql.conf`
- `postgresql.auto.conf`
- `pg_hba.conf`
- `pg_ident.conf`
- `recovery.conf`
- `standby.signal`
- `recovery.signal`
- `postgres/**/*.conf`
- `postgresql/**/*.conf`
- `db/postgres/**/*.conf`
- `database/postgres/**/*.conf`
- `infra/postgres/**/*.conf`
- `deploy/postgres/**/*.conf`

MySQL and MariaDB candidates:

- `my.cnf`
- `mysqld.cnf`
- `mysql.cnf`
- `mariadb.cnf`
- `50-server.cnf`
- `mysql/**/*.cnf`
- `mariadb/**/*.cnf`
- `db/mysql/**/*.cnf`
- `db/mariadb/**/*.cnf`
- `database/mysql/**/*.cnf`
- `database/mariadb/**/*.cnf`
- `infra/mysql/**/*.cnf`
- `deploy/mysql/**/*.cnf`
- `*.cnf` when the path clearly contains `mysql`, `mariadb`, `db`, or `database`.

Sensitive files detected but not read:

- `.env`
- `.env.*`
- `.envrc`
- `.pgpass`
- `.my.cnf`
- `.mylogin.cnf`
- `.sql`
- `*.sql`
- `*.dump`
- `*.backup`
- `*.bak`

Context files detected but not expanded into primary scope:

- Docker Compose files that mount database config, only as path/context.
- Kubernetes ConfigMaps or Secrets with database-looking names, only as context; their audit belongs to `k8s_config_basic`.
- Terraform database resources, only as context; their audit belongs to `terraform_config_basic`.
- Certificate and key paths referenced by config files, without reading certificate or key contents outside the candidate file.

Candidate folders and path contexts:

- `postgres/**`
- `postgresql/**`
- `mysql/**`
- `mariadb/**`
- `db/**`
- `database/**`
- `data/**`
- `infra/**`
- `infrastructure/**`
- `deploy/**`
- `server/**`
- `vps/**`

## 5. Dumps, Backups, and Credential Files

Database dumps and backups can contain table data, password hashes, application secrets, personal data, and operational metadata. v1 should be conservative:

- Detect dumps and backups as `database_dump_or_backup_file_present`.
- Do not read dump or backup contents.
- Do not parse SQL table data.
- Do not extract row values, schema contents, grants, or credentials from dumps.
- Record only safe metadata such as path, file category, size if available from archive metadata, and not-read reason.

Credential-adjacent files should also be conservative:

- Detect `.pgpass`, `.my.cnf`, and `.mylogin.cnf` as sensitive client credential files.
- Do not read their contents in v1.
- Do not infer credentials, hosts, users, or databases from those files.
- If a non-hidden server config such as `my.cnf` is a normal candidate, it may be read within limits; hidden client credential files are not read.

## 6. Include Handling

PostgreSQL and MySQL/MariaDB configs can include other files or directories. v1 should not behave like a database engine:

- Detect PostgreSQL `include`, `include_dir`, and `include_if_exists`.
- Detect MySQL/MariaDB `!include` and `!includedir`.
- Do not resolve includes outside the current file by default.
- Do not read absolute host paths.
- Do not read outside the archive.
- If an included file is also independently detected as a normal archive candidate, it may be reviewed as its own file through normal archive scanning, not by resolving the include.
- Record include paths/globs safely and redact secret-like path fragments if needed.
- Treat unresolved includes as context and parser uncertainty, not as proof of misconfiguration.

## 7. Out of Scope

`database_config_basic` v1 must not perform:

- PostgreSQL, MySQL, or MariaDB execution.
- `psql`, `mysql`, `mariadb`, `pg_ctl`, `postgres`, `mysqld`, `mysqladmin`, `pg_dump`, or `mysqldump` execution.
- Database connections.
- Credential validation.
- Query execution.
- Socket opening.
- Network calls.
- Docker execution.
- Runtime configuration validation.
- Engine version validation against live binaries.
- Live database posture checks.
- User table, dump, backup, or data analysis.
- Include resolution from host paths, network paths, or outside the archive.
- `.env`, `.env.*`, `.envrc`, `.pgpass`, `.my.cnf`, or `.mylogin.cnf` content reads.
- CVE, advisory, reputation, or exploitability lookup.
- Claims that a database is compromised, breached, exploitable, reachable, or vulnerable.

## 8. Initial Finding Model

All findings should include `id` and `code` with the same value when practical, plus title, level, confidence, category, context, engine, file path, line number when available, description, safe evidence, and recommendation.

### Generic and Sensitive Files

- `database_env_file_sensitive_present`
- `database_client_credentials_file_present`
- `database_dump_or_backup_file_present`
- `database_password_like_value`
- `database_credential_url_hint`
- `database_private_key_hint`
- `database_include_absolute_path`
- `database_include_not_resolved`

### PostgreSQL Network and Exposure

- `postgres_listen_addresses_all`
- `postgres_listen_addresses_public_hint`
- `postgres_port_default_exposed_hint`
- `postgres_unix_socket_permissions_permissive`

### PostgreSQL Auth

- `postgres_pg_hba_trust_auth`
- `postgres_pg_hba_md5_auth_hint`
- `postgres_pg_hba_password_auth_hint`
- `postgres_pg_hba_all_all_open_world`
- `postgres_pg_hba_replication_open_world`
- `postgres_password_encryption_weak_or_missing`

### PostgreSQL TLS

- `postgres_ssl_disabled`
- `postgres_ssl_cert_path_missing_hint`
- `postgres_ssl_key_path_missing_hint`

### PostgreSQL Logging and Audit

- `postgres_logging_collector_off`
- `postgres_log_connections_off`
- `postgres_log_disconnections_off`
- `postgres_log_statement_all_hint`
- `postgres_log_min_duration_statement_disabled_hint`

### PostgreSQL Replication and Backup

- `postgres_wal_level_replica_or_logical_hint`
- `postgres_archive_mode_off`
- `postgres_hot_standby_enabled_hint`
- `postgres_replication_slots_hint`

### PostgreSQL Dangerous or Permissive Settings

- `postgres_superuser_reserved_connections_low_hint`
- `postgres_shared_preload_libraries_present`
- `postgres_search_path_unsafe_hint`

### MySQL and MariaDB Network and Exposure

- `mysql_bind_address_all`
- `mysql_skip_networking_disabled_hint`
- `mysql_port_default_exposed_hint`
- `mysql_mysqlx_bind_all_hint`

### MySQL and MariaDB Auth

- `mysql_skip_grant_tables_enabled`
- `mysql_allow_empty_password_hint`
- `mysql_local_infile_enabled`
- `mysql_secure_file_priv_empty_or_missing_hint`
- `mysql_old_passwords_enabled_hint`
- `mysql_default_authentication_weak_hint`

### MySQL and MariaDB TLS

- `mysql_ssl_disabled_or_missing`
- `mysql_require_secure_transport_off`
- `mysql_tls_version_legacy_hint`
- `mysql_ssl_key_or_cert_path_present`

### MySQL and MariaDB Logging and Audit

- `mysql_general_log_enabled_hint`
- `mysql_slow_query_log_disabled_hint`
- `mysql_log_error_missing_hint`
- `mysql_log_bin_disabled_hint`

### MySQL and MariaDB Replication and Backup

- `mysql_server_id_missing_for_replication_hint`
- `mysql_binlog_format_statement_hint`
- `mysql_relay_log_info_repository_file_hint`

### MySQL and MariaDB Dangerous or Permissive Settings

- `mysql_symbolic_links_enabled`
- `mysql_secure_auth_off_hint`
- `mysql_sql_mode_permissive_hint`

## 9. Severity and Confidence

Severity should be conservative by default.

Medium examples:

- `trust` auth in `pg_hba.conf`.
- Open-world `pg_hba.conf` rules for all users/databases.
- Open-world replication rules.
- PostgreSQL `listen_addresses = '*'` in production-like context.
- MySQL/MariaDB `bind-address = 0.0.0.0` or `::`.
- `skip-grant-tables` enabled.
- Empty passwords allowed.
- `local_infile` enabled in production-like context.
- TLS disabled or clearly missing in production-like context.
- Password-like values in config.
- Dump or backup files present in production-like archives.
- Private key material detected.

Low examples:

- Weak or legacy auth hints such as `md5` or `password` auth.
- Missing or disabled logging signals.
- Missing backup/archive/binlog signals.
- Default port exposure hints.
- Includes detected but not resolved.
- Permissive SQL modes when context is unclear.
- Certificate/key paths present without validation.

Info examples:

- Database engine config detected.
- Include directive detected.
- Replication-related settings present.
- Dumps/backups detected but not read when presented as context.
- Parser uncertainty.
- Supporting Compose, Kubernetes, or Terraform context detected.

Path context should adjust severity but not rewrite facts:

- `production`, `prod`, `live`, `deploy`, `server`, `vps`, `data`, `database`, and `db` preserve severity.
- `dev`, `test`, `local`, `example`, `sample`, `docs`, and `sandbox` degrade severity.
- Ambiguous config snippets should avoid deployment-specific claims.

## 10. Redaction and Safe Evidence

Never show raw values for:

- Passwords.
- Connection strings.
- Database URLs.
- Replication passwords.
- SSL private keys.
- Private key blocks.
- Certificate contents.
- Usernames paired with passwords.
- DSNs.
- API tokens in extension configs.
- Audit/log destination credentials.
- Backup destination credentials.
- `.pgpass` values.
- `.my.cnf` client password values.
- `.env` contents.
- SQL dump contents.

Safe evidence may include:

- File path.
- Database engine.
- Section or context.
- Directive or setting name.
- Line number.
- `pg_hba.conf` database, user, address, and auth method when not secret-like.
- Bind/listen address when not credential-like.
- Port number.
- Fixed `[REDACTED]`.

Evidence must not include prefixes, suffixes, hashes, fingerprints, or reversible identifiers for secrets. Raw JSON, future backend exports, frontend reports, and errors must be defensively redacted even for legacy or malformed payloads.

Uploaded archive bytes may still contain secrets and are stored locally; redaction protects Inspectra results and reports, not the original uploaded archive.

## 11. Parsing Strategy

The first runtime implementation should use bounded text parsing and the same archive safety model as other passive modules. It should not add a heavy parser dependency unless a safe parser already exists in the runtime and fits the module's non-execution constraints.

PostgreSQL parsing:

- Strip comments beginning with `#` outside quoted values where practical.
- Parse `key = value` lines.
- Preserve safe setting names, redacted values, line numbers, and file paths.
- Parse `pg_hba.conf` line-oriented records best-effort.
- Detect `include`, `include_dir`, and `include_if_exists`.
- Do not validate syntax against a PostgreSQL server version.

MySQL/MariaDB parsing:

- Track INI-like sections such as `[mysqld]`, `[server]`, `[mariadb]`, `[client]`, and `[mysql]`.
- Parse `key=value`, `key = value`, and boolean flag lines.
- Handle comments beginning with `#` or `;`.
- Detect `!include` and `!includedir`.
- Treat unknown sections and directives as controlled parser uncertainty where needed.
- Do not validate syntax against a MySQL or MariaDB server version.

Shared rules:

- Do not evaluate includes.
- Do not read sensitive credential files or dump files.
- Do not connect to databases.
- Do not infer live reachability.
- Record parse uncertainty and truncation as controlled errors or informational notes, not unhandled exceptions.

## 12. Proposed JSON Result

The result should align with existing passive audit contracts:

```json
{
  "analyzer": "database_config_basic",
  "archive_type": "zip",
  "summary": {
    "files_considered": 0,
    "files_reviewed": 0,
    "database_files_detected": 0,
    "postgres_files_detected": 0,
    "mysql_files_detected": 0,
    "mariadb_files_detected": 0,
    "pg_hba_files_detected": 0,
    "dump_or_backup_files_detected": 0,
    "engines_detected": 0,
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
  "engines": [],
  "postgres_settings": [],
  "pg_hba_rules": [],
  "mysql_settings": [],
  "includes": [],
  "dump_or_backup_files": [],
  "findings": [],
  "redaction_notes": [],
  "errors": [],
  "truncated": false
}
```

Candidate future limits:

- `INSPECTRA_DATABASE_CONFIG_MAX_FILES`, default `100`.
- `INSPECTRA_DATABASE_CONFIG_MAX_FILE_BYTES`, default `524288`.
- `INSPECTRA_DATABASE_CONFIG_MAX_TOTAL_BYTES`, default `2097152`.

Finding objects should tolerate sparse fields and include, when available:

- `id` / `code`
- `title`
- `level`
- `confidence`
- `category`
- `context`
- `engine`
- `file_path`
- `line`
- `section`
- `setting`
- `auth_method`
- `address`
- `port`
- `description`
- `evidence`
- `recommendation`

## 13. Expected UX and Reporting

The future UI and exports should present `database_config_basic` as a passive static database config review, not a vulnerability scanner.

Recommended sections:

- Summary.
- Files reviewed/skipped.
- Engines detected.
- PostgreSQL settings.
- `pg_hba.conf` rules.
- MySQL/MariaDB settings.
- Network exposure.
- Authentication posture.
- TLS posture.
- Logging/audit posture.
- Replication/backup posture.
- Dumps/backups detected and not read.
- Includes detected and not resolved.
- Findings grouped by severity, category, engine, and context.
- Limits, errors, and truncation.
- Redaction notes.
- Raw JSON defensively redacted.

Reports should clearly state that Inspectra does not start databases, run `psql`/`mysql`/`mariadb`, connect to databases, validate credentials, execute queries, parse dump contents, validate runtime state, query CVEs/advisories, or confirm exploitability.

## 14. Future Tests

Runner tests:

- PostgreSQL `listen_addresses = '*'` generates `postgres_listen_addresses_all`.
- PostgreSQL `pg_hba.conf` `trust` auth generates `postgres_pg_hba_trust_auth`.
- PostgreSQL `pg_hba.conf` `0.0.0.0/0` all/all generates `postgres_pg_hba_all_all_open_world`.
- PostgreSQL `ssl = off` generates `postgres_ssl_disabled`.
- PostgreSQL password-like setting is redacted.
- PostgreSQL absolute include is detected and not resolved.
- MySQL/MariaDB `bind-address = 0.0.0.0` generates `mysql_bind_address_all`.
- MySQL/MariaDB `skip-grant-tables` generates `mysql_skip_grant_tables_enabled`.
- MySQL/MariaDB `local_infile = 1` generates `mysql_local_infile_enabled`.
- MySQL/MariaDB `require_secure_transport = OFF` generates `mysql_require_secure_transport_off`.
- MySQL/MariaDB password-like setting is redacted.
- MySQL/MariaDB `!includedir /etc/mysql/conf.d` is detected and not resolved.
- `.env`, `.pgpass`, and hidden `.my.cnf` are detected as sensitive/no-read.
- `.sql`, `.dump`, `.backup`, and `.bak` files are detected as dumps/backups and not read.
- Comments do not generate strong findings.
- Path traversal, absolute archive names, symlinks, hardlinks, and non-regular archive entries are not read.
- Limits and truncation are respected.
- Serialized JSON does not contain fixture secrets.

Backend/reporting tests:

- Endpoint accepts only archives.
- Runner call targets `/analyze/database-config`.
- Job type is `database_config_basic`.
- Summary tolerates sparse and malformed payloads.
- Exports redact legacy secrets.
- Findings with missing optional fields render safely.

Frontend tests:

- Action appears only for archives.
- Report renders summary, engines, PostgreSQL settings, `pg_hba.conf`, MySQL settings, includes, dumps/backups, findings, limits, errors, and redaction notes.
- Queued, running, failed, sparse, and malformed payloads do not break.
- Raw JSON is redacted.
- DOM does not contain fixture secrets.

Suggested fixture secrets:

- `super-secret-password`
- `raw-db-password-123456`
- `postgres://user:pass@example.com/db`
- `mysql://user:pass@example.com/db`
- `replication_password_should_not_render`
- `PGPASSWORD=super-secret-password`
- `MYSQL_PWD=super-secret-password`
- `-----BEGIN PRIVATE KEY-----`

## 15. Implementation Microphases

1. Docs-first design and scope freeze.
2. Runner/parser passive analysis plus redaction and tests.
3. Backend endpoint/job/storage/reporting and tests.
4. Frontend action/report UX and tests.
5. End-to-end contract/redaction review.
6. Docs/smoke closeout.

Each runtime phase should preserve the same non-scope: no database execution, no database connections, no credential validation, no queries, no dump parsing, no Docker execution, no network calls, no CVE/advisory lookup, no real `.env` or credential-file reads, and no exploitability claims.

## 16. Future Documentation Updates

When implemented, update:

- `README.md` with the API launch example, UI action, limits, and no-scope.
- `docs/architecture.md` with the runner/backend/frontend/reporting flow.
- `docs/security-scope.md` with allowed database config review scope and explicit out-of-scope behavior.
- A future closeout document such as `docs/future/database-config-basic-closeout.md`.

Documentation must continue to state that Inspectra does not start databases, run DB clients, connect to servers, validate credentials, execute queries, parse dumps, read `.env`/credential files, query CVEs/advisories, call external services, or confirm exploitability.
