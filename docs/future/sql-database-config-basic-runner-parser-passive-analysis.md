# sql_database_config_basic Runner Parser Passive Analysis

Status: runner/parser microphase implemented. Backend, jobs, reporting exports, and frontend UI are intentionally not part of this phase.

## Integrated Surface

- Internal runner endpoint: `POST /analyze/sql-database-config`.
- Analyzer name: `sql_database_config_basic`.
- Source input: local uploaded archive path supplied by the runner API.
- Analysis mode: archive-only, bounded, passive, textual, and redaction-first.
- Limits:
  - `INSPECTRA_SQL_DATABASE_CONFIG_MAX_FILES`, default `100`.
  - `INSPECTRA_SQL_DATABASE_CONFIG_MAX_FILE_BYTES`, default `524288`.
  - `INSPECTRA_SQL_DATABASE_CONFIG_MAX_TOTAL_BYTES`, default `2097152`.

The implementation reuses the existing passive SQL database config parser lineage where appropriate, while exposing the explicit `sql_database_config_basic` contract from `docs/future/sql-database-config-basic-design.md`.

## Runtime Scope

The runner detects and reviews PostgreSQL, MySQL, and MariaDB config candidates inside archives, including:

- PostgreSQL config files and `pg_hba.conf`.
- MySQL and MariaDB `.cnf`/`.ini` style config files.
- Include directives as context, marked as not resolved.
- Adjacent sensitive files, dumps, backups, data files, WAL/binlog-like files, and key/certificate-like files as present but not read.

The runner emits a JSON result with:

- `analyzer`
- `archive_type`
- `summary`
- `limits`
- `files_detected`
- `files_reviewed`
- `postgres_configs`
- `postgres_hba_rules`
- `mysql_configs`
- `database_settings`
- `includes`
- `sensitive_files`
- `dump_or_backup_files`
- `data_files`
- `findings`
- `redaction_notes`
- `errors`
- `truncated`

## Explicit Non-Scope

This phase does not:

- Start PostgreSQL, MySQL, or MariaDB.
- Run `psql`, `mysql`, `mysqladmin`, `mysqld`, `postgres`, `pg_ctl`, `mariadb`, `pg_dump`, `mysqldump`, or related clients.
- Open sockets or connect to databases.
- Execute SQL queries.
- Validate credentials.
- Resolve includes.
- Read `.env`, `.env.*`, `.envrc`, client credential files, dumps, backups, data directories, WAL/binlog files, private keys, or certificate contents.
- Execute Docker.
- Make network calls.
- Query CVEs/advisories.
- Claim exploitability, compromise, reachability, or confirmed vulnerability.

## Findings Covered

This runner phase covers representative review indicators for:

- PostgreSQL listen/bind posture, default port, disabled TLS, weak password encryption, SSL key/certificate path references, and unresolved includes.
- PostgreSQL `pg_hba.conf` trust, MD5/password auth hints, public CIDR, and all-database/all-user broad rules.
- MySQL/MariaDB bind posture, default port, disabled secure transport, `skip-grant-tables`, `local_infile`, broad/empty `secure_file_priv`, symbolic links, logging and TLS hints, and unresolved includes.
- Sensitive `.env`/client credential files detected but not read.
- Dumps, backups, PostgreSQL data/WAL files, MySQL/InnoDB/binlog files, and key/certificate-like files detected but not read.

All findings remain heuristic review indicators requiring human validation.

## Redaction Guarantees

The runner redacts secret-like values before returning findings, evidence, settings, errors, or serialized result data. Tests assert the full JSON result does not contain fixture secrets such as database URLs with credentials, `PGPASSWORD`, `MYSQL_PWD`, private key blocks, dump row material, or client credential file contents.

Redaction uses the fixed placeholder `[REDACTED]` and intentionally avoids prefixes, suffixes, hashes, fingerprints, or reversible identifiers.

## Validation Reference

Reference commands for this phase:

- `python3 -m compileall tools/runner/main.py tools/tests/test_runner.py`
- `.venv/bin/python -m pytest tools/tests/test_runner.py -k sql_database_config`
- `.venv/bin/python -m pytest tools/tests/test_runner.py -k "not web_basic"`
- `PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools`
- `git diff --check`
- `git diff --cached --check`

## Residual Risks

- Textual parsing can produce false positives and false negatives.
- Includes are not resolved, so generated or included effective config may differ.
- The runner does not know live network reachability or database runtime state.
- Dumps, backups, data directories, WAL/binlogs, and credential files are only detected as present and not read.
- Redaction is best-effort and may miss unusual secret formats.

## Next Microphase

Recommended next phase: `SQL-DATABASE-CONFIG-BASIC-03-BACKEND-ENDPOINT-JOB-STORAGE-REPORTING`.
