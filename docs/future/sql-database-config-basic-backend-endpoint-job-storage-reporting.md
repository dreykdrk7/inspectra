# sql_database_config_basic Backend Integration

Status: backend/job/storage/reporting microphase for the passive SQL database config audit.

## Integrated Surface

- Backend endpoint: `POST /audits/sql-database-config/{file_id}`.
- Audit type/job analyzer: `sql_database_config_basic`.
- Runner endpoint used by backend jobs: `POST /analyze/sql-database-config`.
- Source files: uploaded files registered as `kind: archive`.
- Storage: the defensively redacted runner result is persisted with a compact `GET /jobs` summary.
- Reporting/export: existing Markdown, HTML, XML, and PDF paths render SQL database config sections and findings.
- Backend redaction: SQL database payloads are redacted before storage and again in API/reporting/export compatibility paths.

The backend does not parse PostgreSQL, MySQL, or MariaDB config itself. It delegates parsing to the local runner and preserves the passive, bounded analyzer contract.

## Backend Limits

The backend forwards SQL database-specific limits to the runner:

- `INSPECTRA_SQL_DATABASE_CONFIG_MAX_FILES`, default `100`.
- `INSPECTRA_SQL_DATABASE_CONFIG_MAX_FILE_BYTES`, default `524288`.
- `INSPECTRA_SQL_DATABASE_CONFIG_MAX_TOTAL_BYTES`, default `2097152`.

## Reporting Sections

Exports now include SQL database sections for:

- Summary and limits.
- Files detected/reviewed.
- PostgreSQL configs.
- PostgreSQL `pg_hba.conf` rules.
- MySQL/MariaDB configs.
- Database settings.
- Includes detected but not resolved.
- Sensitive files detected but not read.
- Dumps/backups detected but not read.
- Data/WAL/binlog/InnoDB files detected but not read.
- Findings.
- Redaction notes.
- Errors and truncation through the shared report sections.

## Scope Kept Out

This microphase does not add frontend UI, periodic jobs, new findings, parser changes, SQL database execution, database clients, sockets, network calls, database connections, credential validation, SQL query execution, include resolution, `.env`/credential/dump/backup/data-file reads, Docker execution, CVE/advisory lookup, or claims of exploitability, compromise, reachability, breach, or confirmed vulnerability.

Findings remain heuristic review indicators that require human validation in the intended deployment context.

## Validation Focus

- Archive-only endpoint behavior.
- Runner call target `/analyze/sql-database-config`.
- Job creation and controlled runner failure handling.
- SQL database-specific limit forwarding.
- Result redaction before storage and through `GET /jobs/{job_id}`.
- Summary extraction for complete, sparse, null, and malformed payloads.
- SQL database sections in Markdown/HTML/XML/PDF export paths.
- Defensive redaction for legacy payloads containing raw database passwords, credential URLs, `PGPASSWORD`, `MYSQL_PWD`, private key blocks, `.pgpass`/`.my.cnf` material, dump row material, and data-file-like values.

Reference commands:

```bash
python3 -m compileall backend tools
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools
.venv/bin/python -m pytest backend/tests/test_backend.py -k sql_database_config
.venv/bin/python -m pytest tools/tests/test_runner.py -k sql_database_config
.venv/bin/python -m pytest backend/tests/test_backend.py
.venv/bin/python -m pytest
git diff --check
git diff --cached --check
```

## Residual Risks

- SQL database config parsing remains runner-side, textual, best-effort, and heuristic.
- Redaction is defensive and best-effort for malformed or legacy payloads.
- Uploaded archive bytes remain stored locally according to the existing Inspectra file storage model.
- Sensitive adjacent files, dumps, backups, data directories, WAL/binlog files, and key/certificate-like files are detected as present but not read.
- Includes are detected but not resolved, so effective runtime config may differ from visible archive text.
- The backend does not validate live database reachability, credentials, runtime state, or engine versions.

## Next Microphase

Recommended next step: `SQL-DATABASE-CONFIG-BASIC-04-FRONTEND-ACTION-REPORT-UX`, adding the archive-only frontend action and SQL database report UX without expanding runtime scope.
