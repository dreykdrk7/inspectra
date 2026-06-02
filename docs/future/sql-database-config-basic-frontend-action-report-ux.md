# sql_database_config_basic Frontend Action and Report UX

Status: frontend UX microphase implemented for the existing passive SQL database config audit surface.

## Integrated Surface

- Frontend action: `Analyze SQL DB config`.
- Backend endpoint consumed: `POST /audits/sql-database-config/{file_id}`.
- Audit type: `sql_database_config_basic`.
- Source file scope: uploaded files registered as `kind=archive`.
- Report UX: dedicated SQL database config report with redacted Raw JSON.

## Rendered Sections

The frontend report renders the backend payload defensively and tolerates sparse, malformed, running, queued, failed, and completed jobs.

- General summary and status.
- Summary metrics.
- Files detected and reviewed.
- Engine/config overview.
- PostgreSQL configs.
- PostgreSQL `pg_hba.conf` rules.
- MySQL/MariaDB configs.
- Database settings.
- Includes detected as not resolved.
- Sensitive adjacent files detected as not read.
- Dumps/backups detected as not read.
- Data/WAL/binlog/InnoDB files detected as not read.
- Findings grouped by level.
- Redaction notes.
- Limits/truncation.
- Controlled errors.
- Raw JSON after frontend redaction.

## Frontend Redaction

The frontend applies defensive redaction before rendering report sections and Raw JSON. It is designed to hide legacy or malformed payload values containing:

- passwords, tokens, API keys, client secrets, replication passwords, and secret-like assignments;
- PostgreSQL/MySQL connection URLs with credentials;
- `PGPASSWORD` and `MYSQL_PWD` values;
- `.pgpass`, `.my.cnf`, dump, backup, data, WAL, binlog, InnoDB, and private-key-like contents if accidentally present;
- private key blocks without preserving `PRIVATE KEY`.

The placeholder is fixed as `[REDACTED]`. The frontend does not intentionally emit prefixes, suffixes, hashes, fingerprints, or reversible secret identifiers.

Safe review text such as `password encryption is weak`, `trust auth configured`, `credential file detected but not read`, or `secure transport disabled` should remain readable when it is not a secret value.

## Scope Kept Out

This microphase does not add findings, change runner behavior, change backend contracts, add exports, or add periodic jobs. It does not execute PostgreSQL, MySQL, or MariaDB; use database clients; open sockets; make network calls; connect to databases; validate credentials; run SQL queries; read `.env`, `.pgpass`, `.my.cnf`, dumps, backups, data files, WAL, binlogs, or private keys; resolve includes; run Docker; consult CVEs/advisories; or claim exploitation, compromise, reachability, breach, or confirmed vulnerabilities.

## Validation Focus

- Archive-only action visibility and endpoint call.
- Dashboard label/filter support for `sql_database_config_basic`.
- Report rendering for complete, sparse, malformed, running, and failed payloads.
- SQL database sections for PostgreSQL, `pg_hba.conf`, MySQL/MariaDB, settings, includes, no-read sensitive files, dumps/backups, and data files.
- DOM and Raw JSON negative checks for fixture secrets.

## Residual Risks

- Frontend redaction is a defensive last layer and remains best-effort.
- Payload semantics still come from the passive runner/backend analyzer.
- Missing fields or legacy payloads are shown conservatively, but frontend rendering cannot validate deployment reality.
- Findings remain heuristic review indicators requiring human review.

## Next Microphase

Recommended next step: `SQL-DATABASE-CONFIG-BASIC-05-END-TO-END-CONTRACT-REDACTION-REVIEW`.
