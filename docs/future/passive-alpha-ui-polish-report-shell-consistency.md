# Passive Alpha UI Polish: Report Shell Consistency

Status: implemented as a focused frontend-only report consistency pass after `docs/future/passive-alpha-ui-polish-dashboard-labels-categories-grouped-actions.md`.

Commit target: `feat(ui): add passive report shell consistency`.

## Scope

This microphase introduces a light shared frontend report shell for selected passive config reports. It does not change backend, runner, job contracts, exports, findings, severities, summaries, redaction logic, endpoints, or raw payload formats.

Implemented UI surfaces:

- Shared `PassiveReportShell` component.
- Common report header for migrated reports.
- Passive review badge.
- Human audit label and category from `frontend/src/auditCatalog.ts`.
- Technical audit type display.
- Job status display.
- Source file, analyzer, archive type, job id, created time, and updated time.
- Stable status copy for queued, running, failed, sparse, completed-with-findings, and completed-with-no-findings states.
- Common passive scope copy.
- Common heuristic-review-indicator copy.
- Common redacted raw JSON placement and label.

## Migrated Reports

This pass intentionally migrates only the newest data-layer reports:

- `RedisConfigJobReport`
- `SqlDatabaseConfigJobReport`

Their module-specific sections remain intact.

Redis-specific sections preserved:

- Summary.
- Files / Configs Detected.
- Redis Settings.
- Sentinel Settings.
- Includes.
- ACL / Dumps / AOF / Backups.
- Findings.
- Redaction Notes.
- Limits / Truncation.
- Errors.
- Redacted Raw JSON.

SQL DB-specific sections preserved:

- Summary.
- Files Detected / Reviewed.
- Engine / Config Overview.
- PostgreSQL Configs.
- PostgreSQL pg_hba.conf Rules.
- MySQL / MariaDB Configs.
- Database Settings.
- Includes Detected / Not Resolved.
- Sensitive Files Detected / Not Read.
- Dumps / Backups Detected / Not Read.
- Data / WAL / Binlog / InnoDB Files Detected / Not Read.
- Findings.
- Redaction Notes.
- Limits / Truncation.
- Errors.
- Redacted Raw JSON.

## Common Copy

The shared shell uses:

```text
Passive static review only. Inspectra reads bounded candidate files from the uploaded archive and reports heuristic review indicators. It does not execute tools, contact live services, validate credentials, query CVEs/advisories, or prove exploitability.
```

It also shows:

```text
Findings are heuristic review indicators and require human validation.
```

Redacted raw JSON uses:

```text
Sensitive-looking values are redacted in results and exports. This does not sanitize the original uploaded file.
```

Controlled copy avoids wording such as compromised, breached, exploitable, confirmed vulnerability, credentials valid, hacked, live exposure confirmed, database exposed, or Redis exposed.

## Stable Status Copy

The shell normalizes:

- `queued`: `Job queued. Results will appear when processing starts.`
- `running`: `Passive analysis is running.`
- `running` with sparse data: `Passive analysis is running. Some result fields are unavailable; showing available redacted data.`
- `failed`: `The job failed in a controlled state. Review errors below; uploaded content was not executed.`
- sparse/malformed completed data: `Some result fields are unavailable; showing available redacted data.`
- completed with findings: `Review indicators were reported. Validate them manually before acting.`
- completed with no findings: `No heuristic findings were reported for this analyzer.`

The no-findings message intentionally does not say that the archive, service, configuration, deployment, database, Redis instance, or credentials are safe or secure.

## Raw JSON

Raw JSON remains available and redacted. The shell places it after module-specific sections under `Redacted Raw JSON`.

This microphase does not change each report's redaction helper. Redis still uses `redactRedisConfigValue`; SQL DB still uses `redactSqlDatabaseConfigValue`.

## Tests

Frontend tests cover:

- Redis shell human label.
- Redis technical audit type.
- Redis category label `Data layer`.
- Redis passive review badge and heuristic copy.
- Redis queued/running/failed/sparse status copy.
- Redis completed-with-no-findings wording without safe/secure claims.
- Redis redacted raw JSON label and no fixture secret leakage.
- Redis-specific sections still render.
- SQL DB shell human label.
- SQL DB technical audit type.
- SQL DB category label `Data layer`.
- SQL DB passive review badge and heuristic copy.
- SQL DB queued/running/failed/sparse status copy.
- SQL DB completed-with-no-findings wording without safe/secure claims.
- SQL DB redacted raw JSON label and no fixture secret leakage.
- SQL DB-specific sections still render.

## Not Changed

- No backend changes.
- No runner changes.
- No endpoint changes.
- No payload contract changes.
- No export format changes.
- No analyzer additions.
- No finding or severity changes.
- No redaction logic changes.
- No active scanning.
- No sockets or network calls.
- No `.env` or sensitive local file reads.

## Pending

Reports not migrated in this microphase:

- PDF.
- Image.
- Manifest.
- Archive.
- Project archive.
- Web/domain/subdomain.
- Django config.
- Docker config.
- Secrets review.
- Node package config.
- CI/CD config.
- Kubernetes config.
- Terraform config.
- Nginx config.
- Compose config.
- Database config.

Future phases can migrate these incrementally if the shell remains stable.

## Next Microphase

Recommended next step:

`PASSIVE-ALPHA-UI-POLISH-AND-UX-COHERENCE-04-STATE-EMPTY-ERROR-POLISH`

That phase should tighten empty states, failed states, sparse payload display, and error wording across the remaining report components without changing backend contracts.
