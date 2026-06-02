# Passive Alpha UI Polish: State, Empty, and Error Polish

Status: implemented as a focused frontend-only state and empty-copy polish pass after `docs/future/passive-alpha-ui-polish-report-shell-consistency.md`.

Commit target: `feat(ui): polish passive report states`.

## Scope

This microphase improves visible state, empty, error, truncation, and redaction-note copy for the existing passive report shell and the two reports currently using it.

Covered frontend surfaces:

- `PassiveReportShell`.
- `RedisConfigJobReport`.
- `SqlDatabaseConfigJobReport`.
- Dashboard file/job empty states.

This microphase does not change backend, runner, endpoint, payload contract, export format, analyzer, finding, severity, redaction logic, raw JSON data, or report-specific parsing.

## Normalized State Copy

The shared shell now uses stable messages for:

- Queued jobs: `Job queued. Results will appear when processing starts.`
- Running jobs: `Passive analysis is running. No external services are contacted for archive config analyzers.`
- Running sparse jobs: running copy plus `Some result fields are unavailable; showing available redacted data.`
- Failed jobs: `The job failed in a controlled state. Review errors below; uploaded content was not executed.`
- Sparse/malformed completed payloads: `Some result fields are unavailable; showing available redacted data.`
- Completed with findings: `Review indicators were reported. Validate them manually before acting.`
- Completed with no findings: `No heuristic findings were reported for this analyzer.`
- Truncated results: `Limits were reached; results may be partial.`

The no-findings copy intentionally does not say the result is safe or secure.

## Empty and Error States

Redis and SQL DB report sections now use common copy:

- Empty module sections: `No entries reported for this section.`
- Empty errors: `No controlled errors were reported.`
- Empty redaction notes: `No redaction notes were reported.`

The findings sections keep explicit no-findings messages:

- Redis: `No heuristic Redis config findings reported.`
- SQL DB: `No heuristic SQL database config findings reported.`

The dashboard now uses clearer empty states:

- Files: `Upload a file or archive to start a passive review.`
- Jobs: `Choose a passive archive review to create a job.`

All existing filters and actions are preserved.

## Redis Report Coverage

Redis-specific sections remain visible and data-preserving:

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

Empty module sections render a clear empty-state line instead of module-specific variants that made sparse reports visually inconsistent.

## SQL DB Report Coverage

SQL DB-specific sections remain visible and data-preserving:

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

The settings table label changed from `Safe value` to `Redacted value` to avoid implying that absence of findings means a configuration is safe.

## Wording Guardrails

Controlled copy introduced or changed in this phase avoids:

- compromised
- breached
- exploitable
- confirmed vulnerability
- credentials valid
- hacked
- live exposure confirmed
- database exposed
- Redis exposed
- safe
- secure

Finding titles and evidence still come from payloads and are not over-sanitized by wording tests.

## Tests

Frontend tests cover:

- `PassiveReportShell` queued/running/failed/sparse/completed/truncated copy.
- Completed-with-no-findings copy without safe/secure wording.
- Redis sparse reports rendering shell, redacted raw JSON, empty sections, no errors, and no redaction notes.
- SQL DB sparse reports rendering shell, redacted raw JSON, empty sections, no errors, and no redaction notes.
- Redis and SQL DB redaction fixtures remain absent from rendered DOM and raw JSON.
- Dashboard no-files and no-jobs empty states.
- Existing archive action grouping and filters through focused App/dashboard tests.

## Not Changed

- No backend changes.
- No runner changes.
- No endpoint changes.
- No payload contract changes.
- No export format changes.
- No analyzer additions.
- No finding or severity changes.
- No redaction logic changes.
- No bulk run action.
- No active scanning.
- No sockets or network calls.
- No `.env` or sensitive local file reads.

## Pending

Remaining reports can receive the same state/empty/error polish incrementally after the shell remains stable:

- PDF, image, manifest, archive, project archive.
- Web/domain/subdomain.
- Django, Docker, Secrets review, Node package, CI/CD, Kubernetes, Terraform, Nginx, Compose, and Database config.

## Next Microphase

Recommended next step:

`PASSIVE-ALPHA-UI-POLISH-AND-UX-COHERENCE-05-REDACTION-AND-SCOPE-COPY-PASS`

That phase should standardize redaction and passive scope copy across the remaining report families without changing analyzer behavior or backend contracts.
