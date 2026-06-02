# redis_config_basic Closeout

Status: `redis_config_basic` is implemented and stable as a v1 passive archive-based Redis/Sentinel config audit module.

This closeout records the runtime scope, smoke checks, redaction posture, residual risks, and product decision for Redis/Sentinel config audits. The original docs-first design remains in `docs/future/redis-config-basic-design.md`.

## Commit Series

- `00a5a6e docs(redis): design passive redis config audit`
- `47dabb9 feat(redis): add passive config runner analysis`
- `d300e76 feat(redis): integrate passive config backend reporting`
- `32aeef4 feat(redis): add passive config frontend report ux`
- `b49f9c4 test(redis): validate passive config end-to-end redaction contract`

## Implemented Surfaces

- Runner endpoint: `POST /analyze/redis-config`.
- Backend endpoint: `POST /audits/redis-config/{file_id}`.
- Audit type: `redis_config_basic`.
- Source files: uploaded files registered as `kind: "archive"`.
- Backend job creation, status transitions, storage, `GET /jobs`, and `GET /jobs/{job_id}` summaries/results.
- Reporting/export: Markdown, HTML, XML, and PDF sections for Redis summary data, files/configs, Redis settings, Sentinel settings, includes, ACL files, dumps/RDB/AOF/appendonly/backups, findings, limits, redaction notes, and errors.
- Frontend action: `Analyze Redis config`, shown only for archive files.
- Frontend report sections and dashboard filter/label support for `redis_config_basic`.
- Frontend raw JSON is defensively redacted before rendering.

## Capabilities

`redis_config_basic` passively reviews bounded Redis and Sentinel config text from uploaded archives. It detects candidate Redis/Sentinel config files and returns review context for:

- Files detected and reviewed.
- Redis config files.
- Sentinel config files.
- Redis settings.
- Sentinel settings.
- Include directives as detected context.
- ACL files as sensitive/no-read context.
- RDB, AOF, appendonly, dump, and backup files as sensitive/no-read context.

The v1 model detects `.env`, `.env.*`, `.envrc`, ACL files, RDB files, AOF files, appendonly directories, dump files, backup files, and Redis include directives without reading sensitive adjacent file contents or resolving includes.

The v1 finding model focuses on conservative review indicators for:

- Bind and protected-mode exposure.
- `requirepass`, `masterauth`, ACL, and Sentinel auth posture.
- TLS settings.
- Persistence and backup posture.
- Replication and Sentinel posture.
- Dangerous command rename patterns.
- Module loading.
- Logging and runtime posture.
- Limit/resource posture.
- Include directives detected but not resolved.
- Sensitive adjacent files present but not read.
- Secret-like Redis values.

Findings are review indicators for human triage. They are not confirmed vulnerabilities, exploitability claims, live Redis truth, data-breach claims, or proof of compromised infrastructure.

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

- No Redis execution.
- No Sentinel execution.
- No `redis-server`, `redis-cli`, `redis-sentinel`, `redis-benchmark`, or equivalent command execution.
- No Redis, Sentinel, or cluster connection.
- No socket opening.
- No network calls.
- No Docker execution or container startup.
- No credential validation.
- No include resolution outside normal archive candidate scanning.
- No host path reads.
- No real `.env`, `.env.*`, or `.envrc` content reads.
- No ACL content reads.
- No RDB, AOF, appendonly, dump, or backup content reads.
- No CVE or advisory lookup.
- No exploitability, compromise, data breach, or confirmed-vulnerability claims.

## Redaction Guarantees

The module treats Redis/Sentinel secrets defensively and best-effort:

- `requirepass` values are redacted.
- `masterauth` values are redacted.
- Sentinel `auth-pass` values are redacted.
- Redis URLs with embedded credentials are redacted.
- Password-like directives and custom secret-like Redis settings are redacted.
- ACL-like values are redacted.
- Private key blocks are redacted without preserving `PRIVATE KEY`.
- `.env`, ACL, RDB, AOF, appendonly, dump, and backup contents are not read.
- Evidence may show safe context such as file path, config type, directive/setting name, line number, address, include target, no-read file path, or `[REDACTED]`.
- The implementation does not intentionally emit prefixes, suffixes, hashes, fingerprints, or reversible secret identifiers.

Uploaded archive bytes may still contain secrets and are stored locally; redaction protects Inspectra results and reports, not the original uploaded archive.

## Technical Smoke Checklist

Recommended API/export smoke before opening the next module:

1. Upload a small `.zip` or `.tar.gz` archive containing `redis.conf` and `sentinel.conf`.
2. Confirm the uploaded file is registered as `kind: "archive"`.
3. Launch the audit with `POST /audits/redis-config/{file_id}`.
4. Confirm the job appears as `redis_config_basic` and transitions through queued/running to completed or a controlled failed state.
5. Confirm `GET /jobs` includes a Redis summary with file, config, finding, redaction, truncation, and error metrics when present.
6. Confirm `GET /jobs/{job_id}` returns a redacted Redis payload.
7. Export the job as Markdown, HTML, XML, and PDF.
8. Confirm `.env*`, `.envrc`, ACL, RDB, AOF, appendonly, dump, backup, and include entries are shown as detected/no-read or detected/not resolved.
9. Confirm fixture secrets do not appear in API responses, exports, or controlled errors.
10. Upload a non-archive file and confirm Redis analysis is rejected by the backend according to the standard archive-only pattern.
11. Confirm the smoke does not execute Redis/Sentinel, use `redis-cli`, open sockets, resolve includes, read sensitive adjacent files, call networks, or query CVEs/advisories.

Suggested fixture secret strings for negative checks:

- `super-secret-password`
- `raw-api-key-123456`
- `token_should_never_render`
- `Authorization: Bearer token_should_never_render`
- `redis://:super-secret-password@redis:6379/0`
- `masterauth_secret_should_not_render`
- `sentinel_auth_should_not_render`
- `ACLHASHSECRET_should_not_render`
- `dump_value_should_not_render`
- `acl_password_hash_should_not_render`
- `-----BEGIN PRIVATE KEY-----`
- `PRIVATE KEY`

## Manual UI Smoke Checklist

1. Upload a Redis fixture archive from the UI.
2. Confirm the uploaded file is shown as an archive.
3. Confirm `Analyze Redis config` appears for the archive.
4. Confirm `Analyze Redis config` is not shown for non-archive files.
5. Launch the analysis from the UI.
6. Confirm the job appears as `redis_config_basic`.
7. Open the Redis report and confirm summary, files/configs, Redis settings, Sentinel settings, includes, ACL files, dumps/RDB/AOF/appendonly/backups, findings, limits/errors, redaction notes, and raw JSON render clearly.
8. Confirm includes are shown as detected/not resolved.
9. Confirm ACL/RDB/AOF/appendonly/dump/backup files are shown as detected/not read.
10. Confirm DOM text and raw JSON do not contain fixture secrets.
11. Confirm report wording stays passive and does not claim confirmed vulnerabilities, exploitability, compromise, or live Redis truth.

## Reference Validations

The end-to-end Redis series used focused runner, backend, frontend, build, and redaction checks, including:

```bash
git status --short
git log --oneline -8
python3 -m compileall backend tools
PYTHONPYCACHEPREFIX=/tmp/inspectra-pycache python3 -m compileall backend tools
.venv/bin/python -m pytest backend/tests/test_backend.py -k redis_config
.venv/bin/python -m pytest tools/tests/test_runner.py -k redis_config
npm run test -- --run RedisConfigJobReport reportHelpers App dashboardFilters
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

- Redis-like text heuristics can produce false positives and false negatives.
- Include directives are detected but not resolved, so effective runtime config can differ from scanned files.
- Runtime Redis defaults, managed-service overlays, ACL semantics, cluster state, and Sentinel live state are not validated.
- Sensitive adjacent files are detected but intentionally not read, so their contents are not assessed.
- RDB, AOF, appendonly, dump, and backup files are not parsed.
- Credentials are not validated.
- Socket reachability and live exposure are not checked.
- TLS/certificate status is not validated against a live service.
- Findings are static declarations, not runtime truth.
- Redaction is best-effort and may miss uncommon secret formats.

## Product Decision

`redis_config_basic` v1 is CLOSED / READY. It fits the Inspectra passive module pattern: docs-first scope, bounded runner analysis, backend job/reporting, frontend report UX, and end-to-end contract/redaction review.

Do not add more Redis implementation now. Future Redis expansions should be separate docs-first modules or microphases after broader Inspectra coverage improves.

Potential backlog:

- Richer Redis version-aware checks.
- Richer Sentinel topology checks without opening sockets.
- Optional Redis ACL syntax modeling without reading external ACL files.
- Optional Redis Cluster config file signals.
- Optional managed-service static export review if users provide safe static exports.
- Optional backup metadata review without parsing data.

Recommended next docs-first module: `sql_database_config_basic`.

Rationale: before the first Inspectra Passive technical alpha closes transversally, the product should freeze one explicit SQL database config design for PostgreSQL, MySQL, and MariaDB under a name that does not blur Redis or future NoSQL/broker modules. The design remains archive-only and passive, and it should not expand the already closed Redis runtime scope.

Deferred future candidates after the SQL database design and transversal passive closeout:

- `apache_config_basic`, if continuing web-edge coverage.
- `rabbitmq_config_basic`, if prioritizing queue/broker config.
- `mongodb_config_basic`, if prioritizing document databases.
- `elasticsearch_config_basic`, if prioritizing search/data-platform config.
