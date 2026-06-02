# redis_config_basic End-to-End Contract and Redaction Review

Status: end-to-end review microphase for `redis_config_basic`.

This document records the contract, redaction posture, smoke checks, and residual risks verified after the Redis runner, backend/job/reporting, and frontend UX microphases. It is not a feature expansion and does not change the passive scope defined in `docs/future/redis-config-basic-design.md`.

## Implemented Surfaces Reviewed

- Runner endpoint: `POST /analyze/redis-config`.
- Backend endpoint: `POST /audits/redis-config/{file_id}`.
- Audit type and analyzer: `redis_config_basic`.
- Source files: uploaded files registered as `kind: "archive"`.
- Backend job execution, storage, `GET /jobs`, and `GET /jobs/{job_id}`.
- Backend exports: Markdown, HTML, XML, and PDF.
- Frontend archive action: `Analyze Redis config`.
- Frontend report and redacted raw JSON rendering.

## Contract Checks

- The backend calls the runner endpoint `/analyze/redis-config`.
- Backend jobs use `redis_config_basic` as the audit type.
- Runner results preserve the expected Redis result fields: `analyzer`, `archive_type`, `summary`, `limits`, `files_detected`, `files_reviewed`, `configs`, `redis_settings`, `sentinel_settings`, `includes`, `acl_files`, `dump_or_aof_files`, `findings`, `redaction_notes`, `errors`, and `truncated`.
- `POST /audits/redis-config/{file_id}` accepts archive files and rejects non-archives.
- Summaries tolerate sparse or incomplete payloads.
- Findings with incomplete optional fields are rendered/exported without breaking.
- Includes are detected as context and not resolved.
- `.env`, `.env.*`, `.envrc`, ACL, RDB, AOF, appendonly, dump, and backup files are detected but not read.

## Redaction Surfaces

Redaction is applied at the runner, backend storage path, public API responses, reporting/export generation, frontend report sections, and frontend raw JSON.

The review fixtures assert that these strings do not appear in serialized outputs:

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

Expected redaction uses the fixed placeholder `[REDACTED]`. The review intentionally avoids prefixes, suffixes, hashes, fingerprints, or reversible identifiers.

## Tests Added or Confirmed

- Runner tests confirm Redis/Sentinel parsing, no-read sensitive adjacent files, include-not-resolved behavior, archive safety, truncation, context severity degradation, and serialized-result redaction.
- Backend tests confirm endpoint creation/rejection, runner endpoint invocation, background job storage, public API redaction, failed-runner handling, summaries, sparse exports, and Markdown/HTML/XML/PDF redaction for legacy payloads.
- Frontend tests confirm archive-only action, dashboard labels/filters, report sections, queued/running/failed/sparse payload handling, DOM redaction, and raw JSON redaction.
- This review adds an API contract test that launches `POST /audits/redis-config/{file_id}` with a mocked runner, waits for the background job path, then validates stored and public `GET /jobs/{job_id}` output remains redacted.

## Scope Kept Out

- No Redis, Sentinel, or cluster execution.
- No `redis-server`, `redis-cli`, `redis-sentinel`, or benchmark execution.
- No socket opening or network calls.
- No Docker or container startup.
- No credential validation.
- No include resolution.
- No real `.env`, ACL, RDB, AOF, appendonly, dump, or backup content reads.
- No CVE or advisory lookup.
- No exploitability, compromise, data-breach, or confirmed-vulnerability claims.

## Residual Risks

- Redis-like text heuristics can produce false positives and false negatives.
- Includes are not resolved, so effective configuration can differ from scanned files.
- Redis runtime defaults, managed-service overlays, ACL semantics, cluster state, and Sentinel live state are not validated.
- Sensitive adjacent files are detected but intentionally not read, so their contents are not assessed.
- Redaction is defensive and best-effort; unusual secret formats may require future hardening.

## Product Decision

`redis_config_basic` is ready for the formal docs/smoke closeout microphase. Do not expand Redis findings or runtime behavior in this review phase. Any future Redis deepening should be separate, docs-first work after the v1 module is closed.

## Recommended Next Microphase

Proceed with `REDIS-CONFIG-BASIC-05-DOCS-SMOKE-CLOSEOUT`.
