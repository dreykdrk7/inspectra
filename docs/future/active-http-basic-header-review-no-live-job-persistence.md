# Active HTTP Basic Header Review No-Live Job Persistence

Status: implemented as `ACTIVE_HTTP_BASIC_HEADER_REVIEW_03_NO_LIVE_JOB_PERSISTENCE`.

This phase persists accepted `active_http_basic_header_review` submissions as
owner-scoped no-live jobs. It does not add a live HTTP client, transport,
runner integration, crawling, redirects, response-body reads, or target
expansion.

## Persisted Job Boundary

- Only enabled, valid, policy-passing contracts are persisted.
- Disabled, missing-approval, malformed, and policy-blocked submissions remain
  controlled responses and do not create jobs.
- Persisted jobs use audit type `active_http_basic_header_review`, `file_id:
  null`, status `completed`, and result status `not_executed`.
- Target display is always `[REDACTED_TARGET]`.
- Persisted result data records method `HEAD`, zero sent requests, no redirect
  following, no response-body read, and manual validation required.
- Public detail, list, report, export, and redacted raw JSON surfaces use
  allowlisted no-live fields and caveats only.

## Still Deferred

- Live HTTP request execution.
- Header collection or response parsing.
- Frontend product flow.
- Tools, runner, Docker, Nmap, archive/run-all, and broad scanner behavior.

Decision marker for this phase:
`ACTIVE_HTTP_BASIC_HEADER_REVIEW_03_NO_LIVE_JOB_PERSISTENCE_ACCEPTED`
