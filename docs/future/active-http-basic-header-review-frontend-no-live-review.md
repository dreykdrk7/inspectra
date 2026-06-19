# Active HTTP Basic Header Review Frontend No-Live Review

Status: implemented as `ACTIVE_HTTP_BASIC_HEADER_REVIEW_06_FRONTEND_NO_LIVE_REVIEW`.

This phase reviewed and tightened the frontend no-live product flow for
`active_http_basic_header_review` before any live HTTP runtime design.

## Review Result

- The frontend request contract remains exact:
  `mode`, `profile`, `target`, fixed `method: HEAD`, and the four required
  confirmation fields only.
- The panel calls only the Inspectra backend API path
  `/active/web/http-basic-header-review`; no browser-side target request path
  was added.
- Accepted jobs are displayed as no-live records: `not_executed`, `HEAD`,
  `requests_sent: 0`, `live_request_performed: false`,
  `redirect_followed: false`, `body_read: false`, manual validation, and HTTP
  header review indicator wording.
- Reports and Raw JSON remain allowlist-based and display `[REDACTED_TARGET]`
  rather than raw URL, host, path, query, fragment, credentials, headers,
  cookies, redirect locations, exception text, or response body.

## Hardening Applied

- The panel clears the submitted target and confirmation checkboxes after an
  accepted no-live job is created.
- Job-list summary wording now includes the fixed method, zero requests,
  no-live booleans, and manual validation wording.
- Tests now cover the delegated-permission path, hardcoded `HEAD` behavior,
  target-clearing after success, backend-path-only submission, and the expanded
  list summary.

No backend live HTTP runtime, browser-side target request, tools integration,
archive/run-all behavior, `tools/runner/main.py` behavior, Docker behavior, or
Nmap behavior was added.

Decision marker for this phase:
`ACTIVE_HTTP_BASIC_HEADER_REVIEW_06_FRONTEND_NO_LIVE_REVIEW_ACCEPTED`
