# Active HTTP Basic Header Review Frontend No-Live Panel

Status: implemented as `ACTIVE_HTTP_BASIC_HEADER_REVIEW_05_FRONTEND_NO_LIVE_PANEL`.

This phase adds the frontend product path for the existing backend
`active_http_basic_header_review` no-live capability.

## Implemented

- Added a typed frontend API client method for
  `POST /active/web/http-basic-header-review`.
- Added a separate Active / HTTP header review panel with one URL target, fixed
  `HEAD` method display, authorization confirmation, target permission
  confirmation, and live-request contract acknowledgement.
- The panel copy states that the current phase stores a no-live review record
  and no HTTP request is performed yet.
- Added dedicated dashboard list/detail/report rendering for
  `active_http_basic_header_review` jobs.
- Report display is allowlist-based and shows `[REDACTED_TARGET]`,
  `not_executed`, `HEAD`, `requests_sent: 0`,
  `live_request_performed: false`, `redirect_followed: false`,
  `body_read: false`, manual validation, and HTTP header review indicator
  wording.

## Still Out Of Scope

- No backend live HTTP runtime was added.
- No browser-side target request was added.
- No tools integration, archive/run-all behavior, or `tools/runner/main.py`
  behavior was added.
- No Docker or Nmap behavior was added or run.
- No custom headers, authentication inputs, request body, redirects, response
  body reads, provider import, passive DNS, or target expansion was added.

Decision marker for this phase:
`ACTIVE_HTTP_BASIC_HEADER_REVIEW_05_FRONTEND_NO_LIVE_PANEL_ACCEPTED`
