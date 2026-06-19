# Active HTTP Basic Header Review Frontend Live Result Rendering

Status: implemented as
`ACTIVE_HTTP_BASIC_HEADER_REVIEW_10_FRONTEND_LIVE_RESULT_RENDERING`.

This phase updates the frontend to safely display both existing no-live
`active_http_basic_header_review` records and future backend-gated live `HEAD`
results.

## Implemented Boundary

- The panel copy now states that the default backend path stores a no-live
  review record.
- The panel also states that backend live mode requires operator configuration,
  all confirmations, and at most one backend `HEAD` request.
- The frontend still submits the exact existing backend contract and exposes no
  live-flag controls.
- The browser never contacts the target; it only calls the Inspectra backend
  API path `/active/web/http-basic-header-review`.
- No-live reports still show `not_executed`, zero requests, no redirect
  following, no body read, and manual validation.
- Live reports can now display status code/status class, request counters,
  redirect/location booleans, security-header presence indicators, `Server`
  present/absent, and aggregate `Set-Cookie` attributes.

## Redaction Boundary

The frontend report helper reconstructs Raw JSON from allowlisted fields for
this audit type. It does not render raw target URL, host, path, query, fragment,
credentials, raw response headers, cookie names or values, `Location` values,
response body, resolved IPs, resolver errors, transport errors, or unknown raw
fields.

## Validation Scope

Validation used frontend fixtures and mocked backend API responses only. No
backend live behavior, browser-side target request, tools integration,
archive/run-all behavior, `tools/runner/main.py` behavior, Docker behavior,
Nmap behavior, or real external HTTP/DNS/TLS/CT activity was added or run.

Decision marker for this phase:
`ACTIVE_HTTP_BASIC_HEADER_REVIEW_10_FRONTEND_LIVE_RESULT_RENDERING_ACCEPTED`
