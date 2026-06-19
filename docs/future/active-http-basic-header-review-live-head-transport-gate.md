# Active HTTP Basic Header Review Live HEAD Transport Gate

Status: implemented as
`ACTIVE_HTTP_BASIC_HEADER_REVIEW_08_BACKEND_LIVE_HEAD_TRANSPORT_GATE`.

This phase adds a disabled-by-default backend live `HEAD` transport gate for
`active_http_basic_header_review`. It preserves the existing no-live default
path unless both backend flags are explicitly enabled:

- `INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_ENABLED=true`;
- `INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_LIVE_HEAD_ENABLED=true`.

## Implemented Boundary

- The original disabled path still returns `blocked_unconfigured`, creates no
  job, and records zero sent requests.
- When only the original capability flag is enabled, accepted submissions still
  create the existing no-live `not_executed` job with zero requests.
- When both flags are enabled, valid and authorized submissions pass through a
  small injectable resolver and `HEAD` transport boundary.
- Tests use fake resolver and fake transport adapters by default.
- The live path sends at most one `HEAD` request, follows no redirects, reads no
  response body, retries nothing, and has no `GET` fallback.
- Pre-request policy blocks, missing approvals, malformed contracts, and
  resolver-guard blocks call no transport and create no job.

## Result Surface

Live terminal results persist only redacted, bounded review data:

- `[REDACTED_TARGET]` target display;
- method `HEAD`;
- request counters and live/no-live booleans;
- status code and status class when available;
- redirect-present and location-header-present booleans only;
- allowlisted security-header presence indicators;
- `Server` present/absent only;
- `Set-Cookie` present/absent, capped count, and aggregate attribute presence;
- controlled timeout or network-error codes without raw exception text.

Raw target, raw URL parts, response-header values, cookie names or values,
redirect locations, response bodies, and raw exception strings are not persisted
or rendered.

## Validation Scope

The implementation was validated with compile checks and focused backend tests
using only fake/injected transport. No real external HTTP, DNS, TLS, CT, Nmap,
or Docker activity was run. Frontend runtime, tools runtime, archive/run-all,
and `tools/runner/main.py` were not changed.

Decision marker for this phase:
`ACTIVE_HTTP_BASIC_HEADER_REVIEW_08_BACKEND_LIVE_HEAD_TRANSPORT_GATE_ACCEPTED`
