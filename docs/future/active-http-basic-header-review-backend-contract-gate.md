# Active HTTP Basic Header Review Backend Contract Gate

Status: implemented as `ACTIVE_HTTP_BASIC_HEADER_REVIEW_02_BACKEND_CONTRACT_GATE`.

This phase adds only a backend contract gate for the future
`active_http_basic_header_review` capability. The gate is controlled by
`INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_ENABLED`, which defaults to `false`.

## Frozen Scope

- `POST /active/web/http-basic-header-review` is the only new route.
- Disabled environments return a controlled `blocked_unconfigured` response.
- Enabled environments validate the single-request contract and still return
  `not_executed` or a controlled block response.
- Public responses use `[REDACTED_TARGET]` and do not expose submitted URL
  paths, query strings, credentials, or hostnames.
- The response records zero sent requests, no redirect following, no body read,
  no persisted job, and no stored result.
- Contract drift such as extra fields, non-`HEAD` methods, custom headers, or
  request-body fields fails closed.

## Deferred

- UI, runner entrypoints, archive orchestration, and broad scanner behavior stay
  outside this phase.
- Passive data expansion and third-party data imports remain deferred.
- A future execution phase must separately design request transport, target
  policy, redaction, persistence, reporting, and operator-facing copy before any
  live request path is enabled.

Decision marker for this phase:
`ACTIVE_HTTP_BASIC_HEADER_REVIEW_02_BACKEND_CONTRACT_GATE_ACCEPTED`
