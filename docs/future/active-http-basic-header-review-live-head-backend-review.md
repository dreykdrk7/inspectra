# Active HTTP Basic Header Review Live HEAD Backend Review

Status: implemented as
`ACTIVE_HTTP_BASIC_HEADER_REVIEW_09_BACKEND_LIVE_HEAD_REVIEW`.

This phase reviewed the backend live `HEAD` transport gate added in phase 08
before any frontend live-result polish or real external smoke.

## Review Result

The backend boundary remains accepted with hardening:

- the original capability flag still defaults to disabled;
- the live `HEAD` flag still defaults to disabled;
- enabling only the original flag preserves the existing no-live job path;
- enabling both flags allows only the injected/fakeable resolver and `HEAD`
  transport path after contract, approval, and target policy checks pass;
- pre-request blocks still create no job and call no transport;
- live results persist only redacted target display, method, counters, status
  class/code, redirect booleans, header-presence indicators, and aggregate
  cookie attributes.

## Hardening Applied

- Local and control-plane hostnames are now blocked before resolver output is
  considered.
- Resolver timeout and resolver error paths are covered as fail-closed,
  no-transport, no-job outcomes.
- Resolver guard coverage now includes metadata, loopback, link-local,
  multicast, unspecified, broadcast, and private-address fake answers.
- Live wrong-owner access is covered as generic not found.
- Header byte cap behavior is covered so oversized header values are counted as
  truncated and not rendered.
- No-live behavior is covered with fake adapters installed to confirm the live
  path is not reached when the live flag is disabled.

## Preserved Boundaries

The reviewed path still sends at most one `HEAD` request, follows no redirects,
retries nothing, sends no body, reads no body, has no `GET` fallback, accepts no
custom operator-supplied headers, and stores no raw URL, host, path, query,
fragment, credentials, response-header values, cookie names or values,
redirect locations, resolved IPs, resolver errors, transport errors, or response
body.

No frontend runtime, tools runtime, archive/run-all behavior,
`tools/runner/main.py` behavior, Docker behavior, Nmap behavior, target
expansion, crawling, fingerprinting, CVE mapping, or exploit logic was added.

## Validation Scope

Validation used compile checks and backend tests with fake/injected resolver and
transport only. No real external HTTP, DNS, TLS, CT, Nmap, or Docker activity
was run.

Decision marker for this phase:
`ACTIVE_HTTP_BASIC_HEADER_REVIEW_09_BACKEND_LIVE_HEAD_REVIEW_ACCEPTED`
