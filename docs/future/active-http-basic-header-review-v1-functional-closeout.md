# Active HTTP Basic Header Review v1 Functional Closeout

Decision: `ACTIVE_HTTP_BASIC_HEADER_REVIEW_11_FUNCTIONAL_CLOSEOUT_ACCEPTED`

This document closes `active_http_basic_header_review` v1 after the design,
backend contract gate, no-live persistence, surface review, frontend no-live
flow, live HEAD design, live backend transport gate, backend live review, and
frontend live result rendering phases.

This closeout found and fixed one boundary gap: root URLs with query strings
were previously accepted by the HTTP header review target policy. They are now
blocked with controlled reason code `query_not_allowed` before no-live
persistence or live transport. The existing path rejection remains the
controlled outcome for non-root paths, including non-root paths that also carry
query strings.

No new Active feature is approved by this closeout. After this block, Inspectra
pauses technically before choosing the next Active feature.

## Reviewed Lineage

Reviewed as the v1 HTTP header review line:

- `8c9c552 docs(active): design http basic header review`;
- `d2f5818 feat(active): add http header review contract gate`;
- `cfee4f3 feat(active): persist http header review no-live jobs`;
- `46d58ab fix(active): harden http header no-live surfaces`;
- `2680818 feat(active): add http header review no-live UI`;
- `cc9dbd4 fix(active): harden http header no-live frontend`;
- `00e0cc1 docs(active): design http header live head runtime`;
- `d64c105 feat(active): gate http header live head transport`;
- `6461c52 fix(active): harden http header live head backend`;
- `4701cd4 feat(active): render http header live results in frontend`.

The closeout review inspected the HTTP header review design and phase docs
under `docs/future/active-http-basic-header-review-*`, the backend runtime,
config, route, model, storage, reporting, and backend tests, plus the frontend
panel, report builder, App integration, API client, type contract, catalog,
filter, and related tests.

## Approved State

`active_http_basic_header_review` v1 is accepted as a narrowly bounded,
disabled-by-default Active capability for one explicit authorized root
`http://` or `https://` URL.

The backend remains the authority for:

- feature gates;
- auth and owner scope;
- exact request contract validation;
- target policy;
- confirmation checks;
- resolver guard;
- at-most-one live HEAD transport when enabled;
- storage shaping;
- report/export/public-result shaping;
- redaction.

Accepted public wording remains `HTTP header review indicator` and `Manual
validation required`.

## Feature Gates

The capability remains closed by default:

- `INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_ENABLED=false`;
- `INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_LIVE_HEAD_ENABLED=false`.

When the capability flag is disabled, the backend returns a controlled
`blocked_unconfigured` response, creates no job, sends no DNS query, and sends
no HTTP request.

When only the capability flag is enabled, accepted requests create a no-live
job record. Live HEAD transport is reachable only when both flags are enabled
and the request passes contract, authorization, target policy, and resolver
guard checks.

## Contract Boundary

The accepted request contract is exactly:

- `mode: live_http_basic_header_review`;
- `profile: http_headers_single_request`;
- `target`;
- `method: HEAD`;
- `authorization_confirmed`;
- `target_control_confirmed`;
- `delegated_permission_confirmed`;
- `live_http_request_confirmed`.

Extra fields are rejected. The frontend preserves this payload and exposes no
live-flag control.

The accepted target policy is:

- `http://` or `https://` only;
- one URL only;
- root path only, empty or `/`;
- no query string;
- no fragment;
- no credentials or userinfo;
- no custom port;
- no wildcard;
- no list, CIDR, range, generated target, or target expansion;
- bounded URL length.

## No-Live Boundary

Accepted no-live jobs persist:

- `audit_type: active_http_basic_header_review`;
- `file_id: null`;
- `target_url: [REDACTED_TARGET]`;
- `result_status: not_executed`;
- `target` and `target_display` as `[REDACTED_TARGET]`;
- method `HEAD`;
- request counters at zero;
- `live_request_performed: false`;
- `redirect_followed: false`;
- `body_read: false`;
- `Manual validation required`.

Completed job lifecycle status means only that the no-live record was stored.
It is not presented as HTTP execution success.

## Live HEAD Boundary

Live behavior remains behind both flags and all checks. The accepted runtime
boundary is:

- at most one backend `HEAD` request;
- no redirect following;
- no retry;
- no request body;
- no response body read;
- no `GET` fallback;
- no operator-supplied headers;
- timeout and response-header byte caps;
- fake/injectable resolver and transport in tests;
- pre-request blocks create no job and call no transport.

The resolver guard blocks local/control-plane hostnames before resolver
consideration, blocks disallowed address classes from fake or real resolver
answers, fails closed on resolver errors, and does not persist raw resolved IPs
or resolver error text. It is a guard, not a DNS discovery feature.

## Redaction Boundary

Storage, API responses, reports, exports, Raw JSON, list summaries, detail
views, and frontend rendering must not expose:

- raw target URL;
- host, path, query, or fragment;
- credentials or userinfo;
- raw response headers;
- header values;
- cookie names or values;
- raw redirect location;
- response body;
- resolved IP address;
- resolver error text;
- transport exception text;
- tokens or secrets.

Persisted and public results are regenerated from allowlisted fields rather
than trusting caller-supplied result fields. Wrong-owner detail, delete, and
export access remains generic not found.

## Result Indicators

The accepted result surface may expose only:

- `[REDACTED_TARGET]`;
- method `HEAD`;
- request counters and execution booleans;
- status code and status class when present;
- redirect/location booleans only;
- allowlisted security-header presence indicators;
- Server present/absent only;
- Set-Cookie present/absent, capped count, and aggregate attributes;
- controlled timeout/network/policy reason codes;
- manual validation requirement.

Timeout and network error states are controlled review context.

## Frontend And Reporting Boundary

The frontend:

- calls only backend API path `/active/web/http-basic-header-review`;
- never contacts the target from the browser;
- exposes no live flag control;
- keeps method fixed/read-only as `HEAD`;
- accurately describes the no-live default and backend-gated live mode;
- renders no-live and live records from allowlisted fields;
- reconstructs Raw JSON from the public result only;
- keeps existing Active Nmap, TLS, DNS inventory, and DNS OSINT UI behavior.

Markdown, HTML, XML, PDF, Raw JSON, list, detail, and frontend report surfaces
use the HTTP header review public-result builder before rendering.

## Not Approved

This v1 closeout does not approve:

- `GET` fallback;
- response body reads;
- redirect following;
- crawling;
- JavaScript execution;
- screenshots;
- authentication inputs;
- custom headers;
- cookies as input;
- request body;
- methods other than `HEAD`;
- forms;
- content discovery;
- directory brute force;
- expanded technology fingerprinting;
- version-to-CVE mapping;
- exploit checks;
- Nmap or port scanning;
- DNS OSINT, passive DNS, or provider import expansion;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- hosted multi-tenant scanning service behavior;
- binary target verdicts;
- completeness claims.

## Residual Risks

Residual risk is intentionally narrow:

- any enabled live HEAD capability still performs real backend network activity
  against the operator-authorized URL;
- DNS resolution for the guard is required before live transport and may
  observe one hostname lookup;
- header-presence indicators are review context and require manual validation;
- future source or UI changes must keep using the allowlisted public-result
  builders for this audit type.

## Validation Results

Validation run during this closeout:

- starting `git status --short --branch`: `## main...origin/main`;
- `.venv/bin/pytest backend/tests/test_backend.py -k active_http_basic_header_review`:
  `47 passed, 643 deselected`;
- `.venv/bin/python -m py_compile backend/app/active_http_basic_header_review.py backend/tests/test_backend.py`:
  passed;
- `.venv/bin/pytest backend/tests/test_backend.py -k "active_http_basic_header_review or active_dns_osint or active_dns_inventory or active_tls_basic or active_nmap_basic"`:
  `352 passed, 338 deselected`;
- `.venv/bin/pytest backend/tests`: `774 passed`;
- `npm run test:run -- ActiveHttpBasicHeaderReviewPanel.test.tsx ActiveHttpBasicHeaderReviewJobReport.test.tsx reportHelpers.test.ts App.test.tsx dashboardFilters.test.ts`
  from `frontend/`: `5` files passed, `104` tests passed;
- `npm run test:run` from `frontend/`: `28` files passed, `196` tests
  passed;
- `npm run build` from `frontend/`: passed with the existing Vite chunk-size
  warning.

Final whitespace checks, staged diff checks, guardrail searches, and final git
status are completed as part of the commit closeout.

## Decision

`ACTIVE_HTTP_BASIC_HEADER_REVIEW_11_FUNCTIONAL_CLOSEOUT_ACCEPTED`
