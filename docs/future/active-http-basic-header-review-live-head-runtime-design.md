# Active HTTP Basic Header Review Live HEAD Runtime Design

Decision: `ACTIVE_HTTP_BASIC_HEADER_REVIEW_07_LIVE_HEAD_RUNTIME_DESIGN_ACCEPTED`

This is a docs-only design for the next possible
`active_http_basic_header_review` step after the accepted no-live phases. It
does not change backend, frontend, tools, archive, runner, storage, reports,
contracts, tests, Docker, Nmap, release, tag, or push state.

## Starting Point

The accepted no-live block already provides:

- disabled-by-default backend gating for
  `POST /active/web/http-basic-header-review`;
- the exact `live_http_basic_header_review` /
  `http_headers_single_request` contract;
- persisted owner-scoped no-live jobs for accepted submissions;
- redaction-first API, report, export, Raw JSON, and frontend surfaces;
- frontend copy that states no HTTP request is performed yet.

The next design may add only one live `HEAD` request for accepted jobs. It
must preserve the current no-live behavior unless the live HEAD flag described
below is explicitly enabled.

## Runtime Objective

The future runtime objective is narrow:

- accept one already-validated, authorized URL submission;
- send at most one HTTP `HEAD` request;
- follow no redirects;
- read no response body;
- derive conservative HTTP header review indicators;
- persist only redacted, bounded result fields;
- keep manual validation required.

The capability remains a review aid. Output must not claim confirmed
vulnerability evidence, exploit evidence, safe posture, or complete assessment.

## Execution Boundary

The existing feature flag may continue to gate the panel and no-live job
contract. Live request behavior should require a second disabled-by-default
flag, proposed as:

```text
INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_LIVE_HEAD_ENABLED=false
```

Required execution gates:

- existing capability flag enabled;
- live HEAD flag enabled;
- existing request contract valid with no extra fields;
- explicit authorization confirmation present;
- direct-control or delegated-permission confirmation present;
- live HTTP request confirmation present;
- target policy passes before any network attempt.

Malformed, disabled, missing-approval, and policy-blocked submissions should
continue to avoid job creation and send zero requests.

## Transport Proposal

Prefer a small injectable transport boundary for this HTTP-only capability:

- default adapter keeps the current no-live result;
- fake adapter is used by tests and smoke checks by default;
- live adapter is available only behind both flags;
- fixed method `HEAD`;
- fixed outbound headers only, such as a product User-Agent and `Accept: */*`;
- bounded timeout, suggested maximum `5` seconds;
- no redirects;
- no retries in v1;
- no request body;
- no custom operator-supplied headers;
- no browser-side request path.

The live adapter should count `network_requests_sent: 1` only after the `HEAD`
request is attempted. Pre-request blocks keep `network_requests_sent: 0`.

## Target Policy

The live design should preserve the current contract shape:

- one URL string only;
- scheme must be `http://` or `https://`;
- root path only, either empty or `/`;
- no query in public display;
- no fragment;
- no URL credentials or userinfo;
- no custom port;
- no wildcard, range, CIDR, pasted list, or generated target;
- maximum URL length remains `2048` characters.

Before the `HEAD` request, the live adapter should perform a bounded resolver
guard with capped answers and fail closed for metadata, control-plane,
loopback, link-local, multicast, unspecified, broadcast, and private-address
answers. Private or loopback target relaxation is not part of this design and
would require a separate local-lab decision.

## Redirect Policy

Redirects are observed only:

- do not follow redirects;
- do not resolve redirect targets;
- do not contact redirect targets;
- do not persist a raw `Location` value;
- record only status class, redirect-present boolean, and
  location-header-present boolean.

`HEAD` responses such as `405` or `501` must not trigger a `GET` fallback in
v1.

## Header Handling

Header processing should be allowlist-first and value-minimizing:

- cap total response-header bytes before derivation;
- never read or store a body;
- never persist raw response headers;
- derive security-header presence booleans for a small allowlist, such as
  HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and
  Permissions-Policy;
- record `Server` as present or absent only;
- record `Set-Cookie` as present or absent, with capped cookie count and
  aggregate attribute booleans only;
- redact cookie names, cookie values, tokens, credentials, redirect URLs,
  exception text, and unknown sensitive header values;
- cap and count truncated or redacted header material.

Public wording should use `HTTP header review indicator` and require manual
validation.

## Statuses

Pre-request outcomes should preserve the current controlled states:

- `blocked_unconfigured`;
- `blocked_missing_approval`;
- `blocked_by_policy`;
- `not_executed` for no-live/default adapter behavior.

Accepted live jobs may use:

- job status `completed` with result status `observed` when a bounded response
  is captured;
- job status `failed` with result status `request_failed` for controlled
  network errors after the attempt starts;
- job status `timed_out` with result status `timed_out` for bounded request
  timeout after the attempt starts.

Error and timeout results must avoid raw exception text, raw target display,
raw headers, and raw redirect values.

## Persistence And Reporting

Persist only owner-scoped, redacted, bounded fields:

- `target` and `target_display` stay `[REDACTED_TARGET]`;
- method `HEAD`;
- request counters and booleans;
- status code and status class when available;
- redirect-present booleans only;
- allowlisted header-presence indicators;
- redacted/truncated counters;
- controlled reason codes and error codes;
- manual-validation and caveat text.

Reports, exports, summaries, list/detail payloads, and Raw JSON must not expose
the submitted URL, host, path, query, fragment, credentials, raw response
headers, cookie names or values, redirect location, response body, or raw
exception text.

## Deferred Sources And Orchestration

Passive-DNS dataset work and DNS-provider connector work remain deferred
because they introduce source credentials, quota behavior, provenance, retention, and
administrator-access questions that are separate from one authorized HTTP
request.

Archive/run-all stays outside this path because this action is live,
operator-confirmed traffic, not bulk replay or automatic project analysis.

`tools/runner/main.py` remains outside this path because it is the passive
runner boundary. This capability should not be added to that monolith.

## Implementation Test Plan

A future implementation microphase should use fake transports by default and
cover:

- disabled flags create no job and send zero requests;
- no-live behavior remains unchanged when only the existing flag is enabled;
- malformed, extra-field, missing-approval, and policy-blocked inputs create no
  job and send zero requests;
- live adapter sends exactly one `HEAD` request for an accepted target;
- no redirect following, no body read, no retry, and no `GET` fallback;
- resolver guard blocks disallowed address classes before HTTP;
- timeout and controlled network errors are redacted and bounded;
- response-header derivation stores only allowlisted indicators;
- reports, exports, API responses, summaries, and Raw JSON keep target and
  header redaction;
- source searches confirm no archive/run-all path or `tools/runner/main.py`
  path changed.

No live external network smoke is approved by this document.

## Not Approved

This design does not approve:

- backend, frontend, tools, archive, or runner code changes in this phase;
- browser-side target requests;
- `GET` fallback;
- redirects;
- response-body reads;
- retries;
- request bodies;
- custom headers;
- authentication inputs;
- cookies as input;
- JavaScript execution;
- crawler behavior;
- forms;
- screenshots;
- technology fingerprint expansion;
- version-to-CVE mapping;
- exploit checks;
- Nmap;
- Docker use;
- target generation or fanout;
- passive-DNS sources;
- DNS-provider connectors;
- archive/run-all behavior;
- `tools/runner/main.py` behavior;
- storage of raw URL, raw response headers, cookie values, redirect locations,
  response bodies, or raw exception text.

## Suggested Next Microphase

```text
ACTIVE_HTTP_BASIC_HEADER_REVIEW_08_BACKEND_LIVE_HEAD_TRANSPORT_GATE
```

That phase should add the disabled-by-default live HEAD gate with fake-transport
tests first, while preserving the no-live default path.

## Decision Marker

`ACTIVE_HTTP_BASIC_HEADER_REVIEW_07_LIVE_HEAD_RUNTIME_DESIGN_ACCEPTED`
