# Active HTTP Basic Header Review Design

Decision: `ACTIVE_HTTP_BASIC_HEADER_REVIEW_01_DESIGN_ACCEPTED`

This document freezes a docs-only design for a future
`active_http_basic_header_review` capability. It does not add an endpoint,
feature flag, request contract, model, storage, report, export, UI, test,
runtime behavior, Docker behavior, Nmap behavior, network request, release,
tag, or push state.

## Product Purpose

`active_http_basic_header_review` is a future Active capability for a single
authorized web-edge review. Its purpose is to capture bounded HTTP response
header and redirect-posture observations for defensive operator review.

The capability should produce review indicators only:

- HTTP header review indicators;
- redirect posture review indicators;
- cookie attribute review indicators only when a `Set-Cookie` header is
  present and redacted;
- server header exposure review indicators.

Manual validation is always required. Results must not be worded as confirmed
security findings, proof of exploitability, safe-target conclusions, or
complete assessment claims.

## Capability Boundary

The future capability must remain:

- disabled by default;
- opt-in for trusted local/private/self-hosted deployments;
- one submitted target per accepted job;
- one bounded HTTP request for v1;
- one explicit operator authorization flow;
- owner-scoped and redaction-first.

Preferred v1 method behavior:

- use `HEAD` as the default method where appropriate;
- define no automatic fallback for v1 unless a later design explicitly freezes
  a bounded fallback policy;
- do not read response bodies.

The capability must not include crawling, JavaScript execution, forms,
authentication, cookies as input, custom headers, request bodies, credential
validation, exploit checks, version-to-CVE mapping, target expansion, port
scanning, or Nmap.

## Proposed Names

These names are design proposals only:

- feature flag:
  `INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_ENABLED=false`;
- endpoint: `POST /active/web/http-basic-header-review`;
- job type: `active_http_basic_header_review`;
- report wording: `HTTP header review indicator`.

The final implementation phase may adjust names only through a separate
contract gate or implementation decision.

## Request Contract Proposal

Proposed exact fields:

```json
{
  "mode": "live_http_basic_header_review",
  "profile": "http_headers_single_request",
  "target": "https://example.com/",
  "method": "HEAD",
  "authorization_confirmed": true,
  "target_control_confirmed": true,
  "delegated_permission_confirmed": false,
  "live_http_request_confirmed": true
}
```

Contract rules:

- `mode` must be `live_http_basic_header_review`;
- `profile` must be `http_headers_single_request`;
- `target` must be one explicit `http://` or `https://` URL;
- `method` must be `HEAD` for v1 unless a later design adds a bounded
  alternative;
- `authorization_confirmed` must be `true`;
- either `target_control_confirmed` or `delegated_permission_confirmed` must be
  `true`;
- `live_http_request_confirmed` must be `true`;
- extra fields should fail closed.

Target shape rules:

- URL only, not a bare host;
- scheme must be `http` or `https`;
- no wildcard;
- no IP range;
- no CIDR;
- no pasted list;
- no URL credentials or userinfo;
- no fragment;
- no query string in public display;
- no custom port unless a later design explicitly allowlists and justifies it;
- bounded URL length, suggested maximum `2048` characters;
- one target only.

## Target Policy

The expected deployment shape is local/private/self-hosted operation by a
trusted operator. The operator must provide one explicit authorized target and
confirm either direct control or delegated permission.

Redirect posture for v1 should be review-only:

- do not follow redirects;
- do not resolve redirect targets;
- do not contact redirect targets;
- record only that a redirect was presented and a redacted/truncated redirect
  indicator when safe.

The future runtime must not automatically expand from:

- redirects;
- response headers;
- links;
- DNS names;
- TLS certificate names;
- cookies;
- server banners;
- OSINT observations;
- uploaded files or archive contents.

The capability must not hand off to DNS, TLS, Nmap, archive/run-all,
`tools/runner/main.py`, provider import, or passive DNS. It must not resolve or
scan adjacent hosts.

## Runtime Model Proposal

If implemented later, runtime should be isolated in one clearly named backend
module, for example:

```text
backend/app/active_http_basic_header_review.py
```

Runtime requirements:

- real network behavior disabled unless the feature flag, auth, owner scope,
  contract validation, target policy, and confirmations all pass;
- fake or injectable transport for tests;
- no browser-side target request from the frontend;
- short timeout cap, suggested default `3` seconds and maximum `5` seconds;
- response-header size cap, suggested `32768` bytes;
- zero response body bytes read for v1;
- no retries for v1;
- no redirect following for v1;
- no raw exception text persisted or rendered;
- controlled error/status mapping.

DNS safety policy may be needed for future runtime if hostnames are accepted,
but it should be designed in the implementation phase with fail-closed checks,
bounded resolution, redacted metadata, and no DNS discovery behavior.

## Result Model Proposal

Suggested statuses:

- `blocked_unconfigured`;
- `blocked_missing_approval`;
- `blocked_by_policy`;
- `not_executed`;
- `completed_review`;
- `client_error_controlled`;
- `timeout`;
- `connection_failed`;
- `unsupported_response`.

Suggested review sections:

- transport/security header presence indicators;
- redirect indicator with `redirect_followed: false`;
- cookie/security attribute indicator only when `Set-Cookie` is present and
  redacted;
- server header exposure review indicator;
- limits and caveats;
- manual validation required.

Reports should avoid confirmed-security wording, proof claims, and safe/unsafe
target conclusions. Missing or present headers are review context for a human,
not a final verdict.

## Redaction Boundary

Public and owner-visible surfaces should preserve:

- target display as `[REDACTED_TARGET]`;
- no raw URL;
- no query string;
- no URL credentials or userinfo;
- no cookies;
- no tokens;
- no authorization headers;
- no raw redirect location when it contains a path, query, fragment, userinfo,
  or different host;
- no raw server exception;
- no response body;
- no full raw headers when sensitive header names or values appear;
- wrong-owner reads, exports, deletes, and Raw JSON access as generic not
  found.

Header values should be allowlisted, redacted, or summarized rather than
dumped wholesale. `Set-Cookie`, `Authorization`, `Proxy-Authorization`,
`Location`, security tokens, session values, and credential-shaped values must
be treated as sensitive.

## Reporting And Frontend Expectations

Future reports and exports should use `HTTP header review indicator` wording
and include `Manual validation required`.

Frontend expectations:

- submit only the backend contract;
- never perform a browser-side request to the target;
- keep target display redacted;
- render controlled statuses and caveats;
- keep Raw JSON redaction-first;
- avoid copy that suggests final security conclusions.

Markdown, HTML, XML, PDF, Raw JSON, list, detail, and frontend report surfaces
must share the same redaction boundary.

## Future Test Plan

Implementation phases should add focused coverage for:

- backend contract validation;
- feature flag disabled behavior;
- missing confirmation behavior;
- target policy rejection;
- fake transport success;
- timeout, connection failure, refused connection, and controlled client
  errors;
- unsupported or malformed response metadata;
- redaction for URL, query string, credentials, cookies, tokens, authorization
  headers, redirect locations, server headers, and exceptions;
- owner scope and wrong-owner generic responses;
- report/export/Raw JSON redaction;
- frontend contract and rendering in a later frontend phase.

Tests should use fake or injected transports by default. No live HTTP, DNS,
TLS, CT, Docker, Nmap, or external target behavior is required for this design.

## Explicitly Not Approved

This design does not approve:

- crawling;
- JavaScript execution;
- screenshots;
- request bodies;
- `POST`, `PUT`, `PATCH`, or `DELETE`;
- authentication;
- cookies or custom headers as input;
- form submission;
- directory brute force;
- content discovery;
- fingerprinting beyond bounded header indicators;
- version-to-CVE mapping;
- exploit checks;
- proof-of-vulnerability claims;
- safe-target claims;
- Nmap or port scanning;
- DNS OSINT, passive DNS, or provider import;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- hosted scanning product behavior.

## Suggested Next Phase

Recommended next microphase:

```text
ACTIVE_HTTP_BASIC_HEADER_REVIEW_02_BACKEND_CONTRACT_GATE
```

That phase should add only a disabled-by-default backend contract gate if the
operator chooses to proceed. It should create no network request path until a
separate runtime phase freezes target policy, fake transport coverage,
redaction, and controlled result mapping.

## Final Decision

```text
ACTIVE_HTTP_BASIC_HEADER_REVIEW_01_DESIGN_ACCEPTED
```

`active_http_basic_header_review` is accepted as a future docs-first design
only: disabled by default, one authorized URL, one bounded header request,
review-indicator wording, manual validation, no crawling, no browser-side
target request, and redaction-first reporting.
