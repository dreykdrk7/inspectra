# Active Network Block 12 Authorized HTTP Header Probe Design

Status: `ACTIVE_HTTP_HEADER_PROBE_DESIGNED_NO_RUNTIME`.

Implementation note: the first runner/backend implementation was added later in
`docs/future/active-network-block-13-authorized-http-header-probe-runner-backend-no-frontend.md`.
This file remains the historical docs-first design reference.

Base hardening review: `docs/future/active-network-block-11-dry-run-hardening-review.md`

Commit scope: docs-first design only. This document does not implement backend, frontend, runner, jobs, HTTP clients, DNS resolution, sockets, subprocesses, Nmap, or live traffic.

## A. Starting State

`active_network_dry_run` v0 is closed as a no-network planning capability.

The dry-run hardening review accepted the surface for docs-first live-probe design:

```text
ACTIVE_DRY_RUN_HARDENING_ACCEPTED_FOR_LIVE_PROBE_DESIGN
```

This does not approve runtime implementation. It only permits designing the first live probe.

The first live candidate is an authorized HTTP Header Probe. It is intentionally scoped before any Nmap work. Nmap remains out of runtime, out of implementation scope, and out of this design except as an explicit no-scope item.

## B. Probe Objective

The HTTP Header Probe should make one minimal, explicitly authorized HTTP/HTTPS header request to a single target URL under strict limits.

The probe is intended to collect response header observations for defensive review. It must not:

- send payloads;
- fuzz paths, parameters, or headers;
- authenticate;
- send request bodies;
- read response bodies;
- crawl;
- exploit;
- validate credentials;
- run Nmap;
- claim exploitability or confirmed vulnerability.

The first implementation should be small enough to audit by reading the code and tests.

## C. Allowed Method

Decision for v0:

```text
HEAD only. No GET fallback.
```

Rationale:

- HEAD usually avoids response body transfer.
- One request is easier to count and audit.
- No fallback avoids hidden additional traffic.
- No fallback avoids accidentally downloading large bodies.
- A `405 Method Not Allowed`, `501 Not Implemented`, timeout, or controlled connection error should be recorded as an error/observation, not followed by GET.

Future designs may consider GET fallback only after separate review and explicit limits.

## D. Live Target Policy

Allowed target form:

- one explicit `http://` or `https://` URL;
- host must be explicit;
- path is allowed but not crawled;
- single public IP is allowed only when provided as a URL with `http` or `https` scheme and it passes the blocked-address policy.

Rejected target forms:

- CIDR ranges;
- IP ranges;
- wildcards;
- URL userinfo;
- private/internal addresses;
- loopback addresses;
- metadata targets;
- link-local addresses;
- multicast, broadcast, or unspecified addresses;
- non-HTTP schemes such as `file:`, `ftp:`, `ssh:`, `gopher:`, or `data:`;
- shell-like or suspicious input;
- multiple targets;
- target lists.

### DNS Resolution

Unlike dry-run, a live hostname probe may require DNS resolution. The v0 design allows DNS only as a bounded target-safety step.

DNS requirements:

- DNS resolution must happen only after feature flag and authorization checks pass.
- DNS resolution must be bounded by a short timeout.
- DNS answer count must be capped.
- Every resolved IP address must be checked against blocked classes before request.
- If any resolved address is private, loopback, metadata, link-local, multicast, broadcast, unspecified, or otherwise blocked, the probe must fail closed and send no HTTP request.
- If multiple IPs are returned, all must be allowed or the probe must fail closed.
- DNS results should be stored minimally: answer count, address families/classes, and policy outcome. Avoid storing full address lists unless needed for audit; if stored, treat them as target metadata and redact consistently in public views.
- No custom recursive DNS configuration in v0.
- No DNS brute force, wildcard checks, reverse DNS, zone transfer, or third-party resolver APIs.

## E. Authorization

The live header probe must require two explicit confirmations.

Authorization statement:

```text
I confirm I own or am authorized to test this target.
```

Live traffic confirmation:

```text
I understand this will send one HTTP HEAD request to the target.
```

Requirements:

- frontend checkbox or API fields must capture both confirmations;
- target summary must be shown before execution;
- mode must be explicit, such as `live_header_probe`;
- profile must be explicit, such as `http_header_probe`;
- target alone is not authorization;
- no auto-run from dry-run output;
- no proof-of-ownership claim;
- authorization is a user assertion and audit record, not verification that the user owns the target.

## F. Feature Flag

New feature flag:

```text
INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED=false
```

Default:

```text
false
```

This flag must be separate from:

```text
INSPECTRA_ACTIVE_DRY_RUN_ENABLED
```

Rationale:

- dry-run enablement must not imply live traffic enablement;
- operators can keep dry-run available while live probes remain disabled;
- tests can assert disabled live mode creates no request and no job side effect beyond controlled rejection, depending on final endpoint pattern.

## G. Limits V0

Strict limits for v0:

| Limit | Value |
| --- | --- |
| `max_targets` | `1` |
| `max_requests` | `1` |
| `method` | `HEAD` only |
| `timeout_seconds` | `3` default, `5` maximum |
| `max_redirects` | `0` |
| `response_body_bytes` | `0` |
| `max_response_header_bytes` | `32768` |
| `max_dns_answers` | small cap, recommended `8` |
| retries | `0` |
| concurrency | `1` |
| global deadline | small, recommended `5` seconds |

Limits are part of policy. If the request asks for a value outside v0 policy, the probe should fail closed before DNS or HTTP.

## H. Redirect Policy

Decision for v0:

```text
Do not follow redirects.
```

If response status is `3xx`:

- record that a redirect was presented;
- record the `Location` header only after redaction and truncation;
- do not contact the redirect target;
- do not resolve the redirect target;
- set `redirect_followed: false`;
- set `redirects_followed: 0`.

Future redirect support requires a separate design covering target revalidation, scheme changes, redirect count, sensitive query redaction, and private-address checks for every hop.

## I. Headers Sent

Allowed request headers:

```text
User-Agent: Inspectra/<version> active-header-probe
Accept: */*
```

Not allowed in v0:

- arbitrary custom headers;
- Authorization;
- Proxy-Authorization;
- cookies;
- bearer/basic credentials;
- user-supplied header values;
- request body;
- POST/PUT/PATCH/DELETE/OPTIONS;
- content upload.

The implementation should centralize headers so tests can assert exact outgoing header names.

## J. Data Collected

Allowed data:

- normalized/redacted requested URL;
- target host and scheme;
- DNS policy outcome and minimal DNS answer metadata;
- HTTP status code;
- response header names;
- response header values after redaction/truncation;
- body read status, always `false`;
- body bytes read, always `0`;
- redirect presented flag;
- redirect followed flag, always `false` in v0;
- coarse timing, if implemented;
- controlled error codes/messages.

TLS handling:

- URL scheme may indicate whether HTTPS was requested.
- v0 should use the HTTP client's default certificate validation.
- v0 should not perform certificate scanning, certificate inventory, expiration analysis, SAN parsing, or TLS configuration assessment.

Not allowed:

- response body;
- raw cookie values;
- raw `Set-Cookie` values;
- raw Authorization-like headers;
- raw token-bearing query strings;
- full redirect chains;
- vulnerability confirmation;
- exploitability claims;
- target ownership claims.

## K. Header Redaction

Redact:

- `Set-Cookie` values;
- `Cookie`;
- `Authorization`;
- `Proxy-Authorization`;
- `X-Api-Key`;
- `API-Key`;
- bearer/basic credentials;
- tokens;
- session IDs;
- CSRF tokens;
- secrets in `Location` query params;
- any header value matching secret-like key/value or credential URL patterns.

Recommended storage:

- store header names;
- store redacted/truncated values;
- for `Set-Cookie`, store only `[REDACTED]` unless a later design proves safe cookie attribute summarization;
- record `redacted_headers_count`;
- record `truncated_headers_count`;
- never emit prefixes, suffixes, hashes, fingerprints, or reversible identifiers.

Fixed placeholder:

```text
[REDACTED]
```

## L. Findings / Indicators

Decision for v0:

```text
Observations first. Findings are optional and should be info/low only.
```

Preferred v0 observations:

- `server_header_present_info`;
- `set_cookie_present_redacted_info`;
- `redirect_present_not_followed_info`;
- `http_scheme_used_hint`;
- `security_header_absent_observation` for common headers only if clearly framed as low-confidence observation.

Possible low/info findings:

- `missing_security_header_hint`;
- `server_header_present_info`;
- `set_cookie_present_redacted_info`;
- `redirect_present_not_followed_info`;
- `http_not_https_hint`.

Hard wording rules:

- no confirmed vulnerability wording;
- no compromised/exploited claims;
- no credential-valid claims;
- no live exploitability claims;
- no severity inflation based on headers alone.

## M. Result Model

Proposed JSON shape:

```json
{
  "analyzer": "active_http_header_probe",
  "mode": "live_header_probe",
  "profile": "http_header_probe",
  "target": {
    "raw": "https://example.test/",
    "normalized": "https://example.test/",
    "scheme": "https",
    "host": "example.test",
    "port": 443,
    "classification": "public_hostname"
  },
  "authorization": {
    "confirmed": true,
    "live_traffic_confirmed": true,
    "statement_version": "active-authorization-v1",
    "live_statement_version": "active-live-head-v1",
    "scope": "single-target"
  },
  "policy": {
    "allowed": true,
    "policy_version": "active-network-v1-http-header-probe",
    "blocked_reasons": [],
    "warnings": []
  },
  "limits": {
    "max_targets": 1,
    "max_requests": 1,
    "method": "HEAD",
    "timeout_seconds": 3,
    "max_redirects": 0,
    "response_body_bytes": 0,
    "max_response_header_bytes": 32768,
    "max_dns_answers": 8,
    "retries": 0,
    "concurrency": 1
  },
  "dns": {
    "resolved": true,
    "answers_count": 1,
    "all_answers_allowed": true,
    "blocked_answers_count": 0
  },
  "request": {
    "method": "HEAD",
    "url": "https://example.test/",
    "headers_sent": {
      "User-Agent": "Inspectra active-header-probe",
      "Accept": "*/*"
    },
    "body_sent": false
  },
  "response": {
    "status_code": 200,
    "headers": [
      {
        "name": "Server",
        "value": "example"
      },
      {
        "name": "Set-Cookie",
        "value": "[REDACTED]"
      }
    ],
    "headers_bytes": 128,
    "body_read": false,
    "body_bytes_read": 0,
    "redirect_presented": false,
    "redirect_followed": false
  },
  "observations": [],
  "findings": [],
  "audit_log": [],
  "errors": [],
  "summary": {
    "network_requests_sent": 1,
    "redirects_followed": 0,
    "body_bytes_read": 0,
    "headers_received_count": 2,
    "redacted_headers_count": 1,
    "truncated_headers_count": 0
  }
}
```

Blocked results should use the same top-level shape where practical, with `policy.allowed: false`, `network_requests_sent: 0`, and controlled `blocked_reasons`.

## N. Live Audit Log

Audit log events should include:

- request received;
- feature flag checked;
- authorization checked;
- target parsed;
- target normalized;
- DNS resolution started;
- DNS resolution completed;
- resolved addresses checked;
- policy evaluated;
- HTTP HEAD request started;
- response headers received;
- response headers redacted;
- request completed;
- timeout/error recorded when applicable.

The audit log must not store secrets. It should store reason codes and safe counters rather than raw sensitive values.

## O. Error States

Controlled error states:

- `active_http_header_probe_disabled`;
- `authorization_missing`;
- `live_traffic_confirmation_missing`;
- `target_required`;
- `target_rejected`;
- `unsupported_scheme`;
- `url_credentials_rejected`;
- `target_cidr_rejected`;
- `target_range_rejected`;
- `wildcard_rejected`;
- `private_range_blocked`;
- `loopback_requires_local_lab`;
- `metadata_target_blocked`;
- `resolved_ip_blocked`;
- `dns_resolution_failed`;
- `dns_answers_limit_exceeded`;
- `timeout`;
- `tls_error`;
- `connection_refused`;
- `head_not_allowed`;
- `response_headers_too_large`;
- `redirect_not_followed`;
- `controlled_network_error`.

Copy must be safe and should not suggest bypasses, retries against third-party targets, or instructions for evading policy.

## P. Reporting / Frontend Expectations

The live header probe report should be separate from `ActiveDryRunJobReport`.

Expected report copy:

```text
One authorized HTTP HEAD request was sent.
```

Expected sections:

- General summary;
- target summary;
- authorization summary;
- policy decision;
- DNS policy summary;
- limits;
- request sent;
- response headers, redacted;
- observations;
- findings, if any;
- audit log;
- controlled errors;
- Redacted Raw JSON.

The report must show:

- live probe badge;
- `network_requests_sent`;
- `body_read: false`;
- `body_bytes_read: 0`;
- `redirect_followed: false`;
- redacted headers;
- no vulnerability confirmation.

Exports should include the same sections with the same redaction.

## Q. Future Tests

Runner/backend tests:

- feature flag disabled creates no request;
- missing authorization creates no request;
- missing live traffic confirmation creates no request;
- private IP blocked creates no request;
- loopback blocked creates no request;
- metadata target blocked creates no request;
- CIDR/range/wildcard blocked creates no request;
- DNS resolving to private IP blocks before request;
- multiple DNS answers fail closed if any answer is blocked;
- one HEAD request is sent for a valid local test server only;
- no GET fallback on `405`, `501`, timeout, or controlled network error;
- redirects are not followed;
- response body is not read;
- header values are redacted;
- `Set-Cookie` raw value is not stored;
- Authorization-like response headers are redacted;
- `Location` query params are redacted;
- timeout is controlled;
- header byte cap is enforced;
- `network_requests_sent` becomes `1` only after the request is actually sent;
- blocked/error-before-request cases report `network_requests_sent: 0`;
- no Nmap imports/runtime;
- no subprocess probes;
- no broad ranges;
- API responses and exports redact legacy payloads.

Frontend tests:

- live probe form requires both confirmations;
- dry-run enablement does not expose live probe controls;
- live disabled state is controlled;
- report renders summary, DNS policy, request, response headers, observations, audit log, errors, and Redacted Raw JSON;
- sparse/running/failed/malformed payloads do not break;
- DOM and Raw JSON do not contain cookie/token/auth/private-key fixture values.

Test environment rule:

- live request-count tests may use only a local in-process test server or mocks;
- no external network tests;
- no Docker, Nmap, DNS brute force, or third-party targets in tests.

## R. Implementation Gates

Before implementation starts, decide:

- HTTP client library;
- DNS resolution strategy and timeout;
- whether full resolved IPs are stored or only counts/classes;
- exact endpoint path;
- exact job type;
- exact frontend panel placement;
- exact report component name;
- exact test server/mocking strategy.

Implementation gates:

- new feature flag defaults false;
- tests prove disabled flag sends no traffic;
- tests prove authorization failures send no traffic;
- tests prove request count;
- tests use local test server only;
- no external network in tests;
- no arbitrary headers;
- no body read;
- no redirect following;
- update security scope before runtime enablement.

## S. No-Scope

- No Nmap.
- No port scanning.
- No multiple targets.
- No CIDR.
- No ranges.
- No wildcard targets.
- No GET fallback.
- No response body read.
- No POST, PUT, PATCH, DELETE, OPTIONS, or custom methods.
- No custom user headers.
- No authentication.
- No cookies.
- No brute force.
- No fuzzing.
- No exploit.
- No credential validation.
- No certificate scanning.
- No screenshot or browser automation.
- No crawling.
- No JavaScript execution.
- No third-party target without authorization.
- No Passive refactor.
- No `tools/runner/main.py` changes.
- No Nmap design or implementation inside this probe.

## T. Decision Field

Final decision:

```text
ACTIVE_HTTP_HEADER_PROBE_DESIGNED_NO_RUNTIME
```

Next recommended microphase:

```text
ACTIVE-NETWORK-BLOCK-13-AUTHORIZED-HTTP-HEADER-PROBE-RUNNER-BACKEND-NO-FRONTEND
```

That next phase should still be gated, local-test-only, no Nmap, no body-read, and no external-network-test.
