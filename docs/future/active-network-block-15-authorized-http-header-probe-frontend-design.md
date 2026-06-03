# Active Network Block 15 Authorized HTTP Header Probe Frontend Design

Status: `ACTIVE_HTTP_HEADER_PROBE_FRONTEND_DESIGNED_NO_UI_RUNTIME`.

Base review: `docs/future/active-network-block-14-end-to-end-authorized-http-header-probe-contract-redaction-review.md`

Backend base: `docs/future/active-network-block-13-authorized-http-header-probe-runner-backend-no-frontend.md`

Original design: `docs/future/active-network-block-12-authorized-http-header-probe-design.md`

Commit scope: docs-first frontend design only. This document does not implement frontend runtime, backend changes, runner changes, endpoint calls, live traffic, DNS resolution, sockets, Nmap, subprocesses, or new jobs.

## A. Starting State

The backend endpoint already exists:

```text
POST /active/network/http-header-probe
```

The backend remains disabled by default:

```text
INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED=false
```

The backend-only review passed with:

```text
ACTIVE_HTTP_HEADER_PROBE_E2E_REVIEW_PASSED_BACKEND_ONLY
```

The implemented job type is:

```text
active_http_header_probe
```

There is no frontend control for this live capability yet. This design freezes the future UI shape before implementation.

## B. UX Placement

Options considered:

- Put the live control in the same `Active / Network` dashboard area beneath the dry-run panel.
- Put the live control in a separate panel named `Authorized HTTP Header Probe`.
- Add a future route dedicated to Active checks.

Decision for the next implementation block:

- Use the same dashboard zone as `Active / Network dry-run`.
- Render a separate panel titled `Authorized HTTP Header Probe`.
- Add a visible `Live request` warning badge.
- Keep it visually distinct from dry-run planning.
- Do not add it to uploaded file or archive action groups.
- Do not auto-run it from a dry-run result.

This keeps target-based Active workflows discoverable while avoiding confusion with passive archive reviews.

## C. Critical Distinction From Dry-Run

The UI must clearly state:

- dry-run sends no network traffic;
- the header probe sends one authorized HTTP `HEAD` request;
- the user must explicitly confirm live traffic;
- the action is not Nmap;
- the action is not a broad scan;
- the action is not a port scan;
- the action is not crawling;
- the action is not vulnerability validation.

Recommended panel copy:

```text
Create a job for one authorized HTTP HEAD request to one explicit URL. This may be logged by the target. No redirects are followed and no response body is read.
```

## D. Form Fields

The future form should include:

- Target URL input.
  - Placeholder: `https://example.test/`
  - Required.
  - Must communicate that only explicit `http://` or `https://` URLs are accepted.
- Mode display.
  - `live_header_probe`
- Profile display.
  - `http_header_probe`
- Method display.
  - `HEAD only`
- Limits display.
  - `max_targets=1`
  - `max_requests=1`
  - `timeout_seconds=3`
  - `max_redirects=0`
  - `response_body_bytes=0`
  - `max_response_header_bytes=32768`
  - `max_dns_answers=8`
  - `retries=0`
  - `concurrency=1`
- Authorization checkbox.
  - `I confirm I own or am authorized to test this target.`
- Live traffic checkbox.
  - `I understand this will send one HTTP HEAD request to the target.`
- Submit button.
  - Preferred: `Create authorized header probe job`
  - Acceptable: `Send authorized HEAD request`

Avoid these action labels and nearby command copy:

- `Scan`
- `Run Nmap`
- `Probe aggressively`
- `Test vulnerability`
- `Exploit`
- `Attack`

## E. Authorization UX

Both confirmations are required before submit is enabled. A target value alone is not authorization.

The panel should show a compact target summary before submit:

- normalized target display, redacted if needed;
- method: `HEAD`;
- max requests: `1`;
- redirects: `0`;
- body read: `0 bytes`;
- custom headers: `none`;
- authorization scope: `single-target`.

Warnings:

- Do not test third-party systems without permission.
- This request may be logged by the target.
- The request sends no body and reads no body.
- The authorization statement is a user assertion, not proof of ownership.

## F. Disabled State

If the backend returns `403` with:

```text
Active HTTP header probe is disabled in this environment.
```

the UI should show:

```text
Active HTTP header probe is disabled in this environment.
```

Optional supporting copy:

```text
This deployment has not enabled live header probes.
```

The disabled state must not include:

- `.env` editing guidance;
- bypass guidance;
- retry spam;
- target execution suggestions;
- claims that DNS or HTTP was attempted.

## G. Request Contract Frontend

The frontend helper should call:

```text
POST /active/network/http-header-probe
```

Request body:

```json
{
  "target": "https://example.test/",
  "authorization": {
    "confirmed": true,
    "live_traffic_confirmed": true,
    "statement": "I confirm I own or am authorized to test this target.",
    "scope": "single-target"
  },
  "mode": "live_header_probe",
  "profile": "http_header_probe",
  "limits": {
    "max_targets": 1,
    "max_requests": 1,
    "timeout_seconds": 3,
    "max_redirects": 0,
    "response_body_bytes": 0,
    "max_response_header_bytes": 32768,
    "max_dns_answers": 8,
    "retries": 0,
    "concurrency": 1
  }
}
```

No unknown fields. No custom headers. No cookies. No auth headers. No request body.

## H. Job Catalog And Filter

Future frontend metadata:

- Audit type: `active_http_header_probe`
- Label: `Authorized HTTP header probe`
- Category: `Active / Network`
- Source family: `target`
- Description: `Sends one authorized HTTP HEAD request and records redacted headers; no redirects or body read.`

This catalog entry must be separate from `active_network_dry_run`.

It must not appear in archive action groups and must not participate in passive archive run-all actions.

## I. Report UX

Future report component:

```text
ActiveHttpHeaderProbeJobReport
```

Recommended sections:

- Live Probe Scope Notice
- Target Summary
- Authorization Summary
- Policy Decision
- DNS Policy Summary
- Request Sent
- Response Headers
- Observations
- Findings
- Blocked Reasons
- Limits
- Audit Log
- Errors
- Redacted Raw JSON

Recommended badges:

- `Active / Network`
- `Live HEAD request`
- `Body not read`
- `Redirects not followed`

Required controlled copy:

- `One authorized HTTP HEAD request was sent.`
- `Response body was not read.`
- `Redirects were not followed.`
- `Header observations are review indicators, not confirmed vulnerabilities.`

For blocked results or pre-request failures:

```text
No HTTP request was sent.
```

Queued, running, failed, sparse, malformed, blocked, and legacy payloads must render without breaking.

## J. Header Display And Redaction

The header table should show:

- header names;
- redacted or truncated values;
- redacted header count;
- truncated header count;
- response header byte limit when present.

The UI must never show raw values for:

- `Set-Cookie`;
- `Cookie`;
- `Authorization`;
- `Proxy-Authorization`;
- bearer/basic credentials;
- API keys;
- client secrets;
- password-like values;
- credential URLs;
- private key text.

Use the fixed placeholder:

```text
[REDACTED]
```

Do not show prefixes, suffixes, hashes, fingerprints, or reversible identifiers.

## K. Error States

The report and form should tolerate controlled states for:

- disabled backend;
- authorization missing;
- live confirmation missing;
- target rejected;
- DNS failed;
- resolved IP blocked;
- timeout;
- TLS error;
- connection refused;
- HEAD not allowed;
- response headers too large;
- controlled network error;
- sparse or malformed result.

Copy should remain factual and calm. It should not imply the target is unsafe, safe, exploitable, compromised, or validated.

## L. Redaction UX

Frontend redaction must cover form feedback, job table target display, report sections, errors, observations, findings, response headers, and Raw JSON for:

- URL userinfo;
- sensitive query parameters;
- response headers;
- cookies;
- bearer/basic values;
- API keys;
- passwords;
- tokens;
- client secrets;
- private key blocks;
- `PRIVATE KEY` text;
- legacy payload fields.

Frontend redaction complements backend/API/export redaction. It does not replace backend-side redaction.

## M. Forbidden Copy

Controlled UI copy must avoid:

- vulnerability confirmed;
- target is safe;
- credential valid;
- exploit;
- attack;
- bypass;
- evade;
- Nmap scan;
- port scan;
- crawl;
- fuzz;
- brute force.

Preferred words:

- authorized;
- HEAD request;
- header observations;
- review indicators;
- no body read;
- no redirects followed.

## N. Future Tests

Expected frontend tests for the implementation block:

- form renders separately from dry-run;
- both checkboxes are required;
- submit is disabled until target plus both confirmations are present;
- request body is exact and has no unknown fields;
- `403` disabled backend state is controlled and avoids `.env` guidance;
- audit catalog/filter entry exists for `active_http_header_probe`;
- report renders live HEAD copy;
- report renders DNS policy summary;
- report renders response headers with redaction;
- report renders `body_read=false` or equivalent body-read summary;
- report renders `body_bytes_read=0`;
- report renders `redirects_followed=0`;
- blocked report says `No HTTP request was sent.`;
- queued/running/failed/sparse/malformed jobs do not break;
- Raw JSON is redacted;
- DOM does not contain fixture secrets;
- forbidden copy is absent;
- no archive action integration exists;
- dry-run panel remains no-network and separate.

Suggested fixture secrets:

- `super-secret-password`
- `token_should_never_render`
- `raw-api-key-123456`
- `Authorization: Bearer token_should_never_render`
- `http://user:pass@example.com`
- `session_should_not_render`
- `cookie_should_not_render`
- `-----BEGIN PRIVATE KEY-----`
- `PRIVATE KEY`

## O. No-Scope

This block does not implement:

- frontend runtime;
- backend changes;
- runner changes;
- endpoint calls;
- live traffic;
- DNS resolution;
- sockets;
- Nmap;
- redirects;
- body reads;
- custom headers;
- auth headers;
- cookies;
- archive actions;
- `.env` guidance or reads.

Future implementation must not add:

- broad scan behavior;
- Nmap runtime;
- port checks;
- crawling;
- fuzzing;
- credential validation;
- exploitability claims;
- automatic execution from dry-run results.

## P. Decision

Final decision:

```text
ACTIVE_HTTP_HEADER_PROBE_FRONTEND_DESIGNED_NO_UI_RUNTIME
```

The frontend design is accepted for a future implementation block. That next block may implement UI and tests, but must preserve the one-HEAD contract, double authorization, disabled-by-default behavior, redaction, no archive integration, and no Nmap/no-subprocess/no-body-read constraints.

## Next Microphase

Completed next microphase:

```text
ACTIVE-NETWORK-BLOCK-16-AUTHORIZED-HTTP-HEADER-PROBE-FRONTEND-IMPLEMENTATION
```

Implementation record: `docs/future/active-network-block-16-authorized-http-header-probe-frontend-implementation.md`

That block implements the designed UI and tests without changing backend, runner, or the live probe contract.
