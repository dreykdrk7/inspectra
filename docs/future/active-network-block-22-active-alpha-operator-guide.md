# Active Network Block 22 Active Alpha Operator Guide

Status: `ACTIVE_LIMITED_LIVE_OPERATOR_GUIDE_ACCEPTED`.

Base checkpoint: `docs/future/active-network-block-21-active-alpha-checkpoint-release-planning.md`

Local smoke method: `docs/future/active-network-block-20-limited-live-smoke-run-local.md`

Limited live closeout: `docs/future/active-network-block-18-authorized-http-header-probe-closeout.md`

Commit scope: docs-only internal operator guide. This block does not change backend, frontend, runner, tests, fixtures, feature flags, target policy, tags, releases, or runtime behavior.

## Purpose

This guide is for trusted internal operators who need to understand how to use, interpret, and limit the current Active alpha surfaces.

Active alpha is not production readiness, external-user readiness, a general vulnerability scanner, an ownership-verification system, a credential validation tool, or approval for broader live testing.

The guide preserves the current closed scope:

- Active dry-run is no-network planning.
- `active_http_header_probe` is the only limited live capability.
- The live capability remains opt-in, disabled by default, double-confirmed, and limited to at most one HTTP `HEAD` request to one explicitly authorized `http://` or `https://` target.
- No Nmap, port scanning, crawling, redirects, response body reads, GET fallback, custom headers, auth/cookies, fuzzing, exploitation, credential validation, or target expansion is included.

## Available Capabilities

### `active_network_dry_run`

Use this surface to preview an Active plan without network behavior.

Expected properties:

- target-based job;
- `file_id: null`;
- no DNS;
- no HTTP;
- no sockets;
- no subprocess probes;
- no Nmap;
- `network_requests_sent: 0`;
- policy and blocked reasons are planning outputs, not live observations.

### `active_http_header_probe`

Use this surface only when a trusted operator is explicitly authorized to test the single target.

Expected properties:

- target-based job;
- `file_id: null`;
- feature-flag gated;
- disabled by default;
- explicit authorization confirmation required;
- explicit live-traffic confirmation required;
- one explicit `http://` or `https://` URL;
- no URL userinfo;
- bounded DNS safety checks only after validation;
- fail-closed behavior for blocked resolved addresses;
- at most one HTTP `HEAD` request;
- no redirects;
- no response body read;
- no GET fallback;
- no custom headers;
- no auth/cookies;
- no crawling;
- no port scanning;
- no Nmap.

This is the only live Active alpha capability.

## Before Enabling

Before enabling live probing in a trusted environment, confirm:

- The operator is trusted and understands the Active alpha limits.
- The target is owned by the operator or explicitly authorized for this exact check.
- The live feature flag is enabled only in the intended trusted environment through that environment's normal deployment mechanism.
- The operator understands that one HTTP `HEAD` request may be visible in target logs.
- The target does not include credentials, secrets, URL userinfo, session tokens, bearer tokens, API keys, passwords, or sensitive query parameters.
- No third-party target is used as a demo target.
- Local result retention is acceptable for targets, summaries, response metadata, controlled errors, reports, exports, and Raw JSON.
- Redaction is understood as defensive and best-effort.
- Authorization is understood as a user assertion, not proof of ownership.
- Production loopback/private target blocking remains unchanged.
- The Block 20 test-double smoke method remains the accepted local verification method.

This guide intentionally does not provide `.env` editing instructions, bypass instructions, demo targets, or third-party target suggestions.

## Interpreting Results

Treat all results as review indicators.

- Missing headers are review indicators, not confirmed vulnerabilities.
- Present headers are useful signals, not proof of complete security.
- DNS or HTTP errors are operational observations, not exploitability findings.
- `blocked` means policy stopped the live request before HTTP.
- `network_requests_sent: 0` means no HTTP request was sent.
- `network_requests_sent: 1` means at most one HTTP `HEAD` request was attempted.
- Redirect observations do not mean redirects were followed.
- Response body data is not read.
- Header observations do not prove that a target is safe or unsafe.

If a result appears sparse, malformed, or legacy-shaped, treat the report as best-effort rendering of stored data and rely on controlled errors/redaction notes instead of over-interpreting missing fields.

## Expected States

### Disabled

The live feature is not enabled. The endpoint rejects the request and should not create a live job, resolve DNS, or send HTTP.

### Blocked

The request or resolved target violates policy. The job or result should record blocked reasons and preserve `network_requests_sent: 0`.

### Queued Or Running

The job has been accepted and is in the normal job lifecycle. Do not interpret queued/running states as target observations.

### Completed

The job finished under the one-HEAD contract. Interpret summary, headers, observations, and findings as heuristic review indicators.

### Controlled Failed

The job failed with a controlled error. Treat the error as an operational observation. Sensitive values should still be redacted.

### Sparse Or Malformed Legacy Payload

Reports and Raw JSON should remain readable and defensively redacted even if older or malformed payloads omit optional fields.

## Redaction And Sensitive Data

Defensive redaction applies across:

- storage and API summaries;
- `GET /jobs`;
- `GET /jobs/{job_id}`;
- Markdown, HTML, XML, and PDF exports;
- frontend job table;
- frontend report sections;
- frontend Raw JSON;
- controlled errors;
- response headers;
- observations and findings;
- audit log entries.

The fixed placeholder is:

```text
[REDACTED]
```

Sensitive values that should be redacted include:

- URL userinfo;
- sensitive query parameters;
- Authorization headers;
- Bearer and Basic credentials;
- cookies and session values;
- API keys;
- tokens;
- passwords;
- client secrets;
- private key blocks;
- secret-like assignments or nested legacy values.

Redaction is best-effort and complements good operator hygiene. Do not intentionally place secrets in targets, queries, copied errors, notes, or example payloads.

## Operator Must Not

- Do not use third-party targets as demos.
- Do not use targets without explicit authorization.
- Do not attempt to bypass loopback/private/metadata/link-local target blocking.
- Do not interpret findings as confirmed exploitation or confirmed vulnerabilities.
- Do not present Active alpha as Nmap.
- Do not present Active alpha as production ready.
- Do not request, enter, or validate credentials.
- Do not expect crawling, port scanning, redirects, GET fallback, response body reads, custom headers, auth, cookies, fuzzing, exploitation, or credential validation.
- Do not add local-lab behavior outside a separate docs-first design.
- Do not broaden target support without a separate scope decision and end-to-end review.

## Recommended Copy

Use:

- `Authorized HTTP Header Probe`
- `one HTTP HEAD request`
- `review indicators`
- `no response body is read`
- `redirects are not followed`
- `authorization is a user assertion, not proof of ownership`
- `disabled by default`
- `redaction is best-effort`

Avoid:

- `vulnerability confirmed`
- `exploitability confirmed`
- `credential valid`
- `safe target`
- `production ready`
- `Nmap ready`
- `bypass`
- `scan`, unless the surrounding context is extremely narrow and restates the one-HEAD limit.

## Mini Runbook

Use this only as a conceptual operator sequence. It intentionally avoids environment-file commands and external demo targets.

1. Confirm the environment is trusted and intended for internal alpha use.
2. Confirm the operator has explicit authorization for the single target.
3. Confirm the relevant live feature flag through the environment's normal deployment mechanism.
4. Use only a single authorized `http://` or `https://` target.
5. Avoid targets containing secrets, userinfo, credentials, tokens, or sensitive query parameters.
6. Complete both authorization confirmations.
7. Review whether the result is disabled, blocked, queued/running, completed, or controlled failed.
8. For blocked results, confirm `network_requests_sent: 0`.
9. For completed results, confirm no redirects were followed and no response body was read.
10. Review reports, exports, UI, and Raw JSON for expected redaction.
11. Share exports only when local retention and sensitivity are acceptable.
12. Disable or return the environment to its normal state according to the team's internal procedure.

## Acceptance Criteria

This guide is accepted when it:

- introduces no bypasses;
- introduces no external demo targets;
- changes no runtime behavior;
- adds no Active capability;
- clearly separates dry-run from live behavior;
- limits result interpretation to review indicators;
- documents redaction and local retention caveats;
- preserves production target policy;
- preserves no-scope boundaries;
- gives operators enough language to avoid overclaiming.

## No-Scope

- No code changes.
- No runtime changes.
- No tests or fixture changes.
- No probes.
- No live traffic.
- No DNS.
- No HTTP.
- No sockets.
- No Docker.
- No Nmap.
- No port scanning.
- No crawling.
- No GET fallback.
- No redirects.
- No body reads.
- No custom headers.
- No auth/cookies.
- No fuzzing.
- No exploitation.
- No credential validation.
- No new Active capability.
- No production target-policy relaxation.
- No local-lab mode.
- No `.env`, `.env.*`, or `.envrc` reads.
- No push.
- No tag or release.

## Next Recommendation

Recommended next microphase:

```text
ACTIVE-NETWORK-BLOCK-23-LIMITED-LIVE-SMOKE-TEST-EXECUTION
```

Rationale:

- The Active line now has internal alpha planning and operator guidance.
- The next useful step is to execute only the accepted no-external-network/test-double smoke subset from Block 20 and record the results, without adding runtime behavior or real target traffic.

Alternative next paths:

- `ACTIVE-NETWORK-BLOCK-23-ACTIVE-ALPHA-README-LINKING-AND-COPY-POLISH` if the team wants one more public/internal documentation alignment pass.
- `ACTIVE-NETWORK-BLOCK-23-NEXT-LIVE-CAPABILITY-DESIGN-DOCS-FIRST` only if product decides to broaden Active after smoke results are recorded.
- `ACTIVE-NETWORK-BLOCK-23-LOCAL-LAB-MODE-DESIGN-DOCS-FIRST` only if real loopback/private local smoke becomes necessary and production policy remains unchanged by default.

Do not proceed to Nmap, port scanning, crawling, broader target support, or another live capability from this guide.

## Validation Commands

Reference checks for this docs-only block:

```text
git status --short
git status --branch --short
git log --oneline -8
git diff --check
git diff --cached --check
git status --short
```

No pytest or npm suite is required when this block remains docs-only.
