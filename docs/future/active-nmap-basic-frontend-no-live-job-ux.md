# Active Nmap Basic: Frontend No-Live Job UX

Status:

`ACTIVE_NMAP_BASIC_52_FRONTEND_ACTIVE_NMAP_NO_LIVE_JOB_UX_PASSED`

## Objective

Connect the existing Active / Nmap basic frontend panel to the backend
persistent no-live behavior introduced in Microphase 50 and hardened in
Microphase 51.

The frontend now submits the bounded request contract to
`POST /active/network/nmap-basic`, expects a `202` `JobRecord`, and renders the
response as an owner-scoped no-live lifecycle record. It does not present the
record as live execution, target proof, evidence, or a security finding.

This phase does not execute Nmap, call real `active-tools`, run Docker or
Compose, perform probes, perform DNS checks, send external HTTP traffic, touch
backend runtime, add exports, integrate archive/run-all, change
`tools/runner/main.py`, add migrations, release, tag, or push.

## Frontend Contract

`frontend/src/api.ts` now treats `createActiveNmapBasic(...)` as returning a
`JobRecord` from the existing backend route. The request body remains the
allowlisted contract:

- `mode: live_nmap_basic`;
- `profile: tcp_connect_small`;
- one explicit target string from the form;
- bounded integer TCP ports;
- `authorization_confirmed: true`;
- `local_private_scope_confirmed: true`;
- `live_traffic_confirmed: true`.

The UI does not expose raw flags, extra args, scripts, credentials, cookies,
tokens, headers, target files, shell commands, or custom profiles.

## UX Behavior

After a successful backend response, the panel displays a controlled no-live
notice with:

- no-live lifecycle record created;
- job id;
- lifecycle state;
- target shown only as `[REDACTED_TARGET]`;
- no Nmap executed;
- no network requests;
- no DNS queries;
- no evidence collected;
- no observations available;
- manual validation required.

`App` wires the panel into the existing job workflow. A successful response
selects the returned job and refreshes the jobs list, so the detail renderer and
dashboard table can show the persistent no-live record.

## Report Rendering

`ActiveNmapBasicJobReport` now distinguishes `JobStatus.completed` from
`result.lifecycle_state`. For `completed_no_live`, the report says the no-live
lifecycle completed and repeats the no-live caveats. It does not treat the job
status as proof of live execution.

When `result.status` is `not_executed`, the report says the capability was not
executed. Controlled states such as `client_error_controlled` and
`unsafe_lifecycle_result` render as sanitized controlled states without target
or payload details.

Frontend Raw JSON remains redacted-first. It redacts target-shaped values,
command fragments, XML, stdout/stderr, service/banner fields, payload-shaped
fields, evidence-shaped fields, and sensitive header/cookie/token/credential
fields.

## Wording Boundaries

The frontend no-live UX uses:

- no-live lifecycle record;
- no Nmap executed;
- no network requests;
- no DNS queries;
- no evidence collected;
- no observations available;
- manual validation required;
- observed exposure / review indicator only for legacy or future bounded TCP
  observations.

It avoids language that would imply a security finding, exploitability, target
ownership proof, completeness, broad discovery, or public-service behavior.

## Tests

Frontend tests cover:

- submitting the exact bounded backend request body;
- receiving a `202` `JobRecord`;
- selecting the returned job and refreshing the jobs list from `App`;
- no-live caveats after submit;
- `completed_no_live` rendered as lifecycle completion, not live execution;
- `not_executed` rendered as not executed;
- `client_error_controlled` and `unsafe_lifecycle_result` rendered as
  sanitized controlled states;
- disabled/backend validation errors rendered without target details;
- Raw JSON/report redaction for target, payload, command/output, service,
  evidence, credential, header, cookie, and token fields;
- absence of raw flags, NSE/scripts, credential inputs, header/cookie/token
  inputs, archive/run-all, and tools-runner wiring in the frontend path.

## Acceptance

This phase is accepted when focused Active Nmap frontend tests, the full
frontend suite, the frontend build, whitespace checks, and guardrail searches
pass, and the change set is limited to frontend UX/API/tests plus documentation.
