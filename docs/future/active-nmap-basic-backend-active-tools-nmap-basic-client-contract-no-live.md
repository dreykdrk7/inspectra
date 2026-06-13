# Active Nmap Basic: Backend Active Tools Nmap Basic Client Contract No-Live

Status:

`ACTIVE_NMAP_BASIC_46_BACKEND_ACTIVE_TOOLS_NMAP_BASIC_CLIENT_CONTRACT_NO_LIVE_PASSED`

## Objective

Add a backend helper contract for the future internal `active-tools`
`/active/nmap-basic` call while keeping the phase mock-only and no-live. The
helper must validate request and response shape, normalize controlled failures,
preserve no-execution safety flags, and avoid leaking target or payload values
in errors.

This phase does not integrate the helper into jobs, public routes, frontend,
archive/run-all, exports, or `tools/runner/main.py`.

## Helper

Backend adds:

```text
run_active_nmap_basic(...)
```

Location:

```text
backend/app/active_tools_client.py
```

The helper:

- normalizes the configured `active-tools` base URL;
- validates an allowlisted request payload before any outbound call;
- posts only to `/active/nmap-basic`;
- accepts a mock/fake HTTP transport for tests;
- applies a bounded timeout parameter;
- maps timeout, connection, non-2xx, invalid JSON, invalid response, and
  unexpected fields into controlled results;
- does not reflect target, payload, token, raw command, XML, stdout, stderr, or
  credential values in errors;
- normalizes only the no-live `not_executed` contract.

## Request Contract

Allowed top-level request fields:

```text
mode
profile
request_id
job_id
correlation_id
target_unit
confirmations_verified_by_backend
limits
```

Required values:

```text
mode: live_nmap_basic
profile: tcp_connect_small
confirmations_verified_by_backend: true
```

`target_unit` is allowed only as a prevalidated backend boundary unit:

```text
target
target_kind
accepted_ports
```

The helper validates shape only; it does not approve targets and is not exposed
through a runtime endpoint. Tests use fake targets such as `example.invalid`
through `httpx.MockTransport`, with no real traffic.

## Response Contract

The no-live success response must preserve:

```text
status: not_executed
capability: active_nmap_basic
execution_enabled: false
target_input_allowed: false
job_created: false
target_expansion_performed: false
network_requests_sent: 0
summary.nmap_executed: false
summary.evidence_available: false
observations: []
```

Responses with unexpected fields, raw command/XML/stdout/stderr, credentials,
tokens, service/banner/version details, true execution flags, nonzero network
request counts, created jobs, target expansion, evidence availability, or
observations are rejected into controlled error states.

## Boundary Confirmations

- No Nmap execution.
- No `nmap --version`.
- No Docker.
- No Compose smoke.
- No probes.
- No DNS checks.
- No external HTTP checks.
- No VPS, LAN, or real-domain traffic.
- No real targets.
- No public endpoint that accepts targets.
- No jobs created.
- No exports created.
- No frontend runtime change.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No migrations, tag, release, or push.

## Tests

Backend tests cover:

- success contract with `httpx.MockTransport`;
- exact `POST /active/nmap-basic` path use;
- invalid request rejection before transport is called;
- default-empty URL controlled failure;
- timeout controlled failure;
- connection controlled failure;
- non-2xx controlled failure;
- invalid JSON controlled failure;
- unexpected/sensitive response fields rejected;
- dangerous or inconsistent no-live flags rejected;
- target/payload redaction from error results;
- source guardrails proving no subprocess, Nmap execution, `nmap --version`,
  job, service-runtime, archive, frontend, or `tools/runner/main.py`
  integration.

## Validation Summary

Completed:

```text
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_tools_nmap_basic_client or active_tools_health_client_source or active_tools_health_client"
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_tools or active_nmap or nmap_basic or boundary or redaction"
```

Results:

```text
21 passed, 385 deselected
99 passed, 307 deselected
```

Additional final validations for diff hygiene, focused guardrail searches, and
repository status are part of the microphase closeout.

## Remaining Gaps

- The helper is not called by backend runtime analysis.
- No job lifecycle uses the internal service.
- No frontend or report/export path consumes active-tools Nmap-basic responses.
- Future phases must separately approve any no-live integration wiring before
  any real execution phase is considered.

## Decision

`ACTIVE_NMAP_BASIC_46_BACKEND_ACTIVE_TOOLS_NMAP_BASIC_CLIENT_CONTRACT_NO_LIVE_PASSED`
