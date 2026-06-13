# Active Nmap Basic Active Tools Internal Service Skeleton No Scan

Decision:

```text
ACTIVE_NMAP_BASIC_36_ACTIVE_TOOLS_INTERNAL_SERVICE_SKELETON_NO_SCAN_ACCEPTED
```

This phase adds a pure Python internal service skeleton for future
`active-tools` `active_nmap_basic` handling. It is no-scan and no-live. It does
not run Docker, run Compose, run Nmap, run `nmap --version`, perform probes,
perform DNS checks, send external HTTP traffic, run `curl`, open a browser, add
a public endpoint, add backend-to-`active-tools` live calls, change backend
runtime, create jobs from `active-tools`, create live exports, integrate
archive/run-all, integrate Active into `tools/runner/main.py`, change frontend
runtime, approve new targets, approve `www.vildek.es`, approve
`app.vildek.es`, approve port `80`, approve public scanner behavior, create
migrations, create a tag, or create a release.

## Objective

Prepare the smallest internal, offline-testable service surface for the future
separate `active-tools` boundary:

- health/readiness handler with no target and no execution;
- `active_nmap_basic` handler that accepts only the backend boundary shape;
- controlled no-scan responses;
- closed rejection of dangerous request fields and target expansion shapes;
- source guards proving no executor, Docker, backend live call, or passive
  runner integration was added.

## Files Added

- `tools/active_runner/service.py`
- `tools/tests/test_active_tools_internal_service_skeleton.py`
- `docs/future/active-nmap-basic-active-tools-internal-service-skeleton-no-scan.md`

Updated references:

- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

## Handler Skeleton

The skeleton is a pure module, not a running server:

- `handle_active_tools_health(payload=None)`
  - conceptual `GET /health`;
  - returns `service: active-tools`;
  - returns `status: scaffold_ready`;
  - advertises `active_nmap_basic` as `disabled_no_scan`;
  - rejects target-bearing health payloads;
  - records `network_requests_sent: 0` and `nmap_executed: false`.
- `handle_active_tools_request(method, path, payload=None)`
  - dispatches only `GET /health` and `POST /active/nmap-basic`;
  - rejects other paths and methods with controlled no-live responses.
- `handle_active_nmap_basic_no_scan(payload)`
  - conceptual `POST /active/nmap-basic`;
  - accepts only `mode: live_nmap_basic`, `profile: tcp_connect_small`,
    `confirmations_verified_by_backend: true`, and a single `target_unit`;
  - accepts only bounded integer `accepted_ports`;
  - rejects target ranges and multi-target shapes;
  - returns `status: not_executed`, `manual_validation_required: true`,
    `observations: []`, and no observed-exposure interpretation because no
    observation exists in this no-scan phase.

The handler does not import or call the real Nmap executor.

## Tests Added

`tools/tests/test_active_tools_internal_service_skeleton.py` covers:

- health/readiness no-target response;
- target-bearing health payload rejection without target leakage;
- valid boundary-shaped `active_nmap_basic` request returning `not_executed`;
- `manual_validation_required: true`;
- absence of `result_interpretation` when there are no observations;
- rejection of raw flags, scripts/NSE, extra args, shell commands,
  credentials, cookies, tokens, headers, target files, and command fields;
- rejection of nested dangerous fields;
- rejection of multiple targets, target ranges, false backend confirmations,
  unsupported mode/profile, and invalid accepted ports;
- method/path dispatch rejection;
- response redaction for raw XML, stdout/stderr, command, PTR hostname,
  resolved IP, script output, credentials, cookies, tokens, headers, and unsafe
  claims;
- source guard confirming the skeleton has no subprocess, Docker SDK,
  Docker socket, Nmap version call, real executor call, `tools/runner/main.py`
  reference, or backend service import.

## No-Run Confirmations

Confirmed for this phase:

- no Docker execution;
- no Compose execution;
- no Nmap execution;
- no `nmap --version`;
- no probes;
- no DNS checks;
- no external HTTP traffic;
- no `curl`;
- no browser;
- no backend-to-`active-tools` live call;
- no backend runtime change to call `active-tools`;
- no jobs created from `active-tools`;
- no live exports;
- no archive/run-all integration;
- no `tools/runner/main.py` integration;
- no frontend runtime change.

## Validation Evidence

Focused new suite:

```text
.venv/bin/python -m pytest tools/tests/test_active_tools_internal_service_skeleton.py
```

Result:

```text
24 passed in 0.03s
```

Active runner Nmap-focused regression:

```text
.venv/bin/python -m pytest tools/tests/test_active_runner.py -k "nmap"
```

Result:

```text
1 passed, 29 deselected in 0.02s
```

Backend active Nmap/boundary/redaction-focused regression:

```text
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap or nmap_basic or boundary or redaction"
```

Result:

```text
73 passed, 307 deselected in 1.47s
```

Final validation for the commit workflow also includes git checks, active-runner
Nmap-focused regression, backend active Nmap/boundary/redaction regression, and
source searches.

## Remaining Gaps

Still pending for separately approved future phases:

- no actual ASGI/server runtime for `active-tools`;
- no real internal network listener;
- no backend-to-`active-tools` live call;
- no Docker/Compose runtime wiring;
- no real `active-tools` job lifecycle;
- no live export path;
- no approved `www.vildek.es`, `app.vildek.es`, port `80`, LAN/VPS/public, or
  multi-domain target expansion;
- no public scanner behavior.

## Decision

`ACTIVE_NMAP_BASIC_36_ACTIVE_TOOLS_INTERNAL_SERVICE_SKELETON_NO_SCAN_ACCEPTED`
