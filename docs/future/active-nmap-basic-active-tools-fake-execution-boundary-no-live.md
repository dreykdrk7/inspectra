# Active Nmap Basic Active Tools Fake Execution Boundary No Live

Decision:

```text
ACTIVE_NMAP_BASIC_38_ACTIVE_TOOLS_FAKE_EXECUTION_BOUNDARY_NO_LIVE_ACCEPTED
```

This phase adds a fake/no-live execution path through the pure internal
`active-tools` boundary for `active_nmap_basic`. It uses only injected,
synthetic responses in offline tests. It does not run Docker, run Compose, run
Nmap, run `nmap --version`, perform probes, perform DNS checks, send external
HTTP traffic, run `curl`, open a browser, start a real server, add a real HTTP
endpoint, add backend-to-`active-tools` live calls, change backend runtime,
create real jobs from `active-tools`, create live exports, integrate
archive/run-all, integrate Active into `tools/runner/main.py`, change frontend
runtime, approve new targets, approve `www.vildek.es`, approve `app.vildek.es`,
approve port `80`, approve public scanner behavior, create migrations, create a
tag, or create a release.

## Objective

Prove that the internal `active-tools` boundary can process a valid backend
boundary request and a synthetic executor response without enabling live
execution:

- default handling stays `not_executed`;
- fake execution exists only when a test injects an explicit executor callable;
- the executor receives only the sanitized boundary request;
- fake responses are allowlisted before returning;
- unsafe fields, unsafe ports, unsafe metadata, and unsafe wording are blocked;
- returned observations stay minimal TCP observed exposure / review indicators.

## Helper Added

`tools/active_runner/service.py` now allows:

```text
handle_active_nmap_basic_no_scan(payload, *, executor=None)
```

When `executor` is omitted, the handler preserves the existing no-scan behavior
and returns `status: not_executed`, `network_requests_sent: 0`,
`summary.nmap_executed: false`, `job_created: false`, and no observations.

When an executor is explicitly injected, the handler:

- validates the same boundary request shape as the no-scan skeleton;
- rejects raw flags, scripts/NSE, credentials, cookies, tokens, headers, shell
  commands, target files, raw XML, stdout/stderr, PTR/resolved-IP fields, and
  other unsupported input before the executor is called;
- passes a sanitized request with sorted, bounded `accepted_ports`;
- validates the fake response against a top-level allowlist;
- validates observation fields and accepted-port policy;
- validates fake execution metadata fields;
- requires `manual_validation_required: true`;
- requires `result_interpretation: observed_exposure_review_indicator`;
- maps fake executor exceptions to a controlled failed response without echoing
  exception text.

## Fake States Covered

The fake boundary accepts only controlled synthetic states:

- `completed`
- `failed`
- `timed_out`
- `nmap_missing`
- `malformed`
- `unsupported_shape`
- `blocked`

It preserves those states only after the response passes the allowlist and
semantic checks. Policy drift, malformed payloads, unsupported shapes, unexpected
fields, and executor exceptions are converted into controlled responses.

## Redaction And Allowlist Evidence

Offline tests cover blocking or controlled handling for fake responses that
contain:

- raw XML;
- stdout/stderr;
- raw command data;
- PTR hostname data;
- resolved IP data;
- script/NSE-like output;
- credentials, cookies, tokens, and headers;
- unexpected metadata fields;
- ports outside the backend-accepted set;
- non-TCP observation protocols;
- unsafe top-level or observation wording such as vulnerability/exploitability
  claims.

Successful fake responses expose only bounded observation records with `port`,
`protocol`, `state`, optional `reason`, `manual_validation_required: true`, and
`result_interpretation: observed_exposure_review_indicator`.

## Tests Added

`tools/tests/test_active_tools_fake_execution_boundary.py` adds offline tests
for:

- valid requests without fake executor still returning `not_executed`;
- explicit fake executor completion producing a synthetic `443/tcp open
  syn-ack` observation;
- sanitized executor input and sorted accepted ports;
- dangerous request fields rejected before executor invocation;
- sensitive or unexpected response fields blocked;
- nested sensitive or unexpected metadata blocked;
- unexpected ports mapped to `policy_drift`;
- unsupported protocols mapped to `unsupported_shape`;
- unsafe semantic wording controlled;
- fake executor exceptions mapped to controlled `failed`;
- controlled fake timeout/error states preserved;
- source guards proving no subprocess, Docker SDK, Docker socket,
  `nmap --version`, real executor, backend import, or `tools/runner/main.py`
  integration.

`tools/tests/test_active_tools_internal_service_skeleton.py` was updated for
the keyword-only `executor` parameter while preserving the no-scan default.

## No-Live Confirmations

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
- no real server start;
- no real HTTP endpoint;
- no backend-to-`active-tools` live call;
- no backend runtime change to call `active-tools`;
- no real jobs created from `active-tools`;
- no live exports;
- no archive/run-all integration;
- no `tools/runner/main.py` integration;
- no frontend runtime change;
- no new target approval.

## Validation Evidence

Fake execution boundary suite:

```text
.venv/bin/python -m pytest tools/tests/test_active_tools_fake_execution_boundary.py
```

Result:

```text
34 passed in 0.05s
```

Health readiness suite:

```text
.venv/bin/python -m pytest tools/tests/test_active_tools_health_readiness.py
```

Result:

```text
20 passed in 0.04s
```

Internal service skeleton suite:

```text
.venv/bin/python -m pytest tools/tests/test_active_tools_internal_service_skeleton.py
```

Result:

```text
24 passed in 0.04s
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
73 passed, 307 deselected in 1.46s
```

Final validation for the commit workflow also includes git checks and source
searches.

## Remaining Gaps

Still pending for separately approved future phases:

- no ASGI/server runtime for `active-tools`;
- no real internal network listener;
- no backend-to-`active-tools` live call;
- no Docker/Compose runtime wiring;
- no real Nmap subprocess execution from the service boundary;
- no real `active-tools` job lifecycle;
- no live export path;
- no approved `www.vildek.es`, `app.vildek.es`, port `80`, LAN/VPS/public, or
  multi-domain target expansion;
- no public scanner behavior.

## Decision

`ACTIVE_NMAP_BASIC_38_ACTIVE_TOOLS_FAKE_EXECUTION_BOUNDARY_NO_LIVE_ACCEPTED`
