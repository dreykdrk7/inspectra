# Active Nmap Basic Backend Active Tools Boundary Contract Tests No Live

Decision:

```text
ACTIVE_NMAP_BASIC_35_BACKEND_ACTIVE_TOOLS_BOUNDARY_CONTRACT_TESTS_NO_LIVE_ACCEPTED
```

This phase adds mocked no-live backend contract tests for the future
backend-to-`active-tools` boundary. It uses pure helpers, synthetic payloads,
and existing backend test fakes only. It does not implement a real
`active-tools` endpoint, add backend-to-`active-tools` live calls, run Docker,
run Nmap, run `nmap --version`, perform probes, perform DNS checks, send
external HTTP traffic, run `curl`, open a browser, use Compose, create real jobs
from `active-tools`, create live exports, integrate archive/run-all, integrate
Active into `tools/runner/main.py`, change frontend runtime, approve new
targets, approve `www.vildek.es`, approve `app.vildek.es`, approve port `80`,
approve public scanner behavior, create migrations, create a tag, or create a
release.

## Source Decisions

Accepted prior decisions:

```text
ACTIVE_NMAP_BASIC_33_BACKEND_REPORT_REDACTION_REAL_SHAPE_NO_LIVE_ACCEPTED
ACTIVE_NMAP_BASIC_34_BACKEND_ACTIVE_TOOLS_BOUNDARY_DESIGN_ACCEPTED
```

Reference prior commit:

```text
def2a2f docs(active): design backend active tools boundary
```

## Objective

Validate the future boundary contract before any live boundary exists:

- request shape is one backend-validated target unit;
- response shape is allowlisted, minimal, and redaction-first;
- controlled errors are mapped without leaking targets or raw output;
- policy drift is represented as a controlled blocked state;
- archive/run-all and `tools/runner/main.py` remain outside Active Nmap.

## Helpers Added

`backend/app/active_nmap_boundary.py` adds pure no-live helpers:

- `build_active_nmap_basic_boundary_request`
  - builds one target-unit request from an already validated backend handoff
    unit;
  - includes `mode: live_nmap_basic`, `profile: tcp_connect_small`,
    `target_kind`, `accepted_ports`, opaque ids, backend-verified
    confirmations, and explicit limits;
  - excludes raw flags, extra args, scripts/NSE, credentials, headers, cookies,
    tokens, target files, target ranges, and shell commands.
- `validate_active_nmap_basic_boundary_response`
  - accepts only controlled statuses and allowlisted response fields;
  - preserves minimal TCP observations, `manual_validation_required: true`, and
    `result_interpretation: observed_exposure_review_indicator`;
  - rejects sensitive or unexpected fields as controlled `blocked` /
    `unexpected_fields`;
  - maps unexpected response ports to controlled `policy_drift`.
- `map_active_nmap_basic_boundary_error`
  - maps future boundary errors to controlled statuses without raw target or
    output data.

These helpers do not import Docker, Nmap, `httpx`, active-tools endpoint code,
or `tools/runner/main.py`, and do not perform network activity.

## Tests Added

`backend/tests/test_backend.py` adds boundary-focused tests for:

- minimal safe boundary request generation for one authorized handoff unit;
- neutral id sanitization without target IP leakage;
- completed response acceptance with one minimal `443/tcp open syn-ack`
  observation;
- rejection of raw XML, stdout/stderr, raw command/args, PTR hostname, resolved
  IP, service/banner/version, script/NSE-like output, credentials, headers,
  cookies, tokens, and confirmed-vulnerability wording;
- blocking of oversized response payloads as controlled `result_too_large`
  output-truncated failures;
- preservation of manual validation and observed exposure review-indicator
  semantics;
- policy drift on unexpected response port;
- controlled mapping for `active_tools_unavailable`, `active_tools_timeout`,
  `nmap_missing`, `malformed_output`, `unsupported_shape`, `policy_drift`,
  `result_too_large`, `unexpected_fields`, `network_failure`, and
  `fqdn_resolution_failed`;
- owner-scoped synthetic blocked job behavior and generic wrong-owner `404`;
- source guard confirming the boundary helper has no live endpoint, Docker,
  Compose, HTTP client, subprocess, archive/run-all, or `tools/runner/main.py`
  integration.

## Request Cases Covered

Covered:

- `mode: live_nmap_basic`;
- `profile: tcp_connect_small`;
- one target unit per boundary request;
- `target_kind`;
- exact `accepted_ports`;
- sanitized `request_id`, `job_id`, and `correlation_id`;
- `confirmations_verified_by_backend: true`;
- explicit process, stdout, stderr, and response limits.

Rejected or absent:

- raw flags;
- extra args;
- custom scripts;
- NSE options;
- credentials;
- headers;
- cookies;
- tokens;
- target files;
- target ranges;
- shell commands.

## Response Cases Covered

Allowed response statuses:

- `completed`;
- `failed`;
- `timed_out`;
- `nmap_missing`;
- `malformed`;
- `unsupported_shape`;
- `blocked`.

Allowed response fields:

- `profile`;
- `target_kind`;
- `manual_validation_required`;
- `result_interpretation`;
- `observations`;
- `output_truncated`;
- safe execution metadata;
- controlled warnings and errors.

Rejected sensitive fields:

- raw XML;
- raw stdout/stderr;
- raw args or command;
- PTR hostnames;
- resolved IP visible for FQDN;
- local paths;
- service/banner/version fields;
- NSE/script output;
- credentials, headers, cookies, and tokens;
- vulnerability, exploitability, target-safety, full-scan, and all-ports-found
  claims.

## Redaction Evidence

The tests assert that controlled helper outputs and backend report/export/API
surfaces do not contain:

- `203.0.113.10`;
- `redacted-ptr.example.internal`;
- raw XML fragments;
- `nmap -sT`;
- stdout/stderr fixture text;
- service/banner/version fixture text;
- script/NSE-like fixture text;
- credentials, cookies, headers, or tokens;
- confirmed-vulnerability, exploitability, target-safety, full-scan, or
  all-ports-found wording.

## Validation Evidence

Initial focused validation:

```text
.venv/bin/python -m pytest backend/tests/test_backend.py -k "boundary"
```

Result:

```text
9 passed, 371 deselected in 1.82s
```

Backend active Nmap/boundary/redaction-focused regression:

```text
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap or nmap_basic or boundary or redaction"
```

Result:

```text
73 passed, 307 deselected in 1.37s
```

Parser redaction regression:

```text
.venv/bin/python -m pytest tools/tests/test_active_runner_nmap_basic_parser_redaction.py
```

Result:

```text
7 passed in 0.02s
```

Parser regression:

```text
.venv/bin/python -m pytest tools/tests/test_active_runner_nmap_basic_parser.py
```

Result:

```text
15 passed in 0.03s
```

Final validation for the commit workflow also includes the required git checks
and source searches.

## No-Run Confirmation

Confirmed for this phase:

- no Docker execution;
- no Nmap execution;
- no `nmap --version`;
- no DNS checks;
- no probes;
- no external HTTP checks;
- no `curl`;
- no browser;
- no Compose;
- no real `active-tools` endpoint;
- no backend-to-`active-tools` live call;
- no real jobs from `active-tools`;
- no real exports from live execution;
- no archive/run-all integration;
- no `tools/runner/main.py` integration.

## Remaining Gaps

Still pending for separately scoped future phases:

- internal `active-tools` service skeleton with no scan;
- health/readiness endpoint with no target and no Nmap execution;
- fake execution through the private boundary;
- real backend-to-`active-tools` live call behind explicit flags;
- Compose/runtime wiring review;
- frontend live UX review;
- separately frozen targets before any live execution;
- retention and cleanup policy for live outputs.

## Final Decision

```text
ACTIVE_NMAP_BASIC_35_BACKEND_ACTIVE_TOOLS_BOUNDARY_CONTRACT_TESTS_NO_LIVE_ACCEPTED
```
