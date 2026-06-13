# Active Nmap Basic Active Tools Health Readiness Hardening No Scan

Decision:

```text
ACTIVE_NMAP_BASIC_37_ACTIVE_TOOLS_HEALTH_READINESS_HARDENING_NO_SCAN_ACCEPTED
```

This phase hardens the pure internal `active-tools` health/readiness handler.
It remains no-scan and no-live. It does not run Docker, run Compose, run Nmap,
run `nmap --version`, perform probes, perform DNS checks, send external HTTP
traffic, run `curl`, open a browser, start a real server, add a real HTTP
endpoint, add backend-to-`active-tools` live calls, change backend runtime,
create jobs from `active-tools`, create live exports, integrate archive/run-all,
integrate Active into `tools/runner/main.py`, change frontend runtime, approve
new targets, approve `www.vildek.es`, approve `app.vildek.es`, approve port
`80`, approve public scanner behavior, create migrations, create a tag, or
create a release.

## Objective

Make `handle_active_tools_health` explicitly readiness-only before any later
fake-execution, ASGI/server runtime, or backend live-call phase:

- no target input;
- no port input;
- no credentials, headers, cookies, or tokens;
- no raw command, args, scripts, or NSE fields;
- no local path, environment, hostname, command, XML, stdout/stderr, PTR,
  resolved IP, service/banner/version, or secret disclosure;
- no Nmap execution or Nmap path/version lookup.

## Health Changes

`tools/active_runner/service.py` now includes:

- `active_tools_capability_metadata()`
  - returns stable capability metadata for `active_nmap_basic`;
  - marks `status: disabled_no_scan`;
  - marks `execution_enabled: false`;
  - marks `target_input_allowed: false`.
- `handle_active_tools_health(payload=None)`
  - accepts only no payload or an empty mapping;
  - returns a small stable readiness payload;
  - rejects non-mapping payloads with `health_payload_not_mapping`;
  - rejects any non-empty mapping with `health_payload_not_accepted`;
  - never echoes submitted values.

## Readiness Response

Expected readiness shape:

```json
{
  "service": "active-tools",
  "status": "scaffold_ready",
  "capabilities": {
    "active_nmap_basic": {
      "status": "disabled_no_scan",
      "execution_enabled": false,
      "target_input_allowed": false
    }
  },
  "network_requests_sent": 0,
  "nmap_executed": false
}
```

The response intentionally omits:

- container hostname;
- local paths;
- environment variables;
- Nmap version;
- targets;
- command or argv;
- stdout/stderr;
- raw XML;
- resolved IP or PTR data;
- service/banner/version data;
- secrets.

## Tests Added

`tools/tests/test_active_tools_health_readiness.py` adds offline tests for:

- health without payload returning controlled readiness;
- target-bearing health payloads rejected without target leakage;
- port payloads rejected without scan behavior;
- credentials, headers, cookies, and tokens rejected without value leakage;
- raw command, args, scripts, and NSE payloads rejected;
- non-mapping payloads rejected;
- no environment, host, path, command, XML, stdout/stderr, PTR, resolved IP, or
  unsafe-claim leakage;
- `nmap_executed: false`;
- `network_requests_sent: 0`;
- `active_nmap_basic` capability status `disabled_no_scan`;
- controlled method/path dispatch errors;
- source guard proving no subprocess, Docker SDK, Docker socket,
  `nmap --version`, real executor, backend service import, host introspection,
  or `tools/runner/main.py` integration.

Existing `tools/tests/test_active_tools_internal_service_skeleton.py` was
updated to expect the hardened capability metadata.

## No-Run Confirmations

Confirmed for this phase:

- no target accepted by health/readiness;
- no scan;
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
- no jobs created from `active-tools`;
- no live exports;
- no archive/run-all integration;
- no `tools/runner/main.py` integration;
- no frontend runtime change.

## Validation Evidence

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
1 passed, 29 deselected in 0.03s
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

- no fake execution through the internal service;
- no ASGI/server runtime;
- no real internal network listener;
- no backend-to-`active-tools` live call;
- no Docker/Compose runtime wiring;
- no real `active-tools` job lifecycle;
- no live export path;
- no approved `www.vildek.es`, `app.vildek.es`, port `80`, LAN/VPS/public, or
  multi-domain target expansion;
- no public scanner behavior.

## Decision

`ACTIVE_NMAP_BASIC_37_ACTIVE_TOOLS_HEALTH_READINESS_HARDENING_NO_SCAN_ACCEPTED`
