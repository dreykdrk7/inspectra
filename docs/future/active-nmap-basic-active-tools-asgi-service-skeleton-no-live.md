# Active Nmap Basic Active Tools ASGI Service Skeleton No Live

Decision:

```text
ACTIVE_NMAP_BASIC_39_ACTIVE_TOOLS_ASGI_SERVICE_SKELETON_NO_LIVE_ACCEPTED
```

This phase creates a minimal internal ASGI skeleton for `active-tools` and
reuses the existing pure handlers for `active_nmap_basic`. It remains no-live.
It does not run Docker, run Compose, run Nmap, run `nmap --version`, perform
probes, perform DNS checks, send external HTTP traffic, run `curl`, open a
browser, start a real server with uvicorn/gunicorn, add backend-to-`active-tools`
live calls, change backend runtime, create real jobs from `active-tools`, create
live exports, integrate archive/run-all, integrate Active into
`tools/runner/main.py`, change frontend runtime, approve new targets, approve
`www.vildek.es`, approve `app.vildek.es`, approve port `80`, approve public
scanner behavior, create migrations, create a tag, or create a release.

## Objective

Move `active-tools` one pragmatic step closer to real integration by adding an
importable ASGI app skeleton:

- internal/private shape only;
- no server process;
- no backend live call;
- no executor unless explicitly injected by tests;
- same pure handler behavior as prior microphases;
- same no-scan/no-live default for `active_nmap_basic`.

## Product Decision

The product focus remains Active/Nmap integration. This phase does not return to
Passive work and does not add enterprise-style infrastructure. The accepted
direction is a small, OSS-friendly internal service skeleton that unlocks the
next integration steps while preserving the existing safety boundaries.

Future hardening microphases should directly unblock integration or materially
reduce risk. Broad hardening work that does not move the `active-tools` boundary
closer to usable, bounded integration should be deferred.

## Files Added

- `tools/active_runner/app.py`
- `tools/tests/test_active_tools_asgi_service_skeleton.py`
- `docs/future/active-nmap-basic-active-tools-asgi-service-skeleton-no-live.md`

Updated references:

- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

## ASGI Routes

`tools/active_runner/app.py` provides:

- `create_active_tools_app(nmap_basic_executor=None)`
- module-level `app = create_active_tools_app()`

The app disables generated docs/OpenAPI routes and exposes only:

- `GET /health`
  - returns stable `scaffold_ready` readiness;
  - reports `active_nmap_basic.status: disabled_no_scan`;
  - reports `network_requests_sent: 0`;
  - reports `nmap_executed: false`;
  - rejects body/query target payloads through the pure health handler.
- `POST /active/nmap-basic`
  - accepts the existing backend boundary shape;
  - calls `handle_active_nmap_basic_no_scan`;
  - defaults to `not_executed`;
  - creates no jobs;
  - performs no target expansion;
  - sends no network traffic;
  - can use a fake executor only when tests explicitly inject one through the
    app factory.

Wrong methods for known paths and unknown paths are routed through
`handle_active_tools_request` so responses remain controlled and no submitted
values are echoed.

## Tests Added

`tools/tests/test_active_tools_asgi_service_skeleton.py` uses a tiny in-memory
ASGI harness instead of starting a server or using sockets. It covers:

- health readiness response;
- health rejection of body and query target payloads;
- valid `POST /active/nmap-basic` returning `not_executed`;
- dangerous field rejection without value leakage;
- multi-target, range, and invalid-port rejection;
- explicitly injected fake executor returning an allowlisted synthetic response;
- wrong method and unknown path controlled errors;
- absence of raw XML, stdout/stderr, command, PTR, resolved IP, script output,
  credentials, cookies, tokens, headers, unsafe claims, and target leakage;
- source guards for no subprocess, Docker SDK, Docker socket, Nmap version call,
  Nmap command literal, backend import, real executor import, uvicorn/gunicorn
  startup, or `tools/runner/main.py` integration.

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
- no uvicorn/gunicorn invocation;
- no backend-to-`active-tools` live call;
- no backend runtime change to call `active-tools`;
- no real jobs created from `active-tools`;
- no live exports;
- no archive/run-all integration;
- no `tools/runner/main.py` integration;
- no frontend runtime change;
- no new target approval.

## Validation Evidence

ASGI skeleton suite:

```text
.venv/bin/python -m pytest tools/tests/test_active_tools_asgi_service_skeleton.py
```

Result:

```text
16 passed in 0.26s
```

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
20 passed in 0.03s
```

Internal service skeleton suite:

```text
.venv/bin/python -m pytest tools/tests/test_active_tools_internal_service_skeleton.py
```

Result:

```text
24 passed in 0.04s
```

Backend active Nmap/boundary/redaction-focused regression:

```text
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap or nmap_basic or boundary or redaction"
```

Result:

```text
73 passed, 307 deselected in 1.44s
```

Final validation for the commit workflow also includes git checks and source
searches.

## Remaining Gaps

Still pending for separately approved future phases:

- no real server process;
- no internal network listener;
- no backend-to-`active-tools` live call;
- no Docker/Compose runtime wiring;
- no real Nmap subprocess execution from the ASGI service;
- no real `active-tools` job lifecycle;
- no live export path;
- no approved `www.vildek.es`, `app.vildek.es`, port `80`, LAN/VPS/public, or
  multi-domain target expansion;
- no public scanner behavior.

## Decision

`ACTIVE_NMAP_BASIC_39_ACTIVE_TOOLS_ASGI_SERVICE_SKELETON_NO_LIVE_ACCEPTED`
