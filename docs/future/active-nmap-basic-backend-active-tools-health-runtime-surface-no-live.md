# Active Nmap Basic: Backend Active Tools Health Runtime Surface No-Live

Status:

`ACTIVE_NMAP_BASIC_45_BACKEND_ACTIVE_TOOLS_HEALTH_RUNTIME_SURFACE_NO_LIVE_PASSED`

## Objective

Expose the backend `check_active_tools_health` helper through a controlled
runtime health surface without executing Nmap, calling `/active/nmap-basic`,
accepting targets, creating jobs, creating exports, touching frontend runtime,
or integrating archive/run-all.

## Runtime Surface

Backend adds:

```text
GET /health/active-tools
```

The route:

- is targetless;
- rejects query parameters;
- rejects request bodies;
- uses only configured backend settings;
- calls the backend health helper for `active-tools` readiness;
- keeps `/health` unchanged as the lightweight backend liveness endpoint;
- remains protected by the existing auth middleware in auth-required modes
  because only `/health`, `/auth/status`, and `/auth/login` are anonymous-safe
  public paths.

## Configuration

The route uses existing settings:

```text
INSPECTRA_ACTIVE_TOOLS_URL
INSPECTRA_ACTIVE_TOOLS_HEALTH_TIMEOUT_SECONDS
```

`INSPECTRA_ACTIVE_TOOLS_URL` remains default-empty. With no configured URL, the
runtime surface returns a controlled `active_tools_unconfigured` state and does
not perform a network request.

## Response Shape

The route returns backend health plus the controlled active-tools health result:

```json
{
  "status": "ok",
  "service": "inspectra-backend",
  "active_tools": {
    "available": false,
    "status": null,
    "active_nmap_basic_status": null,
    "execution_enabled": null,
    "target_input_allowed": null,
    "network_requests_sent": null,
    "nmap_executed": null,
    "error_code": "active_tools_unconfigured"
  }
}
```

When a fake checker reports the expected readiness state in tests, the same
surface returns:

```json
{
  "available": true,
  "status": "scaffold_ready",
  "active_nmap_basic_status": "disabled_no_scan",
  "execution_enabled": false,
  "target_input_allowed": false,
  "network_requests_sent": 0,
  "nmap_executed": false,
  "error_code": null
}
```

## Boundary Confirmations

- No Nmap execution.
- No `nmap --version`.
- No backend call to `/active/nmap-basic`.
- No target input accepted.
- No port input accepted.
- No jobs created.
- No exports created.
- No frontend runtime change.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No probes.
- No DNS checks.
- No external HTTP checks in tests.
- No VPS, LAN, or real-domain traffic.
- No new published ports.
- No migrations, tag, or release.

## Tests

Backend tests cover:

- default-empty `INSPECTRA_ACTIVE_TOOLS_URL` returns
  `active_tools_unconfigured`;
- configured runtime surface uses an injected fake checker and passes only the
  configured base URL plus timeout;
- unavailable active-tools health returns a controlled response without
  breaking backend health;
- query parameters and bodies are rejected without leaking supplied values;
- auth-required anonymous requests are denied before input validation;
- source guardrails keep the health surface separate from
  `/active/nmap-basic`, job creation, Nmap execution, subprocess use, archive,
  and `tools/runner/main.py`.

## Validation Summary

Completed:

```text
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_tools_health or health_runtime_surface or test_health or auth_required_anonymous"
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_tools or active_nmap or nmap_basic or boundary or redaction"
```

Results:

```text
19 passed, 378 deselected
90 passed, 307 deselected
```

Additional final validations for diff hygiene and guardrail searches are part
of the microphase closeout.

## Remaining Gaps

- The runtime surface checks readiness only; it does not start or manage
  `active-tools`.
- The backend still has no `/active/nmap-basic` client for `active-tools`.
- No job lifecycle is connected to the internal service.
- No live Nmap executor response is processed by backend through the internal
  service boundary.

## Decision

`ACTIVE_NMAP_BASIC_45_BACKEND_ACTIVE_TOOLS_HEALTH_RUNTIME_SURFACE_NO_LIVE_PASSED`
