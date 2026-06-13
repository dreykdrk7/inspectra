# Active Nmap Basic: Backend Active Tools Health Client No-Live

Status:

`ACTIVE_NMAP_BASIC_43_BACKEND_ACTIVE_TOOLS_HEALTH_CLIENT_NO_LIVE_ACCEPTED`

## Objective

Add a backend helper for checking the internal `active-tools` `/health`
endpoint in a controlled no-live phase. The helper prepares future backend
integration by validating service readiness shape only; it does not call
`/active/nmap-basic`, execute Nmap, create jobs, create exports, touch frontend
runtime, or integrate archive/run-all.

## Client Added

Added file:

```text
backend/app/active_tools_client.py
```

The helper is:

```text
check_active_tools_health(base_url, timeout_seconds=..., transport=...)
```

It returns only controlled fields:

- `available`;
- `status`;
- `active_nmap_basic_status`;
- `execution_enabled`;
- `target_input_allowed`;
- `network_requests_sent`;
- `nmap_executed`;
- `error_code`.

It allowlists the expected `/health` shape and treats unexpected top-level,
capability, or `active_nmap_basic` fields as
`active_tools_unexpected_fields`. It does not return raw response payloads.

## Configuration

Added backend settings:

- `INSPECTRA_ACTIVE_TOOLS_URL`, default empty/unconfigured;
- `INSPECTRA_ACTIVE_TOOLS_HEALTH_TIMEOUT_SECONDS`, default `2`.

An empty URL returns `active_tools_unconfigured` without making a request. The
helper is not invoked from backend runtime in this phase.

## Controlled Error States

- `active_tools_unconfigured`;
- `active_tools_unavailable`;
- `active_tools_timeout`;
- `active_tools_invalid_response`;
- `active_tools_unexpected_fields`;
- `active_tools_not_ready`.

## Tests Added

Tests were added in:

```text
backend/tests/test_backend.py
```

They cover:

- default empty config and explicit internal URL parsing;
- empty URL returning `active_tools_unconfigured`;
- fake `/health` success returning `available: true`;
- `disabled_no_scan`, `execution_enabled: false`, and
  `target_input_allowed: false` interpretation;
- `nmap_executed: true` rejected as invalid/degraded;
- nonzero `network_requests_sent` rejected as invalid/degraded;
- dangerous or unexpected fields not reflected;
- timeout mapped to `active_tools_timeout`;
- connection error mapped to `active_tools_unavailable`;
- invalid JSON mapped to `active_tools_invalid_response`;
- fake transport path check confirming no `/active/nmap-basic` call;
- source guard confirming no Nmap subprocess, Docker SDK/socket,
  archive/run-all, `tools/runner/main.py`, or backend runtime integration.

## Smoke Decision

No real backend-to-`active-tools` smoke was run in this phase. The accepted
scope uses fake HTTP transport only. A real backend health smoke through Compose
remains a future separately approved phase.

## Boundary Confirmations

- No Nmap execution.
- No `nmap --version`.
- No target-bearing scan command.
- No probes.
- No DNS checks.
- No external HTTP checks.
- No backend call to `/active/nmap-basic`.
- No backend runtime invocation of the new helper.
- No real jobs created from `active-tools`.
- No live exports.
- No frontend runtime change.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No approval for `www.vildek.es`.
- No approval for `app.vildek.es`.
- No approval for port `80`.
- No LAN/VPS/public target expansion.
- No public scanner behavior.
- No migrations, tag, or release.

## Validations

Completed:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_tools or active_nmap or nmap_basic or boundary or redaction"
.venv/bin/python -m pytest tools/tests/test_active_tools_asgi_service_skeleton.py
.venv/bin/python -m pytest tools/tests/test_active_tools_health_readiness.py
.venv/bin/python -m pytest tools/tests/test_active_tools_fake_execution_boundary.py
rg -n "active_tools_unconfigured|active_tools_unavailable|active_tools_timeout|active_tools_invalid_response|active_tools_unexpected_fields|active_tools_not_ready|disabled_no_scan|target_input_allowed|nmap_executed|network_requests_sent" backend docs README.md
rg -n "subprocess|docker.sock|DockerClient|from docker|nmap --version|nmap -sT|tools/runner/main.py" backend tools docs README.md
rg -n "vps-40567620|51.38.225.243" backend tools/tests
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" backend tools docs README.md
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Initial focused result:

```text
backend/tests/test_backend.py -k "active_tools": 12 passed, 380 deselected
```

Final results:

```text
backend/tests/test_backend.py -k "active_tools or active_nmap or nmap_basic or boundary or redaction": 85 passed, 307 deselected
tools/tests/test_active_tools_asgi_service_skeleton.py: 16 passed
tools/tests/test_active_tools_health_readiness.py: 20 passed
tools/tests/test_active_tools_fake_execution_boundary.py: 34 passed
git diff --check: passed
git diff --cached --check: passed
active_tools health state search: expected backend/docs/README references
subprocess/Docker/Nmap guardrail search: expected docs/tests/fixture/passive-runner references only
vps-40567620 / 51.38.225.243 search in backend and tools tests: no matches
unsafe wording and no-scope search: expected docs/tests policy references only
active_nmap_basic / nmap_basic search in tools/runner/main.py: no matches
check_active_tools_health source search: helper and tests only; no main.py/services.py invocation
```

## Remaining Gaps

- The backend does not yet call `active-tools` from runtime.
- No `/active/nmap-basic` backend client exists yet.
- No backend-to-Compose health smoke has been accepted or run.
- No live Nmap executor response is processed by backend through the internal
  service boundary.
- Future phases still need request/response timeout policy, owner-scope
  lifecycle wiring, storage, redaction, and report integration review.

## Decision

`ACTIVE_NMAP_BASIC_43_BACKEND_ACTIVE_TOOLS_HEALTH_CLIENT_NO_LIVE_ACCEPTED`
