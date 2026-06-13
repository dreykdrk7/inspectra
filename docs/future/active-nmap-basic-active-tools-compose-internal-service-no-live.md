# Active Nmap Basic: Active Tools Compose Internal Service No-Live

Status:

`ACTIVE_NMAP_BASIC_42_ACTIVE_TOOLS_COMPOSE_INTERNAL_SERVICE_NO_LIVE_PASSED`

## Objective

Add optional Docker Compose wiring for `active-tools` as an internal ASGI
service in no-live mode. This phase prepares future backend-to-`active-tools`
integration but does not add a backend live call, execute Nmap, create jobs,
create exports, touch frontend runtime, integrate archive/run-all, or expose
`active-tools` as a public service.

## Product Decision

This is a pragmatic OSS/self-hosted integration step. The service is now
startable through an explicit Compose profile so a later microphase can test a
backend client against an internal service boundary. Normal Compose startup is
unchanged, and `active-tools` remains inactive unless the `active` profile is
requested.

## Compose File

Modified file:

```text
docker-compose.active-tools.example.yml
```

The file remains separate from the main Compose runtime. It uses:

- service name: `active-tools`;
- profile: `active`;
- image: `inspectra-active-tools:asgi-smoke`;
- build context: `.`;
- Dockerfile: `docker/active-tools/Dockerfile`;
- command:
  `python -m uvicorn active_runner.app:app --host 0.0.0.0 --port 8080`;
- internal network: `inspectra_internal`;
- no `ports`;
- no `network_mode: host`;
- no `privileged: true`;
- no Docker socket mount;
- `read_only: true`;
- tmpfs `/tmp:rw,noexec,nosuid,size=16m`;
- `cap_drop: [ALL]`;
- `security_opt: no-new-privileges:true`;
- minimal non-sensitive environment: `INSPECTRA_ACTIVE_TOOLS_MODE=asgi_no_live`;
- healthcheck using Python `urllib.request` against
  `http://127.0.0.1:8080/health` inside the container.

## Config Validation

Command:

```text
docker compose -f docker-compose.active-tools.example.yml --profile active config
```

Observed effective config confirmed:

- `profiles: [active]`;
- `command: python -m uvicorn active_runner.app:app --host 0.0.0.0 --port 8080`;
- `image: inspectra-active-tools:asgi-smoke`;
- `read_only: true`;
- tmpfs `/tmp:rw,noexec,nosuid,size=16m`;
- `cap_drop: ALL`;
- `security_opt: no-new-privileges:true`;
- healthcheck is local `/health`;
- network `inspectra_internal` is `internal: true`;
- no published ports appeared.

## Compose Smoke

Command:

```text
docker compose -f docker-compose.active-tools.example.yml --profile active up -d active-tools
```

Observed:

```text
Container inspectra-active-tools Started
```

No host port was published. Health and Nmap-basic checks were executed from
inside the container with `docker compose exec -T active-tools python -c ...`.

## Health Response

Internal-only request:

```text
GET http://127.0.0.1:8080/health
```

Observed response:

```text
200
{"service":"active-tools","status":"scaffold_ready","capabilities":{"active_nmap_basic":{"status":"disabled_no_scan","execution_enabled":false,"target_input_allowed":false}},"network_requests_sent":0,"nmap_executed":false}
```

## Nmap Basic No-Live Response

Internal-only request:

```text
POST http://127.0.0.1:8080/active/nmap-basic
```

Payload used a synthetic container-loopback contract target:

```json
{
  "mode": "live_nmap_basic",
  "profile": "tcp_connect_small",
  "request_id": "req-compose-redacted",
  "job_id": "job-compose-redacted",
  "correlation_id": "corr-compose-redacted",
  "target_unit": {
    "target": "127.0.0.1",
    "target_kind": "container_loopback",
    "accepted_ports": [65000]
  },
  "confirmations_verified_by_backend": true,
  "limits": {
    "process_timeout_seconds": 20,
    "stdout_max_bytes": 131072,
    "stderr_max_bytes": 8192,
    "response_max_bytes": 32768
  }
}
```

Observed response:

```text
200
{"service":"active-tools","status":"not_executed","capability":"active_nmap_basic","mode":"live_nmap_basic","profile":"tcp_connect_small","execution_enabled":false,"manual_validation_required":true,"reason":"active_tools_internal_service_skeleton_no_scan","observations":[],"job_created":false,"target_expansion_performed":false,"network_requests_sent":0,"summary":{"target_count":1,"port_count":1,"nmap_executed":false,"evidence_available":false},"warnings":["no_scan_service_skeleton"],"errors":[]}
```

Confirmed response properties:

- `status: not_executed`;
- `manual_validation_required: true`;
- `observations: []`;
- `job_created: false`;
- `network_requests_sent: 0`;
- `summary.nmap_executed: false`;
- no raw XML;
- no stdout or stderr;
- no command or raw args;
- no PTR hostname or resolved IP evidence;
- no credentials, tokens, headers, or cookies;
- no vulnerability, exploitability, target-safety, all-ports-found, or
  full-scan wording.

## Cleanup

Command:

```text
docker compose -f docker-compose.active-tools.example.yml --profile active down
```

Observed:

```text
Container inspectra-active-tools Removed
Network inspectra-active-tools-example_inspectra_internal Removed
```

Cleanup verification:

```text
docker ps -a --filter name=inspectra-active-tools --format {{.Names}}
```

Observed result: no matching container names.

## Boundary Confirmations

- No Nmap execution.
- No `nmap --version`.
- No target-bearing scan command.
- No probes.
- No DNS checks.
- No external HTTP checks.
- No browser or curl against targets.
- No backend-to-`active-tools` live call.
- No backend runtime change.
- No real jobs created from `active-tools`.
- No live exports.
- No main Compose runtime wiring.
- No archive/run-all integration.
- No `tools/runner/main.py` integration.
- No frontend runtime change.
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
.venv/bin/python -m pytest tools/tests/test_active_tools_docker_scaffold_static.py
.venv/bin/python -m pytest tools/tests/test_active_tools_asgi_service_skeleton.py
.venv/bin/python -m pytest tools/tests/test_active_tools_fake_execution_boundary.py
.venv/bin/python -m pytest tools/tests/test_active_tools_health_readiness.py
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap or nmap_basic or boundary or redaction"
docker compose -f docker-compose.active-tools.example.yml --profile active config
docker compose -f docker-compose.active-tools.example.yml --profile active up -d active-tools
docker compose -f docker-compose.active-tools.example.yml --profile active exec -T active-tools python -c "..."  # /health
docker compose -f docker-compose.active-tools.example.yml --profile active exec -T active-tools python -c "..."  # /active/nmap-basic
docker compose -f docker-compose.active-tools.example.yml --profile active down
docker ps -a --filter name=inspectra-active-tools --format {{.Names}}
rg -n "subprocess|docker.sock|nmap --version|nmap -sT|tools/runner/main.py" tools/active_runner tools/tests docker docs README.md
rg -n "ports:|network_mode: host|privileged: true|/var/run/docker.sock|profile|active-tools|disabled_no_scan|scaffold_ready|network_requests_sent|nmap_executed|not_executed|job_created" docker-compose.active-tools.example.yml docker tools docs README.md
rg -n "vps-40567620|51.38.225.243" backend tools/tests
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" backend tools docs README.md
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Results:

```text
tools/tests/test_active_tools_docker_scaffold_static.py: 5 passed
tools/tests/test_active_tools_asgi_service_skeleton.py: 16 passed
tools/tests/test_active_tools_fake_execution_boundary.py: 34 passed
tools/tests/test_active_tools_health_readiness.py: 20 passed
backend/tests/test_backend.py -k "active_nmap or nmap_basic or boundary or redaction": 73 passed, 307 deselected
docker compose config: passed
GET /health: 200 scaffold_ready / disabled_no_scan / nmap_executed false
POST /active/nmap-basic: 200 not_executed / job_created false / network_requests_sent 0 / summary.nmap_executed false
docker ps cleanup check: no matching container names
vps-40567620 / 51.38.225.243 search in backend and tools tests: no matches
active_nmap_basic / nmap_basic search in tools/runner/main.py: no matches
unsafe wording and guardrail searches: expected docs/tests policy references only
```

## Remaining Gaps

- No backend-to-`active-tools` live client exists yet.
- The main Compose runtime remains unchanged.
- No live Nmap executor path was exercised by the ASGI service.
- No parser processing of real Nmap output happened in this phase.
- No frontend exposure or operator UI was added.
- Future backend integration still needs separate request/response timeout,
  error mapping, owner-scope, storage, and redaction review.

## Decision

`ACTIVE_NMAP_BASIC_42_ACTIVE_TOOLS_COMPOSE_INTERNAL_SERVICE_NO_LIVE_PASSED`
