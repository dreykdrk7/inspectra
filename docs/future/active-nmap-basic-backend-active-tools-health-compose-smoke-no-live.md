# Active Nmap Basic: Backend Active Tools Health Compose Smoke No-Live

Status:

`ACTIVE_NMAP_BASIC_44_BACKEND_ACTIVE_TOOLS_HEALTH_COMPOSE_SMOKE_NO_LIVE_PASSED`

## Objective

Run a controlled smoke of the backend `check_active_tools_health` helper against
the Compose-started `active-tools` service, querying only `/health`. This phase
validates the first real helper-to-service contact on a local/internal Docker
network without calling `/active/nmap-basic`, executing Nmap, creating jobs,
creating exports, touching frontend runtime, or integrating archive/run-all.

## Compose Commands

Base config validation:

```text
docker compose -f docker-compose.active-tools.example.yml --profile active config
```

Observed:

- profile `active`;
- image `inspectra-active-tools:asgi-smoke`;
- command `python -m uvicorn active_runner.app:app --host 0.0.0.0 --port 8080`;
- no host-published ports;
- internal network;
- read-only filesystem;
- tmpfs `/tmp:rw,noexec,nosuid,size=16m`;
- dropped capabilities;
- `no-new-privileges:true`;
- local container healthcheck for `/health`.

## Temporary Override

A temporary local override was created at:

```text
/tmp/inspectra-active-tools-health-smoke.override.yml
```

Content:

```yaml
services:
  active-tools:
    ports:
      - "127.0.0.1:18080:8080"
```

Override config validation showed the intended loopback-only publish. The
effective container still had no host-published port because the service stayed
on the internal-only Docker network, so the smoke moved to a one-off container
on that same internal network. The override was deleted after cleanup and was
not committed.

## Service Startup

Command:

```text
docker compose -f docker-compose.active-tools.example.yml -f /tmp/inspectra-active-tools-health-smoke.override.yml --profile active up -d --no-build --force-recreate active-tools
```

Observed:

```text
Network inspectra-active-tools-example_inspectra_internal Created
Container inspectra-active-tools Started
```

The existing local `inspectra-active-tools:asgi-smoke` image was used with
`--no-build`.

## Backend Helper Script

The first host-loopback attempt returned a controlled
`active_tools_unavailable` because the loopback publish was not effective. A
direct host attempt against the container's internal Docker IP also returned
`active_tools_unavailable`.

Final successful smoke used a one-off container attached to the same internal
Compose network, with the repository mounted read-only. The command executed
the backend helper and requested only `/health`:

```text
docker run --rm --network inspectra-active-tools-example_inspectra_internal --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges:true -v /home/edward/proyectos_web/inspectra:/workspace:ro -w /workspace -e PYTHONPATH=/workspace/backend:/workspace/tools:/workspace/.venv/lib/python3.10/site-packages inspectra-active-tools:asgi-smoke python -c "import asyncio, json; from app.active_tools_client import check_active_tools_health; result = asyncio.run(check_active_tools_health('http://active-tools:8080', timeout_seconds=2)); print(json.dumps(result, sort_keys=True))"
```

Observed response:

```json
{"active_nmap_basic_status": "disabled_no_scan", "available": true, "error_code": null, "execution_enabled": false, "network_requests_sent": 0, "nmap_executed": false, "status": "scaffold_ready", "target_input_allowed": false}
```

## Log Check

Command:

```text
docker compose -f docker-compose.active-tools.example.yml -f /tmp/inspectra-active-tools-health-smoke.override.yml --profile active logs --tail 80 active-tools
```

Observed logs contained only `GET /health` requests for the service healthcheck
and the helper smoke. No `/active/nmap-basic` request appeared.

## Cleanup

Command:

```text
docker compose -f docker-compose.active-tools.example.yml -f /tmp/inspectra-active-tools-health-smoke.override.yml --profile active down
```

Observed:

```text
Container inspectra-active-tools Removed
Network inspectra-active-tools-example_inspectra_internal Removed
```

Additional cleanup:

```text
test ! -f /tmp/inspectra-active-tools-health-smoke.override.yml
docker ps -a --filter name=inspectra-active-tools --format '{{.Names}}'
```

Observed:

- temporary override absent;
- no matching `inspectra-active-tools` container names.

## Boundary Confirmations

- No backend call to `/active/nmap-basic`.
- No Nmap execution.
- No `nmap --version`.
- No target-bearing scan command.
- No probes.
- No external DNS checks.
- No external HTTP checks.
- No browser or curl.
- No backend runtime invocation added.
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
docker image inspect inspectra-active-tools:asgi-smoke --format {{.Id}}
docker compose -f docker-compose.active-tools.example.yml --profile active config
docker compose -f docker-compose.active-tools.example.yml -f /tmp/inspectra-active-tools-health-smoke.override.yml --profile active config
docker compose -f docker-compose.active-tools.example.yml -f /tmp/inspectra-active-tools-health-smoke.override.yml --profile active up -d --no-build --force-recreate active-tools
docker compose -f docker-compose.active-tools.example.yml -f /tmp/inspectra-active-tools-health-smoke.override.yml --profile active ps
docker run --rm --network inspectra-active-tools-example_inspectra_internal --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges:true -v /home/edward/proyectos_web/inspectra:/workspace:ro -w /workspace -e PYTHONPATH=/workspace/backend:/workspace/tools:/workspace/.venv/lib/python3.10/site-packages inspectra-active-tools:asgi-smoke python -c "..."
docker compose -f docker-compose.active-tools.example.yml -f /tmp/inspectra-active-tools-health-smoke.override.yml --profile active logs --tail 80 active-tools
docker compose -f docker-compose.active-tools.example.yml -f /tmp/inspectra-active-tools-health-smoke.override.yml --profile active down
docker ps -a --filter name=inspectra-active-tools --format '{{.Names}}'
test ! -f /tmp/inspectra-active-tools-health-smoke.override.yml
```

Results:

```text
health compose smoke: passed
helper smoke: available true / scaffold_ready / disabled_no_scan / target_input_allowed false / network_requests_sent 0 / nmap_executed false
logs: GET /health only, no /active/nmap-basic
cleanup: no matching container names
temporary override: absent after cleanup
```

Final test and search validations are recorded in the phase closeout.

## Remaining Gaps

- Backend runtime still does not invoke the helper.
- No `/active/nmap-basic` backend client exists yet.
- No job lifecycle is connected to the internal service.
- No live Nmap executor response is processed by backend through the internal
  service boundary.
- Future phases still need request/response timeout policy, owner-scope
  lifecycle wiring, storage, redaction, and report integration review.

## Decision

`ACTIVE_NMAP_BASIC_44_BACKEND_ACTIVE_TOOLS_HEALTH_COMPOSE_SMOKE_NO_LIVE_PASSED`
