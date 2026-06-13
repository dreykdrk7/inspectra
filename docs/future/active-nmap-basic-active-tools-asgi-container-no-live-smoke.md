# Active Nmap Basic: Active Tools ASGI Container No-Live Smoke

Status:

`ACTIVE_NMAP_BASIC_40_ACTIVE_TOOLS_ASGI_CONTAINER_NO_LIVE_SMOKE_PASSED`

## Objective

Validate that the internal `active-tools` ASGI app can start inside the
Dockerized `active-tools` image and answer `GET /health` in no-live mode. This
phase intentionally stops before Nmap execution, target handling, backend live
calls, Compose runtime wiring, jobs, exports, frontend runtime changes, or
approval of new targets.

## Pragmatic OSS Decision

This phase keeps the Active/Nmap path moving with the smallest useful
integration step: package the minimal ASGI runtime in the existing separate
`active-tools` image, start the app manually for a local container smoke, and
verify only `/health`.

The default Dockerfile command remains the existing scaffold no-run readiness
command. Running an ASGI service remains an explicit operator/test command, not
default product runtime.

## Changes Made

- Added `docker/active-tools/requirements.txt` with only:
  - `fastapi>=0.115,<1.0`
  - `uvicorn>=0.30,<1.0`
- Updated `docker/active-tools/Dockerfile` to install that minimal ASGI runtime
  during image build.
- Preserved the default `CMD` as `scaffold_no_run`.
- Kept no `EXPOSE`, no `HEALTHCHECK`, no public-port default, no host-network
  default, no privileged container, and no Docker socket.
- Extended static scaffold tests to assert the explicit ASGI packaging and the
  preserved no-run default command.

No backend runtime, frontend runtime, archive/run-all integration,
`tools/runner/main.py`, migrations, release, or tag state changed.

## Build Command

The image was rebuilt because the Dockerfile changed:

```text
docker build -f docker/active-tools/Dockerfile -t inspectra-active-tools:asgi-smoke .
```

Observed result:

```text
naming to docker.io/library/inspectra-active-tools:asgi-smoke done
```

The build installed only the direct ASGI packaging dependencies above plus
their Python runtime dependencies. It did not execute Nmap and did not start a
container.

## Run Command

The ASGI service smoke used a single local container, with the host port bound
only to loopback:

```text
docker run --rm -d --name inspectra-active-tools-asgi-smoke \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -p 127.0.0.1:18080:8080 \
  inspectra-active-tools:asgi-smoke \
  python -m uvicorn active_runner.app:app --host 0.0.0.0 --port 8080
```

The app listened on `0.0.0.0` inside the container so Docker's loopback-only
host publish could reach it. The host binding remained `127.0.0.1`; no public
host port, host networking, privileged mode, Docker socket, Compose runtime
wiring, or sensitive environment input was used.

## Health Response

The only HTTP request sent by this smoke was to local container loopback via
the host loopback publish:

```text
http://127.0.0.1:18080/health
```

The sandboxed local request was first blocked by the command sandbox with
`Operation not permitted`; the same loopback-only request was then run with
tool approval and returned:

```text
200
{"service":"active-tools","status":"scaffold_ready","capabilities":{"active_nmap_basic":{"status":"disabled_no_scan","execution_enabled":false,"target_input_allowed":false}},"network_requests_sent":0,"nmap_executed":false}
```

This confirms the containerized ASGI app can start and return the expected
no-live health contract:

- `service: active-tools`
- `status: scaffold_ready`
- `active_nmap_basic.status: disabled_no_scan`
- `execution_enabled: false`
- `target_input_allowed: false`
- `network_requests_sent: 0`
- `nmap_executed: false`

The response contained no host, environment, path, command, XML, stdout,
stderr, PTR hostname, resolved IP, secrets, target evidence, vulnerability
claim, exploitability claim, target-safety claim, or full-scan claim.

## Cleanup

The smoke container was removed after the health check:

```text
docker rm -f inspectra-active-tools-asgi-smoke
```

Observed result:

```text
inspectra-active-tools-asgi-smoke
```

## Boundary Confirmations

- No Nmap execution.
- No `nmap --version`.
- No target-bearing scan command.
- No probes.
- No DNS checks.
- No external HTTP checks.
- No browser or curl against targets.
- No call to `/active/nmap-basic` from outside the offline ASGI tests.
- No backend-to-`active-tools` live call.
- No backend runtime change.
- No real jobs created from `active-tools`.
- No live exports.
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
.venv/bin/python -m pytest tools/tests/test_active_tools_asgi_service_skeleton.py
.venv/bin/python -m pytest tools/tests/test_active_tools_docker_scaffold_static.py
.venv/bin/python -m pytest tools/tests/test_active_tools_fake_execution_boundary.py tools/tests/test_active_tools_health_readiness.py
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap or nmap_basic or boundary or redaction"
docker build -f docker/active-tools/Dockerfile -t inspectra-active-tools:asgi-smoke .
docker run --rm -d --name inspectra-active-tools-asgi-smoke --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges:true -p 127.0.0.1:18080:8080 inspectra-active-tools:asgi-smoke python -m uvicorn active_runner.app:app --host 0.0.0.0 --port 8080
.venv/bin/python -c "..."  # loopback-only GET /health
docker rm -f inspectra-active-tools-asgi-smoke
docker ps -a --filter name=inspectra-active-tools-asgi-smoke --format {{.Names}}
rg -n "subprocess|docker.sock|nmap --version|nmap -sT|tools/runner/main.py" tools/active_runner tools/tests docker docs README.md
rg -n "raw_xml|stdout|stderr|ptr_hostname|resolved_ip|script_output|nse|credentials|cookies|tokens|headers|disabled_no_scan|scaffold_ready|network_requests_sent|nmap_executed" tools backend docs README.md
rg -n "vps-40567620|51.38.225.243" backend tools/tests
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" backend tools docs README.md
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Results:

```text
tools/tests/test_active_tools_asgi_service_skeleton.py: 16 passed
tools/tests/test_active_tools_docker_scaffold_static.py: 5 passed
tools/tests/test_active_tools_fake_execution_boundary.py tools/tests/test_active_tools_health_readiness.py: 54 passed
backend/tests/test_backend.py -k "active_nmap or nmap_basic or boundary or redaction": 73 passed, 307 deselected
GET /health: 200 scaffold_ready / disabled_no_scan / nmap_executed false
docker ps cleanup check: no matching container names
vps-40567620 / 51.38.225.243 search: no matches
```

The remaining searches returned expected historical documentation/test
guardrail hits and existing backend Active Nmap Basic no-live/reporting code;
they did not show a new `tools/runner/main.py` integration, a backend
live-to-`active-tools` call, a new public scanner claim, or a new unsafe result
claim.

## Remaining Gaps

- No backend-to-`active-tools` live client exists yet.
- No Compose runtime wiring is approved.
- No `/active/nmap-basic` container smoke was executed in this phase.
- No parser/executor live path was exercised by the ASGI service.
- The image still has a default no-run command, so future runtime service
  startup needs a separate approved wiring phase.
- Dependency pinning remains bounded by package ranges, not exact hashes.

## Decision

`ACTIVE_NMAP_BASIC_40_ACTIVE_TOOLS_ASGI_CONTAINER_NO_LIVE_SMOKE_PASSED`
