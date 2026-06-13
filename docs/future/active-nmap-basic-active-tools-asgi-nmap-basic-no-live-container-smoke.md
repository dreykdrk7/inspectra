# Active Nmap Basic: Active Tools ASGI Nmap Basic No-Live Container Smoke

Status:

`ACTIVE_NMAP_BASIC_41_ACTIVE_TOOLS_ASGI_NMAP_BASIC_NO_LIVE_CONTAINER_SMOKE_PASSED`

## Objective

Validate that the Docker-packaged internal `active-tools` ASGI app can answer
`POST /active/nmap-basic` inside a local container in no-live mode. This smoke
uses the same conceptual route the backend will eventually call, but it does
not execute Nmap, call backend, create jobs, create exports, use Compose, or
approve targets.

## Product Decision

This is a practical OSS/self-hosted integration step. It exercises the
containerized ASGI route with a valid backend-boundary payload and confirms the
service still returns controlled `not_executed` metadata. It is not a live scan
approval and not public scanner readiness.

## Image

The existing image was reused:

```text
docker image inspect inspectra-active-tools:asgi-smoke
```

Observed image details:

```text
Id: sha256:0b3a1f1df7e10f16c7c19508d781e6bc7ec0f1197670c45b289ad79f3fd897f6
User: appuser
Cmd: python -c "import json, shutil; print(json.dumps({'service':'active-tools','mode':'scaffold_no_run','nmap_present': shutil.which('nmap') is not None}))"
```

No rebuild was needed for this phase.

## Run Command

The ASGI service ran in one local container with the host port bound only to
loopback:

```text
docker run --rm -d --name inspectra-active-tools-asgi-post-smoke \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -p 127.0.0.1:18080:8080 \
  inspectra-active-tools:asgi-smoke \
  python -m uvicorn active_runner.app:app --host 0.0.0.0 --port 8080
```

The app listened on `0.0.0.0` inside the container so the Docker loopback-only
host publish could reach it. The host binding remained `127.0.0.1`; no public
host port, host networking, privileged mode, Docker socket, Compose runtime
wiring, or sensitive environment input was used.

## Health Response

The first request was local-only:

```text
GET http://127.0.0.1:18080/health
```

Observed response:

```text
200
{"service":"active-tools","status":"scaffold_ready","capabilities":{"active_nmap_basic":{"status":"disabled_no_scan","execution_enabled":false,"target_input_allowed":false}},"network_requests_sent":0,"nmap_executed":false}
```

## POST Payload

The `POST /active/nmap-basic` request used a synthetic container-loopback
contract payload:

```json
{
  "mode": "live_nmap_basic",
  "profile": "tcp_connect_small",
  "request_id": "req-test-redacted",
  "job_id": "job-test-redacted",
  "correlation_id": "corr-test-redacted",
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

Although the payload contains `127.0.0.1`, this phase did not execute Nmap or
send any target-bearing scan. The route remained no-live.

No owned-domain, VPS, LAN, third-party, `www.urlbreve.es`, `www.vildek.es`,
`app.vildek.es`, port `443`, or port `80` target was used.

## POST Response

The local-only request was:

```text
POST http://127.0.0.1:18080/active/nmap-basic
```

Observed response:

```text
200
{"service":"active-tools","status":"not_executed","capability":"active_nmap_basic","mode":"live_nmap_basic","profile":"tcp_connect_small","execution_enabled":false,"manual_validation_required":true,"reason":"active_tools_internal_service_skeleton_no_scan","observations":[],"job_created":false,"target_expansion_performed":false,"network_requests_sent":0,"summary":{"target_count":1,"port_count":1,"nmap_executed":false,"evidence_available":false},"warnings":["no_scan_service_skeleton"],"errors":[]}
```

Confirmed response properties:

- HTTP status was `200`.
- `status: not_executed`.
- `manual_validation_required: true`.
- `summary.nmap_executed: false`.
- `network_requests_sent: 0`.
- `job_created: false`.
- `observations: []`.
- No raw XML.
- No stdout or stderr.
- No command or raw args.
- No PTR hostname.
- No resolved IP evidence.
- No credentials, tokens, headers, or cookies.
- No vulnerability, exploitability, target-safety, all-ports-found, or
  full-scan wording.

## Cleanup

The smoke container was removed:

```text
docker rm -f inspectra-active-tools-asgi-post-smoke
```

Observed result:

```text
inspectra-active-tools-asgi-post-smoke
```

Cleanup verification:

```text
docker ps -a --filter name=inspectra-active-tools-asgi-post-smoke --format {{.Names}}
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
- No Compose runtime wiring.
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
.venv/bin/python -m pytest tools/tests/test_active_tools_asgi_service_skeleton.py
.venv/bin/python -m pytest tools/tests/test_active_tools_fake_execution_boundary.py
.venv/bin/python -m pytest tools/tests/test_active_tools_health_readiness.py
.venv/bin/python -m pytest tools/tests/test_active_tools_internal_service_skeleton.py
.venv/bin/python -m pytest backend/tests/test_backend.py -k "active_nmap or nmap_basic or boundary or redaction"
docker image inspect inspectra-active-tools:asgi-smoke
docker run --rm -d --name inspectra-active-tools-asgi-post-smoke --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges:true -p 127.0.0.1:18080:8080 inspectra-active-tools:asgi-smoke python -m uvicorn active_runner.app:app --host 0.0.0.0 --port 8080
.venv/bin/python -c "..."  # loopback-only GET /health
.venv/bin/python -c "..."  # loopback-only POST /active/nmap-basic
docker rm -f inspectra-active-tools-asgi-post-smoke
docker ps -a --filter name=inspectra-active-tools-asgi-post-smoke --format {{.Names}}
rg -n "subprocess|docker.sock|nmap --version|nmap -sT|tools/runner/main.py" tools/active_runner tools/tests docker docs README.md
rg -n "raw_xml|stdout|stderr|ptr_hostname|resolved_ip|script_output|nse|credentials|cookies|tokens|headers|disabled_no_scan|scaffold_ready|network_requests_sent|nmap_executed|not_executed|job_created" tools backend docs README.md
rg -n "vps-40567620|51.38.225.243" backend tools/tests
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" backend tools docs README.md
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

Results:

```text
tools/tests/test_active_tools_asgi_service_skeleton.py: 16 passed
tools/tests/test_active_tools_fake_execution_boundary.py: 34 passed
tools/tests/test_active_tools_health_readiness.py: 20 passed
tools/tests/test_active_tools_internal_service_skeleton.py: 24 passed
backend/tests/test_backend.py -k "active_nmap or nmap_basic or boundary or redaction": 73 passed, 307 deselected
GET /health: 200 scaffold_ready / disabled_no_scan / nmap_executed false
POST /active/nmap-basic: 200 not_executed / job_created false / network_requests_sent 0 / summary.nmap_executed false
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
- No live Nmap executor path was exercised by the ASGI service.
- No parser processing of real Nmap output happened in this phase.
- The image still defaults to scaffold no-run readiness; future service startup
  wiring needs a separate approved phase.

## Decision

`ACTIVE_NMAP_BASIC_41_ACTIVE_TOOLS_ASGI_NMAP_BASIC_NO_LIVE_CONTAINER_SMOKE_PASSED`
