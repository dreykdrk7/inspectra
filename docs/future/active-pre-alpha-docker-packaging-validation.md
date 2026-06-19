# Active Pre-Alpha Docker Packaging Validation

Decision: `ACTIVE_PRE_ALPHA_DOCKER_PACKAGING_VALIDATION_06_ACCEPTED`

Status: Docker/Compose packaging validation for the Inspectra Active technical
alpha candidate. This phase used the existing repository packaging files first,
found three packaging blockers, applied the smallest packaging-only fixes, and
validated the root Compose package locally.

## Scope

This phase was limited to Docker/Compose packaging validation and documentation.

Performed:

- checked git state and current head;
- ran pre-Docker diff checks;
- ran a focused Active backend test slice;
- ran the frontend production build outside Docker;
- rendered root Compose config;
- built root Compose images;
- started root Compose services;
- checked backend health and frontend local headers;
- rendered the Active tools example config only;
- tore down validation containers;
- documented packaging blockers, fixes, and residual gaps.

Not performed:

- publishing a release;
- creating a version marker;
- uploading commits to a remote;
- remote server deployment;
- image capture;
- submitting Active jobs;
- real external target use;
- running the port-scanning tool.

Docker build/package dependency traffic occurred only during image build steps.
No target-directed protocol traffic was performed.

## Git State

Initial status:

```text
## main...origin/main
```

Initial head:

```text
1dd86cc docs(active): plan pre-alpha packaging
```

Branch tracking:

```text
main 1dd86cc [origin/main] docs(active): plan pre-alpha packaging
```

## Pre-Docker Baseline

Pre-Docker checks:

```text
git diff --check
git diff --cached --check
```

Result: both passed.

Focused Active backend slice:

```text
.venv/bin/pytest backend/tests/test_backend.py -k "active_nmap_basic or active_tls_basic or active_dns_inventory or active_dns_osint or active_http_basic_header_review"
```

Result: `352 passed, 338 deselected`.

Frontend production build:

```text
npm run build
```

Result: passed. The known Vite large-chunk warning remains.

## Root Compose Config Validation

Command:

```text
docker compose config
```

Result: passed.

Rendered services:

- `audit-tools`;
- `backend`;
- `frontend`.

Confirmed:

- `audit-tools` remains internal to Compose and exposes `8081/tcp`;
- backend publishes container port `8000`;
- frontend publishes container port `5173`;
- no Docker socket mount is rendered;
- no Active feature flag is forced on by the root Compose defaults;
- `audit-tools` stays on the internal runner path plus its existing egress
  network;
- backend keeps the internal runner path and now also has a host-access network
  for the documented local port;
- frontend has the host-access network for the documented local port.

## Build Validation

Initial command:

```text
docker compose build
```

Initial sandbox result: blocked before image build because Docker buildx tried
to update local Docker metadata under the operator home directory. The same
command was rerun with approved Docker access.

First build result: backend, frontend, and audit-tools built successfully.

Build dependency traffic observed:

- Docker base image metadata and layers;
- Python package downloads for backend and audit-tools during uncached build;
- npm package install for frontend during uncached build;
- Debian package index/package downloads for audit-tools during uncached build.

Initial frontend `npm ci` output reported audit warnings for two dependency
issues. This validation did not run dependency upgrade work.

Final command after packaging fixes:

```text
docker compose build
```

Final result: backend, frontend, and audit-tools built successfully.

Final images:

- `inspectra-backend`;
- `inspectra-frontend`;
- `inspectra-audit-tools`.

## Startup Validation

Initial command:

```text
docker compose up -d
```

The first startup found a backend image packaging blocker:

```text
ModuleNotFoundError: No module named 'active_runner'
```

Fix:

- `docker-compose.yml` now gives the backend build a named
  `active_runner` build context;
- `backend/Dockerfile` copies that context into `/app/active_runner`;
- the backend build context stays narrow and does not pull the whole
  repository into the backend image.

The next startup found a frontend packaging blocker:

```text
ENOENT: no such file or directory, mkdir '/app/node_modules/.vite-temp'
```

Fix:

- `frontend/Dockerfile` now builds the Vite production bundle during image
  build;
- `frontend/docker-static-server.mjs` serves the built `dist/` directory with
  Node's standard library;
- the frontend container no longer runs Vite dev mode at runtime.

The next startup found that host-published ports were not reachable while
backend/frontend were attached only to an internal Compose network.

Fix:

- `docker-compose.yml` now keeps the internal runner network and adds
  `inspectra_host_access` only for backend/frontend host access;
- default host ports remain `8000` and `5173`;
- optional local overrides were added for occupied developer machines:
  `INSPECTRA_BACKEND_HOST_PORT` and `INSPECTRA_FRONTEND_HOST_PORT`.

On this workstation, port `8000` was already owned by an unrelated Docker
container:

```text
cazorla-events-backend-1   0.0.0.0:8000->8000/tcp
```

No unrelated container was stopped. Final validation used alternate local ports
while preserving the default Compose ports.

Final startup command:

```text
INSPECTRA_BACKEND_HOST_PORT=18000 INSPECTRA_FRONTEND_HOST_PORT=15173 docker compose up -d
```

Result: passed.

Final `docker compose ps -a` result:

```text
inspectra-audit-tools   Up (healthy)   8081/tcp
inspectra-backend       Up (healthy)   0.0.0.0:18000->8000/tcp
inspectra-frontend      Up             0.0.0.0:15173->5173/tcp
```

Backend health check:

```text
curl -fsS http://localhost:18000/health
```

Result:

```json
{"status":"ok","service":"inspectra-backend"}
```

Frontend local check:

```text
curl -I http://localhost:15173/
```

Result: `HTTP/1.1 200 OK`.

Cleanup:

```text
INSPECTRA_BACKEND_HOST_PORT=18000 INSPECTRA_FRONTEND_HOST_PORT=15173 docker compose down
```

Result: containers and validation networks were removed.

## Active Tools Example Config

Command:

```text
COMPOSE_DISABLE_ENV_FILE=1 docker compose -f docker-compose.active-tools.example.yml --profile active config --no-interpolate
```

Result: passed.

The Active tools example remained config-only in this phase. Its container was
not started.

## Packaging Fixes Made

Changed files:

- `backend/Dockerfile`;
- `docker-compose.yml`;
- `frontend/Dockerfile`;
- `frontend/docker-static-server.mjs`;
- `docs/future/active-pre-alpha-docker-packaging-validation.md`.

Fix summary:

- backend image now includes the `active_runner` package needed by backend
  imports;
- frontend image now uses a production static bundle instead of runtime Vite
  dev mode;
- backend/frontend have a host-access Compose network for documented local
  ports while `audit-tools` remains on the internal runner path;
- default host ports remain unchanged, with local override hooks for conflicts.

## Remaining Gaps

- Image tag naming and provenance are not frozen.
- Dependency audit warnings from the frontend install should be triaged in a
  separate dependency/release-readiness phase if they matter for the alpha.
- Active tools remains example-only and separate from root Compose startup.
  That is acceptable for this alpha because root Compose does not require it
  for disabled-by-default Active operation.
- Release notes still need final packaging evidence.
- No remote deploy or remote smoke was performed.

## Release Readiness Recommendation

The root Compose package is now validated for local technical-alpha packaging
after the packaging-only fixes in this phase.

Recommended next microphase:

```text
ACTIVE_PRE_ALPHA_RELEASE_NOTES_FINALIZE_07
```

Then proceed to release/tag planning:

```text
ACTIVE_PRE_ALPHA_RELEASE_TAG_PLAN_07
```

Do not add another Active runtime capability before alpha publication.

## Decision

```text
ACTIVE_PRE_ALPHA_DOCKER_PACKAGING_VALIDATION_06_ACCEPTED
```
