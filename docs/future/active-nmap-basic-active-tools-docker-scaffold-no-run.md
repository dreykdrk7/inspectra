# Active Nmap Basic Active Tools Docker Scaffold No-Run

Decision:

```text
ACTIVE_NMAP_BASIC_21_ACTIVE_TOOLS_DOCKER_SCAFFOLD_NO_RUN_ACCEPTED
```

This scaffold-only phase creates the initial Docker/Compose packaging files for
the future `active-tools` service without building images, running Docker,
executing Nmap, changing backend/frontend/runner runtime, adding runner HTTP
endpoints, or wiring backend live calls.

## Context

Accepted prior decisions:

- `ACTIVE_NMAP_BASIC_19_NMAP_PACKAGING_PLAN_ACTIVE_RUNNER_RECOMMENDED`
- `ACTIVE_NMAP_BASIC_20_ACTIVE_TOOLS_DOCKER_DESIGN_ACCEPTED`

The prior packaging plan recommends a separate Dockerized Active runner/image
instead of normal host-local Nmap installation. The Docker design accepts
`active-tools` as a separate future service/image with no public port by
default, no host network by default, no privileged container, no Docker socket,
bounded execution, and separation from backend direct subprocess execution,
archive/run-all, and `tools/runner/main.py`.

## Scaffold Added

Files added:

- `docker/active-tools/Dockerfile`
- `docker/active-tools/Dockerfile.dockerignore`
- `docker-compose.active-tools.example.yml`
- `tools/tests/test_active_tools_docker_scaffold_static.py`

Documentation updated:

- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No existing Dockerfile, existing `docker-compose.yml`, backend runtime,
frontend runtime, passive runner runtime, or Active runner runtime file was
modified.

## Dockerfile Scaffold

The scaffold Dockerfile is located at:

```text
docker/active-tools/Dockerfile
```

It currently:

- uses `python:3.12-slim`, aligned with current backend and audit-tools images;
- declares the future Nmap packaging path through package installation;
- installs only `nmap` through the package manager;
- creates a non-root `appuser`;
- copies only `tools/active_runner` into the image path;
- does not copy `tools/runner/main.py`;
- exposes no port;
- defines no healthcheck;
- defines no HTTP endpoint;
- does not run Nmap at build time;
- has a non-scanning default command that reports scaffold mode and binary
  presence if a later phase explicitly starts the container.

This Dockerfile has not been built.

## Docker Ignore Scaffold

The scaffold ignore file is located at:

```text
docker/active-tools/Dockerfile.dockerignore
```

It excludes secret-bearing and unnecessary paths from a future repo-root build
context, including `.env`, `.env.*`, `.envrc`, `data`, upload/result storage,
node modules, build output, Python caches, and local virtual environments.

No secret file was opened or read by this phase.

## Compose Scaffold

The Compose scaffold is an example file:

```text
docker-compose.active-tools.example.yml
```

It intentionally does not modify the main `docker-compose.yml`, so normal
`docker compose up` behavior is unchanged.

The example service:

- is named `active-tools`;
- uses profile `active`;
- builds from `docker/active-tools/Dockerfile` if a later phase explicitly
  approves build validation;
- publishes no ports;
- uses an internal network;
- uses `read_only: true`;
- uses `/tmp` tmpfs;
- drops all capabilities;
- sets `no-new-privileges:true`;
- sets basic process and memory limits;
- does not use host network;
- does not set `privileged: true`;
- does not mount the Docker socket;
- does not add backend-to-active-tools calls;
- does not add archive/run-all integration.

This Compose example has not been run.

## Static Test Scaffold

The static test file:

```text
tools/tests/test_active_tools_docker_scaffold_static.py
```

checks that:

- scaffold files exist;
- Dockerfile keeps the Active boundary separate from `tools/runner/main.py`;
- Dockerfile exposes no port and defines no healthcheck;
- Dockerfile does not run Nmap via a `CMD ["nmap"...]` shape or `nmap -...`
  command;
- Compose example requires profile `active`;
- Compose example has no `ports:`;
- Compose example has no `network_mode: host`;
- Compose example has no `privileged: true`;
- Compose example has no Docker socket mount;
- ignore file excludes secret, runtime-data, node-module, cache, and local
  virtualenv paths.

These tests are static and do not build Docker images, run Docker, execute
Nmap, probe targets, perform DNS checks, or make external HTTP requests.

Validation run:

```text
.venv/bin/python -m pytest tools/tests/test_active_tools_docker_scaffold_static.py
```

Result:

```text
4 passed
```

YAML parsing was also checked with existing local PyYAML. The parser loaded
`docker-compose.active-tools.example.yml`, confirmed profile `active`, confirmed
no `ports` key on the `active-tools` service, and confirmed the internal network
setting. No Docker command was run for this validation.

## Preserved Boundaries

The scaffold preserves the accepted boundaries:

- `active-tools` remains separate from backend, frontend, audit-tools/passive
  runner, and `tools/runner/main.py`;
- backend direct subprocess execution for Nmap remains blocked;
- backend-to-active-tools live calls remain blocked;
- runner HTTP endpoints remain blocked;
- archive/run-all integration remains blocked;
- frontend behavior remains unchanged;
- feature flag defaults remain unchanged;
- no target scope is approved;
- LAN, VPS, domain, public, and third-party targets remain blocked;
- public scanner behavior remains blocked.

## Not Built Or Run

This phase did not:

- install Nmap on the host;
- execute Nmap;
- run Docker;
- run `docker build`;
- run `docker compose`;
- build images;
- start containers;
- perform probes;
- perform DNS checks;
- send external HTTP traffic;
- change runtime behavior;
- create migrations;
- create a tag;
- create a release.

## Remaining Risks

Risks for later implementation phases:

- Nmap package version pinning still needs a build-time policy.
- The Dockerfile has not been build-validated.
- The Compose example has not been run.
- Container loopback semantics still require a separately frozen smoke target.
- The future boundary API is still undecided.
- Resource limits and filesystem hardening may need adjustment after real build
  review.
- Operator enablement must remain explicit and easy to clean up.

## Next Microphase

Recommended next phase:

```text
ACTIVE-NMAP-BASIC-22-ACTIVE-TOOLS-DOCKER-STATIC-REVIEW
```

That phase should review the scaffold statically and, if explicitly scoped,
may decide whether a later build-only phase is safe. It should still not run
Nmap, perform probes, perform DNS checks, send external HTTP traffic, add
backend-to-active-tools live calls, add runner HTTP endpoints, integrate
archive/run-all, or widen targets.

## Final Decision

```text
ACTIVE_NMAP_BASIC_21_ACTIVE_TOOLS_DOCKER_SCAFFOLD_NO_RUN_ACCEPTED
```

The initial `active-tools` Docker/Compose scaffold exists for future review.
It remains disabled/no-run, separate from passive runner runtime, separate from
backend live execution, and not yet build- or smoke-validated.
