# Active Nmap Basic Active Tools Docker Static Review

Decision:

```text
ACTIVE_NMAP_BASIC_22_ACTIVE_TOOLS_DOCKER_STATIC_REVIEW_PASSED
```

This static review phase reviews the `active-tools` Docker/Compose scaffold
created for the future `active_nmap_basic` packaging path. It does not build
images, run Docker, execute Nmap, perform probes, perform DNS checks, send
external HTTP traffic, change backend/frontend/runner runtime, add runner HTTP
endpoints, integrate archive/run-all, create migrations, create a tag, or create
a release.

## Context

Accepted prior decisions:

- `ACTIVE_NMAP_BASIC_19_NMAP_PACKAGING_PLAN_ACTIVE_RUNNER_RECOMMENDED`
- `ACTIVE_NMAP_BASIC_20_ACTIVE_TOOLS_DOCKER_DESIGN_ACCEPTED`
- `ACTIVE_NMAP_BASIC_21_ACTIVE_TOOLS_DOCKER_SCAFFOLD_NO_RUN_ACCEPTED`

The accepted direction is to make Nmap available through a separate Dockerized
Active tools boundary, not through host-local Nmap as a normal requirement, not
through backend direct subprocess execution, and not by adding Active/Nmap into
the passive runner monolith.

## Files Reviewed

Reviewed scaffold files:

- `docker/active-tools/Dockerfile`
- `docker/active-tools/Dockerfile.dockerignore`
- `docker-compose.active-tools.example.yml`
- `tools/tests/test_active_tools_docker_scaffold_static.py`

Reviewed context documents:

- `docs/future/active-nmap-basic-active-tools-docker-design.md`
- `docs/future/active-nmap-basic-active-tools-docker-scaffold-no-run.md`
- `docs/future/active-nmap-basic-implementation-plan.md`
- `README.md`
- `docs/architecture.md`
- `docs/security-scope.md`

No secret-bearing environment file was opened or read.

## Static Findings

### Dockerfile

The scaffold Dockerfile passes static review for the current no-run boundary:

- it uses `python:3.12-slim`, aligned with current Python service images;
- it keeps `active-tools` separate from backend, frontend, audit-tools/passive
  runner, and `tools/runner/main.py`;
- it copies only `tools/active_runner` into the image;
- it installs only package-managed `nmap` and no broad scanner, exploit,
  brute-force, crawling, credential, fuzzing, or custom-script tooling;
- it does not run Nmap during build;
- it does not expose a port;
- it defines no healthcheck that could become a probe;
- it creates and switches to a non-root `appuser`;
- its default command only reports scaffold mode and binary presence if a later
  phase explicitly starts the container;
- it does not accept raw user flags, shell commands, custom profiles, scripts,
  credentials, headers, cookies, tokens, target files, or target lists.

This is acceptable for a scaffold that has not been built and is not wired into
runtime.

### Docker Ignore

The Dockerfile-specific ignore file is appropriate for the proposed repo-root
build context:

- it excludes local environment files by pattern;
- it excludes Git metadata, Python caches, local virtualenvs, node modules,
  frontend build output, runtime data, upload storage, result storage, logs, and
  temporary files;
- it limits accidental inclusion of unrelated application artifacts in a future
  build context.

The future build-only phase must still confirm the Docker frontend/build mode
honors `docker/active-tools/Dockerfile.dockerignore` for this path, or replace it
with an equivalent approved context strategy before any repeatable build claim.

### Compose Example

The Compose scaffold is acceptable as an example-only file:

- it is separate from the main `docker-compose.yml`;
- it requires profile `active`;
- it publishes no ports;
- it uses an internal network;
- it does not use host networking;
- it does not set `privileged: true`;
- it does not mount the Docker socket;
- it uses `read_only: true`;
- it provides `/tmp` tmpfs;
- it drops all capabilities;
- it sets `no-new-privileges:true`;
- it sets basic memory and process limits;
- it does not add backend-to-active-tools calls;
- it does not add runner HTTP endpoints;
- it does not integrate archive/run-all.

Normal `docker compose up` behavior for the existing application remains
unchanged because the example file is not the main Compose file.

### Static Tests

The existing static test file checks the main scaffold guardrails without
building images, running Docker, executing Nmap, making probes, resolving DNS,
or sending external HTTP traffic. The tests cover file presence, Active/passive
runner separation, no exposed ports in the Dockerfile, no scanning healthcheck,
no direct Nmap command shape, active Compose profile use, no published Compose
ports, no host network, no privileged mode, no Docker socket mount, and ignore
patterns for sensitive/runtime paths.

This review does not modify test code because the phase is documentation-only.

## Gaps

The scaffold is acceptable for static review, but the following gaps remain for
later phases:

- the base image is not pinned by digest;
- the Nmap package version is not pinned or recorded as image metadata;
- the Dockerfile has not been build-validated;
- the Compose example has not been run or converted into runtime wiring;
- Dockerfile-specific ignore behavior has not been validated by a real build;
- `mem_limit` and related hardening settings may need portability review across
  Compose implementations;
- container loopback semantics are not yet frozen for a Dockerized smoke;
- no internal active-tools boundary API has been selected or implemented;
- no backend live call to active-tools is approved;
- no runner HTTP endpoint is approved.

These gaps are not blockers for a static review pass. They are blockers for any
claim that the image is reproducible, runnable, smoke-tested, or production
ready.

## Residual Risks

Residual risks for later implementation:

- An operator could misread the example Compose file as permission to run
  Active/Nmap workflows before the build/run phases are approved.
- A future build could include unexpected files if the ignore strategy is not
  honored by the selected Docker frontend.
- Package drift could change the installed Nmap version unless pinning or
  metadata is added.
- A later smoke could accidentally target container loopback rather than the
  intended host-local smoke boundary.
- Future convenience changes could add public ports, host networking,
  privileged mode, Docker socket mounts, raw flags, NSE/script enablement, broad
  target support, or passive runner coupling.

## Build-Only Readiness Decision

The scaffold is safe to advance to a future separately approved build-only
phase, with these strict limits:

- build-only means no container start;
- no `docker compose up`;
- no Nmap execution;
- no target probes;
- no DNS checks;
- no external HTTP traffic;
- no backend-to-active-tools live calls;
- no runner HTTP endpoints;
- no archive/run-all integration;
- no `tools/runner/main.py` integration;
- no LAN, VPS, domain, third-party, broad-range, or public target approval.

The future build-only phase should validate only image construction, package
presence metadata, image contents, non-root posture, absence of public ports,
and no-run defaults.

## Still Blocked

The following remain blocked after this review:

- running Docker;
- running `docker build`;
- running `docker compose`;
- starting containers;
- executing Nmap;
- local, LAN, VPS, domain, third-party, or internet scanning;
- broad ranges, target expansion, crawling, DNS expansion, raw flags, scripts,
  NSE, stealth, evasion, brute force, exploit behavior, credential validation,
  custom profiles, shell execution, and target files;
- backend direct Nmap subprocess execution;
- backend live calls to `active-tools`;
- runner HTTP endpoints;
- frontend workflow changes;
- archive/run-all integration;
- release, tag, or public scanner behavior.

## Validation Evidence

Planned validation for this phase:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
.venv/bin/python -m pytest tools/tests/test_active_tools_docker_scaffold_static.py
```

Additional static checks should search Docker, docs, README, and tools for
`active-tools`, `active_nmap_basic`, Nmap/Docker terms, host-network/privileged
port exposure, Docker socket references, and no-scope wording. These checks are
textual only.

## Final Decision

```text
ACTIVE_NMAP_BASIC_22_ACTIVE_TOOLS_DOCKER_STATIC_REVIEW_PASSED
```

The `active-tools` Docker/Compose scaffold passes static review for a future
separately approved build-only phase. It remains unbuilt, unrun, disabled from
normal app startup, disconnected from backend live execution, disconnected from
runner HTTP endpoints, disconnected from archive/run-all, separated from the
passive runner, and not approved for Nmap execution or any target traffic.
