# Active Nmap Basic Active Tools Docker Build-Only

Decision:

```text
ACTIVE_NMAP_BASIC_23_ACTIVE_TOOLS_DOCKER_BUILD_ONLY_PASSED
```

This build-only phase validates that the `active-tools` Docker scaffold can
build as a local image. It does not start containers, run `docker compose up`,
run `docker run`, execute Nmap, execute commands inside the image, perform
probes, perform DNS checks, send target traffic, change backend/frontend/runner
runtime, add runner HTTP endpoints, wire backend-to-active-tools live calls,
integrate archive/run-all, create migrations, create a tag, or create a
release.

## Context

Accepted prior decisions:

- `ACTIVE_NMAP_BASIC_20_ACTIVE_TOOLS_DOCKER_DESIGN_ACCEPTED`
- `ACTIVE_NMAP_BASIC_21_ACTIVE_TOOLS_DOCKER_SCAFFOLD_NO_RUN_ACCEPTED`
- `ACTIVE_NMAP_BASIC_22_ACTIVE_TOOLS_DOCKER_STATIC_REVIEW_PASSED`

Commit under test:

```text
b900ecc docs(active): review active tools docker scaffold
```

## Objective

Confirm that the scaffold packaging path is viable enough for the next review
step by building the image from:

```text
docker/active-tools/Dockerfile
```

The validation is intentionally limited to image construction and image
metadata inspection. Package download traffic and base-image download traffic
from the Docker build are the only external traffic allowed in this phase.

## Commands Executed

Static pre-checks:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
.venv/bin/python -m pytest tools/tests/test_active_tools_docker_scaffold_static.py
```

YAML parse check:

```text
.venv/bin/python -c "... yaml.safe_load('docker-compose.active-tools.example.yml') ..."
```

Build-only command:

```text
docker build -f docker/active-tools/Dockerfile -t inspectra-active-tools:build-smoke .
```

Image inspect commands:

```text
docker image inspect inspectra-active-tools:build-smoke --format '{{json .Config}}'
docker image inspect inspectra-active-tools:build-smoke --format 'ID={{.Id}} Size={{.Size}} RepoTags={{json .RepoTags}}'
```

Two earlier `docker image inspect` formatting attempts failed because the
template referenced absent optional metadata fields. They did not start a
container, execute Nmap, or affect the build result.

Post-documentation source searches:

```text
rg -n "active-tools|active_nmap_basic|Nmap|nmap|Dockerfile|docker-compose|profile|privileged|host network|network_mode|ports|docker.sock" docker docs README.md tools
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" docker docs README.md tools
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

## Build Result

Result:

```text
PASSED
```

Local image tag:

```text
inspectra-active-tools:build-smoke
```

Image metadata from inspect:

```text
ID=sha256:3c20b21166a8b20063f9c8985cc03ae3785f04844d36d6f6ad1dfe44e33bea31
Size=148280655
RepoTags=["inspectra-active-tools:build-smoke"]
User="appuser"
WorkingDir="/app"
```

The image config command remains the scaffold no-run command:

```text
["python","-c","import json, shutil; print(json.dumps({'service':'active-tools','mode':'scaffold_no_run','nmap_present': shutil.which('nmap') is not None}))"]
```

This command was inspected as metadata only. It was not executed.

## Build Evidence

The build completed successfully using Docker's default builder.

Observed build facts:

- Docker loaded `docker/active-tools/Dockerfile`;
- Docker resolved `python:3.12-slim` to an immutable digest for this build;
- build context transfer was small, reported as `81.56kB`;
- package manager build traffic fetched Debian package indexes and packages;
- `apt-get install --no-install-recommends nmap` installed package-managed Nmap
  and package dependencies during the image build;
- Docker copied only `tools/active_runner` into `/app/active_runner`;
- Docker exported and tagged the image as
  `inspectra-active-tools:build-smoke`.

The build output reported package-managed `nmap` version `7.95+dfsg-3` from the
Debian package repository. This was observed from package installation output,
not by running `nmap --version`.

## No-Run Confirmation

This phase did not run:

- `docker run`;
- `docker compose up`;
- `docker exec`;
- container startup;
- the image `CMD`;
- Nmap;
- `nmap --version` inside a container;
- target probes;
- DNS checks;
- external HTTP target traffic;
- backend-to-active-tools calls;
- runner HTTP endpoints;
- archive/run-all integration.

The only external traffic allowed and observed was normal Docker build/package
download traffic for base image and Debian package acquisition.

## Safety Review

The build confirms packaging viability only. It does not prove runtime safety,
target authorization, scan behavior, output parsing, report redaction, or smoke
correctness.

Preserved boundaries:

- `active-tools` remains separate from backend, frontend, audit-tools/passive
  runner, and `tools/runner/main.py`;
- no public service is started;
- no public port is published by this phase;
- no host network or privileged runtime is exercised;
- no Docker socket mount is exercised;
- no Active target is approved;
- no LAN, VPS, domain, public, third-party, broad-range, or scanner-public
  behavior is approved;
- no raw flags, scripts, NSE execution, stealth, evasion, brute force, exploit
  behavior, credential validation, crawling, DNS expansion, shell execution, or
  custom profiles are approved.

## Gaps Remaining

Remaining gaps for future phases:

- base image digest is observed during the build but not pinned in the
  Dockerfile;
- package-managed Nmap version is observed from build logs but not pinned in
  the Dockerfile;
- image provenance and rebuild reproducibility are not frozen;
- no runtime hardening has been exercised by starting a container;
- no Nmap binary readiness command has been run inside the container;
- no no-target readiness phase has validated the image `CMD`;
- no Dockerized loopback target semantics are frozen;
- no backend-to-active-tools boundary API is selected or implemented;
- no runner HTTP endpoint is approved;
- no real target traffic is approved.

## Next Recommended Phase

Recommended next phase:

```text
ACTIVE-NMAP-BASIC-24-ACTIVE-TOOLS-RUN-NO-TARGET-READINESS
```

That phase should remain separate and may only be considered if explicitly
approved. It should decide whether starting the built image without target
traffic is acceptable, and it should still not execute Nmap against a target,
perform probes, perform DNS checks, send external HTTP target traffic, approve
LAN/VPS/domain/public targets, wire backend live calls, add runner HTTP
endpoints, or integrate archive/run-all.

## Final Decision

```text
ACTIVE_NMAP_BASIC_23_ACTIVE_TOOLS_DOCKER_BUILD_ONLY_PASSED
```

The `active-tools` Docker scaffold built successfully as
`inspectra-active-tools:build-smoke`. Image metadata was inspected without
starting a container. No Nmap command was executed, no container was run, no
target traffic occurred, no runtime was changed, and no broader Active/Nmap
approval was granted.
