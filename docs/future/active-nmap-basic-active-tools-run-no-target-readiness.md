# Active Nmap Basic Active Tools Run No-Target Readiness

Decision:

```text
ACTIVE_NMAP_BASIC_24_ACTIVE_TOOLS_RUN_NO_TARGET_READINESS_PASSED
```

This run no-target readiness phase starts the previously built `active-tools`
image exactly once with Docker runtime hardening flags and `--network none`. It
validates only that the scaffold no-run command starts, emits controlled JSON,
and exits without target traffic. It does not execute Nmap against any target,
run `nmap 127.0.0.1`, run `nmap localhost`, run `nmap --script`, perform
probes, perform DNS checks, send external HTTP traffic, run Compose, publish
ports, use host networking, use privileged mode, mount the Docker socket,
change backend/frontend/runner runtime, add runner HTTP endpoints, wire
backend-to-active-tools live calls, integrate archive/run-all, create
migrations, create a tag, or create a release.

## Context

Accepted prior decisions:

- `ACTIVE_NMAP_BASIC_21_ACTIVE_TOOLS_DOCKER_SCAFFOLD_NO_RUN_ACCEPTED`
- `ACTIVE_NMAP_BASIC_22_ACTIVE_TOOLS_DOCKER_STATIC_REVIEW_PASSED`
- `ACTIVE_NMAP_BASIC_23_ACTIVE_TOOLS_DOCKER_BUILD_ONLY_PASSED`

Commit under test:

```text
ae8ec59 test(active): build active tools docker image
```

Image under test:

```text
inspectra-active-tools:build-smoke
```

Previously observed image id:

```text
sha256:3c20b21166a8b20063f9c8985cc03ae3785f04844d36d6f6ad1dfe44e33bea31
```

## Objective

Validate the first no-target container start for the `active-tools` scaffold.
The only allowed runtime behavior is executing the image's default scaffold
command, which checks binary presence through Python path lookup and emits
readiness JSON. The phase does not execute the Nmap binary.

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

Image inspect:

```text
docker image inspect inspectra-active-tools:build-smoke --format '{{json .Config}}'
docker image inspect inspectra-active-tools:build-smoke --format 'ID={{.Id}} Size={{.Size}} RepoTags={{json .RepoTags}}'
```

No-target readiness run:

```text
docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges:true inspectra-active-tools:build-smoke
```

Post-documentation source searches:

```text
rg -n "active-tools|active_nmap_basic|Nmap|nmap|Dockerfile|docker-compose|profile|privileged|host network|network_mode|ports|docker.sock|network none" docker docs README.md tools
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" docker docs README.md tools
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

## Image Inspect Result

Image metadata inspection confirmed:

```text
ID=sha256:3c20b21166a8b20063f9c8985cc03ae3785f04844d36d6f6ad1dfe44e33bea31
Size=148280655
RepoTags=["inspectra-active-tools:build-smoke"]
User="appuser"
WorkingDir="/app"
```

The image default command remains:

```text
["python","-c","import json, shutil; print(json.dumps({'service':'active-tools','mode':'scaffold_no_run','nmap_present': shutil.which('nmap') is not None}))"]
```

## Observed Output

The no-target readiness run exited successfully with:

```json
{"service": "active-tools", "mode": "scaffold_no_run", "nmap_present": true}
```

This output was produced by the scaffold Python command. It confirms that the
container can start and that Nmap is present on the image path. It does not
execute Nmap.

## Runtime Guardrails Used

The readiness run used:

- `--rm`;
- `--network none`;
- `--read-only`;
- `--tmpfs /tmp:rw,noexec,nosuid,size=16m`;
- `--cap-drop ALL`;
- `--security-opt no-new-privileges:true`;
- no `--network host`;
- no `--privileged`;
- no `-p` or `--publish`;
- no Docker socket mount;
- no bind mounts;
- no sensitive environment variables.

## No-Target Confirmation

This phase did not run:

- `docker compose up`;
- any Compose service;
- `docker exec`;
- `nmap 127.0.0.1`;
- `nmap localhost`;
- `nmap --script`;
- `nmap --version`;
- any Nmap command;
- probes;
- DNS checks;
- external HTTP target traffic;
- backend API requests;
- job creation;
- backend-to-active-tools calls;
- runner HTTP endpoints;
- archive/run-all integration.

The container was started with `--network none`, so it had no Docker network
attachment for target traffic. No ports were published.

## Safety Review

The run confirms only no-target readiness of the scaffold command. It does not
approve scan execution, target authorization, runtime service exposure, backend
integration, or report evidence behavior.

Preserved boundaries:

- `active-tools` remains separate from backend, frontend, audit-tools/passive
  runner, and `tools/runner/main.py`;
- no backend runtime behavior changed;
- no frontend runtime behavior changed;
- no runner runtime behavior changed;
- no backend live call exists;
- no runner HTTP endpoint exists;
- no archive/run-all integration exists;
- no LAN, VPS, domain, public, third-party, or broad-range target is approved;
- no public scanner behavior is approved;
- no raw flags, scripts, NSE execution, stealth, evasion, brute force, exploit
  behavior, credential validation, crawling, DNS expansion, shell execution, or
  custom profiles are approved.

## Gaps Remaining

Remaining gaps for future phases:

- base image digest is still observed but not pinned in the Dockerfile;
- package-managed Nmap version is observed from build logs but not pinned;
- the Nmap binary has not been executed even for `--version`;
- no target-bearing Nmap command has been approved;
- Dockerized loopback target semantics remain unfrozen;
- no backend-to-active-tools boundary API has been selected or implemented;
- no runner HTTP endpoint is approved;
- no real target traffic is approved;
- runtime hardening was exercised only for this one no-target container start.

## Next Recommended Phase

Recommended next phase:

```text
ACTIVE-NMAP-BASIC-25-ACTIVE-TOOLS-NMAP-VERSION-NO-TARGET
```

That phase should remain separately approved and, if accepted, should only run a
no-target version/readiness command such as `nmap --version` under
`--network none`. It should still not run Nmap against a target, perform probes,
perform DNS checks, send external HTTP target traffic, approve LAN/VPS/domain or
public targets, wire backend live calls, add runner HTTP endpoints, or integrate
archive/run-all.

## Final Decision

```text
ACTIVE_NMAP_BASIC_24_ACTIVE_TOOLS_RUN_NO_TARGET_READINESS_PASSED
```

The `active-tools` image starts and exits successfully in no-target readiness
mode with `--network none`, emits controlled scaffold JSON, and confirms
`nmap_present: true` by path lookup only. No Nmap command was executed, no
target traffic occurred, no Compose service was started, no ports were
published, no runtime was changed, and no broader Active/Nmap approval was
granted.
