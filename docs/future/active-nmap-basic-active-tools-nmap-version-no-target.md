# Active Nmap Basic Active Tools Nmap Version No-Target

Decision:

```text
ACTIVE_NMAP_BASIC_25_ACTIVE_TOOLS_NMAP_VERSION_NO_TARGET_PASSED
```

This no-target version readiness phase runs only `nmap --version` inside the
previously built `active-tools` image under Docker runtime hardening flags and
`--network none`. It does not execute Nmap against any target, run
`nmap 127.0.0.1`, run `nmap localhost`, run `nmap <hostname>`, run
`nmap --script`, execute NSE, perform probes, perform DNS checks, send external
HTTP traffic, run Compose, publish ports, use host networking, use privileged
mode, mount the Docker socket, pass sensitive environment variables, change
backend/frontend/runner runtime, add runner HTTP endpoints, wire
backend-to-active-tools live calls, integrate archive/run-all, create
migrations, create a tag, or create a release.

## Context

Accepted prior decisions:

- `ACTIVE_NMAP_BASIC_23_ACTIVE_TOOLS_DOCKER_BUILD_ONLY_PASSED`
- `ACTIVE_NMAP_BASIC_24_ACTIVE_TOOLS_RUN_NO_TARGET_READINESS_PASSED`

Commit under test:

```text
dfde518 test(active): run active tools no-target readiness
```

Image under test:

```text
inspectra-active-tools:build-smoke
```

## Objective

Confirm the packaged Nmap binary reports its version inside the `active-tools`
image without a target, without scan behavior, and without network access.

This phase intentionally does not use the default scaffold command. It overrides
the container command with exactly:

```text
nmap --version
```

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
docker image inspect inspectra-active-tools:build-smoke --format 'ID={{.Id}} Size={{.Size}} RepoTags={{json .RepoTags}} User={{.Config.User}} WorkingDir={{.Config.WorkingDir}}'
```

No-target Nmap version readiness:

```text
docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges:true inspectra-active-tools:build-smoke nmap --version
```

Post-documentation source searches:

```text
rg -n "active-tools|active_nmap_basic|Nmap|nmap|Dockerfile|docker-compose|profile|privileged|host network|network_mode|ports|docker.sock|network none|nmap --version" docker docs README.md tools
rg -n "confirmed vulnerability|exploitable|target is safe|all ports found|scan the internet|full network scan|brute force|credential validation|crawl|NSE|--script|raw flags|arbitrary internet scanning|broad ranges|public scanner|SaaS" docker docs README.md tools
rg -n "active_nmap_basic|nmap_basic" tools/runner/main.py backend/app/services.py backend/app/main.py
```

## Image Inspect Result

Image metadata inspection confirmed:

```text
ID=sha256:3c20b21166a8b20063f9c8985cc03ae3785f04844d36d6f6ad1dfe44e33bea31
Size=148280655
RepoTags=["inspectra-active-tools:build-smoke"]
User=appuser
WorkingDir=/app
```

The prompt context included a duplicated image-id fragment. The local observed
image id above is the actual value from `docker image inspect`.

## Observed Nmap Version Output

The no-target version command exited successfully with:

```text
Nmap version 7.95 ( https://nmap.org )
Platform: x86_64-pc-linux-gnu
Compiled with: liblua-5.4.7 openssl-3.5.6 libssh2-1.11.1 libz-1.3.1 libpcre2-10.46 libpcap-1.10.5 nmap-libdnet-1.12 ipv6
Compiled without:
Available nsock engines: epoll poll select
```

Observed version:

```text
7.95
```

This confirms version/presence only. It is not a scan, not a probe, not a DNS
check, and not target traffic.

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
- `nmap <hostname>`;
- `nmap --script`;
- NSE;
- any target-bearing Nmap command;
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

The run confirms only no-target Nmap version readiness. It does not approve
scan execution, target authorization, runtime service exposure, backend
integration, report evidence behavior, or public scanner use.

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
- package-managed Nmap version is observed but not pinned;
- no target-bearing Nmap command has been approved;
- Dockerized loopback target semantics remain unfrozen;
- no authorized local target smoke has been approved in the container;
- no backend-to-active-tools boundary API has been selected or implemented;
- no runner HTTP endpoint is approved;
- no real target traffic is approved;
- runtime hardening has been exercised only for no-target container starts.

## Next Recommended Phase

Recommended next phase:

```text
ACTIVE-NMAP-BASIC-26-ACTIVE-TOOLS-LOCAL-SMOKE-TARGET-FREEZE
```

That phase should remain documentation-first and should freeze any future
Dockerized local smoke target semantics before target-bearing execution. It
should not run Nmap against a target, perform probes, perform DNS checks, send
external HTTP target traffic, approve LAN/VPS/domain or public targets, wire
backend live calls, add runner HTTP endpoints, or integrate archive/run-all.

## Final Decision

```text
ACTIVE_NMAP_BASIC_25_ACTIVE_TOOLS_NMAP_VERSION_NO_TARGET_PASSED
```

The `active-tools` image successfully ran `nmap --version` once under
`--network none` and strict runtime flags. Nmap version `7.95` was observed.
No target was supplied, no scan was run, no DNS or HTTP target traffic occurred,
no Compose service was started, no ports were published, no runtime was changed,
and no broader Active/Nmap approval was granted.
