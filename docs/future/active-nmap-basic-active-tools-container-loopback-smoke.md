# Active Nmap Basic Active Tools Container Loopback Smoke

Decision:

```text
ACTIVE_NMAP_BASIC_27_ACTIVE_TOOLS_CONTAINER_LOOPBACK_SMOKE_PASSED
```

This target-bearing container-local smoke executes one minimal allowlisted Nmap
invocation inside the previously built `active-tools` image against only the
container's own loopback target. It uses Docker `--network none`, exact target
`127.0.0.1`, exact TCP port `65000`, and the frozen `tcp_connect_small` argv
shape. It does not use `localhost`, `::1`, a hostname, a domain, LAN, VPS,
public internet, third-party targets, Compose, published ports, host network,
privileged mode, Docker socket mounts, unnecessary bind mounts, sensitive
environment variables, DNS checks, external HTTP traffic, crawling, NSE,
`--script`, service/version detection, OS detection, UDP, SYN scan, brute force,
credential validation, raw user flags, backend/frontend/runner runtime changes,
runner HTTP endpoints, backend-to-active-tools live calls, archive/run-all,
`tools/runner/main.py` integration, migrations, tags, or releases.

## Context

Accepted prior decisions:

- `ACTIVE_NMAP_BASIC_23_ACTIVE_TOOLS_DOCKER_BUILD_ONLY_PASSED`
- `ACTIVE_NMAP_BASIC_24_ACTIVE_TOOLS_RUN_NO_TARGET_READINESS_PASSED`
- `ACTIVE_NMAP_BASIC_25_ACTIVE_TOOLS_NMAP_VERSION_NO_TARGET_PASSED`
- `ACTIVE_NMAP_BASIC_26_ACTIVE_TOOLS_LOCAL_SMOKE_TARGET_FREEZE_ACCEPTED`

Commit under test:

```text
4033d2c docs(active): freeze active tools local smoke target
```

Image under test:

```text
inspectra-active-tools:build-smoke
```

Previously observed Nmap version:

```text
7.95
```

## Objective

Validate that a minimal Nmap invocation can run inside the `active-tools`
container against its own loopback under `--network none`, without external
network reachability, DNS expansion, Compose, backend integration, jobs,
exports, runner endpoints, or approval for real targets.

This phase validates only container-local execution mechanics for the frozen
smoke target. It is not a security assessment of the host, a domain, a LAN, a
VPS, a Compose service, a production service, or Inspectra backend integration.

## Frozen Target And Port

Exact target:

```text
127.0.0.1
```

Exact port:

```text
65000
```

Docker network:

```text
--network none
```

Interpretation:

```text
closed-port local container loopback smoke
```

`127.0.0.1` here means the loopback interface inside the `active-tools`
container process. It does not mean the host loopback interface and does not
validate access to backend, frontend, a Compose peer, LAN, VPS, or any owned
domain.

## Commands Executed

Pre-checks:

```text
git status --short
git status --branch --short
git diff --check
git diff --cached --check
.venv/bin/python -m pytest tools/tests/test_active_tools_docker_scaffold_static.py
```

YAML parse check:

```text
.venv/bin/python -c "import pathlib, yaml; yaml.safe_load(pathlib.Path('docker-compose.active-tools.example.yml').read_text()); print('PyYAML available'); print('YAML parsed')"
```

Image inspect:

```text
docker image inspect inspectra-active-tools:build-smoke --format 'ID={{.Id}} Size={{.Size}} RepoTags={{json .RepoTags}} User={{.Config.User}} WorkingDir={{.Config.WorkingDir}}'
```

Target-bearing container loopback smoke, executed exactly once:

```text
docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges:true inspectra-active-tools:build-smoke nmap -sT -Pn -n --max-retries 1 --host-timeout 30s -oX - -p 65000 -- 127.0.0.1
```

Post-documentation source searches:

```text
rg -n "active-tools|active_nmap_basic|Nmap|nmap|127.0.0.1|65000|loopback|container|network none|container loopback smoke" docker docs README.md tools
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

## Observed Nmap Output

The one permitted target-bearing smoke exited with code `0` and produced bounded
XML output:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.95 scan initiated Fri Jun 12 19:40:44 2026 as: nmap -sT -Pn -n -&#45;max-retries 1 -&#45;host-timeout 30s -oX - -p 65000 -&#45; 127.0.0.1 -->
<nmaprun scanner="nmap" args="nmap -sT -Pn -n -&#45;max-retries 1 -&#45;host-timeout 30s -oX - -p 65000 -&#45; 127.0.0.1" start="1781293244" startstr="Fri Jun 12 19:40:44 2026" version="7.95" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="1" services="65000"/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="1781293244" endtime="1781293244"><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
</hostnames>
<ports><port protocol="tcp" portid="65000"><state state="closed" reason="conn-refused" reason_ttl="0"/></port>
</ports>
<times srtt="56" rttvar="5000" to="100000"/>
</host>
<runstats><finished time="1781293244" timestr="Fri Jun 12 19:40:44 2026" summary="Nmap done at Fri Jun 12 19:40:44 2026; 1 IP address (1 host up) scanned in 0.02 seconds" elapsed="0.02" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
```

Observed result:

```text
target: 127.0.0.1
port: 65000/tcp
state: closed
reason: conn-refused
elapsed: 0.02 seconds
```

## Interpretation

The observed `closed` state is the expected conservative result for the frozen
container loopback smoke. It means only that, from inside the isolated
`active-tools` container, a TCP connect scan to its own `127.0.0.1:65000`
completed and received a connection-refused result.

This does not prove:

- host security;
- host exposure;
- external reachability;
- Compose connectivity;
- backend integration;
- runner endpoint behavior;
- report/export behavior;
- ownership or reachability of any domain;
- production readiness;
- target safety;
- complete port coverage;
- confirmed vulnerability or exploitability.

## Guardrail Confirmations

Confirmed:

- Docker was run with `--network none`.
- Target was exactly `127.0.0.1`.
- Port was exactly `65000`.
- Nmap used `-n`, so no DNS resolution was requested.
- Nmap used `-sT`, not SYN scan.
- Nmap used `-Pn`, so no host discovery probe was needed.
- No NSE or `--script` was used.
- No service/version detection was used.
- No OS detection was used.
- No UDP scan was used.
- No `localhost`, `::1`, hostname, domain, LAN, VPS, public, or third-party
  target was used.
- No `www.vildek.es`, `app.vildek.es`, or `www.urlbreve.es` target was used.
- No Compose command was run.
- No ports were published.
- No host network was used.
- No privileged mode was used.
- No Docker socket was mounted.
- No unnecessary bind mounts were used.
- No sensitive environment variables were passed.
- No external HTTP target traffic was sent.
- No backend API request was made.
- No job was created.
- No export was created.
- No runner HTTP endpoint was added or called.
- No archive/run-all integration was used.

The XML stylesheet reference is a local `file://` path inside the image metadata
output format and is not an HTTP request.

## No-Go Checks

No-go conditions were not observed:

- target did not differ from `127.0.0.1`;
- port did not differ from `65000`;
- Docker network did not differ from `--network none`;
- command did not use host network, privileged mode, published ports, Docker
  socket, Compose, or bind-mounted inputs;
- command did not include raw user flags, scripts, NSE, stealth/evasion,
  service/version detection, OS detection, UDP, SYN scan, brute force,
  credential validation, crawling, DNS expansion, target files, or shell
  execution;
- command did not use LAN, VPS, domain, public internet, or third-party targets;
- backend/frontend/runner runtime was not changed.

## Owned Domains Still Blocked

The following operator-owned candidate domains remain recorded for future
separate phases only and were not used:

- `www.vildek.es`;
- `app.vildek.es`;
- `www.urlbreve.es`.

A later own-domain target freeze should still be opened separately before any
domain-bearing Nmap command is considered. `app.vildek.es` remains later than a
first lower-risk own-domain smoke because it is a business application surface.

## Gaps Remaining

Remaining gaps for future phases:

- no owned-domain target freeze has been accepted;
- no LAN, VPS, public, or Compose service target is approved;
- no backend-to-active-tools live boundary API is selected or implemented;
- no runner HTTP endpoint exists;
- no Inspectra job lifecycle was exercised with real `active-tools`;
- no report/export path was exercised from this run;
- no Raw JSON integration was exercised from this run;
- no base-image digest pinning or package-version pinning was added;
- public scanner behavior remains blocked.

## Final Decision

```text
ACTIVE_NMAP_BASIC_27_ACTIVE_TOOLS_CONTAINER_LOOPBACK_SMOKE_PASSED
```

The first target-bearing Dockerized `active-tools` smoke passed using exactly
the frozen container-loopback target `127.0.0.1`, port `65000`, Docker
`--network none`, and the allowlisted `tcp_connect_small` argv shape. Nmap
reported `65000/tcp` as `closed` with `conn-refused` inside the container. No
external network, DNS, HTTP target traffic, Compose service, backend
integration, job, export, runner endpoint, archive/run-all integration, owned
domain target, LAN/VPS/public target, runtime change, tag, or release was used
or approved.
