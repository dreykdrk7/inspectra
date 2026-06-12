# Active Nmap Basic Own-Domain Authorized Smoke Execution

Decision:

```text
ACTIVE_NMAP_BASIC_29_OWN_DOMAIN_AUTHORIZED_SMOKE_EXECUTION_PASSED
```

This one-shot own-domain smoke executes the previously frozen `active-tools`
Nmap command against exactly `www.urlbreve.es` on TCP port `443`. It does not
use `www.vildek.es`, `app.vildek.es`, more than one domain, port `80`, ranges,
`-p-`, top ports, LAN targets, generic VPS targets, third-party targets,
arbitrary public targets, manual DNS checks, `curl`, browser checks, manual HTTP
checks, Compose, published ports, host network, privileged mode, Docker socket
mounts, bind-mounted target files, sensitive environment variables, raw user
flags, NSE, `--script`, service/version detection, OS detection, UDP, SYN scan,
brute force, credential validation, crawling, DNS expansion, subdomain
discovery, backend/frontend/runner runtime changes, runner HTTP endpoints,
backend-to-active-tools live calls, jobs, exports, archive/run-all,
`tools/runner/main.py` integration, migrations, tags, or releases.

## Context

Accepted prior decisions:

- `ACTIVE_NMAP_BASIC_27_ACTIVE_TOOLS_CONTAINER_LOOPBACK_SMOKE_PASSED`
- `ACTIVE_NMAP_BASIC_28_OWN_DOMAIN_AUTHORIZED_SMOKE_TARGET_FREEZE_ACCEPTED`

Commit under test:

```text
3f5b1eb docs(active): freeze own domain nmap smoke target
```

Frozen target:

```text
www.urlbreve.es
```

Frozen port:

```text
443
```

DNS decision from the freeze:

```text
Option A: allow only the minimum DNS resolution Nmap needs for exact FQDN www.urlbreve.es.
```

Because the target is an FQDN and no IP-freeze exists, the command intentionally
does not use `-n`.

## Objective

Execute exactly one own-domain authorized Nmap smoke from `active-tools` using
the frozen target and port. The goal is only to record a bounded TCP observation
for the explicitly authorized FQDN at that moment.

This phase does not validate domain ownership independently, does not assess
production security, does not exercise backend integration, and does not create
Inspectra jobs or exports.

## Authorization Declared

The operator previously declared these domains as owned/authorized candidates:

- `www.vildek.es`;
- `app.vildek.es`;
- `www.urlbreve.es`.

Only `www.urlbreve.es` was selected and frozen for this first own-domain smoke.
The other candidate domains remain blocked.

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

Own-domain smoke, executed exactly once:

```text
docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges:true inspectra-active-tools:build-smoke nmap -sT -Pn --max-retries 1 --host-timeout 30s -oX - -p 443 -- www.urlbreve.es
```

Post-documentation source searches:

```text
rg -n "active-tools|active_nmap_basic|Nmap|nmap|own-domain|authorized|[www.urlbreve.es|www.vildek.es|app.vildek.es|443|DNS|target](http://www.urlbreve.es|www.vildek.es|app.vildek.es|443|DNS|target) freeze|smoke execution" docker docs README.md tools
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

The one permitted own-domain smoke exited with code `0` and produced bounded
XML output:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.95 scan initiated Fri Jun 12 20:00:05 2026 as: nmap -sT -Pn -&#45;max-retries 1 -&#45;host-timeout 30s -oX - -p 443 -&#45; www.urlbreve.es -->
<nmaprun scanner="nmap" args="nmap -sT -Pn -&#45;max-retries 1 -&#45;host-timeout 30s -oX - -p 443 -&#45; www.urlbreve.es" start="1781294405" startstr="Fri Jun 12 20:00:05 2026" version="7.95" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="1" services="443"/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="1781294405" endtime="1781294405"><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="51.38.225.243" addrtype="ipv4"/>
<hostnames>
<hostname name="www.urlbreve.es" type="user"/>
<hostname name="vps-40567620.vps.ovh.net" type="PTR"/>
</hostnames>
<ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="https" method="table" conf="3"/></port>
</ports>
<times srtt="31500" rttvar="31500" to="157500"/>
</host>
<runstats><finished time="1781294405" timestr="Fri Jun 12 20:00:05 2026" summary="Nmap done at Fri Jun 12 20:00:05 2026; 1 IP address (1 host up) scanned in 0.31 seconds" elapsed="0.31" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
```

The XML stylesheet reference is a local `file://` path inside the image output
format and is not an HTTP request.

## Result Summary

Observed result:

```text
target: www.urlbreve.es
resolved address reported by Nmap: 51.38.225.243
port: 443/tcp
state: open
reason: syn-ack
service field: https, method table
elapsed: 0.31 seconds
```

Nmap also reported one PTR hostname:

```text
vps-40567620.vps.ovh.net
```

No manual DNS check or reverse-DNS sweep command was run. The PTR value appeared
as part of Nmap's default DNS behavior for the single exact FQDN target. This is
recorded as a gap for future hardening because a later phase may prefer an
IP-freeze plus `-n` if PTR output must be avoided.

The `service` field is Nmap's table-based port label for TCP/443. No
service/version detection flag such as `-sV` was used.

## Conservative Interpretation

The observed `open` state is an observed TCP exposure / review indicator for
the exact authorized domain `www.urlbreve.es` on TCP port `443` at the time of
the smoke.

It is not:

- a confirmed vulnerability;
- proof of exploitability;
- proof that the target is safe;
- a full scan;
- proof that all ports were found;
- proof that production is secure or insecure;
- independent proof of domain ownership;
- approval for arbitrary internet scanning;
- approval for `www.vildek.es` or `app.vildek.es`;
- approval for a public scanner service.

## Guardrail Confirmations

Confirmed:

- Target was exactly `www.urlbreve.es`.
- Port was exactly `443`.
- No other domain was supplied.
- `www.vildek.es` was not used.
- `app.vildek.es` was not used.
- Port `80` was not used.
- No ranges, `-p-`, or top ports were used.
- No raw user flags were used.
- No NSE or `--script` was used.
- No service/version detection was used.
- No OS detection was used.
- No UDP scan was used.
- No SYN scan was requested.
- No brute force was used.
- No credential validation was used.
- No crawling was used.
- No manual DNS checks were run.
- No `curl` command was run.
- No browser was opened.
- No manual HTTP check was performed.
- No Compose command was run.
- No ports were published.
- No host network was used.
- No privileged mode was used.
- No Docker socket was mounted.
- No bind-mounted target file was used.
- No sensitive environment variables were passed.
- No backend API request was made.
- No backend-to-active-tools live call exists.
- No runner HTTP endpoint was added or called.
- No Inspectra job was created.
- No export was created.
- No archive/run-all integration was used.
- No `tools/runner/main.py` integration was used.

## No-Go Checks

No no-go condition was observed:

- target did not differ from `www.urlbreve.es`;
- target count did not exceed one;
- port did not differ from `443`;
- command did not include `www.vildek.es`, `app.vildek.es`, LAN, generic VPS,
  third-party, arbitrary public, range, or target-list input;
- command did not include port `80`, ranges, top ports, or `-p-`;
- command did not include scripts/NSE, raw flags, service/version detection, OS
  detection, UDP, SYN scan, brute force, credential validation, crawling,
  subdomain discovery, or DNS expansion flags;
- command did not introduce backend/frontend/runner runtime changes.

## Domains Still Blocked

Still blocked after this phase:

- `www.vildek.es`;
- `app.vildek.es`;
- all-domain or multi-domain smoke;
- port `80`;
- any target other than `www.urlbreve.es`;
- any port other than `443`;
- LAN targets;
- generic VPS targets;
- third-party targets;
- arbitrary public targets.

## Gaps Remaining

Remaining gaps for future phases:

- No backend-to-active-tools live boundary API is selected or implemented.
- No runner HTTP endpoint exists.
- No Inspectra job lifecycle has been exercised with real `active-tools`.
- No report/export path was exercised from this run.
- No Raw JSON integration was exercised from this run.
- No owned-domain result redaction review has been performed for backend reports.
- No IP-freeze exists for `www.urlbreve.es`.
- Nmap default DNS behavior emitted a PTR hostname; a future hardening phase may
  choose IP-freeze plus `-n` if PTR output should be blocked.
- `www.vildek.es`, `app.vildek.es`, port `80`, LAN/VPS/public target expansion,
  multi-domain scans, and public scanner behavior remain blocked.

## Final Decision

```text
ACTIVE_NMAP_BASIC_29_OWN_DOMAIN_AUTHORIZED_SMOKE_EXECUTION_PASSED
```

The first own-domain authorized `active-tools` Nmap smoke passed. It ran once
against exact target `www.urlbreve.es`, exact port `443`, and the frozen
`tcp_connect_small` command shape. Nmap reported `443/tcp` as `open` with
reason `syn-ack`. This is only an observed TCP exposure / review indicator for
the exact authorized FQDN at that moment. No manual DNS check, manual HTTP
check, `curl`, browser, Compose, backend integration, job, export, runner
endpoint, archive/run-all integration, alternate domain, port `80`, runtime
change, tag, release, vulnerability claim, exploitability claim, target-safety
claim, full-scan claim, all-ports-found claim, or public scanner approval was
introduced.
