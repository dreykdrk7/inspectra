# Active Nmap Basic Own-Domain Authorized Smoke Target Freeze

Decision:

```text
ACTIVE_NMAP_BASIC_28_OWN_DOMAIN_AUTHORIZED_SMOKE_TARGET_FREEZE_ACCEPTED
```

This docs-only own-domain target freeze selects one explicitly authorized domain
for a future extremely limited `active-tools` Nmap smoke. It does not execute
Docker, execute Nmap, execute `nmap --version`, run Nmap against a domain,
perform probes, perform manual DNS checks, send manual external HTTP traffic,
run `curl` against domains, open domains in a browser, use Compose, publish
ports, use host networking, use privileged mode, mount the Docker socket, change
backend/frontend/runner runtime, add runner HTTP endpoints, wire
backend-to-active-tools live calls, integrate archive/run-all, integrate Active
inside `tools/runner/main.py`, create migrations, create a tag, create a
release, approve LAN targets, approve a generic VPS target, approve arbitrary
public targets, approve public scanner behavior, or approve all candidate
domains together.

## Context

Accepted prior decisions:

- `ACTIVE_NMAP_BASIC_25_ACTIVE_TOOLS_NMAP_VERSION_NO_TARGET_PASSED`
- `ACTIVE_NMAP_BASIC_26_ACTIVE_TOOLS_LOCAL_SMOKE_TARGET_FREEZE_ACCEPTED`
- `ACTIVE_NMAP_BASIC_27_ACTIVE_TOOLS_CONTAINER_LOOPBACK_SMOKE_PASSED`

Previous commit:

```text
c5b69b6 test(active): run active tools container loopback smoke
```

Current state:

- `active-tools` builds.
- `active-tools` starts in no-target readiness.
- `nmap --version` works without a target.
- Container loopback smoke `127.0.0.1:65000` passed with a closed result.
- No backend-to-active-tools integration exists.
- No runner HTTP endpoint exists.
- No archive/run-all integration exists.
- No domain target has been approved before this freeze.

## Objective

Freeze the first own-domain target for a future tightly bounded Nmap smoke from
`active-tools`, before any domain-bearing command is executed.

This phase documents authorization, exact target, exact port, DNS semantics,
future command shape, interpretation, no-go criteria, and rollback. It does not
run the future command.

## Authorization Declared By The Operator

The operator states that these domains are owned/authorized candidates for
future phases:

- `www.vildek.es`;
- `app.vildek.es`;
- `www.urlbreve.es`.

This phase records that declaration as product/operator context. It does not
independently prove domain ownership, does not validate DNS, and does not
perform any live reachability check.

## Candidate Review

Candidate: `www.urlbreve.es`

- Chosen for the first own-domain freeze.
- Lower business-surface risk than `app.vildek.es`.
- Frozen only for a future port `443` smoke.

Candidate: `www.vildek.es`

- Not chosen for the first smoke.
- Remains blocked until a separate explicit phase chooses it.

Candidate: `app.vildek.es`

- Not chosen for the first smoke.
- Remains blocked for later phases because it is a business application
  surface.

## Frozen Target

Chosen exact target:

```text
www.urlbreve.es
```

Blocked targets:

- `www.vildek.es`;
- `app.vildek.es`;
- any other domain;
- any hostname other than `www.urlbreve.es`;
- any LAN target;
- any generic VPS target;
- any third-party target;
- any arbitrary public target;
- any range or target list.

Only one target is frozen. The three candidate domains are not approved as a
set.

## Frozen Ports

Chosen exact port set:

```text
[443]
```

Blocked:

- port `80`;
- any port other than `443`;
- ranges;
- `-p-`;
- top ports;
- discovery-style port selection;
- multiple ports.

Port `80` can be reconsidered only in a later explicit phase.

## DNS Decision

Decision: Option A.

A future execution may use the exact FQDN `www.urlbreve.es` as the Nmap target
and permit only the minimum DNS resolution Nmap requires for that exact FQDN.
No manual DNS check is performed in this phase. No separate `dig`, `host`,
`nslookup`, resolver query, browser, `curl`, or HTTP reachability check is
approved here.

Because the target is an FQDN, `-n` is not included in the proposed future
command. Keeping `-n` would conflict with using an unresolved FQDN as the target.
If a future phase requires `-n`, it must first freeze an IP address in a separate
phase and keep the domain only as an authorization reference.

Allowed later DNS behavior:

- only the resolution required by Nmap for exact target `www.urlbreve.es`;
- no subdomain discovery;
- no DNS expansion;
- no reverse-DNS sweep;
- no wildcard checks;
- no additional candidate names;
- no manual DNS preflight in this phase.

If a future execution cannot preserve those DNS limits, it must stop before
running Nmap and open a separate IP-freeze or DNS-semantics phase.

## Future Command Proposed, Not Executed

The future command is documented for the next separately approved execution
phase only. It was not executed in this phase.

```text
docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges:true inspectra-active-tools:build-smoke nmap -sT -Pn --max-retries 1 --host-timeout 30s -oX - -p 443 -- www.urlbreve.es
```

Command notes:

- this is not a `--network none` smoke because the future domain execution would
  require DNS and target network reachability;
- the future phase must still avoid host networking, published ports, privileged
  mode, and Docker socket mounts;
- no `--network host`;
- no `--privileged`;
- no published ports;
- no Docker socket mount;
- no bind-mounted target files;
- no sensitive environment variables;
- no raw user flags;
- no `-n` because the target is an FQDN and DNS decision Option A is selected;
- no `--script`;
- no NSE;
- no service/version detection;
- no OS detection;
- no UDP;
- no SYN scan;
- no brute force;
- no credential validation;
- no crawling.

## Limits

Future execution limits:

- target count: exactly one;
- target: exactly `www.urlbreve.es`;
- ports: exactly `[443]`;
- profile: `tcp_connect_small`;
- scan type: TCP connect with `-sT`;
- host discovery: disabled with `-Pn`;
- retries: `--max-retries 1`;
- host timeout: `--host-timeout 30s`;
- output: XML to stdout with `-oX -`;
- evidence: bounded and redacted before any report integration;
- storage: no persistent artifact unless a later phase explicitly defines it;
- backend: no live call unless a later phase explicitly implements and approves
  it.

## Expected Interpretation

A future result against `www.urlbreve.es:443` should be interpreted only as an
observed exposure or review indicator for that exact authorized domain and exact
port at that time.

It must not be presented as:

- a confirmed vulnerability;
- proof of exploitability;
- proof that the target is safe;
- a full scan;
- all ports found;
- proof of production readiness;
- proof of domain ownership;
- approval for arbitrary internet scanning;
- approval for a public scanner service.

## No-Go Criteria

A future own-domain smoke must stop before execution if any of these conditions
are present:

- target differs from `www.urlbreve.es`;
- more than one domain is included;
- `www.vildek.es` is included;
- `app.vildek.es` is included;
- a LAN, generic VPS, third-party, arbitrary public, or range target is used;
- port differs from `443`;
- port `80` is included;
- ranges, top ports, `-p-`, or discovery port selection are used;
- DNS expansion is added;
- subdomain discovery is added;
- reverse-DNS sweep behavior is added;
- crawling is added;
- NSE or `--script` is added;
- service/version detection is added;
- OS detection is added;
- UDP or SYN scan is added;
- brute force is added;
- credential validation is added;
- raw user flags are accepted;
- backend integration is added in the same phase;
- runner HTTP endpoint is added in the same phase;
- archive/run-all integration is added in the same phase;
- `tools/runner/main.py` integration is added in the same phase;
- report or UX copy claims confirmed vulnerability, exploitability, target
  safety, full scan, all ports found, or public scanner readiness.

## Future Rollback And Cleanup

A future execution phase should define rollback and cleanup before running:

- stop immediately on any no-go condition;
- do not retry with a different domain or port;
- do not broaden to `www.vildek.es`, `app.vildek.es`, port `80`, ranges, or top
  ports;
- do not switch to host network or privileged mode to force connectivity;
- do not create backend jobs, exports, or persistent artifacts unless that phase
  explicitly approves them;
- if Docker execution fails, record a blocked decision rather than changing
  scope;
- if Nmap fails in a controlled way, record the failure without adding flags;
- keep any captured output bounded and redacted;
- preserve this freeze document as the rollback reference.

## Still Blocked

Still blocked after this freeze:

- execution of the proposed command;
- Docker execution;
- Nmap execution;
- `nmap --version`;
- manual DNS checks;
- manual HTTP checks;
- `curl` or browser checks against domains;
- `www.vildek.es`;
- `app.vildek.es`;
- all three domains together;
- port `80`;
- LAN targets;
- generic VPS targets;
- arbitrary public targets;
- third-party targets;
- public scanner behavior;
- Compose;
- published ports;
- host network;
- privileged mode;
- Docker socket mounts;
- backend-to-active-tools live calls;
- runner HTTP endpoints;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- migrations, tags, and releases.

## Next Recommended Phase

Recommended next phase:

```text
ACTIVE-NMAP-BASIC-29-OWN-DOMAIN-AUTHORIZED-SMOKE-EXECUTION
```

That phase may execute the proposed command once only if it preserves this
freeze exactly: target `www.urlbreve.es`, port `443`, profile
`tcp_connect_small`, no raw flags, no scripts/NSE, no DNS expansion, no
subdomain discovery, no reverse-DNS sweep, no HTTP checks, no Compose, no
backend integration, no runner endpoint, no archive/run-all, and no scope
expansion.

If the project instead wants to keep `-n`, the next phase should be an IP-freeze
phase, not a domain execution phase.

## Final Decision

```text
ACTIVE_NMAP_BASIC_28_OWN_DOMAIN_AUTHORIZED_SMOKE_TARGET_FREEZE_ACCEPTED
```

The first future own-domain Nmap smoke target is frozen to exactly
`www.urlbreve.es` on port `443`. DNS decision Option A is accepted: a later
execution may allow only the minimal Nmap DNS resolution needed for that exact
FQDN, with no DNS expansion, no subdomain discovery, no reverse-DNS sweep, and
no manual DNS checks in this phase. `www.vildek.es`, `app.vildek.es`, port `80`,
LAN/VPS/public targets, backend integration, runner endpoints, archive/run-all,
public scanner behavior, and execution itself remain blocked until separately
approved.
