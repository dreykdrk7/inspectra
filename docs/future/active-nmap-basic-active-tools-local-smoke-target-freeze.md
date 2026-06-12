# Active Nmap Basic Active Tools Local Smoke Target Freeze

Decision:

```text
ACTIVE_NMAP_BASIC_26_ACTIVE_TOOLS_LOCAL_SMOKE_TARGET_FREEZE_ACCEPTED
```

This docs-only target semantics freeze decides how the first future
target-bearing Dockerized `active-tools` smoke should be interpreted before any
Nmap command is run with a target. It does not execute Docker, execute Nmap,
execute `nmap --version`, run Nmap against a target, perform probes, perform
DNS checks, send external HTTP traffic, use Compose, publish ports, use host
networking, use privileged mode, mount the Docker socket, change
backend/frontend/runner runtime, add runner HTTP endpoints, wire
backend-to-active-tools live calls, integrate archive/run-all, integrate Active
inside `tools/runner/main.py`, create migrations, create a tag, create a
release, approve LAN/VPS/domain/public targets, or approve public scanner
behavior.

## Context

Accepted prior decisions:

- `ACTIVE_NMAP_BASIC_23_ACTIVE_TOOLS_DOCKER_BUILD_ONLY_PASSED`
- `ACTIVE_NMAP_BASIC_24_ACTIVE_TOOLS_RUN_NO_TARGET_READINESS_PASSED`
- `ACTIVE_NMAP_BASIC_25_ACTIVE_TOOLS_NMAP_VERSION_NO_TARGET_PASSED`

Previous commit:

```text
97de5d5 test(active): record active tools nmap version
```

Current local image context:

```text
tag: inspectra-active-tools:build-smoke
observed Nmap: 7.95
```

The previous no-target readiness and version phases established only that the
image can start with no target and that packaged Nmap reports version `7.95`
under `--network none`. They did not approve target-bearing execution.

## Objective

Freeze the target semantics for a future first Dockerized `active-tools`
target-bearing smoke while keeping all real target execution blocked for this
phase.

The goal is to make the next target-bearing step narrow enough to confirm only
that a controlled Nmap invocation can run inside the container, without proving
external reachability, service exposure, internet scanning, or ownership of any
domain.

## Container Loopback Semantics

When Nmap runs inside `active-tools`, target `127.0.0.1` means the loopback
interface of that container process. It does not mean the host machine, the
backend container, the frontend container, another Compose service, a LAN
device, a VPS, or an owned domain.

With Docker `--network none`, the container has no normal Docker network
attachment. A future target `127.0.0.1` therefore stays inside the container's
own network namespace. It can validate only closed/local loopback execution
semantics for the container process. It cannot validate that Inspectra can reach
the host, a Compose peer, a LAN service, or the public internet.

## Relationship To The Earlier Host-Local Freeze

`ACTIVE_NMAP_BASIC_17_REAL_LOCAL_SMOKE_TARGET_FREEZE_ACCEPTED` froze a future
host-local smoke to `127.0.0.1:65000` for a host-local Nmap execution path. That
freeze remains valid for the host-local path, but it does not automatically
carry over to Dockerized `active-tools`.

The same literal address has different meaning in the container path:

- host-local `127.0.0.1` means host loopback;
- container `127.0.0.1` means container loopback;
- a Compose service name would mean an internal Docker network peer only if a
  future design explicitly creates that network and service;
- an owned domain would require external DNS/network behavior and a separate
  authorization freeze.

## Options Evaluated

Option A: internal container loopback.

- Future exact target: `127.0.0.1`.
- Future exact port: `65000`.
- Future Docker network: `--network none`.
- Interpretation: closed-port local container loopback smoke.
- Benefit: validates a minimal target-bearing Nmap invocation without external
  network reachability.
- Limitation: does not test host, LAN, Compose, VPS, or owned-domain
  reachability.

Option B: controlled dummy service on an internal Compose network.

- Would require an explicitly designed dummy service and internal network.
- Would introduce Compose service semantics and extra runtime design.
- Not approved in this phase.

Option C: owned authorized domain smoke.

- Candidate domains may be useful later, but they require DNS/network behavior,
  target authorization wording, no-go rules, and a separate target freeze.
- Not approved in this phase.

Option D: no target-bearing smoke yet.

- Safest if the project wants another no-run checkpoint before any target
  argument.
- Leaves execution readiness untested beyond `nmap --version`.

## Recommended First Target-Bearing Smoke

Recommended strategy for the first future target-bearing Dockerized smoke is
Option A.

Future exact target:

```text
127.0.0.1
```

Future exact port:

```text
65000
```

Future Docker network:

```text
--network none
```

Future interpretation:

```text
closed-port local container loopback smoke
```

This should be treated only as a controlled local execution check inside the
`active-tools` container. It is not evidence of real exposure, not an internet
scan, not a host-local reachability test, not a Compose service test, not a LAN
test, not a VPS/domain smoke, and not a product-ready Active scanner workflow.

## Result Interpretation For The Future Smoke

A future result against `127.0.0.1:65000` under `--network none` should be
interpreted as follows:

- closed or no open TCP port is the expected conservative baseline;
- the observation is about the container's own loopback only;
- the result should be worded as a local execution/review indicator;
- the result must not claim a confirmed vulnerability;
- the result must not claim exploitability;
- the result must not claim the target is safe;
- the result must not claim all ports were found;
- the result must not imply external reachability was tested.

The smoke should use only bounded output and redacted evidence. It should not
store raw command output beyond the already accepted bounded/redacted result
shape.

## Owned Domains Recorded As Future Candidates Only

The operator states that the following domains are owned/authorized candidates
for possible later phases:

- `www.vildek.es`;
- `app.vildek.es`;
- `www.urlbreve.es`.

This phase does not approve any of those domains as targets. They remain
blocked until a separate docs-first phase freezes one exact own-domain smoke
target, expected traffic, timing, no-go criteria, evidence limits, and rollback.

For a later own-domain target freeze, the recommended first candidate should be
one of:

- `www.urlbreve.es`;
- `www.vildek.es`.

`app.vildek.es` should remain later than the first own-domain smoke because it
is a business application surface.

## No-Go Criteria

A future target-bearing Dockerized smoke must stop before execution if any of
these conditions are present:

- target is not exactly `127.0.0.1`;
- port is not exactly `65000`;
- Docker network is not exactly `--network none`;
- Docker command uses host networking;
- Docker command uses privileged mode;
- Docker command publishes ports;
- Docker command mounts the Docker socket;
- Docker command uses Compose service discovery;
- command includes raw flags, `--script`, NSE, stealth, evasion, service/version
  detection, OS detection, UDP, brute force, exploit, credential validation,
  crawling, DNS expansion, target files, or shell execution;
- command includes a LAN, VPS, domain, public internet, or third-party target;
- backend-to-active-tools live calls are added in the same phase;
- runner HTTP endpoints are added in the same phase;
- archive/run-all integration is added in the same phase;
- evidence or report copy claims confirmed vulnerability, exploitability, target
  safety, full coverage, or public scanner readiness.

## Still Blocked

The following remain blocked after this freeze:

- `www.vildek.es`;
- `app.vildek.es`;
- `www.urlbreve.es`;
- LAN targets;
- VPS targets;
- public internet targets;
- third-party targets;
- Compose service targets;
- host-loopback reachability from inside Docker;
- backend integration;
- backend-to-active-tools live calls;
- runner HTTP endpoints;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- scanner public service behavior;
- any release/tag claim.

## Next Recommended Phase

Recommended next phase:

```text
ACTIVE-NMAP-BASIC-27-ACTIVE-TOOLS-CONTAINER-LOOPBACK-SMOKE
```

That phase may execute one target-bearing Nmap command only if it preserves this
freeze exactly:

- target `127.0.0.1`;
- port `65000`;
- Docker `--network none`;
- no Compose;
- no published ports;
- no host network;
- no privileged mode;
- no Docker socket mount;
- no scripts/NSE/raw flags;
- no DNS checks;
- no external HTTP traffic;
- no LAN/VPS/domain/public target.

A separate later own-domain freeze may be opened as:

```text
ACTIVE-NMAP-BASIC-XX-OWN-DOMAIN-AUTHORIZED-SMOKE-TARGET-FREEZE
```

That later phase should start with a single domain, preferably `www.urlbreve.es`
or `www.vildek.es`, and keep `app.vildek.es` blocked until after lower-risk
owned-domain smoke semantics are accepted.

## Final Decision

```text
ACTIVE_NMAP_BASIC_26_ACTIVE_TOOLS_LOCAL_SMOKE_TARGET_FREEZE_ACCEPTED
```

The first future Dockerized target-bearing smoke should use only container
loopback target `127.0.0.1`, port `65000`, and Docker `--network none`, and its
result should be interpreted only as a closed-port local container loopback
smoke. This phase does not run Docker or Nmap, does not approve the operator's
owned domains, does not approve LAN/VPS/domain/public targets, does not approve
Compose service targets, and does not approve backend/runner integration or
public scanner behavior.
