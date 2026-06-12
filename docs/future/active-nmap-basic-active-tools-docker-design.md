# Active Nmap Basic Active Tools Docker Design

Decision:

```text
ACTIVE_NMAP_BASIC_20_ACTIVE_TOOLS_DOCKER_DESIGN_ACCEPTED
```

This docs-only phase designs the future Docker/Compose architecture for a
separate Active runner service, tentatively `active-tools`, that can package
Nmap for the future `active_nmap_basic` capability. It does not modify any
Dockerfile, modify Compose, install Nmap, build images, start containers,
execute Nmap, run probes, perform DNS checks, send external HTTP traffic, or
change backend, frontend, or runner runtime behavior.

## Objective

Design a Dockerized Active tools boundary that keeps Nmap availability
reproducible while preserving the existing safety model:

- backend validates requests, owns jobs, and stores redacted results;
- backend does not execute Nmap directly;
- backend does not import subprocess for Nmap;
- `tools/runner/main.py` remains passive and does not absorb Active/Nmap;
- archive/run-all does not trigger Active/Nmap;
- `active_nmap_basic` stays disabled by default and explicit opt-in only.

## Context

Microphase 18 correctly blocked the first real local smoke because no local
Nmap binary was available:

```text
ACTIVE_NMAP_BASIC_18_REAL_LOCAL_SMOKE_EXECUTION_BLOCKED_NMAP_MISSING
```

Microphase 19 then recommended packaging Nmap inside a separate Dockerized
Active runner/image instead of treating host-local Nmap installation as the
normal Inspectra requirement:

```text
ACTIVE_NMAP_BASIC_19_NMAP_PACKAGING_PLAN_ACTIVE_RUNNER_RECOMMENDED
```

This phase turns that recommendation into a concrete architecture design only.
It intentionally stops before Dockerfile or Compose implementation.

## Proposed Architecture

The future topology should add one isolated Active service:

```text
backend
frontend
audit-tools / passive runner
active-tools
```

Boundary rules:

- `active-tools` is a separate Docker image/service for Active tooling.
- `active-tools` packages Nmap and future tightly scoped Active tools.
- `active-tools` is separate from backend, frontend, audit-tools/passive runner,
  and `tools/runner/main.py`.
- backend communicates with `active-tools` only through a controlled internal
  boundary in a future phase.
- no public port is exposed by default.
- no archive/run-all path calls `active-tools`.
- frontend copy and confirmations remain separate from archive actions.

The design is intentionally modular. Passive archive/file analysis and Active
network tooling must remain independently understandable, configurable,
testable, and hardenable.

## Image Design

Tentative image/service name:

```text
active-tools
```

Future Dockerfile location:

```text
docker/active-tools/Dockerfile
```

The exact path can be adjusted in the implementation phase if the repository's
Docker layout chooses a different convention. This design does not create that
file.

Proposed base image:

- Prefer a slim Debian-family Python image aligned with Inspectra's supported
  Python runtime if the service needs Python for validation, execution control,
  and parsing.
- Pin the base image by immutable digest in the future implementation.
- Avoid broad distro images that include unrelated tooling.
- Avoid Alpine unless a later implementation review confirms Nmap behavior,
  package pinning, and Python dependencies are equivalent for this use.

Future Nmap installation strategy:

- Install only Nmap and minimum runtime dependencies.
- Pin Nmap version where the package source supports it.
- If exact package pinning is not reliable, pin the base image digest, record
  the package repository snapshot/version used at build time, and expose the
  Nmap version as image metadata and a non-scanning readiness value.
- Do not install NSE script bundles beyond what the package requires for the
  binary, and do not enable NSE execution in the command builder.
- Do not install brute-force, exploitation, crawling, credential, fuzzing, or
  broad discovery tools.

Image contents should be minimal:

- Python runtime only if needed for the Active runner process.
- Nmap binary.
- Inspectra Active runner code required for `active_nmap_basic`.
- No Docker CLI.
- No Docker socket tooling.
- No shell-based orchestration scripts that accept user input.
- No extra scanners.
- No credential stores.
- No bundled target lists.

## Compose Service Design

Tentative Compose service name:

```text
active-tools
```

Activation:

- Disabled by default.
- Enabled only by an explicit Compose profile or equivalent operator opt-in,
  for example a future `active` profile.
- Runtime `active_nmap_basic` still also requires the backend feature flag.
- Availability of the service must not imply authorization to run scans.

Networking:

- Attach `active-tools` only to a private internal Compose network shared with
  backend when explicitly enabled.
- Do not publish ports to the host by default.
- Do not attach `active-tools` to frontend-facing networks unless a later
  review proves it is necessary.
- Do not use `network_mode: host` by default.
- Do not grant direct access to the Docker socket.

Backend communication:

- backend-to-active-tools communication should use service discovery on the
  internal network in a future phase.
- The boundary must be authenticated or otherwise constrained to the internal
  deployment context if an HTTP service is selected.
- The backend must still perform auth, owner-scope, feature-flag, contract,
  target, port, confirmation, and redaction checks before handing work to
  `active-tools`.

No Compose implementation is made in this phase.

## Security Controls

Future service hardening should start from:

- no `privileged`;
- no Docker socket mount;
- no host network by default;
- no public ports by default;
- drop all Linux capabilities by default, then add back only the minimum proven
  necessary for the accepted Nmap profile;
- prefer TCP connect scans (`-sT`) that do not require raw socket capabilities;
- run as a non-root user where feasible;
- read-only filesystem where feasible;
- tmpfs for temporary working directories where feasible;
- no persistent writable volume unless a later phase proves it is needed;
- bounded CPU, memory, process, and file-descriptor limits where supported;
- strict timeout controls at both request and subprocess layers;
- structured logs that avoid raw targets, raw commands, stdout, stderr, raw XML,
  secrets, tokens, cookies, headers, and credentials.

The `tcp_connect_small` profile is intentionally compatible with avoiding raw
packet capabilities. If a later phase discovers a capability is needed, that
phase must document why, prove it is minimal, and keep SYN/UDP/OS/service
version detection out of scope unless separately approved.

## Execution Limits

The future `active-tools` execution path must preserve existing runner-side
limits:

- allowlisted argv construction only;
- argv list execution only;
- no shell string;
- no raw user flags;
- fixed `live_nmap_basic` mode;
- fixed `tcp_connect_small` profile;
- bounded target count;
- bounded TCP port count;
- bounded process timeout;
- bounded Nmap host timeout;
- bounded stdout and stderr capture;
- bounded XML parse input;
- cleanup of any temporary working directory;
- controlled result states such as completed, failed, timed out, missing Nmap,
  malformed output, truncated output, and no observed ports.

Output must remain shaped before it crosses the boundary back to backend. Raw
Nmap XML, raw targets, raw commands, stdout, and stderr must not become normal
API/report/export fields.

## Boundary Options

This phase does not implement a backend-to-active-tools boundary. The future
implementation should choose deliberately among these options.

### Option A: Internal HTTP Service

Shape:

- `active-tools` runs a small internal service on the private Compose network.
- backend submits a structured request and receives a bounded structured result.

Pros:

- clear service boundary;
- natural availability/health checks;
- no backend subprocess import;
- can enforce request size, timeout, and structured error handling.

Cons:

- introduces an internal API that must avoid becoming a public scanner API;
- requires authentication, network isolation, or equivalent internal controls;
- requires careful logs and error redaction.

Fit:

Preferred direction if the service stays private, disabled by default, and
strictly behind backend authorization and target validation.

### Option B: CLI Wrapper Inside Active Container

Shape:

- backend or another orchestrator invokes a command inside the `active-tools`
  container.

Pros:

- smaller service surface inside `active-tools`;
- easier to keep a batch-style runner.

Cons:

- risks Docker socket or container-exec coupling;
- can tempt backend into orchestration responsibilities;
- less natural for owner-scoped job state and availability checks;
- harder to operate safely without broad container privileges.

Fit:

Not preferred for the normal Inspectra path. It may remain a private developer
debug idea outside the supported runtime, but it should not require backend
Docker socket access.

### Option C: Backend Internal Adapter Without Service Boundary

Shape:

- backend imports or executes Active runner code directly.

Pros:

- fewer services;
- simpler local wiring at first.

Cons:

- violates the packaging decision's separation goal;
- risks backend direct subprocess execution;
- weakens the backend safety boundary;
- makes future hardening and resource isolation harder.

Fit:

Rejected for Nmap execution. Backend may keep an injectable no-live adapter for
tests, but real Nmap execution should live in `active-tools`.

## Network Design And Loopback Semantics

Nmap target semantics change once Nmap runs inside a container:

- `127.0.0.1` inside `active-tools` means the `active-tools` container itself,
  not the operator host and not the backend container.
- `localhost` remains disallowed for the frozen smoke because it can imply name
  resolution and ambiguous operator intent.
- `network_mode: host` is not approved as the default solution.
- LAN, VPS, domain, public, and third-party targets remain blocked by this
  phase.

Future local smoke options should therefore be redesigned for container
semantics. A later smoke phase may choose a controlled target service on the
same private Compose network, with an exact service name/IP, exact port, and
explicit no-DNS/no-public/no-LAN constraints if the phase approves it. This
phase does not approve that target, create that service, or run the smoke.

For the original frozen target `127.0.0.1:65000`, a future Dockerized rerun
would only test loopback inside `active-tools`. That can still validate Nmap
availability and command execution if explicitly accepted later, but it does
not validate reachability of the host machine.

## Availability Checks

A future `active-tools` availability check should not run Nmap against a target.
Acceptable checks to design later include:

- service health endpoint that reports process readiness only;
- Nmap binary presence and version check at container startup or readiness time,
  without running a scan;
- structured status visible to backend as unavailable, ready, or degraded;
- no target input and no network traffic in the readiness path.

The backend must treat availability as necessary but not sufficient. A ready
`active-tools` service does not bypass feature flags, auth-required mode,
owner-scope checks, target policy, port policy, or confirmations.

## Smoke Implications

The next real smoke after Docker packaging must account for:

- the service is disabled by default and must be explicitly enabled for the
  smoke;
- backend feature flag remains separate from Compose service activation;
- no host network is approved;
- no public/LAN/VPS/domain target is approved;
- container loopback differs from host loopback;
- target and port must be frozen again for the Dockerized topology;
- logs, API responses, Raw JSON, and exports must be checked for redaction;
- cleanup must stop the Active service and remove temporary artifacts;
- no archive/run-all path may trigger the smoke;
- no `tools/runner/main.py` path may trigger the smoke.

This phase does not execute a smoke.

## Integration Notes

Future backend integration should preserve:

- `INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED=false` by default;
- deny-anonymous behavior before validation details in auth-required modes;
- owner-scoped target jobs with `file_id: null`;
- backend-side target and port validation before any handoff;
- explicit authorization, local/private/self-hosted scope, and live traffic
  confirmations;
- no runner connection unless the feature flag and service availability both
  pass;
- no archive/run-all integration;
- no passive runner integration;
- frontend copy that says observed exposure, review indicator, and manual
  validation required.

## Risks

Key risks to control in later implementation:

- accidentally making `active-tools` reachable as a public scanner;
- using host network to simplify local smoke semantics;
- granting `privileged` or broad Linux capabilities;
- letting Nmap package versions drift without traceability;
- leaking raw targets, raw commands, stdout, stderr, or XML in logs;
- treating stdout/stderr as trusted;
- confusing container loopback with host loopback;
- leaving Active service enabled persistently after smoke;
- adding future tools to `active-tools` without the same allowlist and
  disabled-by-default discipline;
- routing archive/run-all or passive runner jobs into Active tooling.

## What Remains Blocked

The following remain blocked:

- Dockerfile changes;
- Compose changes;
- Docker build;
- Docker run;
- Nmap installation;
- Nmap execution;
- backend runtime changes;
- frontend runtime changes;
- runner runtime changes;
- runner HTTP endpoint implementation;
- backend direct subprocess execution for Nmap;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- host network as a default solution;
- `privileged` containers;
- Docker socket access;
- LAN targets;
- VPS/domain smoke;
- public targets;
- public scanner behavior;
- raw flags, NSE, `--script`, stealth/evasion, UDP, SYN scan, OS detection,
  service/version detection, brute force, exploit scripts, credential
  validation, crawling, DNS expansion, broad ranges, confirmed vulnerability,
  exploitability, target-safety, full-scan, and all-ports-found claims.

## Next Microphase

Recommended next phase:

```text
ACTIVE-NMAP-BASIC-21-ACTIVE-TOOLS-DOCKER-SCAFFOLD-NO-RUN
```

That phase, if approved, should create the initial Dockerfile/Compose scaffold
without building images, running Docker, executing Nmap, adding a runner HTTP
endpoint, changing backend/frontend/runtime behavior, or widening target scope.
It should include static checks and docs only unless explicitly scoped
otherwise.

## Final Decision

```text
ACTIVE_NMAP_BASIC_20_ACTIVE_TOOLS_DOCKER_DESIGN_ACCEPTED
```

The future Nmap packaging path is a separate Dockerized Active runner service
or image, tentatively `active-tools`, with no public port by default, no host
network by default, no privileged container, no Docker socket, explicit
activation, bounded execution, and continued separation from backend direct
subprocess execution, archive/run-all, and `tools/runner/main.py`.
