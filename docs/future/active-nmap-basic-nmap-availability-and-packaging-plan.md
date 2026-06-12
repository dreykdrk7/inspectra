# Active Nmap Basic Nmap Availability And Packaging Plan

Decision:

```text
ACTIVE_NMAP_BASIC_19_NMAP_PACKAGING_PLAN_ACTIVE_RUNNER_RECOMMENDED
```

This docs-only phase records how Inspectra should make Nmap available after the
first real local `active_nmap_basic` smoke was correctly blocked because no
local `nmap` binary was installed. It does not install Nmap, execute Nmap, run
Docker, modify Dockerfiles or Compose files, change backend/frontend/runner
runtime, add endpoints, or approve any new target scope.

## Context

Microphase 18 ended with:

```text
ACTIVE_NMAP_BASIC_18_REAL_LOCAL_SMOKE_EXECUTION_BLOCKED_NMAP_MISSING
```

The preflight result was:

- `command -v nmap`: exit code 1;
- no local Nmap path was returned;
- no Nmap installation was attempted;
- no Nmap command was executed;
- no Docker command was executed;
- no backend smoke server was started;
- no live request was sent;
- no job or export was created;
- no DNS check, probe, or external HTTP traffic occurred.

The product and architecture decision for future work is that Nmap should not be
a normal manual dependency of the host. Inspectra should package Nmap inside its
own Dockerized Active boundary, preferably as a separate Active runner service
or image such as `active-tools`.

## Decision Summary

Recommended path:

- package Nmap in a separate Active runner image/service, tentatively
  `active-tools`;
- keep the backend from executing Nmap directly;
- keep the backend from importing subprocess for Nmap;
- keep Active/Nmap out of the passive runner monolith at `tools/runner/main.py`;
- keep the existing mocked/no-live path as the safe fallback until packaging and
  execution wiring are separately implemented;
- keep `active_nmap_basic` disabled by default and explicit opt-in only;
- keep archive/run-all, public scanner behavior, VPS/domain smoke, LAN targets,
  and broad scans blocked.

This phase recommends packaging architecture only. It does not build, run, or
test an `active-tools` container.

## Options Evaluated

### Option 1: Host-Local Manual Install

Description:

Install Nmap directly on the operator host and rely on `command -v nmap` during
normal Inspectra use.

Security:

- Weak default boundary because tool availability and permissions depend on the
  host.
- Easier for local debugging, but harder to reason about in supported flows.

Reproducibility:

- Poor as a product default because versions, paths, package managers, and OS
  behavior vary by host.

Complexity:

- Low initial setup, but high support variance.

Host impact:

- Contaminates the host with an extra security tool and host-level permissions.

Docker impact:

- Avoids Docker work initially, but conflicts with Inspectra's reproducible
  containerized posture.

Isolation:

- Weak compared with a dedicated container boundary.

Modular design fit:

- Poor as the normal route. It creates a hidden dependency outside the Inspectra
  runtime topology.

Public scanner risk:

- Higher operational ambiguity because host tools can be reused outside the
  bounded service path.

Decision:

Do not use host-local manual install as the default or documented normal
Inspectra requirement. It may remain acceptable only as an operator's private
manual debug action outside the official Inspectra flow, outside CI, and outside
the supported smoke path.

### Option 2: Add Nmap To The Passive Runner

Description:

Install Nmap into the existing passive runner image and let
`tools/runner/main.py` absorb Active/Nmap behavior.

Security:

- Mixes passive file/archive analysis with live Active capability.
- Expands the blast radius of the passive runner.

Reproducibility:

- Better than host-local install if containerized, but it muddies which service
  owns active network behavior.

Complexity:

- Fewer services at first, but increasing code and operational complexity over
  time.

Host impact:

- Better than host-local install, but not enough to justify the boundary merge.

Docker impact:

- Smaller topology change than a new service, but larger passive image and more
  confusing deployment semantics.

Isolation:

- Poor for Inspectra's modular direction. Passive and Active controls become
  harder to reason about independently.

Modular design fit:

- Poor. It risks turning `tools/runner/main.py` into a large mixed-purpose
  monolith.

Public scanner risk:

- Higher because Active capability becomes co-located with broad passive job
  machinery unless extra care is added everywhere.

Decision:

Discourage this option unless a later architecture review finds a strong,
explicit reason. Active/Nmap should not be absorbed into `tools/runner/main.py`.

### Option 3: Separate Active Runner Image/Service

Description:

Create a separate Docker image/service for Active tooling, tentatively named
`active-tools`, containing Nmap and future tightly scoped Active tools. Backend
communication would go through a controlled boundary rather than direct backend
subprocess execution.

Security:

- Best boundary among the evaluated options.
- Allows service-specific network policy, capabilities, resource limits,
  timeouts, logging, and cleanup.
- Keeps the backend from executing host commands.

Reproducibility:

- Strong. Nmap version and availability become part of Inspectra's packaged
  runtime rather than host state.

Complexity:

- Higher than a host install or passive-runner merge, but the complexity is
  explicit and easier to control.

Host impact:

- Low. The host only needs the normal container runtime already used by
  Inspectra, not a separate Nmap install.

Docker impact:

- Requires a later Docker/Compose design for image, service, build context,
  health, resource limits, and disabled-by-default activation.

Isolation:

- Strong. Active tools can be hardened and enabled independently from passive
  archive/file analysis.

Modular design fit:

- Strong. The boundary matches the existing separation between passive runner
  behavior and `tools/active_runner/` concepts.

Public scanner risk:

- Lower if paired with feature flags, authorization confirmations, target
  policy, strict profiles, bounded timeouts, bounded output/storage, no
  archive/run-all integration, and reporting copy that says observed exposure or
  review indicator rather than confirmed vulnerability.

Decision:

Recommended. Future Nmap availability should be delivered through a separate
Active runner image/service such as `active-tools`.

### Option 4: Stay Mocked/No-Live Only

Description:

Keep only fake/mocked no-live validation for `active_nmap_basic`.

Security:

- Safest short-term state because no live execution exists.

Reproducibility:

- Strong for tests, but it does not solve real Nmap availability.

Complexity:

- Low, but incomplete.

Host impact:

- None.

Docker impact:

- None in this phase.

Isolation:

- Strong by absence of execution.

Modular design fit:

- Acceptable as a temporary fallback, not as the final availability strategy.

Public scanner risk:

- Minimal while no live execution exists.

Decision:

Keep as fallback until an `active-tools` packaging path is designed and
implemented in later phases. It does not resolve Microphase 18's missing Nmap
blocker by itself.

## Proposed Architecture

Future architecture should preserve these boundaries:

- Backend owns API authentication, owner scope, request validation, job
  lifecycle, redaction, reporting, and storage.
- Backend does not execute Nmap directly and does not import subprocess for
  Nmap.
- Backend talks only to a controlled Active boundary when live execution is
  explicitly enabled in a future phase.
- The Active boundary is a separate runner/service/image, tentatively
  `active-tools`, with Nmap installed inside the image.
- The passive runner at `tools/runner/main.py` remains passive and does not
  absorb Active/Nmap.
- The existing `tools/active_runner/` package remains the conceptual home for
  Active-specific validation, allowlisted command construction, controlled
  execution, parsing, and result shaping.
- Archive/run-all does not call Active/Nmap.
- Frontend controls remain separate from archive actions and keep explicit
  live-traffic confirmations.

The eventual Docker/Compose design should consider:

- separate service name and image naming;
- disabled-by-default service activation;
- no default public exposure;
- least required Linux capabilities;
- bounded CPU/memory/process limits;
- bounded runtime timeouts;
- bounded stdout/stderr/output storage;
- explicit cleanup for temporary work directories;
- clear health/readiness behavior that does not run scans;
- no secrets in logs;
- no raw command, raw target, raw XML, stdout, or stderr leakage in API/report
  surfaces;
- operator documentation that explains packaged availability without asking the
  operator to install Nmap on the host.

## Guardrails Preserved

The packaging plan does not relax any `active_nmap_basic` guardrail:

- disabled by default;
- explicit opt-in only;
- local/private/self-hosted use only;
- authorized targets only;
- no arbitrary internet scanning;
- no public scanner behavior;
- no SaaS scanner semantics;
- no broad ranges;
- no LAN target approval in this phase;
- no VPS/domain smoke approval;
- no stealth or evasion;
- no NSE or `--script`;
- no raw flags;
- no brute force;
- no exploit scripts;
- no credential validation;
- no crawling;
- no DNS expansion;
- no archive/run-all integration;
- no `tools/runner/main.py` integration;
- no backend direct subprocess execution for Nmap;
- no confirmed vulnerability, exploitability, target-safety, full-scan, or
  all-ports-found claims.

## Redaction And Reporting

Packaging Nmap does not change reporting semantics. Future output must remain:

- bounded before storage;
- target-redacted where API/report surfaces require it;
- free of raw XML, raw command, raw stdout, raw stderr, headers, cookies,
  tokens, credentials, service banners, and unsupported script output;
- worded as observed exposure, review indicator, or manual validation required;
- never worded as confirmed vulnerability, exploitability proof, target safe,
  full scan, or all ports found.

## Cleanup And Operator Steps

Future implementation should document operator steps around packaged Active
tooling, not host package installation:

- how to enable the Active service explicitly;
- how to confirm the service is available without running a scan;
- how to run only the frozen local smoke when separately approved;
- how to stop the Active service;
- how to inspect logs without leaking sensitive targets or raw output;
- how to remove temporary work/output artifacts.

This phase does not define final commands, build images, run Compose, install
Nmap, or start any service.

## What Remains Blocked

The following remain blocked after this plan:

- Nmap installation on the host as a normal Inspectra requirement;
- Nmap installation in this phase;
- Dockerfile or Compose changes in this phase;
- Docker build or Docker run in this phase;
- real Nmap execution;
- real local smoke rerun;
- backend direct subprocess execution for Nmap;
- runner HTTP endpoint creation;
- archive/run-all integration;
- `tools/runner/main.py` integration;
- LAN targets;
- VPS/domain smoke;
- third-party targets;
- public scanner behavior;
- broad ranges;
- raw flags, NSE, scripts, stealth/evasion, brute force, exploit scripts,
  credential validation, crawling, DNS expansion, and confirmed-vulnerability
  claims.

## Next Microphase

Recommended next phase:

```text
ACTIVE-NMAP-BASIC-20-ACTIVE-TOOLS-DOCKER-DESIGN
```

That phase should remain docs-only unless separately scoped otherwise. It should
design the `active-tools` Docker/Compose shape, image ownership, service
boundary, disabled-by-default activation, network/capability/resource hardening,
health checks, log/redaction posture, and operator documentation. It should not
build or run Docker, install Nmap, execute Nmap, add runner endpoints, change
backend/frontend/runtime behavior, or widen target scope unless a later request
explicitly changes the phase type and guardrails.

## Final Decision

```text
ACTIVE_NMAP_BASIC_19_NMAP_PACKAGING_PLAN_ACTIVE_RUNNER_RECOMMENDED
```

Nmap availability should be solved through a separate Dockerized Active runner
image/service, tentatively `active-tools`. Host-local manual Nmap installation
is not the normal Inspectra requirement, backend direct Nmap execution remains
blocked, and the passive runner must not absorb Active/Nmap.
