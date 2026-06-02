# Active Network Block 01 Docs-First Scope

Status: `ACTIVE_NETWORK_SCOPE_FROZEN_DOCS_FIRST_NO_RUNTIME`.

Passive release: `https://github.com/dreykdrk7/inspectra/releases/tag/v0.1.0-passive-alpha`

Passive tag: `v0.1.0-passive-alpha`

Tagged commit: `c3ce00fd3259cc49494db1ee0ef4cdffc229dca9`

Related decisions:

- `docs/future/post-passive-alpha-active-block-decision.md`
- `docs/future/post-passive-alpha-runner-architecture-decision.md`

This document freezes the first docs-first scope for a future Active/Network product block. It does not implement Active runtime, create an active runner, create endpoints, modify backend/runner/frontend code, run network checks, run Nmap, create tags, create releases, or mutate the Passive Alpha.

## A. Starting State

Inspectra Passive Technical Alpha v0.1.0 has been published as a GitHub prerelease. It is a stable passive snapshot and does not include Active/Nmap/network scanning.

Active is a new and separate product block:

- Active is not part of `v0.1.0-passive-alpha`.
- Active does not mutate the Passive Alpha tag or release.
- The passive runner monolith in `tools/runner/main.py` is not modified by this block.
- The future Active runner must be separate and modular.
- This phase is documentation only and implements no runtime.

Two post-release decisions constrain this scope:

- `HYBRID_ACTIVE_DESIGN_WITH_HARDENING_GATES`: open Active design docs now, but block runtime behind safety and hardening gates.
- `START_ACTIVE_WITH_SEPARATE_MODULAR_RUNNER_DESIGN`: do not add Active/Nmap/network to `tools/runner/main.py`; design a separate Active runner.

## B. Active Block Objective

The future Active/Network block should add carefully bounded validation capabilities for explicitly authorized targets. The purpose is defensive: help users understand selected, authorized target posture without turning Inspectra into an offensive tool.

The block must start with design, dry-run contracts, and authorization before any real traffic exists.

The product goals are:

- improve defensive value beyond static review;
- keep target ownership and authorization explicit;
- begin with no-network dry-run behavior;
- use least-intrusive checks when live checks are eventually introduced;
- keep Nmap as a later docs-first design topic, not the first runtime;
- preserve the passive archive/file no-network guarantee.

## C. Security Principles

Active work must follow these principles:

- Explicit authorization first.
- Least intrusive checks.
- Dry-run before live traffic.
- Target allowlist and validation.
- Safe target normalization before execution, storage, or audit logs.
- Rate limits and timeouts.
- Audit logging for requested checks.
- Local/trusted alpha first.
- Fail closed on ambiguity.
- Safe defaults.
- Clear user-facing copy.
- Findings as review indicators, not confirmed vulnerabilities.
- No stealth.
- No evasion.
- No exploitation.
- No credential attacks.
- No broad scanning.

The product should prefer not running a check over running a check against an ambiguous, unauthorized, or risky target.

## D. Target Model

Future Active requests may need to represent these target types:

- URL.
- Hostname or domain.
- Single IP address.
- Local lab target.
- CIDR or range as a future concept only.

CIDR/range targets are rejected in v0.

Future target fields to consider:

- raw target input;
- normalized target;
- target type;
- authorization confirmation;
- user-provided ownership or authorization statement;
- active mode or dry-run flag;
- limits profile;
- created timestamp;
- requested-by identity if authentication exists later;
- rejected target reason when blocked;
- local-lab mode indicator when applicable.

Target normalization should reject shell-like input, embedded credentials, unsupported schemes, malformed addresses, broad ranges, wildcards, and payload-like strings before any job is created.

## E. Allowed Targets V0

Allowed target classes for a future v0 should be narrow:

- `localhost` or loopback targets only in explicit local-lab mode.
- Explicit HTTP/HTTPS URLs entered by the user.
- Explicit hostnames or domains entered by the user.
- A single explicit IP address when it is not in a blocked class.
- Synthetic fixture or lab targets.
- Targets with explicit authorization confirmation.

Private RFC1918/internal ranges should be blocked by default. A local-lab exception can be designed, but it must be explicit, visible to the user, and separate from normal active behavior.

## F. Rejected Targets V0

Future v0 should reject:

- broad CIDRs and ranges;
- wildcards;
- internet-wide scans;
- multicast addresses;
- broadcast addresses;
- cloud metadata IPs and hostnames;
- link-local addresses;
- unspecified addresses;
- private/internal ranges by default;
- onion or anonymous-network targets;
- file URLs;
- non-HTTP URL schemes for HTTP probes;
- shell commands;
- URLs with credentials;
- suspicious payload-like targets;
- targets with whitespace/control characters that change meaning;
- target lists that exceed configured limits;
- any target without explicit authorization confirmation.

Loopback may be permitted only in explicit local-lab mode. Private RFC1918 targets should remain blocked by default and require a separately designed local-lab exception.

## G. Authorization UX And API

Any future Active UX or API must require explicit confirmation before an active check can run.

Required copy:

```text
I confirm I own or am authorized to test this target.
```

```text
I understand this may contact the target.
```

```text
Do not scan third-party systems without permission.
```

Expected UX/API behavior:

- checkbox or equivalent confirmation;
- visible target summary before execution;
- normalized target shown before execution;
- dry-run option first;
- no default active run;
- clear limits and expected contact type;
- rejected-target messages that are specific but not bypass-oriented;
- warnings that results are indicators requiring human review.

The product should not treat a typed target as permission. Authorization must be an explicit field.

## H. Active No-Scope

Active no-scope is strict:

- No exploitation.
- No exploit payloads.
- No offensive payload generation.
- No brute force.
- No credential stuffing.
- No credential validation.
- No credential attacks.
- No fuzzing.
- No DoS or stress testing.
- No stealth.
- No evasion.
- No bypass.
- No anonymization guidance.
- No malware behavior.
- No persistence.
- No destructive checks.
- No wide scans.
- No broad CIDR/range scanning in v0.
- No Nmap runtime in v0.
- No scanning without explicit user confirmation.
- No third-party scanning without authorization.
- No claims that simple probes confirm exploitability, compromise, breach, or vulnerability.

Nmap remains out of runtime scope until safety gates are closed and a separate Nmap docs-first design is approved.

## I. First Active Capability Strategy

Recommended strategy:

1. Dry-run contract first.
2. Then optional low-risk authorized HTTP header probe design.
3. Nmap docs/design later.
4. Nmap runtime only after safety gates.

The first implementation should not produce network traffic. It should validate target parsing, authorization capture, blocked target classes, dry-run job storage, planned checks, limits, controlled errors, and audit logs without contacting anything.

If a live check is later approved, the first candidate should be a low-risk HTTP HEAD/GET header probe against one explicit authorized target with tight request limits. It should build on the existing `web_basic` safety lessons without silently expanding `web_basic`.

## J. Safety Controls

Future controls to design before runtime:

- Active disabled by default.
- Explicit environment flag to enable Active.
- Max targets per request.
- Max requests per target.
- Timeout per request.
- Global timeout.
- Strict allowed methods for HTTP probes.
- User agent identifying Inspectra for HTTP probes.
- No redirects or tightly limited redirects.
- Response body size cap.
- No request body payloads in v0.
- No custom arbitrary headers in v0 unless separately designed.
- No arbitrary ports by default.
- Audit log for requested checks.
- Controlled error taxonomy.
- Redaction for URLs with credentials and sensitive query parameters.
- Fail-closed behavior for ambiguous target parsing or DNS/address classification.

Recommended initial behavior is dry-run with `max_requests: 0` and `timeout_seconds: 0`.

## K. Result Model

Future dry-run result shape can start with:

```json
{
  "analyzer": "active_network_dry_run",
  "mode": "dry_run",
  "target": {
    "raw": "https://example.test",
    "normalized": "https://example.test",
    "type": "url",
    "authorization_confirmed": true
  },
  "limits": {
    "max_requests": 0,
    "timeout_seconds": 0
  },
  "planned_checks": [],
  "blocked_reasons": [],
  "findings": [],
  "audit_log": [],
  "errors": []
}
```

Additional fields to consider later:

- requested-by identity;
- local-lab mode;
- target policy version;
- created/completed timestamps;
- normalized host/IP metadata;
- rejected-target details;
- dry-run planned endpoint/probe list;
- active safety decisions.

## L. Relationship With Existing Web And Domain Flows

Inspectra already has bounded authorized baseline flows:

- `web_basic`;
- `domain_basic`;
- `subdomain_inventory_basic`.

Those flows are separate from this Active block. Active work must not silently expand them.

Reusable safety principles include:

- explicit authorization confirmation;
- URL credential rejection;
- blocked metadata/link-local/multicast/reserved targets;
- private/loopback controls;
- allowed-port controls;
- bounded HTTP/DNS behavior;
- controlled errors;
- redaction of sensitive URL/query values.

The archive-based passive modules keep their no-network guarantee. Adding Active later must not weaken that guarantee.

## M. Architecture Constraint

Architecture constraint:

- No Active code in `tools/runner/main.py`.
- No Active runner files in this phase.
- Future Active runner should be separate, for example `tools/active_runner/`.
- Backend routes should be separate later, but final endpoint shape is not defined here.
- No code is created now.

The runner architecture decision remains:

```text
START_ACTIVE_WITH_SEPARATE_MODULAR_RUNNER_DESIGN
```

## N. Future Microphases

Recommended sequence:

1. `ACTIVE-NETWORK-BLOCK-02-RUNBOOK-AND-THREAT-MODEL`

   Document abuse cases, operator runbook, rate limits, audit logs, rejected target classes, failure states, controlled errors, and incident response. No runtime.

2. `ACTIVE-NETWORK-BLOCK-03-DRY-RUN-CONTRACTS-DESIGN`

   Design backend/frontend/storage/reporting contracts for dry-run active checks that record intended checks without network traffic.

3. `ACTIVE-NETWORK-BLOCK-04-DRY-RUN-SKELETON-NO-NETWORK`

   If approved later, implement only a dry-run skeleton with no network calls, no probes, and no Nmap.

4. `ACTIVE-NETWORK-BLOCK-05-AUTHORIZED-HTTP-HEADER-PROBE-DESIGN`

   Design the first possible low-risk live probe with explicit authorization, tight limits, and no broad scanning.

5. `ACTIVE-NETWORK-BLOCK-06-NMAP-DOCS-FIRST-DESIGN`

   Design Nmap constraints only after dry-run and low-risk HTTP probe safety gates are documented.

## O. Decision Field

Final decision:

```text
ACTIVE_NETWORK_SCOPE_FROZEN_DOCS_FIRST_NO_RUNTIME
```

Meaning:

- Active/Network scope is frozen at docs-first level.
- No Active runtime exists.
- No active runner exists.
- No endpoints exist.
- No Nmap runtime exists.
- Dry-run and safety design come before any network traffic.
- Passive Alpha remains unchanged.

Next recommended microphase:

```text
ACTIVE-NETWORK-BLOCK-02-RUNBOOK-AND-THREAT-MODEL
```

That runbook and threat model is documented in:

```text
docs/future/active-network-block-02-runbook-and-threat-model.md
```

Decision:

```text
ACTIVE_RUNBOOK_THREAT_MODEL_FROZEN_NO_RUNTIME
```

Dry-run contracts are documented in:

```text
docs/future/active-network-block-03-dry-run-contracts-design.md
```

Decision:

```text
ACTIVE_DRY_RUN_CONTRACTS_DESIGNED_NO_RUNTIME
```

## P. No-Scope

This microphase does not include:

- code changes;
- active runner files;
- endpoints;
- backend changes;
- frontend changes;
- runner changes;
- Nmap;
- network calls;
- tests beyond docs checks;
- push;
- tags;
- releases;
- `.env` reads;
- mutation of `v0.1.0-passive-alpha`.
