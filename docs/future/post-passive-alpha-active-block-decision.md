# Post-Passive Alpha Active Block Decision

Status: `HYBRID_ACTIVE_DESIGN_WITH_HARDENING_GATES`.

Passive release: `https://github.com/dreykdrk7/inspectra/releases/tag/v0.1.0-passive-alpha`

Passive tag: `v0.1.0-passive-alpha`

Tagged commit: `c3ce00fd3259cc49494db1ee0ef4cdffc229dca9`

This document records the docs-first decision for whether Inspectra should open an Active/Nmap/network product block after the Passive Technical Alpha publication. It does not implement Active behavior, add Nmap, add endpoints, change backend/runner/frontend code, create tags, create releases, run network checks, or expand the passive alpha release.

## A. Starting State

Inspectra Passive Technical Alpha has been published as a stable local technical-alpha snapshot:

- Branch `main` was pushed to `origin`.
- Tag `v0.1.0-passive-alpha` was pushed to `origin`.
- GitHub prerelease was created.
- Release notes are available at `docs/releases/v0.1.0-passive-alpha.md`.
- Publication is recorded in `docs/future/passive-alpha-github-release-publish.md`.

The passive snapshot remains intentionally bounded:

- local uploads and local storage;
- archive-only passive config analyzers;
- bounded authorized web, domain, and explicit subdomain baseline flows;
- heuristic review indicators;
- best-effort `[REDACTED]` redaction;
- no active scanning, no Nmap, no port scanning, no exploitation, and no credential validation.

Active/Nmap/network work is not part of the Passive Alpha. Any Active work must be opened as a separate product block with its own safety boundaries, authorization model, target model, runbooks, threat model, and release/versioning decisions.

## B. Product Question

The product question is not simply "can Inspectra run active checks?" It is:

- Should Inspectra open Active now, or should it first execute post-alpha hardening?
- What additional legal, safety, and abuse risks does Active introduce compared with passive local file review?
- What product value justifies introducing those risks?
- Which gates must be frozen before any Active runtime code exists?

Opening Active adds value because it can eventually move Inspectra from static review indicators into bounded validation of explicitly authorized targets. That can help users connect configuration findings with observed web-edge or network posture. It also differentiates Inspectra from purely static review tools.

Active also changes the product's risk profile. Network traffic can affect third-party systems, create logging/noise, trip rate limits, be mistaken for hostile scanning, or be misused if target authorization is weak. Even low-intensity probes require explicit authorization, target constraints, rate limits, dry-run behavior, audit logs, clear copy, and strong no-scope language before implementation.

The safety-critical work before touching Active code is:

- target authorization model;
- allowlist and validation model;
- dry-run contract;
- rate limits and timeouts;
- audit logging;
- abuse-case review;
- UX copy that does not imply permission where none exists;
- hard no-scope for exploitation, stealth, evasion, brute force, credential attacks, destructive tests, and wide scanning.

## C. Options

### Option A: Start Active/Nmap Docs-First Now

Pros:

- Gives Inspectra the next meaningful product-value jump.
- Helps differentiate Inspectra from static review-only tools.
- Can begin safely with design and contracts without executing network activity.
- Lets the team discover authorization, target-model, and UX requirements early.

Cons:

- Raises legal, safety, and abuse stakes compared with passive archive/file review.
- Requires explicit authorization workflows and target validation.
- Requires strict rate limits, timeouts, audit trails, and failure-state handling.
- Can change external perception of Inspectra from defensive review tool to scanner.
- Nmap in particular carries stronger scanning connotations and should not be the first runtime implementation.

### Option B: Post-Alpha Hardening First

Pros:

- Strengthens authentication, deployment, storage, onboarding, and local-data controls before expanding capability.
- Reduces risk if Inspectra later supports external users or less trusted environments.
- Keeps the product narrative focused on the just-published Passive Alpha.
- Gives reporting/export and UX polish more time before adding a higher-risk capability.

Cons:

- Less visible functional progress.
- Delays validation of the Active product direction.
- May postpone discovery of target authorization and safety-design gaps.

### Option C: Hybrid

The hybrid path opens Active as docs-first only, while blocking runtime implementation behind hardening and safety gates.

This means:

- Create `ACTIVE-NETWORK-BLOCK-01-DOCS-FIRST-SCOPE`.
- Do not implement Nmap yet.
- Do not run active probes yet.
- Keep Passive stable and unchanged.
- Design Active target authorization, allowlists, dry-run behavior, audit logs, rate limits, and no-scope first.
- Execute post-alpha hardening in parallel or before any Active runtime code.

This gives product learning without silently changing Inspectra's risk profile.

## D. Recommendation

Recommendation: Option C.

Decision: `HYBRID_ACTIVE_DESIGN_WITH_HARDENING_GATES`.

Open `ACTIVE-NETWORK-BLOCK-01-DOCS-FIRST-SCOPE` as the next Active-oriented microphase, but keep runtime Active blocked. Nmap should remain design-only until the target model, authorization flow, dry-run contract, abuse cases, rate limits, audit logs, and user-facing safety copy are frozen.

In parallel, or immediately after the first Active scope document, continue post-alpha readiness hardening:

- authentication and deployment hardening;
- storage retention and cleanup/reset tooling;
- onboarding and local-data deletion guidance;
- legal/security disclaimer for user-uploaded content and active target authorization;
- multi-user isolation and authorization model;
- report/export readability follow-up.

## E. Proposed Initial Active Scope

A future Active v0 block may include only carefully bounded behavior:

- Targets must be explicitly entered by the user.
- Targets must be owned by the user or explicitly authorized.
- Target authorization must be confirmed in the UI/API before any active action.
- Targets should be limited to local/trusted environments first.
- Hostnames, domains, and IPs should be allowlisted or validated against a strict policy.
- Cloud metadata, link-local, multicast, reserved, and other sensitive/internal targets should remain blocked by default unless a documented local-lab exception exists.
- Wide ranges should be rejected.
- Scans should use strict rate limits.
- Scans should use strict timeouts and global deadlines.
- The first contract should support dry-run mode that records intended checks without network activity.
- Audit logs should record who requested what, when, target normalization, authorization confirmation, and selected limits.
- Findings should remain review indicators unless manually validated.
- Nmap should be optional and later, not the first line of code.
- The first implementation candidate, if any, should be lower risk than Nmap, such as an explicitly authorized web-header probe with HEAD/GET only and tight limits.

Initial Active v0 must not include stealth, evasion, exploitation, brute force, credential stuffing, stress/DoS, payload delivery, malware, persistence, wide internet scanning, or default scans without confirmation.

## F. Active No-Scope

Active no-scope must be explicit and non-negotiable:

- No scanning third-party targets without explicit authorization.
- No default active scan without confirmation.
- No wide internet scanning.
- No broad CIDR/range scanning in v0.
- No exploitation.
- No exploit payloads.
- No offensive payload generation.
- No stealth.
- No evasion.
- No anonymization guidance.
- No bypass guidance.
- No brute force.
- No credential stuffing.
- No credential attacks.
- No credential validation unless separately designed as a defensive, authorized, minimal-scope feature later.
- No malware behavior.
- No persistence.
- No destructive tests.
- No DoS or stress testing.
- No fuzzing against live services.
- No vulnerability confirmation claims from simple probes.
- No Nmap runtime until safety and target model are frozen.
- No mutation of the Passive Alpha tag or release line.

## G. Future Microphases

Recommended sequence:

1. `ACTIVE-NETWORK-BLOCK-01-DOCS-FIRST-SCOPE`

   Define safety boundaries, authorization model, allowed targets, rejected targets, no-scope, UX copy, API copy, and versioning assumptions. No runtime.

2. `ACTIVE-NETWORK-BLOCK-02-RUNBOOK-AND-THREAT-MODEL`

   Document abuse cases, operator runbook, rate limits, audit logs, blocked target classes, failure states, error copy, and incident handling. No runtime.

3. `ACTIVE-NETWORK-BLOCK-03-DRY-RUN-CONTRACTS`

   Design backend/frontend contracts that record intended active checks without executing network activity. If implemented later, dry-run should prove request validation, authorization capture, job storage, summaries, and reporting without network effects.

4. `ACTIVE-NETWORK-BLOCK-04-AUTHORIZED-WEB-HEADER-PROBE-DESIGN`

   If product direction still supports Active, design a very low-risk probe using bounded HTTP HEAD/GET only against an explicit authorized target. This should build on existing `web_basic` safety patterns rather than jumping to Nmap.

5. `ACTIVE-NETWORK-BLOCK-05-NMAP-DOCS-FIRST-DESIGN`

   Nmap enters only after authorization, target validation, rate limits, audit logs, and dry-run contracts are frozen. This phase should design allowed scan profiles, rejected flags, output handling, timeouts, and UX warnings before any Nmap runtime code.

## H. Release And Handoff Note

The Passive Alpha release remains stable:

- Do not mutate `v0.1.0-passive-alpha`.
- Do not retag the passive release.
- Do not add Active/Nmap language to the passive release as if it were included.
- Active should use new commits after the passive release.
- Active should use a new branch or clearly scoped commit series.
- Active versioning should not reuse `v0.1.0-passive-alpha`.

Possible future names can be decided later:

- `v0.2.0-active-alpha`
- `v0.2.0-network-alpha`
- `v0.1.0-active-preview`

The naming decision should wait until Active scope, target model, and release criteria are documented.

## I. Decision Field

Final decision:

```text
HYBRID_ACTIVE_DESIGN_WITH_HARDENING_GATES
```

Meaning:

- Open Active design docs now.
- Do not implement Active runtime yet.
- Do not implement Nmap yet.
- Keep Passive Alpha stable and unchanged.
- Treat post-alpha hardening as a gate before any public or higher-risk Active capability.

Next recommended microphase:

```text
ACTIVE-NETWORK-BLOCK-01-DOCS-FIRST-SCOPE
```

That scope freeze is documented in:

```text
docs/future/active-network-block-01-docs-first-scope.md
```

Decision:

```text
ACTIVE_NETWORK_SCOPE_FROZEN_DOCS_FIRST_NO_RUNTIME
```

Parallel or follow-up hardening path:

```text
POST_ALPHA_READINESS_BACKLOG_EXECUTION-01-DOCS-FIRST-PLAN
```
