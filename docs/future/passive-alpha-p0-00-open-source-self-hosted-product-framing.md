# Passive Alpha P0 00 Open Source Self Hosted Product Framing

Status: `PASSIVE_ALPHA_OPEN_SOURCE_SELF_HOSTED_FRAMING_ACCEPTED`.

Base implementation readiness plan: `docs/future/passive-alpha-gap-fixes-08-implementation-readiness-plan.md`

Base auth and user-isolation design: `docs/future/passive-alpha-gap-fixes-03-auth-and-user-isolation-design.md`

Base deployment threat model: `docs/future/passive-alpha-gap-fixes-02-deployment-threat-model.md`

Commit scope: docs-only product and deployment framing before future P0 auth/runtime planning. This block clarifies that Inspectra is open-source, altruistic, local-first, and self-hosted-first. It does not change backend, frontend, runner, tests, fixtures, schemas, storage, reports, exports, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_OPEN_SOURCE_SELF_HOSTED_FRAMING_ACCEPTED
```

Inspectra should be framed as an open-source defensive audit app that people and teams can run for themselves.

The project is not a commercial SaaS product, not a subscription platform, and not a broad multi-tenant enterprise service. Any future public/community online instance is an optional convenience with strict limits and disclaimers, not the primary product shape.

## Product Intent

Inspectra is:

- open-source;
- altruistic;
- local-first and self-hosted-first;
- designed for people and teams to audit their own projects or explicitly authorized targets;
- suitable for local installs, own-server installs, and private/internal team installs when controls exist.

Inspectra is not:

- a commercial SaaS;
- a product sold by subscription tiers;
- a billing or quota platform;
- an enterprise multi-tenant SaaS;
- a scan-as-a-service offering;
- a public Active/Nmap scanning service.

## Supported Deployment Framing

### Primary

- Local machine install.
- Self-hosted single-instance server.
- Private/internal team install controlled by the operator or organization running it.

### Optional

- Public/community hosted instance with strict limits, visible disclaimers, abuse prevention, short retention, and no guarantee of availability.

This optional public/community instance is a convenience for users who cannot or do not want to install Inspectra. It should not be described as a commercial SaaS, paid subscription service, enterprise tenant platform, or broad public scanning utility.

### Unsupported

- Commercial SaaS by subscription.
- Arbitrary scan-as-a-service.
- Unauthenticated public upload service.
- Broad multi-tenant enterprise platform.
- Public Active/Nmap scanning service.
- Third-party target testing without explicit authorization.

## Auth Implications

Auth does not mean SaaS.

Auth is needed to:

- protect a self-hosted instance exposed beyond localhost;
- avoid anonymous uploads in any public/community instance;
- separate users in a limited community instance;
- protect reports, exports, Raw JSON, uploads, jobs, and target histories;
- apply ownership, retention, limits, and abuse controls.

Auth does not imply:

- billing;
- subscription tiers;
- tenant plans;
- quota monetization;
- customer organizations;
- commercial RBAC;
- a full multi-tenant SaaS business model.

## Recommended Auth Shape After Reframing

The next auth design should optimize for:

- default trusted local mode for development and local personal use;
- optional single-admin or single-user auth for self-hosted installs;
- optional lightweight multi-user support for a public/community instance;
- owner-scoped resources whenever more than one user can exist;
- clear admin/operator boundaries;
- no enterprise SaaS tenant model for now.

If future docs use "single-tenant hosted", they should mean an individual self-hosted or dedicated instance, not a sold SaaS tenant. If docs use "public/external", they should mean users outside the trusted local operator boundary, not necessarily paying customers.

## Public Online Instance Caveats

If Inspectra offers a public/community online instance, it should have:

- auth or equivalent anti-abuse controls before real uploads;
- strict upload, analyzer, job, export, and retention limits;
- visible disclaimers and authorized-use copy;
- short retention and clear deletion caveats;
- no regulated or highly sensitive data support;
- no third-party targets as demos;
- no public Active/Nmap behavior;
- abuse prevention and rate limiting as future concerns;
- the right to disable, restrict, or remove the instance without commercial availability guarantees.

## Documentation Wording Changes

Use:

- "open-source";
- "self-hosted";
- "local-first";
- "own server";
- "private/internal install";
- "public/community instance";
- "optional hosted convenience";
- "users outside the trusted local operator boundary".

Avoid or qualify:

- "SaaS";
- "tenant";
- "customer";
- "billing";
- "subscription";
- "plans";
- "enterprise multi-tenant";
- "platform";
- "scan-as-a-service".

Existing docs that say "single-tenant hosted" should be read as "a dedicated self-hosted or individually operated instance". Existing docs that say "public/external" should be read as "usage beyond a trusted local operator", not as commercial SaaS readiness.

## What Remains True

Even with the non-SaaS framing:

- public/external runtime remains blocked without auth, ownership, retention, hardening, visible limits, disclaimers, and security review;
- anonymous public upload remains unsafe;
- reports, exports, SBOMs, Raw JSON, uploaded originals, and target histories remain sensitive;
- redaction remains best-effort;
- users must only audit their own projects or explicitly authorized targets;
- Active Alpha remains internal and limited;
- Nmap remains out of scope unless a separate docs-first decision explicitly scopes it.

## Implementation Roadmap Adjustment

The next recommended block remains:

```text
PASSIVE-ALPHA-P0-01-AUTH-BOUNDARY-DESIGN-TO-RUNTIME-PLAN
```

Its goal should be auth for self-hosted, local, private/internal, and optional public/community safety. It should not design billing, paid plans, commercial tenants, enterprise RBAC, sales workflows, or SaaS monetization.

## No-Scope

- No code.
- No runtime changes.
- No tests or fixture changes.
- No auth implementation.
- No billing.
- No SaaS plans.
- No tenant billing model.
- No DB migration.
- No storage schema change.
- No UI implementation.
- No cleanup implementation.
- No probes.
- No live traffic.
- No DNS or HTTP.
- No Docker.
- No Nmap.
- No port scanning.
- No crawling.
- No exploitation.
- No credential validation.
- No new Active capability.
- No new Passive analyzer.
- No `.env`, `.env.*`, or `.envrc` reads.
- No push.
- No real tag or release.

## Acceptance Criteria

- Open-source and self-hosted intent is documented.
- Commercial SaaS framing is explicitly avoided.
- Auth rationale is reframed as safety for local, self-hosted, private/internal, and optional community use.
- Public/community instance caveats are documented.
- The next auth block remains valid and corrected.
- No runtime or capability changes are made.

## Next Recommendation

```text
PASSIVE-ALPHA-P0-01-AUTH-BOUNDARY-DESIGN-TO-RUNTIME-PLAN
```

Proceed to auth-boundary planning with this framing: self-hosted/open-source safety first, not SaaS commercialization.

## Validation Commands

Reference checks for this docs-only framing block:

```text
git status --short
git status --branch --short
git log --oneline -12
git diff --check
git diff --cached --check
git status --short
```

No pytest or npm suite is required while this block remains docs-only.
