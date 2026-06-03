# Passive Alpha Closeout Or Release Candidate

Status: `PASSIVE_ALPHA_TRUSTED_LOCAL_RELEASE_CANDIDATE_ACCEPTED`.

Base recheck: `docs/future/active-network-block-26-passive-alpha-readiness-recheck.md`

Gap fixes plan: `docs/future/passive-alpha-gap-fixes-01-plan.md`

Passive suite closeout: `docs/future/passive-suite-alpha-transversal-closeout.md`

Packaging readiness: `docs/future/passive-alpha-packaging-readiness.md`

Post-tag handoff: `docs/future/passive-alpha-post-tag-verification-handoff.md`

Backlog triage: `docs/future/post-alpha-readiness-backlog-triage.md`

Commit scope: docs-only Passive Alpha closeout/release-candidate record after Active Alpha v0 closeout. This block does not change backend, frontend, runner, tests, fixtures, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_TRUSTED_LOCAL_RELEASE_CANDIDATE_ACCEPTED
```

Inspectra is accepted as a trusted local Passive Alpha / release-candidate documentation package.

This decision does not approve production deployment, public external-user use, multi-tenant use, Nmap, broader Active behavior, new Active capabilities, or new passive analyzer implementation.

## Product State

Passive Alpha remains the main product readiness line:

- Passive module expansion is closed.
- Trusted local demo/release documentation exists.
- The passive alpha tag and GitHub prerelease are already documented in the post-tag handoff.
- Findings remain heuristic review indicators.
- Redaction remains defensive and best-effort.
- Uploaded originals and job results remain locally stored according to the MVP data model.

Active Alpha v0 is closed as internal and limited:

- `active_network_dry_run` is no-network planning.
- `active_http_header_probe` is the only limited live capability.
- The live capability is opt-in, disabled by default, double-confirmed, target-based, and capped to one HTTP `HEAD` request.
- Active is not production ready.
- Active is not external-user ready.
- Nmap, port checks, crawling, broader Active behavior, local-lab mode, and new live capabilities remain out of scope.

## Alpha Inventory

### Passive Archive/File Surfaces

Closed or alpha-visible passive/local surfaces:

- PDF/image metadata checks.
- Dependency manifest parsing.
- Archive metadata inspection.
- Project-archive manifest analysis.
- SBOM export for completed manifest and project-archive jobs.
- `django_config_basic`.
- `docker_config_basic`.
- `secrets_review_basic`.
- `node_package_config_basic`.
- `ci_cd_config_basic`.
- `k8s_config_basic`.
- `terraform_config_basic`.
- `nginx_config_basic`.
- `compose_config_basic`.
- `database_config_basic`.
- `sql_database_config_basic`.
- `redis_config_basic`.

Archive-based config modules are offered only for uploaded files registered as `kind: "archive"`. They are local, bounded, no-network, redaction-first, and do not execute user projects, package managers, Docker, Kubernetes, Terraform, Nginx, databases, Redis/Sentinel, CI workflows, provider APIs, registries, or CVE/advisory lookups.

### Authorized Baseline Families

Implemented authorized baseline families:

- `web_basic`: one explicitly authorized URL with bounded HTTP behavior.
- `domain_basic`: one explicitly authorized domain with bounded DNS queries.
- `subdomain_inventory_basic`: explicit authorized candidates only.

These are separate from archive-only passive config modules and have their own documented authorization and network/DNS limits.

### Active Internal Alpha

Active surfaces remain separate:

- `active_network_dry_run`: no-network planning, `network_requests_sent: 0`.
- `active_http_header_probe`: internal limited one-HEAD capability, disabled by default.

Active does not convert Passive Alpha into a broader live product.

## Accepted Evidence

Accepted evidence for this documentation package:

- README, architecture, and security scope are aligned around passive/local scope, archive-only config modules, no-scope, redaction, local storage, and Active separation.
- `docs/future/passive-suite-alpha-transversal-closeout.md` records Passive Alpha as ready and closed for module expansion.
- `docs/future/passive-alpha-packaging-readiness.md` records trusted local demo readiness with limitations.
- `docs/future/post-alpha-readiness-backlog-triage.md` classifies release gates, external-user blockers, nice-to-have polish, post-release backlog, and Active/Nmap as out of passive release scope.
- `docs/future/passive-alpha-post-tag-verification-handoff.md` records the passive alpha tag/release handoff and published prerelease state.
- `docs/future/active-network-block-25-active-alpha-closeout.md` closes Active Alpha v0 as internal and limited.
- `docs/future/active-network-block-26-passive-alpha-readiness-recheck.md` found no blocker for the current trusted local/passive alpha posture after Active closeout.
- Active Block 24 performed a forbidden-copy review and found no dangerous positive Active capability claim.

No new tests, smokes, tags, pushes, or releases are executed by this block.

## Readiness Statement

Accepted for:

- trusted local Passive Alpha documentation package;
- release-candidate handoff for the current local/passive posture;
- local demo/smoke narratives using documented synthetic fixtures;
- continued product hardening from a known baseline.

Not accepted for:

- production deployment;
- public external users;
- multi-tenant public service use;
- unattended handling of real sensitive archives;
- Nmap;
- broader Active behavior;
- additional live capabilities;
- new passive analyzer implementation;
- credential validation;
- exploitability, breach, compromise, or confirmed-vulnerability claims.

## Should-Fix Before Public Or External Use

Before public/external use, resolve or explicitly gate:

- authentication and deployment hardening;
- storage retention, cleanup, and reset controls;
- onboarding and local-data deletion guidance;
- legal/security disclaimer for uploaded content;
- multi-user isolation and authorization model;
- deployment threat model;
- visible limits and file-size messaging;
- report/export readability polish.

These are not blockers for the trusted local Passive Alpha documentation package, but they are blockers for a public/external product posture.

## Backlog

Backlog after this closeout:

- broader `PassiveReportShell` migration;
- fixture-driven smoke script;
- demo reset workflow;
- dashboard and cross-analyzer summary polish;
- severity and confidence explanation polish;
- future passive modules only after explicit re-scope;
- Nmap or broader Active only after separate docs-first product decision.

## Product Gate Before Public/External Use

Before moving beyond trusted local use:

- define authentication and deployment boundaries;
- define local-data retention and cleanup behavior;
- define user isolation;
- review legal/security disclaimer wording;
- execute and record the chosen release smoke if a new release candidate is prepared;
- review limits, file-size, and local-storage copy;
- review deployment threat model;
- verify that Active remains separated or explicitly re-scoped.

## Nmap Statement

Nmap is not designed, implemented, enabled, tested, or approved in this block.

If product wants to discuss Nmap, use:

```text
NMAP-SCOPE-DECISION-DOCS-FIRST
```

That decision must cover product need, authorization, safety, threat model, target policy, rate limits, operator copy, redaction, testing, no-external-demo-target rules, and explicit acceptance before any implementation. Do not go directly from this closeout to Nmap runtime.

## No-Scope

- No code.
- No runtime changes.
- No tests or fixture changes.
- No probes.
- No live traffic.
- No DNS or HTTP.
- No Docker.
- No Nmap.
- No port scanning.
- No crawling.
- No GET fallback.
- No redirects.
- No body reads.
- No custom headers.
- No auth or cookies.
- No fuzzing.
- No exploitation.
- No credential validation.
- No new Active capability.
- No new Passive analyzer implementation.
- No target-policy relaxation.
- No local-lab mode.
- No `.env`, `.env.*`, or `.envrc` reads.
- No push.
- No real tag or release.

## Next Recommendation

Completed next microphase:

```text
PASSIVE-ALPHA-GAP-FIXES-01
```

Rationale:

- The trusted local Passive Alpha/release-candidate documentation package is accepted.
- The next useful work is hardening toward public/external readiness, starting with product blockers rather than new analyzers or Active expansion.

Alternative paths:

- `PASSIVE-ALPHA-TRUSTED-LOCAL-RELEASE-NOTES` if product wants a fresh internal/local notes package instead of hardening work.
- `NMAP-SCOPE-DECISION-DOCS-FIRST` only if product explicitly chooses to discuss Nmap scope, without implementation.
- `NEXT-LIVE-CAPABILITY-DESIGN-DOCS-FIRST` only if product explicitly chooses to broaden Active after this closeout.

Do not proceed directly to Nmap, another Active capability, or a new passive analyzer implementation from this closeout.

## Validation Commands

Reference checks for this docs-only block:

```text
git status --short
git status --branch --short
git log --oneline -12
git diff --check
git diff --cached --check
git status --short
```

No pytest or npm suite is required while this block remains docs-only.
