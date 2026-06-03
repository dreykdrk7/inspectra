# Passive Alpha P0 01 Auth Boundary Design To Runtime Plan

Status: `PASSIVE_ALPHA_AUTH_BOUNDARY_RUNTIME_PLAN_ACCEPTED`.

Base open-source/self-hosted framing: `docs/future/passive-alpha-p0-00-open-source-self-hosted-product-framing.md`

Base implementation readiness plan: `docs/future/passive-alpha-gap-fixes-08-implementation-readiness-plan.md`

Base auth and user-isolation design: `docs/future/passive-alpha-gap-fixes-03-auth-and-user-isolation-design.md`

Commit scope: docs-only authentication/session boundary plan before any future auth runtime. This block defines supported auth modes, first runtime shape, boundary rules, protected surfaces, tests, and migration implications. It does not change backend, frontend, runner, tests, fixtures, schemas, storage, reports, exports, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_AUTH_BOUNDARY_RUNTIME_PLAN_ACCEPTED
```

Inspectra should introduce auth as a safety boundary for self-hosted, private/internal, and optional public/community use.

This decision does not implement auth. It defines the minimum future runtime shape and keeps the project framed as open-source, local-first, and self-hosted-first rather than commercial SaaS.

## Objective

Define the initial auth/session boundary before owner fields, API guards, storage migration, delete semantics, cleanup controls, or public/community runtime claims.

This block:

- names supported auth modes;
- chooses the first runtime shape;
- compares future session/auth mechanism options;
- defines deny-by-default boundary rules;
- lists protected interfaces;
- defines minimum future tests;
- prepares `PASSIVE-ALPHA-P0-02-OWNER-MODEL-AND-STORAGE-MIGRATION-PLAN`.

## Auth Rationale

Auth is needed to:

- protect self-hosted instances exposed beyond localhost;
- protect a limited public/community instance;
- prevent anonymous uploads, reads, exports, Raw JSON access, deletion, and reset;
- provide a principal for ownership, retention, limits, and audit decisions;
- keep target-based baseline and internal Active jobs tied to an accountable user.

Auth does not imply:

- commercial SaaS;
- billing;
- quotas sold as plans;
- paid tenants;
- tenant billing model;
- enterprise RBAC;
- monetization.

## Supported Auth Modes

### `trusted_local_no_auth`

Purpose:

- Localhost/dev/local trusted use.
- Current trusted local workflow compatibility.
- Synthetic fixture demos.

Rules:

- Conceptually maps all resources to a default local operator.
- Must not be described as public, production, or internet-safe.
- Must warn if future runtime detects network exposure without auth.
- Should be disabled or blocked for public/community use.

### `self_hosted_single_admin`

Purpose:

- Own server or personal machine.
- Small self-hosted install with one accountable operator.
- First recommended runtime mode.

Rules:

- One admin/operator account owns all uploaded files, jobs, results, exports, Raw JSON, and target histories.
- No anonymous upload/list/read/export/delete.
- Admin is effectively owner of everything in the instance.
- Still must not bypass redaction, target policy, feature flags, or Active authorization gates.

### `private_team_lightweight_users`

Purpose:

- Controlled private/internal team install.
- Multiple authenticated users inside one operator-controlled instance.
- No commercial SaaS or enterprise tenant model.

Rules:

- Each uploaded file, job, result, export, Raw JSON view, and target history needs an owner.
- Users see only their own resources unless an explicit admin read-all boundary is accepted.
- Admin read-all is privileged data access and must be documented.
- Background jobs process only accepted jobs with owner context.

### `public_community_limited_instance`

Purpose:

- Optional community convenience instance for people who cannot or do not want to install Inspectra.
- Strictly limited and non-commercial.

Rules:

- No anonymous real uploads.
- Auth or equivalent anti-abuse controls required before real uploads.
- Strict limits and short retention.
- Visible disclaimers and authorized-use copy.
- No regulated or highly sensitive data support.
- No public Active/Nmap behavior.
- Target-based checks require explicit authorization.
- Instance may be disabled, restricted, reset, or removed without commercial availability guarantees.

## Unsupported Auth And Product Modes

- Unauthenticated public upload service.
- Paid SaaS tenants.
- Billing or subscription plans.
- Tenant billing model.
- Enterprise multi-tenant RBAC.
- Arbitrary scan-as-a-service.
- Public Active/Nmap scanner.
- Third-party target testing without explicit authorization.

## Recommended First Runtime Shape

Recommended first implementation target:

```text
self_hosted_single_admin
```

Equivalent label for implementation planning:

```text
single_user_auth
```

Rationale:

- It protects the most likely exposed self-hosted installation.
- It is smaller than multi-user ownership runtime.
- It can preserve `trusted_local_no_auth` for localhost/dev.
- It gives `PASSIVE-ALPHA-P0-02` a concrete default operator/principal to map legacy local data.
- It avoids billing, tenants, organizations, and enterprise RBAC.

Do not start with complex multi-user auth unless the product explicitly decides to prioritize a public/community instance first.

## Session And Auth Mechanism Options

### Simple Local Password And Session Cookie

Pros:

- Best fit for self-hosted single-admin mode.
- No external provider dependency.
- Easy to understand for local/open-source installs.

Risks:

- Requires careful cookie, CSRF, password storage, setup, reset, and host-binding decisions.
- Must avoid insecure defaults if exposed beyond localhost.

Recommendation:

- Preferred initial runtime candidate for `self_hosted_single_admin`, subject to a separate implementation plan.

### Reverse-Proxy Auth

Pros:

- Fits many self-hosted deployments.
- Lets operators reuse existing auth in Nginx, Caddy, Authelia, OAuth2 Proxy, Tailscale, VPN, or SSO layers.

Risks:

- Requires clear trusted-header boundaries.
- Unsafe if the backend is reachable directly.

Recommendation:

- Document as an alternative integration mode, not the only default.

### OAuth/OIDC

Pros:

- Strong fit for private/internal teams later.

Risks:

- More configuration complexity.
- Easy to overdesign toward enterprise SaaS.

Recommendation:

- Future option, not initial runtime.

### Magic Link Or Email Auth

Pros:

- Friendly for public/community instances.

Risks:

- Requires email infrastructure and abuse controls.
- Adds operational complexity.

Recommendation:

- Future option for community instance planning, not initial runtime.

### Basic Auth Behind A Proxy

Pros:

- Simple for personal self-hosted deployments.

Risks:

- Weak UX and security if used incorrectly.
- Does not establish app-level ownership by itself.

Recommendation:

- Acceptable only as a documented proxy-side guardrail, not a full app auth model.

## Boundary Rules

Default rule:

```text
Deny unless the deployment mode, authenticated principal, owner, role, action, feature flag, target/file policy, and limits all allow the request.
```

Required boundary rules:

- No anonymous upload.
- No anonymous file list or metadata read.
- No anonymous job creation for sensitive jobs.
- No anonymous job list.
- No anonymous job detail or result read.
- No anonymous report export.
- No anonymous SBOM export.
- No anonymous Raw JSON.
- No anonymous delete or reset.
- Health, static assets, and login/onboarding pages may be public only if they expose no sensitive data.
- Backend authorization is authoritative.
- Frontend guards are UX only.
- Redaction remains required after authorization succeeds.

## Admin And Operator Boundary

Admin/operator can:

- configure or maintain the instance;
- view health and operational status;
- perform cleanup/reset only according to documented retention policy;
- own everything in `self_hosted_single_admin` mode.

Admin/operator must not:

- bypass redaction requirements;
- bypass target policy;
- bypass Active feature flags or double confirmation;
- bypass no-read sensitive-file boundaries;
- silently read all users' sensitive data in a private-team or public/community mode unless admin read-all is explicitly accepted and disclosed.

For `self_hosted_single_admin`, admin read-all is inherent because the admin is the sole owner. For `private_team_lightweight_users` or `public_community_limited_instance`, admin read-all is privileged data access and must be a separate product/security decision.

## Trusted Local Compatibility

Trusted local compatibility should work as:

- current local workflows map conceptually to `trusted_local_no_auth`;
- future migrations can map legacy local jobs/uploads/results to a default local operator;
- default local operator is a compatibility bridge, not internet-safe auth;
- docs must warn if a no-auth app is exposed on `0.0.0.0`, a LAN, or the public internet;
- localhost/dev no-auth must not be used to claim public/community readiness.

## Public Community Instance Boundary

A public/community instance, if offered later, must have:

- no anonymous real uploads;
- auth or equivalent anti-abuse controls;
- rate limits and abuse prevention as future requirements;
- strict upload, analyzer, job, export, and retention limits;
- short retention;
- visible disclaimers;
- no regulated or highly sensitive data support;
- no public Active/Nmap;
- target-based checks only with explicit authorization;
- ability to disable, restrict, reset, or remove the instance.

## Interfaces And Surfaces To Protect

Future auth must protect:

- upload endpoints;
- file metadata and file listing;
- audit/job creation;
- job listing;
- job detail and result reads;
- report exports: Markdown, HTML, XML, PDF;
- SBOM exports;
- Raw JSON;
- delete and reset operations;
- baseline target jobs;
- internal Active jobs;
- target histories;
- admin/operational views;
- configuration surfaces that reveal deployment details.

Public without sensitive data:

- health endpoint, only if it exposes no sensitive data;
- static frontend shell;
- login/onboarding/disclaimer pages.

## Minimum Future Tests

Future runtime implementation should test:

- anonymous users cannot upload;
- anonymous users cannot list files;
- anonymous users cannot read file metadata;
- anonymous users cannot create sensitive audit jobs;
- anonymous users cannot list jobs;
- anonymous users cannot read job detail/results;
- anonymous users cannot export Markdown/HTML/XML/PDF;
- anonymous users cannot export SBOMs;
- anonymous users cannot view Raw JSON;
- anonymous users cannot delete or reset;
- login/session is required for sensitive endpoints;
- trusted local mode behavior is explicit and bounded;
- `self_hosted_single_admin` can complete upload, job, report, export, Raw JSON, and delete flows;
- health/static/login surfaces do not leak sensitive data;
- target-based jobs require auth and explicit target authorization;
- internal Active remains feature-flagged and double-confirmed;
- redaction regression tests still pass.

## Migration Implications For P0-02

`PASSIVE-ALPHA-P0-02-OWNER-MODEL-AND-STORAGE-MIGRATION-PLAN` depends on this block.

Implications:

- An auth principal must exist before `owner_id` can be meaningful.
- `trusted_local_no_auth` needs a default local operator for legacy/local data.
- `self_hosted_single_admin` can map all resources to the admin owner.
- Multi-user modes require per-user ownership for uploads, jobs, results, reports, exports, Raw JSON, and target histories.
- Target-based jobs with `file_id: null` still need an owner.
- Exports, SBOMs, and Raw JSON inherit ownership from the job/result.
- Legacy jobs without owner should be mapped, quarantined, or blocked according to the migration plan.

## Open Questions

- Should the first implementation use simple local password/session cookie or reverse-proxy auth?
- Should initial admin setup happen through CLI, setup page, config file, or generated one-time token?
- Should `trusted_local_no_auth` be allowed only when bound to localhost?
- How should runtime detect or warn about `0.0.0.0` exposure without auth?
- Which endpoints may remain public beyond health/static/login?
- Should admin read-all exist outside `self_hosted_single_admin`?
- Should a public/community instance be planned after single-admin auth or after private-team ownership?
- Should shareable report links remain disabled until ownership is complete?

## Out Of Scope

- Auth implementation.
- Login UI.
- Session or cookie implementation.
- Password reset.
- OAuth/OIDC runtime.
- DB migrations.
- `owner_id` implementation.
- Billing.
- SaaS tenants.
- Enterprise RBAC.
- Nmap.
- New Active behavior.
- New Passive analyzers.
- Runtime cleanup.
- Report/export implementation.
- Target-policy relaxation.
- Local-lab mode.

## No-Scope

- No code.
- No runtime changes.
- No tests or fixture changes.
- No UI implementation.
- No report/export implementation.
- No auth implementation.
- No session or cookie implementation.
- No cleanup implementation.
- No DB migration.
- No storage schema change.
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
- No billing.
- No SaaS plans.
- No tenant billing model.
- No target-policy relaxation.
- No local-lab mode.
- No `.env`, `.env.*`, or `.envrc` reads.
- No push.
- No real tag or release.

## Acceptance Criteria

- Auth modes are defined.
- SaaS and commercial framing are avoided.
- First runtime shape is chosen.
- Boundary rules are defined.
- Admin/operator boundary is defined.
- Trusted local compatibility is defined.
- Public/community caveats are defined.
- Protected surfaces are listed.
- Minimum future tests are defined.
- Migration implications for P0-02 are clear.
- No runtime or capability changes are made.

## Next Recommendation

```text
PASSIVE-ALPHA-P0-02-OWNER-MODEL-AND-STORAGE-MIGRATION-PLAN
```

Proceed to owner model and migration planning after the auth principal/default-operator boundary is accepted.

## Validation Commands

Reference checks for this docs-only auth-boundary plan:

```text
git status --short
git status --branch --short
git log --oneline -12
git diff --check
git diff --cached --check
git status --short
```

No pytest or npm suite is required while this block remains docs-only.
