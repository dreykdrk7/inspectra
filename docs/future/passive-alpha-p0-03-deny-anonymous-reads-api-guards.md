# Passive Alpha P0 03 Deny Anonymous Reads API Guards

Status: `PASSIVE_ALPHA_DENY_ANONYMOUS_API_GUARDS_PLAN_ACCEPTED`.

Base owner model and storage migration plan: `docs/future/passive-alpha-p0-02-owner-model-and-storage-migration-plan.md`

Base auth-boundary runtime plan: `docs/future/passive-alpha-p0-01-auth-boundary-design-to-runtime-plan.md`

Base open-source/self-hosted framing: `docs/future/passive-alpha-p0-00-open-source-self-hosted-product-framing.md`

Base implementation readiness plan: `docs/future/passive-alpha-gap-fixes-08-implementation-readiness-plan.md`

Commit scope: docs-only API guard plan before future runtime implementation. This block defines deny-anonymous principles, deployment-mode behavior, protected surfaces, public-safe surfaces, error behavior, trusted-local compatibility, target-flow implications, and minimum tests. It does not change backend, frontend, runner, tests, fixtures, schemas, storage, reports, exports, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_DENY_ANONYMOUS_API_GUARDS_PLAN_ACCEPTED
```

Inspectra should deny anonymous access to sensitive API surfaces before owner lookup in any non-local or auth-required mode.

This is a safety boundary for open-source, local-first, and self-hosted-first use. It is not a SaaS, billing, subscription, tenant, quota monetization, or enterprise multi-tenant design.

## Objective

Define the API guard boundary for future runtime work.

This block does not implement guards. It names the sensitive routes and product surfaces that must reject anonymous requests, defines how `trusted_local_no_auth` remains bounded to localhost/dev/local trusted use, and prepares the next owner-scoped runtime block:

```text
PASSIVE-ALPHA-P0-04-OWNER-SCOPED-JOBS-RESULTS-EXPORTS
```

## Guard Principles

- Deny anonymous by default for sensitive endpoints.
- Reject anonymous requests before owner lookup.
- Avoid revealing whether a file, job, export, target, or result exists before auth succeeds.
- Backend authorization is authoritative.
- Frontend guards are UX only.
- Health, static assets, login, onboarding, and documentation pages may remain public only if they expose no sensitive data.
- `trusted_local_no_auth` is allowed only for localhost/dev/local trusted use.
- `trusted_local_no_auth` maps sensitive actions to the default local operator only inside that explicit local mode.
- `self_hosted_single_admin` requires auth when exposed beyond local trusted use.
- `private_team_lightweight_users` and `public_community_limited_instance` require auth and deny anonymous real uploads, reads, jobs, exports, Raw JSON, delete/reset, and target flows.
- Redaction remains required after auth succeeds.
- No guard should relax target policy, Active feature flags, double confirmation, archive/file boundaries, or no-read sensitive-file rules.
- No guard introduces billing, SaaS tenants, tenant billing, commercial plans, enterprise RBAC, Nmap, or new capabilities.

## Deployment Mode Behavior

### `trusted_local_no_auth`

Allowed only for:

- localhost/dev;
- trusted local operator workflows;
- synthetic fixture demos.

Behavior:

- Sensitive endpoints can map to the default local operator.
- The mode must be explicit and documented.
- Future runtime should warn or fail closed if this mode is bound to non-local interfaces.
- It must not be described as public, production, internet-safe, or community-instance ready.

### `self_hosted_single_admin`

Behavior:

- Auth is required for all sensitive endpoints.
- The admin principal owns all resources by default.
- Anonymous uploads, reads, job creation, exports, Raw JSON, delete/reset, and target flows are denied.
- Owner checks can be simple in P0 because the authenticated admin is the sole owner.

### `private_team_lightweight_users`

Behavior:

- Auth is required.
- Anonymous access is denied for all sensitive endpoints.
- P0-03 denies anonymous first.
- P0-04 must enforce owner-scoped reads and writes.
- Admin read-all remains a separate explicit product/security decision.

### `public_community_limited_instance`

Behavior:

- No anonymous real uploads.
- No anonymous reads or exports.
- Auth or equivalent anti-abuse controls are required before real uploads.
- Strict limits, short retention, onboarding/disclaimers, and abuse controls remain future requirements.
- Active/Nmap public behavior remains out of scope.

## Protected Endpoint And Surface Inventory

This inventory is based on the current backend route surface and planned P0 ownership/deletion surfaces. P0-03 is about denying anonymous access; P0-04 is responsible for full owner-scoped enforcement.

| Surface | Current or planned route/surface | Anonymous behavior | Authenticated behavior | Trusted local behavior | Future owner check required |
| --- | --- | --- | --- | --- | --- |
| Upload PDF/image/manifest/archive | `POST /files/pdf`, `/files/image`, `/files/manifest`, `/files/archive` | Deny outside trusted local | Allowed in auth modes; assign owner later | Map to default local operator | Yes |
| List files | `GET /files` | Deny outside trusted local | Allowed; owner filter in P0-04 | Default local operator sees local files | Yes |
| Read file metadata | `GET /files/{file_id}` | Deny outside trusted local | Allowed; owner check in P0-04 | Default local operator reads local metadata | Yes |
| Delete file | `DELETE /files/{file_id}` | Deny outside trusted local | Allowed only after delete policy and owner/admin checks | Default local operator only if local delete remains enabled | Yes |
| Create file-based job | `POST /audits/*/{file_id}` | Deny outside trusted local | Allowed for authenticated users; source ownership in P0-04 | Default local operator creates local jobs | Yes |
| Create target-based baseline job | `POST /audits/web/basic`, `/audits/domain/basic`, `/audits/subdomains/basic` | Deny outside trusted local | Allowed only with auth and target authorization metadata | Default local operator creates local target jobs | Yes |
| Create Active dry-run | `POST /active/network/dry-run` | Deny outside trusted local | Allowed only if enabled and authorized | Default local operator only when explicitly enabled | Yes |
| Create Active one-HEAD | `POST /active/network/http-header-probe` | Deny outside trusted local | Allowed only if enabled, authorized, and double-confirmed | Default local operator only when explicitly enabled | Yes |
| List jobs | `GET /jobs` | Deny outside trusted local | Allowed; owner filter in P0-04 | Default local operator sees local jobs | Yes |
| Read job detail/result | `GET /jobs/{job_id}` | Deny outside trusted local | Allowed; owner check in P0-04 | Default local operator reads local jobs | Yes |
| View frontend report | Frontend job report routes/views | Deny via backend API outside trusted local | UX guard plus backend job authorization | Local frontend can render default-operator jobs | Yes |
| Export Markdown/HTML/XML/PDF | `GET /jobs/{job_id}/export/*` | Deny outside trusted local | Allowed; owner check before render in P0-04 | Default local operator exports local jobs | Yes |
| Export SBOM | `GET /jobs/{job_id}/sbom/*` | Deny outside trusted local | Allowed; owner check before render in P0-04 | Default local operator exports local SBOMs | Yes |
| View Raw JSON | API job result and frontend Raw JSON | Deny outside trusted local | Allowed; owner check and redaction in P0-04 | Default local operator views local Raw JSON | Yes |
| Delete job/result | Planned delete job/result surface | Deny outside trusted local | Allowed only after retention/delete policy and owner/admin checks | Default local operator only if local delete remains enabled | Yes |
| Reset demo/data | Planned reset/cleanup surface | Deny outside trusted local | Admin/operator only according to retention policy | Local demo reset only for known synthetic/demo data | Yes |
| Admin/config/operational views | Planned admin/config/ops surfaces | Deny outside public-safe health/static/login | Admin/operator only | Local operator only | Maybe, admin boundary explicit |

## Public-Safe Surfaces

The following may remain public if they expose no sensitive data:

- health endpoint;
- static frontend shell;
- login page;
- onboarding and disclaimer pages;
- documentation/static assets.

Public-safe surfaces must not expose:

- filenames;
- file IDs;
- job IDs;
- job counts;
- target URLs or domains;
- source paths;
- local storage paths;
- Raw JSON;
- errors with sensitive context;
- feature flag details that help abuse;
- deployment secrets;
- provider tokens;
- internal config values;
- `.env`, backup, state, dump, or source-file content;
- whether a particular file/job/target exists.

Health should remain minimal. If version, build, feature-flag, or storage information is later added, it needs a separate review.

## Error And Response Behavior

Anonymous-denied behavior:

- Return controlled `401 Unauthorized` or `403 Forbidden`.
- Keep response messages generic.
- Do not reveal whether a file, job, export, SBOM, Raw JSON payload, target history, or delete target exists.
- Do not reveal another user's filenames, targets, summaries, errors, paths, or redaction notes.
- Do not include stack traces.
- Do not include raw exception text if it might contain user input.

Missing owner behavior:

- In non-local/auth-required modes, missing owner should be a controlled denial until migration maps or quarantines the resource.
- In trusted local mode, accepted legacy resources may map to the default local operator.
- Logs should record minimal, redacted operational context.

Suggested response posture:

- Use `401` when no authenticated principal is present and auth is required.
- Use `403` when a principal is present but the action is not allowed.
- Use generic `404` only if the product later decides to avoid resource enumeration for authenticated users without access.

The exact `401` versus `403` split remains an implementation question.

## Trusted Local Compatibility

Trusted local compatibility remains important, but it is not an internet-safe deployment mode.

Rules:

- `trusted_local_no_auth` must be explicit.
- It should be allowed only for localhost/dev/local trusted use.
- Sensitive actions map to the default local operator.
- Future runtime should warn or fail closed if no-auth mode is bound to `0.0.0.0`, a LAN interface, or a public interface.
- Docs and UI must not say no-auth mode is safe for self-hosted exposed, private-team, or public/community use.
- Migrated local data can map to the default local operator according to P0-02.

## Relationship To Ownership And P0-04

P0-03 and P0-04 are intentionally separate.

P0-03:

- denies anonymous access first;
- defines public-safe allowlist boundaries;
- keeps trusted local compatibility explicit;
- prepares central auth-required route behavior;
- does not complete multi-user isolation.

P0-04:

- enforces owner-scoped file/job/result/export/Raw JSON access;
- filters lists by owner;
- checks source file ownership before creating file-based jobs;
- checks job ownership before rendering exports/SBOM/Raw JSON;
- prevents user A from reading user B resources;
- defines admin read-all behavior if accepted.

After P0-03, authenticated single-admin mode may access all resources because the admin is the sole owner. Private-team and public/community isolation still require P0-04 owner enforcement before real use.

## Relationship To Target-Based Flows

Target-based flows are sensitive even when no file is uploaded.

Rules:

- Target jobs require auth before creation outside trusted local mode.
- Target authorization metadata remains required.
- `web_basic`, `domain_basic`, and `subdomain_inventory_basic` remain authorized target flows.
- `active_network_dry_run` remains no-network and independent.
- `active_http_header_probe` remains limited live, feature-flagged, policy-gated, authorized, and double-confirmed.
- Anonymous users cannot run dry-run or one-HEAD jobs.
- Active feature flags are still required after auth succeeds.
- Nmap is not included.
- No target-policy relaxation is approved.

## Runtime Implementation Candidates

These are docs-only implementation candidates for a future runtime block:

- central dependency, middleware, or helper for auth-required endpoints;
- explicit route allowlist for public-safe endpoints;
- deployment mode flag for `trusted_local_no_auth` versus auth-required modes;
- default local operator principal for trusted local compatibility;
- controlled auth error helper;
- sensitive route test matrix;
- logging helper that redacts auth and resource-denial context;
- API docs/comments identifying whether each route is public-safe or auth-required.

Do not implement these in this block.

## Minimum Future Tests

Future runtime implementation should test:

- anonymous users cannot upload files;
- anonymous users cannot list files;
- anonymous users cannot read file metadata;
- anonymous users cannot delete files;
- anonymous users cannot create file-based jobs;
- anonymous users cannot create target-based baseline jobs;
- anonymous users cannot create Active dry-run jobs;
- anonymous users cannot create Active one-HEAD jobs;
- anonymous users cannot list jobs;
- anonymous users cannot read job details or results;
- anonymous users cannot render frontend reports from protected API data;
- anonymous users cannot export Markdown/HTML/XML/PDF reports;
- anonymous users cannot export SBOMs;
- anonymous users cannot view Raw JSON;
- anonymous users cannot delete jobs/results;
- anonymous users cannot reset demo/data;
- health/static/login/onboarding public surfaces leak no sensitive data;
- trusted local no-auth behavior is explicit and bounded;
- no-auth exposed beyond local interfaces warns or fails closed when such detection exists;
- `self_hosted_single_admin` auth passes upload, job, report, export, SBOM, Raw JSON, and target-job flows;
- auth errors do not reveal resource existence;
- missing owner denies non-local reads according to P0-02;
- Active feature flags and double confirmation still apply after auth succeeds;
- redaction tests still pass.

## Open Questions

- Should anonymous denied return `401` or `403` by default?
- Should inaccessible authenticated resources return `403` or generic `404`?
- How should `trusted_local_no_auth` be configured safely?
- Should no-auth mode require an explicit local-only bind check?
- How should runtime detect `0.0.0.0` exposure without auth?
- Should health reveal service name only, or also version/build?
- Should export routes require auth even in local mode, or map to default local operator?
- Do admin/config/operational views exist in P0, or are they a later design?
- What should the frontend do when API returns `401` for a previously public route?
- Should browser storage be cleared automatically on logout in future auth runtime?

## Out Of Scope

- Auth implementation.
- API guard implementation.
- Owner-scoped checks.
- Sessions or cookies.
- Login UI.
- `owner_id` implementation.
- Storage migrations.
- DB/schema changes.
- Cleanup/delete runtime.
- Report/export implementation.
- SBOM implementation changes.
- Frontend route implementation.
- Billing.
- SaaS tenants.
- Tenant billing model.
- Enterprise RBAC.
- Nmap.
- New Active behavior.
- New Passive analyzers.
- Target-policy relaxation.
- Public/community runtime approval.

## No-Scope

- No code.
- No runtime changes.
- No tests or fixture changes.
- No auth implementation.
- No session or cookie implementation.
- No owner checks implementation.
- No API guard implementation.
- No DB/storage migration.
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
- No billing.
- No SaaS plans.
- No tenant billing model.
- No target-policy relaxation.
- No local-lab mode.
- No `.env`, `.env.*`, or `.envrc` reads.
- No push.
- No real tag or release.

## Acceptance Criteria

- Guard principles are defined.
- Deployment behavior is defined.
- Protected surfaces are inventoried.
- Public-safe surfaces are defined.
- Error behavior is defined.
- Trusted local compatibility is defined.
- Target-flow implications are defined.
- Minimum future tests are defined.
- P0-04 relationship is clear.
- No runtime or capability changes are made.

## Next Recommendation

```text
PASSIVE-ALPHA-P0-04-OWNER-SCOPED-JOBS-RESULTS-EXPORTS
```

Proceed to owner-scoped jobs, results, reports, exports, SBOM, Raw JSON, and target-history planning after anonymous API guard behavior is accepted.

## Validation Commands

Reference checks for this docs-only API guard plan:

```text
git status --short
git status --branch --short
git log --oneline -12
git diff --check
git diff --cached --check
git status --short
```

No pytest or npm suite is required while this block remains docs-only.
