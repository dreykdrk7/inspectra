# Passive Alpha P0 07 P0 Runtime Planning Closeout

Status: `PASSIVE_ALPHA_P0_RUNTIME_PLANNING_CLOSED`.

Base deployment hardening checklist: `docs/future/passive-alpha-p0-06-deployment-hardening-checklist.md`

Base retention/delete runtime plan: `docs/future/passive-alpha-p0-05-retention-delete-semantics-runtime-plan.md`

Base owner-scoped resources plan: `docs/future/passive-alpha-p0-04-owner-scoped-jobs-results-exports.md`

Base deny-anonymous API guards plan: `docs/future/passive-alpha-p0-03-deny-anonymous-reads-api-guards.md`

Base owner model and storage migration plan: `docs/future/passive-alpha-p0-02-owner-model-and-storage-migration-plan.md`

Base auth-boundary runtime plan: `docs/future/passive-alpha-p0-01-auth-boundary-design-to-runtime-plan.md`

Base open-source/self-hosted framing: `docs/future/passive-alpha-p0-00-open-source-self-hosted-product-framing.md`

Base implementation readiness plan: `docs/future/passive-alpha-gap-fixes-08-implementation-readiness-plan.md`

Runtime 01 auth-mode/local-operator slice: `docs/future/passive-alpha-runtime-01-auth-mode-flag-and-local-operator.md`

Runtime 02 single-admin auth skeleton: `docs/future/passive-alpha-runtime-02-single-admin-auth-skeleton.md`

Commit scope: docs-only closeout for Passive Alpha P0 runtime planning. This block consolidates accepted docs-first decisions, runtime dependencies, the first implementation sequence, blockers, tests, and risk register. It does not change backend, frontend, runner, tests, fixtures, schemas, storage, auth, sessions, cookies, migrations, API guards, owner checks, retention/delete behavior, cleanup, CORS, CSRF, TLS, reverse proxy behavior, reports, exports, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_P0_RUNTIME_PLANNING_CLOSED
```

The Passive Alpha P0 runtime planning line is closed at the docs-first planning level.

Inspectra remains open-source, altruistic, local-first, and self-hosted-first. The P0 runtime controls are security and privacy boundaries for local, self-hosted, private/internal, and optional limited public/community use. They are not a commercial SaaS, billing, quota monetization, paid-plan, subscription, tenant billing, enterprise multi-tenant, or scan-as-a-service model.

## Closeout Summary

P0 planning now defines the safety model needed before Inspectra is exposed beyond trusted local use. The accepted line covers:

- open-source/self-hosted product framing;
- auth and session boundary;
- owner model and legacy storage migration;
- deny-anonymous API guards;
- owner-scoped jobs, results, exports, Raw JSON, and target histories;
- retention and delete semantics;
- deployment hardening checklist.

No runtime behavior is implemented by this closeout. The next work should be small runtime slices, starting with the auth mode flag and default local/operator concept.

## Accepted P0 Decisions

| Block | Decision | Primary output |
| --- | --- | --- |
| P0-00 | `PASSIVE_ALPHA_OPEN_SOURCE_SELF_HOSTED_FRAMING_ACCEPTED` | Inspectra is open-source, local-first, self-hosted-first, and non-commercial. |
| P0-01 | `PASSIVE_ALPHA_AUTH_BOUNDARY_RUNTIME_PLAN_ACCEPTED` | Deployment/auth modes and first runtime shape are defined. |
| P0-02 | `PASSIVE_ALPHA_OWNER_MODEL_STORAGE_MIGRATION_PLAN_ACCEPTED` | Owner model, target-job ownership, and trusted local legacy mapping are defined. |
| P0-03 | `PASSIVE_ALPHA_DENY_ANONYMOUS_API_GUARDS_PLAN_ACCEPTED` | Sensitive routes that must deny anonymous access are listed. |
| P0-04 | `PASSIVE_ALPHA_OWNER_SCOPED_RESOURCES_PLAN_ACCEPTED` | Files, jobs, results, reports, exports, SBOMs, Raw JSON, and target histories are owner-scoped. |
| P0-05 | `PASSIVE_ALPHA_RETENTION_DELETE_RUNTIME_PLAN_ACCEPTED` | Source deletion, job/result deletion, retention, cleanup, and reset semantics are defined. |
| P0-06 | `PASSIVE_ALPHA_DEPLOYMENT_HARDENING_CHECKLIST_ACCEPTED` | Host binding, TLS/proxy, CORS/CSRF, storage, logs, backups, Active boundaries, and no-go checks are defined. |

## What Is Defined

- Open-source, local-first, self-hosted-first framing.
- Supported deployment modes:
  - `trusted_local_no_auth`
  - `self_hosted_single_admin`
  - `private_team_lightweight_users`
  - `public_community_limited_instance`
- Auth modes and first runtime shape:
  - trusted local no-auth for localhost/dev/local trusted use only;
  - `single_user_auth` for the first self-hosted runtime;
  - default local/admin operator compatibility.
- Owner model:
  - uploaded files;
  - file metadata;
  - jobs;
  - results;
  - reports;
  - Markdown/HTML/XML/PDF exports;
  - SBOM exports;
  - Raw JSON;
  - delete/reset operations;
  - baseline target jobs;
  - internal Active jobs;
  - target histories.
- Legacy migration strategy:
  - existing trusted local data maps to a default local/admin operator for `self_hosted_single_admin`;
  - ownerless records are not silently exposed in non-local modes.
- Deny-anonymous boundary:
  - sensitive uploads, reads, job creation, results, reports, exports, Raw JSON, target histories, delete/reset, and admin/config surfaces require auth outside trusted local mode.
- Owner-scoped enforcement:
  - lists filter by owner;
  - direct ID reads check owner;
  - file-based jobs require source ownership;
  - target-based jobs carry an owner with `file_id: null`;
  - report/export/Raw JSON access follows job ownership.
- Delete and retention semantics:
  - source upload deletion removes source bytes and keeps redacted historical job results with source-deleted markers by default;
  - job/result deletion removes result JSON, report/export/SBOM availability, and Raw JSON access;
  - admin cleanup, demo reset, scheduler, logs, backups, and manual downloads have explicit caveats.
- Deployment hardening checklist:
  - host binding;
  - reverse proxy and TLS;
  - future session/cookie controls;
  - CORS and CSRF;
  - storage permissions;
  - logs and audit;
  - backups and snapshots;
  - retention config;
  - admin/operator access;
  - Active boundaries;
  - public/community no-go checks.
- No-go checklist before exposing an instance beyond trusted local use.

## What Is Not Implemented

- Auth runtime.
- Session or cookie runtime.
- Login UI.
- `owner_id` fields.
- Storage migrations.
- API guards.
- Owner checks.
- Source/job/result delete runtime.
- Cleanup scheduler.
- Deployment hardening runtime.
- Host-binding fail-closed checks.
- CORS or CSRF changes.
- TLS or reverse proxy setup.
- Report/export UI polish.
- Runtime tests or fixtures.
- Public/community runtime.
- Multi-user runtime.
- Billing, SaaS, tenant billing, or enterprise multi-tenant behavior.
- Nmap.
- New Active behavior.
- New Passive analyzers.

## Recommended Runtime Implementation Sequence

1. `PASSIVE-ALPHA-RUNTIME-01-AUTH-MODE-FLAG-AND-LOCAL-OPERATOR`
2. `PASSIVE-ALPHA-RUNTIME-02-SINGLE-ADMIN-AUTH-SKELETON`
3. `PASSIVE-ALPHA-RUNTIME-03-DENY-ANONYMOUS-SENSITIVE-ROUTES`
4. `PASSIVE-ALPHA-RUNTIME-04-OWNER-METADATA-WRITE-PATH`
5. `PASSIVE-ALPHA-RUNTIME-05-LEGACY-LOCAL-DATA-MAPPING`
6. `PASSIVE-ALPHA-RUNTIME-06-OWNER-SCOPED-READS-AND-EXPORTS`
7. `PASSIVE-ALPHA-RUNTIME-07-DELETE-SOURCE-AND-JOB-RESULTS`
8. `PASSIVE-ALPHA-RUNTIME-08-DEPLOYMENT-HARDENING-SMOKE`

Each runtime slice should stay small and testable. Do not combine auth, ownership, retention/delete, UI, and deployment hardening in one large diff.

## First Runtime Slice

Recommended first runtime block:

```text
PASSIVE-ALPHA-RUNTIME-01-AUTH-MODE-FLAG-AND-LOCAL-OPERATOR
```

Rationale:

- It defines runtime mode before full login behavior.
- It keeps `trusted_local_no_auth` explicit instead of implicit.
- It introduces the default local/admin operator concept needed for owner mapping.
- It prepares tests for auth-required paths without breaking the current trusted local workflow.
- It gives later slices a stable operator/principal shape before `owner_id`, migrations, API guards, or owner checks are added.

Expected first-slice boundaries:

- Add mode/config naming only as separately scoped runtime work.
- Keep existing trusted local smoke behavior working.
- Do not add multi-user behavior.
- Do not expose non-local/public mode.
- Do not add billing, SaaS tenants, Nmap, new Active behavior, or new analyzers.

## Runtime Blockers Before Non-Local/Public/Community

Non-local, self-hosted exposed, private/internal, or optional public/community use remains blocked until:

- auth is implemented;
- anonymous sensitive routes are denied;
- owner metadata exists;
- owner checks are enforced;
- source and job/result delete semantics are implemented;
- storage paths are not web-served directly;
- CORS and CSRF are reviewed;
- TLS/reverse proxy guidance is documented;
- retention/delete controls are visible;
- disclaimers and limits are surfaced;
- logs and controlled errors avoid sensitive context;
- Active target flows remain gated and disabled by default unless explicitly enabled;
- security review is passed.

## Minimum Test Suite For Runtime Slices

Future runtime implementation should include tests for:

- trusted local mode keeps current smoke flows working;
- auth-required mode denies anonymous sensitive endpoints;
- default local/admin operator is assigned or mapped;
- public-safe health/static/login/onboarding surfaces expose no sensitive data;
- redaction regressions stay passing;
- file list/detail/delete route guards;
- job list/detail/result route guards;
- report and Markdown/HTML/XML/PDF export route guards;
- SBOM export route guards;
- Raw JSON route guards;
- target-based jobs with `file_id: null`;
- Active dry-run remains independent and no-network;
- Active one-HEAD remains disabled by default unless explicitly enabled;
- failed, sparse, malformed, queued, and running payloads do not leak data across owners.

## Runtime Risk Register

- Breaking the current trusted local workflow.
- Accidentally exposing no-auth behavior on LAN or public interfaces.
- Ownerless legacy files/jobs/results becoming reachable in non-local modes.
- Partial migrations leaving mixed owner state.
- Frontend code assuming sensitive backend APIs remain public.
- Report/export routes leaking before auth and owner guards.
- Raw JSON routes exposing legacy sensitive payloads before guard coverage.
- Logs or controlled errors retaining sensitive context.
- Delete/reset operations removing more data than intended.
- Manual downloads, backups, snapshots, and browser copies outliving app-side deletion.
- Active target flows becoming reachable without the intended feature flags and confirmations.

## Product Readiness Statement

- Trusted local use remains accepted for synthetic fixture demos and local operator workflows.
- Self-hosted exposed use is pending runtime implementation of auth, owner checks, retention/delete controls, deployment hardening, visible copy, and review.
- Private/internal team use is pending the same runtime controls plus owner-scoped behavior.
- Optional public/community use is pending runtime controls, anti-abuse/limits, short retention, operator controls, and security review.
- Commercial SaaS, billing, subscription plans, tenant billing, enterprise multi-tenancy, scan-as-a-service behavior, and Nmap are out of scope.

## No-Go Before Runtime Implementation

- Do not implement multi-user behavior before single-admin mode is stable.
- Do not add billing, SaaS, tenant billing, subscription plans, or enterprise tenancy.
- Do not add Nmap.
- Do not add new Passive analyzers.
- Do not add public Active behavior.
- Do not combine auth, ownership, retention/delete, cleanup, and UI in one large diff.
- Do not read `.env`, `.env.*`, or `.envrc` files.
- Do not weaken existing Active target policy or production checks to make local smoke easier.
- Do not present findings as confirmed vulnerabilities, exploitability proof, or breach evidence.

## Out Of Scope

- Runtime implementation.
- Tests or fixture changes.
- Backend changes.
- Frontend changes.
- Runner changes.
- Auth implementation.
- Session or cookie implementation.
- Login UI.
- Owner field implementation.
- Storage migration.
- API guard implementation.
- Owner check implementation.
- Delete/reset implementation.
- Cleanup scheduler.
- Deployment hardening implementation.
- CORS/CSRF implementation.
- TLS or reverse proxy setup.
- Report/export implementation.
- Report/export UI polish.
- New Active capability.
- New Passive analyzer.
- Nmap.
- Push, tag, or release.

## Acceptance Criteria

- Final decision is recorded as `PASSIVE_ALPHA_P0_RUNTIME_PLANNING_CLOSED`.
- P0-00 through P0-06 accepted decisions are summarized.
- Defined runtime boundaries are listed.
- Non-implemented runtime work is explicit.
- Runtime implementation sequence is defined.
- First runtime slice is selected.
- Blockers before non-local/public/community use are listed.
- Minimum runtime tests are listed.
- Risk register is documented.
- Product readiness statement is clear.
- No-go conditions are clear.
- No runtime or capability changes are made.

## Runtime Implementation Notes

The first runtime slice is now accepted as `PASSIVE_ALPHA_RUNTIME_AUTH_MODE_LOCAL_OPERATOR_ACCEPTED`. It adds explicit backend auth mode parsing and the default local/admin operator concept while preserving current trusted local endpoint behavior.

The second runtime slice is now accepted as `PASSIVE_ALPHA_RUNTIME_SINGLE_ADMIN_AUTH_SKELETON_ACCEPTED`. It adds `GET /auth/status` and configured/unconfigured status for future single-admin auth without adding login, sessions, cookies, owner metadata, global guards, or permission changes.

## Next Recommendation

```text
PASSIVE-ALPHA-RUNTIME-03-DENY-ANONYMOUS-SENSITIVE-ROUTES
```

Continue runtime work by applying deny-anonymous behavior to sensitive routes when auth mode requires it. Keep owner metadata, owner checks, migrations, retention/delete runtime, cleanup, deployment hardening, UI polish, public/community support, billing/SaaS concepts, Nmap, new Active behavior, and new analyzers for later separately scoped microphases.

## Validation Commands

Reference checks for this docs-only closeout:

```text
git status --short
git status --branch --short
git log --oneline -12
git diff --check
git diff --cached --check
git status --short
```

No pytest or npm suite is required while this block remains docs-only.
