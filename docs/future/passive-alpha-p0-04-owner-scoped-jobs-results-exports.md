# Passive Alpha P0 04 Owner Scoped Jobs Results Exports

Status: `PASSIVE_ALPHA_OWNER_SCOPED_RESOURCES_PLAN_ACCEPTED`.

Base deny-anonymous API guards plan: `docs/future/passive-alpha-p0-03-deny-anonymous-reads-api-guards.md`

Base owner model and storage migration plan: `docs/future/passive-alpha-p0-02-owner-model-and-storage-migration-plan.md`

Base auth-boundary runtime plan: `docs/future/passive-alpha-p0-01-auth-boundary-design-to-runtime-plan.md`

Base implementation readiness plan: `docs/future/passive-alpha-gap-fixes-08-implementation-readiness-plan.md`

Retention/delete runtime plan: `docs/future/passive-alpha-p0-05-retention-delete-semantics-runtime-plan.md`

Commit scope: docs-only owner-scoped enforcement plan before future runtime implementation. This block defines owner-scoped rules for files, jobs, results, reports, exports, SBOMs, Raw JSON, target histories, background job context, legacy data, and admin/operator boundaries. It does not change backend, frontend, runner, tests, fixtures, schemas, storage, reports, exports, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_OWNER_SCOPED_RESOURCES_PLAN_ACCEPTED
```

Inspectra should enforce owner-scoped access for sensitive resources after anonymous access is denied.

This enforcement is a safety boundary for open-source, local-first, and self-hosted-first deployments. It is not a SaaS, billing, subscription, quota, tenant billing, commercial customer, or enterprise multi-tenant model.

## Objective

Define how future runtime should enforce ownership for files, jobs, results, reports, exports, SBOMs, Raw JSON, target jobs, target histories, failed/sparse jobs, and background job context.

This block does not implement ownership. It prepares a future implementation where P0-03 rejects anonymous requests first, then P0-04 authorizes authenticated principals against owner metadata before returning or mutating sensitive resources.

## Enforcement Principles

- Deny anonymous first according to P0-03.
- Then check ownership for every sensitive resource.
- Backend authorization is authoritative.
- Frontend filters and route guards are UX only.
- List endpoints are filtered by owner.
- Direct ID access checks owner before returning content.
- File-based job creation requires ownership of the source file.
- Reports render only after job owner authorization.
- Markdown/HTML/XML/PDF exports render only after job owner authorization.
- SBOM exports render only after job owner authorization.
- Raw JSON follows job ownership.
- Target-based jobs have an owner even with `file_id: null`.
- Target authorization metadata is tied to the owner/job.
- Background jobs preserve owner context from queue creation through result write.
- Failed, sparse, malformed, queued, and running jobs are still owner-scoped.
- Redaction remains required after owner checks succeed.
- Storage paths and user-controlled filenames are not authorization.
- Owner metadata is not a billing, SaaS tenant, or commercial tenant boundary.

## Deployment Mode Behavior

### `trusted_local_no_auth`

Behavior:

- The default local operator owns all trusted local resources.
- Owner checks may resolve to that default local operator.
- This mode is only for localhost/dev/local trusted use.
- It must not be described as public, production, or internet-safe.
- Future runtime should warn or fail closed if exposed beyond local trusted interfaces.

### `self_hosted_single_admin`

Behavior:

- The authenticated admin owns all resources by default.
- Owner checks still exist, but they are simple because there is one owner.
- This is the first recommended runtime shape from P0-01.
- Admin still cannot bypass redaction, target policy, feature flags, or Active authorization gates.

### `private_team_lightweight_users`

Behavior:

- User A cannot see, create jobs for, export, delete, or view Raw JSON for user B resources.
- Lists are filtered by owner.
- Direct ID access checks owner.
- Admin read-all is a separate explicit product/security decision.

### `public_community_limited_instance`

Behavior:

- Strict owner isolation is required before real use.
- Short retention, strict limits, visible disclaimers, and abuse controls remain future requirements.
- Public Active/Nmap is out of scope.
- Admin/operator boundaries must be disclosed if admin read-all is later accepted.

## Resource Enforcement Matrix

| Resource or action | Owner source | Required check | Failure behavior | Notes |
| --- | --- | --- | --- | --- |
| List files | File metadata `owner_id` | Return only caller-owned files | Empty list or controlled denial | Do not leak other users' filenames, IDs, kinds, hashes, or sizes |
| Read file metadata | File metadata `owner_id` | Caller owns file or accepted admin boundary | Controlled `403` or generic `404` decision later | Check before returning filename, path-derived metadata, hash, kind, or size |
| Create file-based job | Source file owner and creator principal | Caller owns source file; job owner becomes caller/source owner | Controlled denial without revealing other file details | Applies to all `POST /audits/*/{file_id}` routes |
| List jobs | Job `owner_id` | Return only caller-owned jobs | Empty list or controlled denial | Summaries, errors, target displays, and deleted-source flags are sensitive |
| Read job result | Job `owner_id` | Caller owns job or accepted admin boundary | Controlled `403` or generic `404` decision later | Applies to completed, failed, queued, running, sparse, and malformed jobs |
| Render frontend report | Job `owner_id` through API data | Backend authorizes job before returning report data | UI shows controlled auth/permission state | Frontend guard is not sufficient |
| Export Markdown/HTML/XML/PDF | Job `owner_id` | Authorize job owner before rendering | Controlled denial before report generation | Avoid rendering content before auth succeeds |
| Export SBOM | Job `owner_id` | Authorize job owner before SBOM generation | Controlled denial before SBOM generation | Applies to CycloneDX and SPDX routes |
| View Raw JSON | Job/result `owner_id` | Authorize job owner before returning result JSON | Controlled denial before redacted payload return | Redaction still required after authorization |
| Delete file/job/result | File/job/result `owner_id` plus retention policy | Caller owns resource or accepted admin cleanup boundary | Controlled denial; no cross-user deletion | Runtime delete semantics are P0-05 |
| Create target baseline job | Creator principal and target authorization metadata | Caller is authenticated; owner stored on job | Controlled denial | Applies to web, domain, and subdomain target jobs |
| Create Active dry-run | Creator principal and Active request metadata | Caller authenticated; feature flag and request policy pass; owner stored | Controlled denial | Dry-run remains no-network |
| Create Active one-HEAD | Creator principal and Active request metadata | Caller authenticated; feature flag, target policy, authorization, and double confirmation pass; owner stored | Controlled denial | No Nmap, no target-policy relaxation |
| List/read target history | Target job `owner_id` | Return only caller-owned target jobs/history | Empty list or controlled denial | Target names, URLs, errors, and policy blocks are sensitive |
| Background job process | Queued job owner context | Process only accepted owned job; write result with same owner | Controlled failure tied to same job owner | Worker must not scan storage globally |
| Admin read-all if accepted | Explicit admin/operator boundary | Admin principal plus accepted read-all policy | Controlled denial if not accepted | In `self_hosted_single_admin`, admin is the sole owner |

## File-Based Jobs

Future runtime should enforce:

- a user can create a job only for their own source file;
- job owner is the creating principal and should match the source file owner in P0;
- result ownership is inherited from the job;
- report/export/SBOM/Raw JSON ownership is inherited from the job/result;
- cross-kind rejections still happen, but only after the caller is authorized to use the source file;
- queued, running, completed, failed, sparse, malformed, and legacy jobs all remain owner-scoped;
- deleted-source markers remain visible only to the job owner or accepted admin boundary.

This applies to:

- PDF/image/manifest jobs;
- archive/project archive jobs;
- passive config archive jobs;
- secrets review jobs;
- dependency/SBOM-capable jobs;
- any future file-based passive analyzer.

## Target-Based Jobs

Future runtime should enforce:

- target jobs have an owner even when `file_id: null`;
- target authorization metadata belongs to the owner/job;
- target histories are owner-scoped;
- job lists and summaries must not reveal another user's target strings;
- target errors and controlled failure states are owner-scoped;
- Active remains feature-flagged and separately authorized;
- `active_http_header_probe` remains double-confirmed and policy-gated;
- `active_network_dry_run` remains no-network;
- Nmap remains out of scope.

This applies to:

- `web_basic`;
- `domain_basic`;
- `subdomain_inventory_basic`;
- `active_network_dry_run`;
- `active_http_header_probe`;
- any future target-based job if separately accepted.

## Reports And Exports

Report and export rendering must authorize before reading or rendering stored job data.

Rules:

- frontend reports depend on authorized backend data;
- Markdown exports require job owner authorization;
- HTML exports require job owner authorization;
- XML exports require job owner authorization;
- PDF exports require job owner authorization;
- SBOM exports require job owner authorization;
- report filenames should not expose another user's sensitive filename or target before auth succeeds;
- rendering should not happen before auth succeeds;
- redaction still applies after auth succeeds.

If stored export artifacts are introduced later:

- store owner metadata;
- store source job ID;
- store format;
- store creation time;
- store retention/delete status;
- authorize artifact reads by owner;
- delete artifacts according to P0-05 retention/delete semantics.

Manual downloads remain outside app control. Deleting a job or export inside Inspectra does not delete copies already downloaded, emailed, shared, screenshotted, backed up, or stored in browser/download folders.

## Raw JSON

Raw JSON is sensitive even when redacted.

Rules:

- Raw JSON access requires job owner authorization.
- Redaction remains required after authorization.
- Legacy, sparse, malformed, failed, queued, and running payloads must not bypass owner checks.
- Raw JSON should not be exposed through public storage paths.
- Raw JSON access should disappear or become controlled if the job/result is deleted in future retention implementation.
- Raw JSON should inherit all target/file owner rules from the job.

## Background And Service Context

Background jobs must preserve owner context.

Future runtime should ensure:

- queued jobs include owner metadata;
- background services process only a specific accepted job;
- runner invocation receives only the job-specific source path or target metadata required by that job;
- result writes preserve the original job owner;
- controlled errors are written to the same job owner scope;
- background processes do not scan storage globally;
- background processes do not create user-visible jobs on their own;
- logs avoid cross-user filenames, targets, Raw JSON, secret-like values, and unredacted errors.

Service/background ownership should not create ownerless records. If a system owner concept is needed later, it should be explicit and separate from user-owned jobs.

## Admin And Operator Boundary

In `self_hosted_single_admin`:

- the admin is the sole owner;
- owner checks can pass for the admin's resources;
- redaction, target policy, feature flags, and Active confirmations still apply.

In `private_team_lightweight_users` and `public_community_limited_instance`:

- admin read-all is not automatically accepted;
- admin read-all must be a separate product/security decision;
- admin export or cleanup behavior must be explicit;
- admin access should be logged with redacted metadata if later implemented;
- admin cannot bypass target policy, redaction, feature flags, or no-read sensitive-file boundaries.

Admin/operator surfaces are privileged data access. They should not be confused with billing tenants, SaaS admin panels, or commercial enterprise RBAC.

## Legacy And Migration Behavior

P0-04 depends on P0-02 migration decisions.

Rules:

- trusted local legacy data maps to the default local operator for local/self-hosted single-admin use;
- public/community instances should start from clean storage or require explicit migration/claim;
- missing owner in non-local modes denies reads;
- legacy exports and Raw JSON follow the migrated job owner or are blocked;
- legacy failed, sparse, malformed, queued, and running jobs are not public just because their payloads are incomplete;
- migration backup/rollback artifacts remain sensitive and outside app cleanup unless separately handled.

If ownership cannot be established, fail closed.

## Failure Behavior

Unauthenticated requests are handled by P0-03.

Authenticated wrong-owner behavior:

- return controlled denial;
- avoid revealing whether the resource exists;
- avoid exposing filenames, target strings, summaries, status, errors, redaction notes, or export availability;
- choose `403` versus generic `404` in implementation planning;
- log only redacted, minimal operational context.

Missing-owner behavior:

- deny in non-local/auth-required modes unless the record is explicitly mapped or claimed;
- allow only accepted trusted-local default operator mapping in local mode;
- do not let missing owner fall back to public access.

## Runtime Implementation Candidates

These are docs-only candidates for future runtime implementation:

- central owner check helper;
- owner-filtered file listing helper;
- owner-filtered job listing helper;
- source-file ownership resolver for file-based job creation;
- job ownership resolver for job detail/result/report/export/SBOM/Raw JSON;
- target job owner metadata assignment;
- target-history ownership helper;
- export authorization helper;
- Raw JSON authorization path;
- background job owner propagation;
- admin-boundary helper if admin read-all is accepted;
- sensitive route tests matrix.

Do not implement these in this block.

## Minimum Future Tests

Future runtime implementation should test:

- user A cannot list user B files;
- user A cannot read user B file metadata;
- user A cannot delete user B file;
- user A cannot create a job for user B file;
- file-based jobs inherit owner;
- job results inherit job owner;
- user A cannot list user B jobs;
- user A cannot read user B job result;
- user A cannot export user B Markdown/HTML/XML/PDF report;
- user A cannot export user B SBOM;
- user A cannot view user B Raw JSON;
- target jobs are owner-scoped with `file_id: null`;
- target histories are owner-scoped;
- background job preserves owner from queue to result write;
- failed jobs are owner-scoped;
- sparse jobs are owner-scoped;
- malformed jobs are owner-scoped;
- queued and running jobs are owner-scoped;
- legacy mapped data is readable only by the default local/admin operator;
- missing-owner records deny non-local reads;
- admin read-all behavior is explicit and tested if accepted;
- wrong-owner errors do not reveal resource existence;
- redaction regressions still pass after owner checks.

## Open Questions

- Should wrong-owner access return `403` or generic `404`?
- Should admin read-all exist outside `self_hosted_single_admin`?
- Should exports remain on-demand only, or become stored owner-scoped artifacts?
- Should shareable report links stay disabled until a separate sharing model exists?
- How exactly should owner metadata propagate through the background task queue?
- How should the default local operator be represented in tests?
- How should legacy failed jobs without owner be mapped, quarantined, or blocked?
- Should target histories have a separate retention class from job results?
- Should an admin cleanup action be able to delete all users' export artifacts?

## Relationship To P0-05 And P0-06

The retention/delete runtime plan is now accepted:

```text
PASSIVE-ALPHA-P0-05-RETENTION-DELETE-SEMANTICS-RUNTIME-PLAN
```

P0-05 depends on owner-scoped enforcement.

Implications:

- delete source depends on file ownership;
- delete job/result depends on job ownership;
- delete all my data depends on owner metadata;
- target-history deletion is owner-scoped;
- export artifact cleanup is owner-scoped if stored artifacts exist;
- Raw JSON disappears or becomes inaccessible according to job/result deletion policy;
- admin cleanup must have explicit scope;
- demo reset must not infer demo resources from filenames alone.

The next recommended block is:

```text
PASSIVE-ALPHA-P0-06-DEPLOYMENT-HARDENING-CHECKLIST
```

Proceed to deployment hardening checklist planning after owner-scoped resources and retention/delete semantics are accepted.

## Out Of Scope

- Owner check implementation.
- Auth implementation.
- API guard implementation.
- Sessions or cookies.
- Login UI.
- `owner_id` implementation.
- Storage migrations.
- DB/schema changes.
- Cleanup/delete runtime.
- Report/export implementation.
- SBOM implementation changes.
- Raw JSON implementation changes.
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
- No report/export implementation.
- No SBOM implementation changes.
- No Raw JSON implementation changes.
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

- Owner-scoped principles are defined.
- Resource enforcement matrix is defined.
- File-based jobs are covered.
- Target-based jobs are covered.
- Reports, exports, SBOM, and Raw JSON are covered.
- Background context is covered.
- Admin/operator boundary is covered.
- Legacy behavior is covered.
- Failure behavior is defined.
- Minimum future tests are defined.
- Relationship to P0-05 is clear.
- No runtime or capability changes are made.

## Next Recommendation

```text
PASSIVE-ALPHA-P0-06-DEPLOYMENT-HARDENING-CHECKLIST
```

Proceed to deployment hardening checklist planning after retention and delete semantics are accepted.

## Validation Commands

Reference checks for this docs-only owner-scoped resources plan:

```text
git status --short
git status --branch --short
git log --oneline -12
git diff --check
git diff --cached --check
git status --short
```

No pytest or npm suite is required while this block remains docs-only.
