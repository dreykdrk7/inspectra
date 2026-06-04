# Passive Alpha P0 02 Owner Model And Storage Migration Plan

Status: `PASSIVE_ALPHA_OWNER_MODEL_STORAGE_MIGRATION_PLAN_ACCEPTED`.

Runtime implementation record: the first owner write-path slice is now accepted as `PASSIVE_ALPHA_RUNTIME_OWNER_METADATA_WRITE_PATH_ACCEPTED` in `docs/future/passive-alpha-runtime-04-owner-metadata-write-path.md`. Trusted-local legacy ownerless data mapping is now accepted as `PASSIVE_ALPHA_RUNTIME_LEGACY_LOCAL_DATA_MAPPING_ACCEPTED` in `docs/future/passive-alpha-runtime-05-legacy-local-data-mapping.md`.

Base auth-boundary runtime plan: `docs/future/passive-alpha-p0-01-auth-boundary-design-to-runtime-plan.md`

Base open-source/self-hosted framing: `docs/future/passive-alpha-p0-00-open-source-self-hosted-product-framing.md`

Base implementation readiness plan: `docs/future/passive-alpha-gap-fixes-08-implementation-readiness-plan.md`

Base retention cleanup reset design: `docs/future/passive-alpha-gap-fixes-04-retention-cleanup-reset-design.md`

Base auth and user-isolation design: `docs/future/passive-alpha-gap-fixes-03-auth-and-user-isolation-design.md`

Deny-anonymous API guards plan: `docs/future/passive-alpha-p0-03-deny-anonymous-reads-api-guards.md`

Owner-scoped resources plan: `docs/future/passive-alpha-p0-04-owner-scoped-jobs-results-exports.md`

Commit scope: docs-only owner model and storage migration plan before future runtime work. This block defines ownership principles, P0 owner concepts, legacy local data migration options, storage implications, API guard implications, retention/delete implications, and future test requirements. It does not change backend, frontend, runner, tests, fixtures, schemas, storage, reports, exports, feature flags, target policy, tags, releases, or runtime behavior.

## Final Decision

```text
PASSIVE_ALPHA_OWNER_MODEL_STORAGE_MIGRATION_PLAN_ACCEPTED
```

Inspectra should introduce an owner model before non-local, self-hosted exposed, private-team, or optional public/community use.

The owner model is a safety boundary for open-source, local-first, and self-hosted-first deployments. It is not a billing model, SaaS tenant model, subscription plan model, quota monetization model, or enterprise multi-tenant design.

## Objective

Define the ownership and migration shape required before implementing `owner_id`, storage schema changes, API guards, delete semantics, cleanup runtime, or public/community runtime claims.

This block does not implement fields, migrations, API authorization, auth runtime, UI, cleanup, reports, exports, or storage changes. It prepares the next P0 runtime blocks by deciding which resources need ownership, how trusted local legacy data should be mapped, and how missing owner metadata should be treated.

## Owner Principles

- Every sensitive resource has an owner before non-local or multi-user use.
- Access is denied when owner metadata is missing unless the resource is explicitly mapped to the trusted default local operator during an accepted migration.
- Backend authorization is authoritative.
- Frontend ownership checks are UX only.
- Ownership applies to file-based jobs and target-based jobs.
- Target-based jobs still need an owner when `file_id: null`.
- Owner metadata is a security and accountability boundary, not a billing, tenant, or commercial customer boundary.
- `self_hosted_single_admin` owns all resources by default.
- `trusted_local_no_auth` maps resources to a default local operator for localhost/dev compatibility only.
- `private_team_lightweight_users` and `public_community_limited_instance` require per-user ownership before real use.
- Reports, exports, SBOMs, and Raw JSON inherit ownership from the job/result they render.
- Redaction remains required after ownership checks succeed.
- Storage paths can help organize data, but path layout alone is not authorization.

## Owner Entities And Resources

### Uploaded Files

Uploaded source files need an owner because originals can contain secrets, source code, customer data, metadata, archives, credentials, or internal paths.

Ownership applies to:

- stored source bytes;
- file metadata;
- file list entries;
- file detail views;
- file delete/tombstone operations;
- archive-derived manifest and candidate-file metadata.

### Audit Jobs

Audit jobs need an owner derived from the creating principal.

File-based jobs:

- require ownership of the source file at creation time;
- inherit the creating principal as `created_by`;
- carry the owner into queue, runner invocation, storage, results, reports, and exports.

Target-based jobs:

- require an owner even when `file_id: null`;
- store target authorization metadata tied to the user/job;
- cover web, DNS, subdomain, dry-run Active, and one-HEAD limited live jobs.

### Job Results And Stored JSON

Stored job results inherit job ownership.

This includes:

- analyzer JSON;
- summaries;
- findings;
- controlled errors;
- redaction notes;
- limits/truncation metadata;
- sparse, malformed, failed, queued, and running job payloads.

### Reports

Reports inherit job ownership.

Report rendering must authorize access to the job before reading stored JSON or rendering:

- Markdown;
- HTML;
- XML;
- PDF;
- frontend report views;
- report helper summaries.

### Exports And Artifacts

Exports inherit job ownership.

If exports remain generated on demand, authorization happens at render time. If future exports become stored artifacts, they need artifact metadata:

- owner;
- source job;
- format;
- created time;
- retention/expiry state;
- delete/tombstone state.

### SBOM Exports

SBOM exports inherit ownership from the source job/result.

SBOMs are sensitive because package names, versions, repository hints, paths, and project structure can identify private software even when no secrets appear.

### Raw JSON

Raw JSON inherits job/result ownership and remains sensitive.

Ownership does not replace redaction. Raw JSON must remain redacted because legacy, malformed, sparse, or unexpected payloads can include sensitive metadata or secret-like values.

### Delete And Reset Operations

Delete and reset actions require ownership or an explicit admin/operator policy.

Ownership applies to:

- deleting a source upload;
- deleting a job/result;
- deleting stored export artifacts if they exist later;
- deleting target histories;
- deleting all owned data;
- demo reset boundaries.

### Authorized Baseline Target Jobs

Baseline target jobs need owners even without files.

This applies to:

- `web_basic`;
- `domain_basic`;
- `subdomain_inventory_basic`;
- any future target-based baseline job.

Authorization confirmation belongs to the user and job. It must not be transferable between users.

### Internal Active Jobs

Internal Active jobs need owners and retain their separate feature gates.

This applies to:

- `active_network_dry_run`;
- `active_http_header_probe`;
- any future Active block if separately accepted.

Active remains feature-flagged, explicitly authorized, double-confirmed where required, and bounded by target policy. Nmap is not designed here.

### Target Histories

Target histories are sensitive and need owners.

They can reveal domains, URLs, target names, errors, response metadata, policy blocks, authorization decisions, and timing. They must not be shared across users by default.

### Logs And Audit Entries

Logs and audit entries are primarily operator/system-scoped but should carry actor metadata where practical.

They should avoid raw source filenames, target secrets, sensitive errors, Raw JSON fragments, secret-like values, and cross-user details. Admin/operator access to logs is privileged and must be explicit.

### Demo And Synthetic Data

Demo/synthetic data should have an owner marker, demo marker, or fixture marker before any reset tooling can safely delete it.

Never infer demo data only from filenames in non-local modes.

## Proposed Model Fields And Concepts

These are docs-only concepts. They do not change the runtime in this block.

### P0 Minimum Concepts

`owner_id`:

- Required concept for uploaded files, jobs, results, target histories, and stored artifacts if artifacts exist.
- Opaque local identifier for a principal.
- In `self_hosted_single_admin`, all resources can map to the admin owner.
- In `trusted_local_no_auth`, legacy resources can map to the default local operator.

`created_by`:

- Records the principal that initiated an upload, job, export, delete, reset, or target authorization.
- Often equal to `owner_id` in P0 single-admin mode.
- Useful for audit entries and future admin-assisted actions.

`owner_kind` or equivalent:

- Optional but recommended for migration clarity.
- Can distinguish `local_operator`, `user`, `system`, and future concepts without creating a SaaS tenant model.
- Keeps default local operator compatibility explicit.

`legacy_owner_migration_status`:

- Tracks whether an existing local record was mapped, quarantined, blocked, or left unmigrated.
- Useful during migration and rollback planning.

`target_authorization_metadata`:

- Required for target-based jobs.
- Should bind authorization confirmation, scope, mode, and timestamp-like metadata to the creating owner/job.
- Does not relax target policy or Active gates.

`export_artifact_metadata`:

- Required only if exports become stored artifacts.
- Should record owner, job, format, created time, expiry/delete state, and redaction caveats.

### Future Or Deferred Concepts

`workspace_id`:

- Deferred for P0.
- May be useful for `private_team_lightweight_users`.
- Should not be introduced as a commercial tenant or billing boundary.

`visibility`:

- Deferred unless shareable reports or admin read-all are explicitly designed.
- Default should be private/owner-only.

`deleted_at`:

- Deferred to delete/retention runtime planning.
- Useful for tombstones and preserving minimal historical state.

`retention_policy`:

- Deferred to the retention/delete runtime block.
- May be per deployment, owner, resource class, or job type later.

`system_owner`:

- Deferred unless background/system artifacts need a formal owner.
- Background jobs should normally preserve the user job owner rather than becoming ownerless system records.

## P0 Minimum Owner Model

Recommended P0 shape:

- one default local/admin principal;
- uploaded files have an owner;
- file metadata follows uploaded file owner;
- jobs have an owner;
- file-based jobs require ownership of their source file;
- results inherit job owner;
- report rendering authorizes against job owner;
- Markdown/HTML/XML/PDF exports authorize against job owner;
- SBOM exports authorize against job owner;
- Raw JSON follows job owner;
- target jobs with `file_id: null` have an owner;
- target authorization metadata belongs to the owner/job;
- delete/reset remains planned and owner-scoped, but runtime delete semantics are not implemented here;
- no full workspace/team model in P0;
- no tenant billing model;
- no enterprise RBAC.

In `self_hosted_single_admin`, the admin principal owns everything by default. This is the first runtime shape recommended by P0-01.

In `trusted_local_no_auth`, the default local operator is a compatibility bridge for localhost/dev/local trusted use only. It must not be treated as public or internet-safe auth.

## Legacy And Local Data Migration Strategy

Existing trusted local data may not have owner metadata. Future migration must treat that explicitly.

### Option A: Map Existing Trusted Local Data To Default Local Operator

Behavior:

- Create or define a default local/admin principal.
- Assign existing uploaded files, jobs, results, exports, Raw JSON, and target histories to that principal.
- Mark records as migrated from trusted local data.

Pros:

- Best compatibility for current local alpha users.
- Minimal disruption for self-hosted single-admin installs.
- Aligns with P0-01 `self_hosted_single_admin` / `single_user_auth`.

Cons:

- Assumes legacy data belongs to the operator performing the migration.
- Not appropriate for arbitrary public/community existing storage.

Recommendation:

- Use this option for trusted local and self-hosted single-admin migration.

### Option B: Quarantine Legacy Data Until Admin Claims It

Behavior:

- Existing records become unavailable through normal reads.
- Admin reviews and claims records into an owner.
- Claimed records become owner-scoped.

Pros:

- Safer when provenance is unclear.
- Useful if a deployment was accidentally exposed.

Cons:

- More operational complexity.
- Requires claim UI or operator tooling not yet designed.

Recommendation:

- Keep as fallback for uncertain storage or future private-team/public-community migration.

### Option C: Block Legacy Reads Until Migrated

Behavior:

- Legacy records without owner are not readable.
- Migration is required before access.

Pros:

- Strongest fail-closed posture.

Cons:

- Breaks trusted local compatibility if used by default.
- Requires clear migration tooling before rollout.

Recommendation:

- Use for non-local, public/community, or uncertain deployments when records cannot be safely mapped.

### Recommended Strategy

For self-hosted-first P0:

- map existing trusted local data to the default local/admin operator;
- record migration status where practical;
- preserve trusted local compatibility;
- deny missing-owner records after migration unless explicitly mapped or quarantined;
- document backup and rollback caveats before any runtime migration.

For public/community instances:

- start from clean storage whenever possible;
- do not import arbitrary legacy local data by default;
- require explicit migration/claiming if legacy data must be brought in;
- keep public/community real uploads blocked until auth, ownership, limits, retention, disclaimers, and security review are implemented.

Rollback and backup caveats:

- future migration should recommend a backup before changing records;
- rollback should not expose ownerless data to anonymous reads;
- backup files remain sensitive and outside app cleanup unless separately handled;
- no backup, rollback, or migration command is implemented in this docs-only block.

## Storage Implications

### Local File Paths

Local storage paths are sensitive and not an authorization boundary by themselves.

Future storage may organize data by owner or opaque ID, but every API read/write/delete/export must authorize against metadata, not simply trust directory layout.

### Owner-Scoped Metadata

File records, job records, result records, target histories, and stored export artifacts should carry owner metadata or inherit it from an authorized parent.

Metadata must avoid exposing other users' filenames, target names, summaries, errors, redaction notes, or paths in list endpoints.

### Generated Exports

Generated exports should prefer on-demand rendering behind authorization. Stored export artifacts, if introduced later, need owner metadata and retention/delete semantics.

### SBOMs

SBOMs should be rendered only after authorizing the source job/result. Stored SBOM artifacts require owner metadata.

### Target Histories

Target histories are owner-scoped even when there is no uploaded file. Target names, URLs, domains, errors, policy decisions, and response metadata must not leak across owners.

### Raw JSON

Raw JSON is owner-scoped and redaction-first. It should never be exposed through storage paths or unauthenticated URLs.

### Demo Fixtures

Synthetic fixtures can remain in source/test directories, but demo-generated uploads/jobs/results need an explicit local/demo/default owner before reset tooling can safely act on them.

### Untrusted Names

Filenames, archive paths, target strings, export names, and user-visible labels are untrusted and potentially sensitive. Future owner checks must not rely on them for identity, ownership, or demo detection.

## Future Migration Phases

Future runtime work should be split into small blocks:

1. Inventory current storage, file records, job records, result JSON, export rendering, SBOM rendering, Raw JSON views, and target-history records.
2. Define the default local/admin principal for trusted local and self-hosted single-admin mode.
3. Add owner metadata fields to new records without enforcing deny missing-owner yet.
4. Add write-path owner assignment for uploads, jobs, target jobs, and generated artifacts if stored.
5. Add read-path compatibility for legacy records.
6. Map trusted local legacy records to default local operator.
7. Mark migration status for legacy records where practical.
8. Add tests for new owner assignment, legacy mapping, and missing-owner behavior.
9. Add backend API guards for anonymous reads and owner checks.
10. Enforce deny missing owner after migration and tests are accepted.

Do not combine all of this into one broad runtime change.

## API Guard Implications For P0-03

The next recommended block is:

```text
PASSIVE-ALPHA-P0-03-DENY-ANONYMOUS-READS-API-GUARDS
```

P0-03 will need the owner concepts defined here.

Implications:

- anonymous requests should be denied before owner lookup for sensitive endpoints;
- authenticated principals should read only their own resources by default;
- file-based job creation should require ownership of the source file;
- target-based job creation should require an owner and target authorization metadata;
- job list endpoints should filter by owner;
- job detail endpoints should authorize by job owner;
- report/export/SBOM/Raw JSON endpoints should authorize by job owner;
- delete/reset endpoints should remain blocked or owner/admin-scoped according to accepted retention policy;
- admin read-all is not automatically accepted outside `self_hosted_single_admin`;
- frontend guards remain UX only.

## Retention And Delete Implications

The retention/delete line depends on owner metadata.

Implications:

- delete source upload must be owner-scoped;
- delete job/result must be owner-scoped;
- delete all my data depends on owner metadata;
- target-history deletion depends on owner metadata;
- generated export artifact deletion depends on owner metadata if artifacts are stored;
- admin cleanup must have explicit scope and logging;
- demo reset must not infer demo resources from filenames alone;
- logs/audit entries should carry actor metadata where practical and remain redacted;
- manual downloads, backups, screenshots, and external copies remain outside app cleanup control.

## Active And Baseline Implications

Target-based flows need ownership even when no file exists.

Rules:

- `web_basic`, `domain_basic`, and `subdomain_inventory_basic` jobs need owner metadata.
- `active_network_dry_run` jobs need owner metadata.
- `active_http_header_probe` jobs need owner metadata.
- Target authorization belongs to the creating owner/job.
- Dry-run remains independent and no-network.
- Limited live remains feature-flagged, authorized, and double-confirmed.
- Nmap is not designed or approved here.
- No target-policy relaxation is approved here.

## Minimum Future Tests

Future runtime implementation should test:

- new uploads get an owner;
- new file metadata is readable only by the owner;
- new file-based jobs inherit or assign the creating owner;
- jobs cannot be created for another user's file;
- job results inherit job owner;
- report rendering requires job owner;
- Markdown/HTML/XML/PDF exports require job owner;
- SBOM exports require job owner;
- Raw JSON requires job owner;
- target job with `file_id: null` gets owner metadata;
- target authorization metadata is tied to the owner/job;
- legacy data maps to default local operator or is blocked according to policy;
- missing owner denies non-local reads;
- user A cannot read user B files, jobs, results, exports, Raw JSON, or target histories in future multi-user mode;
- admin behavior is explicit and tested;
- background jobs preserve owner context;
- failed, sparse, malformed, queued, and running jobs do not leak across owners;
- delete/reset tests use owner metadata and do not infer demo state from filename alone;
- redaction tests still pass after ownership checks.

## Open Questions

- Should the first runtime use simple `owner_id`, or `owner_kind` plus `owner_id`?
- Should `workspace_id` be deferred completely until private-team runtime?
- How should the default local operator be created?
- Should default local operator creation be automatic, setup-page based, CLI based, or config based?
- What should happen to legacy exports if stored artifacts already exist?
- Should migration be automatic for local/self-hosted single-admin mode or manually confirmed?
- Should clean storage be mandatory for any public/community instance?
- Should admin read-all exist in private-team mode?
- How should system/background ownership be represented without creating ownerless records?
- Should shareable report links remain disabled until owner-scoped sharing is designed?

## Out Of Scope

- `owner_id` implementation.
- Storage migrations.
- Schema changes.
- API guards.
- Auth runtime.
- Sessions or cookies.
- Login UI.
- Report/export implementation.
- SBOM implementation changes.
- Raw JSON implementation changes.
- Delete/reset runtime.
- Cleanup runtime.
- UI changes.
- SaaS tenant model.
- Billing.
- Subscription plans.
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
- No UI implementation.
- No report/export implementation.
- No auth implementation.
- No session or cookie implementation.
- No cleanup implementation.
- No DB migration.
- No storage schema change.
- No `owner_id` implementation.
- No API guard implementation.
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

- Owner principles are defined.
- Owner resources are defined.
- P0 minimum owner model is defined.
- Legacy migration strategy is defined.
- Storage implications are defined.
- API guard implications for P0-03 are defined.
- Retention/delete implications are defined.
- Active/baseline ownership implications are defined.
- Minimum future tests are defined.
- No runtime or capability changes are made.

## Next Recommendation

```text
PASSIVE-ALPHA-P0-05-RETENTION-DELETE-SEMANTICS-RUNTIME-PLAN
```

The deny-anonymous API guards plan and owner-scoped resources plan are now accepted. Proceed to retention and delete semantics planning after anonymous requests are denied and sensitive resources are owner-scoped.

## Validation Commands

Reference checks for this docs-only owner model and migration plan:

```text
git status --short
git status --branch --short
git log --oneline -12
git diff --check
git diff --cached --check
git status --short
```

No pytest or npm suite is required while this block remains docs-only.
