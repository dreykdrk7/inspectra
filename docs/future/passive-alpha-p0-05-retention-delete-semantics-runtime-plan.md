# Passive Alpha P0 05 Retention Delete Semantics Runtime Plan

Status: `PASSIVE_ALPHA_RETENTION_DELETE_RUNTIME_PLAN_ACCEPTED`.

Base owner-scoped resources plan: `docs/future/passive-alpha-p0-04-owner-scoped-jobs-results-exports.md`

Base deny-anonymous API guards plan: `docs/future/passive-alpha-p0-03-deny-anonymous-reads-api-guards.md`

Base owner model and storage migration plan: `docs/future/passive-alpha-p0-02-owner-model-and-storage-migration-plan.md`

Base retention cleanup reset design: `docs/future/passive-alpha-gap-fixes-04-retention-cleanup-reset-design.md`

Base implementation readiness plan: `docs/future/passive-alpha-gap-fixes-08-implementation-readiness-plan.md`

Deployment hardening checklist: `docs/future/passive-alpha-p0-06-deployment-hardening-checklist.md`

Commit scope: docs-only retention and delete runtime plan for future Passive Alpha P0 work. This block defines future semantics and sequencing for owner-scoped delete and retention behavior. It does not change backend, frontend, runner, tests, fixtures, schemas, storage, reports, exports, feature flags, target policy, tags, releases, or runtime behavior.

Runtime implementation record: `docs/future/passive-alpha-runtime-07-delete-source-and-job-results.md` accepts and implements the minimal P0 slice for owner-scoped source upload deletion plus completed/failed job/result deletion. Broader delete-all-owned-data, scheduler cleanup, admin cleanup, demo reset, stored artifact cleanup, and queued/running cancellation remain future work.

## Final Decision

```text
PASSIVE_ALPHA_RETENTION_DELETE_RUNTIME_PLAN_ACCEPTED
```

Inspectra should implement future retention and deletion semantics only after anonymous access is denied and sensitive resources are owner-scoped.

The recommended P0 product default is:

- deleting a source upload removes stored source bytes;
- historical job results remain available to the owner as redacted derived records with a `source_deleted` marker;
- deleting a job/result removes the stored result, report/export availability, SBOM availability when applicable, and Raw JSON access;
- a future "delete all owned data" operation may cascade across owned uploads, jobs, results, exports, Raw JSON, and target histories;
- stored exports should be avoided where possible in favor of on-demand rendering behind authorization.

This is not a secure erase claim. Manual downloads, browser caches, screenshots, external copies, host backups, snapshots, object-store versions, and target-side logs remain outside app-side deletion control.

## Objective

Define the future runtime semantics, state names, delete operations, cleanup boundaries, failure behavior, and minimum tests for Passive Alpha retention and deletion.

This block does not implement:

- delete endpoints beyond current behavior;
- job/result deletion;
- "delete all owned data";
- scheduled cleanup;
- demo reset;
- admin cleanup;
- auth checks;
- owner checks;
- migrations;
- storage layout changes;
- UI controls.

It gives the next runtime blocks a concrete policy to implement in small, testable steps.

## Retention And Delete Principles

- Owner-scoped deletion is required for every user-controlled delete operation.
- Deny anonymous first; then check owner/admin scope before deletion or cleanup.
- Deletion must be explicit and understandable before the user acts.
- Source uploads have the highest sensitivity because originals can contain secrets, code, customer data, archives, metadata, credentials, and internal paths.
- Derived results are sensitive because they can contain filenames, paths, target names, summaries, controlled errors, redaction notes, and legacy/malformed fields.
- Exports, SBOMs, and Raw JSON are sensitive even after redaction.
- Manual downloads, browser downloads, screenshots, email attachments, copied files, shared reports, backups, snapshots, and target-side infrastructure logs are outside app control.
- Inspectra should not make a secure deletion guarantee.
- Logs and audit entries should be redacted and minimal.
- Trusted local/manual cleanup compatibility remains acceptable for localhost/dev/local trusted use.
- Public/community use requires short retention, strict limits, and clear storage/deletion caveats before real use.
- Cleanup code, when later implemented, should delete known app-owned bytes/artifacts by metadata rather than inspect no-read sensitive files.
- No delete or cleanup operation should relax or override target policy, Active gates, redaction, auth, owner checks, archive boundaries, or no-read sensitive-file rules.

## Resource Policy Matrix

| Resource class | Owner | Sensitivity | Trusted local default | Future self-hosted single-admin | Public/community behavior | Delete semantics | Caveats |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Source uploads | File owner or default local operator | Highest | Kept until manual delete/current upload delete | Owner/admin can delete source bytes | Short retention required | Remove stored source bytes; mark related jobs with source-deleted state | Does not remove downloaded copies or backups |
| File metadata | File owner or default local operator | High | Currently removed with current source delete | Prefer minimal tombstone only if needed | Minimize retained metadata | Remove or tombstone with minimal owner-scoped state | Filenames and hashes can be sensitive |
| Audit jobs | Job owner | High | Kept under `data/results/jobs` | Owner/admin can delete job/result later | Short retention required | Job delete removes result and report availability; optional minimal tombstone | Queued/running deletion needs separate cancellation/deferred policy |
| Job results/stored JSON | Job owner | High | Kept until manual cleanup | Owner/admin delete removes result JSON | Short retention required | Delete result payload and Raw JSON access | Redacted JSON remains sensitive |
| Raw JSON | Job/result owner | High | Derived from stored job result | Follows job/result retention | Short retention required | No separate public artifact; inaccessible after job/result deletion | Redaction still required before deletion |
| Markdown/HTML/XML/PDF exports | Job owner | High | Rendered on demand from job JSON | Prefer on-demand rendering; stored artifacts need owner/TTL | Short TTL if stored | Job/result delete removes availability; stored artifacts deleted by TTL/delete | Manual downloads outside app control |
| SBOM exports | Job owner | Medium to high | Rendered on demand from supported job JSON | Prefer on-demand rendering; stored artifacts need owner/TTL | Short TTL if stored | Job/result delete removes availability; stored artifacts deleted by TTL/delete | Package names and paths can expose private structure |
| Target histories | Target job owner | High | Kept as target job results | Owner/admin delete by job/history | Short retention required | Delete app-side target input/result/error history | DNS/HTTP/target logs outside Inspectra remain outside control |
| Logs/audit entries | Operator/system with actor metadata where practical | Medium to high | Operator-managed local logs | Short redacted retention | Short redacted retention required | Rotate/expire; keep minimal redacted operational entries | Logs must not become a secondary secret store |
| Temp/cache | Owning job or system cleanup scope | Same as parent resource | Short-lived where practical | Short TTL; cleanup by job/system metadata | Short TTL required | Delete after job completion/failure or expiry | Avoid reading sensitive temp content for classification |
| Demo/synthetic data | Demo owner/default local operator plus demo marker | Low by intent, but still controlled | Local demo reset may remove marked demo data | Reset only marked demo data | Must not delete real user data | Delete only demo-marked uploads/jobs/results/artifacts | Do not infer demo state from filename alone |

## P0 Product Decisions

### Source Upload Delete

P0 should preserve the current product posture:

- delete source upload removes stored source bytes;
- file metadata can be removed or replaced by a minimal tombstone if future owner/runtime needs one;
- related historical job results stay available to the owner as redacted derived results;
- related jobs show `source_deleted` / `source_file_deleted_at` style state;
- no re-run from the deleted source is possible.

Rationale:

- this matches the current trusted-local behavior closely;
- it minimizes source-byte retention while preserving report history;
- it avoids surprising users by deleting historical results when they only asked to delete the upload.

### Source Delete Cascade

Default source delete should not cascade to job/result deletion in P0.

Cascade deletion remains valid for a separate explicit operation:

- "delete all owned data";
- an optional advanced "delete source and derived results";
- admin cleanup by retention policy.

### Job/Result Delete

Job/result deletion should remove:

- stored result JSON;
- frontend report data access;
- Markdown/HTML/XML/PDF export availability;
- SBOM export availability when applicable;
- Raw JSON access;
- stored export artifacts if those are introduced.

It may leave a minimal tombstone if needed for idempotency or auditability.

### Delete All Owned Data

P0 may include "delete all owned data" only after owner checks and deny-anonymous guards exist.

If accepted, it should cascade across:

- owned source uploads;
- owned file metadata/tombstones according to policy;
- owned jobs;
- owned job results;
- owned stored exports/SBOM artifacts;
- owned Raw JSON access;
- owned target histories;
- owned demo data.

It must not delete other owners' data, system logs outside policy, backups, snapshots, browser downloads, or external report copies.

### Stored Exports

Prefer on-demand export rendering in P0.

If stored export artifacts are later introduced, they must have:

- owner;
- source job ID;
- format;
- creation time;
- retention expiry;
- deletion state;
- authorization before read.

## Delete Operations

### Delete Source Upload

Required checks:

- deny anonymous first;
- caller owns the file or an accepted admin cleanup boundary applies;
- source record exists and is not already deleted.

Affected resources:

- stored source bytes;
- file metadata or file tombstone;
- related job source-deleted markers.

What remains:

- redacted historical job results by default;
- reports/exports derived from remaining job results;
- minimal deleted-source marker visible only to authorized owner/admin;
- manual downloads and backups outside app control.

Expected response:

- controlled success for first delete;
- idempotent controlled response for repeated delete if tombstones are retained, or generic not-found if no tombstone is retained;
- wrong owner should not learn whether the file exists.

Future tests:

- owner can delete own source;
- wrong owner cannot delete source;
- anonymous cannot delete source;
- source bytes are removed;
- related jobs show source-deleted state only to authorized owner/admin;
- historical result behavior matches the accepted default.

### Delete Job Or Result

Required checks:

- deny anonymous first;
- caller owns the job/result or an accepted admin cleanup boundary applies;
- job is in a deletable state.

Affected resources:

- stored job result JSON;
- frontend report data;
- Raw JSON access;
- Markdown/HTML/XML/PDF export availability;
- SBOM export availability if compatible;
- stored export/SBOM artifacts if those exist later.

What remains:

- optional minimal tombstone with `result_deleted` / `deleted_at`;
- redacted audit log entry if future audit logging exists.

Expected response:

- controlled success;
- repeated delete should be idempotent if tombstone exists;
- queued/running jobs should be denied until cancellation exists or marked deletion-requested with no result exposure after completion.

Future tests:

- owner can delete own completed result;
- wrong owner cannot delete job/result;
- Raw JSON becomes inaccessible;
- report/export/SBOM endpoints become controlled unavailable responses;
- sparse/malformed/failed jobs can be deleted without exceptions;
- queued/running delete behavior matches the accepted policy.

### Delete Export Artifact

Required checks:

- deny anonymous first;
- caller owns the source job/artifact or accepted admin cleanup boundary applies;
- artifact exists if stored artifacts are introduced.

Affected resources:

- stored Markdown/HTML/XML/PDF/SBOM artifact only.

What remains:

- underlying job/result unless separately deleted;
- manual downloads outside app control.

Expected response:

- controlled success or no-op if exports are on-demand only;
- wrong owner should not learn artifact existence.

Future tests:

- stored artifact deletion is owner-scoped;
- deleting artifact does not delete job/result unless explicitly requested;
- job/result delete also removes stored artifacts if they exist.

### Delete All Owned Data

Required checks:

- deny anonymous first;
- authenticated owner;
- explicit confirmation;
- admin boundary only if executing for another owner is separately accepted.

Affected resources:

- all owned source uploads;
- all owned jobs/results;
- all owned Raw JSON access;
- all owned stored export/SBOM artifacts;
- all owned target histories;
- owned demo data.

What remains:

- minimal redacted audit/tombstone entries if policy accepts them;
- system logs according to shorter redacted retention;
- external/manual copies outside app control.

Expected response:

- summary counts by resource class;
- controlled partial-failure report if some resources could not be removed;
- retry-safe behavior.

Future tests:

- owner deletion removes only owned resources;
- another user's resources remain inaccessible and untouched;
- missing-owner records deny in non-local modes;
- partial deletion returns controlled errors and can be retried.

### Delete Target History

Required checks:

- deny anonymous first;
- caller owns the target job/history;
- target job status is compatible with deletion policy.

Affected resources:

- app-side target string/display;
- target result JSON;
- target errors;
- target Raw JSON access;
- target report/export availability.

What remains:

- external DNS/HTTP logs, resolver logs, target server logs, proxies, and infrastructure records outside Inspectra.

Expected response:

- controlled owner-scoped success;
- wrong owner should not learn target existence.

Future tests:

- owner can delete own target history;
- wrong owner cannot;
- target reports/Raw JSON disappear after job/result deletion;
- Active dry-run remains independent and reports `network_requests_sent: 0`;
- Active one-HEAD remains internal/limited and policy-gated.

### Delete Raw JSON

Raw JSON should not be a separate public artifact.

Required checks:

- deny anonymous first;
- caller owns job/result;
- delete job/result to remove Raw JSON access.

Affected resources:

- stored job result payload that powers Raw JSON.

What remains:

- optional result tombstone;
- manual copies outside app control.

Future tests:

- deleting job/result removes Raw JSON access;
- Raw JSON is still redacted before deletion;
- legacy payloads do not leak during delete/error responses.

### Admin Cleanup

Required checks:

- explicit admin/operator principal;
- accepted admin cleanup policy;
- redacted logging;
- scope and retention window chosen before execution.

Affected resources:

- expired uploads/results/artifacts/histories according to retention policy;
- demo data only when marked;
- logs only through log retention/rotation policy.

What remains:

- minimal redacted operational outcomes;
- external/manual/backed-up copies outside app control.

Expected response:

- counts by resource class;
- controlled partial failures;
- no sensitive filenames, targets, Raw JSON, or secret-like values in logs.

Future tests:

- admin cleanup is explicit;
- admin cleanup does not override redaction or target policy;
- private/community admin cleanup is scoped;
- cleanup logs avoid sensitive fields.

### Demo Reset

Required checks:

- trusted local operator or accepted admin/demo operator;
- demo/synthetic marker before non-local reset;
- explicit reset scope.

Affected resources:

- demo-marked uploads;
- demo-marked jobs/results;
- demo-marked exports/artifacts;
- demo temp/cache.

What remains:

- real user data;
- unmarked data;
- system logs according to retention policy.

Expected response:

- controlled summary of demo resources removed;
- refusal if demo marker is absent in non-local modes.

Future tests:

- demo reset removes only demo-marked resources;
- filename-only inference is not used;
- public/community reset cannot delete real user data.

## Deletion States

Future runtime may use these state concepts. They are docs-only in this block.

`deleted_at`:

- timestamp-like value for a deleted resource or tombstone;
- should be owner-scoped and minimal.

`source_deleted`:

- boolean or derived state showing source bytes were removed;
- current runtime has `source_file_deleted_at`, which is compatible with this concept.

`result_deleted`:

- state showing job/result JSON was removed or tombstoned;
- report/export/Raw JSON should become inaccessible.

`tombstone`:

- minimal record used for idempotency, auditability, or user clarity;
- should not retain sensitive filenames, target strings, errors, Raw JSON fragments, hashes, or secret-like values unless explicitly accepted.

`cleanup_status`:

- controlled cleanup outcome such as `pending`, `completed`, `partial`, or `failed`;
- logs should remain redacted.

`retention_expires_at`:

- expiry for uploads, results, target histories, or logs according to deployment policy.

`export_expires_at`:

- expiry for stored report/SBOM artifacts if artifacts are introduced.

## Retention Windows And Scheduled Cleanup

### Trusted Local

Default:

- manual cleanup first;
- current upload delete remains useful;
- no scheduler requirement;
- explicit local storage caveat in docs/UI.

Qualitative retention:

- local operator controls `data/`;
- source uploads/results remain until the operator deletes them or future cleanup exists;
- temp/cache should be short-lived where practical.

### Self-Hosted Single-Admin

Default:

- optional configurable retention after auth/ownership exist;
- source uploads should have a shorter window than redacted derived results when possible;
- logs should have shorter redacted retention than job results;
- export artifacts should be on-demand or short TTL if stored.

Qualitative retention:

- uploads: short to moderate configurable window;
- results/Raw JSON: moderate configurable window;
- target histories: moderate or shorter configurable window;
- logs: short redacted window;
- temp/cache: shortest practical TTL.

### Public/Community

Default:

- short retention required before real use;
- strict upload/result limits;
- explicit delete controls;
- no anonymous sensitive reads;
- no public Active/Nmap behavior.

Qualitative retention:

- uploads: short;
- results/Raw JSON: short;
- exports: on-demand or very short TTL if stored;
- target histories: short;
- logs: short and redacted;
- temp/cache: shortest practical TTL.

No exact mandatory values are chosen in this docs-only block. Exact windows should be set in a future deployment hardening or runtime configuration block.

## Export And SBOM Cleanup

Rules:

- prefer on-demand rendering from authorized job results;
- authorize before rendering;
- if stored artifacts are introduced, store owner, job ID, format, created time, and expiry;
- deleting job/result removes stored export/SBOM artifacts if they exist;
- export TTL cleanup should be owner-aware and redacted in logs;
- manual downloads are outside app control;
- exports remain sensitive after redaction.

Future tests:

- exports require job owner authorization;
- stored artifacts, if present, require artifact owner authorization;
- deleting job/result removes export/SBOM availability;
- manual download caveat appears in docs/UI copy.

## Raw JSON Cleanup

Rules:

- Raw JSON follows job result retention;
- Raw JSON is not a separate public artifact;
- Raw JSON becomes inaccessible after job/result deletion;
- Raw JSON redaction remains required before deletion;
- sparse, malformed, failed, queued, running, and legacy jobs cannot skip delete/auth/owner checks.

Future tests:

- deleted result blocks Raw JSON access;
- Raw JSON payloads with legacy secret-like values are redacted in API/error paths before deletion;
- wrong owner does not learn Raw JSON existence.

## Target Histories And Active/Baseline

Rules:

- target history is owner-scoped;
- deleting a target job deletes app-side target input, result, error history, reports, exports, and Raw JSON access;
- external DNS records, resolver logs, HTTP server logs, proxies, and infrastructure logs are outside Inspectra deletion control;
- `active_network_dry_run` remains independent and no-network with `network_requests_sent: 0`;
- `active_http_header_probe` remains internal/limited, feature-flagged, authorized, double-confirmed, and capped to one `HEAD` request;
- Nmap remains out of scope.

Future tests:

- target histories are owner-scoped;
- target delete removes app-side target history only;
- blocked target jobs do not leak target strings across owners;
- dry-run deletion does not imply live traffic cleanup;
- one-HEAD deletion docs mention external target logs outside app control.

## Demo Reset

Rules:

- demo/synthetic marker is required before non-local reset;
- reset only demo data;
- never infer demo status from filename alone in non-local modes;
- trusted local reset may be simpler but must be documented as local/trusted only;
- public/community reset must not delete real user data.

Recommended markers:

- explicit demo owner/workspace;
- fixture marker;
- created-by-demo-seed metadata;
- local-only demo mode marker.

Future tests:

- demo reset removes only marked demo resources;
- real uploads/jobs/results survive demo reset;
- missing demo marker blocks non-local reset;
- reset summaries avoid sensitive names and target strings.

## Admin Cleanup

Rules:

- admin cleanup is explicit and redacted;
- in `self_hosted_single_admin`, the admin owns all resources by default;
- in private/community modes, admin cleanup must be scoped by an accepted policy;
- admin read-all is a separate decision from cleanup;
- cleanup logs avoid sensitive fields;
- admin cannot override target policy, Active feature flags, redaction, or no-read sensitive-file boundaries.

Future tests:

- admin cleanup requires admin principal;
- admin cleanup cannot read sensitive contents just to classify deletion;
- cleanup logs use minimal redacted metadata;
- admin cleanup in private/community mode respects the accepted scope.

## Failure And Recovery

Rules:

- partial deletion returns controlled errors and resource-class counts;
- delete operations should be retry-safe;
- repeated delete should be idempotent when tombstones exist;
- wrong-owner access should not reveal whether a deleted resource exists;
- missing owner denies non-local delete/read unless mapped or claimed by accepted migration;
- queued/running job deletion is deferred or denied until cancellation semantics exist;
- if deletion is requested for a running job in a future design, result exposure after completion must be blocked;
- logs must avoid sensitive filenames, targets, Raw JSON, stack traces, and secret-like values.

Future tests:

- partial deletion reports controlled failures;
- retry completes remaining cleanup without reintroducing sensitive data;
- wrong-owner and anonymous delete responses do not leak resource existence;
- deletion of failed/sparse/malformed jobs does not throw unhandled exceptions.

## Minimum Future Tests

Runtime implementation should test:

- owner can delete own source upload;
- wrong owner cannot delete source upload;
- anonymous cannot delete source upload;
- source bytes are removed;
- historical job behavior matches the accepted preserve-results-with-source-deleted-marker policy;
- job/result delete removes result, report availability, export availability, SBOM availability, and Raw JSON access;
- delete all owned data removes only owned resources;
- target history delete is owner-scoped;
- stored export artifact cleanup works if artifacts are introduced;
- manual download caveat appears in docs/UI;
- missing owner denies non-local delete/read;
- demo reset deletes only demo-marked resources;
- admin cleanup is explicit and scoped;
- cleanup logs avoid sensitive fields;
- queued/running job deletion is denied or deferred according to accepted policy;
- partial deletion returns controlled errors and supports retry;
- redaction regression passes after delete/retention changes.

## Relationship To P0-06 And P0-07

The deployment hardening checklist is now accepted:

```text
PASSIVE-ALPHA-P0-06-DEPLOYMENT-HARDENING-CHECKLIST
```

P0-06 should turn this retention/delete policy into deployment hardening questions before runtime implementation:

- storage permissions for uploads, results, temp/cache, and logs;
- backup/snapshot caveats and retention;
- log rotation and redaction;
- retention configuration surface;
- admin access and cleanup scope;
- no-auth exposure checks;
- host binding and reverse proxy posture;
- secrets/config handling;
- manual cleanup guidance for trusted local deployments;
- warning copy for downloads, exports, SBOMs, and Raw JSON.

The next recommended block is:

```text
PASSIVE-ALPHA-P0-07-P0-RUNTIME-PLANNING-CLOSEOUT
```

Close the P0 planning line before beginning runtime implementation slices.

## Open Questions

- Should source delete always preserve redacted historical results by default, or should some deployment modes default to cascade?
- Should "delete all owned data" exist in P0, or wait until after single-admin auth/ownership stabilizes?
- Is scheduled cleanup part of P0 runtime, or a later hardening block?
- What exact retention windows should uploads, results, target histories, logs, temp/cache, exports, and SBOMs use?
- Should exports remain on-demand only, or should stored artifacts exist?
- How should queued/running job deletion behave before cancellation support exists?
- What backup/snapshot policy should self-hosted operators document?
- Should admin cleanup be able to act across owners in private/community modes?
- What should public/community retention defaults be if that mode is ever accepted?
- How much tombstone metadata is needed for idempotency without retaining sensitive metadata?

## Out Of Scope

- Delete/runtime implementation.
- Job/result delete endpoint implementation.
- "Delete all owned data" implementation.
- Cleanup scheduler or cron.
- Demo reset implementation.
- Admin cleanup implementation.
- Auth implementation.
- Owner checks implementation.
- Sessions or cookies.
- Login UI.
- `owner_id` implementation.
- Storage migrations.
- DB/schema changes.
- Report/export implementation changes.
- SBOM implementation changes.
- Raw JSON implementation changes.
- Frontend UI changes.
- Tests or fixture changes.
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
- No backend changes.
- No frontend changes.
- No runner changes.
- No cleanup implementation.
- No scheduler or cron implementation.
- No DB migration.
- No storage schema change.
- No delete/reset UI.
- No auth implementation.
- No owner checks implementation.
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

- Final decision is recorded.
- Future retention/delete principles are defined.
- Resource policy matrix is defined.
- P0 product decisions are documented.
- Delete source upload semantics are defined.
- Delete job/result semantics are defined.
- Delete all owned data semantics are defined.
- Export/SBOM cleanup is defined.
- Raw JSON cleanup is defined.
- Target history deletion is covered.
- Demo reset and admin cleanup boundaries are covered.
- Failure/recovery behavior is defined.
- Minimum future tests are defined.
- Relationship to P0-06 is clear.
- No runtime or capability changes are made.

## Next Recommendation

```text
PASSIVE-ALPHA-P0-07-P0-RUNTIME-PLANNING-CLOSEOUT
```

Close the P0 planning line before starting runtime implementation.

## Validation Commands

Reference checks for this docs-only retention/delete runtime plan:

```text
git status --short
git status --branch --short
git log --oneline -12
git diff --check
git diff --cached --check
git status --short
```

No pytest or npm suite is required while this block remains docs-only.
